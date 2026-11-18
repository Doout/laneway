//! Translate authenticated node ownership and ordered ACLs into kernel state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use laneway_protocol::{
    Id,
    policy::{CompiledPolicy, CompiledRule},
    v1::{Capability, IpProtocol, RouteAdvertisementMode, RouteKind},
};

use crate::{config::Config, controller::Snapshot};

const MAX_PEERS: usize = 512;
const MAX_PREFIXES: usize = 8192;
const MAX_RULES: usize = 4096;
const MAX_NFT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PeerPlan {
    pub(super) key: [u8; 32],
    pub(super) prefixes: Vec<IpNet>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct DevicePlan {
    pub(super) overlays: Vec<IpNet>,
    pub(super) peers: BTreeMap<Id, PeerPlan>,
    acl: Vec<(Direction, String)>,
    pub(super) nat_sources: Vec<IpNet>,
}

impl DevicePlan {
    pub(super) fn same_paths(&self, other: &Self) -> bool {
        self.overlays == other.overlays
            && self.peers == other.peers
            && self.nat_sources == other.nat_sources
    }

    pub(super) fn compile(config: &Config, snapshot: &Snapshot, local: Id) -> Result<Self> {
        ensure!(
            snapshot.peers.len() <= MAX_PEERS + 1,
            "WireGuard device peer limit exceeded"
        );
        let mut owners = BTreeMap::<Id, BTreeSet<IpNet>>::new();
        for (&node, peer) in &snapshot.peers {
            ensure!(
                peer.wireguard_key.is_some(),
                "controller peer {node} has no WireGuard key"
            );
            for &address in &peer.overlays {
                owners.entry(node).or_default().insert(IpNet::from(address));
            }
        }
        for route in &snapshot.routes {
            if matches!(route.kind, RouteKind::Overlay | RouteKind::Subnet) {
                ensure!(
                    !route.destination.addr().is_multicast()
                        && !route.destination.addr().is_unspecified(),
                    "WireGuard route has an invalid ownership prefix"
                );
                owners
                    .entry(route.via)
                    .or_default()
                    .insert(route.destination);
            }
        }
        validate_ownership(&owners)?;
        let peers = snapshot
            .peers
            .iter()
            .filter(|(node, _)| **node != local)
            .map(|(&node, peer)| {
                Ok((
                    node,
                    PeerPlan {
                        key: peer.wireguard_key.context("missing WireGuard peer key")?,
                        prefixes: owners
                            .remove(&node)
                            .context("missing WireGuard peer ownership")?
                            .into_iter()
                            .collect(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let acl = compile_acl(&snapshot.policy, &peers, local)?;
        let mut nat_sources = Vec::new();
        if config.forwarding.exit_gateway
            && snapshot.authorized_exits.contains(&local)
            && snapshot.enabled_capabilities & Capability::LanewayExitNodeV1 as u64 != 0
        {
            let families: BTreeSet<_> = snapshot
                .routes
                .iter()
                .filter(|route| {
                    route.via == local
                        && route.kind == RouteKind::Exit
                        && route.mode == RouteAdvertisementMode::Nat
                })
                .map(|route| route.destination.addr().is_ipv4())
                .collect();
            nat_sources.extend(
                snapshot
                    .peers
                    .iter()
                    .filter(|(node, _)| **node != local)
                    .flat_map(|(_, peer)| peer.overlays.iter().copied())
                    .filter(|address| families.contains(&address.is_ipv4()))
                    .map(IpNet::from),
            );
            nat_sources.sort_unstable();
        }
        Ok(Self {
            overlays: snapshot.overlays.clone(),
            peers,
            acl,
            nat_sources,
        })
    }

    pub(super) fn firewall(
        &self,
        table: &str,
        interface: &str,
        port: u16,
        uplink: Option<&str>,
        draining: bool,
    ) -> Result<String> {
        let mut script = format!(
            "create table inet {table}\n\
             add chain inet {table} inbound\n\
             add chain inet {table} outbound\n"
        );
        for (direction, rule) in &self.acl {
            writeln!(script, "add rule inet {table} {} {rule}", direction.chain())?;
            ensure!(
                script.len() <= MAX_NFT_BYTES,
                "WireGuard policy exceeds byte limit"
            );
        }
        let local_in = if draining { "drop" } else { "jump inbound" };
        let local_out = if draining { "drop" } else { "jump outbound" };
        let state = if draining {
            " ct state established,related"
        } else {
            ""
        };
        write!(
            script,
            "add rule inet {table} inbound drop\n\
             add rule inet {table} outbound drop\n\
             add chain inet {table} local_in {{ type filter hook input priority -10; policy accept; }}\n\
             add chain inet {table} local_out {{ type filter hook output priority -10; policy accept; }}\n\
             add chain inet {table} transit {{ type filter hook forward priority -10; policy accept; }}\n\
             add rule inet {table} local_in iifname \"{interface}\" {local_in}\n\
             add rule inet {table} local_in iifname != \"lo\" udp dport {port} drop\n\
             add rule inet {table} local_out oifname \"{interface}\" {local_out}\n\
             add rule inet {table} transit iifname \"{interface}\" oifname \"{interface}\" drop\n"
        )?;
        if let Some(uplink) = uplink.filter(|_| !self.nat_sources.is_empty()) {
            writeln!(
                script,
                "add rule inet {table} transit iifname \"{interface}\" oifname \"{uplink}\"{state} jump inbound"
            )?;
            writeln!(
                script,
                "add rule inet {table} transit iifname \"{uplink}\" oifname \"{interface}\"{state} jump outbound"
            )?;
        }
        writeln!(
            script,
            "add rule inet {table} transit iifname \"{interface}\" drop"
        )?;
        writeln!(
            script,
            "add rule inet {table} transit oifname \"{interface}\" drop"
        )?;
        Ok(script)
    }
}

fn validate_ownership(owners: &BTreeMap<Id, BTreeSet<IpNet>>) -> Result<()> {
    let mut prefixes = owners.values().flatten().copied().collect::<Vec<_>>();
    ensure!(
        prefixes.len() <= MAX_PREFIXES,
        "WireGuard ownership prefix limit exceeded"
    );
    prefixes.sort_unstable_by_key(|prefix| (prefix.addr(), prefix.prefix_len()));
    for pair in prefixes.windows(2) {
        ensure!(
            !pair[0].contains(&pair[1].addr()),
            "overlapping WireGuard ownership: {} and {}",
            pair[0],
            pair[1]
        );
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    In,
    Out,
}

impl Direction {
    fn chain(self) -> &'static str {
        match self {
            Self::In => "inbound",
            Self::Out => "outbound",
        }
    }
}

fn compile_acl(
    policy: &CompiledPolicy,
    peers: &BTreeMap<Id, PeerPlan>,
    local: Id,
) -> Result<Vec<(Direction, String)>> {
    ensure!(
        !policy.default_accepts(),
        "WireGuard policy must default deny"
    );
    ensure!(
        policy.rules().len() <= MAX_RULES,
        "WireGuard policy rule limit exceeded"
    );
    let mut result = Vec::new();
    let mut bytes = 0usize;
    for rule in policy.rules() {
        for node in rule.source_nodes().iter().chain(rule.destination_nodes()) {
            ensure!(
                *node == local || peers.contains_key(node),
                "WireGuard policy refers to an absent node"
            );
        }
        for direction in [Direction::In, Direction::Out] {
            let (our_nodes, remote_nodes, remote_field) = match direction {
                Direction::In => (rule.destination_nodes(), rule.source_nodes(), "saddr"),
                Direction::Out => (rule.source_nodes(), rule.destination_nodes(), "daddr"),
            };
            if !our_nodes.is_empty() && !our_nodes.contains(&local) {
                continue;
            }
            let remote_prefixes: Vec<_> = remote_nodes
                .iter()
                .filter_map(|node| peers.get(node))
                .flat_map(|peer| peer.prefixes.iter().copied())
                .collect();
            if !remote_nodes.is_empty() && remote_prefixes.is_empty() {
                continue;
            }
            for ipv4 in [true, false] {
                for text in render_rule(rule, ipv4, remote_field, &remote_prefixes)? {
                    bytes += text.len();
                    ensure!(
                        result.len() < MAX_RULES && bytes <= MAX_NFT_BYTES,
                        "expanded WireGuard policy exceeds safety bounds"
                    );
                    result.push((direction, text));
                }
            }
        }
    }
    Ok(result)
}

fn render_rule(
    rule: &CompiledRule,
    ipv4: bool,
    remote_field: &str,
    remote: &[IpNet],
) -> Result<Vec<String>> {
    let protocol = rule.protocol();
    if (ipv4 && protocol == IpProtocol::Icmpv6) || (!ipv4 && protocol == IpProtocol::Icmp) {
        return Ok(Vec::new());
    }
    let family = if ipv4 { "ip" } else { "ip6" };
    let version = if ipv4 { "ipv4" } else { "ipv6" };
    let field = if ipv4 { "protocol" } else { "nexthdr" };
    let mut matches = format!("meta nfproto {version}");
    for (key, prefixes) in [
        (remote_field, remote),
        ("saddr", rule.source_prefixes()),
        ("daddr", rule.destination_prefixes()),
    ] {
        if prefixes.is_empty() {
            continue;
        }
        let same_family = prefixes
            .iter()
            .copied()
            .filter(|p| p.addr().is_ipv4() == ipv4)
            .collect::<Vec<_>>();
        if same_family.is_empty() {
            return Ok(Vec::new());
        }
        // nftables interval sets must not include overlapping entries.
        let set = IpNet::aggregate(&same_family)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(matches, " {family} {key} {{ {set} }}")?;
    }
    let ports = rule.destination_ports();
    let transports = match (protocol, ports.is_empty()) {
        (IpProtocol::Any, false) => vec![IpProtocol::Tcp, IpProtocol::Udp],
        (IpProtocol::Tcp | IpProtocol::Udp, _) | (_, true) => vec![protocol],
        _ => return Ok(Vec::new()), // A port cannot match a non-port protocol.
    };
    let verdict = if rule.accepts() { "accept" } else { "drop" };
    transports
        .into_iter()
        .map(|transport| {
            let mut text = matches.clone();
            if transport != IpProtocol::Any {
                write!(text, " {family} {field} {}", transport as i32)?;
            }
            if !ports.is_empty() {
                let keyword = if transport == IpProtocol::Tcp {
                    "tcp"
                } else {
                    "udp"
                };
                // Use one rule per normalized set. Maintain first-match ordering
                // while allowing ranges and discrete ports in the same selector.
                let set = port_set(ports);
                write!(text, " {keyword} dport {{ {set} }}")?;
            }
            write!(text, " counter {verdict} comment \"lw-wg-{}\"", rule.id())?;
            Ok(text)
        })
        .collect()
}

fn port_set(ports: &[(u16, u16)]) -> String {
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::new();
    for (first, last) in sorted {
        if let Some(previous) = merged.last_mut().filter(|p| first <= p.1.saturating_add(1)) {
            previous.1 = previous.1.max(last);
        } else {
            merged.push((first, last));
        }
    }
    merged
        .into_iter()
        .map(|(first, last)| {
            if first == last {
                first.to_string()
            } else {
                format!("{first}-{last}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::{
        IpPrefix, PolicyAction, PolicyRule, PolicySnapshot, PortRange, TrafficSelector,
    };

    use crate::controller::tests::id;

    #[test]
    fn cryptographic_ownership_rejects_ambiguous_or_overlapping_prefixes() {
        let prefixes = |input: &[&str]| input.iter().map(|p| p.parse::<IpNet>().unwrap()).collect();
        let mut owners = BTreeMap::from([
            (id(1), prefixes(&["100.96.0.0/24", "fd42::1/128"])),
            (id(2), prefixes(&["100.96.1.0/24", "fd42::2/128"])),
        ]);
        assert!(validate_ownership(&owners).is_ok());
        owners.insert(id(3), prefixes(&["100.96.0.18/32"]));
        assert!(validate_ownership(&owners).is_err());
        owners.insert(id(3), prefixes(&["fd42::2/128"]));
        assert!(validate_ownership(&owners).is_err());
    }

    #[test]
    fn kernel_policy_preserves_order_node_and_prefix_intersection_and_port_union() {
        let network = id(9);
        let local = id(1);
        let peer = id(2);
        let rule = |id, action: PolicyAction, priority, selector| PolicyRule {
            rule_id: id,
            action: action as i32,
            priority,
            selector: Some(selector),
            ..PolicyRule::default()
        };
        let policy = CompiledPolicy::compile(
            PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: 1,
                default_action: PolicyAction::Deny as i32,
                rules: vec![
                    rule(
                        id(6).as_bytes().to_vec(),
                        PolicyAction::Accept,
                        50,
                        TrafficSelector {
                            ip_protocol: IpProtocol::Any as i32,
                            ..TrafficSelector::default()
                        },
                    ),
                    rule(
                        id(5).as_bytes().to_vec(),
                        PolicyAction::Deny,
                        10,
                        TrafficSelector {
                            source_node_ids: vec![peer.as_bytes().to_vec()],
                            destination_node_ids: vec![local.as_bytes().to_vec()],
                            source_prefixes: vec![IpPrefix {
                                address: vec![100, 96, 0, 0],
                                prefix_length: 24,
                            }],
                            ip_protocol: IpProtocol::Any as i32,
                            destination_ports: vec![
                                PortRange {
                                    first: 8443,
                                    last: 8450,
                                },
                                PortRange {
                                    first: 8441,
                                    last: 8443,
                                },
                                PortRange {
                                    first: 443,
                                    last: 443,
                                },
                            ],
                            ..TrafficSelector::default()
                        },
                    ),
                ],
            },
            network,
            1,
        )
        .unwrap();
        let peers = BTreeMap::from([(
            peer,
            PeerPlan {
                key: [3; 32],
                prefixes: vec![
                    "100.96.0.2/32".parse().unwrap(),
                    "fd42::2/128".parse().unwrap(),
                ],
            },
        )]);
        let acl = compile_acl(&policy, &peers, local).unwrap();
        let denies: Vec<_> = acl
            .iter()
            .filter(|(_, text)| text.contains(" drop "))
            .collect();
        assert_eq!(denies.len(), 2);
        assert!(
            acl[..2]
                .iter()
                .all(|(direction, _)| *direction == Direction::In)
        );
        assert!(denies.iter().all(|(_, rule)| {
            rule.contains("ip saddr { 100.96.0.2/32 } ip saddr { 100.96.0.0/24 }")
                && rule.contains("dport { 443, 8441-8450 }")
                && !rule.contains("ip6")
        }));
        assert!(acl[2].1.contains(" accept "));
        assert!(compile_acl(&policy, &BTreeMap::new(), local).is_err());
    }
}
