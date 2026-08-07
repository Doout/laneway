//! Strict, language-neutral stable-v1 traffic-policy compilation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::{Id, v1};

/// A fully validated immutable ACL snapshot.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    default_accept: bool,
    rules: Vec<Rule>,
}

#[derive(Clone, Debug)]
struct Rule {
    id: Id,
    priority: u32,
    accept: bool,
    source_nodes: Vec<Id>,
    source_prefixes: Vec<IpNet>,
    destination_nodes: Vec<Id>,
    destination_prefixes: Vec<IpNet>,
    protocol: v1::IpProtocol,
    destination_ports: Vec<(u16, u16)>,
}

/// Policy compilation failures are deliberately semantic rather than tied to
/// protobuf implementation error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Snapshot network or epoch did not match its containing configuration.
    #[error("policy identity or epoch mismatch")]
    Identity,
    /// The default action or one rule action was unspecified or unknown.
    #[error("policy action is invalid")]
    Action,
    /// A rule identifier was malformed or duplicated.
    #[error("policy rule identifier is invalid or duplicated")]
    RuleId,
    /// A rule omitted its selector or used an invalid selector field.
    #[error("policy selector is invalid")]
    Selector,
}

impl CompiledPolicy {
    /// Compiles a policy only when its identity exactly matches the containing
    /// controller snapshot. Rules are sorted by the stable-v1 priority and ID
    /// order before publication.
    pub fn compile(
        snapshot: v1::PolicySnapshot,
        network: Id,
        epoch: u64,
    ) -> Result<Self, PolicyError> {
        if snapshot.network_id != network.as_bytes() || snapshot.configuration_epoch != epoch {
            return Err(PolicyError::Identity);
        }
        let default_accept = action(snapshot.default_action)?;
        let mut rules = Vec::with_capacity(snapshot.rules.len());
        let mut ids = std::collections::HashSet::with_capacity(snapshot.rules.len());
        for input in snapshot.rules {
            let id = Id::from_slice(&input.rule_id).map_err(|_| PolicyError::RuleId)?;
            if !ids.insert(id) {
                return Err(PolicyError::RuleId);
            }
            let selector = input.selector.ok_or(PolicyError::Selector)?;
            let protocol = v1::IpProtocol::try_from(selector.ip_protocol)
                .map_err(|_| PolicyError::Selector)?;
            if protocol == v1::IpProtocol::Unspecified {
                return Err(PolicyError::Selector);
            }
            let source_nodes = ids_from_wire(&selector.source_node_ids)?;
            let destination_nodes = ids_from_wire(&selector.destination_node_ids)?;
            let source_prefixes = prefixes_from_wire(selector.source_prefixes)?;
            let destination_prefixes = prefixes_from_wire(selector.destination_prefixes)?;
            let mut destination_ports = Vec::with_capacity(selector.destination_ports.len());
            for port in selector.destination_ports {
                if port.first == 0 || port.first > port.last || port.last > u32::from(u16::MAX) {
                    return Err(PolicyError::Selector);
                }
                destination_ports.push((port.first as u16, port.last as u16));
            }
            rules.push(Rule {
                id,
                priority: input.priority,
                accept: action(input.action)?,
                source_nodes,
                source_prefixes,
                destination_nodes,
                destination_prefixes,
                protocol,
                destination_ports,
            });
        }
        rules.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(Self {
            default_accept,
            rules,
        })
    }

    /// Applies the first matching rule to one complete raw IPv4 or IPv6
    /// packet. Malformed packets fail closed before rule evaluation.
    pub fn allows(&self, source: Id, destination: Id, raw: &[u8]) -> bool {
        let Some(packet) = Packet::parse(raw) else {
            return false;
        };
        self.rules
            .iter()
            .find(|rule| rule.matches(source, destination, packet))
            .map_or(self.default_accept, |rule| rule.accept)
    }

    /// Returns the explicit fallback action carried by the snapshot.
    pub const fn default_accepts(&self) -> bool {
        self.default_accept
    }
}

impl Rule {
    fn matches(&self, source: Id, destination: Id, packet: Packet) -> bool {
        (self.source_nodes.is_empty() || self.source_nodes.contains(&source))
            && (self.destination_nodes.is_empty() || self.destination_nodes.contains(&destination))
            && (self.source_prefixes.is_empty()
                || self
                    .source_prefixes
                    .iter()
                    .any(|prefix| prefix.contains(&packet.source)))
            && (self.destination_prefixes.is_empty()
                || self
                    .destination_prefixes
                    .iter()
                    .any(|prefix| prefix.contains(&packet.destination)))
            && (self.protocol == v1::IpProtocol::Any
                || self.protocol as i32 == i32::from(packet.protocol))
            && (self.destination_ports.is_empty()
                || packet.destination_port.is_some_and(|port| {
                    self.destination_ports
                        .iter()
                        .any(|(first, last)| port >= *first && port <= *last)
                }))
    }
}

fn action(value: i32) -> Result<bool, PolicyError> {
    match v1::PolicyAction::try_from(value).ok() {
        Some(v1::PolicyAction::Accept) => Ok(true),
        Some(v1::PolicyAction::Deny) => Ok(false),
        _ => Err(PolicyError::Action),
    }
}

fn ids_from_wire(values: &[Vec<u8>]) -> Result<Vec<Id>, PolicyError> {
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let id = Id::from_slice(value).map_err(|_| PolicyError::Selector)?;
        if output.contains(&id) {
            return Err(PolicyError::Selector);
        }
        output.push(id);
    }
    Ok(output)
}

/// Parses a protobuf IP prefix and rejects host bits and mapped IPv4 forms.
pub fn prefix_from_wire(value: v1::IpPrefix) -> Result<IpNet, PolicyError> {
    let address = match value.address.as_slice() {
        bytes @ [_, _, _, _] => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).expect("length checked"),
        )),
        bytes if bytes.len() == 16 => {
            let address = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).expect("length checked"));
            if address.to_ipv4_mapped().is_some() {
                return Err(PolicyError::Selector);
            }
            IpAddr::V6(address)
        }
        _ => return Err(PolicyError::Selector),
    };
    let prefix = match address {
        IpAddr::V4(address) if value.prefix_length <= 32 => IpNet::V4(
            Ipv4Net::new(address, value.prefix_length as u8).map_err(|_| PolicyError::Selector)?,
        ),
        IpAddr::V6(address) if value.prefix_length <= 128 => IpNet::V6(
            Ipv6Net::new(address, value.prefix_length as u8).map_err(|_| PolicyError::Selector)?,
        ),
        _ => return Err(PolicyError::Selector),
    };
    if prefix.trunc() != prefix {
        return Err(PolicyError::Selector);
    }
    Ok(prefix)
}

fn prefixes_from_wire(values: Vec<v1::IpPrefix>) -> Result<Vec<IpNet>, PolicyError> {
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let prefix = prefix_from_wire(value)?;
        if output.contains(&prefix) {
            return Err(PolicyError::Selector);
        }
        output.push(prefix);
    }
    Ok(output)
}

#[derive(Clone, Copy)]
struct Packet {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    destination_port: Option<u16>,
}

impl Packet {
    fn parse(raw: &[u8]) -> Option<Self> {
        match raw.first()? >> 4 {
            4 if raw.len() >= 20 => {
                let header = usize::from(raw[0] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
                if header < 20 || header > raw.len() || total != raw.len() {
                    return None;
                }
                let protocol = raw[9];
                Some(Self {
                    source: IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw[12..16]).ok()?)),
                    destination: IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(&raw[16..20]).ok()?,
                    )),
                    protocol,
                    destination_port: destination_port(raw, header, protocol),
                })
            }
            6 if raw.len() >= 40
                && usize::from(u16::from_be_bytes([raw[4], raw[5]])) + 40 == raw.len() =>
            {
                let protocol = raw[6];
                Some(Self {
                    source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).ok()?)),
                    destination: IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&raw[24..40]).ok()?,
                    )),
                    protocol,
                    destination_port: destination_port(raw, 40, protocol),
                })
            }
            _ => None,
        }
    }
}

fn destination_port(raw: &[u8], offset: usize, protocol: u8) -> Option<u16> {
    ((protocol == 6 || protocol == 17) && raw.len() >= offset + 4)
        .then(|| u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{PolicyRule, PortRange, TrafficSelector};

    fn prefix(address: [u8; 4], length: u32) -> v1::IpPrefix {
        v1::IpPrefix {
            address: address.to_vec(),
            prefix_length: length,
        }
    }

    fn udp(port: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[100, 96, 0, 1]);
        packet[16..20].copy_from_slice(&[100, 96, 0, 2]);
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet
    }

    #[test]
    fn first_match_and_default_deny_are_stable() {
        let network = Id::new([1; 16]).unwrap();
        let source = Id::new([2; 16]).unwrap();
        let destination = Id::new([3; 16]).unwrap();
        let policy = CompiledPolicy::compile(
            v1::PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: 7,
                default_action: v1::PolicyAction::Deny as i32,
                rules: vec![PolicyRule {
                    rule_id: [9_u8; 16].to_vec(),
                    priority: 10,
                    action: v1::PolicyAction::Accept as i32,
                    selector: Some(TrafficSelector {
                        source_node_ids: vec![source.as_bytes().to_vec()],
                        destination_node_ids: vec![destination.as_bytes().to_vec()],
                        source_prefixes: vec![prefix([100, 96, 0, 0], 24)],
                        destination_prefixes: vec![prefix([100, 96, 0, 2], 32)],
                        ip_protocol: v1::IpProtocol::Udp as i32,
                        destination_ports: vec![PortRange {
                            first: 53,
                            last: 53,
                        }],
                    }),
                    description: String::new(),
                }],
            },
            network,
            7,
        )
        .unwrap();
        assert!(policy.allows(source, destination, &udp(53)));
        assert!(!policy.allows(source, destination, &udp(54)));
        assert!(!policy.allows(destination, source, &udp(53)));
        assert!(!policy.allows(source, destination, &[0x45; 19]));
    }

    #[test]
    fn rejects_ambiguous_or_noncanonical_input() {
        let network = Id::new([1; 16]).unwrap();
        let mut snapshot = v1::PolicySnapshot {
            network_id: network.as_bytes().to_vec(),
            configuration_epoch: 1,
            default_action: v1::PolicyAction::Deny as i32,
            rules: vec![],
        };
        snapshot.rules = vec![PolicyRule {
            rule_id: [2_u8; 16].to_vec(),
            priority: 1,
            action: v1::PolicyAction::Accept as i32,
            selector: Some(TrafficSelector {
                ip_protocol: v1::IpProtocol::Any as i32,
                source_prefixes: vec![prefix([10, 0, 0, 1], 24)],
                ..Default::default()
            }),
            description: String::new(),
        }];
        assert_eq!(
            CompiledPolicy::compile(snapshot, network, 1).unwrap_err(),
            PolicyError::Selector
        );
    }
}
