//! Metadata-only policy evaluation from one authorized configuration snapshot.
use super::{configuration, managed_policy, snapshot_policy};
use crate::access_admin::{AccessError, AclSelector};
use anyhow::{Context, Result, ensure};
use laneway_protocol::{
    Id,
    policy::{CompiledPolicy, Packet, prefix_from_wire},
    v1::{NodePeer, PolicyAction, PolicyRule, PolicySnapshot, RouteKind, RouteSnapshot},
};
use rusqlite::{OptionalExtension, Transaction};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashSet, net::IpAddr};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    flow: Flow,
    proposed_rules: Option<Vec<ProposedRule>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Flow {
    pub(super) source_node_id: String,
    pub(super) destination_node_id: Option<String>,
    pub(super) destination_ip: Option<String>,
    pub(super) protocol: String,
    #[serde(default)]
    pub(super) destination_port: u16,
}

pub(super) struct CheckedFlow {
    pub(super) source: Id,
    pub(super) destination: Option<Id>,
    pub(super) ip: Option<IpAddr>,
    protocol: u8,
    port: u16,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Unavailable {
    #[error("{0}")]
    Inactive(&'static str),
    #[error("no node or approved route resolves destination IP")]
    Unresolved,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposedRule {
    rule_id: String,
    priority: u32,
    action: String,
    selector: AclSelector,
    #[serde(default)]
    description: String,
    #[serde(default)]
    enabled: bool,
}

pub(crate) fn preview(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    req: Result<Preview>,
) -> Result<Value> {
    check_network(tx, net)?;
    let req = req?;
    let flow = req.flow.check()?.bind_overlay(tx, net)?;
    let evaluator = Evaluator::load(tx, net, now, &flow).map_err(preview_error)?;
    let mut result = json!({
        "current": evaluator.current()?,
        "scope": "manual_acl_with_current_managed_access",
    });
    if let Some(rules) = req.proposed_rules {
        result["proposed"] = evaluator.evaluate(proposal(rules, net, evaluator.epoch)?)?;
    }
    Ok(result)
}

pub(super) fn check_network(tx: &Transaction<'_>, net: Id) -> Result<()> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?)",
        [net.as_bytes()],
        |row| row.get(0),
    )?;
    ensure!(exists, AccessError::Missing);
    Ok(())
}

fn preview_error(err: anyhow::Error) -> anyhow::Error {
    match err.downcast_ref::<Unavailable>() {
        Some(Unavailable::Inactive(reason)) => AccessError::Invalid(reason).into(),
        Some(Unavailable::Unresolved) => {
            AccessError::Invalid("no node or approved route resolves destination IP").into()
        }
        None => err,
    }
}

pub(super) struct Evaluator<'tx, 'db> {
    tx: &'tx Transaction<'db>,
    net: Id,
    now: i64,
    epoch: u64,
    source: Id,
    destination: Id,
    user: Option<Id>,
    peers: Vec<NodePeer>,
    routes: RouteSnapshot,
    packet: Packet,
}

impl<'tx, 'db> Evaluator<'tx, 'db> {
    pub(super) fn load(
        tx: &'tx Transaction<'db>,
        net: Id,
        now: i64,
        flow: &CheckedFlow,
    ) -> Result<Self> {
        let user = active_node(
            tx,
            net,
            flow.source,
            now,
            "source identity is revoked or expired",
        )?;
        if let Some(node) = flow.destination {
            active_node(
                tx,
                net,
                node,
                now,
                "destination identity is revoked or expired",
            )?;
        }
        let epoch = configuration::configuration_epoch(tx, net, 0)?;
        let peers = configuration::peers(tx, net, now)?;
        let routes = configuration::routes(tx, net, epoch, now)?;
        let (destination, to) = resolve(&peers, &routes, flow.destination, flow.ip)?;
        let from = addresses(peer(&peers, flow.source)?)
            .find(|ip| ip.is_ipv4() == to.is_ipv4())
            .ok_or(AccessError::Invalid(
                "source has no address in the destination address family",
            ))?;
        let protocol = flow.protocol;
        ensure!(
            !(protocol == 1 && to.is_ipv6() || protocol == 58 && to.is_ipv4()),
            AccessError::Invalid("ICMP protocol does not match address family")
        );
        Ok(Self {
            tx,
            net,
            now,
            epoch,
            source: flow.source,
            destination,
            user,
            peers,
            routes,
            packet: Packet {
                source: from,
                destination: to,
                protocol,
                destination_port: matches!(protocol, 6 | 17).then_some(flow.port),
            },
        })
    }

    pub(super) fn current(&self) -> Result<Value> {
        self.evaluate(snapshot_policy::compile(self.tx, self.net, self.epoch)?)
    }

    fn evaluate(&self, mut snapshot: PolicySnapshot) -> Result<Value> {
        if let Some(user) = self.user {
            managed_policy::apply(
                self.tx,
                (self.net, self.source),
                user,
                self.now,
                &self.peers,
                &self.routes,
                &mut snapshot,
            )?;
        }
        let effective = CompiledPolicy::compile(snapshot, self.net, self.epoch)?;
        let mut trace = Vec::new();
        let (accept, matched) = effective.evaluate(
            self.source,
            self.destination,
            self.packet,
            |rule, matched| {
                trace.push(json!({
                    "rule_id": rule.id().to_string(),
                    "priority": rule.priority(),
                    "action": action_name(rule.accepts()),
                    "matched": matched,
                }));
            },
        );
        let mut result = json!({
            "configuration_epoch": self.epoch,
            "action": action_name(accept),
            "default_result": matched.is_none(),
            "destination_node_id": self.destination.to_string(),
            "destination_ip": self.packet.destination,
            "trace": trace,
        });
        if let Some(id) = matched {
            result["matched_rule_id"] = json!(id.to_string());
        }
        Ok(result)
    }
}

impl Flow {
    pub(super) fn check(&self) -> Result<CheckedFlow> {
        let source = parse_id(&self.source_node_id, "invalid source node ID")?;
        let destination = self
            .destination_node_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .map(|id| parse_id(id, "invalid destination node ID"))
            .transpose()?;
        let ip = self.ip()?;
        ensure!(
            destination.is_some() || ip.is_some(),
            AccessError::Invalid("destination node ID or IP is required")
        );
        Ok(CheckedFlow {
            source,
            destination,
            ip,
            protocol: self.protocol()?,
            port: self.destination_port,
        })
    }

    fn protocol(&self) -> Result<u8> {
        match (
            self.protocol.to_ascii_lowercase().as_str(),
            self.destination_port,
        ) {
            ("tcp" | "udp", 0) => {
                Err(AccessError::Invalid("destination port is required for TCP/UDP").into())
            }
            ("tcp", _) => Ok(6),
            ("udp", _) => Ok(17),
            ("icmp", 0) => Ok(1),
            ("icmpv6", 0) => Ok(58),
            ("icmp" | "icmpv6", _) => {
                Err(AccessError::Invalid("destination port only applies to TCP/UDP").into())
            }
            _ => Err(AccessError::Invalid("protocol must be tcp, udp, icmp, or icmpv6").into()),
        }
    }

    fn ip(&self) -> Result<Option<IpAddr>> {
        let Some(text) = self.destination_ip.as_deref().filter(|ip| !ip.is_empty()) else {
            return Ok(None);
        };
        let invalid = AccessError::Invalid("invalid destination IP");
        if let Ok(ip) = text.parse::<IpAddr>()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
        {
            return Ok(Some(ip));
        }
        Err(invalid.into())
    }
}

impl CheckedFlow {
    pub(super) fn bind_overlay(mut self, tx: &Transaction<'_>, net: Id) -> Result<Self> {
        // An allocated overlay address belongs to its node even if maintenance
        // has not reaped an expired lease yet. Do not try a default route for it.
        if self.destination.is_none()
            && let Some(ip) = self.ip
        {
            let bytes = match ip {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            self.destination = tx.query_row(
                "SELECT node_id FROM overlay_addresses WHERE network_id=? AND address=? AND released_at IS NULL",
                (net.as_bytes(), bytes),
                |r| r.get::<_, [u8; 16]>(0),
            ).optional()?.map(Id::new).transpose()?;
        }
        Ok(self)
    }
}

fn parse_id(text: &str, message: &'static str) -> Result<Id> {
    text.parse()
        .map_err(|_| AccessError::Invalid(message).into())
}

fn active_node(
    tx: &Transaction<'_>,
    net: Id,
    node: Id,
    now: i64,
    inactive: &'static str,
) -> Result<Option<Id>> {
    let (user, active): (Option<[u8; 16]>, bool) = tx
        .query_row(
            "SELECT user_id, revoked_at IS NULL AND
             CASE WHEN enrollment_class='ephemeral' THEN coalesce(lease_expires_at>?3,0)
                  ELSE lease_expires_at IS NULL OR lease_expires_at>?3 END
             FROM nodes WHERE network_id=?1 AND id=?2",
            (net.as_bytes(), node.as_bytes(), now),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(AccessError::Missing)?;
    ensure!(active, Unavailable::Inactive(inactive));
    user.map(Id::new).transpose().map_err(Into::into)
}

fn peer(peers: &[NodePeer], node: Id) -> Result<&NodePeer> {
    peers
        .iter()
        .find(|p| p.node_id == node.as_bytes())
        .context("active node missing from peer snapshot")
}

fn addresses(peer: &NodePeer) -> impl Iterator<Item = IpAddr> + '_ {
    peer.overlay_addresses
        .iter()
        .filter_map(|raw| match raw.len() {
            4 => Some(IpAddr::from(<[u8; 4]>::try_from(raw.as_slice()).ok()?)),
            16 => Some(IpAddr::from(<[u8; 16]>::try_from(raw.as_slice()).ok()?)),
            _ => None,
        })
}

fn resolve(
    peers: &[NodePeer],
    routes: &RouteSnapshot,
    target: Option<Id>,
    ip: Option<IpAddr>,
) -> Result<(Id, IpAddr)> {
    if let Some(target) = target {
        let p = peer(peers, target)?;
        match ip {
            None => {
                let address = addresses(p)
                    .next()
                    .ok_or(AccessError::Invalid("destination node has no address"))?;
                return Ok((target, address));
            }
            Some(ip) if addresses(p).any(|address| address == ip) => return Ok((target, ip)),
            _ => {}
        }
    }
    let ip = ip.ok_or(AccessError::Invalid(
        "destination node ID or IP is required",
    ))?;
    if target.is_none()
        && let Some(p) = peers
            .iter()
            .find(|p| addresses(p).any(|address| address == ip))
    {
        return Ok((Id::from_slice(&p.node_id)?, ip));
    }
    // Approved routes are already sorted by longest prefix, metric, then ID.
    for route in &routes.routes {
        if route.kind == RouteKind::Overlay as i32
            || target.is_some_and(|id| id.as_bytes() != route.via_node_id.as_slice())
        {
            continue;
        }
        let prefix = prefix_from_wire(route.destination.clone().context("route missing prefix")?)?;
        if prefix.contains(&ip) {
            return Ok((Id::from_slice(&route.via_node_id)?, ip));
        }
    }
    if target.is_some() {
        return Err(AccessError::Invalid(
            "destination IP does not belong to the node or its approved routes",
        )
        .into());
    }
    Err(Unavailable::Unresolved.into())
}

fn proposal(rules: Vec<ProposedRule>, net: Id, epoch: u64) -> Result<PolicySnapshot> {
    ensure!(
        rules.len() <= 4096,
        AccessError::Invalid("too many proposed ACL rules")
    );
    let mut ids = HashSet::new();
    let mut snapshot = PolicySnapshot {
        network_id: net.as_bytes().to_vec(),
        configuration_epoch: epoch,
        default_action: PolicyAction::Deny as i32,
        rules: Vec::new(),
    };
    for rule in rules {
        let id = parse_id(&rule.rule_id, "proposed rule requires a valid rule_id")?;
        let action = match rule.action.as_str() {
            "accept" => PolicyAction::Accept,
            "deny" => PolicyAction::Deny,
            _ => return Err(AccessError::Invalid("invalid proposed action").into()),
        };
        let selector = rule
            .selector
            .validated_wire()
            .map_err(|_| AccessError::Invalid("invalid proposed selector"))?;
        if rule.enabled {
            ensure!(
                ids.insert(id),
                AccessError::Invalid("duplicate proposed rule ID")
            );
            snapshot.rules.push(PolicyRule {
                rule_id: id.as_bytes().to_vec(),
                priority: rule.priority,
                action: action as i32,
                selector: Some(selector),
                description: rule.description,
            });
        }
    }
    Ok(snapshot)
}

fn action_name(accept: bool) -> &'static str {
    if accept { "accept" } else { "deny" }
}
