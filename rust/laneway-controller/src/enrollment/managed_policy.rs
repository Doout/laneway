//! Per-user scope, computed from the same snapshot as the route and peer lists.
mod named_grants;

use super::renewal::NodeCredential;
use anyhow::{Result, ensure};
use laneway_protocol::{
    DEFAULT_MAX_CONTROL_PAYLOAD, Id,
    policy::CompiledPolicy,
    v1::{
        IpPrefix, IpProtocol, NodePeer, PolicyAction, PolicyRule, PolicySnapshot, Route, RouteKind,
        RouteSnapshot, TrafficSelector,
    },
};
use prost::Message;
use rusqlite::Transaction;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

struct Grants<'a> {
    net: Id,
    user: Id,
    sources: Vec<Vec<u8>>,
    peers: HashMap<&'a [u8], &'a NodePeer>,
    routes: &'a [Route],
    rules: Vec<PolicyRule>,
    max_bytes: usize,
}

pub(super) fn apply(
    tx: &Transaction<'_>,
    peer: &NodeCredential,
    user: Id,
    now: i64,
    peers: &[NodePeer],
    routes: &RouteSnapshot,
    policy: &mut PolicySnapshot,
) -> Result<Vec<Vec<u8>>> {
    let enabled: bool = tx.query_row(
        "SELECT enabled FROM access_users WHERE network_id=? AND id=?",
        (peer.net.as_bytes(), user.as_bytes()),
        |r| r.get(0),
    )?;
    let sources = {
        let mut stmt = tx.prepare(
            "SELECT id FROM nodes WHERE network_id=?1 AND user_id=?2 AND revoked_at IS NULL
            AND (lease_expires_at IS NULL OR lease_expires_at>?3) ORDER BY id LIMIT 16385",
        )?;
        let values = stmt
            .query_map((peer.net.as_bytes(), user.as_bytes(), now), |r| {
                r.get::<_, Vec<u8>>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            values.len() <= 16384 && values.iter().any(|id| id == peer.node.as_bytes()),
            "invalid managed source set"
        );
        values
    };
    let mut grants = Grants {
        net: peer.net,
        user,
        sources,
        peers: peers.iter().map(|p| (p.node_id.as_slice(), p)).collect(),
        routes: &routes.routes,
        rules: Vec::new(),
        max_bytes: DEFAULT_MAX_CONTROL_PAYLOAD.saturating_sub(policy.encoded_len()),
    };
    let exits = if enabled {
        let exits = grants.direct(tx, peers)?;
        grants.named(tx)?;
        exits
    } else {
        Vec::new()
    };

    // The hard deny precedes all manual rules. A global allow, even at
    // priority zero, cannot widen the grant for any device of this user.
    let mut hash = Sha256::new();
    hash.update(b"laneway-managed-user-deny-v1:");
    hash.update(user.as_bytes());
    let deny = Id::from_slice(&hash.finalize()[..16])?;
    let selector = grants.selector(IpProtocol::Any, Vec::new(), Vec::new());
    grants.push(PolicyRule {
        rule_id: deny.as_bytes().to_vec(),
        priority: 1,
        action: PolicyAction::Deny as i32,
        selector: Some(selector),
        description: "Managed user default deny".into(),
    })?;
    grants.rules.sort_unstable_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    for row in &mut policy.rules {
        row.priority = row.priority.saturating_add(2);
    }
    grants.rules.append(&mut policy.rules);
    policy.rules = grants.rules;
    CompiledPolicy::compile(policy.clone(), peer.net, policy.configuration_epoch)?;
    Ok(exits)
}

impl Grants<'_> {
    fn direct(&mut self, tx: &Transaction<'_>, peers: &[NodePeer]) -> Result<Vec<Vec<u8>>> {
        let mut stmt=tx.prepare("SELECT g.id,g.target_kind,g.node_id FROM access_grants g WHERE g.network_id=?1 AND
            ((g.subject_kind='user' AND g.user_id=?2) OR (g.subject_kind='team' AND g.team_id IN
            (SELECT team_id FROM access_team_members WHERE network_id=?1 AND user_id=?2))) ORDER BY g.id")?;
        let mut rows = stmt.query((self.net.as_bytes(), self.user.as_bytes()))?;
        let mut exits = BTreeSet::new();
        let mut network = None;
        let approved_exits: BTreeSet<_> = self
            .routes
            .iter()
            .filter(|r| r.kind == RouteKind::Exit as i32)
            .map(|r| r.via_node_id.as_slice())
            .collect();
        while let Some(row) = rows.next()? {
            let id = read_id(row, 0)?;
            let node: Option<Vec<u8>> = row.get(2)?;
            let selector = match (row.get::<_, String>(1)?.as_str(), node) {
                ("network", None) => {
                    // Only private overlay and approved subnet destinations
                    // are reachable from a network grant, never default exits.
                    let (ids, ips) =
                        network.get_or_insert_with(|| network_targets(peers, self.routes));
                    self.selector(IpProtocol::Any, ids.clone(), ips.clone())
                }
                ("node", Some(node)) => {
                    Id::from_slice(&node)?;
                    let Some(peer) = self.peers.get(node.as_slice()) else {
                        continue;
                    };
                    self.selector(IpProtocol::Any, vec![node], overlay_prefixes(peer))
                }
                ("exit", Some(node)) => {
                    Id::from_slice(&node)?;
                    if !approved_exits.contains(node.as_slice()) {
                        continue;
                    }
                    exits.insert(node.clone());
                    self.selector(
                        IpProtocol::Any,
                        vec![node],
                        vec![IpPrefix {
                            address: vec![0; 4],
                            prefix_length: 0,
                        }],
                    )
                }
                _ => anyhow::bail!("invalid managed access grant target"),
            };
            self.allow(id, selector, "Managed user access grant")?;
        }
        Ok(exits.into_iter().collect())
    }

    fn selector(&self, p: IpProtocol, ids: Vec<Vec<u8>>, ips: Vec<IpPrefix>) -> TrafficSelector {
        TrafficSelector {
            source_node_ids: self.sources.clone(),
            destination_node_ids: ids,
            destination_prefixes: ips,
            ip_protocol: p as i32,
            ..Default::default()
        }
    }

    fn allow(&mut self, id: Id, selector: TrafficSelector, description: &str) -> Result<()> {
        if selector.destination_node_ids.is_empty() || selector.destination_prefixes.is_empty() {
            return Ok(());
        }
        self.push(PolicyRule {
            rule_id: id.as_bytes().to_vec(),
            priority: 0,
            action: PolicyAction::Accept as i32,
            selector: Some(selector),
            description: description.into(),
        })
    }

    fn push(&mut self, rule: PolicyRule) -> Result<()> {
        let cost = rule.encoded_len() + 8;
        ensure!(
            self.rules.len() < 4096 && cost <= self.max_bytes,
            "managed policy exceeds snapshot bounds"
        );
        self.max_bytes -= cost;
        self.rules.push(rule);
        Ok(())
    }
}

fn read_id(row: &rusqlite::Row<'_>, col: usize) -> Result<Id> {
    Ok(Id::new(row.get::<_, [u8; 16]>(col)?)?)
}
fn overlay_prefixes(peer: &NodePeer) -> Vec<IpPrefix> {
    peer.overlay_addresses
        .iter()
        .map(|address| IpPrefix {
            address: address.clone(),
            prefix_length: (address.len() * 8) as u32,
        })
        .collect()
}
fn network_targets(peers: &[NodePeer], routes: &[Route]) -> (Vec<Vec<u8>>, Vec<IpPrefix>) {
    let mut ids: BTreeSet<_> = peers.iter().map(|p| p.node_id.clone()).collect();
    let mut prefixes: Vec<_> = peers.iter().flat_map(overlay_prefixes).collect();
    for route in routes.iter().filter(|r| r.kind == RouteKind::Subnet as i32) {
        if let Some(ip) = &route.destination {
            prefixes.push(ip.clone());
            ids.insert(route.via_node_id.clone());
        }
    }
    (ids.into_iter().collect(), prefixes)
}
