//! Private directory over a single policy and certificate snapshot.
use super::{EnrollError, configuration, managed_policy, renewal::NodeCredential};
use crate::{
    SessionStore,
    access_admin::{AccessError, Port, ServiceProtocol, service_ports},
    check_snapshot,
};
use anyhow::{Result, ensure};
use laneway_protocol::{
    DEFAULT_MAX_CONTROL_PAYLOAD, Id,
    v1::{NodePeer, PolicyAction, PolicySnapshot, RouteSnapshot},
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Serialize)]
struct Catalog {
    network_id: String,
    zone: String,
    valid_until_unix_seconds: i64,
    records: Vec<Record>,
    services: Vec<Service>,
}

#[derive(Clone, Serialize)]
struct Record {
    name: String,
    node_id: String,
    addresses: Vec<IpAddr>,
}

#[derive(Serialize)]
struct Service {
    name: String,
    host: String,
    resource_id: String,
    service_id: String,
    protocol: &'static str,
    ports: Vec<Port>,
}

struct Visibility {
    nodes: HashSet<Id>,
    grants: HashSet<Id>,
}

impl SessionStore {
    pub fn node_private_dns(&mut self, peer: &NodeCredential) -> Result<Vec<u8>> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = configuration::clock(&tx)?;
        let binding = peer.binding(&tx, now)?;
        let cert_end =
            i64::try_from(configuration::certificate_health(&peer.der)?.not_after_unix_seconds)?;
        let deadline = cert_end.min(binding.lease.unwrap_or(i64::MAX));
        let catalog =
            source_catalog(&tx, peer.net, peer.node, now, deadline)?.ok_or(EnrollError::Denied)?;
        let bytes = serde_json::to_vec(&catalog)?;
        ensure!(
            bytes.len() <= DEFAULT_MAX_CONTROL_PAYLOAD,
            "private DNS catalog exceeds response limit"
        );
        ensure!(
            configuration::clock(&tx)? < catalog.valid_until_unix_seconds,
            EnrollError::Denied
        );
        tx.commit()?;
        Ok(bytes)
    }
}

// Read the same permission-filtered view the node receives. The diagnostic
// caller has already authorized the network and does not impersonate an mTLS node.
pub(super) fn diagnostic_lookup(
    tx: &Transaction<'_>,
    net: Id,
    node: Id,
    now: i64,
    name: &str,
) -> Result<Option<(Vec<IpAddr>, i64)>> {
    let Some(catalog) = source_catalog(tx, net, node, now, i64::MAX)? else {
        return Ok(None);
    };
    ensure!(
        configuration::clock(tx)? < catalog.valid_until_unix_seconds,
        AccessError::Conflict
    );
    let name = name.strip_suffix('.').unwrap_or(name);
    let addresses = catalog
        .records
        .into_iter()
        .find(|record| record.name.eq_ignore_ascii_case(name))
        .map_or_else(Vec::new, |record| record.addresses);
    Ok(Some((addresses, catalog.valid_until_unix_seconds)))
}

fn source_catalog(
    tx: &Transaction<'_>,
    net: Id,
    node: Id,
    now: i64,
    deadline: i64,
) -> Result<Option<Catalog>> {
    let subject = tx.query_row(
        "SELECT user_id,lease_expires_at FROM nodes WHERE network_id=?1 AND id=?2 AND revoked_at IS NULL
         AND (enrollment_class<>'ephemeral' OR lease_expires_at IS NOT NULL)
         AND (lease_expires_at IS NULL OR lease_expires_at>?3)",
        (net.as_bytes(), node.as_bytes(), now),
        |r| Ok((r.get::<_, Option<[u8; 16]>>(0)?, r.get::<_, Option<i64>>(1)?)),
    ).optional()?;
    let Some((user, lease)) = subject else {
        return Ok(None);
    };
    let peers = configuration::peers(tx, net, now)?;
    let mut visibility = Visibility {
        nodes: HashSet::from([node]),
        grants: HashSet::new(),
    };
    if let Some(user) = user {
        let epoch = configuration::configuration_epoch(tx, net, 0)?;
        // Overlay-only view. Routes and manual ACLs cannot reveal peer names.
        let routes = RouteSnapshot {
            network_id: net.as_bytes().to_vec(),
            configuration_epoch: epoch,
            routes: Vec::new(),
        };
        let mut policy = PolicySnapshot {
            network_id: net.as_bytes().to_vec(),
            configuration_epoch: epoch,
            default_action: PolicyAction::Deny as i32,
            rules: Vec::new(),
        };
        managed_policy::apply(
            tx,
            (net, node),
            Id::new(user)?,
            now,
            &peers,
            &routes,
            &mut policy,
        )?;
        visibility.add_policy(&peers, policy)?;
    }
    catalog(
        tx,
        net,
        &peers,
        Some(&visibility),
        now,
        deadline.min(lease.unwrap_or(i64::MAX)),
    )
    .map(Some)
}

impl Visibility {
    fn add_policy(&mut self, peers: &[NodePeer], policy: PolicySnapshot) -> Result<()> {
        let mut by_address = HashMap::new();
        for peer in peers {
            let id = Id::from_slice(&peer.node_id)?;
            for address in &peer.overlay_addresses {
                ensure!(
                    by_address.insert(address.as_slice(), id).is_none(),
                    "duplicate overlay address"
                );
            }
        }
        for rule in policy
            .rules
            .into_iter()
            .filter(|r| r.action == PolicyAction::Accept as i32)
        {
            let Some(selector) = rule.selector else {
                continue;
            };
            self.grants.insert(Id::from_slice(&rule.rule_id)?);
            let ids = selector
                .destination_node_ids
                .iter()
                .map(|b| b.as_slice())
                .collect::<HashSet<_>>();
            for prefix in selector.destination_prefixes {
                if prefix.prefix_length as usize == 8 * prefix.address.len()
                    && let Some(id) = by_address.get(prefix.address.as_slice())
                    && ids.contains(id.as_bytes().as_slice())
                {
                    self.nodes.insert(*id);
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn admin_catalog(tx: &Transaction<'_>, net: Id, now: i64) -> Result<serde_json::Value> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?)",
        [net.as_bytes()],
        |r| r.get(0),
    )?;
    ensure!(exists, AccessError::Missing);
    let peers = configuration::peers(tx, net, now)?;
    let catalog = catalog(tx, net, &peers, None, now, i64::MAX)?;
    let bytes = serde_json::to_vec(&catalog)?;
    ensure!(
        bytes.len() <= DEFAULT_MAX_CONTROL_PAYLOAD,
        "private DNS catalog exceeds response limit"
    );
    ensure!(
        configuration::clock(tx)? < catalog.valid_until_unix_seconds,
        AccessError::Conflict
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn catalog(
    tx: &Transaction<'_>,
    net: Id,
    peers: &[NodePeer],
    visibility: Option<&Visibility>,
    now: i64,
    deadline: i64,
) -> Result<Catalog> {
    let zone = format!("{net}.laneway.internal");
    let (records, hosts) = records(peers, &zone, visibility)?;
    let mut expiry = deadline.min(now.saturating_add(30));
    let mut leases = tx.prepare("SELECT id,lease_expires_at FROM nodes WHERE network_id=?1 AND revoked_at IS NULL AND lease_expires_at>?2")?;
    let mut rows = leases.query((net.as_bytes(), now))?;
    while let Some(row) = rows.next()? {
        if hosts.contains_key(&Id::new(row.get(0)?)?) {
            expiry = expiry.min(row.get(1)?);
        }
    }
    let services = services(tx, net, &hosts, visibility)?;
    Ok(Catalog {
        network_id: net.to_string(),
        zone,
        valid_until_unix_seconds: expiry,
        records,
        services,
    })
}

fn dns_label(name: &str) -> String {
    let mut label = String::new();
    for c in name.chars().filter_map(|c| c.to_lowercase().next()) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            label.push(c);
        } else if !label.is_empty() && !label.ends_with('-') {
            label.push('-');
        }
        if label.len() == 30 {
            break;
        }
    }
    let label = label.trim_end_matches('-');
    if label.is_empty() {
        "node".into()
    } else {
        label.into()
    }
}

fn records(
    peers: &[NodePeer],
    zone: &str,
    visibility: Option<&Visibility>,
) -> Result<(Vec<Record>, HashMap<Id, String>)> {
    // Count aliases before filtering: a hidden colliding peer must not cause an alias to be published.
    let labels = peers.iter().map(|p| dns_label(&p.name)).collect::<Vec<_>>();
    let mut counts = HashMap::new();
    for label in &labels {
        *counts.entry(label).or_insert(0usize) += 1;
    }
    let mut records = Vec::new();
    let mut hosts = HashMap::new();
    for (peer, label) in peers.iter().zip(&labels) {
        let id = Id::from_slice(&peer.node_id)?;
        if visibility.is_some_and(|view| !view.nodes.contains(&id)) {
            continue;
        }
        let name = format!("n-{id}.{zone}");
        let addresses = peer
            .overlay_addresses
            .iter()
            .map(|address| -> Result<IpAddr> {
                if let Ok(a) = <[u8; 4]>::try_from(address.as_slice()) {
                    return Ok(Ipv4Addr::from(a).into());
                }
                let a = Ipv6Addr::from(<[u8; 16]>::try_from(address.as_slice())?);
                ensure!(
                    a.to_ipv4_mapped().is_none(),
                    "invalid mapped overlay address"
                );
                Ok(a.into())
            })
            .collect::<Result<Vec<_>>>()?;
        hosts.insert(id, name.clone());
        let mut entry = Record {
            name,
            node_id: id.to_string(),
            addresses,
        };
        records.push(entry.clone());
        if counts[label] == 1 {
            entry.name = format!("{label}.{zone}");
            records.push(entry);
        }
    }
    records.sort_unstable_by(|a, b| a.name.cmp(&b.name));
    Ok((records, hosts))
}

fn services(
    tx: &Transaction<'_>,
    net: Id,
    hosts: &HashMap<Id, String>,
    visibility: Option<&Visibility>,
) -> Result<Vec<Service>> {
    if visibility.is_some_and(|view| view.grants.is_empty()) {
        return Ok(Vec::new());
    }
    let mut stmt = tx.prepare("SELECT g.id,r.id,r.name,r.node_id,s.id,s.name,s.protocol,s.ports_sealed
        FROM access_resource_grants g JOIN access_resources r ON r.id=g.resource_id AND r.network_id=g.network_id
        JOIN access_services s ON s.id=g.service_id AND s.network_id=g.network_id
        WHERE g.network_id=? AND r.enabled=1 AND s.enabled=1 AND r.target_kind='node'
        ORDER BY g.id LIMIT 16385")?;
    let mut query = stmt.query([net.as_bytes()])?;
    let mut ports = service_ports::prepare(tx)?;
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let mut count = 0;
    while let Some(row) = query.next()? {
        count += 1;
        ensure!(count <= 16384, "too many private DNS resource grants");
        let grant = Id::new(row.get(0)?)?;
        if visibility.is_some_and(|view| !view.grants.contains(&grant)) {
            continue;
        }
        let node = Id::new(row.get(3)?)?;
        let Some(host) = hosts.get(&node) else {
            continue;
        };
        let resource = Id::new(row.get(1)?)?;
        let service = Id::new(row.get(4)?)?;
        if !seen.insert((resource, service)) {
            continue;
        }
        let proto = ServiceProtocol::from_stored(&row.get::<_, String>(6)?)?;
        ensure!(row.get::<_, bool>(7)?, "unsealed service");
        result.push(Service {
            name: format!(
                "{} / {}",
                row.get::<_, String>(2)?,
                row.get::<_, String>(5)?
            ),
            host: host.clone(),
            resource_id: resource.to_string(),
            service_id: service.to_string(),
            protocol: proto.name(),
            ports: service_ports::read(&mut ports, service, proto)?,
        });
    }
    result.sort_unstable_by(|a, b| {
        (&a.name, &a.resource_id, &a.service_id).cmp(&(&b.name, &b.resource_id, &b.service_id))
    });
    Ok(result)
}
