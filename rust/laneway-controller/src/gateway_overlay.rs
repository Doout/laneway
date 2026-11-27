//! A managed gateway's token, route and generated packet policy share one
//! network-scoped identity. The operator's manual ACL history stays independent.
use crate::{bootstrap_discovery::Discovery, enrollment, enrollment_tokens::ROUTER};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::Ipv4Net;
use laneway_protocol::{
    Id,
    v1::{
        IpPrefix, IpProtocol, PolicyAction, PolicyRule, PolicySnapshot, PortRange, TrafficSelector,
    },
};
use rusqlite::{OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{net::Ipv4Addr, path::Path};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub struct GatewaySpec {
    pub gateway: Id,
    pub network: Id,
    pub client: Id,
    pub address: Ipv4Addr,
    pub port: u16,
}

const LABEL: &str = "managed-twingate-v1";

/// The current gateway is a singleton per network. Its token record can be
/// found by primary key on the controller/relay polling path, independent of
/// the number of historical enrollment records in that network.
fn token_id(network: Id) -> Id {
    let mut digest = Sha256::new_with_prefix(b"laneway/managed-twingate/v1/network-token/");
    digest.update(network.as_bytes());
    Id::from_slice(&digest.finalize()[..16]).expect("nonzero derived ID")
}

impl GatewaySpec {
    fn key(&self, purpose: &[u8]) -> Id {
        let mut digest = Sha256::new_with_prefix(b"laneway/managed-twingate/v1/");
        digest.update(purpose);
        digest.update(self.network.as_bytes());
        digest.update(self.gateway.as_bytes());
        // Changing the allowed caller preserves the enrolled service and route.
        // The current caller is bound separately in the token record's label.
        digest.update(self.address.octets());
        digest.update(self.port.to_be_bytes());
        Id::from_slice(&digest.finalize()[..16]).expect("nonzero derived ID")
    }

    fn route_id(&self, node: Id) -> Id {
        // A replacement enrollment gets a new route identity. Inventory which
        // references an old, withdrawn route remains attached to that record.
        self.key(node.as_bytes())
    }

    fn label(&self) -> String {
        format!(
            "{LABEL}:{}:{}:{}:{}",
            self.gateway, self.client, self.address, self.port
        )
    }

    // A manually issued invitation can have any label, but its randomly
    // generated ID cannot be chosen to match this spec's integration ID.
    fn from_label(network: Id, label: &str) -> Option<(Self, i64)> {
        let (label, lease) = label.split_once('/').unwrap_or((label, "0"));
        let deadline = lease.parse::<i64>().ok()?;
        let mut fields = label.split(':');
        if fields.next()? != LABEL {
            return None;
        }
        let spec = Self {
            network,
            gateway: fields.next()?.parse().ok()?,
            client: fields.next()?.parse().ok()?,
            address: fields.next()?.parse().ok()?,
            port: fields.next()?.parse().ok()?,
        };
        fields.next().is_none().then_some((spec, deadline))
    }
}

fn transaction<T>(
    path: &Path,
    action: impl FnOnce(&Transaction<'_>, i64) -> Result<T>,
) -> Result<T> {
    let mut db = crate::open_existing(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::check_snapshot(&tx)?;
    let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
    let result = action(&tx, now)?;
    tx.commit()?;
    Ok(result)
}

#[derive(Debug, thiserror::Error)]
#[error(
    "Existing approved host route {route_id} must be withdrawn before this gateway can publish its route."
)]
pub struct GatewayRouteConflict {
    pub route_id: Id,
}

fn check(
    tx: &Transaction<'_>,
    spec: &GatewaySpec,
    now: i64,
) -> Result<Option<GatewayRouteConflict>> {
    ensure!(
        spec.port != 0 && spec.address.is_private(),
        "gateway requires an exact private IPv4 host and TCP port"
    );
    let (pool, length): ([u8; 4], u8) = tx
        .query_row(
            "SELECT ipv4_address,ipv4_prefix_length FROM networks WHERE id=?",
            [spec.network.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .context("gateway network does not exist")?;
    ensure!(
        !Ipv4Net::new(pool.into(), length)?.contains(&spec.address),
        "resource conflicts with overlay pool"
    );
    ensure!(
        client_ip(tx, spec, now)?.is_some(),
        "selected client is inactive or belongs to another network"
    );
    let mut stmt = tx.prepare(
        "SELECT prefix_address,prefix_length,state,id,node_id FROM routes WHERE network_id=?1
         AND length(prefix_address)=4 AND kind<>'exit' AND
         (state='approved' OR (state='advertised' AND prefix_length=32))
         AND (valid_until IS NULL OR valid_until>?2)",
    )?;
    let mut rows = stmt.query(params![spec.network.as_bytes(), now])?;
    let mut conflict = None;
    while let Some(row) = rows.next()? {
        let route = Id::new(row.get(3)?)?;
        if route == spec.route_id(Id::new(row.get(4)?)?) {
            continue;
        }
        let ip: [u8; 4] = row.get(0)?;
        let prefix = Ipv4Net::new(ip.into(), row.get(1)?)?;
        if prefix.prefix_len() == 32
            && prefix.addr() == spec.address
            && row.get_ref(2)?.as_str()? == "approved"
        {
            ensure!(
                conflict.is_none(),
                "multiple competing approved host routes"
            );
            conflict = Some(GatewayRouteConflict { route_id: route });
            continue;
        }
        ensure!(
            !prefix.contains(&spec.address),
            "resource conflicts with an existing route {prefix}"
        );
    }
    Ok(conflict)
}

fn client_ip(tx: &Transaction<'_>, s: &GatewaySpec, now: i64) -> Result<Option<[u8; 4]>> {
    Ok(tx.query_row("SELECT a.address FROM nodes n JOIN overlay_addresses a ON a.node_id=n.id AND a.network_id=n.network_id
        WHERE n.network_id=?1 AND n.id=?2 AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?3)
        AND (n.user_id IS NULL OR EXISTS(SELECT 1 FROM access_users u WHERE u.network_id=n.network_id AND u.id=n.user_id AND u.enabled=1))
        AND a.released_at IS NULL AND length(a.address)=4", params![s.network.as_bytes(),s.client.as_bytes(),now], |r|r.get(0)).optional()?)
}

pub fn preflight(database: &Path, spec: &GatewaySpec) -> Result<Option<GatewayRouteConflict>> {
    transaction(database, |tx, now| check(tx, spec, now))
}

pub fn issue(
    database: &Path,
    spec: &GatewaySpec,
    discovery: &Discovery,
) -> Result<Zeroizing<String>> {
    transaction(database, |tx, now| {
        check(tx, spec, now)?;
        let (name, code) = issue_grant(tx, spec, now)?;
        discovery.connector_setup(tx, spec.network, &name, &code)
    })
}

fn issue_grant(
    tx: &Transaction<'_>,
    spec: &GatewaySpec,
    now: i64,
) -> Result<(String, Zeroizing<String>)> {
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::fill(raw.as_mut())?;
    let hash: [u8; 32] = Sha256::digest(raw.as_slice()).into();
    let key = token_id(spec.network);
    // Fresh names allow a new deployment after revocation; names are never used for authorization.
    let name = format!("twingate-{}-{}", spec.gateway, hex::encode(&hash[..4]));
    let changed = tx.execute("INSERT INTO enrollment_tokens(id,network_id,token_hash,label,expires_at,created_at,requested_name,enabled_capabilities)
        VALUES(?1,?2,?3,?4,?5+600,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET
        token_hash=excluded.token_hash,expires_at=excluded.expires_at,created_at=excluded.created_at,requested_name=excluded.requested_name
        WHERE enrollment_tokens.network_id=excluded.network_id AND enrollment_tokens.label=excluded.label AND enrollment_tokens.consumed_at IS NULL",
        params![key.as_bytes(),spec.network.as_bytes(),hash,spec.label(),now,name,ROUTER as i64])?;
    ensure!(changed == 1, "gateway is already enrolled");
    audit(tx, spec, "twingate.gateway.issue", now)?;
    Ok((name, Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_slice()))))
}

fn audit(tx: &Transaction<'_>, spec: &GatewaySpec, action: &str, now: i64) -> Result<()> {
    enrollment::audit(
        tx,
        spec.network,
        None,
        action,
        ("twingate_gateway", spec.gateway),
        json!({"client_id":spec.client.to_string(),"address":spec.address,"tcp_port":spec.port}),
        now,
    )
}

fn owned_node(tx: &Transaction<'_>, s: &GatewaySpec) -> Result<Option<Id>> {
    tx.query_row("SELECT consumed_by FROM enrollment_tokens WHERE network_id=?1 AND id=?2 AND (label=?3 OR label GLOB ?3 || '/*') AND consumed_by IS NOT NULL",
        params![s.network.as_bytes(),token_id(s.network).as_bytes(),s.label()], |r|r.get::<_,[u8;16]>(0))
        .optional()?.map(Id::new).transpose().map_err(Into::into)
}

pub fn activate(database: &Path, spec: &GatewaySpec) -> Result<bool> {
    transaction(database, |tx, now| {
        let Some(node) = owned_node(tx, spec)? else {
            return Ok(false);
        };
        let online:bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM nodes n JOIN node_locations l ON l.node_id=n.id
            WHERE n.id=?1 AND n.network_id=?2 AND n.revoked_at IS NULL AND n.enabled_capabilities=?3
            AND l.observed_at BETWEEN ?4-90 AND ?4 AND EXISTS(SELECT 1 FROM certificates c WHERE c.network_id=n.network_id
            AND c.node_id=n.id AND c.revoked_at IS NULL AND c.not_before<=?4 AND c.not_after>?4))",
            params![node.as_bytes(),spec.network.as_bytes(),ROUTER as i64,now],|r|r.get(0))?;
        if !online {
            withdraw(tx, spec, node, now)?;
            return Ok(false);
        }
        if let Some(conflict) = check(tx, spec, now)? {
            return Err(conflict.into());
        }
        let key = spec.route_id(node);
        let inserted = tx.execute("INSERT INTO routes(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,created_at,approved_at)
            VALUES(?1,?2,?3,?4,32,'subnet','nat',100,'approved',?5,?5)
            ON CONFLICT(id) DO UPDATE SET state='approved',approved_at=?5,withdrawn_at=NULL
            WHERE routes.network_id=?2 AND routes.node_id=?3 AND routes.prefix_address=?4 AND routes.prefix_length=32
            AND routes.kind='subnet' AND routes.mode='nat' AND routes.state='withdrawn'",
            params![key.as_bytes(),spec.network.as_bytes(),node.as_bytes(),spec.address.octets(),now])?;
        if inserted > 0 {
            enrollment::bump(tx, spec.network)?;
            audit(tx, spec, "twingate.gateway.publish", now)?;
        }
        ensure!(
            published(tx, spec, node)?,
            "managed route ownership or state changed"
        );
        // The route target is immutable in the public schema. Keep the
        // renewable publication lease on its consumed enrollment record.
        let label = spec.label();
        tx.execute(
            "UPDATE enrollment_tokens SET label=?1 || '/' || (?2+90) WHERE id=?3 AND network_id=?4 AND consumed_by=?5
             AND (label=?1 OR (label GLOB ?1 || '/*' AND CAST(substr(label,length(?1)+2) AS INTEGER) < ?2+60))",
            params![label,now,token_id(spec.network).as_bytes(),spec.network.as_bytes(),node.as_bytes()],
        )?;
        Ok(true)
    })
}

fn published(tx: &Transaction<'_>, s: &GatewaySpec, node: Id) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM routes WHERE id=?1 AND network_id=?2 AND node_id=?3 AND prefix_address=?4
        AND prefix_length=32 AND kind='subnet' AND mode='nat' AND state='approved' AND valid_until IS NULL)",
        params![s.route_id(node).as_bytes(),s.network.as_bytes(),node.as_bytes(),s.address.octets()], |r|r.get(0))?)
}

fn withdraw(tx: &Transaction<'_>, s: &GatewaySpec, node: Id, now: i64) -> Result<()> {
    if tx.execute("UPDATE routes SET state='withdrawn',withdrawn_at=?5 WHERE id=?1 AND network_id=?2 AND node_id=?3 AND prefix_address=?4
        AND prefix_length=32 AND kind='subnet' AND mode='nat' AND state='approved'",
        params![s.route_id(node).as_bytes(),s.network.as_bytes(),node.as_bytes(),s.address.octets(),now])? > 0 {
        enrollment::bump(tx,s.network)?;
        audit(tx,s,"twingate.gateway.withdraw",now)?;
    }
    Ok(())
}

/// Move the grant between callers without issuing a new service identity.
pub fn change_client(database: &Path, previous: &GatewaySpec, client: Id) -> Result<()> {
    let desired = GatewaySpec {
        client,
        ..*previous
    };
    transaction(database, |tx, now| {
        // The external owner journal may retry after the SQLite commit.
        if owned_node(tx, &desired)?.is_some() {
            return Ok(());
        }
        let node = owned_node(tx, previous)?.context("gateway caller binding changed")?;
        ensure!(
            client != node,
            "a dedicated gateway cannot be its own caller"
        );
        ensure!(
            published(tx, previous, node)?,
            "gateway is not currently published"
        );
        if let Some(conflict) = check(tx, &desired, now)? {
            return Err(conflict.into());
        }
        let changed = tx.execute(
            "UPDATE enrollment_tokens SET label=?1 || substr(label,length(?4)+1) WHERE id=?2 AND network_id=?3
             AND (label=?4 OR label GLOB ?4 || '/*') AND consumed_by=?5",
            params![desired.label(), token_id(previous.network).as_bytes(), previous.network.as_bytes(),
                previous.label(), node.as_bytes()],
        )?;
        ensure!(changed == 1, "gateway caller binding changed");
        enrollment::bump(tx, desired.network)?;
        audit(tx, &desired, "twingate.gateway.change_client", now)
    })
}

pub fn deactivate(database: &Path, spec: &GatewaySpec) -> Result<()> {
    transaction(database, |tx, now| {
        if let Some(node) = owned_node(tx, spec)? {
            withdraw(tx, spec, node, now)?;
        }
        Ok(())
    })
}

pub fn cleanup(database: &Path, s: &GatewaySpec) -> Result<()> {
    transaction(database, |tx, now| {
        if let Some(node) = owned_node(tx, s)? {
            withdraw(tx, s, node, now)?;
            let scope = params![now, s.network.as_bytes(), node.as_bytes()];
            tx.execute("UPDATE nodes SET revoked_at=?1 WHERE network_id=?2 AND id=?3 AND revoked_at IS NULL",scope)?;
            tx.execute("UPDATE certificates SET revoked_at=?1,revocation_reason='managed gateway removed' WHERE network_id=?2 AND node_id=?3 AND revoked_at IS NULL",scope)?;
            tx.execute("UPDATE overlay_addresses SET released_at=?1 WHERE network_id=?2 AND node_id=?3 AND released_at IS NULL",scope)?;
            enrollment::bump(tx, s.network)?;
        }
        let removed = tx.execute(
            "DELETE FROM enrollment_tokens WHERE network_id=?1 AND id=?2 AND (label=?3 OR label GLOB ?3 || '/*')",
            params![s.network.as_bytes(), token_id(s.network).as_bytes(), s.label()],
        )?;
        if removed != 0 {
            audit(tx, s, "twingate.gateway.remove", now)?;
        }
        Ok(())
    })
}

fn enrolled_gateway(tx: &Transaction<'_>, network: Id) -> Result<Option<(GatewaySpec, Id, i64)>> {
    let row: Option<(String, [u8; 16])> = tx
        .query_row(
            "SELECT t.label,t.consumed_by FROM enrollment_tokens t JOIN nodes n
         ON n.network_id=t.network_id AND n.id=t.consumed_by
         WHERE t.network_id=?1 AND t.id=?2 AND n.revoked_at IS NULL",
            params![network.as_bytes(), token_id(network).as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(label, node)| {
        let (spec, deadline) =
            GatewaySpec::from_label(network, &label).context("invalid managed gateway binding")?;
        Ok((spec, Id::new(node)?, deadline))
    })
    .transpose()
}

/// Configuration service owns a second expiry check. A stalled reconciler
/// cannot renew the old forwarding authority on either a node or a relay.
pub(crate) fn expire_publications(tx: &Transaction<'_>, network: Id, now: i64) -> Result<()> {
    if let Some((spec, node, deadline)) = enrolled_gateway(tx, network)?
        && deadline <= now
    {
        withdraw(tx, &spec, node, now)?;
    }
    Ok(())
}

pub(crate) fn publication_deadline(tx: &Transaction<'_>, network: Id) -> Result<i64> {
    if let Some((spec, node, deadline)) = enrolled_gateway(tx, network)?
        && published(tx, &spec, node)?
    {
        return Ok(deadline);
    }
    Ok(i64::MAX)
}

// Apply at the final composition boundary on every node and relay. Even a
// higher-level user/network grant cannot expand access to the dedicated peer.
pub(crate) fn apply_policy(
    tx: &Transaction<'_>,
    network: Id,
    policy: &mut PolicySnapshot,
) -> Result<()> {
    let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
    let Some((s, node, deadline)) = enrolled_gateway(tx, network)? else {
        return Ok(());
    };
    let mut generated = Vec::with_capacity(4);
    if deadline > now
        && published(tx, &s, node)?
        && let Some(ip) = client_ip(tx, &s, now)?
    {
        generated.push(rule(
            &s,
            b"forward",
            PolicyAction::Accept,
            flow(s.client, node, ip, s.address.octets(), s.port, s.port),
        ));
        // Wire v1 supports destination ports. Return traffic is confined to
        // the resource /32, the enrolled gateway, client /32 and unprivileged TCP ports.
        generated.push(rule(
            &s,
            b"return",
            PolicyAction::Accept,
            flow(node, s.client, s.address.octets(), ip, 1024, u16::MAX),
        ));
    }
    for (key, source) in [
        (b"deny-out".as_slice(), true),
        (b"deny-in".as_slice(), false),
    ] {
        let mut selector = TrafficSelector {
            ip_protocol: IpProtocol::Any as i32,
            ..Default::default()
        };
        if source {
            selector.source_node_ids.push(node.as_bytes().to_vec())
        } else {
            selector.destination_node_ids.push(node.as_bytes().to_vec())
        }
        generated.push(rule(&s, key, PolicyAction::Deny, selector));
    }
    ensure!(
        generated.len() + policy.rules.len() <= 4096,
        "gateway policy exceeds rule limit"
    );
    policy.rules.sort_unstable_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    for (index, r) in policy.rules.iter_mut().enumerate() {
        r.priority = u32::try_from(index)? + 2;
    }
    generated.append(&mut policy.rules);
    policy.rules = generated;
    Ok(())
}

fn rule(
    s: &GatewaySpec,
    key: &[u8],
    action: PolicyAction,
    selector: TrafficSelector,
) -> PolicyRule {
    PolicyRule {
        rule_id: s.key(key).as_bytes().to_vec(),
        priority: u32::from(action == PolicyAction::Deny),
        action: action as i32,
        selector: Some(selector),
        description: "Managed Twingate gateway".into(),
    }
}

fn flow(
    source: Id,
    destination: Id,
    src: [u8; 4],
    dst: [u8; 4],
    first: u16,
    last: u16,
) -> TrafficSelector {
    let host = |ip: [u8; 4]| IpPrefix {
        address: ip.to_vec(),
        prefix_length: 32,
    };
    TrafficSelector {
        source_node_ids: vec![source.as_bytes().to_vec()],
        destination_node_ids: vec![destination.as_bytes().to_vec()],
        source_prefixes: vec![host(src)],
        destination_prefixes: vec![host(dst)],
        ip_protocol: IpProtocol::Tcp as i32,
        destination_ports: vec![PortRange {
            first: first.into(),
            last: last.into(),
        }],
    }
}

#[cfg(all(test, unix))]
mod tests;
