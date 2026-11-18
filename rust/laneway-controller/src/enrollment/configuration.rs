//! Stable-v1 snapshots are built from one database view for one live TLS peer.
use super::{
    EnrollError, audit, maintenance, managed_policy, renewal::NodeCredential, snapshot_policy,
};
use crate::{SessionStore, check_snapshot, enrollment_tokens::EXIT};
use anyhow::{Context, Result, ensure};
use laneway_protocol::{DEFAULT_MAX_CONTROL_PAYLOAD, Id, policy::prefix_from_wire, v1::*};
use prost::Message;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;
use std::collections::HashSet;
use x509_parser::parse_x509_certificate;

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error("known epoch is ahead of controller")]
    StaleEpoch,
}

impl SessionStore {
    pub fn node_configuration(
        &mut self,
        peer: &NodeCredential,
        req: ConfigurationRequest,
        holds_exit_claim: bool,
        validity: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<controller_envelope::Body> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = clock(&tx)?;
        peer.binding(&tx, now)?;
        ensure!(!cancelled(), "configuration cancelled");
        maintain_configuration(&tx, peer.net, now)?;
        tx.commit()?;

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = clock(&tx)?;
        let bound = peer.binding(&tx, now)?;
        let is_exit = bound.lease.is_some() && bound.capabilities == EXIT as i64;
        ensure!(is_exit == holds_exit_claim, EnrollError::Denied);
        let (class, user): (String, Option<Vec<u8>>) = tx.query_row(
            "SELECT enrollment_class,user_id FROM nodes WHERE network_id=? AND id=?",
            (peer.net.as_bytes(), peer.node.as_bytes()),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let user = user.as_deref().map(Id::from_slice).transpose()?;
        let class = match class.as_str() {
            "durable" => EnrollmentClass::DurableNode,
            "remembered" => EnrollmentClass::RememberedUser,
            "ephemeral" => EnrollmentClass::EphemeralUser,
            _ => anyhow::bail!("invalid enrollment class"),
        };
        let epoch = configuration_epoch(&tx, peer.net, req.known_configuration_epoch)?;
        let heartbeat = if is_exit {
            Some(heartbeat(
                &tx,
                peer,
                req.ephemeral_exit_lease_generation,
                now,
            )?)
        } else {
            ensure!(
                req.ephemeral_exit_lease_generation == 0,
                EnrollError::Malformed("unexpected exit lease generation")
            );
            None
        };
        let health = certificate_health(&peer.der)?;
        let end = configuration_deadline(&tx, peer.net, now, validity, &health)?
            .min(heartbeat.map_or(i64::MAX, |(suspect, _)| suspect));
        ensure!(end > now, "configuration expired during maintenance");
        let mut lease = ConfigurationLease {
            configuration_epoch: epoch,
            valid_until_unix_seconds: end.try_into()?,
            ..Default::default()
        };
        if let Some((suspect, revoke)) = heartbeat {
            lease.ephemeral_exit_lease_generation = req.ephemeral_exit_lease_generation;
            lease.ephemeral_exit_suspect_at_unix_seconds = suspect.try_into()?;
            lease.ephemeral_exit_revoke_at_unix_seconds = revoke.try_into()?;
        }
        let snapshot = if req.known_configuration_epoch == epoch && heartbeat.is_none() {
            controller_envelope::Body::ConfigurationLease(lease)
        } else {
            let peers = peers(&tx, peer.net, now)?;
            let subject = peers
                .iter()
                .find(|p| p.node_id == peer.node.as_bytes())
                .context("node has no active peer record")?;
            let routes = routes(&tx, peer.net, epoch, now)?;
            let mut policy = snapshot_policy::compile(&tx, peer.net, epoch)?;
            let exits = if let Some(user) = user {
                managed_policy::apply(&tx, peer, user, now, &peers, &routes, &mut policy)?
            } else {
                let mut seen = HashSet::new();
                routes
                    .routes
                    .iter()
                    .filter(|r| r.kind == RouteKind::Exit as i32 && seen.insert(&r.via_node_id))
                    .map(|r| r.via_node_id.clone())
                    .collect()
            };
            let response = NodeConfiguration {
                configuration_epoch: epoch,
                overlay_addresses: subject.overlay_addresses.clone(),
                routes: Some(routes),
                policy: Some(policy),
                enabled_capabilities: bound.capabilities.try_into()?,
                valid_until_unix_seconds: lease.valid_until_unix_seconds,
                revoked_certificate_serials: revocations(&tx, peer.net, now)?,
                peers,
                relays: relays(&tx, peer.net)?,
                candidate_exchange: Some(CandidateExchangePolicy {
                    enabled: true,
                    max_candidates: 8,
                    candidate_ttl_seconds: 120,
                }),
                exit_policy: Some(ExitNodePolicy {
                    authorized_node_ids: exits,
                }),
                certificate_health: Some(health),
                enrollment_class: class as i32,
                identity_lease_expires_at_unix_seconds: bound
                    .lease
                    .unwrap_or_default()
                    .try_into()?,
                ephemeral_exit_lease_generation: lease.ephemeral_exit_lease_generation,
                ephemeral_exit_suspect_at_unix_seconds: lease
                    .ephemeral_exit_suspect_at_unix_seconds,
                ephemeral_exit_revoke_at_unix_seconds: lease.ephemeral_exit_revoke_at_unix_seconds,
            };
            ensure!(
                response.encoded_len() + 64 <= DEFAULT_MAX_CONTROL_PAYLOAD,
                "configuration exceeds frame limit"
            );
            controller_envelope::Body::NodeConfiguration(response)
        };
        ensure!(
            clock(&tx)? < end && !cancelled(),
            "configuration expired or cancelled before publication"
        );
        tx.commit()?;
        Ok(snapshot)
    }
}
pub(super) fn maintain_configuration(tx: &Transaction<'_>, net: Id, now: i64) -> Result<()> {
    maintenance::expire_routes(tx, net, now)?;
    maintenance::expire(tx, now)?;
    maintenance::expire_exits(tx, now)
}

pub(super) fn configuration_epoch(tx: &Transaction<'_>, net: Id, known: u64) -> Result<u64> {
    let epoch: u64 = tx
        .query_row(
            "SELECT configuration_epoch FROM networks WHERE id=?",
            [net.as_bytes()],
            |r| r.get::<_, i64>(0),
        )?
        .try_into()?;
    ensure!(epoch > 0, "invalid configuration epoch");
    ensure!(known <= epoch, ConfigurationError::StaleEpoch);
    Ok(epoch)
}

pub(super) fn configuration_deadline(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    validity: u64,
    health: &CertificateHealth,
) -> Result<i64> {
    // If bounded maintenance left excess work (or a deadline was crossed),
    // do not renew the old epoch. The next poll will sweep another batch.
    let next:Option<i64>=tx.query_row("SELECT min(deadline) FROM (
        SELECT valid_until AS deadline FROM routes WHERE network_id=?1 AND state='approved'
        UNION ALL SELECT lease_expires_at FROM nodes WHERE network_id=?1 AND revoked_at IS NULL
        UNION ALL SELECT revoke_at FROM ephemeral_exit_sessions WHERE network_id=?1 AND terminated_at IS NULL
    )",[net.as_bytes()],|r|r.get(0))?;
    let end = now
        .checked_add(i64::try_from(validity)?)
        .context("invalid configuration validity")?
        .min(next.unwrap_or(i64::MAX))
        .min(i64::try_from(health.not_after_unix_seconds)?);
    ensure!(end > now, "configuration expired during maintenance");
    Ok(end)
}

pub(super) fn clock(tx: &Transaction<'_>) -> Result<i64> {
    Ok(tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?)
}
pub(super) fn certificate_health(der: &[u8]) -> Result<CertificateHealth> {
    let (_, leaf) =
        parse_x509_certificate(der).map_err(|_| anyhow::anyhow!("invalid verified certificate"))?;
    let start = leaf.validity().not_before.timestamp();
    let end = leaf.validity().not_after.timestamp();
    ensure!(start > 0 && end > start, "invalid certificate validity");
    Ok(CertificateHealth {
        presented_serial: laneway_protocol::certificate_serial_from_der(der)?,
        not_after_unix_seconds: end.try_into()?,
        renew_after_unix_seconds: (start + (end - start) * 2 / 3).try_into()?,
        revoked: false,
    })
}
fn heartbeat(
    tx: &Transaction<'_>,
    peer: &NodeCredential,
    generation: u64,
    now: i64,
) -> Result<(i64, i64)> {
    let generation = i64::try_from(generation).map_err(|_| EnrollError::Denied)?;
    ensure!(generation > 0, EnrollError::Denied);
    let old: i64 = tx
        .query_row(
            "SELECT suspect_at FROM ephemeral_exit_sessions WHERE node_id=?1 AND network_id=?2
        AND generation=?3 AND terminated_at IS NULL AND last_heartbeat_at<=?4 AND revoke_at>?4",
            params![peer.node.as_bytes(), peer.net.as_bytes(), generation, now],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(EnrollError::Denied)?;
    ensure!(tx.execute("UPDATE ephemeral_exit_sessions SET last_heartbeat_at=?1,suspect_at=?1+20,revoke_at=?1+60 WHERE node_id=?2",
        params![now,peer.node.as_bytes()])?==1,EnrollError::Denied);
    if old <= now {
        audit(
            tx,
            peer.net,
            Some(peer.node),
            "ephemeral_exit.session.reconnect",
            ("node", peer.node),
            json!({"generation":generation}),
            now,
        )?
    }
    Ok((now + 20, now + 60))
}
fn peers(tx: &Transaction<'_>, net: Id, now: i64) -> Result<Vec<NodePeer>> {
    let mut stmt=tx.prepare("SELECT n.id,n.name,n.wireguard_public_key,
         (SELECT address FROM overlay_addresses a WHERE a.node_id=n.id AND a.network_id=n.network_id AND length(address)=4 AND released_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1),
         (SELECT address FROM overlay_addresses a WHERE a.node_id=n.id AND a.network_id=n.network_id AND length(address)=16 AND released_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1)
        FROM nodes n WHERE n.network_id=?1 AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2) ORDER BY n.name,n.id LIMIT 16385")?;
    let mut rows = stmt.query((net.as_bytes(), now))?;
    let mut result = Vec::new();
    while let Some(r) = rows.next()? {
        ensure!(result.len() < 16384, "too many peers");
        let id: Vec<u8> = r.get(0)?;
        Id::from_slice(&id)?;
        let key: Option<[u8; 32]> = r.get(2)?;
        if let Some(k) = key {
            ensure!(
                x25519_dalek::x25519([1; 32], k) != [0; 32],
                "invalid stored WireGuard key"
            )
        }
        let ipv4: Vec<u8> = r
            .get::<_, Option<Vec<u8>>>(3)?
            .context("peer missing IPv4 assignment")?;
        let mut addresses = vec![ipv4];
        if let Some(v6) = r.get::<_, Option<Vec<u8>>>(4)? {
            prefix_from_wire(IpPrefix {
                address: v6.clone(),
                prefix_length: 128,
            })?;
            addresses.push(v6)
        }
        result.push(NodePeer {
            node_id: id,
            name: r.get(1)?,
            overlay_addresses: addresses,
            wireguard_public_key: key.map_or_else(Vec::new, |v| v.to_vec()),
        })
    }
    Ok(result)
}
const OVERLAY_ROUTES:&str="SELECT a.id,a.node_id,a.address,a.prefix_length,'overlay','none',0
        FROM overlay_addresses a JOIN nodes n ON n.id=a.node_id AND n.network_id=a.network_id
        WHERE a.network_id=?1 AND a.released_at IS NULL AND n.revoked_at IS NULL
          AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2) ORDER BY a.prefix_length DESC,a.address,a.id LIMIT 16385";
const APPROVED_ROUTES:&str="SELECT r.id,r.node_id,r.prefix_address,r.prefix_length,r.kind,r.mode,r.metric
        FROM routes r JOIN nodes n ON n.id=r.node_id AND n.network_id=r.network_id WHERE r.network_id=?1 AND r.state='approved'
        AND (r.valid_until IS NULL OR r.valid_until>?2) AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2)
        ORDER BY r.prefix_length DESC,r.metric,r.id LIMIT 16385";

fn routes(tx: &Transaction<'_>, net: Id, epoch: u64, now: i64) -> Result<RouteSnapshot> {
    let mut result = Vec::new();
    read_routes(tx, net, now, OVERLAY_ROUTES, &mut result)?;
    read_routes(tx, net, now, APPROVED_ROUTES, &mut result)?;
    Ok(RouteSnapshot {
        network_id: net.as_bytes().to_vec(),
        configuration_epoch: epoch,
        routes: result,
    })
}

pub(super) fn advertised_routes(tx: &Transaction<'_>, net: Id, now: i64) -> Result<Vec<Route>> {
    let mut result = Vec::new();
    read_routes(tx, net, now, APPROVED_ROUTES, &mut result)?;
    Ok(result)
}

fn read_routes(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    sql: &str,
    result: &mut Vec<Route>,
) -> Result<()> {
    let mut stmt = tx.prepare(sql)?;
    let mut rows = stmt.query((net.as_bytes(), now))?;
    while let Some(r) = rows.next()? {
        ensure!(result.len() < 16384, "too many routes");
        let id: Vec<u8> = r.get(0)?;
        let via: Vec<u8> = r.get(1)?;
        Id::from_slice(&id)?;
        Id::from_slice(&via)?;
        let destination = IpPrefix {
            address: r.get(2)?,
            prefix_length: r.get(3)?,
        };
        prefix_from_wire(destination.clone())?;
        let (kind, mode) = match (
            r.get::<_, String>(4)?.as_str(),
            r.get::<_, String>(5)?.as_str(),
        ) {
            ("overlay", "none")
                if usize::try_from(destination.prefix_length)? == destination.address.len() * 8 =>
            {
                (RouteKind::Overlay, RouteAdvertisementMode::Unspecified)
            }
            ("subnet", "nat") => (RouteKind::Subnet, RouteAdvertisementMode::Nat),
            ("subnet", "routed") => (RouteKind::Subnet, RouteAdvertisementMode::Routed),
            ("exit", "nat") if destination.prefix_length == 0 => {
                (RouteKind::Exit, RouteAdvertisementMode::Nat)
            }
            ("exit", "routed") if destination.prefix_length == 0 => {
                (RouteKind::Exit, RouteAdvertisementMode::Routed)
            }
            _ => anyhow::bail!("invalid route kind or forwarding mode"),
        };
        result.push(Route {
            destination: Some(destination),
            via_node_id: via,
            kind: kind as i32,
            metric: r.get(6)?,
            route_id: id,
            mode: mode as i32,
        });
    }
    Ok(())
}
pub(super) fn revocations(tx: &Transaction<'_>, net: Id, now: i64) -> Result<Vec<Vec<u8>>> {
    let mut stmt=tx.prepare("SELECT serial FROM certificates WHERE network_id=? AND revoked_at IS NOT NULL AND not_after>? ORDER BY serial LIMIT 16385")?;
    let serials = stmt
        .query_map((net.as_bytes(), now), |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        serials.len() <= 16384
            && serials
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 32 && s[0] != 0),
        "invalid or oversized certificate revocations"
    );
    Ok(serials)
}
fn relays(tx: &Transaction<'_>, net: Id) -> Result<Vec<RelayEndpoint>> {
    let mut stmt=tx.prepare("SELECT service_id,name,endpoint FROM relays WHERE network_id=? AND enabled=1 AND service_id IS NOT NULL ORDER BY id LIMIT 33")?;
    let values = stmt
        .query_map([net.as_bytes()], |r| {
            Ok(RelayEndpoint {
                service_id: r.get(0)?,
                name: r.get(1)?,
                endpoint: r.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(values.len() <= 32, "too many relays");
    for r in &values {
        Id::from_slice(&r.service_id)?;
    }
    Ok(values)
}
