//! Bounded, network-scoped runtime configuration over authenticated TLS.
use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use laneway_protocol::{
    AuthenticatedIdentity, Id, Role, identity_from_certificate_der,
    v1::{
        CandidateExchangePolicy, ErrorCode, ExitNodePolicy, NodeConfiguration, RelayConfiguration,
        RouteKind, RouteSnapshot, controller_envelope::Body,
    },
};
use rusqlite::{Transaction, params};
use x509_parser::parse_x509_certificate;

use crate::{
    enrollment::{NodePeer, expire_ephemeral},
    policy,
    store::Store,
};

pub(crate) use crate::enrollment::EnrollmentError as SnapshotError;

mod data;
mod expiry;

type Outcome<T> = std::result::Result<T, SnapshotError>;

/// The caller must supply the leaf of a peer chain verified by TLS.
pub(crate) fn node(
    store: &mut Store,
    leaf_der: &[u8],
    known_epoch: u64,
    now: i64,
) -> Outcome<Body> {
    let peer = NodePeer::from_tls_leaf(leaf_der)?;
    let tx = store.enrollment_transaction()?;
    let authorized = peer.authenticate(&tx, now)?;
    let network = peer.network_id;
    let result = prepare(&tx, network, known_epoch, now, |epoch, deadline| {
        let revocations = policy::revoked_serials(&tx, network, now)?;
        let health = policy::certificate_health(leaf_der, &revocations)?;
        let mut routes = data::overlay_routes(&tx, network, now)?;
        routes.extend(data::approved_routes(&tx, network, now)?);
        ensure!(
            routes.len() <= data::MAX_ROUTES,
            "node route directory exceeds limit"
        );
        let (mut exit_nodes, mut seen) = (Vec::new(), HashSet::new());
        for route in &routes {
            if route.kind() == RouteKind::Exit && seen.insert(route.via_node_id.as_slice()) {
                exit_nodes.push(route.via_node_id.clone());
            }
        }
        let peers = data::node_peers(&tx, network, now)?;
        let overlay_addresses = peers
            .iter()
            .find(|candidate| candidate.node_id == peer.node_id.as_bytes())
            .context("authorized local node missing from active peer table")?
            .overlay_addresses
            .clone();
        Ok(Body::NodeConfiguration(NodeConfiguration {
            configuration_epoch: epoch,
            overlay_addresses,
            routes: Some(RouteSnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: epoch,
                routes,
            }),
            policy: Some(policy::policy_snapshot(&tx, network, epoch)?),
            enabled_capabilities: authorized.enabled_capabilities,
            valid_until_unix_seconds: deadline,
            revoked_certificate_serials: revocations,
            peers,
            relays: data::active_relays(&tx, network)?,
            candidate_exchange: Some(CandidateExchangePolicy {
                enabled: true,
                max_candidates: 8,
                candidate_ttl_seconds: 120,
            }),
            exit_policy: Some(ExitNodePolicy {
                authorized_node_ids: exit_nodes,
            }),
            certificate_health: Some(health),
            enrollment_class: authorized.class as i32,
            identity_lease_expires_at_unix_seconds: u64::try_from(
                authorized.lease_until.unwrap_or(0),
            )?,
        }))
    })?;
    tx.commit()?;
    result
}

/// Relay authority is explicitly registered by network and service ID. Legacy
/// relay rows without a service ID cannot authorize even a trusted peer leaf.
pub(crate) fn relay(
    store: &mut Store,
    leaf_der: &[u8],
    known_epoch: u64,
    now: i64,
) -> Outcome<Body> {
    let relay = relay_identity(leaf_der, now)?;
    let tx = store.enrollment_transaction()?;
    let registered: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM relays WHERE network_id=?1 AND service_id=?2 AND enabled=1)",
        params![
            relay.network_id.as_bytes().as_slice(),
            relay.subject_id.as_bytes().as_slice()
        ],
        |row| row.get(0),
    )?;
    if !registered {
        return Err(failure(
            403,
            ErrorCode::PermissionDenied,
            "relay is not authorized",
        ));
    }
    let network = relay.network_id;
    let result = prepare(&tx, network, known_epoch, now, |epoch, deadline| {
        let peers = data::relay_peers(
            data::overlay_routes(&tx, network, now)?,
            data::approved_routes(&tx, network, now)?,
        )?;
        let revocations = policy::revoked_serials(&tx, network, now)?;
        let health = policy::certificate_health(leaf_der, &revocations)?;
        Ok(Body::RelayConfiguration(RelayConfiguration {
            network_id: network.as_bytes().to_vec(),
            configuration_epoch: epoch,
            peers,
            policy: Some(policy::policy_snapshot(&tx, network, epoch)?),
            valid_until_unix_seconds: deadline,
            revoked_certificate_serials: revocations,
            certificate_health: Some(health),
        }))
    })?;
    tx.commit()?;
    result
}

fn relay_identity(der: &[u8], now: i64) -> Outcome<AuthenticatedIdentity> {
    let unauthenticated = || failure(401, ErrorCode::Unauthenticated, "authentication failed");
    let identity = identity_from_certificate_der(der).map_err(|_| unauthenticated())?;
    if identity.role != Role::Relay {
        return Err(unauthenticated());
    }
    let (remaining, certificate) = parse_x509_certificate(der).map_err(|_| unauthenticated())?;
    if !remaining.is_empty() {
        return Err(unauthenticated());
    }
    let validity = certificate.validity();
    if now < validity.not_before.timestamp() || now >= validity.not_after.timestamp() {
        return Err(failure(
            403,
            ErrorCode::PermissionDenied,
            "relay certificate is outside its validity interval",
        ));
    }
    Ok(identity)
}

fn prepare(
    db: &Transaction<'_>,
    network: Id,
    known_epoch: u64,
    now: i64,
    full: impl FnOnce(u64, u64) -> Result<Body>,
) -> Result<Outcome<Body>> {
    ensure!(now > 0, "controller snapshot time must be positive");
    expiry::expire_approved_routes(db, network, now)?;
    expire_ephemeral(db, now)?;
    // Bounded maintenance can leave this network with overdue rows.
    // Commit the pass, but do not publish a partially expired epoch or renew
    // a stale snapshot under its old epoch.
    if expiry::pending_expiry(db, network, now)? {
        return Ok(Err(failure(
            503,
            ErrorCode::ResourceExhausted,
            "expiry maintenance is in progress",
        )));
    }
    let epoch: u64 = db.query_row(
        "SELECT configuration_epoch FROM networks WHERE id=?1",
        params![network.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    ensure!(epoch != 0, "stored configuration epoch is zero");
    let deadline = expiry::lease_deadline(db, network, now)?;
    match policy::epoch_gate(known_epoch, epoch, deadline) {
        policy::EpochGate::Full => Ok(Ok(full(epoch, deadline)?)),
        policy::EpochGate::Unchanged(lease) => Ok(Ok(Body::ConfigurationLease(lease))),
        policy::EpochGate::Ahead => Ok(Err(failure(
            409,
            ErrorCode::StaleEpoch,
            "known configuration epoch is ahead of controller",
        ))),
    }
}

fn failure(status: u16, code: ErrorCode, detail: &'static str) -> SnapshotError {
    SnapshotError {
        status,
        code,
        detail,
        retryable: status >= 500,
    }
}

#[cfg(test)]
mod tests;
