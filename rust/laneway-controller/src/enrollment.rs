//! Enrollment uses the Go database schema and commits a one-time token, its
//! node, addresses, certificate, and audit records as a single transaction.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::{
    Id,
    v1::{CertificateChain, EnrollmentClass, EnrollmentRequest, EnrollmentResponse, ErrorCode},
};
use rusqlite::{ErrorCode as SqliteCode, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

use crate::store::Store;

mod authority;
mod renewal;
mod tokens;
pub(crate) use authority::EnrollmentAuthority;
pub(crate) use renewal::{NodePeer, renew};
pub(crate) use tokens::{IssueRequest, issue_token};

const SUBNET_ROUTER: i64 = 1 << 3;
const EXIT_NODE: i64 = 1 << 4;

#[derive(Debug)]
pub(crate) struct EnrollmentError {
    pub(crate) status: u16,
    pub(crate) code: ErrorCode,
    pub(crate) detail: &'static str,
    pub(crate) retryable: bool,
}

impl EnrollmentError {
    const fn new(status: u16, code: ErrorCode, detail: &'static str) -> Self {
        Self {
            status,
            code,
            detail,
            retryable: status >= 500,
        }
    }

    fn malformed(detail: &'static str) -> Self {
        Self::new(400, ErrorCode::Malformed, detail)
    }

    fn denied(detail: &'static str) -> Self {
        Self::new(403, ErrorCode::PermissionDenied, detail)
    }

    fn conflict(detail: &'static str) -> Self {
        Self::new(409, ErrorCode::PermissionDenied, detail)
    }

    fn invalid_token() -> Self {
        Self::new(401, ErrorCode::Unauthenticated, "authentication failed")
    }
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(self.detail)
    }
}
impl std::error::Error for EnrollmentError {}

impl From<anyhow::Error> for EnrollmentError {
    fn from(_: anyhow::Error) -> Self {
        Self::new(500, ErrorCode::Internal, "internal controller error")
    }
}
impl From<rusqlite::Error> for EnrollmentError {
    fn from(error: rusqlite::Error) -> Self {
        if matches!(
            error.sqlite_error_code(),
            Some(SqliteCode::ConstraintViolation)
        ) {
            Self::conflict("request conflicts with controller state")
        } else {
            anyhow::Error::from(error).into()
        }
    }
}

struct Token {
    id: Vec<u8>,
    network: Vec<u8>,
    expires: i64,
    consumed: Option<i64>,
    class: String,
    lifetime: Option<i64>,
    name: Option<String>,
    capabilities: i64,
}

fn clock() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

pub(crate) fn enroll(
    store: &mut Store,
    issuer: &EnrollmentAuthority,
    request: EnrollmentRequest,
    canceled: &AtomicBool,
) -> Result<EnrollmentResponse, EnrollmentError> {
    enroll_with_clock(store, issuer, request, clock, || {
        canceled.load(Ordering::Acquire)
    })
}

fn enroll_with_clock(
    store: &mut Store,
    issuer: &EnrollmentAuthority,
    mut request: EnrollmentRequest,
    now: impl Fn() -> Result<i64>,
    canceled: impl Fn() -> bool,
) -> Result<EnrollmentResponse, EnrollmentError> {
    // Preserve the Go validation order and remove the only plaintext token copy
    // in the decoded request before opening SQLite transactions.
    let secret = Zeroizing::new(std::mem::take(&mut request.enrollment_token));
    let key = authority::public_key(&request.pkcs10_csr_der)?;
    let wireguard = parse_wireguard(&request.wireguard_public_key)?;
    let network = if request.expected_network_id.is_empty() {
        None
    } else {
        Some(Id::from_slice(&request.expected_network_id).map_err(|_| {
            EnrollmentError::malformed("expected_network_id must be a nonzero NetworkID")
        })?)
    };
    let class = EnrollmentClass::try_from(request.expected_enrollment_class)
        .map_err(|_| EnrollmentError::malformed("invalid expected enrollment class"))?;
    if class != EnrollmentClass::Unspecified && network.is_none() {
        return Err(EnrollmentError::malformed(
            "expected_enrollment_class requires expected_network_id",
        ));
    }
    if wireguard.is_some() && (class == EnrollmentClass::Unspecified || network.is_none()) {
        return Err(EnrollmentError::malformed(
            "wireguard_public_key requires authenticated expected_network_id and expected_enrollment_class",
        ));
    }
    let hash = token_hash(&secret)?;
    drop(secret);

    if canceled() {
        return Err(anyhow::anyhow!("enrollment request canceled").into());
    }
    // Lease revocation is independent of whether this token succeeds.
    expire(store.enrollment_transaction()?, now()?)?;
    let tx = store.enrollment_transaction()?;
    let now = now()?;
    let token = tx.query_row(
        "SELECT id,network_id,expires_at,consumed_at,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities
         FROM enrollment_tokens WHERE token_hash=?1",
        [hash.as_slice()],
        |row| Ok(Token { id: row.get(0)?, network: row.get(1)?, expires: row.get(2)?, consumed: row.get(3)?,
            class: row.get(4)?, lifetime: row.get(5)?, name: row.get(6)?, capabilities: row.get(7)? }),
    ).optional()?.ok_or_else(EnrollmentError::invalid_token)?;
    if token.consumed.is_some() {
        return Err(EnrollmentError::conflict(
            "enrollment code has already been used",
        ));
    }
    if now >= token.expires {
        return Err(EnrollmentError::new(
            401,
            ErrorCode::Unauthenticated,
            "enrollment code has expired",
        ));
    }
    let token_id = Id::from_slice(&token.id).context("invalid persisted token ID")?;
    let network_id = Id::from_slice(&token.network).context("invalid persisted token network")?;
    if network.is_some_and(|network| network != network_id) {
        return Err(EnrollmentError::denied(
            "enrollment code belongs to a different network",
        ));
    }
    let name = match (request.requested_name.as_str(), token.name.as_deref()) {
        ("", Some(bound)) => bound,
        (requested, Some(bound)) if requested != bound => {
            return Err(EnrollmentError::denied(
                "enrollment code is bound to a different device name",
            ));
        }
        (requested, _) => requested,
    };
    if !valid_name(name) {
        return Err(EnrollmentError::malformed("invalid request"));
    }
    let enrolled_class = stored_class(&token.class)?;
    if class != EnrollmentClass::Unspecified && class != enrolled_class {
        return Err(EnrollmentError::denied(
            "enrollment code has a different enrollment class",
        ));
    }
    if token.capabilities & !(SUBNET_ROUTER | EXIT_NODE) != 0 {
        return Err(anyhow::anyhow!("invalid persisted token capabilities").into());
    }
    let lease = match (enrolled_class, token.lifetime) {
        (EnrollmentClass::EphemeralUser, Some(lifetime @ 300..=86400)) => {
            let active: i64 = tx.query_row(
                "SELECT count(*) FROM nodes WHERE network_id=?1 AND enrollment_class='ephemeral' AND revoked_at IS NULL AND lease_expires_at>?2",
                params![network_id.as_bytes(), now], |r| r.get(0),
            )?;
            if active >= 4096 {
                return Err(EnrollmentError::conflict(
                    "request conflicts with controller state",
                ));
            }
            Some(
                now.checked_add(lifetime)
                    .context("ephemeral lease overflow")?,
            )
        }
        (EnrollmentClass::EphemeralUser, _) | (_, Some(_)) => {
            return Err(anyhow::anyhow!("invalid persisted token lifetime").into());
        }
        _ => None,
    };
    let node = random_id()?;
    tx.execute(
        "INSERT INTO nodes (id,network_id,name,enabled_capabilities,created_at,enrollment_class,lease_expires_at,wireguard_public_key)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![node.as_bytes(), network_id.as_bytes(), name, token.capabilities, now, token.class, lease,
            wireguard.as_ref().map(<[u8; 32]>::as_slice)],
    )?;
    let overlays = allocate(&tx, network_id, node, now)?;
    if token.capabilities & EXIT_NODE != 0 {
        invited_exit(&tx, network_id, node, lease, now)?;
    }
    let consumed = tx.execute(
        "UPDATE enrollment_tokens SET consumed_at=?1,consumed_by=?2 WHERE id=?3 AND consumed_at IS NULL AND expires_at>?1",
        params![now, node.as_bytes(), token_id.as_bytes()],
    )?;
    if consumed != 1 {
        return Err(EnrollmentError::conflict(
            "enrollment code has already been used",
        ));
    }
    increment_epoch(&tx, network_id, None)?;
    let mut details = format!(
        r#"{{"enrollment_class":"{}","ipv4_address":"{}""#,
        token.class,
        Ipv4Addr::from(
            <[u8; 4]>::try_from(overlays[0].as_slice()).context("invalid allocated IPv4")?
        )
    );
    if let Some(ipv6) = overlays.get(1) {
        let addr = Ipv6Addr::from(
            <[u8; 16]>::try_from(ipv6.as_slice()).context("invalid allocated IPv6")?,
        );
        details.push_str(&format!(r#","ipv6_address":"{addr}""#));
    }
    if let Some(lease) = lease {
        details.push_str(&format!(r#","lease_expires_at":{lease}"#));
    }
    details.push('}');
    audit(
        &tx,
        network_id,
        AuditActor::Node(node),
        "node.enroll",
        "node",
        node,
        &details,
        now,
    )?;
    let material = issuer.issue(&key, network_id, node, lease, now)?;
    add_certificate(&tx, network_id, node, &material, now)?;
    let response = EnrollmentResponse {
        network_id: network_id.as_bytes().to_vec(),
        node_id: node.as_bytes().to_vec(),
        certificate_chain: Some(CertificateChain {
            certificates_der: issuer.chain(material.leaf),
            not_after_unix_seconds: u64::try_from(material.not_after)
                .context("invalid certificate expiry")?,
        }),
        overlay_addresses: overlays,
        enrollment_class: enrolled_class as i32,
        lease_expires_at_unix_seconds: u64::try_from(lease.unwrap_or_default())
            .context("invalid ephemeral lease")?,
        wireguard_public_key: wireguard.map(|key| key.to_vec()).unwrap_or_default(),
    };
    if canceled() {
        return Err(anyhow::anyhow!("enrollment request canceled").into());
    }
    tx.commit()?;
    Ok(response)
}

fn add_certificate(
    tx: &Transaction<'_>,
    network_id: Id,
    node: Id,
    material: &authority::Material,
    now: i64,
) -> Result<(), EnrollmentError> {
    let certificate = random_id()?;
    tx.execute(
        "INSERT INTO certificates (id,network_id,node_id,serial,der,not_before,not_after,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![certificate.as_bytes(), network_id.as_bytes(), node.as_bytes(), material.serial,
            material.leaf, material.not_before, material.not_after, now],
    )?;
    audit(
        tx,
        network_id,
        AuditActor::Node(node),
        "certificate.issue",
        "certificate",
        certificate,
        "{}",
        now,
    )?;
    Ok(())
}

fn random_id() -> Result<Id> {
    loop {
        if let Ok(id) = Id::new(random_bytes()?) {
            return Ok(id);
        }
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("generate controller random data: {error}"))?;
    Ok(bytes)
}

fn token_hash(secret: &str) -> Result<[u8; 32], EnrollmentError> {
    if secret.len() != 43 {
        return Err(EnrollmentError::invalid_token());
    }
    let mut raw = Zeroizing::new([0u8; 33]);
    if URL_SAFE_NO_PAD.decode_slice(secret, raw.as_mut()).ok() != Some(32) {
        return Err(EnrollmentError::invalid_token());
    }
    let mut canonical = URL_SAFE_NO_PAD.encode(&raw[..32]);
    let matches = canonical == secret;
    canonical.zeroize();
    if !matches {
        return Err(EnrollmentError::invalid_token());
    }
    Ok(Sha256::digest(&raw[..32]).into())
}

pub(crate) fn parse_wireguard(bytes: &[u8]) -> Result<Option<[u8; 32]>, EnrollmentError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EnrollmentError::malformed("invalid wireguard_public_key"))?;
    let mut probe = [0; 32];
    probe[0] = 9;
    if x25519_dalek::x25519(probe, key) == [0; 32] {
        return Err(EnrollmentError::malformed("invalid wireguard_public_key"));
    }
    Ok(Some(key))
}

fn stored_class(value: &str) -> Result<EnrollmentClass> {
    Ok(match value {
        "durable" => EnrollmentClass::DurableNode,
        "remembered" => EnrollmentClass::RememberedUser,
        "ephemeral" => EnrollmentClass::EphemeralUser,
        _ => anyhow::bail!("invalid persisted enrollment class"),
    })
}

fn increment_epoch(
    tx: &Transaction<'_>,
    network: Id,
    expected: Option<u64>,
) -> Result<(), EnrollmentError> {
    let changed = tx.execute(
        "UPDATE networks SET configuration_epoch=configuration_epoch+1
        WHERE id=?1 AND configuration_epoch<9223372036854775807
          AND (?2 IS NULL OR configuration_epoch=?2)",
        params![network.as_bytes(), expected],
    )?;
    if changed != 1 {
        return Err(EnrollmentError::conflict(
            "request conflicts with controller state",
        ));
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.trim() == name && !name.contains('\0')
}

enum AuditActor {
    Node(Id),
    System,
    ServicePrincipal(Id),
}

#[allow(clippy::too_many_arguments)]
fn audit(
    tx: &Transaction<'_>,
    network: Id,
    actor: AuditActor,
    action: &str,
    target_type: &str,
    target: Id,
    details: &str,
    now: i64,
) -> Result<()> {
    let id = random_id()?;
    let (actor_kind, actor_id) = match actor {
        AuditActor::Node(id) => ("node", Some(id)),
        AuditActor::System => ("system", None),
        AuditActor::ServicePrincipal(id) => ("service_principal", Some(id)),
    };
    tx.execute(
        "INSERT INTO audit_events (id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![id.as_bytes(), network.as_bytes(), actor_kind,
            actor_id.as_ref().map(Id::as_bytes), action, target_type, target.as_bytes(), details, now],
    )?;
    Ok(())
}

fn invited_exit(
    tx: &Transaction<'_>,
    network: Id,
    node: Id,
    lease: Option<i64>,
    now: i64,
) -> Result<(), EnrollmentError> {
    let active: i64 = tx.query_row(
        "SELECT count(*) FROM routes WHERE network_id=?1 AND kind='exit' AND state='approved'",
        [network.as_bytes()],
        |r| r.get(0),
    )?;
    let metric = active
        .checked_add(100)
        .context("exit route metric overflow")?;
    if metric > 1_000_000 {
        return Err(EnrollmentError::conflict(
            "request conflicts with controller state",
        ));
    }
    let id = random_id()?;
    tx.execute(
        "INSERT INTO routes (id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at,approved_at)
         VALUES (?1,?2,?3,zeroblob(4),0,'exit','nat',?4,'approved',?5,?6,?6)",
        params![id.as_bytes(), network.as_bytes(), node.as_bytes(), metric, lease, now],
    )?;
    audit(
        tx,
        network,
        AuditActor::System,
        "route.invited_exit.approve",
        "route",
        id,
        &format!(r#"{{"prefix":"0.0.0.0/0","metric":{metric}}}"#),
        now,
    )?;
    Ok(())
}

fn allocate(
    tx: &Transaction<'_>,
    network: Id,
    node: Id,
    now: i64,
) -> Result<Vec<Vec<u8>>, EnrollmentError> {
    struct PoolRows {
        v4: Vec<u8>,
        bits4: u32,
        next4: i64,
        v6: Option<Vec<u8>>,
        bits6: Option<u32>,
        next6: i64,
    }
    let PoolRows {
        v4,
        bits4,
        next4,
        v6,
        bits6,
        next6,
    } = tx.query_row(
        "SELECT ipv4_address,ipv4_prefix_length,next_ipv4,ipv6_address,ipv6_prefix_length,next_ipv6
         FROM networks WHERE id=?1",
        [network.as_bytes()],
        |row| {
            Ok(PoolRows {
                v4: row.get(0)?,
                bits4: row.get(1)?,
                next4: row.get(2)?,
                v6: row.get(3)?,
                bits6: row.get(4)?,
                next6: row.get(5)?,
            })
        },
    )?;
    if !(8..=30).contains(&bits4) || next4 <= 0 {
        return Err(anyhow::anyhow!("invalid persisted IPv4 pool or cursor").into());
    }
    let base4 = u32::from_be_bytes(
        v4.try_into()
            .map_err(|_| anyhow::anyhow!("invalid persisted IPv4 prefix"))?,
    );
    let usable4 = (1u64 << (32 - bits4)) - 2;
    if u64::from(base4) % (usable4 + 2) != 0 {
        return Err(anyhow::anyhow!("persisted IPv4 pool is not canonical").into());
    }
    let (candidate, next) = allocate_from(
        tx,
        network,
        node,
        usable4,
        next4 as u64,
        32,
        now,
        |offset| (base4 + offset as u32).to_be_bytes().to_vec(),
    )?;
    tx.execute(
        "UPDATE networks SET next_ipv4=?1 WHERE id=?2",
        params![next as i64, network.as_bytes()],
    )?;
    let mut overlays = vec![candidate];
    match (v6, bits6) {
        (None, None) => {}
        (Some(v6), Some(bits @ 64..=120)) if next6 > 0 => {
            let base6 = u128::from_be_bytes(
                v6.try_into()
                    .map_err(|_| anyhow::anyhow!("invalid persisted IPv6 prefix"))?,
            );
            let host_bits = 128 - bits;
            let capacity = (1u128 << host_bits) - 1;
            if base6 & capacity != 0 {
                return Err(anyhow::anyhow!("persisted IPv6 pool is not canonical").into());
            }
            let usable = capacity.min(i64::MAX as u128) as u64;
            let (candidate, next) = allocate_from(
                tx,
                network,
                node,
                usable,
                next6 as u64,
                128,
                now,
                |offset| (base6 + u128::from(offset)).to_be_bytes().to_vec(),
            )?;
            tx.execute(
                "UPDATE networks SET next_ipv6=?1 WHERE id=?2",
                params![next as i64, network.as_bytes()],
            )?;
            overlays.push(candidate);
        }
        _ => return Err(anyhow::anyhow!("invalid persisted IPv6 pool or cursor").into()),
    }
    Ok(overlays)
}

#[allow(clippy::too_many_arguments)]
fn allocate_from(
    tx: &Transaction<'_>,
    network: Id,
    node: Id,
    usable: u64,
    start: u64,
    bits: i64,
    now: i64,
    address: impl Fn(u64) -> Vec<u8>,
) -> Result<(Vec<u8>, u64), EnrollmentError> {
    let mut offset = if start > usable { 1 } else { start };
    for _ in 0..usable {
        let candidate = address(offset);
        let id = random_id()?;
        let inserted = tx.execute(
            "INSERT INTO overlay_addresses (id,network_id,node_id,address,prefix_length,created_at)
             VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(network_id,address) DO NOTHING",
            params![
                id.as_bytes(),
                network.as_bytes(),
                node.as_bytes(),
                candidate,
                bits,
                now
            ],
        )?;
        let reused = if inserted == 1 {
            true
        } else {
            tx.execute(
                "UPDATE overlay_addresses SET id=?1,node_id=?2,prefix_length=?3,created_at=?4,released_at=NULL
                 WHERE network_id=?5 AND address=?6 AND released_at IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM certificates c WHERE c.node_id=overlay_addresses.node_id
                     AND c.not_after>?4 AND c.revoked_at IS NULL)",
                params![id.as_bytes(), node.as_bytes(), bits, now, network.as_bytes(), candidate],
            )? == 1
        };
        offset = if offset == usable { 1 } else { offset + 1 };
        if reused {
            return Ok((candidate, offset));
        }
    }
    Err(anyhow::anyhow!("overlay allocation exhausted").into())
}

fn expire(tx: Transaction<'_>, now: i64) -> Result<(), EnrollmentError> {
    expire_ephemeral(&tx, now)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn expire_ephemeral(tx: &Transaction<'_>, now: i64) -> Result<(), EnrollmentError> {
    const BATCH: i64 = 1024;
    let pending = {
        let mut stmt = tx.prepare(
            "SELECT id,network_id,lease_expires_at FROM nodes
             WHERE enrollment_class='ephemeral' AND revoked_at IS NULL AND lease_expires_at<=?1
             ORDER BY lease_expires_at,id LIMIT ?2",
        )?;
        stmt.query_map(params![now, BATCH], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut networks = HashSet::new();
    for (node, network, lease) in pending {
        let node = Id::from_slice(&node).context("invalid expired node identity")?;
        let network = Id::from_slice(&network).context("invalid expired network identity")?;
        let changed = tx.execute(
            "UPDATE nodes SET revoked_at=?1,name=substr(name,1,210)||'~expired~'||lower(hex(id))
             WHERE id=?2 AND revoked_at IS NULL AND enrollment_class='ephemeral' AND lease_expires_at<=?1",
            params![now, node.as_bytes()],
        )?;
        if changed != 1 {
            continue;
        }
        tx.execute(
            "UPDATE overlay_addresses SET released_at=?1 WHERE node_id=?2 AND released_at IS NULL",
            params![now, node.as_bytes()],
        )?;
        tx.execute(
            "UPDATE certificates SET revoked_at=?1,revocation_reason='ephemeral lease expired'
            WHERE node_id=?2 AND revoked_at IS NULL",
            params![now, node.as_bytes()],
        )?;
        tx.execute(
            "UPDATE routes SET state='withdrawn',withdrawn_at=?1
            WHERE node_id=?2 AND state IN ('advertised','approved')",
            params![now, node.as_bytes()],
        )?;
        audit(
            tx,
            network,
            AuditActor::System,
            "ephemeral.expire",
            "node",
            node,
            &format!(r#"{{"lease_expires_at":{lease}}}"#),
            now,
        )?;
        networks.insert(network);
    }
    for network in networks {
        increment_epoch(tx, network, None)?;
    }
    let cutoff = now.saturating_sub(604800);
    tx.execute(
        "DELETE FROM nodes WHERE id IN (
             SELECT id FROM nodes WHERE enrollment_class='ephemeral' AND revoked_at IS NOT NULL AND lease_expires_at<=?1
             ORDER BY lease_expires_at,id LIMIT ?2)",
        params![cutoff, BATCH],
    )?;
    tx.execute(
        "DELETE FROM enrollment_tokens WHERE id IN (
             SELECT id FROM enrollment_tokens WHERE enrollment_class='ephemeral' AND expires_at<=?1
             ORDER BY expires_at,id LIMIT ?2)",
        params![cutoff, BATCH],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
