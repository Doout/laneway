//! Redeem one invitation, with authorization derived only from the stored grant.
mod addresses;
pub mod configuration;
pub mod credential_recovery;
pub(crate) mod diagnostics;
mod exit;
mod maintenance;
mod managed_policy;
pub(crate) mod policy_preview;
pub(crate) mod private_dns;
pub mod relay_configuration;
pub mod renewal;
mod replay;
pub mod revocation;
pub(crate) mod snapshot_policy;

use crate::enrollment_tokens::{EXIT, ROUTER};
use crate::{
    SessionStore, check_snapshot,
    node_pki::{NodeIssuer, VerifiedCsr},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::{
    Id,
    v1::{CertificateChain, EnrollmentClass, EnrollmentRequest, EnrollmentResponse},
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnrollError {
    #[error("{0}")]
    Malformed(&'static str),
    #[error("authentication failed")]
    Invalid,
    #[error("permission denied")]
    Denied,
    #[error("enrollment code has expired")]
    Expired,
    #[error("enrollment code has already been used")]
    Used,
    #[error("enrollment code belongs to a different network")]
    Network,
    #[error("enrollment code has a different enrollment class")]
    Class,
    #[error("enrollment code is bound to a different device name")]
    Name,
    #[error("request conflicts with controller state")]
    Conflict,
    #[error("overlay pool exhausted")]
    PoolExhausted,
}
fn new_id() -> Result<Id> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes)?;
    Ok(Id::new(bytes)?)
}
fn audit(
    tx: &Transaction<'_>,
    net: Id,
    actor: Option<Id>,
    action: &str,
    target: (&str, Id),
    details: Value,
    now: i64,
) -> Result<()> {
    tx.execute("INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
        VALUES(randomblob(16),?1,?2,?3,?4,?5,?6,?7,?8)",params![net.as_bytes(),if actor.is_some(){"node"}else{"system"},actor.as_ref().map(Id::as_bytes),action,target.0,target.1.as_bytes(),details.to_string(),now])?;
    Ok(())
}
fn bump(tx: &Transaction<'_>, net: Id) -> Result<()> {
    ensure!(tx.execute("UPDATE networks SET configuration_epoch=configuration_epoch+1 WHERE id=? AND configuration_epoch<9223372036854775807",[net.as_bytes()])?==1,EnrollError::Conflict);
    Ok(())
}
struct Grant {
    id: [u8; 16],
    network: [u8; 16],
    expires: i64,
    consumed: Option<i64>,
    consumed_by: Option<[u8; 16]>,
    class: String,
    lifetime: Option<i64>,
    name: Option<String>,
    caps: i64,
    user: Option<[u8; 16]>,
}

fn record_certificate(
    tx: &Transaction<'_>,
    net: Id,
    node: Id,
    issuer: &NodeIssuer,
    cert: crate::node_pki::IssuedCertificate,
    now: i64,
) -> Result<CertificateChain> {
    let id = new_id()?;
    tx.execute("INSERT INTO certificates(id,network_id,node_id,serial,der,not_before,not_after,created_at) VALUES(?,?,?,?,?,?,?,?)",params![id.as_bytes(),net.as_bytes(),node.as_bytes(),cert.serial,cert.der,cert.not_before,cert.not_after,now])?;
    audit(
        tx,
        net,
        Some(node),
        "certificate.issue",
        ("certificate", id),
        json!({}),
        now,
    )?;
    Ok(CertificateChain {
        certificates_der: std::iter::once(cert.der)
            .chain(issuer.intermediates().iter().cloned())
            .collect(),
        not_after_unix_seconds: u64::try_from(cert.not_after)?,
    })
}

impl SessionStore {
    pub fn redeem_enrollment(
        &mut self,
        mut req: EnrollmentRequest,
        issuer: &NodeIssuer,
        cancelled: impl Fn() -> bool,
    ) -> Result<EnrollmentResponse> {
        let secret = Zeroizing::new(std::mem::take(&mut req.enrollment_token));
        let csr = VerifiedCsr::parse(&req.pkcs10_csr_der)
            .map_err(|_| EnrollError::Malformed("invalid PKCS#10 CSR"))?;
        let key = if req.wireguard_public_key.is_empty() {
            None
        } else {
            let key: [u8; 32] = req
                .wireguard_public_key
                .as_slice()
                .try_into()
                .map_err(|_| EnrollError::Malformed("invalid wireguard_public_key"))?;
            ensure!(
                x25519_dalek::x25519([1; 32], key) != [0; 32],
                EnrollError::Malformed("invalid wireguard_public_key")
            );
            Some(key)
        };
        let expected_net = if req.expected_network_id.is_empty() {
            None
        } else {
            Some(
                Id::from_slice(&req.expected_network_id)
                    .map_err(|_| EnrollError::Malformed("invalid expected_network_id"))?,
            )
        };
        let expected_class = EnrollmentClass::try_from(req.expected_enrollment_class)
            .map_err(|_| EnrollError::Malformed("expected_enrollment_class is unknown"))?;
        ensure!(
            expected_class == EnrollmentClass::Unspecified || expected_net.is_some(),
            EnrollError::Malformed("expected_enrollment_class requires expected_network_id")
        );
        ensure!(
            key.is_none()
                || (expected_net.is_some() && expected_class != EnrollmentClass::Unspecified),
            EnrollError::Malformed(
                "wireguard_public_key requires authenticated expected_network_id and expected_enrollment_class"
            )
        );
        // Exact recovery requires explicit network, durable enrollment
        // class and WireGuard bindings.
        let request_digest = (key.is_some() && expected_class == EnrollmentClass::DurableNode)
            .then(|| replay::request_digest(&req));
        ensure!(secret.len() == 43, EnrollError::Invalid);
        let raw = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(secret.as_bytes())
                .map_err(|_| EnrollError::Invalid)?,
        );
        ensure!(raw.len() == 32, EnrollError::Invalid);
        let hash: [u8; 32] = Sha256::digest(&*raw).into();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        ensure!(!cancelled(), "enrollment cancelled");
        maintenance::expire(&tx, tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?)?;
        tx.commit()?;

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let grant=tx.query_row("SELECT id,network_id,expires_at,consumed_at,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities,user_id,consumed_by FROM enrollment_tokens WHERE token_hash=?",[hash],|r| Ok(Grant{id:r.get(0)?,network:r.get(1)?,expires:r.get(2)?,consumed:r.get(3)?,class:r.get(4)?,lifetime:r.get(5)?,name:r.get(6)?,caps:r.get(7)?,user:r.get(8)?,consumed_by:r.get(9)?})).optional()?.ok_or(EnrollError::Invalid)?;
        if let Some(consumed_at) = grant.consumed {
            let response = replay::recover(&tx, &grant, consumed_at, now, request_digest, issuer)?;
            ensure!(!cancelled(), "enrollment cancelled");
            tx.commit()?;
            return Ok(response);
        }
        ensure!(now < grant.expires, EnrollError::Expired);
        let net = Id::new(grant.network)?;
        ensure!(expected_net.is_none_or(|v| v == net), EnrollError::Network);
        let name = if let Some(bound) = grant.name.as_deref() {
            ensure!(
                req.requested_name.is_empty() || req.requested_name == bound,
                EnrollError::Name
            );
            bound
        } else {
            &req.requested_name
        };
        ensure!(
            !name.is_empty() && name.len() <= 253 && name.trim() == name && !name.contains('\0'),
            EnrollError::Malformed("invalid request")
        );
        let class = match grant.class.as_str() {
            "ephemeral" => EnrollmentClass::EphemeralUser,
            "durable" => EnrollmentClass::DurableNode,
            "remembered" => EnrollmentClass::RememberedUser,
            _ => anyhow::bail!("invalid stored enrollment class"),
        };
        let ephemeral = class == EnrollmentClass::EphemeralUser;
        ensure!(
            ephemeral == grant.lifetime.is_some(),
            "invalid stored enrollment lifetime"
        );
        ensure!(
            expected_class == EnrollmentClass::Unspecified || expected_class == class,
            EnrollError::Class
        );
        let caps = grant.caps;
        ensure!(
            caps >= 0
                && (caps as u64) & !(ROUTER | EXIT) == 0
                && !(ephemeral && caps as u64 == ROUTER | EXIT),
            "invalid stored enrollment capabilities"
        );
        if let Some(user) = &grant.user {
            Id::new(*user)?;
            ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM access_users WHERE id=? AND network_id=? AND enabled=1)",(user,net.as_bytes()),|r|r.get::<_,bool>(0))?,EnrollError::Invalid);
        }
        let lease = if let Some(seconds) = grant.lifetime {
            ensure!(
                (300..=86400).contains(&seconds),
                "invalid stored ephemeral lifetime"
            );
            let count:i64=tx.query_row("SELECT count(*) FROM nodes WHERE network_id=? AND enrollment_class='ephemeral' AND revoked_at IS NULL AND lease_expires_at>?",(net.as_bytes(),now),|r|r.get(0))?;
            ensure!(count < 4096, EnrollError::Conflict);
            Some(now + seconds)
        } else {
            None
        };
        let node = new_id()?;
        let inserted=tx.execute("INSERT INTO nodes(id,network_id,name,enabled_capabilities,created_at,enrollment_class,lease_expires_at,wireguard_public_key,user_id)
          VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",params![node.as_bytes(),net.as_bytes(),name,caps,now,grant.class,lease,key,grant.user])?;
        ensure!(inserted == 1, EnrollError::Conflict);
        let addresses = addresses::allocate(&tx, net, node, now)?;
        let generation = if caps as u64 & EXIT != 0 {
            exit::grant(&tx, net, node, lease, now)?
        } else {
            0
        };
        ensure!(tx.execute("UPDATE enrollment_tokens SET consumed_at=?,consumed_by=? WHERE id=? AND consumed_at IS NULL AND expires_at>?",params![now,node.as_bytes(),grant.id,now])?==1,EnrollError::Used);
        bump(&tx, net)?;
        let mut details =
            json!({"enrollment_class":grant.class,"ipv4_address":addresses[0].to_string()});
        if let Some(v6) = addresses.get(1) {
            details["ipv6_address"] = json!(v6.to_string());
        }
        if let Some(t) = lease {
            details["lease_expires_at"] = json!(t);
        }
        if generation != 0 {
            audit(
                &tx,
                net,
                None,
                "ephemeral_exit.session.start",
                ("node", node),
                json!({"generation":generation,"suspect_at":now+20,"revoke_at":now+60}),
                now,
            )?;
        }
        let cert = issuer.issue(&csr, net, node, now, lease)?;
        let serial = (request_digest.is_some() && replay::eligible(&grant))
            .then(|| hex::encode(&cert.serial));
        let chain = record_certificate(&tx, net, node, issuer, cert, now)?;
        let response = EnrollmentResponse {
            network_id: net.as_bytes().to_vec(),
            node_id: node.as_bytes().to_vec(),
            certificate_chain: Some(chain),
            overlay_addresses: addresses
                .into_iter()
                .map(|a| match a {
                    IpAddr::V4(v) => v.octets().to_vec(),
                    IpAddr::V6(v) => v.octets().to_vec(),
                })
                .collect(),
            enrollment_class: class as i32,
            lease_expires_at_unix_seconds: lease.unwrap_or(0) as u64,
            wireguard_public_key: req.wireguard_public_key,
            ephemeral_exit_lease_generation: generation,
        };
        if let Some((request_digest, serial)) = request_digest.zip(serial) {
            details["retry_receipt"] =
                replay::receipt_json(&grant, request_digest, serial, &response);
        }
        audit(
            &tx,
            net,
            Some(node),
            "node.enroll",
            ("node", node),
            details,
            now,
        )?;
        ensure!(!cancelled(), "enrollment cancelled");
        tx.commit()?;
        Ok(response)
    }
}
