use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use laneway_protocol::{
    Id, Role, identity_from_certificate_der,
    v1::{CertificateChain, EnrollmentClass, RenewalRequest, RenewalResponse},
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::store::Store;

use super::{
    AuditActor, EXIT_NODE, EnrollmentAuthority, EnrollmentError, SUBNET_ROUTER, add_certificate,
    audit, authority, clock, expire, increment_epoch, parse_wireguard, stored_class,
};

/// A parsed leaf handed off by a transport that already verified the client
/// chain and TLS proof of possession. Authorization still checks durable state.
pub(crate) struct NodePeer<'a> {
    pub(crate) network_id: Id,
    pub(crate) node_id: Id,
    pub(crate) not_after: i64,
    not_before: i64,
    serial: &'a [u8],
    der: &'a [u8],
}

pub(crate) struct NodeAuthorization {
    pub(crate) class: EnrollmentClass,
    pub(crate) lease_until: Option<i64>,
    pub(crate) wireguard_key: Option<[u8; 32]>,
    pub(crate) enabled_capabilities: u64,
    pub(crate) configuration_epoch: u64,
}

impl<'a> NodePeer<'a> {
    pub(crate) fn from_tls_leaf(der: &'a [u8]) -> Result<Self, EnrollmentError> {
        let denied = || EnrollmentError::denied("permission denied");
        let (rest, leaf) = x509_parser::parse_x509_certificate(der).map_err(|_| denied())?;
        let identity = identity_from_certificate_der(der).map_err(|_| denied())?;
        if !rest.is_empty() || identity.role != Role::Node {
            return Err(denied());
        }
        let raw_serial = leaf.raw_serial();
        if raw_serial.first().is_none_or(|byte| byte & 0x80 != 0) {
            return Err(denied());
        }
        let serial = &raw_serial[raw_serial
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(raw_serial.len())..];
        if !(1..=32).contains(&serial.len()) {
            return Err(denied());
        }
        Ok(Self {
            network_id: identity.network_id,
            node_id: identity.subject_id,
            not_before: leaf.validity().not_before.timestamp(),
            not_after: leaf.validity().not_after.timestamp(),
            serial,
            der,
        })
    }

    /// Check this exact persisted identity against the settings that authorize
    /// the current request. Call inside the read or write transaction that
    /// uses the returned state so revocation cannot race a successful request.
    pub(crate) fn authenticate(
        &self,
        db: &Connection,
        now: i64,
    ) -> Result<NodeAuthorization, EnrollmentError> {
        let denied = || EnrollmentError::denied("permission denied");
        if now < self.not_before || now >= self.not_after {
            return Err(denied());
        }
        struct Binding {
            class: String,
            lease_until: Option<i64>,
            key: Option<Vec<u8>>,
            capabilities: i64,
            epoch: i64,
        }
        let binding = db
            .query_row(
                "SELECT n.enrollment_class,n.lease_expires_at,n.wireguard_public_key,
                    n.enabled_capabilities,w.configuration_epoch
             FROM nodes n
             JOIN networks w ON w.id=n.network_id
             JOIN certificates c ON c.network_id=n.network_id AND c.node_id=n.id
             WHERE n.network_id=?1 AND n.id=?2 AND n.revoked_at IS NULL
               AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?3)
               AND c.serial=?4 AND c.der=?5 AND c.revoked_at IS NULL
               AND c.not_before<=?3 AND c.not_after>?3",
                params![
                    self.network_id.as_bytes(),
                    self.node_id.as_bytes(),
                    now,
                    self.serial,
                    self.der
                ],
                |row| {
                    Ok(Binding {
                        class: row.get(0)?,
                        lease_until: row.get(1)?,
                        key: row.get(2)?,
                        capabilities: row.get(3)?,
                        epoch: row.get(4)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(denied)?;
        let class = stored_class(&binding.class)?;
        if (class == EnrollmentClass::EphemeralUser) != binding.lease_until.is_some()
            || binding.epoch < 1
            || binding.capabilities & !(SUBNET_ROUTER | EXIT_NODE) != 0
        {
            return Err(anyhow::anyhow!("invalid persisted node authorization").into());
        }
        let wireguard_key = binding
            .key
            .as_deref()
            .map(parse_wireguard)
            .transpose()
            .context("invalid persisted WireGuard key")?
            .flatten();
        if binding.key.is_some() && wireguard_key.is_none() {
            return Err(anyhow::anyhow!("missing persisted WireGuard key").into());
        }
        Ok(NodeAuthorization {
            class,
            lease_until: binding.lease_until,
            wireguard_key,
            enabled_capabilities: binding.capabilities as u64,
            configuration_epoch: binding.epoch as u64,
        })
    }
}

pub(crate) fn renew(
    store: &mut Store,
    issuer: &EnrollmentAuthority,
    peer_certificate_der: &[u8],
    request: RenewalRequest,
    canceled: &AtomicBool,
) -> Result<RenewalResponse, EnrollmentError> {
    renew_with_clock(
        store,
        issuer,
        peer_certificate_der,
        request,
        canceled,
        clock,
    )
}

fn renew_with_clock(
    store: &mut Store,
    issuer: &EnrollmentAuthority,
    peer_certificate_der: &[u8],
    request: RenewalRequest,
    canceled: &AtomicBool,
    now: impl Fn() -> Result<i64>,
) -> Result<RenewalResponse, EnrollmentError> {
    let peer = NodePeer::from_tls_leaf(peer_certificate_der)?;
    {
        let tx = store.enrollment_transaction()?;
        peer.authenticate(&tx, now()?)?;
    }
    let tls_key = authority::public_key(&request.pkcs10_csr_der)?;
    let proposed_wireguard = parse_wireguard(&request.wireguard_public_key)?;
    if canceled.load(Ordering::Acquire) {
        return Err(anyhow::anyhow!("renewal request canceled").into());
    }
    expire(store.enrollment_transaction()?, now()?)?;
    let tx = store.enrollment_transaction()?;
    let now = now()?;
    let current = peer.authenticate(&tx, now)?;
    // Stable-v1 requests without a WireGuard binding keep the existing key.
    let wireguard = proposed_wireguard.or(current.wireguard_key);
    let material = issuer.issue(
        &tls_key,
        peer.network_id,
        peer.node_id,
        current.lease_until,
        now,
    )?;
    add_certificate(&tx, peer.network_id, peer.node_id, &material, now)?;

    if wireguard != current.wireguard_key {
        tx.execute(
            "UPDATE nodes SET wireguard_public_key=?1 WHERE id=?2 AND network_id=?3",
            params![
                wireguard.as_ref().map(<[u8; 32]>::as_slice),
                peer.node_id.as_bytes(),
                peer.network_id.as_bytes()
            ],
        )?;
        increment_epoch(&tx, peer.network_id, Some(current.configuration_epoch))?;
        audit(
            &tx,
            peer.network_id,
            AuditActor::Node(peer.node_id),
            "node.wireguard_key.rotate",
            "node",
            peer.node_id,
            "{}",
            now,
        )?;
    }
    let response = RenewalResponse {
        certificate_chain: Some(CertificateChain {
            certificates_der: issuer.chain(material.leaf),
            not_after_unix_seconds: u64::try_from(material.not_after)
                .context("invalid renewal certificate expiry")?,
        }),
        wireguard_public_key: wireguard.map(|key| key.to_vec()).unwrap_or_default(),
    };
    if canceled.load(Ordering::Acquire) {
        return Err(anyhow::anyhow!("renewal request canceled").into());
    }
    tx.commit()?;
    Ok(response)
}

#[cfg(test)]
mod tests;
