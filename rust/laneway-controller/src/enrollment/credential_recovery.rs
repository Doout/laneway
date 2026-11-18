//! Explicit same-key recovery for expired, persistent node credentials.
use super::{EnrollError, audit, configuration::clock, record_certificate};
use crate::{
    SessionStore,
    access_admin::AccessError,
    check_snapshot,
    node_pki::{NodeIssuer, VerifiedCsr},
    schema,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::{Id, Role, identity_from_certificate_der, v1::CertificateChain};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

const APPROVAL_LIFETIME: i64 = 10 * 60;
const ELIGIBLE_NODE: &str = "n.revoked_at IS NULL AND n.enrollment_class IN ('durable','remembered')
    AND n.lease_expires_at IS NULL AND (n.user_id IS NULL OR EXISTS(
        SELECT 1 FROM access_users u WHERE u.id=n.user_id AND u.network_id=n.network_id AND u.enabled=1))";

pub(crate) fn approve(
    tx: &Transaction<'_>,
    net: Id,
    node: Id,
    now: i64,
    serial: &[u8],
) -> Result<(Zeroizing<String>, i64)> {
    ensure!(schema::is_fleet(tx)?, AccessError::Missing);
    ensure!(
        (1..=32).contains(&serial.len()) && serial[0] != 0,
        AccessError::Invalid("invalid certificate serial")
    );
    let certificate: [u8; 16] = tx.query_row(
        &format!("SELECT c.id FROM certificates c JOIN nodes n ON n.id=c.node_id AND n.network_id=c.network_id
            WHERE c.network_id=?1 AND c.node_id=?2 AND c.serial=?3 AND c.revoked_at IS NULL
            AND c.not_after<=?4 AND {ELIGIBLE_NODE}"),
        (net.as_bytes(), node.as_bytes(), serial, now),
        |r| r.get(0),
    ).optional()?.ok_or(AccessError::Missing)?;
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *entropy)?;
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(entropy.as_slice()));
    let digest = Sha256::digest(token.as_bytes());
    let expires = now + APPROVAL_LIFETIME;
    tx.execute(
        "UPDATE node_credential_recovery_grants SET consumed_at=?2 WHERE node_id=?1 AND consumed_at IS NULL",
        (node.as_bytes(), now),
    )?;
    tx.execute(
        "INSERT INTO node_credential_recovery_grants(token_hash,network_id,node_id,certificate_id,expires_at,created_at)
         VALUES(?,?,?,?,?,?)",
        (digest.as_slice(), net.as_bytes(), node.as_bytes(), certificate, expires, now),
    )?;
    Ok((token, expires))
}

impl SessionStore {
    /// Prove possession of the approved expired credential key, without ever
    /// accepting the expired certificate as a TLS client identity.
    pub fn recover_node_credential(
        &mut self,
        token: &str,
        csr: &[u8],
        issuer: &NodeIssuer,
        cancelled: impl Fn() -> bool,
    ) -> Result<CertificateChain> {
        let mut decoded = Zeroizing::new([0u8; 32]);
        ensure!(
            token.len() == 43 && URL_SAFE_NO_PAD.decode_slice(token, &mut *decoded) == Ok(32),
            EnrollError::Denied
        );
        let digest = Sha256::digest(token.as_bytes());
        let binding = format!("laneway-recovery:{}", hex::encode(digest));
        let (csr, spki) =
            VerifiedCsr::for_recovery(csr, &binding).map_err(|_| EnrollError::Denied)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        ensure!(schema::is_fleet(&tx)? && !cancelled(), EnrollError::Denied);
        let now = clock(&tx)?;
        let (net, node, old): ([u8; 16], [u8; 16], Vec<u8>) = tx.query_row(
            &format!("SELECT n.network_id,n.id,c.der FROM node_credential_recovery_grants g
                JOIN nodes n ON n.id=g.node_id AND n.network_id=g.network_id
                JOIN certificates c ON c.id=g.certificate_id AND c.node_id=n.id AND c.network_id=n.network_id
                WHERE g.token_hash=?1 AND g.consumed_at IS NULL AND g.expires_at>?2
                  AND c.revoked_at IS NULL AND c.not_after<=?2 AND {ELIGIBLE_NODE}"),
            (digest.as_slice(), now),
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?.ok_or(EnrollError::Denied)?;
        let (net, node) = (Id::new(net)?, Id::new(node)?);
        let identity = identity_from_certificate_der(&old).map_err(|_| EnrollError::Denied)?;
        let (rest, old) = X509Certificate::from_der(&old).map_err(|_| EnrollError::Denied)?;
        ensure!(
            rest.is_empty()
                && identity.role == Role::Node
                && identity.network_id == net
                && identity.subject_id == node
                && old.validity().not_after.timestamp() <= now
                && old.public_key().raw == spki,
            EnrollError::Denied
        );
        let cert = issuer.issue(&csr, net, node, now, None)?;
        let chain = record_certificate(&tx, net, node, issuer, cert, now)?;
        let consume_time = clock(&tx)?;
        ensure!(
            !cancelled()
                && tx.execute(
                    "UPDATE node_credential_recovery_grants SET consumed_at=?2
                 WHERE token_hash=?1 AND consumed_at IS NULL AND expires_at>?2",
                    (digest.as_slice(), consume_time),
                )? == 1,
            EnrollError::Denied
        );
        audit(
            &tx,
            net,
            Some(node),
            "node.credential_recovery.consume",
            ("node", node),
            serde_json::json!({}),
            now,
        )?;
        ensure!(!cancelled(), EnrollError::Denied);
        tx.commit()?;
        Ok(chain)
    }
}
