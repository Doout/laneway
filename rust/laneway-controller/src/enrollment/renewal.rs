//! Workload authorization and certificate renewal on the verified mTLS transport.
use super::{EnrollError, audit, bump, maintenance, record_certificate};
use crate::{
    SessionStore, check_snapshot,
    node_pki::{NodeIssuer, VerifiedCsr},
};
use anyhow::{Result, ensure};
use laneway_protocol::{
    Id, Role, certificate_serial_from_der, identity_from_certificate_der,
    v1::{RenewalRequest, RenewalResponse},
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::json;

pub struct NodeCredential {
    pub(crate) net: Id,
    pub(crate) node: Id,
    pub(super) serial: Vec<u8>,
    pub(super) der: Vec<u8>,
}

pub(crate) struct Binding {
    pub(super) lease: Option<i64>,
    key: Option<[u8; 32]>,
    pub(crate) capabilities: i64,
}
#[derive(Clone, Copy)]
pub enum RenewalTransport {
    Https,
    Quic { holds_exit_claim: bool },
}

impl NodeCredential {
    /// Input must be the TLS stack's verified leaf, never supplied by HTTP.
    pub fn from_verified_peer(der: &[u8]) -> Result<Self> {
        let id = identity_from_certificate_der(der).map_err(|_| EnrollError::Invalid)?;
        ensure!(id.role == Role::Node, EnrollError::Invalid);
        let serial = certificate_serial_from_der(der).map_err(|_| EnrollError::Invalid)?;
        Ok(Self {
            net: id.network_id,
            node: id.subject_id,
            serial,
            der: der.to_vec(),
        })
    }
    pub(crate) fn binding(&self, tx: &Transaction<'_>, now: i64) -> Result<Binding> {
        // Match exact certificate bytes as well as serial and identity. The DB
        // decides whether a previously authenticated TLS peer is still allowed.
        let binding=tx.query_row("SELECT n.lease_expires_at,n.wireguard_public_key,n.enabled_capabilities
            FROM nodes n JOIN certificates c ON c.node_id=n.id AND c.network_id=n.network_id
            WHERE n.network_id=?1 AND n.id=?2 AND c.serial=?3 AND c.der=?4
              AND n.revoked_at IS NULL AND c.revoked_at IS NULL AND c.not_before<=?5 AND c.not_after>?5
              AND ((n.enrollment_class='ephemeral' AND n.lease_expires_at>?5)
                OR (n.enrollment_class IN ('durable','remembered') AND n.lease_expires_at IS NULL))",
            params![self.net.as_bytes(),self.node.as_bytes(),self.serial,self.der,now],|r|Ok(Binding{lease:r.get(0)?,key:r.get(1)?,capabilities:r.get(2)?})).optional()?.ok_or(EnrollError::Denied)?;
        Ok(binding)
    }
    fn exit_admission(
        &self,
        tx: &Transaction<'_>,
        bound: &Binding,
        now: i64,
    ) -> Result<Option<bool>> {
        if bound.lease.is_none() || bound.capabilities != crate::enrollment_tokens::EXIT as i64 {
            return Ok(None);
        }
        Ok(Some(tx.query_row("SELECT suspect_at<=?1 FROM ephemeral_exit_sessions WHERE node_id=?2 AND network_id=?3 AND terminated_at IS NULL AND revoke_at>?1",params![now,self.node.as_bytes(),self.net.as_bytes()],|r|r.get(0)).optional()?.ok_or(EnrollError::Denied)?))
    }
    fn renewal_binding(
        &self,
        tx: &Transaction<'_>,
        transport: RenewalTransport,
    ) -> Result<(i64, Binding)> {
        let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let bound = self.binding(tx, now)?;
        if let RenewalTransport::Quic { holds_exit_claim } = transport {
            ensure!(
                self.exit_admission(tx, &bound, now)?.is_some() == holds_exit_claim,
                EnrollError::Denied
            );
        }
        Ok((now, bound))
    }
}
impl SessionStore {
    /// Returns takeover eligibility only for an active ephemeral Exit. Ordinary
    /// nodes do not take an exclusive control-session slot.
    pub fn node_control_admission(&mut self, peer: &NodeCredential) -> Result<Option<bool>> {
        let tx = self.db.transaction()?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let bound = peer.binding(&tx, now)?;
        let result = peer.exit_admission(&tx, &bound, now)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn check_node_peer(&mut self, peer: &NodeCredential) -> Result<()> {
        let tx = self.db.transaction()?;
        check_snapshot(&tx)?;
        peer.binding(&tx, tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?)?;
        tx.commit()?;
        Ok(())
    }
    pub fn renew_certificate(
        &mut self,
        peer: &NodeCredential,
        req: RenewalRequest,
        issuer: &NodeIssuer,
        transport: RenewalTransport,
        cancelled: impl Fn() -> bool,
    ) -> Result<RenewalResponse> {
        ensure!(!cancelled(), "renewal cancelled");
        // Authorize after the body has arrived, before verifying its signature.
        // Release the read transaction before doing CPU-intensive CSR work.
        {
            let tx = self.db.transaction()?;
            check_snapshot(&tx)?;
            peer.renewal_binding(&tx, transport)?;
            tx.commit()?;
        }
        let csr = VerifiedCsr::parse(&req.pkcs10_csr_der)
            .map_err(|_| EnrollError::Malformed("invalid PKCS#10 CSR"))?;
        let requested = if req.wireguard_public_key.is_empty() {
            None
        } else {
            let k: [u8; 32] = req
                .wireguard_public_key
                .as_slice()
                .try_into()
                .map_err(|_| EnrollError::Malformed("invalid wireguard_public_key"))?;
            ensure!(
                x25519_dalek::x25519([1; 32], k) != [0; 32],
                EnrollError::Malformed("invalid wireguard_public_key")
            );
            Some(k)
        };
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        ensure!(!cancelled(), "renewal cancelled");
        let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        peer.binding(&tx, now)?;
        maintenance::expire(&tx, now)?;
        tx.commit()?;

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let (now, bound) = peer.renewal_binding(&tx, transport)?;
        if let Some(k) = bound.key {
            ensure!(
                x25519_dalek::x25519([1; 32], k) != [0; 32],
                "invalid stored WireGuard key"
            );
        }
        let key = requested.or(bound.key);
        let cert = issuer.issue(&csr, peer.net, peer.node, now, bound.lease)?;
        let chain = record_certificate(&tx, peer.net, peer.node, issuer, cert, now)?;
        if key != bound.key {
            let changed = tx.execute(
                "UPDATE OR IGNORE nodes SET wireguard_public_key=? WHERE id=? AND network_id=?",
                params![key, peer.node.as_bytes(), peer.net.as_bytes()],
            )?;
            ensure!(changed == 1, EnrollError::Conflict);
            bump(&tx, peer.net)?;
            audit(
                &tx,
                peer.net,
                Some(peer.node),
                "node.wireguard_key.rotate",
                ("node", peer.node),
                json!({}),
                now,
            )?;
        }
        // A certificate or ephemeral authorization can expire while signing.
        peer.renewal_binding(&tx, transport)?;
        ensure!(!cancelled(), "renewal cancelled");
        tx.commit()?;
        Ok(RenewalResponse {
            certificate_chain: Some(chain),
            wireguard_public_key: key.map_or_else(Vec::new, |k| k.to_vec()),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };
    use rusqlite::Connection;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    #[test]
    fn unauthorized_renewal_is_denied_before_parsing_csr() -> Result<()> {
        let mut store = SessionStore {
            db: Connection::open_in_memory()?,
        };
        let tx = store.db.transaction()?;
        crate::schema::initialize(&tx, 1)?;
        tx.commit()?;

        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut ca = CertificateParams::new(vec![])?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca.self_signed(&key)?;
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let issuer = NodeIssuer::new(std::slice::from_ref(ca.der()), &key, 300)?;
        let peer = NodeCredential {
            net: Id::new([1; 16])?,
            node: Id::new([2; 16])?,
            serial: vec![1],
            der: vec![1],
        };
        let err = store
            .renew_certificate(
                &peer,
                RenewalRequest::default(),
                &issuer,
                RenewalTransport::Https,
                || false,
            )
            .unwrap_err();
        assert!(matches!(err.downcast_ref(), Some(EnrollError::Denied)));
        Ok(())
    }
}
