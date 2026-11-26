//! Recover a recently committed enrollment response for an identical request.
use super::{EnrollError, Grant, ROUTER};
use crate::node_pki::NodeIssuer;
use anyhow::{Result, ensure};
use laneway_protocol::v1::{
    CertificateChain, EnrollmentClass, EnrollmentRequest, EnrollmentResponse,
};
use prost::Message;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) fn eligible(grant: &Grant) -> bool {
    grant.class == "durable" && matches!(grant.caps as u64, 0 | ROUTER) && grant.lifetime.is_none()
}

pub(super) fn request_digest(request: &EnrollmentRequest) -> [u8; 32] {
    debug_assert!(request.enrollment_token.is_empty());
    let mut hash = Sha256::new_with_prefix(b"laneway/enrollment/retry-request/v1");
    hash.update(request.encode_to_vec());
    hash.finalize().into()
}

fn response_digest(response: &EnrollmentResponse) -> String {
    hex::encode(Sha256::digest(response.encode_to_vec()))
}

pub(super) fn receipt_json(
    grant: &Grant,
    request_digest: [u8; 32],
    serial: String,
    response: &EnrollmentResponse,
) -> Value {
    json!({
        "request_sha256": hex::encode(request_digest),
        "certificate_serial": serial,
        "response_sha256": response_digest(response),
        "user_id": grant.user.map(hex::encode),
    })
}

#[derive(Deserialize)]
struct EnrollmentEvent {
    retry_receipt: Option<Receipt>,
}

#[derive(Deserialize)]
struct Receipt {
    request_sha256: String,
    certificate_serial: String,
    response_sha256: String,
    user_id: Option<String>,
}

pub(super) fn recover(
    tx: &Transaction<'_>,
    grant: &Grant,
    consumed_at: i64,
    now: i64,
    request_digest: Option<[u8; 32]>,
    issuer: &NodeIssuer,
) -> Result<EnrollmentResponse> {
    ensure!(
        eligible(grant) && now >= consumed_at && now < grant.expires,
        EnrollError::Used
    );
    let request_digest = request_digest.ok_or(EnrollError::Used)?;
    let node = grant.consumed_by.ok_or(EnrollError::Used)?;
    let event: String = tx
        .query_row(
            "SELECT details_json FROM audit_events
             WHERE actor_kind='node' AND actor_id=?1 AND created_at=?2
               AND network_id=?3 AND action='node.enroll' AND target_type='node' AND target_id=?1",
            params![node, consumed_at, grant.network],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(EnrollError::Used)?;
    let receipt = serde_json::from_str::<EnrollmentEvent>(&event)
        .ok()
        .and_then(|event| event.retry_receipt)
        .ok_or(EnrollError::Used)?;
    ensure!(
        receipt.request_sha256 == hex::encode(request_digest)
            && receipt.user_id == grant.user.map(hex::encode),
        EnrollError::Used
    );
    let serial = hex::decode(receipt.certificate_serial).map_err(|_| EnrollError::Used)?;
    let (der, not_after, key): (Vec<u8>, i64, Vec<u8>) = tx
        .query_row(
            "SELECT c.der,c.not_after,n.wireguard_public_key
             FROM nodes n JOIN certificates c ON c.node_id=n.id AND c.network_id=n.network_id
             WHERE n.id=?1 AND n.network_id=?2 AND c.serial=?3
               AND n.revoked_at IS NULL AND c.revoked_at IS NULL
               AND c.not_before<=?4 AND c.not_after>?4
               AND n.enrollment_class='durable' AND n.lease_expires_at IS NULL
               AND n.user_id IS ?5 AND n.enabled_capabilities=?6
               AND n.wireguard_public_key IS NOT NULL
               AND (n.user_id IS NULL OR EXISTS(SELECT 1 FROM access_users u
                 WHERE u.id=n.user_id AND u.network_id=n.network_id AND u.enabled=1))",
            params![node, grant.network, serial, now, grant.user, grant.caps],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(EnrollError::Used)?;
    let mut addresses = tx.prepare_cached(
        "SELECT address FROM overlay_addresses
         WHERE node_id=?1 AND network_id=?2 AND released_at IS NULL ORDER BY length(address)",
    )?;
    let overlay_addresses = addresses
        .query_map(params![node, grant.network], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let response = EnrollmentResponse {
        network_id: grant.network.to_vec(),
        node_id: node.to_vec(),
        certificate_chain: Some(CertificateChain {
            certificates_der: std::iter::once(der)
                .chain(issuer.intermediates().iter().cloned())
                .collect(),
            not_after_unix_seconds: u64::try_from(not_after)?,
        }),
        overlay_addresses,
        enrollment_class: EnrollmentClass::DurableNode as i32,
        wireguard_public_key: key,
        ..Default::default()
    };
    // Abort rather than return changed addresses, a rotated key, or a chain
    // assembled from a different set of configured intermediates.
    ensure!(
        receipt.response_sha256 == response_digest(&response),
        EnrollError::Used
    );
    Ok(response)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };
    use rusqlite::Connection;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    #[test]
    fn durable_connector_retry_recovers_only_original_live_enrollment() -> Result<()> {
        let mut store = crate::SessionStore {
            db: Connection::open_in_memory()?,
        };
        let network = [1u8; 16];
        let secret = [2u8; 32];
        let tx = store.db.transaction()?;
        crate::schema::initialize(&tx, 1)?;
        tx.execute(
            "INSERT INTO networks(id,name,ipv4_address,ipv4_prefix_length,created_at)
             VALUES(?1,'test',x'0a010000',29,unixepoch())",
            [network],
        )?;
        tx.execute(
            "INSERT INTO enrollment_tokens(id,network_id,token_hash,expires_at,created_at,enabled_capabilities)
             VALUES(randomblob(16),?1,?2,unixepoch()+3600,unixepoch(),?3)",
            params![network, Sha256::digest(secret).as_slice(), ROUTER as i64],
        )?;
        tx.commit()?;
        let issuer_key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut ca = CertificateParams::new(vec![])?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca.self_signed(&issuer_key)?;
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(issuer_key.serialize_der()));
        let issuer = NodeIssuer::new(std::slice::from_ref(ca.der()), &key, 3600)?;
        let node_key = KeyPair::generate_for(&PKCS_ED25519)?;
        let csr = CertificateParams::new(vec![])?.serialize_request(&node_key)?;
        let request = EnrollmentRequest {
            enrollment_token: URL_SAFE_NO_PAD.encode(secret),
            pkcs10_csr_der: csr.der().to_vec(),
            requested_name: "test-connector".to_owned(),
            expected_network_id: network.to_vec(),
            expected_enrollment_class: EnrollmentClass::DurableNode as i32,
            wireguard_public_key: x25519_dalek::x25519(
                [3; 32],
                x25519_dalek::X25519_BASEPOINT_BYTES,
            )
            .to_vec(),
        };
        let original = store.redeem_enrollment(request.clone(), &issuer, || false)?;
        assert_eq!(
            original,
            store.redeem_enrollment(request.clone(), &issuer, || false)?
        );

        let mut changed = request.clone();
        changed.requested_name.push_str("-other");
        assert!(matches!(
            store
                .redeem_enrollment(changed, &issuer, || false)
                .unwrap_err()
                .downcast_ref(),
            Some(EnrollError::Used)
        ));
        let (epoch, nodes, certs, enrollments): (i64, i64, i64, i64) = store.db.query_row(
            "SELECT configuration_epoch, (SELECT count(*) FROM nodes),
                 (SELECT count(*) FROM certificates),
                 (SELECT count(*) FROM audit_events WHERE action='node.enroll')
             FROM networks",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        assert_eq!((epoch, nodes, certs, enrollments), (2, 1, 1, 1));

        store
            .db
            .execute("UPDATE certificates SET revoked_at=unixepoch()", [])?;
        assert!(matches!(
            store
                .redeem_enrollment(request, &issuer, || false)
                .unwrap_err()
                .downcast_ref(),
            Some(EnrollError::Used)
        ));
        Ok(())
    }
}
