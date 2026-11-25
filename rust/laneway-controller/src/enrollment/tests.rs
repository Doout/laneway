use super::*;
use laneway_config::Config;
use laneway_protocol::{AuthenticatedIdentity, Role, identity_from_certificate_der};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ED25519,
    PublicKeyData,
};
use tempfile::TempDir;

use crate::store::InitialNetwork;

pub(super) const NOW: i64 = 1_900_000_000;

pub(super) fn id(value: u8) -> Id {
    Id::new([value; 16]).unwrap()
}

pub(super) fn fixture() -> (TempDir, Store, EnrollmentAuthority) {
    let dir = tempfile::tempdir().unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate_for(&PKCS_ED25519).unwrap())
        .unwrap();
    let ca_cert = dir.path().join("authority.crt");
    let ca_key = dir.path().join("authority.key");
    std::fs::write(&ca_cert, ca.pem()).unwrap();
    std::fs::write(&ca_key, ca.key().serialize_pem()).unwrap();
    let mut config = Config::default();
    config.tls.ca = ca_cert.to_str().unwrap().to_owned();
    config.controller.ca_private_key = ca_key.to_str().unwrap().to_owned();
    let authority = EnrollmentAuthority::from_config(&config).unwrap();
    let mut store = Store::open(&dir.path().join("controller.db")).unwrap();
    store
        .prepare(
            Some(
                &InitialNetwork::new(
                    id(1),
                    "fixture".to_owned(),
                    "100.115.0.0/30".parse().unwrap(),
                    Some("fd00:115::/120".parse().unwrap()),
                )
                .unwrap(),
            ),
            AuthenticatedIdentity {
                network_id: id(1),
                role: Role::Controller,
                subject_id: id(2),
            },
            None,
        )
        .unwrap();
    (dir, store, authority)
}

pub(super) fn token(
    store: &mut Store,
    value: u8,
    class: &str,
    lifetime: Option<i64>,
    name: &str,
    capabilities: i64,
) -> String {
    let secret = URL_SAFE_NO_PAD.encode([value; 32]);
    let hash = token_hash(&secret).unwrap();
    let tx = store.enrollment_transaction().unwrap();
    tx.execute(
        "INSERT INTO enrollment_tokens (id,network_id,token_hash,label,expires_at,created_at,
         enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities)
         VALUES (?1,?2,?3,'fixture',?4,?5,?6,?7,?8,?9)",
        params![
            id(value).as_bytes(),
            id(1).as_bytes(),
            hash,
            NOW + 3600,
            NOW - 5,
            class,
            lifetime,
            name,
            capabilities
        ],
    )
    .unwrap();
    tx.commit().unwrap();
    secret
}

pub(super) fn request(secret: &str, class: EnrollmentClass) -> (EnrollmentRequest, KeyPair) {
    let mut private = [5; 32];
    private[31] = class as u8 + 1;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .unwrap();
    (
        EnrollmentRequest {
            enrollment_token: secret.into(),
            requested_name: String::new(),
            wireguard_public_key: public.to_vec(),
            expected_network_id: id(1).as_bytes().to_vec(),
            expected_enrollment_class: class as i32,
            pkcs10_csr_der: csr.der().to_vec(),
        },
        key,
    )
}

#[test]
fn durable_enrollment_binds_keys_and_only_consumes_once() {
    let (_dir, mut store, authority) = fixture();
    let secret = token(&mut store, 10, "durable", None, "fixture-node", 0);
    let (request, tls) = request(&secret, EnrollmentClass::DurableNode);
    for invalid in [
        EnrollmentRequest {
            expected_network_id: id(2).as_bytes().to_vec(),
            ..request.clone()
        },
        EnrollmentRequest {
            expected_enrollment_class: EnrollmentClass::RememberedUser as i32,
            ..request.clone()
        },
        EnrollmentRequest {
            requested_name: "wrong-name".into(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            enroll_with_clock(&mut store, &authority, invalid, || Ok(NOW), || false)
                .unwrap_err()
                .status,
            403
        );
    }
    let response = enroll_with_clock(
        &mut store,
        &authority,
        request.clone(),
        || Ok(NOW),
        || false,
    )
    .unwrap();
    assert_eq!(response.wireguard_public_key, request.wireguard_public_key);
    assert_eq!(
        response.overlay_addresses,
        vec![
            vec![100, 115, 0, 1],
            "fd00:115::1".parse::<Ipv6Addr>().unwrap().octets().to_vec()
        ]
    );
    let chain = response.certificate_chain.unwrap();
    assert_eq!(chain.certificates_der.len(), 1);
    let leaf = &chain.certificates_der[0];
    let (_, certificate) = x509_parser::parse_x509_certificate(leaf).unwrap();
    assert_eq!(certificate.public_key().raw, tls.subject_public_key_info());
    let identity = identity_from_certificate_der(leaf).unwrap();
    assert_eq!(identity.role, Role::Node);
    assert_eq!(identity.subject_id.as_bytes().as_slice(), response.node_id);
    let error =
        enroll_with_clock(&mut store, &authority, request, || Ok(NOW), || false).unwrap_err();
    assert_eq!(error.status, 409);
    assert_eq!(error.detail, "enrollment code has already been used");

    let tx = store.enrollment_transaction().unwrap();
    let (nodes, certs, audits, epoch): (i64, i64, i64, i64) = tx
        .query_row(
            "SELECT (SELECT count(*) FROM nodes),(SELECT count(*) FROM certificates),
            (SELECT count(*) FROM audit_events WHERE action IN ('certificate.issue','node.enroll')),
            (SELECT configuration_epoch FROM networks)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((nodes, certs, audits, epoch), (1, 1, 2, 2));
}

#[test]
fn ephemeral_lease_caps_certificate_and_revokes_all_derivative_state() {
    let (_dir, mut store, authority) = fixture();
    let secret = token(
        &mut store,
        10,
        "ephemeral",
        Some(300),
        "temporary",
        EXIT_NODE,
    );
    let (request, _) = request(&secret, EnrollmentClass::EphemeralUser);
    let response =
        enroll_with_clock(&mut store, &authority, request, || Ok(NOW), || false).unwrap();
    assert_eq!(response.lease_expires_at_unix_seconds, (NOW + 300) as u64);
    assert_eq!(
        response.certificate_chain.unwrap().not_after_unix_seconds,
        (NOW + 300) as u64
    );
    expire(store.enrollment_transaction().unwrap(), NOW + 300).unwrap();
    let tx = store.enrollment_transaction().unwrap();
    let state: (String, i64, i64, String, i64) = tx
        .query_row(
            "SELECT (SELECT state FROM routes),(SELECT revoked_at FROM nodes),
            (SELECT count(*) FROM overlay_addresses WHERE released_at IS NOT NULL),
            (SELECT revocation_reason FROM certificates),
            (SELECT configuration_epoch FROM networks)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(
        state,
        (
            "withdrawn".into(),
            NOW + 300,
            2,
            "ephemeral lease expired".into(),
            3
        )
    );
}

#[test]
fn credential_persistence_failure_rolls_back_token_and_address_cursor() {
    let (_dir, mut store, authority) = fixture();
    let secret = token(&mut store, 10, "remembered", None, "rollback", 0);
    let (request, _) = request(&secret, EnrollmentClass::RememberedUser);
    let tx = store.enrollment_transaction().unwrap();
    tx.execute_batch(
        "CREATE TRIGGER reject_certificate BEFORE INSERT ON certificates
        BEGIN SELECT RAISE(ABORT,'fixture signing persistence failure'); END;",
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(
        enroll_with_clock(
            &mut store,
            &authority,
            request.clone(),
            || Ok(NOW),
            || false
        )
        .is_err()
    );

    let tx = store.enrollment_transaction().unwrap();
    let (nodes, overlays, consumed, next): (i64, i64, i64, i64) = tx
        .query_row(
            "SELECT (SELECT count(*) FROM nodes),(SELECT count(*) FROM overlay_addresses),
            (SELECT count(*) FROM enrollment_tokens WHERE consumed_at IS NOT NULL),
            (SELECT next_ipv4 FROM networks)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((nodes, overlays, consumed, next), (0, 0, 0, 1));
    tx.execute_batch("DROP TRIGGER reject_certificate").unwrap();
    tx.commit().unwrap();
    let response =
        enroll_with_clock(&mut store, &authority, request, || Ok(NOW), || false).unwrap();
    assert_eq!(response.overlay_addresses[0], vec![100, 115, 0, 1]);
}

#[test]
fn cancellation_before_commit_rolls_back_enrollment() {
    let (_dir, mut store, authority) = fixture();
    let secret = token(&mut store, 10, "durable", None, "cancellation", 0);
    let (request, _) = request(&secret, EnrollmentClass::DurableNode);
    let checks = std::cell::Cell::new(0);
    assert!(
        enroll_with_clock(
            &mut store,
            &authority,
            request.clone(),
            || Ok(NOW),
            || {
                checks.set(checks.get() + 1);
                checks.get() > 1
            }
        )
        .is_err()
    );
    let response =
        enroll_with_clock(&mut store, &authority, request, || Ok(NOW), || false).unwrap();
    assert_eq!(response.overlay_addresses[0], vec![100, 115, 0, 1]);
}

#[test]
fn issue_requires_durable_root_and_persists_only_the_hash() {
    let (_dir, mut store, _authority) = fixture();
    let root = store.root_principal().unwrap();
    let now = clock().unwrap();
    let request = || {
        serde_json::from_value(serde_json::json!({
            "network_id": id(1).to_string(),
            "label": "fixture",
            "expires_at_unix_seconds": now + 600,
            "enrollment_class": "ephemeral",
            "session_lifetime_seconds": 300,
            "requested_name": "temporary",
            "enabled_capabilities": SUBNET_ROUTER,
        }))
        .unwrap()
    };
    let canceled = AtomicBool::new(false);
    match issue_token(&mut store, id(9), request(), &canceled) {
        Ok(_) => panic!("wrong service principal was accepted"),
        Err(error) => assert_eq!(error.status, 401),
    }
    let invalid = serde_json::from_value(serde_json::json!({
        "network_id": id(1).to_string(), "expires_at_unix_seconds": now + 600,
        "enrollment_class": "ephemeral", "session_lifetime_seconds": 299,
    }))
    .unwrap();
    assert!(issue_token(&mut store, root, invalid, &canceled).is_err());
    let issued = issue_token(&mut store, root, request(), &canceled).unwrap();
    let serialized = serde_json::to_value(&issued).unwrap();
    let hash = token_hash(serialized["enrollment_token"].as_str().unwrap()).unwrap();
    let tx = store.enrollment_transaction().unwrap();
    let (stored, class, lifetime, name, capabilities): (Vec<u8>, String, i64, String, i64) = tx
        .query_row(
            "SELECT token_hash,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities FROM enrollment_tokens",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap();
    assert_eq!(stored, hash);
    assert_eq!(
        (class.as_str(), lifetime, name.as_str(), capabilities),
        ("ephemeral", 300, "temporary", SUBNET_ROUTER)
    );
    let actor: Vec<u8> = tx.query_row(
        "SELECT actor_id FROM audit_events WHERE actor_kind='service_principal' AND action='enrollment_token.issue'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(actor, root.as_bytes());
}
