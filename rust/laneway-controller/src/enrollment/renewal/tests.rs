use super::*;
use crate::enrollment::{
    enroll_with_clock,
    tests::{NOW, fixture, request, token},
};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519, PublicKeyData};

fn renewal_request(value: Option<u8>) -> (RenewalRequest, KeyPair) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .unwrap();
    let wireguard = value
        .map(|value| {
            x25519_dalek::x25519([value; 32], x25519_dalek::X25519_BASEPOINT_BYTES).to_vec()
        })
        .unwrap_or_default();
    (
        RenewalRequest {
            pkcs10_csr_der: csr.der().to_vec(),
            wireguard_public_key: wireguard,
        },
        key,
    )
}

#[test]
fn rotates_bound_key_and_reissues_same_key_without_advancing_epoch() {
    let (_dir, mut store, authority) = fixture();
    let secret = token(
        &mut store,
        10,
        "remembered",
        None,
        "remembered",
        SUBNET_ROUTER,
    );
    let (initial, _) = request(&secret, EnrollmentClass::RememberedUser);
    let initial = enroll_with_clock(&mut store, &authority, initial, || Ok(NOW), || false).unwrap();
    let initial_chain = initial.certificate_chain.unwrap();
    let old_leaf = &initial_chain.certificates_der[0];
    let (replacement, key) = renewal_request(Some(44));
    let canceled = AtomicBool::new(false);
    let renewed = renew_with_clock(
        &mut store,
        &authority,
        old_leaf,
        replacement.clone(),
        &canceled,
        || Ok(NOW + 1),
    )
    .unwrap();
    assert_eq!(
        renewed.wireguard_public_key,
        replacement.wireguard_public_key
    );
    assert_ne!(renewed.wireguard_public_key, initial.wireguard_public_key);
    let issued = renewed.certificate_chain.unwrap().certificates_der;
    let fresh_leaf = &issued[0];
    assert_eq!(
        NodePeer::from_tls_leaf(old_leaf).unwrap().node_id,
        NodePeer::from_tls_leaf(fresh_leaf).unwrap().node_id
    );
    let (_, parsed) = x509_parser::parse_x509_certificate(fresh_leaf).unwrap();
    assert_eq!(parsed.public_key().raw, key.subject_public_key_info());

    // A repeated CSR and an omitted WG key are both accepted by Go. Neither
    // changes the active WG binding or advances the network configuration.
    let repeated = renew_with_clock(
        &mut store,
        &authority,
        old_leaf,
        replacement,
        &canceled,
        || Ok(NOW + 2),
    )
    .unwrap();
    assert_eq!(repeated.wireguard_public_key, renewed.wireguard_public_key);
    assert_ne!(
        repeated.certificate_chain.unwrap().certificates_der[0],
        *fresh_leaf
    );
    let (compat, _) = renewal_request(None);
    let legacy = renew_with_clock(
        &mut store,
        &authority,
        fresh_leaf,
        compat,
        &canceled,
        || Ok(NOW + 3),
    )
    .unwrap();
    assert_eq!(legacy.wireguard_public_key, renewed.wireguard_public_key);

    let tx = store.enrollment_transaction().unwrap();
    let authenticated = NodePeer::from_tls_leaf(old_leaf)
        .unwrap()
        .authenticate(&tx, NOW + 3)
        .unwrap();
    assert_eq!(authenticated.class, EnrollmentClass::RememberedUser);
    assert_eq!(authenticated.configuration_epoch, 3);
    assert_eq!(authenticated.enabled_capabilities, SUBNET_ROUTER as u64);
    let (certs, rotates): (i64, i64) = tx
        .query_row(
            "SELECT (SELECT count(*) FROM certificates),
            (SELECT count(*) FROM audit_events WHERE action='node.wireguard_key.rotate')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((certs, rotates), (4, 1));
}

#[test]
fn denies_revoked_or_unrecorded_certificates_and_expired_leases() {
    let (_dir, mut store, authority) = fixture();
    let secret = token(&mut store, 10, "ephemeral", Some(300), "temporary", 0);
    let (initial, _) = request(&secret, EnrollmentClass::EphemeralUser);
    let initial = enroll_with_clock(&mut store, &authority, initial, || Ok(NOW), || false).unwrap();
    let initial_chain = initial.certificate_chain.unwrap();
    let leaf = &initial_chain.certificates_der[0];
    let peer = NodePeer::from_tls_leaf(leaf).unwrap();
    let (renewal, _) = renewal_request(Some(77));
    let canceled = AtomicBool::new(false);
    let valid = renew_with_clock(
        &mut store,
        &authority,
        leaf,
        renewal.clone(),
        &canceled,
        || Ok(NOW + 50),
    )
    .unwrap();
    assert_eq!(
        valid.certificate_chain.unwrap().not_after_unix_seconds,
        (NOW + 300) as u64
    );
    assert_eq!(
        renew_with_clock(
            &mut store,
            &authority,
            leaf,
            renewal.clone(),
            &canceled,
            || Ok(NOW + 300)
        )
        .unwrap_err()
        .status,
        403
    );

    let mut altered = leaf.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert_eq!(
        renew_with_clock(
            &mut store,
            &authority,
            &altered,
            renewal.clone(),
            &canceled,
            || Ok(NOW + 51)
        )
        .unwrap_err()
        .status,
        403,
    );

    let tx = store.enrollment_transaction().unwrap();
    tx.execute(
        "UPDATE certificates SET revoked_at=?1 WHERE serial=?2",
        params![NOW + 20, peer.serial],
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        renew_with_clock(
            &mut store,
            &authority,
            leaf,
            renewal.clone(),
            &canceled,
            || Ok(NOW + 51)
        )
        .unwrap_err()
        .status,
        403
    );

    let (_, unrecorded_key) = renewal_request(None);
    let unrecorded = authority
        .issue(
            &rcgen::SubjectPublicKeyInfo::from_der(&unrecorded_key.subject_public_key_info())
                .unwrap(),
            peer.network_id,
            peer.node_id,
            Some(NOW + 300),
            NOW + 51,
        )
        .unwrap();
    assert_eq!(
        renew_with_clock(
            &mut store,
            &authority,
            &unrecorded.leaf,
            renewal,
            &canceled,
            || Ok(NOW + 52)
        )
        .unwrap_err()
        .status,
        403
    );
}

#[test]
fn duplicate_wireguard_binding_rolls_back_certificate_and_epoch() {
    let (_dir, mut store, authority) = fixture();
    let first_token = token(&mut store, 10, "durable", None, "first", 0);
    let second_token = token(&mut store, 11, "remembered", None, "second", 0);
    let (first, _) = request(&first_token, EnrollmentClass::DurableNode);
    let (second, _) = request(&second_token, EnrollmentClass::RememberedUser);
    let first = enroll_with_clock(&mut store, &authority, first, || Ok(NOW), || false).unwrap();
    let second = enroll_with_clock(&mut store, &authority, second, || Ok(NOW), || false).unwrap();
    let first_chain = first.certificate_chain.unwrap();
    let first_leaf = &first_chain.certificates_der[0];
    let (mut replacement, _) = renewal_request(None);
    replacement.wireguard_public_key = second.wireguard_public_key;
    let error = renew_with_clock(
        &mut store,
        &authority,
        first_leaf,
        replacement,
        &AtomicBool::new(false),
        || Ok(NOW + 1),
    )
    .unwrap_err();
    assert_eq!(error.status, 409);
    let tx = store.enrollment_transaction().unwrap();
    let auth = NodePeer::from_tls_leaf(first_leaf)
        .unwrap()
        .authenticate(&tx, NOW + 1)
        .unwrap();
    assert_eq!(
        auth.wireguard_key.unwrap().as_slice(),
        first.wireguard_public_key
    );
    assert_eq!(auth.configuration_epoch, 3);
    assert_eq!(
        tx.query_row("SELECT count(*) FROM certificates", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn concurrent_identical_renewals_only_advance_the_epoch_once() {
    use std::sync::{Barrier, Mutex};

    let (_dir, mut store, authority) = fixture();
    let secret = token(&mut store, 10, "durable", None, "overlapping", 0);
    let (initial, _) = request(&secret, EnrollmentClass::DurableNode);
    let initial = enroll_with_clock(&mut store, &authority, initial, || Ok(NOW), || false).unwrap();
    let old_leaf = initial
        .certificate_chain
        .unwrap()
        .certificates_der
        .remove(0);
    let (replacement, _) = renewal_request(Some(44));
    let store = Mutex::new(store);
    let start = Barrier::new(2);

    let renewed = std::thread::scope(|scope| {
        let renew_one = || {
            start.wait();
            renew_with_clock(
                &mut store.lock().unwrap(),
                &authority,
                &old_leaf,
                replacement.clone(),
                &AtomicBool::new(false),
                || Ok(NOW + 1),
            )
            .unwrap()
        };
        let first = scope.spawn(renew_one);
        let second = renew_one();
        [first.join().unwrap(), second]
    });
    assert_eq!(
        renewed[0].wireguard_public_key,
        renewed[1].wireguard_public_key
    );
    assert_ne!(renewed[0].certificate_chain, renewed[1].certificate_chain);
    let mut store = store.into_inner().unwrap();
    let tx = store.enrollment_transaction().unwrap();
    let auth = NodePeer::from_tls_leaf(&old_leaf)
        .unwrap()
        .authenticate(&tx, NOW + 1)
        .unwrap();
    assert_eq!(auth.configuration_epoch, 3);
}
