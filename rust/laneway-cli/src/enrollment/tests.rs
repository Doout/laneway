use super::*;
use laneway_protocol::v1::CertificateChain;
use rcgen::{
    BasicConstraints, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, PublicKeyData, SanType,
};
use time::{Duration as TimeDuration, OffsetDateTime};

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn issuer(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut parameters = CertificateParams::default();
    parameters.distinguished_name.push(DnType::CommonName, name);
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    CertifiedIssuer::self_signed(parameters, KeyPair::generate().unwrap()).unwrap()
}

fn fixture(ca_pem: &[u8]) -> Controller<'_> {
    Controller {
        endpoint: "https://controller.example",
        quic_endpoint: "controller.example:8443",
        server_name: "controller.example",
        network_id: id(1),
        service_id: id(2),
        ca_pem,
    }
}

fn response(
    class: EnrollmentClass,
    keys: &Keys,
    cert_key: &impl PublicKeyData,
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> EnrollmentResponse {
    let now = OffsetDateTime::now_utc();
    let mut parameters = CertificateParams::default();
    parameters.not_before = now - TimeDuration::seconds(20);
    parameters.not_after = now + TimeDuration::seconds(90);
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    parameters.subject_alt_names.push(SanType::URI(
        format!("spiffe://laneway/network/{}/node/{}", id(1), id(3))
            .try_into()
            .unwrap(),
    ));
    let cert = parameters.signed_by(cert_key, issuer).unwrap();
    EnrollmentResponse {
        network_id: id(1).as_bytes().to_vec(),
        node_id: id(3).as_bytes().to_vec(),
        overlay_addresses: vec![vec![100, 96, 0, 5]],
        certificate_chain: Some(CertificateChain {
            certificates_der: vec![cert.der().to_vec()],
            not_after_unix_seconds: (now + TimeDuration::seconds(90)).unix_timestamp() as u64,
        }),
        enrollment_class: class as i32,
        lease_expires_at_unix_seconds: if class == EnrollmentClass::EphemeralUser {
            now.unix_timestamp() as u64 + 100
        } else {
            0
        },
        wireguard_public_key: keys.wg_public.to_vec(),
    }
}

#[test]
fn checks_issued_chain_and_both_generated_keys() {
    let ca = issuer("Enrollment root");
    let roots = ca.pem();
    let controller = fixture(roots.as_bytes());
    let keys = Keys::generate(Some("test")).unwrap();
    let class = EnrollmentClass::RememberedUser;
    let good = response(class, &keys, &keys.tls, &ca);
    let credentials = verify_enrollment(&controller, &keys, class, good.clone()).unwrap();
    assert_eq!(credentials.node_id, id(3));
    assert_eq!(
        credentials.overlays,
        ["100.96.0.5".parse::<IpAddr>().unwrap()]
    );
    assert!(credentials.lease_expires_at.is_none());
    let chain = tls::certificates(&credentials.certificate_pem).unwrap();
    tls::verify_key_pair(&chain, &credentials.private_key_pem).unwrap();
    assert!(certificate_times(&credentials.certificate_pem).unwrap().1 > SystemTime::now());

    let other_key = KeyPair::generate().unwrap();
    let other_ca = issuer("Wrong root");
    for bad in [
        response(class, &keys, &other_key, &ca),
        response(class, &keys, &keys.tls, &other_ca),
        EnrollmentResponse {
            wireguard_public_key: vec![0; 32],
            ..good.clone()
        },
        EnrollmentResponse {
            node_id: id(4).as_bytes().to_vec(),
            ..good.clone()
        },
        EnrollmentResponse {
            enrollment_class: EnrollmentClass::EphemeralUser as i32,
            ..good.clone()
        },
        EnrollmentResponse {
            overlay_addresses: vec![vec![0, 0, 0, 0]],
            ..good.clone()
        },
        EnrollmentResponse {
            lease_expires_at_unix_seconds: 1,
            ..good
        },
    ] {
        assert!(verify_enrollment(&controller, &keys, class, bad).is_err());
    }
}

#[test]
fn ephemeral_certificate_must_fit_unexpired_lease() {
    let ca = issuer("Ephemeral enrollment root");
    let roots = ca.pem();
    let controller = fixture(roots.as_bytes());
    let keys = Keys::generate(None).unwrap();
    let class = EnrollmentClass::EphemeralUser;
    let good = response(class, &keys, &keys.tls, &ca);
    assert!(
        verify_enrollment(&controller, &keys, class, good.clone())
            .unwrap()
            .lease_expires_at
            .is_some()
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for invalid_lease in [0, now - 1, now + 30, u64::MAX] {
        let bad = EnrollmentResponse {
            lease_expires_at_unix_seconds: invalid_lease,
            ..good.clone()
        };
        assert!(verify_enrollment(&controller, &keys, class, bad).is_err());
    }
}
