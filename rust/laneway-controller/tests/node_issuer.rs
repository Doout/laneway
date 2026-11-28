use anyhow::{Result, anyhow};
use laneway_controller::node_pki::{NodeIssuer, VerifiedCsr};
use laneway_protocol::{Id, Role, identity_from_certificate_der};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, SanType,
};
use rustls::RootCertStore;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use std::{collections::HashSet, sync::Arc, time::Duration};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate, X509CertificationRequest};

const NOW: i64 = 1_800_000_000;
const LIFETIME: i64 = 48 * 3600;

fn ca(name: &str, path_len: u8, expires: i64) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(vec![])?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = OffsetDateTime::from_unix_timestamp(NOW - 3600)?;
    params.not_after = OffsetDateTime::from_unix_timestamp(expires)?;
    Ok(params)
}

fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivatePkcs8KeyDer::from(key.serialize_der()).into()
}

#[test]
fn node_issuer_signs_only_the_authorized_identity_and_honors_lease_bounds() -> Result<()> {
    let root_key = KeyPair::generate_for(&PKCS_ED25519)?;
    let root_params = ca("Lab Root", 1, NOW + 72 * 3600)?;
    let root = root_params.self_signed(&root_key)?;
    let root_private_key = private_key(&root_key);
    let root_signer = Issuer::new(root_params, root_key);
    let intermediate_key = KeyPair::generate_for(&PKCS_ED25519)?;
    let intermediate =
        ca("Online issuer", 0, NOW + 86400)?.signed_by(&intermediate_key, &root_signer)?;
    let root_chain = std::slice::from_ref(root.der());
    let full_chain = [intermediate.der().clone(), root.der().clone()];
    let root_key = root_private_key;
    let intermediate_key = private_key(&intermediate_key);
    let direct = NodeIssuer::new(root_chain, &root_key, LIFETIME)?;
    let online = NodeIssuer::new(&full_chain, &intermediate_key, LIFETIME)?;
    assert_eq!(
        online.intermediates(),
        NodeIssuer::new(
            std::slice::from_ref(intermediate.der()),
            &intermediate_key,
            LIFETIME,
        )?
        .intermediates()
    );
    assert!(NodeIssuer::new(root_chain, &intermediate_key, LIFETIME).is_err());
    assert!(NodeIssuer::new(root_chain, &root_key, 0).is_err());
    let reverse = [root.der().clone(), intermediate.der().clone()];
    assert!(NodeIssuer::new(&reverse, &root_key, LIFETIME).is_err());
    let duplicate = [intermediate.der().clone(), intermediate.der().clone()];
    assert!(NodeIssuer::new(&duplicate, &intermediate_key, LIFETIME).is_err());

    let mut trust = RootCertStore::empty();
    trust.add(root.der().clone())?;
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(trust),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()?;
    let network = Id::new([0x11; 16])?;
    let node = Id::new([0x33; 16])?;
    let mut serials = HashSet::new();

    // OpenSSL-generated public requests exercise RSA signature identifiers
    // without requiring a system tool or a private fixture key at test time.
    let mut requests = vec![
        include_bytes!("fixtures/rsa-pkcs1.csr").to_vec(),
        include_bytes!("fixtures/rsa-pss.csr").to_vec(),
    ];
    for algorithm in [
        &PKCS_ED25519,
        &PKCS_ECDSA_P256_SHA256,
        &PKCS_ECDSA_P384_SHA384,
    ] {
        let key = KeyPair::generate_for(algorithm)?;
        let mut params = CertificateParams::new(vec!["requested.example".into()])?;
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Requester");
        params.subject_alt_names.push(SanType::URI(
            format!("spiffe://laneway/network/{network}/relay/{node}").try_into()?,
        ));
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55555, 1],
                vec![5, 0],
            ));
        requests.push(params.serialize_request(&key)?.der().to_vec());
    }

    for request in requests {
        let csr = VerifiedCsr::parse(&request)?;
        let (_, requester) = X509CertificationRequest::from_der(&request)
            .map_err(|error| anyhow!("decode generated CSR: {error}"))?;
        for (issuer, chain, lease, expires) in [
            (&direct, &[][..], None, NOW + LIFETIME),
            (&online, &full_chain[..1], None, NOW + 86400),
            (&online, &full_chain[..1], Some(NOW + 300), NOW + 300),
        ] {
            let issued = issuer.issue(&csr, network, node, NOW, lease)?;
            let der = issued.der.into();
            verifier.verify_client_cert(
                &der,
                chain,
                UnixTime::since_unix_epoch(Duration::from_secs(NOW.try_into()?)),
            )?;
            let (_, leaf) = X509Certificate::from_der(der.as_ref())
                .map_err(|error| anyhow!("decode issued certificate: {error}"))?;
            let identity = identity_from_certificate_der(der.as_ref())?;
            assert_eq!(identity.network_id, network);
            assert_eq!(identity.subject_id, node);
            assert_eq!(identity.role, Role::Node);
            assert_eq!(
                leaf.public_key().raw,
                requester.certification_request_info.subject_pki.raw
            );
            assert_eq!(
                leaf.subject_alternative_name()?
                    .unwrap()
                    .value
                    .general_names
                    .len(),
                1
            );
            assert_eq!(leaf.subject().iter_organization().count(), 0);
            assert!(!leaf.basic_constraints()?.unwrap().value.ca);
            assert!(leaf.key_usage()?.unwrap().value.digital_signature());
            assert_eq!(leaf.validity().not_before.timestamp(), NOW - 60);
            assert_eq!(leaf.validity().not_after.timestamp(), expires);
            assert!(serials.insert(issued.serial));
            assert!(
                leaf.extensions()
                    .iter()
                    .all(|ext| ext.oid.to_id_string() != "1.3.6.1.4.1.55555.1")
            );
        }
        assert!(online.issue(&csr, network, node, NOW, Some(NOW)).is_err());
        assert!(
            online
                .issue(&csr, network, node, NOW + 86400, None)
                .is_err()
        );
        let mut trailing = request.clone();
        trailing.push(0);
        assert!(VerifiedCsr::parse(&trailing).is_err());
        let mut damaged = request;
        *damaged.last_mut().unwrap() ^= 1;
        assert!(VerifiedCsr::parse(&damaged).is_err());
    }
    assert!(VerifiedCsr::parse(&[]).is_err());
    assert!(VerifiedCsr::parse(&vec![0; 65537]).is_err());
    Ok(())
}
