//! Certificate issuance for enrollment and renewal. A verified CSR contributes
//! only a public key. The authorized transaction supplies both identity IDs,
//! the clock, and any lease deadline; requested names and extensions are not grants.
use anyhow::{Context, Result, ensure};
use laneway_protocol::{AuthenticatedIdentity, Id, Role};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer,
};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate, X509CertificationRequest};

const MAX_DER: usize = 64 * 1024;
const SERVICE_LIFETIME: i64 = 30 * 24 * 60 * 60;

pub struct VerifiedCsr(SubjectPublicKeyInfo);

// Check the *full* algorithm identifier (including parameters), the type of
// the signer's public key and the signed bytes together. In particular, RSA
// PSS and PKCS#1 are not interchangeable. Use rustls' existing provider.
fn verify_signed_der(der: &[u8], spki: &[u8]) -> Result<()> {
    let (tbs, algorithm, (sig, bits)) = yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            Ok((
                r.next().read_der()?,
                r.next().read_tagged_der()?,
                r.next().read_bitvec_bytes()?,
            ))
        })
    })
    .map_err(|_| anyhow::anyhow!("invalid signed DER sequence"))?;
    ensure!(
        algorithm.tag() == yasna::tags::TAG_SEQUENCE && bits == sig.len() * 8,
        "invalid signature encoding"
    );
    let spki = SubjectPublicKeyInfoDer::from(spki);
    let key = webpki::RawPublicKeyEntity::try_from(&spki).context("invalid signing public key")?;
    ensure!(
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .all
            .iter()
            .any(|alg| alg.signature_alg_id().as_ref() == algorithm.value()
                && key.verify_signature(*alg, &tbs, &sig).is_ok()),
        "invalid or unsupported signature"
    );
    Ok(())
}

impl VerifiedCsr {
    pub fn parse(der: &[u8]) -> Result<Self> {
        ensure!(
            !der.is_empty() && der.len() <= MAX_DER,
            "PKCS#10 CSR must be 1..65536 bytes"
        );
        let (rest, csr) = X509CertificationRequest::from_der(der)
            .map_err(|_| anyhow::anyhow!("invalid PKCS#10 CSR"))?;
        let info = &csr.certification_request_info;
        ensure!(
            rest.is_empty() && info.version.0 == 0,
            "invalid PKCS#10 CSR"
        );
        let spki = info.subject_pki.raw;
        verify_signed_der(der, spki).context("invalid PKCS#10 CSR signature")?;
        Ok(Self(
            SubjectPublicKeyInfo::from_der(spki).context("unsupported CSR public key")?,
        ))
    }
}

pub struct NodeIssuer {
    signer: Issuer<'static, KeyPair>,
    intermediates: Vec<Vec<u8>>,
    valid_from: i64,
    valid_to: i64,
    lifetime_seconds: i64,
}

pub struct IssuedCertificate {
    pub serial: Vec<u8>,
    pub der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

impl NodeIssuer {
    /// The operator supplies trusted CA material, issuer first; an offline
    /// root key is not required. This does not discover or trust peer-sent CAs.
    pub fn new(
        chain: &[CertificateDer<'_>],
        key: &PrivateKeyDer<'_>,
        lifetime_seconds: i64,
    ) -> Result<Self> {
        ensure!(
            !chain.is_empty() && chain.len() <= 8 && lifetime_seconds > 0,
            "invalid node CA configuration"
        );
        let key = KeyPair::try_from(key).context("invalid CA signing key")?;
        let mut parsed = Vec::new();
        for der in chain {
            ensure!(der.len() <= MAX_DER, "oversized CA certificate");
            let (rest, cert) = X509Certificate::from_der(der)
                .map_err(|_| anyhow::anyhow!("invalid CA certificate"))?;
            ensure!(
                rest.is_empty() && cert.signature_algorithm == cert.tbs_certificate.signature,
                "invalid CA certificate"
            );
            let bc = cert
                .basic_constraints()?
                .context("missing CA basic constraints")?
                .value;
            ensure!(
                bc.ca
                    && bc
                        .path_len_constraint
                        .is_none_or(|n| n as usize >= parsed.len()),
                "invalid CA path length or basic constraints"
            );
            ensure!(
                cert.key_usage()?.is_none_or(|ku| ku.value.key_cert_sign()),
                "CA may not sign certificates"
            );
            ensure!(
                !parsed
                    .iter()
                    .any(|p: &X509Certificate| p.as_raw() == cert.as_raw()),
                "duplicate CA certificate"
            );
            parsed.push(cert);
        }
        ensure!(
            key.subject_public_key_info() == parsed[0].public_key().raw,
            "CA certificate and key do not match"
        );
        let mut intermediates = Vec::new();
        for (i, cert) in parsed.iter().enumerate() {
            if let Some(parent) = parsed.get(i + 1) {
                ensure!(
                    cert.issuer() == parent.subject(),
                    "CA chain must be issuer first"
                );
                verify_signed_der(cert.as_raw(), parent.public_key().raw)
                    .context("invalid CA chain signature")?;
            } else if cert.issuer() == cert.subject() {
                verify_signed_der(cert.as_raw(), cert.public_key().raw)
                    .context("invalid root signature")?;
                continue; // Do not return the trust anchor to the node.
            }
            intermediates.push(cert.as_raw().to_vec());
        }
        let valid_from = parsed
            .iter()
            .map(|c| c.validity().not_before.timestamp())
            .max()
            .unwrap();
        let valid_to = parsed
            .iter()
            .map(|c| c.validity().not_after.timestamp())
            .min()
            .unwrap();
        ensure!(
            valid_from < valid_to,
            "CA chain has no common validity interval"
        );
        Ok(Self {
            signer: Issuer::from_ca_cert_der(&chain[0], key)?,
            intermediates,
            valid_from,
            valid_to,
            lifetime_seconds,
        })
    }

    pub fn intermediates(&self) -> &[Vec<u8>] {
        &self.intermediates
    }

    /// Signs a local controller replacement, retaining the identity and
    /// names selected by the operator's original trusted service certificate.
    /// Unlike node enrollment, no network caller can invoke this operation.
    pub fn issue_controller(
        &self,
        identity: AuthenticatedIdentity,
        names: &[SanType],
        now: i64,
        minimum_validity: i64,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        ensure!(
            identity.role == Role::Controller && !names.is_empty(),
            "invalid controller service names"
        );
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let (chain, _) = self.sign_service(&key, identity, names, now, minimum_validity)?;
        Ok((chain, PrivatePkcs8KeyDer::from(key.serialize_der()).into()))
    }

    pub(crate) fn issue_relay(
        &self,
        csr: &VerifiedCsr,
        identity: AuthenticatedIdentity,
        names: &[SanType],
        now: i64,
        minimum_validity: i64,
    ) -> Result<laneway_protocol::v1::CertificateChain> {
        ensure!(identity.role == Role::Relay, "invalid relay role");
        let (chain, expires) = self.sign_service(&csr.0, identity, names, now, minimum_validity)?;
        Ok(laneway_protocol::v1::CertificateChain {
            certificates_der: chain.into_iter().map(|der| der.as_ref().to_vec()).collect(),
            not_after_unix_seconds: expires.try_into()?,
        })
    }

    fn sign_service(
        &self,
        key: &impl PublicKeyData,
        identity: AuthenticatedIdentity,
        names: &[SanType],
        now: i64,
        minimum_validity: i64,
    ) -> Result<(Vec<CertificateDer<'static>>, i64)> {
        let role = match identity.role {
            Role::Relay => "relay",
            Role::Controller => "controller",
            _ => anyhow::bail!("not a renewable service role"),
        };
        ensure!(
            names
                .iter()
                .all(|name| matches!(name, SanType::DnsName(_) | SanType::IpAddress(_))),
            "invalid service names"
        );
        ensure!(
            self.valid_from <= now && now < self.valid_to,
            "service issuer is not currently valid"
        );
        let not_after = now.saturating_add(SERVICE_LIFETIME).min(self.valid_to);
        ensure!(
            not_after.saturating_sub(now) >= minimum_validity,
            "service issuer needs operator renewal"
        );
        let mut serial = [0; 16];
        getrandom::fill(&mut serial)?;
        if serial == [0; 16] {
            serial[15] = 1;
        }
        let mut params = CertificateParams::default();
        params.distinguished_name.push(
            DnType::CommonName,
            format!("laneway-{role}-{}", identity.subject_id),
        );
        params.subject_alt_names = names.to_vec();
        params.subject_alt_names.push(SanType::URI(
            format!(
                "spiffe://laneway/network/{}/{role}/{}",
                identity.network_id, identity.subject_id
            )
            .try_into()?,
        ));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if identity.role == Role::Relay {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
        }
        params.use_authority_key_identifier_extension = true;
        params.not_before =
            OffsetDateTime::from_unix_timestamp(now.saturating_sub(60).max(self.valid_from))?;
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after)?;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let certificate = params.signed_by(key, &self.signer)?;
        let chain = std::iter::once(certificate.der().clone())
            .chain(self.intermediates.iter().cloned().map(CertificateDer::from))
            .collect();
        Ok((chain, not_after))
    }

    pub fn issue(
        &self,
        csr: &VerifiedCsr,
        network: Id,
        node: Id,
        now: i64,
        lease: Option<i64>,
    ) -> Result<IssuedCertificate> {
        ensure!(
            self.valid_from <= now && now < self.valid_to,
            "node CA is not currently valid"
        );
        let not_after = now
            .saturating_add(self.lifetime_seconds)
            .min(self.valid_to)
            .min(lease.unwrap_or(i64::MAX));
        ensure!(now < not_after, "node lease has expired");
        let not_before = now.saturating_sub(60);
        let mut serial = [0; 16];
        getrandom::fill(&mut serial)?;
        if serial == [0; 16] {
            serial[15] = 1
        }
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("laneway-node-{node}"));
        params.subject_alt_names = vec![SanType::URI(
            format!("spiffe://laneway/network/{network}/node/{node}").try_into()?,
        )];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.use_authority_key_identifier_extension = true;
        params.not_before = OffsetDateTime::from_unix_timestamp(not_before)?;
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after)?;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let cert = params.signed_by(&csr.0, &self.signer)?;
        let serial = serial.iter().skip_while(|b| **b == 0).copied().collect();
        Ok(IssuedCertificate {
            der: cert.der().to_vec(),
            serial,
            not_before,
            not_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, PKCS_ED25519};
    use rustls::pki_types::PrivatePkcs8KeyDer;

    #[test]
    fn rejects_unsigned_changes_to_requests_and_ca_certificates() -> Result<()> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let ca_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut params = CertificateParams::new(vec![])?;
        let csr = params.serialize_request(&key)?;
        VerifiedCsr::parse(csr.der())?;
        let mut changed = csr.der().to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(VerifiedCsr::parse(&changed).is_err());
        let ordinary = params.self_signed(&key)?;
        assert!(NodeIssuer::new(std::slice::from_ref(ordinary.der()), &ca_key, 300).is_err());
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = params.self_signed(&key)?;
        NodeIssuer::new(std::slice::from_ref(ca.der()), &ca_key, 300)?;
        let mut changed = ca.der().to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(NodeIssuer::new(&[changed.into()], &ca_key, 300).is_err());
        Ok(())
    }
}
