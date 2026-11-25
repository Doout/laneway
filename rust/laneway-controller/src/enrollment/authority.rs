use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use anyhow::{Context, Result, ensure};
use laneway_config::Config;
use laneway_protocol::Id;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose,
    PublicKeyData, SanType, SerialNumber,
};
use rustls::pki_types::{PrivateKeyDer, UnixTime};
use time::OffsetDateTime;
use x509_parser::{parse_x509_certificate, prelude::FromDer};

use super::{EnrollmentError, random_bytes};

pub(crate) struct EnrollmentAuthority {
    issuer: Issuer<'static, KeyPair>,
    chain: Vec<Vec<u8>>,
    valid_from: i64,
    valid_until: i64,
    leaf_validity: i64,
}

pub(super) struct Material {
    pub(super) serial: Vec<u8>,
    pub(super) leaf: Vec<u8>,
    pub(super) not_before: i64,
    pub(super) not_after: i64,
}

impl EnrollmentAuthority {
    pub(crate) fn from_config(config: &Config) -> Result<Self> {
        let roots = crate::startup::certificates(Path::new(&config.tls.ca))?;
        let path = if config.controller.issuer_certificate.is_empty() {
            &config.tls.ca
        } else {
            &config.controller.issuer_certificate
        };
        let issuer_chain = crate::startup::certificates(Path::new(path))?;
        ensure!(
            roots.len() == 1 && issuer_chain.last() == roots.first(),
            "enrollment authority must anchor in tls.ca"
        );
        crate::startup::validate_issuer_chain(&issuer_chain, UnixTime::now())?;

        let mut pem = zeroize::Zeroizing::new(Vec::new());
        File::open(&config.controller.ca_private_key)
            .context("open enrollment signer key")?
            .take((1 << 20) + 1)
            .read_to_end(&mut pem)?;
        ensure!(
            pem.len() <= 1 << 20,
            "enrollment signer key file exceeds limit"
        );
        let mut key = Cursor::new(pem.as_slice());
        let private_key =
            rustls_pemfile::private_key(&mut key)?.context("enrollment signer key is missing")?;
        ensure!(
            matches!(private_key, PrivateKeyDer::Pkcs8(_))
                && rustls_pemfile::read_one(&mut key)?.is_none(),
            "enrollment signer needs exactly one PKCS#8 key"
        );
        let signing_key =
            KeyPair::try_from(&private_key).context("unsupported enrollment signing key")?;
        let (_, leaf) = parse_x509_certificate(&issuer_chain[0])
            .map_err(|_| anyhow::anyhow!("parse enrollment issuer certificate"))?;
        ensure!(
            leaf.public_key().raw == signing_key.subject_public_key_info(),
            "enrollment signer key does not match issuer certificate"
        );
        let issuer = Issuer::from_ca_cert_der(&issuer_chain[0], signing_key)?;
        let leaf_validity = config.controller.leaf_validity.nanos() / 1_000_000_000;
        ensure!(
            leaf_validity > 0,
            "enrollment leaf validity must permit a positive certificate lifetime"
        );
        Ok(Self {
            issuer,
            chain: issuer_chain[..issuer_chain.len() - 1]
                .iter()
                .map(|der| der.to_vec())
                .collect(),
            valid_from: leaf.validity().not_before.timestamp(),
            valid_until: leaf.validity().not_after.timestamp(),
            leaf_validity,
        })
    }

    pub(super) fn issue(
        &self,
        key: &rcgen::SubjectPublicKeyInfo,
        network: Id,
        node: Id,
        lease: Option<i64>,
        now: i64,
    ) -> Result<Material> {
        let not_after = now
            .checked_add(self.leaf_validity)
            .context("certificate lifetime overflow")?
            .min(self.valid_until)
            .min(lease.unwrap_or(i64::MAX));
        ensure!(
            now >= self.valid_from && not_after > now,
            "enrollment signing authority is outside its validity period"
        );
        let not_before = now.checked_sub(60).context("certificate start overflow")?;
        let random = random_bytes::<16>()?;
        let serial = random
            .iter()
            .position(|&byte| byte != 0)
            .map_or_else(|| vec![1], |first| random[first..].to_vec());
        let mut params = CertificateParams::default();
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params
            .distinguished_name
            .push(DnType::CommonName, format!("laneway-node-{node}"));
        params.not_before = OffsetDateTime::from_unix_timestamp(not_before)?;
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after)?;
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.subject_alt_names = vec![SanType::URI(
            format!("spiffe://laneway/network/{network}/node/{node}").try_into()?,
        )];
        let cert = params.signed_by(key, &self.issuer)?;
        let leaf = cert.der().to_vec();
        ensure!(
            (1..=65536).contains(&leaf.len()),
            "issued certificate exceeds wire limit"
        );
        Ok(Material {
            serial,
            leaf,
            not_before,
            not_after,
        })
    }

    pub(super) fn chain(&self, leaf: Vec<u8>) -> Vec<Vec<u8>> {
        std::iter::once(leaf)
            .chain(self.chain.iter().cloned())
            .collect()
    }
}

pub(super) fn public_key(der: &[u8]) -> Result<rcgen::SubjectPublicKeyInfo, EnrollmentError> {
    if !(1..=65536).contains(&der.len()) {
        return Err(EnrollmentError::malformed(
            "PKCS#10 CSR must be 1..65536 bytes",
        ));
    }
    let (rest, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(der)
        .map_err(|_| EnrollmentError::malformed("invalid PKCS#10 CSR"))?;
    if !rest.is_empty() {
        return Err(EnrollmentError::malformed("invalid PKCS#10 CSR"));
    }
    csr.verify_signature()
        .map_err(|_| EnrollmentError::malformed("invalid PKCS#10 CSR signature"))?;
    rcgen::SubjectPublicKeyInfo::from_der(csr.certification_request_info.subject_pki.raw)
        .map_err(|_| EnrollmentError::malformed("unsupported PKCS#10 CSR public key"))
}
