//! One rotating relay identity shared by inbound and outbound TLS.
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use laneway_protocol::{
    AuthenticatedIdentity, Role, certificate_serial_from_der, identity_from_certificate_der,
    service_names, v1::CertificateChain,
};
use rustls::{
    RootCertStore, SignatureScheme,
    client::{ResolvesClientCert, verify_server_cert_signed_by_trust_anchor},
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime},
    server::{
        ClientHello, ParsedCertificate, ResolvesServerCert, WebPkiClientVerifier,
        danger::ClientCertVerifier,
    },
    sign::CertifiedKey,
};
use std::{collections::BTreeSet, fs, path::PathBuf, sync::Arc, time::Duration};
use zeroize::Zeroizing;

use crate::{config::TlsConfig, public_tls::cache, tls};

pub(crate) const RENEW_PATH: &str = "/v1/relay/renew";

#[derive(Clone, Debug)]
pub(crate) struct Health {
    pub(crate) serial: Vec<u8>,
    pub(crate) not_after: u64,
    pub(crate) renew_after: u64,
}

#[derive(Debug)]
struct Managed {
    path: PathBuf,
    names: BTreeSet<service_names::Name>,
    roots: Arc<RootCertStore>,
    verifier: Arc<dyn ClientCertVerifier>,
}

#[derive(Debug)]
pub(crate) struct Workload {
    identity: AuthenticatedIdentity,
    key: ArcSwap<CertifiedKey>,
    managed: Option<Managed>,
}

impl Workload {
    pub(crate) fn load(config: &TlsConfig) -> Result<Arc<Self>> {
        let signer = tls::load_private_key(&config.private_key_file)?;
        let chain = tls::load_certificates(&config.certificate_file)?;
        let seed = certified(chain, signer)?;
        let leaf = seed.end_entity_cert()?;
        let identity = identity_from_certificate_der(leaf.as_ref())?;
        ensure!(
            identity.role == Role::Relay,
            "workload leaf must have the relay role"
        );
        let (key, managed) = if let Some(dir) = &config.renewal_dir {
            cache::directory(dir, true)?;
            let path = fs::canonicalize(dir)?.join("relay-service.pem");
            ensure!(
                fs::canonicalize(&config.certificate_file)? != path
                    && fs::canonicalize(&config.private_key_file)? != path,
                "relay renewal bundle must not replace a configured seed file"
            );
            let now = UnixTime::now().as_secs();
            let seed_health = health(leaf)?;
            let roots = Arc::new(tls::roots(&config.ca_file)?);
            let managed = Managed {
                path,
                names: service_names::from_der(leaf.as_ref())?,
                verifier: WebPkiClientVerifier::builder_with_provider(
                    Arc::clone(&roots),
                    Arc::new(rustls::crypto::ring::default_provider()),
                )
                .build()?,
                roots,
            };
            managed
                .verify(
                    &seed,
                    identity,
                    now.min(seed_health.not_after.saturating_sub(1)),
                )
                .context("relay renewal seed is not trusted")?;
            let replacement = match managed.read(identity, now) {
                Ok(value) => value,
                Err(_) => {
                    tracing::warn!("ignoring an unusable cached relay credential");
                    None
                }
            };
            let key = replacement
                .filter(|(_, newer)| newer.not_after > seed_health.not_after)
                .map(|(key, _)| key)
                .unwrap_or(seed);
            ensure!(
                health(key.end_entity_cert()?)?.not_after > now,
                "relay credential expired; restore an operator-issued credential before resuming renewal"
            );
            (key, Some(managed))
        } else {
            (seed, None)
        };
        Ok(Arc::new(Self {
            identity,
            key: ArcSwap::from_pointee(key),
            managed,
        }))
    }

    pub(crate) fn identity(&self) -> AuthenticatedIdentity {
        self.identity
    }

    pub(crate) fn health(&self) -> Result<Health> {
        health(self.key.load().end_entity_cert()?)
    }

    pub(crate) fn managed(&self) -> bool {
        self.managed.is_some()
    }

    pub(crate) fn due(&self) -> Result<bool> {
        Ok(self.managed() && UnixTime::now().as_secs() >= self.health()?.renew_after)
    }

    pub(crate) fn install(&self, chain: CertificateChain, signer: &rcgen::KeyPair) -> Result<()> {
        let managed = self
            .managed
            .as_ref()
            .context("relay certificate renewal is disabled")?;
        let current = self.health()?;
        let der = chain
            .certificates_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(signer.serialize_der());
        let candidate = certified(der, private.into())?;
        let health = managed.verify(&candidate, self.identity, UnixTime::now().as_secs())?;
        ensure!(
            health.not_after == chain.not_after_unix_seconds
                && health.not_after > current.not_after
                && health.serial != current.serial,
            "renewal response did not extend the current relay certificate"
        );
        let mut bundle = Zeroizing::new(signer.serialize_pem());
        for cert in &candidate.cert {
            bundle.push_str(&pem::encode(&pem::Pem::new("CERTIFICATE", cert.as_ref())));
        }
        cache::write(&managed.path, bundle.as_bytes())
            .context("persist relay credential atomically")?;
        self.key.store(Arc::new(candidate));
        Ok(())
    }
}

impl ResolvesServerCert for Workload {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.key.load_full())
    }
}

impl ResolvesClientCert for Workload {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.key.load_full())
    }
    fn has_certs(&self) -> bool {
        true
    }
}

impl Managed {
    fn read(
        &self,
        identity: AuthenticatedIdentity,
        now: u64,
    ) -> Result<Option<(CertifiedKey, Health)>> {
        let Some(bytes) = cache::read(&self.path)? else {
            return Ok(None);
        };
        let mut key_input = bytes.as_slice();
        let mut cert_input = bytes.as_slice();
        let key =
            rustls_pemfile::private_key(&mut key_input)?.context("no cached relay private key")?;
        let chain = rustls_pemfile::certs(&mut cert_input).collect::<std::io::Result<Vec<_>>>()?;
        let cached = certified(chain, key)?;
        let health = self.verify(&cached, identity, now)?;
        Ok(Some((cached, health)))
    }

    fn verify(
        &self,
        candidate: &CertifiedKey,
        identity: AuthenticatedIdentity,
        now: u64,
    ) -> Result<Health> {
        candidate.keys_match()?;
        let (leaf, chain) = candidate
            .cert
            .split_first()
            .context("no relay certificate")?;
        ensure!(
            identity_from_certificate_der(leaf.as_ref())? == identity
                && service_names::from_der(leaf.as_ref())? == self.names,
            "relay certificate identity or names changed"
        );
        let now = UnixTime::since_unix_epoch(Duration::from_secs(now));
        self.verifier.verify_client_cert(leaf, chain, now)?;
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(leaf)?,
            &self.roots,
            chain,
            now,
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
        )?;
        let (_, leaf_info) = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid workload certificate"))?;
        ensure!(
            leaf_info
                .extended_key_usage()?
                .is_some_and(|usage| usage.value.server_auth && usage.value.client_auth),
            "relay workload certificate requires server and client authentication"
        );
        health(leaf)
    }
}

fn certified(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<CertifiedKey> {
    ensure!(
        (1..=8).contains(&chain.len()),
        "invalid relay TLS chain length"
    );
    Ok(CertifiedKey::from_der(
        chain,
        key,
        &rustls::crypto::ring::default_provider(),
    )?)
}

fn health(leaf: &CertificateDer<'_>) -> Result<Health> {
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid relay TLS leaf"))?;
    let before = u64::try_from(parsed.validity().not_before.timestamp())?;
    let after = u64::try_from(parsed.validity().not_after.timestamp())?;
    ensure!(after > before && before > 0, "invalid relay TLS validity");
    Ok(Health {
        serial: certificate_serial_from_der(leaf.as_ref())?,
        not_after: after,
        renew_after: before + (after - before) * 2 / 3,
    })
}
