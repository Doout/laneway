pub(crate) mod cache;

use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{ClientHello, ParsedCertificate, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{AcmeConfig, AcmeState, EventOk, ResolvesServerCertAcme};
use std::{
    io,
    sync::{Arc, Mutex},
};

use crate::{config::PublicHttpsConfig, tls};

const HTTP_ALPN: &[u8] = b"http/1.1";
const ACME_ALPN: &[u8] = b"acme-tls/1";
const ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";

pub(crate) struct PublicTls {
    name: String,
    http: Arc<ServerConfig>,
    challenge: Option<Arc<ServerConfig>>,
}

pub(crate) struct Selected {
    pub(crate) tls: Arc<ServerConfig>,
    pub(crate) challenge: bool,
}

pub(crate) struct Renewal(AcmeState<io::Error>);

impl Renewal {
    pub(crate) async fn run(mut self) {
        while let Some(event) = self.0.next().await {
            match event {
                Ok(EventOk::DeployedNewCert) => tracing::info!("renewed public HTTPS certificate"),
                Ok(EventOk::DeployedCachedCert) => {
                    tracing::info!("loaded public HTTPS certificate from ACME cache")
                }
                Ok(EventOk::CertCacheStore | EventOk::AccountCacheStore) => {}
                // ACME logs may include remote order data. The retry continues
                // in the background without printing credentials or challenges.
                Err(error) => tracing::warn!(
                    kind = event_kind(&error),
                    "public HTTPS ACME operation failed; retry scheduled"
                ),
            }
        }
    }
}

fn event_kind(error: &rustls_acme::EventError<io::Error, io::Error>) -> &'static str {
    use rustls_acme::EventError::*;
    match error {
        CertCacheLoad(_) => "certificate cache read",
        AccountCacheLoad(_) => "account cache read",
        CertCacheStore(_) => "certificate cache write",
        AccountCacheStore(_) => "account cache write",
        CachedCertParse(_) | NewCertParse(_) => "certificate validation",
        Order(_) => "ACME order",
    }
}

impl PublicTls {
    pub(crate) fn new(config: &PublicHttpsConfig) -> Result<(Self, Option<Renewal>)> {
        let name = &config.server_name;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let explicit = config
            .certificate
            .as_ref()
            .zip(config.private_key.as_ref())
            .map(|(cert, key)| -> Result<_> {
                let chain = tls::load_certificates(cert)?;
                let private = tls::load_private_key(key)?;
                usable_key(chain, private, name, &provider, true)
            })
            .transpose()
            .context("load configured public HTTPS credentials")?;

        let (acme, reload, challenge) = if let Some(dir) = &config.cache_dir {
            let cache = cache::Cache::new(dir, name, Arc::clone(&provider))?;
            let seed = if explicit.is_none() && config.acme_directory.is_none() {
                cache.go_seed()
            } else {
                None
            };
            let domains = [name.as_str()];
            let mut builder = if let Some(path) = &config.acme_ca {
                let mut roots = RootCertStore::empty();
                for der in tls::load_certificates(path)? {
                    roots.add(der).context("load ACME directory trust root")?;
                }
                let verify = ClientConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                AcmeConfig::new_with_client_config(domains, Arc::new(verify))
            } else {
                AcmeConfig::new_with_provider(domains, Arc::clone(&provider))
            };
            builder = if let Some(url) = &config.acme_directory {
                builder.directory(url)
            } else {
                builder.directory_lets_encrypt(true)
            };
            let state = builder.cache(cache).state();
            let resolver = state.resolver();
            let validator = make_config(Arc::clone(&provider), resolver.clone(), ACME_ALPN)?;
            (
                Some((resolver, seed)),
                Some(Renewal(state)),
                Some(validator),
            )
        } else {
            (None, None, None)
        };

        let (managed, seed) = acme.map_or((None, None), |(managed, seed)| (Some(managed), seed));
        let http = make_config(
            provider,
            Arc::new(HttpResolver {
                name: name.clone(),
                managed,
                seed: explicit.or(seed),
                last: Mutex::default(),
            }),
            HTTP_ALPN,
        )?;
        Ok((
            Self {
                name: name.clone(),
                http,
                challenge,
            },
            reload,
        ))
    }

    pub(crate) fn select(&self, hello: ClientHello<'_>) -> Result<Selected> {
        ensure!(
            hello.server_name() == Some(self.name.as_str()),
            "unexpected public TLS server name"
        );
        if rustls_acme::is_tls_alpn_challenge(&hello) {
            return Ok(Selected {
                tls: Arc::clone(
                    self.challenge
                        .as_ref()
                        .context("ACME TLS validation is disabled")?,
                ),
                challenge: true,
            });
        }
        ensure!(
            hello
                .alpn()
                .is_none_or(|mut values| values.any(|p| p == HTTP_ALPN)),
            "unsupported public TLS protocol"
        );
        Ok(Selected {
            tls: Arc::clone(&self.http),
            challenge: false,
        })
    }
}

fn make_config(
    provider: Arc<CryptoProvider>,
    resolver: Arc<dyn ResolvesServerCert>,
    alpn: &[u8],
) -> Result<Arc<ServerConfig>> {
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server.alpn_protocols = vec![alpn.to_vec()];
    server.send_tls13_tickets = 0;
    Ok(Arc::new(server))
}

#[derive(Debug)]
struct HttpResolver {
    name: String,
    managed: Option<Arc<ResolvesServerCertAcme>>,
    seed: Option<CheckedKey>,
    last: Mutex<ManagedKeys>,
}

#[derive(Debug, Default)]
struct ManagedKeys {
    seen: Option<Arc<CertifiedKey>>,
    candidate: Option<CheckedKey>,
    active: Option<CheckedKey>,
}

impl ResolvesServerCert for HttpResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(managed) = self.managed.as_ref().and_then(|acme| acme.resolve(hello)) {
            let mut cached = self.last.lock().ok()?;
            if cached
                .seen
                .as_ref()
                .is_none_or(|known| !Arc::ptr_eq(known, &managed))
            {
                let record = CheckedKey::new(Arc::clone(&managed), &self.name).ok();
                if record.is_none() {
                    tracing::warn!("ignoring invalid public HTTPS certificate");
                }
                cached.seen = Some(managed);
                cached.candidate = record;
            }
            if cached.candidate.as_ref().is_some_and(CheckedKey::valid_now) {
                cached.active = cached.candidate.take();
            }
            if let Some(key) = cached.active.as_ref()
                && key.valid_now()
            {
                return Some(Arc::clone(&key.key));
            }
        }
        self.seed
            .as_ref()
            .filter(|key| key.valid_now())
            .map(|key| Arc::clone(&key.key))
    }
}

#[derive(Debug)]
struct CheckedKey {
    key: Arc<CertifiedKey>,
    not_before: i64,
    not_after: i64,
}

impl CheckedKey {
    fn new(key: Arc<CertifiedKey>, name: &str) -> Result<Self> {
        let der = key
            .end_entity_cert()
            .context("public certificate chain is empty")?;
        let parsed = ParsedCertificate::try_from(der)?;
        rustls::client::verify_server_name(&parsed, &ServerName::try_from(name)?)?;
        let (_, leaf) = x509_parser::parse_x509_certificate(der.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid public certificate"))?;
        ensure!(
            laneway_protocol::identity_from_certificate_der(der.as_ref()).is_err()
                && leaf
                    .extensions()
                    .iter()
                    .all(|item| item.oid.to_id_string() != ACME_IDENTIFIER),
            "public HTTPS requires a non-workload, non-challenge certificate"
        );
        key.keys_match()
            .context("public HTTPS key does not match the certificate")?;
        let not_before = leaf.validity().not_before.timestamp();
        let not_after = leaf.validity().not_after.timestamp();
        ensure!(
            not_after > not_before,
            "public certificate has an invalid validity window"
        );
        Ok(Self {
            key,
            not_before,
            not_after,
        })
    }

    fn valid_now(&self) -> bool {
        i64::try_from(UnixTime::now().as_secs())
            .is_ok_and(|now| (self.not_before..self.not_after).contains(&now))
    }
}

fn usable_key(
    chain: Vec<CertificateDer<'static>>,
    private: PrivateKeyDer<'static>,
    name: &str,
    provider: &CryptoProvider,
    require_current: bool,
) -> Result<CheckedKey> {
    let key = CheckedKey::new(
        Arc::new(CertifiedKey::from_der(chain, private, provider)?),
        name,
    )?;
    ensure!(
        !require_current || key.valid_now(),
        "public certificate is not currently valid"
    );
    Ok(key)
}
