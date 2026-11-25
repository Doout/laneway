use std::{
    fs,
    io::{Cursor, ErrorKind, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt};
use laneway_protocol::read_bounded;
use p256::{SecretKey, pkcs8::EncodePrivateKey};
use rustls::{
    ServerConfig, SignatureScheme,
    crypto::ring::default_provider,
    pki_types::ServerName,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{AccountCache, AcmeConfig, AcmeState, CertCache, is_tls_alpn_challenge};
use tracing::{debug, warn};
use x509_parser::parse_x509_certificate;

use crate::config::PublicHttpsConfig;

pub(crate) const HTTP_ALPN: &[u8] = b"http/1.1";
const ACME_ALPN: &[u8] = b"acme-tls/1";
const ACCOUNT_KEY_FILE: &str = "acme_account+key";
const MAX_CACHE_ENTRY: u64 = 4 << 20;
const LEGACY_ACCOUNT_KEY_FILE: &str = "acme_account.key";

pub(crate) struct PublicTls {
    http: Arc<ServerConfig>,
    challenge: Arc<ServerConfig>,
    name: String,
}

impl PublicTls {
    pub(crate) fn new(config: &PublicHttpsConfig) -> Result<(Self, Acme)> {
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory
            .create(&config.cache_dir)
            .context("create public certificate cache")?;
        let name = config.server_name.to_ascii_lowercase();
        let cache = GoCache(config.cache_dir.clone());
        let rsa_name = format!("{name}+rsa");
        let rsa = cache
            .read(&rsa_name)
            .and_then(|data| {
                data.map(|data| cached_certified_key(&data, &name))
                    .transpose()
            })
            .unwrap_or_else(|error| {
                warn!(%error, "ignored invalid cached RSA public certificate");
                None
            });
        let state = AcmeConfig::new([&name])
            .directory_lets_encrypt(true)
            .cache(cache)
            .state();
        let http = tls_config(
            Arc::new(PublicCerts {
                acme: state.resolver(),
                rsa,
            }),
            HTTP_ALPN,
        )?;
        let challenge = tls_config(state.resolver(), ACME_ALPN)?;
        Ok((
            Self {
                http,
                challenge,
                name,
            },
            Acme(state),
        ))
    }

    pub(crate) fn select(&self, hello: &ClientHello<'_>) -> Result<Arc<ServerConfig>> {
        ensure!(
            hello
                .server_name()
                .is_some_and(|name| name.eq_ignore_ascii_case(&self.name)),
            "public TLS requires the configured SNI"
        );
        if is_tls_alpn_challenge(hello) {
            return Ok(Arc::clone(&self.challenge));
        }
        ensure!(
            hello
                .alpn()
                .is_some_and(|mut alpn| alpn.any(|protocol| protocol == HTTP_ALPN)),
            "public TLS requires HTTP/1.1 ALPN"
        );
        Ok(Arc::clone(&self.http))
    }
}

#[derive(Debug)]
struct PublicCerts {
    acme: Arc<dyn ResolvesServerCert>,
    rsa: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for PublicCerts {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let compatible_rsa = self
            .rsa
            .as_ref()
            .filter(|key| {
                key.key.choose_scheme(hello.signature_schemes()).is_some() && leaf_valid_now(key)
            })
            .cloned();
        let compatible_acme = if hello
            .signature_schemes()
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
        {
            self.acme.resolve(hello).filter(|key| leaf_valid_now(key))
        } else {
            None
        };
        compatible_acme.or(compatible_rsa)
    }
}

fn tls_config(resolver: Arc<dyn ResolvesServerCert>, protocol: &[u8]) -> Result<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![protocol.to_vec()];
    Ok(Arc::new(config))
}

pub(crate) struct Acme(AcmeState<anyhow::Error, anyhow::Error>);

impl Acme {
    pub(crate) fn prime(&mut self) {
        // The cache implementation is synchronous. Install a valid cached
        // certificate before the listener accepts its first ClientHello.
        if let Some(Some(event)) = self.0.next().now_or_never() {
            Self::log(event);
        }
    }

    pub(crate) async fn run(mut self) {
        while let Some(event) = self.0.next().await {
            Self::log(event);
        }
    }

    fn log(event: rustls_acme::Event<anyhow::Error, anyhow::Error>) {
        match event {
            Ok(event) => debug!(?event, "public certificate ACME event"),
            Err(error) => warn!(?error, "public certificate ACME operation failed"),
        }
    }
}

struct GoCache(PathBuf);

impl GoCache {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match fs::File::open(self.0.join(Path::new(name))) {
            Ok(file) => read_bounded(file, MAX_CACHE_ENTRY)
                .map(Some)
                .context("read public ACME cache"),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("read public ACME cache"),
        }
    }

    fn store(&self, name: &str, contents: &[u8]) -> Result<()> {
        ensure!(
            contents.len() as u64 <= MAX_CACHE_ENTRY,
            "public ACME cache entry exceeds its size limit"
        );
        let mut file = tempfile::NamedTempFile::new_in(&self.0)
            .context("create private public ACME cache file")?;
        file.write_all(contents)
            .context("write public ACME cache")?;
        file.as_file()
            .sync_all()
            .context("sync public ACME cache")?;
        file.persist(self.0.join(name))
            .context("replace public ACME cache file")?;
        Ok(())
    }
}

#[async_trait]
impl CertCache for GoCache {
    type EC = anyhow::Error;

    async fn load_cert(&self, domains: &[String], _: &str) -> Result<Option<Vec<u8>>> {
        let Some(data) = self.read(&domains[0])? else {
            return Ok(None);
        };
        // Go's autocert cache stores a SEC1 key first, then leaf and chain.
        // rustls-acme consumes the same PEM sequence with a PKCS#8 key.
        cached_certified_key(&data, &domains[0])?;
        let mut entries = pem::parse_many(data).context("decode cached public certificate PEM")?;
        let key = normalize_p256_key(&entries[0])?;
        entries[0] = pem::Pem::new("PRIVATE KEY", key);
        Ok(Some(pem::encode_many(&entries).into_bytes()))
    }

    async fn store_cert(&self, domains: &[String], _: &str, cert: &[u8]) -> Result<()> {
        self.store(&domains[0], cert)
    }
}

#[async_trait]
impl AccountCache for GoCache {
    type EA = anyhow::Error;

    async fn load_account(&self, _: &[String], _: &str) -> Result<Option<Vec<u8>>> {
        let key = match self.read(ACCOUNT_KEY_FILE)? {
            Some(key) => Some(key),
            None => self.read(LEGACY_ACCOUNT_KEY_FILE)?,
        };
        key.map(|bytes| {
            let key = pem::parse(bytes).context("read cached ACME account PEM")?;
            normalize_p256_key(&key)
        })
        .transpose()
    }

    async fn store_account(&self, _: &[String], _: &str, account: &[u8]) -> Result<()> {
        let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", account));
        self.store(ACCOUNT_KEY_FILE, pem.as_bytes())
    }
}

fn normalize_p256_key(key: &pem::Pem) -> Result<Vec<u8>> {
    match key.tag() {
        "PRIVATE KEY" => Ok(key.contents().to_vec()),
        "EC PRIVATE KEY" => {
            let key = SecretKey::from_sec1_der(key.contents())
                .map_err(|_| anyhow::anyhow!("invalid cached P-256 private key"))?;
            let pkcs8 = key
                .to_pkcs8_der()
                .map_err(|_| anyhow::anyhow!("encode cached P-256 key"))?;
            Ok(pkcs8.as_bytes().to_vec())
        }
        _ => anyhow::bail!("unsupported cached P-256 private key format"),
    }
}

fn cached_certified_key(data: &[u8], name: &str) -> Result<Arc<CertifiedKey>> {
    let key = rustls_pemfile::private_key(&mut Cursor::new(data))?
        .context("cached public certificate is missing its private key")?;
    let certificates =
        rustls_pemfile::certs(&mut Cursor::new(data)).collect::<std::io::Result<Vec<_>>>()?;
    let certified_key = CertifiedKey::from_der(certificates, key, &default_provider())?;
    let leaf = certified_key.end_entity_cert()?;
    let leaf = rustls::server::ParsedCertificate::try_from(leaf)?;
    rustls::client::verify_server_name(&leaf, &ServerName::try_from(name)?)?;
    ensure!(
        leaf_valid_now(&certified_key),
        "cached public certificate is outside its validity period"
    );
    Ok(Arc::new(certified_key))
}

fn leaf_valid_now(cert: &CertifiedKey) -> bool {
    cert.end_entity_cert()
        .ok()
        .and_then(|leaf| parse_x509_certificate(leaf.as_ref()).ok())
        .is_some_and(|(_, leaf)| leaf.validity().is_valid())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

    #[test]
    fn cache_limits_reads_and_writes_and_preserves_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let cache = GoCache(directory.path().to_owned());
        let name = "bootstrap.example.invalid";
        assert!(cache.read(name).unwrap().is_none());
        cache.store(name, b"original").unwrap();
        let oversized = vec![0; MAX_CACHE_ENTRY as usize + 1];
        assert!(cache.store(name, &oversized).is_err());
        assert_eq!(cache.read(name).unwrap().unwrap(), b"original");
        let path = directory.path().join(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(path, oversized).unwrap();
        assert!(cache.read(name).is_err());
    }

    #[tokio::test]
    async fn reuses_go_pem_cache_and_selects_only_the_configured_public_tls() {
        let _ = default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let name = "bootstrap.example.invalid";
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        use p256::pkcs8::DecodePrivateKey;
        let sec1 = SecretKey::from_pkcs8_der(&key_pair.serialize_der())
            .unwrap()
            .to_sec1_der()
            .unwrap();
        let legacy_key = pem::encode(&pem::Pem::new("EC PRIVATE KEY", sec1.to_vec()));
        fs::write(
            directory.path().join(name),
            format!("{legacy_key}{}", certificate.pem()),
        )
        .unwrap();
        fs::write(directory.path().join(LEGACY_ACCOUNT_KEY_FILE), &legacy_key).unwrap();
        let cache = GoCache(directory.path().to_owned());
        let account_key = cache.load_account(&[], "").await.unwrap().unwrap();
        let account_key = rustls::pki_types::PrivatePkcs8KeyDer::from(account_key);
        assert!(
            default_provider()
                .key_provider
                .load_private_key(rustls::pki_types::PrivateKeyDer::Pkcs8(account_key))
                .is_ok()
        );

        let (public, mut acme) = PublicTls::new(&PublicHttpsConfig {
            server_name: name.to_owned(),
            cache_dir: directory.path().to_owned(),
        })
        .unwrap();
        assert!(matches!(
            acme.0.next().now_or_never().flatten(),
            Some(Ok(rustls_acme::EventOk::DeployedCachedCert))
        ));

        let mut roots = RootCertStore::empty();
        roots.add(certificate.der().clone()).unwrap();
        for (sni, protocol, accepted) in [
            (name, HTTP_ALPN, true),
            ("other.example.invalid", HTTP_ALPN, false),
            (name, &b"h2"[..], false),
            (name, ACME_ALPN, false),
        ] {
            let mut config =
                ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth();
            config.alpn_protocols = vec![protocol.to_vec()];
            let (client, server) = tokio::io::duplex(8192);
            let connect = TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(sni).unwrap(), client);
            let accept = async {
                let hello = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), server)
                    .await
                    .unwrap();
                let config = public.select(&hello.client_hello())?;
                Ok::<_, anyhow::Error>(hello.into_stream(config).await?)
            };
            let (client, server) = tokio::join!(connect, accept);
            assert_eq!(client.is_ok(), accepted, "client for {sni}/{protocol:?}");
            assert_eq!(server.is_ok(), accepted, "server for {sni}/{protocol:?}");
        }
    }
}
