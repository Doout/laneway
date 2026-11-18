//! Local controller certificate renewal. The configured leaf pins the service
//! identity and names; replacements use the existing online issuer and CA.
use super::pem;
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_controller::node_pki::NodeIssuer;
use laneway_protocol::{AuthenticatedIdentity, Role, identity_from_certificate_der};
use rcgen::SanType;
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use x509_parser::{extensions::GeneralName, prelude::X509Certificate};

const LEASE: &str = "controller-service.pem";
const RETRY_SECONDS: u64 = 30;

#[derive(Debug)]
pub(super) struct Identity(ArcSwap<CertifiedKey>);

impl Identity {
    pub(super) fn load(cert: &Path, key: &Path) -> Result<Self> {
        let chain =
            rustls_pemfile::certs(&mut pem(cert, false)?).collect::<std::io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut pem(key, true)?)?
            .context("missing TLS private key")?;
        Ok(Self(ArcSwap::from_pointee(certified(chain, key)?)))
    }

    pub(super) fn active(&self) -> Arc<CertifiedKey> {
        self.0.load_full()
    }
}

impl ResolvesServerCert for Identity {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.active())
    }
}

fn certified(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<CertifiedKey> {
    ensure!(
        (1..=8).contains(&chain.len()),
        "invalid TLS certificate chain length"
    );
    Ok(CertifiedKey::from_der(
        chain,
        key,
        &rustls::crypto::ring::default_provider(),
    )?)
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Name {
    Dns(String),
    Ip(IpAddr),
}

impl Name {
    fn rustls(&self) -> Result<ServerName<'static>> {
        Ok(match self {
            Self::Ip(ip) => ServerName::IpAddress((*ip).into()),
            Self::Dns(dns) => ServerName::try_from(dns.clone())?,
        })
    }

    fn san(&self) -> Result<SanType> {
        Ok(match self {
            Self::Ip(ip) => SanType::IpAddress(*ip),
            Self::Dns(dns) => SanType::DnsName(dns.as_str().try_into()?),
        })
    }
}

#[derive(PartialEq, Eq)]
struct Template {
    id: AuthenticatedIdentity,
    names: BTreeSet<Name>,
}

struct Binding {
    template: Template,
    expires: i64,
}

impl Binding {
    fn read(leaf: &CertificateDer<'_>) -> Result<Self> {
        let id = identity_from_certificate_der(leaf.as_ref())?;
        ensure!(
            id.role == Role::Controller,
            "renewal requires a controller service identity"
        );
        let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid TLS certificate"))?;
        let names = bound_names(&cert)?;
        Ok(Self {
            template: Template { id, names },
            expires: cert.validity().not_after.timestamp(),
        })
    }
}

fn bound_names(cert: &X509Certificate<'_>) -> Result<BTreeSet<Name>> {
    let ext = cert
        .subject_alternative_name()?
        .context("controller certificate has no SAN")?;
    let mut names = BTreeSet::new();
    let mut uris = 0;
    for name in &ext.value.general_names {
        let bound = match name {
            GeneralName::URI(_) => {
                uris += 1;
                continue;
            }
            GeneralName::DNSName(name) => Name::Dns(name.to_ascii_lowercase()),
            GeneralName::IPAddress(raw) if raw.len() == 4 => {
                Name::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(*raw)?).into())
            }
            GeneralName::IPAddress(raw) if raw.len() == 16 => {
                Name::Ip(Ipv6Addr::from(<[u8; 16]>::try_from(*raw)?).into())
            }
            _ => anyhow::bail!("unsupported controller SAN entry"),
        };
        ensure!(
            names.len() < 32 && names.insert(bound),
            "non-unique or oversized controller SAN"
        );
    }
    ensure!(
        uris == 1 && !names.is_empty(),
        "missing controller service names"
    );
    Ok(names)
}

pub(super) struct Renewal {
    active: Arc<Identity>,
    template: Template,
    names: Vec<SanType>,
    verifier: Arc<WebPkiServerVerifier>,
    issuer: Arc<NodeIssuer>,
    path: PathBuf,
    expires: i64,
    before: i64,
}

impl Renewal {
    pub(super) fn prepare(
        directory: &Path,
        seed_paths: [&Path; 2],
        active: Arc<Identity>,
        roots: RootCertStore,
        issuer: Arc<NodeIssuer>,
        before: i64,
    ) -> Result<Self> {
        ensure!(
            directory.is_absolute(),
            "controller renewal state directory must be absolute"
        );
        let mut directory_builder = fs::DirBuilder::new();
        directory_builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory_builder.mode(0o700);
        }
        directory_builder
            .create(directory)
            .context("create controller renewal directory")?;
        let meta = fs::symlink_metadata(directory)?;
        ensure!(
            meta.is_dir(),
            "controller renewal state must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "controller renewal state directory must be owner-only"
            );
        }
        let path = fs::canonicalize(directory)?.join(LEASE);
        for source in seed_paths {
            ensure!(
                fs::canonicalize(source)? != path,
                "controller renewal bundle must not replace a configured seed file"
            );
        }
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        let seed = active.active();
        let binding = Binding::read(seed.end_entity_cert()?)?;
        let time = clock()?;
        // An expired seed can still select the service identity, but must have
        // been valid under the current trust roots before its expiry.
        verify(
            &verifier,
            &seed,
            &binding.template,
            time.min(binding.expires - 1),
        )
        .context("configured controller leaf is not trusted for renewal")?;
        let names = binding
            .template
            .names
            .iter()
            .map(Name::san)
            .collect::<Result<Vec<_>>>()?;
        let mut renewal = Self {
            active,
            template: binding.template,
            names,
            verifier,
            issuer,
            path,
            expires: binding.expires,
            before,
        };
        match renewal.reload(time) {
            Ok(Some((candidate, expiry))) => {
                renewal.active.0.store(Arc::new(candidate));
                renewal.expires = expiry;
            }
            Ok(None) => {}
            Err(_) => eprintln!("Ignoring an unusable cached controller TLS replacement"),
        }
        if renewal.expires <= time {
            renewal
                .rotate(time)
                .context("recover expired controller TLS certificate")?;
        }
        Ok(renewal)
    }

    fn reload(&self, time: i64) -> Result<Option<(CertifiedKey, i64)>> {
        let meta = match fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            meta.is_file(),
            "cached controller TLS replacement must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "cached controller TLS replacement is not owner-only"
            );
        }
        let contents = pem(&self.path, true)?.into_inner();
        let mut chain = contents.as_slice();
        let mut key = contents.as_slice();
        let chain = rustls_pemfile::certs(&mut chain).collect::<std::io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut key)?.context("missing cached TLS key")?;
        let candidate = certified(chain, key)?;
        let expiry = verify(&self.verifier, &candidate, &self.template, time)?;
        Ok((expiry > self.expires).then_some((candidate, expiry)))
    }

    fn rotate(&mut self, time: i64) -> Result<()> {
        let (chain, key) =
            self.issuer
                .issue_controller(self.template.id, &self.names, time, self.before + 300)?;
        let candidate = certified(chain, key.clone_key())?;
        let expiry = verify(&self.verifier, &candidate, &self.template, time)?;
        ensure!(
            expiry > self.expires,
            "renewed controller TLS certificate must extend validity"
        );
        persist(&self.path, &candidate.cert, &key)?;
        self.active.0.store(Arc::new(candidate));
        self.expires = expiry;
        eprintln!("Renewed internal controller TLS certificate; expires at Unix second {expiry}");
        Ok(())
    }

    pub(super) async fn run(mut self) {
        loop {
            let wait = match clock() {
                Ok(time) => (self.expires - self.before - time).max(0) as u64,
                Err(_) => RETRY_SECONDS,
            };
            if wait != 0 {
                tokio::time::sleep(Duration::from_secs(wait.min(60))).await;
                continue;
            }
            let outcome = tokio::task::spawn_blocking(move || {
                let result = clock().and_then(|time| self.rotate(time));
                (self, result)
            })
            .await;
            let Ok((next, result)) = outcome else {
                eprintln!("Internal controller TLS renewal task failed");
                return;
            };
            self = next;
            if let Err(err) = result {
                eprintln!("Could not renew internal controller TLS certificate: {err}");
                tokio::time::sleep(Duration::from_secs(RETRY_SECONDS)).await;
            }
        }
    }
}

fn clock() -> Result<i64> {
    Ok(UnixTime::now().as_secs().try_into()?)
}

fn verify(
    verifier: &WebPkiServerVerifier,
    key: &CertifiedKey,
    template: &Template,
    time: i64,
) -> Result<i64> {
    let (leaf, chain) = key
        .cert
        .split_first()
        .context("empty controller certificate chain")?;
    key.keys_match()?;
    let binding = Binding::read(leaf)?;
    ensure!(
        binding.template == *template,
        "controller certificate identity or names changed"
    );
    let now = UnixTime::since_unix_epoch(Duration::from_secs(time.try_into()?));
    for name in &template.names {
        verifier.verify_server_cert(leaf, chain, &name.rustls()?, &[], now)?;
    }
    Ok(binding.expires)
}

fn persist(path: &Path, chain: &[CertificateDer<'_>], key: &PrivateKeyDer<'_>) -> Result<()> {
    let dir = path.parent().context("missing renewal directory")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    let encoded = zeroize::Zeroizing::new(STANDARD.encode(key.secret_der()));
    write_pem(&mut tmp, "PRIVATE KEY", encoded.as_bytes())?;
    for cert in chain {
        write_pem(
            &mut tmp,
            "CERTIFICATE",
            STANDARD.encode(cert.as_ref()).as_bytes(),
        )?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn write_pem(out: &mut impl Write, kind: &str, encoded: &[u8]) -> std::io::Result<()> {
    writeln!(out, "-----BEGIN {kind}-----")?;
    for line in encoded.chunks(64) {
        out.write_all(line)?;
        out.write_all(b"\n")?;
    }
    writeln!(out, "-----END {kind}-----")
}
