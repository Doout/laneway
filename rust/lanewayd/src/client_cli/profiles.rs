use std::{
    env, fs,
    io::{self, ErrorKind, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use laneway_private as private;
use laneway_protocol::{AuthenticatedIdentity, Id, Role, identity_from_certificate_der};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MANIFEST: &str = "profile.json";
const MAX_MANIFEST: usize = 64 << 10;
const MAX_CREDENTIAL: usize = 256 << 10;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    version: u32,
    pub(super) authority: String,
    pub(super) network_id: String,
    pub(super) controller_service_id: String,
    pub(super) node_id: String,
    name: String,
    pub(super) generation: String,
    created_at: String,
}

pub(super) struct Files {
    pub(super) ca: PathBuf,
    pub(super) certificate: PathBuf,
    pub(super) private_key: PathBuf,
    wireguard_key: PathBuf,
}

pub(super) struct Saved {
    pub(super) profile: Profile,
    pub(super) files: Files,
}

pub(super) struct Credentials<'a> {
    pub(super) ca: &'a [u8],
    pub(super) certificate: &'a [u8],
    pub(super) private_key: &'a [u8],
    pub(super) wireguard_key: &'a [u8],
}

pub(super) struct Store {
    root: PathBuf,
}

impl Store {
    pub(super) fn from_environment() -> Self {
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let root = env::var_os("LANEWAY_PROFILE_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let config = if cfg!(target_os = "macos") {
                    home.map(|home| home.join("Library/Application Support"))
                } else {
                    match env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
                        Some(path) => Some(PathBuf::from(path)).filter(|path| path.is_absolute()),
                        None => home.map(|home| home.join(".config")),
                    }
                };
                config
                    .map(|path| path.join("laneway/profiles"))
                    .unwrap_or_else(|| PathBuf::from(".laneway"))
            });
        Self { root }
    }

    pub(super) fn path(&self, authority: &str) -> PathBuf {
        self.root.join(profile_key(authority))
    }

    pub(super) fn lock(&self, authority: &str) -> Result<fs::File> {
        ensure!(
            self.root.is_absolute(),
            "LANEWAY_PROFILE_DIR must be an absolute path"
        );
        let parent = self
            .root
            .parent()
            .context("invalid saved login directory")?;
        fs::create_dir_all(parent)?;
        private::ensure_directory(&self.root).context("open private saved login directory")?;
        // Keep the lock outside the authority directory so logout and a new
        // enrollment serialize even when the login directory is absent.
        private::try_lock(&self.root.join(format!(".{}.lock", profile_key(authority))))
            .context("saved login is in use")
    }

    pub(super) fn exists(&self, authority: &str) -> Result<bool> {
        Ok(self.load(authority)?.is_some())
    }

    pub(super) fn load(&self, authority: &str) -> Result<Option<Saved>> {
        let directory = self.path(authority);
        match private::check_directory(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("open saved login directory"),
        }
        let path = directory.join(MANIFEST);
        let bytes = match read_bounded(&path, MAX_MANIFEST) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let profile: Profile = serde_json::from_slice(&bytes).context("parse saved login")?;
        ensure!(
            profile.authority.eq_ignore_ascii_case(authority)
                && self.path(&profile.authority) == directory,
            "saved login belongs to a different authority"
        );
        profile.validate()?;
        ensure!(
            profile.generation.starts_with("credentials-")
                && !profile.generation.contains(['/', '\\']),
            "invalid saved login generation"
        );
        let generation = directory.join(&profile.generation);
        private::check_directory(&generation)?;
        let files = Files::new(&generation);
        for path in [
            &files.ca,
            &files.certificate,
            &files.private_key,
            &files.wireguard_key,
        ] {
            // Hold only one bounded buffer at a time and clear credential bytes.
            let _ = zeroize::Zeroizing::new(read_bounded(path, MAX_CREDENTIAL)?);
        }
        Ok(Some(Saved { profile, files }))
    }

    pub(super) fn default_authority(&self) -> Result<Option<String>> {
        match private::check_directory(&self.root) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("open saved login root"),
        }
        let mut authorities = Vec::new();
        for entry in self.root.read_dir()? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            private::check_directory(&entry.path())?;
            let bytes = read_bounded(&entry.path().join(MANIFEST), MAX_MANIFEST)?;
            let profile: Profile = serde_json::from_slice(&bytes).context("parse saved login")?;
            ensure!(
                self.path(&profile.authority) == entry.path(),
                "saved login is stored under the wrong authority"
            );
            self.load(&profile.authority)?
                .context("saved login disappeared")?;
            authorities.push(profile.authority);
        }
        authorities.sort_unstable();
        match authorities.len() {
            0 => Ok(None),
            1 => Ok(authorities.pop()),
            _ => anyhow::bail!(
                "multiple saved logins ({}); specify DOMAIN",
                authorities.join(", ")
            ),
        }
    }

    pub(super) fn save(&self, mut profile: Profile, credentials: Credentials<'_>) -> Result<()> {
        let identity = profile.validate()?;
        ensure!(
            credentials.wireguard_key.len() == 32,
            "invalid saved WireGuard key"
        );
        let chain = rustls_pemfile::certs(&mut io::Cursor::new(credentials.certificate))
            .collect::<io::Result<Vec<_>>>()?;
        ensure!(
            identity_from_certificate_der(
                chain.first().context("missing saved login certificate")?
            )? == identity,
            "saved login certificate does not match its manifest"
        );
        let directory = self.path(&profile.authority);
        private::ensure_directory(&directory).context("prepare saved login directory")?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("credentials-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let staged = builder.tempdir_in(&directory)?;
        private::check_directory(staged.path())?;
        let files = Files::new(staged.path());
        for (path, bytes) in [
            (&files.ca, credentials.ca),
            (&files.certificate, credentials.certificate),
            (&files.private_key, credentials.private_key),
            (&files.wireguard_key, credentials.wireguard_key),
        ] {
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_CREDENTIAL,
                "invalid saved credential size"
            );
            private::create(path, bytes)?;
        }
        profile.generation = staged
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .context("invalid credential generation")?
            .to_owned();
        let mut manifest = serde_json::to_vec_pretty(&profile)?;
        manifest.push(b'\n');
        // Once publication begins, retain the generation even if syncing the
        // manifest reports an error after the rename.
        let _ = staged.keep();
        private::write(&directory.join(MANIFEST), &manifest).context("publish saved login")
    }

    pub(super) async fn renew(
        &self,
        authority: &str,
        generation: &str,
        metadata: &super::bootstrap::Metadata,
    ) -> Result<Saved> {
        use crate::rootless_cli::enroll::wireguard_public_key;
        use lanewayd_rs::{TlsConfig, renew_saved_login};

        let _lock = self.lock(authority)?;
        let saved = self.load(authority)?.context("saved login is missing")?;
        if saved.profile.generation != generation {
            return Ok(saved);
        }
        let ca = saved.confirm_binding(metadata)?;
        let mut wireguard = zeroize::Zeroizing::new([0; 32]);
        getrandom::fill(wireguard.as_mut()).context("generate replacement WireGuard key")?;
        let mut settings = metadata.controller.config();
        settings.timeout = std::time::Duration::from_secs(30);
        let tls = TlsConfig {
            ca: saved.files.ca,
            certificate: saved.files.certificate,
            private_key: saved.files.private_key,
        };
        let node = saved.profile.validate()?;
        let (certificate, key) = renew_saved_login(
            &settings,
            &tls,
            node.network_id,
            node.subject_id,
            wireguard_public_key(*wireguard),
        )
        .await
        .context("refresh saved login")?;
        self.save(
            saved.profile,
            Credentials {
                ca: &ca,
                certificate: &certificate,
                private_key: key.as_bytes(),
                wireguard_key: wireguard.as_ref(),
            },
        )?;
        self.load(authority)?
            .context("renewed login was not published")
    }

    pub(super) fn logout(&self, authority: &str) -> Result<()> {
        let _lock = self.lock(authority)?;
        let directory = self.path(authority);
        private::check_directory(&directory).context("open saved login")?;
        fs::remove_dir_all(directory).context("remove saved login")?;
        println!(
            "logged out of {authority}; the controller identity remains revocable by its NodeID"
        );
        Ok(())
    }
}

impl Saved {
    pub(super) fn renewal_at(&self, now: u64) -> Result<u64> {
        let bytes = read_bounded(&self.files.certificate, MAX_CREDENTIAL)?;
        let leaf = rustls_pemfile::certs(&mut io::Cursor::new(&bytes))
            .next()
            .transpose()?
            .context("saved login has no certificate")?;
        let (_, cert) = x509_parser::parse_x509_certificate(&leaf)
            .map_err(|_| anyhow::anyhow!("invalid saved login certificate"))?;
        let start: u64 = cert.validity().not_before.timestamp().try_into()?;
        let end: u64 = cert.validity().not_after.timestamp().try_into()?;
        ensure!(end > start, "invalid saved login certificate lifetime");
        ensure!(
            now < end,
            "saved login certificate expired; log in again with a new token"
        );
        Ok(start + (end - start) * 2 / 3)
    }

    pub(super) fn confirm_binding(&self, metadata: &super::bootstrap::Metadata) -> Result<Vec<u8>> {
        ensure!(
            metadata.network_id == self.profile.network_id
                && metadata.controller.service_id == self.profile.controller_service_id,
            "controller identity changed; refusing to renew the saved login"
        );
        let ca = read_bounded(&self.files.ca, MAX_CREDENTIAL)?;
        ensure!(
            std::str::from_utf8(&ca)?.trim() == metadata.trust.ca_pem.trim(),
            "controller CA changed; refusing to renew the saved login"
        );
        Ok(ca)
    }
}

impl Profile {
    pub(super) fn new(authority: &str, network: Id, service: Id, node: Id) -> Result<Self> {
        Ok(Self {
            version: 1,
            authority: authority.to_owned(),
            network_id: network.to_string(),
            controller_service_id: service.to_string(),
            node_id: node.to_string(),
            name: "remembered-user".into(),
            generation: String::new(),
            created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        })
    }

    fn validate(&self) -> Result<AuthenticatedIdentity> {
        ensure!(
            self.version == 1 && !self.authority.is_empty(),
            "invalid saved login manifest"
        );
        self.controller_service_id
            .parse::<Id>()
            .context("invalid saved controller identity")?;
        OffsetDateTime::parse(&self.created_at, &Rfc3339)
            .context("invalid saved login timestamp")?;
        Ok(AuthenticatedIdentity {
            network_id: self.network_id.parse()?,
            role: Role::Node,
            subject_id: self.node_id.parse()?,
        })
    }
}

impl Files {
    fn new(generation: &Path) -> Self {
        Self {
            ca: generation.join("ca.crt"),
            certificate: generation.join("node.crt"),
            private_key: generation.join("node.key"),
            wireguard_key: generation.join("wireguard.key"),
        }
    }
}

fn profile_key(authority: &str) -> String {
    let digest = Sha256::digest(authority.trim().to_lowercase().as_bytes());
    hex::encode(&digest[..16])
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    private::open_private_file(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "invalid saved login file size: {}",
        path.display()
    );
    Ok(bytes)
}

pub(super) fn enrollment_code(path: Option<&Path>) -> Result<zeroize::Zeroizing<String>> {
    let value = if let Some(path) = path {
        String::from_utf8(read_bounded(path, 4096)?)?
    } else {
        use std::io::IsTerminal;
        ensure!(
            io::stdin().is_terminal(),
            "use --token-file in a non-interactive session"
        );
        rpassword::prompt_password("Enrollment code: ")?
    };
    let value = zeroize::Zeroizing::new(value);
    let code = value.trim();
    ensure!(
        !code.is_empty()
            && code.len() <= 4096
            && !code.bytes().any(|byte| byte.is_ascii_whitespace()),
        "invalid enrollment code"
    );
    Ok(zeroize::Zeroizing::new(code.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_existing_profile_and_publishes_a_private_generation() -> Result<()> {
        let work = tempfile::tempdir()?;
        let store = Store {
            root: work.path().join("profiles"),
        };
        let domain = "https://Net.Example";
        let net = Id::new([1; 16])?;
        let service = Id::new([2; 16])?;
        let node = Id::new([3; 16])?;
        let _lock = store.lock(domain)?;
        let directory = store.path(domain);
        private::create_directory(&directory)?;
        let old = directory.join("credentials-go234");
        private::create_directory(&old)?;
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let mut params = rcgen::CertificateParams::new(Vec::new())?;
        params.subject_alt_names.push(rcgen::SanType::URI(
            format!("spiffe://laneway/network/{net}/node/{node}").try_into()?,
        ));
        let pem = params.self_signed(&key)?.pem();
        let private_key = key.serialize_pem();
        let creds = Credentials {
            ca: pem.as_bytes(),
            certificate: pem.as_bytes(),
            private_key: private_key.as_bytes(),
            wireguard_key: &[7; 32],
        };
        for (name, contents) in [
            ("ca.crt", creds.ca),
            ("node.crt", creds.certificate),
            ("node.key", creds.private_key),
            ("wireguard.key", creds.wireguard_key),
        ] {
            private::create(&old.join(name), contents)?;
        }
        let mut profile = Profile::new(domain, net, service, node)?;
        profile.generation = "credentials-go234".into();
        profile.created_at = "2026-07-23T19:52:31.192753928Z".into();
        private::create(&directory.join(MANIFEST), &serde_json::to_vec(&profile)?)?;
        assert_eq!(store.default_authority()?.as_deref(), Some(domain));
        assert_eq!(
            store
                .load("https://net.example")?
                .unwrap()
                .files
                .certificate,
            old.join("node.crt")
        );
        store.save(profile, creds)?;
        let replacement = store.load(domain)?.unwrap();
        assert_ne!(replacement.profile.generation, "credentials-go234");
        assert_eq!(
            replacement.profile.created_at,
            "2026-07-23T19:52:31.192753928Z"
        );
        assert!(old.join("node.key").exists());
        assert!(private::open_private_file(&replacement.files.private_key).is_ok());
        drop(_lock);
        store.logout(domain)?;
        assert!(store.default_authority()?.is_none());
        Ok(())
    }
}
