use std::{
    env, fs,
    fs::File,
    io::{ErrorKind, Read},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::Id;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{profile_path, profile_root};
use crate::{bootstrap::Metadata, enrollment::Credentials};

const MAX_MANIFEST_BYTES: u64 = 64 << 10;
const MAX_CREDENTIAL_BYTES: u64 = 256 << 10;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    version: u32,
    pub(super) authority: String,
    pub(super) network_id: String,
    pub(super) controller_service_id: String,
    pub(super) node_id: String,
    pub(super) name: String,
    generation: String,
    created_at: String,
}

// Windows supports saving profiles. The foreground connect consumers are Unix-only.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) struct SavedProfile {
    pub(crate) authority: String,
    pub(crate) network_id: String,
    pub(crate) controller_service_id: String,
    pub(crate) node_id: String,
    pub(crate) ca: PathBuf,
    pub(crate) certificate: PathBuf,
    pub(crate) private_key: PathBuf,
    pub(crate) wireguard_key: PathBuf,
    pub(super) manifest: Manifest,
}

impl Manifest {
    pub(super) fn new(authority: &str, metadata: &Metadata, node_id: Id) -> Result<Self> {
        Ok(Self {
            version: 1,
            authority: authority.to_owned(),
            network_id: metadata.network_id.clone(),
            controller_service_id: metadata.controller.service_id.clone(),
            node_id: node_id.to_string(),
            name: "remembered-user".to_owned(),
            generation: String::new(),
            created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        })
    }
}

pub(super) fn current_root() -> PathBuf {
    profile_root(|key| env::var_os(key))
}

pub(super) fn lock_profile(root: &Path, authority: &str) -> Result<File> {
    let path = profile_path(root, authority);
    let key = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("encode saved login directory")?;
    laneway_private::lock(&root.join(format!(".lock-{key}"))).context("lock saved login")
}

pub(super) fn ensure_profile_root(root: &Path) -> Result<()> {
    ensure!(
        root.is_absolute(),
        "LANEWAY_PROFILE_DIR must be an absolute path"
    );
    if let Some(parent) = root.parent() {
        create_missing_private_dirs(parent)?;
    }
    laneway_private::ensure_directory(root).context("open or create profile root")?;
    Ok(())
}

fn create_missing_private_dirs(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let parent = path.parent().context("saved login root has no parent")?;
            create_missing_private_dirs(parent)?;
            laneway_private::ensure_directory(path).context("create profile root")
        }
        Ok(_) => bail!("saved login root ancestor is not a directory"),
        Err(error) => Err(error).context("open profile root"),
    }
}

pub(crate) fn default_authority() -> Result<String> {
    default_authority_at(&current_root())
}

fn default_authority_at(root: &Path) -> Result<String> {
    laneway_private::check_directory(root).context("open saved login root")?;
    let mut authorities = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(key) = name.to_str() else { continue };
        if key.len() != 32 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let directory = entry.path();
        let manifest = read_manifest(&directory)?;
        ensure!(
            !manifest.authority.is_empty() && profile_path(root, &manifest.authority) == directory,
            "saved login metadata is invalid or stored under the wrong authority"
        );
        authorities.push(load_at(root, &manifest.authority)?.authority);
    }
    authorities.sort();
    match authorities.as_slice() {
        [] => Err(std::io::Error::from(ErrorKind::NotFound).into()),
        [authority] => Ok(authority.clone()),
        many => bail!(
            "multiple saved logins ({}); specify DOMAIN",
            many.join(", ")
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn load(authority: &str) -> Result<SavedProfile> {
    load_at(&current_root(), authority)
}

pub(super) fn load_at(root: &Path, authority: &str) -> Result<SavedProfile> {
    laneway_private::check_directory(root).context("open saved login root")?;
    let directory = profile_path(root, authority);
    let manifest = read_manifest(&directory)?;
    let mut name = Path::new(&manifest.generation).components();
    ensure!(
        manifest.version == 1
            && !manifest.authority.is_empty()
            && profile_path(root, &manifest.authority) == directory
            && manifest.generation.starts_with("credentials-")
            && matches!(name.next(), Some(Component::Normal(value)) if value == manifest.generation.as_str())
            && name.next().is_none(),
        "saved login metadata is invalid or belongs to another authority"
    );
    manifest
        .network_id
        .parse::<Id>()
        .context("saved login has an invalid network identity")?;
    manifest
        .controller_service_id
        .parse::<Id>()
        .context("saved login has an invalid controller identity")?;
    manifest
        .node_id
        .parse::<Id>()
        .context("saved login has an invalid node identity")?;
    OffsetDateTime::parse(&manifest.created_at, &Rfc3339)
        .context("saved login has an invalid creation date")?;

    let generation = directory.join(&manifest.generation);
    laneway_private::check_directory(&generation).context("open saved login credentials")?;
    let ca = generation.join("ca.crt");
    let certificate = generation.join("node.crt");
    let private_key = generation.join("node.key");
    let wireguard_key = generation.join("wireguard.key");
    for path in [&ca, &certificate, &private_key, &wireguard_key] {
        let file = laneway_private::open_private_file(path)
            .with_context(|| format!("open saved {}", path.display()))?;
        let length = file.metadata()?.len();
        ensure!(
            (1..=MAX_CREDENTIAL_BYTES).contains(&length),
            "saved login file {} is empty or too large",
            path.display()
        );
    }
    Ok(SavedProfile {
        authority: manifest.authority.clone(),
        network_id: manifest.network_id.clone(),
        controller_service_id: manifest.controller_service_id.clone(),
        node_id: manifest.node_id.clone(),
        ca,
        certificate,
        private_key,
        wireguard_key,
        manifest,
    })
}

fn read_manifest(directory: &Path) -> Result<Manifest> {
    laneway_private::check_directory(directory).context("open saved login")?;
    let bytes = read_limited(&directory.join("profile.json"), MAX_MANIFEST_BYTES)?;
    serde_json::from_slice(&bytes).context("parse saved login")
}

fn read_limited(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = laneway_private::open_private_file(path)
        .with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= maximum,
        "{} is empty or too large",
        path.display()
    );
    Ok(bytes)
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
impl SavedProfile {
    pub(crate) fn validate_metadata(&self, metadata: &Metadata) -> Result<()> {
        ensure!(
            self.network_id == metadata.network_id
                && self.controller_service_id == metadata.controller.service_id,
            "controller identity changed; refusing to use the saved login (log out and verify before logging in again)"
        );
        ensure!(
            String::from_utf8(read_limited(&self.ca, MAX_CREDENTIAL_BYTES)?)?.trim()
                == metadata.trust.ca_pem.trim(),
            "controller CA changed; refusing to use the saved login"
        );
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn read_ca(&self) -> Result<Vec<u8>> {
        read_limited(&self.ca, MAX_CREDENTIAL_BYTES)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn read_certificate(&self) -> Result<Vec<u8>> {
        read_limited(&self.certificate, MAX_CREDENTIAL_BYTES)
    }

    pub(crate) fn read_wireguard_key(&self) -> Result<[u8; 32]> {
        let bytes = zeroize::Zeroizing::new(read_limited(&self.wireguard_key, 32)?);
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("saved login contains an invalid WireGuard private key"))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn generation(&self) -> &str {
        &self.manifest.generation
    }
}

pub(super) fn save(
    root: &Path,
    mut manifest: Manifest,
    ca: &[u8],
    credentials: &Credentials,
    replace: bool,
) -> Result<SavedProfile> {
    ensure!(
        manifest.node_id.parse::<Id>()? == credentials.node_id,
        "saved login credentials do not match the profile node ID"
    );
    let directory = profile_path(root, &manifest.authority);
    laneway_private::ensure_directory(&directory).context("create profile")?;
    let generation = new_generation(&directory)?;
    manifest.generation = generation
        .file_name()
        .and_then(|value| value.to_str())
        .context("encode saved credential generation")?
        .to_owned();
    if let Err(error) = write_generation(&generation, ca, credentials) {
        let _ = fs::remove_dir_all(&generation);
        return Err(error);
    }
    let mut encoded = serde_json::to_vec_pretty(&manifest)?;
    ensure!(
        (encoded.len() as u64) < MAX_MANIFEST_BYTES,
        "saved login metadata is too large"
    );
    encoded.push(b'\n');
    let path = directory.join("profile.json");
    if replace {
        laneway_private::write(&path, &encoded)?;
    } else {
        laneway_private::create(&path, &encoded)?;
    }
    load_at(root, &manifest.authority)
}

fn new_generation(directory: &Path) -> Result<PathBuf> {
    let mut unique = [0_u8; 16];
    getrandom::fill(&mut unique).context("generate saved credential directory name")?;
    let path = directory.join(format!("credentials-{}", hex::encode(unique)));
    laneway_private::create_directory(&path).context("create saved credential directory")?;
    Ok(path)
}

fn write_generation(generation: &Path, ca: &[u8], credentials: &Credentials) -> Result<()> {
    for (name, bytes) in [
        ("ca.crt", ca),
        ("node.crt", credentials.certificate_pem.as_slice()),
        ("node.key", credentials.private_key_pem.as_slice()),
        (
            "wireguard.key",
            credentials.wireguard_private_key.as_slice(),
        ),
    ] {
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_CREDENTIAL_BYTES,
            "saved {name} is empty or too large"
        );
        laneway_private::create(&generation.join(name), bytes)
            .with_context(|| format!("save {name}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::credentials::is_missing;

    fn metadata() -> Metadata {
        Metadata {
            network_id: "11111111111111111111111111111111".into(),
            controller: crate::bootstrap::Controller {
                service_id: "22222222222222222222222222222222".into(),
                ..Default::default()
            },
            trust: crate::bootstrap::Trust {
                ca_pem: "test CA\n".into(),
            },
            ..Default::default()
        }
    }

    fn credentials(key: u8) -> Credentials {
        Credentials {
            node_id: Id::new([3; 16]).unwrap(),
            certificate_pem: b"certificate fixture".to_vec(),
            private_key_pem: b"private key fixture".to_vec().into(),
            wireguard_private_key: [key; 32].into(),
            overlays: Vec::new(),
            lease_expires_at: None,
        }
    }

    #[test]
    fn preserves_manifest_and_generations_across_key_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("laneway/profiles");
        assert!(is_missing(&default_authority_at(&root).unwrap_err()));
        ensure_profile_root(&root).unwrap();
        let metadata = metadata();
        let first = credentials(7);
        let initial = Manifest::new("example.test", &metadata, first.node_id).unwrap();
        let first = save(
            &root,
            initial,
            metadata.trust.ca_pem.as_bytes(),
            &first,
            false,
        )
        .unwrap();
        assert_eq!(first.read_wireguard_key().unwrap(), [7; 32]);
        assert_eq!(first.manifest.name, "remembered-user");
        first.validate_metadata(&metadata).unwrap();
        let old_key_path = first.wireguard_key.clone();
        let created_at = first.manifest.created_at.clone();
        assert_eq!(default_authority_at(&root).unwrap(), "example.test");
        let updated = save(
            &root,
            first.manifest,
            metadata.trust.ca_pem.as_bytes(),
            &credentials(8),
            true,
        )
        .unwrap();
        assert_eq!(updated.manifest.created_at, created_at);
        assert_ne!(updated.wireguard_key, old_key_path);
        assert_eq!(updated.read_wireguard_key().unwrap(), [8; 32]);
        assert_eq!(fs::read(old_key_path).unwrap(), [7; 32]);
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(profile_path(&root, "EXAMPLE.TEST").join("profile.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["version"], 1);
        assert_eq!(manifest["authority"], "example.test");
        assert_eq!(
            manifest["controller_service_id"],
            metadata.controller.service_id
        );
        let mut changed = metadata;
        changed.trust.ca_pem = "different root".into();
        assert!(updated.validate_metadata(&changed).is_err());
    }

    #[test]
    fn loads_existing_go_manifest_and_rejects_multiple_default_profiles() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("profiles");
        ensure_profile_root(&root).unwrap();
        let directory = profile_path(&root, "old.example");
        let generation = directory.join("credentials-102938");
        laneway_private::ensure_directory(&directory).unwrap();
        laneway_private::create_directory(&generation).unwrap();
        let credentials = credentials(9);
        write_generation(&generation, b"CA", &credentials).unwrap();
        let existing = br#"{
          "version": 1,
          "authority": "old.example",
          "network_id": "11111111111111111111111111111111",
          "controller_service_id": "22222222222222222222222222222222",
          "node_id": "03030303030303030303030303030303",
          "name": "remembered-user",
          "generation": "credentials-102938",
          "created_at": "2026-11-25T20:30:49.125022307Z"
        }"#;
        laneway_private::create(&directory.join("profile.json"), existing).unwrap();
        let old = load_at(&root, "OLD.EXAMPLE").unwrap();
        assert_eq!(old.read_wireguard_key().unwrap(), [9; 32]);
        assert_eq!(default_authority_at(&root).unwrap(), "old.example");
        let metadata = metadata();
        let manifest = Manifest::new("another.example", &metadata, credentials.node_id).unwrap();
        save(&root, manifest, b"CA", &credentials, false).unwrap();
        let error = default_authority_at(&root).unwrap_err().to_string();
        assert!(error.contains("another.example, old.example"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_insecure_credentials_and_symlinked_generation() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("profiles");
        ensure_profile_root(&root).unwrap();
        let credentials = credentials(9);
        let metadata = metadata();
        let manifest = Manifest::new("example.test", &metadata, credentials.node_id).unwrap();
        let profile = save(&root, manifest, b"CA", &credentials, false).unwrap();
        fs::set_permissions(&profile.private_key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_at(&root, "example.test").is_err());
        let parent = profile.private_key.parent().unwrap();
        let other_directory = tmp.path().join("elsewhere");
        fs::rename(parent, &other_directory).unwrap();
        symlink(other_directory, parent).unwrap();
        assert!(load_at(&root, "example.test").is_err());
    }
}
