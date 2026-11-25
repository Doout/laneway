use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use laneway_config::Config;
use laneway_protocol::Id;
use lanewayd_rs::TlsConfig;
use nix::unistd::{Gid, Uid, chown, fchown};
use zeroize::Zeroizing;

use super::{Credentials, Manifest, Metadata};

const CREDS_LIMIT: u64 = 256 << 10;
const FILES: [&str; 5] = [
    "ca.crt",
    "node.crt",
    "node.key",
    "wireguard.key",
    "laneway.toml",
];
const MANIFEST: &str = "node-install.json";
const LOCK: &str = ".node-install.lock";

pub(super) struct Paths {
    config: PathBuf,
    state: PathBuf,
    socket: PathBuf,
}

impl Paths {
    pub(super) fn installed() -> Self {
        Self {
            config: "/etc/laneway".into(),
            state: "/var/lib/laneway".into(),
            socket: "/run/laneway/lanewayd.sock".into(),
        }
    }

    pub(super) fn lock(&self, group_if_missing: Option<u32>) -> Result<File> {
        match (group_if_missing, fs::symlink_metadata(&self.config)) {
            (Some(group), Err(error)) if error.kind() == ErrorKind::NotFound => {
                prepare_directory(&self.config, group)?;
            }
            (_, _) => check_root_directory(&self.config)?,
        }
        let path = self.config.join(LOCK);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)
            .context("open managed node lock")?;
        validate_file(&file, &path, 0o600, 0)?;
        fs2::FileExt::lock_exclusive(&file).context("lock managed node configuration")?;
        Ok(file)
    }

    pub(super) fn manifest(&self) -> Result<Option<Manifest>> {
        let path = self.config.join(MANIFEST);
        let file = match open_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("open managed node manifest"),
        };
        validate_file(&file, &path, 0o600, 0)?;
        let bytes = read_bounded(file, 4096)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).context("parse managed node manifest")?;
        ensure!(
            manifest.version == 1,
            "unsupported managed node manifest version"
        );
        manifest
            .network_id
            .parse::<Id>()
            .context("invalid managed network identity")?;
        manifest
            .node_id
            .parse::<Id>()
            .context("invalid managed node identity")?;
        Ok(Some(manifest))
    }

    pub(super) fn check_unmanaged_absent(&self) -> Result<()> {
        for name in FILES {
            let path = self.config.join(name);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", path.display()));
                }
                Ok(_) => bail!("refusing to replace unmanaged path {}", path.display()),
            }
        }
        Ok(())
    }

    pub(super) fn validate_files(&self, gid: u32) -> Result<Config> {
        for name in FILES {
            let path = self.config.join(name);
            let file = open_file(&path).with_context(|| format!("open {}", path.display()))?;
            validate_file(&file, &path, 0o640, gid)?;
        }
        let config = Config::load(&self.config.join("laneway.toml"))?;
        ensure!(
            config.mode == "node"
                && Path::new(&config.tls.ca) == self.config.join("ca.crt")
                && Path::new(&config.tls.certificate) == self.config.join("node.crt")
                && Path::new(&config.tls.private_key) == self.config.join("node.key")
                && Path::new(&config.wireguard.private_key) == self.config.join("wireguard.key"),
            "managed node configuration points outside its installed credential paths"
        );
        Ok(config)
    }

    pub(super) fn install(
        &self,
        gid: u32,
        metadata: &Metadata,
        credentials: &Credentials,
        config: &[u8],
        manifest: &Manifest,
    ) -> Result<()> {
        prepare_directory(&self.config, gid)?;
        let mut encoded = serde_json::to_vec_pretty(manifest)?;
        encoded.push(b'\n');
        let values: [(&str, &[u8], u32, u32); 6] = [
            ("ca.crt", metadata.trust.ca_pem.as_bytes(), 0o640, gid),
            ("node.crt", &credentials.certificate_pem, 0o640, gid),
            (
                "node.key",
                credentials.private_key_pem.as_slice(),
                0o640,
                gid,
            ),
            (
                "wireguard.key",
                credentials.wireguard_private_key.as_slice(),
                0o640,
                gid,
            ),
            ("laneway.toml", config, 0o640, gid),
            (MANIFEST, &encoded, 0o600, 0),
        ];
        let mut written = Vec::new();
        let result = (|| {
            for (name, bytes, mode, owner) in values {
                let destination = self.config.join(name);
                write_file(&destination, bytes, mode, owner, false)?;
                written.push(destination);
            }
            File::open(&self.config)?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = result {
            let cleanup = written
                .into_iter()
                .rev()
                .map(|path| fs::remove_file(path).map_err(Into::into));
            return Err(super::service::failures(error, cleanup));
        }
        Ok(())
    }

    pub(super) fn stage_current(&self) -> Result<StagedCredentials> {
        let ca = self.read_ca()?;
        let cert = self.read("node.crt")?;
        let key = Zeroizing::new(self.read("node.key")?);
        StagedCredentials::new(&self.config, &ca, &cert, &key)
    }

    pub(super) fn stage_enrollment(
        &self,
        metadata: &Metadata,
        credentials: &Credentials,
    ) -> Result<StagedCredentials> {
        StagedCredentials::new(
            &self.config,
            metadata.trust.ca_pem.as_bytes(),
            &credentials.certificate_pem,
            &credentials.private_key_pem,
        )
    }

    pub(super) fn read_ca(&self) -> Result<Vec<u8>> {
        self.read("ca.crt")
    }

    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.config.join(name);
        read_bounded(open_file(&path)?, CREDS_LIMIT)
            .with_context(|| format!("read managed {}", path.display()))
    }

    pub(super) fn check_removal(&self, remove_state: bool) -> Result<()> {
        for name in FILES.into_iter().chain([MANIFEST]) {
            let path = self.config.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => ensure!(
                    metadata.is_file() && metadata.uid() == 0,
                    "refuse to remove unsafe managed path {}",
                    path.display()
                ),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", path.display()));
                }
            }
        }
        if remove_state {
            match fs::symlink_metadata(&self.state) {
                Ok(metadata) => ensure!(
                    metadata.is_dir(),
                    "refuse to remove unsafe state directory {}",
                    self.state.display()
                ),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect node state directory"),
            }
        }
        Ok(())
    }

    pub(super) fn remove(&self, remove_state: bool) -> Result<()> {
        self.check_removal(remove_state)?;
        for name in FILES.into_iter().chain([MANIFEST]) {
            match fs::remove_file(self.config.join(name)) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                outcome => outcome.with_context(|| format!("remove managed {name}"))?,
            }
        }
        File::open(&self.config)?.sync_all()?;
        if remove_state {
            match fs::remove_dir_all(&self.state) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                outcome => outcome.context("remove managed node state")?,
            }
        }
        Ok(())
    }

    pub(super) fn promote(&self, gid: u32, credentials: &Credentials) -> Result<()> {
        self.reconcile_wireguard(gid, credentials)?;
        self.replace_tls(
            gid,
            &credentials.certificate_pem,
            &credentials.private_key_pem,
        )
    }

    pub(super) fn reconcile_wireguard(&self, gid: u32, credentials: &Credentials) -> Result<()> {
        self.replace(
            "wireguard.key",
            credentials.wireguard_private_key.as_slice(),
            gid,
        )
    }

    pub(super) fn restore_tls(&self, gid: u32, credentials: &StagedCredentials) -> Result<()> {
        let certificate = laneway_private::read(&credentials.tls.certificate)?;
        let key = Zeroizing::new(laneway_private::read(&credentials.tls.private_key)?);
        self.replace_tls(gid, &certificate, &key)
    }

    fn replace_tls(&self, gid: u32, certificate: &[u8], key: &[u8]) -> Result<()> {
        self.replace("node.crt", certificate, gid)?;
        self.replace("node.key", key, gid)
    }

    fn replace(&self, name: &str, bytes: &[u8], gid: u32) -> Result<()> {
        write_file(&self.config.join(name), bytes, 0o640, gid, true)?;
        File::open(&self.config)?.sync_all()?;
        Ok(())
    }

    pub(super) fn render_config(
        &self,
        metadata: &Metadata,
        name: &str,
        relay: (Id, &str),
        direct: bool,
    ) -> Result<String> {
        let string = |value: &str| toml::Value::String(value.to_owned());
        let path = |value: &Path| -> Result<toml::Value> {
            Ok(string(
                value.to_str().context("managed path is not Unicode")?,
            ))
        };
        let rendered = format!(
            r#"mode = "node"
state_dir = {state}
socket_path = {socket}
[tls]
certificate = {cert}
private_key = {key}
ca = {ca}
[node]
name = {name}
relay_address = {endpoint}
relay_network_id = {network}
relay_service_id = "{relay_service}"
reconnect_min = "1s"
reconnect_max = "30s"
[controller]
endpoint = {controller}
quic_endpoint = {controller_quic}
server_name = {server_name}
network_id = {network}
service_id = {controller_service}
poll_interval = "30s"
[direct]
enabled = {direct}
listen = "0.0.0.0:0"
candidate_ttl = "2m"
probe_interval = "200ms"
probe_timeout = "3s"
rendezvous_interval = "30s"
max_candidates = 8
[exit]
enabled = false
failure_mode = "closed"
[wireguard]
enabled = false
private_key = {wireguard}
interface = "lane0"
listen_port = 0
mtu = 1280
"#,
            state = path(&self.state)?,
            socket = path(&self.socket)?,
            cert = path(&self.config.join("node.crt"))?,
            key = path(&self.config.join("node.key"))?,
            ca = path(&self.config.join("ca.crt"))?,
            name = string(name),
            endpoint = string(relay.1),
            network = string(&metadata.network_id),
            relay_service = relay.0,
            controller = string(&metadata.controller.enrollment_endpoint),
            controller_quic = string(&metadata.controller.quic_endpoint),
            server_name = string(&metadata.controller.server_name),
            controller_service = string(&metadata.controller.service_id),
            wireguard = path(&self.config.join("wireguard.key"))?,
        );
        Config::parse(&rendered).context("validate generated managed node configuration")?;
        Ok(rendered)
    }
}

fn prepare_directory(path: &Path, gid: u32) -> Result<()> {
    match DirBuilder::new().mode(0o750).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create managed node configuration directory"),
    }
    check_root_directory(path)?;
    chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(gid)))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
    Ok(())
}

fn check_root_directory(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let info = fs::symlink_metadata(ancestor)?;
        ensure!(
            info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0,
            "{} must be a protected root-owned directory",
            ancestor.display()
        );
    }
    Ok(())
}

fn open_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
}

fn validate_file(file: &File, path: &Path, mode: u32, gid: u32) -> Result<()> {
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.uid() == 0 && info.gid() == gid && info.mode() & 0o7777 == mode,
        "managed node path is missing or unsafe: {}",
        path.display()
    );
    Ok(())
}

fn read_bounded(file: File, max: u64) -> Result<Vec<u8>> {
    ensure!(
        file.metadata()?.is_file(),
        "managed node path is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= max,
        "managed node file is empty or oversized"
    );
    Ok(bytes)
}

fn write_file(path: &Path, bytes: &[u8], mode: u32, gid: u32, replace: bool) -> Result<()> {
    let mut temp =
        tempfile::NamedTempFile::new_in(path.parent().context("managed node file has no parent")?)?;
    temp.write_all(bytes)?;
    fchown(
        temp.as_file(),
        Some(Uid::from_raw(0)),
        Some(Gid::from_raw(gid)),
    )?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temp.as_file().sync_all()?;
    if replace {
        temp.persist(path)
    } else {
        temp.persist_noclobber(path)
    }
    .with_context(|| format!("publish managed node file {}", path.display()))?;
    Ok(())
}

pub(super) struct StagedCredentials {
    _directory: tempfile::TempDir,
    pub(super) tls: TlsConfig,
}

impl StagedCredentials {
    fn new(parent: &Path, ca: &[u8], certificate: &[u8], key: &[u8]) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("laneway-managed-node-")
            .tempdir_in(parent)?;
        let root = directory.path().join("credentials");
        laneway_private::create_directory(&root)?;
        let tls = TlsConfig {
            ca: root.join("ca.crt"),
            certificate: root.join("node.crt"),
            private_key: root.join("node.key"),
        };
        for (path, contents) in [
            (&tls.ca, ca),
            (&tls.certificate, certificate),
            (&tls.private_key, key),
        ] {
            laneway_private::create(path, contents)?;
        }
        Ok(Self {
            _directory: directory,
            tls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_restores_tls_and_retains_the_controller_bound_wireguard_key() {
        // The production files must be root-owned, so this fixture can only
        // exercise publication when the isolated test process runs as root.
        if !Uid::effective().is_root() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        let paths = Paths {
            config: config.clone(),
            state: root.path().join("state"),
            socket: root.path().join("socket"),
        };
        fs::create_dir(&config).unwrap();
        for (name, content) in [
            ("ca.crt", b"ca".as_slice()),
            ("node.crt", b"previous cert"),
            ("node.key", b"previous key"),
            ("wireguard.key", &[1; 32]),
        ] {
            write_file(&config.join(name), content, 0o640, 0, false).unwrap();
        }
        assert!(write_file(&config.join("node.key"), b"clobber", 0o640, 0, false).is_err());
        let previous = paths.stage_current().unwrap();
        let credentials = Credentials {
            node_id: Id::new([1; 16]).unwrap(),
            certificate_pem: b"rotated cert".to_vec(),
            private_key_pem: b"rotated key".to_vec().into(),
            wireguard_private_key: [2; 32].into(),
            overlays: Vec::new(),
            lease_expires_at: None,
        };
        paths.promote(0, &credentials).unwrap();
        paths.restore_tls(0, &previous).unwrap();
        assert_eq!(fs::read(config.join("node.key")).unwrap(), b"previous key");
        assert_eq!(fs::read(config.join("node.crt")).unwrap(), b"previous cert");
        assert_eq!(fs::read(config.join("wireguard.key")).unwrap(), [2; 32]);
    }
}
