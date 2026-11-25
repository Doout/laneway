use std::{
    fs::{self, DirBuilder, File, OpenOptions, Permissions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use laneway_config::Config;
use zeroize::Zeroizing;

use crate::enrollment::{self, Controller, Credentials};

use super::Setup;

pub(super) const IDENTITY_FILES: &[&str] = &[
    "connector.toml",
    "ca.crt",
    "node.crt",
    "node.key",
    "wireguard.key",
];

pub(super) fn identity_count(state_dir: &Path) -> Result<usize> {
    let mut count = 0;
    for name in IDENTITY_FILES {
        match state_dir.join(name).symlink_metadata() {
            Ok(_) => count += 1,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect Connector identity {name}"));
            }
        }
    }
    Ok(count)
}

pub(super) fn read_regular(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && (1..=limit as u64).contains(&metadata.len()),
        "expected a nonempty bounded regular file"
    );
    if private {
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "--setup-token-file must not be accessible by group or other users"
        );
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut data)?;
    ensure!(
        !data.is_empty() && data.len() <= limit,
        "expected a nonempty bounded regular file"
    );
    Ok(std::mem::take(&mut *data))
}

pub(super) fn validate(state_dir: &Path) -> Result<Config> {
    for name in IDENTITY_FILES {
        ensure!(
            state_dir
                .join(name)
                .symlink_metadata()
                .is_ok_and(|meta| meta.is_file()),
            "Connector identity is incomplete or unsafe: {name}"
        );
    }
    let bytes = read_regular(&state_dir.join("connector.toml"), 1 << 20, false)?;
    Config::parse(std::str::from_utf8(&bytes)?).context("decode Connector configuration")
}

pub(super) fn configure(state_dir: &Path) -> Result<()> {
    let config = validate(state_dir)?;
    if config.connector.userspace && config.direct.enabled.unwrap_or_default() {
        return Ok(());
    }
    if !config.connector.userspace {
        ensure!(
            config.mode == "node"
                && config.direct.enabled.unwrap_or_default()
                && !config.routing.output_interface.is_empty()
                && config.routing.nat
                && !config.exit.enabled
                && config.exit.serve
                && !config.wireguard.enabled
                && !config.controller.endpoint.is_empty()
                && !config.controller.quic_endpoint.is_empty()
                && !config.controller.server_name.is_empty(),
            "existing configuration is not a recognized legacy Docker Connector; refusing automatic migration"
        );
    }
    let setup = Setup {
        name: config.node.name,
        code: String::new(),
        controller_endpoint: config.controller.endpoint,
        controller_quic: config.controller.quic_endpoint,
        server_name: config.controller.server_name,
        network_id: config.controller.network_id,
        controller_service_id: config.controller.service_id,
        relay_endpoint: config.node.relay_address,
        relay_service_id: config.node.relay_service_id,
        ca_pem: Vec::new(),
    };
    let content = render_config(state_dir, &setup)?;
    Config::parse(&content).context("validate migrated Connector configuration")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".connector.toml-")
        .tempfile_in(state_dir)?;
    temporary.write_all(content.as_bytes())?;
    temporary
        .as_file()
        .set_permissions(Permissions::from_mode(0o444))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(state_dir.join("connector.toml"))
        .map_err(|err| err.error)
        .context("publish migrated Connector configuration")?;
    println!(
        "Connector {} configuration migrated to unprivileged userspace mode",
        setup.name
    );
    Ok(())
}

pub(super) fn activate(state_dir: &Path, setup: &Setup) -> Result<()> {
    activate_with(state_dir, setup, || {
        let controller = Controller {
            endpoint: &setup.controller_endpoint,
            quic_endpoint: &setup.controller_quic,
            server_name: &setup.server_name,
            network_id: setup
                .network_id
                .parse()
                .context("invalid Connector network identity")?,
            service_id: setup
                .controller_service_id
                .parse()
                .context("invalid Connector controller identity")?,
            ca_pem: &setup.ca_pem,
        };
        enrollment::enroll_durable(&controller, &setup.code, &setup.name)
    })
}

fn activate_with(
    state_dir: &Path,
    setup: &Setup,
    enroll: impl FnOnce() -> Result<Credentials>,
) -> Result<()> {
    let parent = state_dir
        .parent()
        .context("Connector state must name a directory")?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .context("create Connector state parent")?;
    match state_dir.symlink_metadata() {
        Ok(meta) => {
            ensure!(meta.is_dir(), "Connector state path is not a directory");
            ensure!(
                fs::read_dir(state_dir)?.next().is_none(),
                "Connector activation refuses to replace existing state"
            );
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("inspect Connector state"),
    }

    let configuration = render_config(state_dir, setup)?;
    // Reject invalid configuration before consuming a single-use enrollment code.
    Config::parse(&configuration).context("validate generated Connector configuration")?;
    let staging = tempfile::Builder::new()
        .prefix(".connector-activation-")
        .tempdir_in(parent)?;
    let credentials = enroll()?;
    for (name, bytes, mode) in [
        ("connector.toml", configuration.as_bytes(), 0o444),
        ("ca.crt", setup.ca_pem.as_slice(), 0o444),
        ("node.crt", credentials.certificate_pem.as_slice(), 0o444),
        ("node.key", credentials.private_key_pem.as_slice(), 0o400),
        ("wireguard.key", &*credentials.wireguard_private_key, 0o400),
    ] {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staging.path().join(name))?;
        write_file(file, bytes, mode)
            .with_context(|| format!("write Connector identity {name}"))?;
    }
    File::open(staging.path())?.sync_all()?;
    fs::rename(staging.path(), state_dir).context("publish Connector identity")?;
    println!(
        "Connector {} activated; persistent identity: {}",
        setup.name,
        state_dir.display()
    );
    Ok(())
}

fn write_file(mut file: File, bytes: &[u8], mode: u32) -> Result<()> {
    file.write_all(bytes)?;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn quote(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

fn render_config(state_dir: &Path, setup: &Setup) -> Result<String> {
    let path = |name: &str| -> Result<String> {
        let candidate = state_dir.join(name);
        Ok(quote(
            candidate
                .to_str()
                .context("Connector state path must be UTF-8")?,
        ))
    };
    let state = quote(
        state_dir
            .to_str()
            .context("Connector state path must be UTF-8")?,
    );
    let cert = path("node.crt")?;
    let key = path("node.key")?;
    let ca = path("ca.crt")?;
    let server = quote(&setup.server_name);
    let name = quote(&setup.name);
    let relay = quote(&setup.relay_endpoint);
    let network = quote(&setup.network_id);
    let relay_service = quote(&setup.relay_service_id);
    let controller = quote(&setup.controller_endpoint);
    let quic = quote(&setup.controller_quic);
    let controller_service = quote(&setup.controller_service_id);
    let fallback = if setup.server_name.contains(':') {
        format!("[{}]:443", setup.server_name)
    } else {
        format!("{}:443", setup.server_name)
    };
    let fallback = quote(&fallback);
    if state_dir.as_os_str().is_empty() {
        bail!("Connector state path must not be empty");
    }
    Ok(format!(
        r#"mode = "node"
state_dir = {state}
socket_path = "/run/laneway/lanewayd.sock"

[tls]
certificate = {cert}
private_key = {key}
ca = {ca}
server_name = {server}

[node]
name = {name}
relay_address = {relay}
relay_network_id = {network}
relay_service_id = {relay_service}
reconnect_min = "1s"
reconnect_max = "30s"

[controller]
endpoint = {controller}
quic_endpoint = {quic}
server_name = {server}
network_id = {network}
service_id = {controller_service}
poll_interval = "30s"

[tcp_fallback]
address = {fallback}

[direct]
enabled = true
listen = ":0"

[connector]
userspace = true
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Setup {
        Setup {
            name: "connector-test".to_owned(),
            code: "fake-test-only".to_owned(),
            controller_endpoint: "https://controller.example.test:8443".to_owned(),
            controller_quic: "controller.example.test:8443".to_owned(),
            server_name: "controller.example.test".to_owned(),
            network_id: "11111111111111111111111111111111".to_owned(),
            controller_service_id: "22222222222222222222222222222222".to_owned(),
            relay_endpoint: "relay.example.test:4433".to_owned(),
            relay_service_id: "33333333333333333333333333333333".to_owned(),
            ca_pem: b"fixture CA".to_vec(),
        }
    }

    fn credentials() -> Result<Credentials> {
        Ok(Credentials {
            node_id: "44444444444444444444444444444444".parse().unwrap(),
            certificate_pem: b"fixture certificate".to_vec(),
            private_key_pem: Zeroizing::new(b"fixture key".to_vec()),
            wireguard_private_key: Zeroizing::new([4; 32]),
            overlays: Vec::new(),
            lease_expires_at: None,
        })
    }

    #[test]
    fn activation_publishes_all_files_and_never_reenrolls_existing_state() {
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("connector");
        fs::create_dir(&dir).unwrap();
        let setup = setup();
        assert!(activate_with(&dir, &setup, || anyhow::bail!("controller unavailable")).is_err());
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
        activate_with(&dir, &setup, credentials).unwrap();
        let config = validate(&dir).unwrap();
        assert!(config.connector.userspace);
        assert_eq!(config.direct.enabled, Some(true));
        assert_eq!(config.node.name, setup.name);
        assert_eq!(identity_count(&dir).unwrap(), IDENTITY_FILES.len());
        for filename in ["node.key", "wireguard.key"] {
            assert_eq!(
                fs::metadata(dir.join(filename))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        assert_eq!(fs::read(dir.join("wireguard.key")).unwrap(), [4; 32]);
        let result = activate_with(&dir, &setup, || panic!("must not consume another token"));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("refuses to replace existing state")
        );
    }

    #[test]
    fn recognized_legacy_configuration_migrates_without_touching_keys() {
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("connector");
        let setup = setup();
        activate_with(&dir, &setup, credentials).unwrap();
        let filename = dir.join("connector.toml");
        fs::set_permissions(&filename, Permissions::from_mode(0o600)).unwrap();
        let config = render_config(&dir, &setup).unwrap().replace(
            "[direct]\nenabled = true\nlisten = \":0\"\n\n[connector]\nuserspace = true\n",
            "[direct]\nenabled = true\nlisten = \"0.0.0.0:4434\"\n\n[routing]\noutput_interface = \"eth0\"\nnat = true\n\n[exit]\nenabled = false\nserve = true\nfailure_mode = \"closed\"\n",
        );
        fs::write(&filename, &config).unwrap();
        assert!(!validate(&dir).unwrap().connector.userspace);
        configure(&dir).unwrap();
        let migrated = validate(&dir).unwrap();
        assert!(migrated.connector.userspace);
        assert!(migrated.routing.output_interface.is_empty());
        assert!(!migrated.exit.serve);
        assert_eq!(fs::read(dir.join("node.key")).unwrap(), b"fixture key");
        let unchanged = fs::read(&filename).unwrap();
        configure(&dir).unwrap();
        assert_eq!(fs::read(&filename).unwrap(), unchanged);
    }

    #[test]
    fn token_open_rejects_symlinks_and_group_access() {
        use std::os::unix::fs::symlink;

        let work = tempfile::tempdir().unwrap();
        let token = work.path().join("token");
        let link = work.path().join("link");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token)
            .unwrap();
        write_file(file, b"protected", 0o600).unwrap();
        symlink(&token, &link).unwrap();
        assert_eq!(read_regular(&token, 64, true).unwrap(), b"protected");
        assert!(read_regular(&link, 64, true).is_err());
        fs::set_permissions(&token, Permissions::from_mode(0o640)).unwrap();
        assert!(read_regular(&token, 64, true).is_err());
        assert_eq!(read_regular(&token, 64, false).unwrap(), b"protected");
    }
}
