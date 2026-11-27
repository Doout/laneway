use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{ArgAction, Args};
use laneway_protocol::{Id, relay_endpoint::canonical_host_port, v1::EnrollmentClass};
use lanewayd_rs::{Agent, Config, TlsConfig};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{process::Command, time::timeout};

use super::{admin::read_file, bootstrap, enrollment::RedeemTarget, profiles::enrollment_code};

const CONFIG_DIR: &str = "/etc/laneway";
const STATE: &str = "/var/lib/laneway";
const IDENTITY: &str = "/var/lib/laneway/identity";
const MANIFEST: &str = "/etc/laneway/node-install.json";
const CA: &str = "/etc/laneway/ca.crt";
const CERTIFICATE: &str = "/var/lib/laneway/identity/node.crt";
const KEY: &str = "/etc/laneway/node.key";
const CONFIG: &str = "/etc/laneway/node-rust.toml";
const EXIT: &str = "/var/lib/laneway/exit-intent-v1.json";
const UNIT: &str = "lanewayd-rs.service";
const LEGACY_UNIT: &str = "lanewayd.service";
const SOCKET: &str = "/run/laneway/lanewayd.sock";
const HEALTH: &str = "/usr/local/sbin/laneway-healthcheck-rs";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

#[derive(Args)]
pub(super) struct Options {
    #[arg(value_name = "DOMAIN")]
    authority: String,
    #[arg(long)]
    token_file: Option<PathBuf>,
    #[arg(long, default_value = "")]
    name: String,
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
    no_direct: bool,
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
    no_start: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    authority: String,
    network_id: String,
    node_id: String,
    direct_enabled: bool,
    runtime: String,
}

#[derive(Clone, Copy)]
struct Owner {
    uid: u32,
    gid: u32,
}

pub(super) async fn run(options: Options) -> Result<()> {
    ensure!(
        laneway_private::is_root(),
        "node install must run as root (for example: sudo laneway node install ...)"
    );
    ensure!(
        options.name.trim() == options.name && options.name.len() <= 253,
        "invalid node name"
    );
    let owner = preflight().await?;
    protected_dir(Path::new("/etc"), 0, None)?;
    protected_dir(Path::new("/var/lib"), 0, None)?;
    create_directory(CONFIG_DIR, 0, owner.gid, 0o750)?;
    let _lock = laneway_private::lock(&Path::new(CONFIG_DIR).join(".node-install.lock"))?;
    let direct = !options.no_direct;

    let existing = match fs::symlink_metadata(MANIFEST) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect managed node manifest"),
    };
    if existing {
        verify_file(MANIFEST, 0, 0, 0o600)?;
        let installed: Manifest = serde_json::from_slice(&read_file(Path::new(MANIFEST), 4096)?)?;
        ensure!(
            installed.version == 1
                && installed.runtime == "rust"
                && installed.authority == options.authority
                && installed.direct_enabled == direct,
            "existing managed node was installed with different authority or dataplane settings"
        );
        installed.network_id.parse::<Id>()?;
        installed.node_id.parse::<Id>()?;
        validate_installation(owner)?;
        if !options.no_start
            && let Err(error) = start().await
        {
            cleanup()
                .await
                .context(format!("cleanup after start failure: {error:#}"))?;
            return Err(error).context("start existing managed node");
        }
        println!(
            "managed node already installed network={} node={} direct={direct}",
            installed.network_id, installed.node_id
        );
        return Ok(());
    }

    for path in [
        CA,
        KEY,
        CERTIFICATE,
        CONFIG,
        MANIFEST,
        EXIT,
        "/etc/laneway/node.crt",
        "/etc/laneway/wireguard.key",
        "/etc/laneway/laneway.toml",
    ] {
        absent(path)?;
    }
    reject_legacy_service().await?;
    create_directory(STATE, owner.uid, owner.gid, 0o700)?;
    create_directory(IDENTITY, owner.uid, owner.gid, 0o700)?;

    let metadata = bootstrap::fetch(&options.authority).await?;
    metadata.current_artifact()?;
    let network = metadata.network_id.parse::<Id>()?;
    let code = enrollment_code(options.token_file.as_deref())?;
    let enrolled = RedeemTarget {
        endpoint: &metadata.controller.enrollment_endpoint,
        ca: metadata.trust.ca_pem.as_bytes(),
        server_name: &metadata.controller.server_name,
        network,
        service: metadata.controller.service_id.parse()?,
    }
    .redeem(&code, &options.name, EnrollmentClass::DurableNode)
    .await?;
    drop(code);

    let staging = tempfile::Builder::new()
        .prefix(".node-install-")
        .tempdir_in(CONFIG_DIR)?;
    let tls = TlsConfig {
        ca: staging.path().join("ca.crt"),
        certificate: staging.path().join("node.crt"),
        private_key: staging.path().join("node.key"),
    };
    fs::write(&tls.ca, metadata.trust.ca_pem.as_bytes())?;
    fs::write(&tls.certificate, &enrolled.certificate)?;
    fs::write(&tls.private_key, enrolled.key.as_bytes())?;
    fs::set_permissions(&tls.private_key, fs::Permissions::from_mode(0o600))?;
    let initial = timeout(
        Duration::from_secs(20),
        lanewayd_rs::rootless::get_configuration(
            &metadata.controller.config(),
            network,
            enrolled.node,
            &tls,
        ),
    )
    .await
    .context("fetch initial managed-node configuration")??;
    let relay = initial
        .relays
        .iter()
        .min_by(|a, b| (&a.service_id, &a.endpoint).cmp(&(&b.service_id, &b.endpoint)))
        .context("controller authorized no relay for the managed node")?;
    let relay_id = Id::from_slice(&relay.service_id)?;
    let config = render(
        &metadata,
        &options.authority,
        enrolled.node,
        relay_id,
        &relay.endpoint,
        direct,
    )?;
    let manifest = Manifest {
        version: 1,
        authority: options.authority,
        network_id: network.to_string(),
        node_id: enrolled.node.to_string(),
        direct_enabled: direct,
        runtime: "rust".into(),
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    let files = [
        (CA, metadata.trust.ca_pem.as_bytes(), 0, owner.gid, 0o640),
        (KEY, enrolled.key.as_bytes(), 0, owner.gid, 0o640),
        (
            CERTIFICATE,
            enrolled.certificate.as_slice(),
            owner.uid,
            owner.gid,
            0o400,
        ),
        (CONFIG, config.as_bytes(), 0, owner.gid, 0o640),
        (MANIFEST, manifest_json.as_slice(), 0, 0, 0o600),
    ];
    let mut published = Vec::new();
    let result = async {
        for (path, data, uid, gid, mode) in files {
            published.push(publish(path, data, uid, gid, mode)?);
        }
        validate_installation(owner)?;
        if !options.no_start && let Err(error) = start().await {
            if let Err(cleanup_error) = cleanup().await {
                published.clear();
                return Err(error).context(format!("credentials retained because the service could not be stopped: {cleanup_error:#}"));
            }
            return Err(error).context("start managed node; a fresh invitation is required to enroll again");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    if let Err(error) = result {
        let mut error = error;
        for file in published.into_iter().rev() {
            if let Err(cleanup_error) = fs::remove_file(&file.path) {
                error = error.context(format!(
                    "also failed to remove {}: {cleanup_error}",
                    file.name
                ));
            }
        }
        return Err(error);
    }

    let name = initial
        .peers
        .iter()
        .find(|peer| peer.node_id == enrolled.node.as_bytes())
        .map_or(options.name.as_str(), |peer| peer.name.as_str());
    println!(
        "managed Rust node installed network={network} node={} name={name} direct={direct}",
        enrolled.node
    );
    Ok(())
}

fn render(
    metadata: &bootstrap::Metadata,
    authority: &str,
    node: Id,
    relay: Id,
    endpoint: &str,
    direct: bool,
) -> Result<String> {
    let canonical = canonical_host_port(endpoint).context("invalid relay endpoint")?;
    let (host, _) = canonical
        .rsplit_once(':')
        .context("invalid relay endpoint")?;
    let host = host.trim_matches(['[', ']']);
    let mut config = json!({
        "mode": "node", "socket_path": SOCKET, "exit_intent_path": EXIT,
        "identity": {"network_id": metadata.network_id, "node_id": node.to_string()},
        "tls": {"ca": CA, "certificate": CERTIFICATE, "private_key": KEY},
        "tun": {"name": "lane0", "mtu": 1280, "configure": true},
        "relay": {"server_name": host, "service_id": relay.to_string()},
        "controller": {"endpoint": metadata.controller.enrollment_endpoint,
            "quic_endpoint": metadata.controller.quic_endpoint, "server_name": metadata.controller.server_name,
            "service_id": metadata.controller.service_id, "poll_interval": "30s", "auto_renew_certificate": true},
        "forwarding": {"exit_client": {"authorized": true, "failure_mode": "closed"}},
    });
    if direct {
        config["direct"] = json!({"listen": "0.0.0.0:0"});
    }
    let url = bootstrap::discovery_url(authority)?;
    if url.host_str().is_some_and(|domain| {
        domain
            .trim_matches(['[', ']'])
            .trim_end_matches('.')
            .eq_ignore_ascii_case(host.trim_end_matches('.'))
    }) {
        let port = url.port().unwrap_or(443);
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        config["tcp_fallback"] = json!({"address": format!("{host}:{port}")});
    }
    Ok(toml::to_string(&config)?)
}

async fn preflight() -> Result<Owner> {
    let version = option_env!("LANEWAY_PRODUCT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    for (path, flag) in [
        ("/usr/local/bin/laneway", "version"),
        ("/usr/local/sbin/lanewayd-rs", "--version"),
        (HEALTH, "--version"),
    ] {
        protected(path, true)?;
        ensure!(
            output(path, &[flag]).await? == version,
            "{path} must match Laneway {version}; install the matching release"
        );
    }
    protected("/usr/local/lib/systemd/system/lanewayd-rs.service", false)?;
    let passwd = output("/usr/bin/getent", &["passwd", "laneway"]).await?;
    let group = output("/usr/bin/getent", &["group", "laneway"]).await?;
    let groups = output("/usr/bin/id", &["-G", "laneway"]).await?;
    let fields: Vec<_> = passwd.split(':').collect();
    let names: Vec<_> = group.split(':').collect();
    let ["laneway", _, uid, gid, _, STATE, shell] = fields.as_slice() else {
        anyhow::bail!("laneway service account does not match the hardened package account");
    };
    ensure!(
        matches!(names.as_slice(), ["laneway", _, group_id, "" | "laneway"] if group_id == gid)
            && groups == *gid
            && (shell.ends_with("/nologin") || shell.ends_with("/false")),
        "laneway service account is not locked or has unexpected supplementary groups"
    );
    let owner = Owner {
        uid: uid.parse()?,
        gid: gid.parse()?,
    };
    ensure!(
        (1..1000).contains(&owner.uid) && (1..1000).contains(&owner.gid),
        "laneway service account must use system UID and GID values"
    );
    Ok(owner)
}

fn protected(path: &str, executable: bool) -> Result<()> {
    let path = Path::new(path);
    for parent in path.ancestors().skip(1) {
        protected_dir(parent, 0, None)?;
    }
    let meta = path.symlink_metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.mode() & 0o7022 == 0
            && (!executable || meta.mode() & 0o100 != 0),
        "expected a protected root-owned package file at {}",
        path.display()
    );
    Ok(())
}

fn absent(path: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {path}")),
        Ok(_) => anyhow::bail!("refusing to replace unmanaged path {path}"),
    }
}

fn protected_dir(path: &Path, uid: u32, exact: Option<(u32, u32)>) -> Result<()> {
    let meta = path.symlink_metadata()?;
    ensure!(
        meta.is_dir()
            && meta.uid() == uid
            && meta.mode() & 0o7022 == 0
            && exact.is_none_or(|(gid, mode)| meta.gid() == gid && meta.mode() & 0o777 == mode),
        "incorrect permissions or ownership on directory {}",
        path.display()
    );
    Ok(())
}

fn create_directory(path: &str, uid: u32, gid: u32, mode: u32) -> Result<()> {
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {
            chown(path, Some(uid), Some(gid))?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).with_context(|| format!("create {path}")),
    }
    // A pre-existing /etc/laneway may be root-owned with 0755 permissions.
    let exact = (path != CONFIG_DIR).then_some((gid, mode));
    protected_dir(Path::new(path), uid, exact)
}

fn verify_file(path: &str, uid: u32, gid: u32, mode: u32) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == uid
            && meta.gid() == gid
            && meta.mode() & 0o7777 == mode,
        "incorrect permissions or ownership on file {path}"
    );
    Ok(())
}

fn validate_installation(owner: Owner) -> Result<()> {
    protected_dir(Path::new(STATE), owner.uid, Some((owner.gid, 0o700)))?;
    protected_dir(Path::new(IDENTITY), owner.uid, Some((owner.gid, 0o700)))?;
    for path in [CA, KEY, CONFIG] {
        verify_file(path, 0, owner.gid, 0o640)?;
    }
    verify_file(CERTIFICATE, owner.uid, owner.gid, 0o400)?;
    verify_file(MANIFEST, 0, 0, 0o600)?;
    Agent::new(Config::load(CONFIG)?)?;
    Ok(())
}

struct Published {
    _directory: File,
    path: PathBuf,
    name: String,
}

fn publish(path: &str, bytes: &[u8], uid: u32, gid: u32, mode: u32) -> Result<Published> {
    let parent = Path::new(path)
        .parent()
        .context("missing managed file parent")?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut file = tempfile::NamedTempFile::new_in(&pinned)?;
    let target = pinned.join(
        Path::new(path)
            .file_name()
            .context("missing managed filename")?,
    );
    file.write_all(bytes)?;
    // SAFETY: the descriptor is an open file owned by this function.
    if unsafe { libc::fchown(file.as_file().as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error()).context("set managed credential owner");
    }
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&target)
        .with_context(|| format!("publish {path}"))?;
    if let Err(error) = directory.sync_all() {
        let _ = fs::remove_file(target);
        return Err(error).with_context(|| format!("sync directory for {path}"));
    }
    Ok(Published {
        _directory: directory,
        path: target,
        name: path.to_owned(),
    })
}

fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn output(program: &str, arguments: &[&str]) -> Result<String> {
    let result = timeout(
        Duration::from_secs(5),
        command(program).args(arguments).output(),
    )
    .await??;
    ensure!(
        result.status.success() && result.stdout.len() <= 4096,
        "{program} did not return valid output"
    );
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}

async fn status(program: &str, arguments: &[&str]) -> Result<bool> {
    Ok(timeout(
        Duration::from_secs(30),
        command(program).args(arguments).status(),
    )
    .await??
    .success())
}

async fn reject_legacy_service() -> Result<()> {
    for verb in ["is-active", "is-enabled"] {
        ensure!(
            !status(SYSTEMCTL, &[verb, "--quiet", LEGACY_UNIT]).await?,
            "the legacy Laneway service is active or enabled"
        );
    }
    Ok(())
}

async fn start() -> Result<()> {
    reject_legacy_service().await?;
    timeout(Duration::from_secs(45), async {
        ensure!(
            status(SYSTEMCTL, &["enable", "--now", UNIT]).await?,
            "could not enable the managed Rust service"
        );
        for _ in 0..10 {
            ensure!(
                status(SYSTEMCTL, &["is-active", "--quiet", UNIT]).await?,
                "managed Rust service stopped"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        loop {
            ensure!(
                status(SYSTEMCTL, &["is-active", "--quiet", UNIT]).await?,
                "managed Rust service stopped"
            );
            if status(HEALTH, &["-unix", SOCKET]).await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await?
}

async fn cleanup() -> Result<()> {
    let stopped = status(SYSTEMCTL, &["stop", UNIT]).await?;
    let disabled = status(SYSTEMCTL, &["disable", UNIT]).await?;
    ensure!(
        stopped && disabled,
        "could not stop and disable managed Rust service"
    );
    let _ = status(SYSTEMCTL, &["reset-failed", UNIT]).await;
    Ok(())
}
