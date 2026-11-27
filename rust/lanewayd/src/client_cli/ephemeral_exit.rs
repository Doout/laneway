//! Stage the transient Exit service's credentials on tmpfs.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use laneway_protocol::{Id, relay_endpoint::canonical_host_port, v1::EnrollmentClass};
use lanewayd_rs::TlsConfig;
use serde_json::json;
use zeroize::Zeroizing;

use super::{bootstrap, enrollment::RedeemTarget};

#[derive(Args)]
pub(super) struct Options {
    #[arg(long)]
    authority: String,
    #[arg(long)]
    runtime_dir: PathBuf,
    #[arg(long)]
    runtime_name: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    token_fd: RawFd,
}

pub(super) fn run(options: Options) -> Result<()> {
    let suffix = options
        .runtime_name
        .strip_prefix("laneway-ephemeral-exit-")
        .context("invalid ephemeral Exit runtime name")?;
    ensure!(
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            && options.runtime_dir.as_os_str()
                == Path::new("/run").join(&options.runtime_name).as_os_str()
            && !options.name.is_empty()
            && options.name.trim() == options.name
            && options.name.len() <= 253
            && options.token_fd >= 3,
        "invalid ephemeral Exit preparation invocation"
    );
    ensure!(
        laneway_private::is_root(),
        "ephemeral Exit preparation requires root"
    );
    let directory = open_runtime(&options.runtime_dir)?;
    harden()?;
    let invitation = read_invitation(options.token_fd)?;
    super::runtime()?.block_on(prepare(options, &directory, invitation))
}

fn open_runtime(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .context("open ephemeral Exit runtime")?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.mode() & 0o7777 == 0o700
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() == 2,
        "ephemeral Exit runtime directory must be private and root-owned"
    );
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs writes to stat and initializes it only on success.
    let filesystem = unsafe {
        syscall(libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()))?;
        stat.assume_init().f_type as u32
    };
    ensure!(
        filesystem == libc::TMPFS_MAGIC as u32,
        "ephemeral Exit runtime directory must be on tmpfs"
    );
    Ok(directory)
}

fn harden() -> Result<()> {
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let lock = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: These syscalls change only this process. Limit pointers are
    // valid for the calls, which run before reading the token or starting Tokio.
    unsafe {
        syscall(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0))
            .context("disable Exit preparation dumps")?;
        syscall(libc::setrlimit(libc::RLIMIT_CORE, &core))
            .context("disable Exit preparation core files")?;
        syscall(libc::setrlimit(libc::RLIMIT_MEMLOCK, &lock))
            .context("raise Exit preparation lock limit")?;
        syscall(libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE))
            .context("lock Exit preparation memory")
    }
}

fn syscall(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_invitation(fd: RawFd) -> Result<Zeroizing<String>> {
    // SAFETY: This command exclusively receives the descriptor from the
    // bootstrap process. F_GETFD validates that it is still open.
    let file = unsafe {
        syscall(libc::fcntl(fd, libc::F_GETFD)).context("invitation descriptor is unavailable")?;
        File::from_raw_fd(fd)
    };
    let mut contents = Zeroizing::new(Vec::with_capacity(129));
    file.take(129).read_to_end(&mut contents)?;
    ensure!(contents.len() <= 128, "Exit invitation is too long");
    let code = std::str::from_utf8(&contents)?.trim();
    ensure!(
        !code.is_empty()
            && code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "invitation has an invalid shape"
    );
    Ok(Zeroizing::new(code.to_owned()))
}

async fn prepare(options: Options, directory: &File, invitation: Zeroizing<String>) -> Result<()> {
    let metadata = bootstrap::fetch(&options.authority).await?;
    let network = metadata.network_id.parse::<Id>()?;
    let enrollment = RedeemTarget {
        endpoint: &metadata.controller.enrollment_endpoint,
        ca: metadata.trust.ca_pem.as_bytes(),
        server_name: &metadata.controller.server_name,
        network,
        service: metadata.controller.service_id.parse()?,
    }
    .redeem(&invitation, &options.name, EnrollmentClass::EphemeralUser)
    .await?;
    drop(invitation);
    let generation = enrollment
        .exit_generation
        .context("controller returned no bounded ephemeral Exit lease")?;
    ensure!(
        generation.get() <= i64::MAX as u64,
        "invalid Exit lease generation"
    );

    let mut staged = Credentials {
        path: PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())),
        written: Vec::new(),
    };
    let tls = TlsConfig {
        ca: staged.write("ca.crt", metadata.trust.ca_pem.as_bytes())?,
        certificate: staged.write("node.crt", &enrollment.certificate)?,
        private_key: staged.write("node.key", enrollment.key.as_bytes())?,
    };
    staged.write("wireguard.key", enrollment.wireguard.as_ref())?;
    let initial = tokio::time::timeout(
        Duration::from_secs(15),
        lanewayd_rs::rootless::get_exit_configuration(
            &metadata.controller.config(),
            network,
            enrollment.node,
            &tls,
            generation,
        ),
    )
    .await
    .context("fetch initial ephemeral Exit configuration")??;
    let relay = initial
        .relays
        .iter()
        .min_by(|a, b| (&a.service_id, &a.endpoint).cmp(&(&b.service_id, &b.endpoint)))
        .context("controller authorized no ephemeral Exit relay")?;
    let relay_id = Id::from_slice(&relay.service_id)?;
    let address =
        canonical_host_port(&relay.endpoint).context("invalid controller relay endpoint")?;
    let name = initial
        .peers
        .iter()
        .find(|peer| peer.node_id == enrollment.node.as_bytes())
        .map_or(options.name.as_str(), |peer| peer.name.as_str());
    let config = toml::to_string(&json!({
        "mode": "node",
        "state_dir": options.runtime_dir.join("state"),
        "socket_path": options.runtime_dir.join("lanewayd.sock"),
        "tls": {
            "ca": "@credential/ca.crt",
            "certificate": "@credential/node.crt",
            "private_key": "@credential/node.key",
            "server_name": "",
        },
        "node": {
            "name": name,
            "relay_address": address,
            "relay_network_id": network.to_string(),
            "relay_service_id": relay_id.to_string(),
            "reconnect_min": "1s",
            "reconnect_max": "10s",
        },
        "controller": {
            "endpoint": metadata.controller.enrollment_endpoint,
            "quic_endpoint": metadata.controller.quic_endpoint,
            "server_name": metadata.controller.server_name,
            "network_id": network.to_string(),
            "service_id": metadata.controller.service_id,
            "poll_interval": "10s",
        },
        "direct": { "enabled": false },
        "exit": { "serve": true, "failure_mode": "closed", "lease_generation": generation.get() },
        "wireguard": { "enabled": true, "private_key": "@credential/wireguard.key", "interface": "lane0", "mtu": 1280 },
        "routing": { "output_interface": "uplink0" },
    }))?;
    staged.write("laneway.toml", config.as_bytes())?;

    let mut output = io::stdout().lock();
    serde_json::to_writer(
        &mut output,
        &json!({
            "runtime_name": options.runtime_name,
            "node_id": enrollment.node.to_string(),
            "network_id": network.to_string(),
            "config": options.runtime_dir.join("laneway.toml"),
            "ca": options.runtime_dir.join("ca.crt"),
            "certificate": options.runtime_dir.join("node.crt"),
            "private_key": options.runtime_dir.join("node.key"),
            "expires_at_unix_seconds": enrollment.lease_expires,
        }),
    )?;
    writeln!(output)?;
    staged.written.clear();
    Ok(())
}

struct Credentials {
    path: PathBuf,
    written: Vec<&'static str>,
}

impl Credentials {
    fn write(&mut self, name: &'static str, contents: &[u8]) -> Result<PathBuf> {
        let path = self.path.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
            .with_context(|| format!("create transient Exit credential {name}"))?;
        self.written.push(name);
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(path)
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        for name in &self.written {
            if let Err(error) = fs::remove_file(self.path.join(name)) {
                eprintln!("could not remove transient Exit credential {name}: {error}");
            }
        }
    }
}
