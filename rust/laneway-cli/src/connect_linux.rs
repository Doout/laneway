use std::{
    fs,
    future::Future,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use lanewayd_rs::{
    Agent, ConfigurationFilter, ExitFailureMode, SessionStatus, rootless::TransportOptions,
};

use crate::connect::SessionOptions;

mod network_helper;

const RUNTIME: &str = "/run/laneway-connect";
const CAP_NET_ADMIN: u64 = 1 << 12;

/// The ordinary-user helper only owns split-tunnel routes. Retain the
/// companion for closed-mode Exit until native policy refresh is verified.
pub(crate) fn eligible(exit_requested: bool, failure_mode: &str) -> bool {
    eligible_with_privileges(exit_requested, failure_mode, root())
}

fn eligible_with_privileges(exit_requested: bool, failure_mode: &str, privileged: bool) -> bool {
    !exit_requested || (privileged && failure_mode == "open")
}

pub(crate) fn preflight() -> Result<()> {
    if !root() {
        network_helper::Helper::locate()?;
        return Ok(());
    }
    let status =
        fs::read_to_string("/proc/self/status").context("read Linux network privileges")?;
    let capabilities = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .context("missing Linux effective capabilities")?;
    ensure!(
        u64::from_str_radix(capabilities.trim(), 16)? & CAP_NET_ADMIN != 0,
        "native Linux connect requires CAP_NET_ADMIN"
    );
    let tun = fs::metadata("/dev/net/tun").context("open Linux TUN device metadata")?;
    ensure!(
        tun.file_type().is_char_device(),
        "/dev/net/tun must be a character device"
    );
    system_tool("ip")?;
    Ok(())
}

fn root() -> bool {
    nix::unistd::geteuid().is_root()
}

pub(crate) async fn run(
    options: TransportOptions,
    session: &SessionOptions,
    filter: ConfigurationFilter,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    ensure!(
        eligible(session.selected_exit.is_some(), &session.failure_mode),
        "this Exit session requires the installed compatibility dataplane"
    );
    let runtime = Path::new(RUNTIME);
    let _lock = if root() {
        laneway_private::ensure_directory(runtime).context("open protected Linux session state")?;
        Some(
            laneway_private::try_lock(&runtime.join("network.lock"))
                .context("another native Laneway connection is configuring this host")?,
        )
    } else {
        None
    };
    laneway_private::check_directory(&session.runtime_dir)
        .context("open private session credential directory")?;

    let network = options.network;
    let node = options.node;
    let mut config = options.system_config(&session.runtime_dir)?;
    config.socket_path = session.runtime_dir.join("laneway.sock");
    if root() {
        config.forwarding.ip_command = system_tool("ip")?;
    }
    config.forwarding.dns_state_file = runtime.join("dns-state.json");
    config.forwarding.subnet_table = "laneway_connect_subnet".into();
    config.forwarding.exit_table = "laneway_connect_exit".into();
    let interface = config.tun.name.clone();
    ensure!(
        !Path::new("/sys/class/net").join(&interface).try_exists()?,
        "network interface {interface} is already in use"
    );
    let selected_exit = session.selected_exit;
    let failure_mode = session.failure_mode.clone();
    let requested_routes =
        (!session.requested_routes.is_empty()).then(|| list(&session.requested_routes));
    let bypasses = list(&session.local_lan);
    let dns_owner = if session.dns.is_empty() {
        "native"
    } else {
        "temporary-session"
    };
    if let Some(exit) = selected_exit {
        let exit_client = &mut config.forwarding.exit_client;
        exit_client.enabled = true;
        exit_client.authorized = true;
        exit_client.selected_node = Some(exit.to_string());
        exit_client.failure_mode = match failure_mode.as_str() {
            "open" => ExitFailureMode::Open,
            "closed" => ExitFailureMode::Closed,
            _ => bail!("invalid exit failure mode"),
        };
        exit_client.dns_servers.clone_from(&session.dns);
        exit_client.local_lan_bypass.clone_from(&session.local_lan);
        config.forwarding.nft_command = system_tool("nft")?;
        if !session.dns.is_empty() {
            config.forwarding.resolvectl_command = system_tool("resolvectl")?;
        }
    }

    let mut agent = Agent::new(config)?.with_configuration_filter(filter)?;
    let journal = if root() {
        "native-active"
    } else {
        agent = agent.with_session_network(network_helper::Helper::locate()?)?;
        "helper-active"
    };
    agent.with_session_status(move |status: SessionStatus| {
            let lease = match status.identity_lease_expires_at {
                0 => "durable".into(),
                expires => expires.to_string(),
            };
            let selection = if let Some(exit) = selected_exit {
                format!("exit={exit} failure-mode={failure_mode}")
            } else if let Some(requested) = &requested_routes {
                format!("routes={requested}")
            } else if status.owned_routes.is_empty() {
                "overlay-only".into()
            } else {
                "authorized-private-routes".into()
            };
            println!(
                "laneway connected actor=user network={network} node={node} name={} overlay={} identity_lease_expires_at={lease} interface={interface} selection={selection} owned_routes={} bypasses={bypasses} dns_owner={dns_owner} cleanup_journal={journal} path={}",
                status.name,
                list(&status.overlays),
                list(&status.owned_routes),
                status.path
            );
        })
        .run_until(shutdown)
        .await
}

fn list<T: ToString>(values: &[T]) -> String {
    if values.is_empty() {
        return "none".into();
    }
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn system_tool(name: &str) -> Result<String> {
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let candidate = PathBuf::from(directory).join(name);
        let path = match fs::canonicalize(candidate) {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("resolve the installed network command"),
        };
        ensure!(
            crate::compat::trusted_executable(&path),
            "network command is not protected: {}",
            path.display()
        );
        return path
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow::anyhow!("installed network command path is not UTF-8"));
    }
    bail!("required Linux network command {name} is unavailable")
}

#[cfg(test)]
mod tests {
    use super::eligible_with_privileges;

    #[test]
    fn closed_exit_stays_on_the_compatibility_dataplane() {
        for privileged in [false, true] {
            assert!(eligible_with_privileges(false, "closed", privileged));
            assert!(eligible_with_privileges(false, "open", privileged));
            assert!(!eligible_with_privileges(true, "closed", privileged));
        }
        assert!(eligible_with_privileges(true, "open", true));
        assert!(!eligible_with_privileges(true, "open", false));
    }
}
