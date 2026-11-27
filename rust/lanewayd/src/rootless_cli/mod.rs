#![deny(unsafe_code)]

mod credentials;
pub(crate) mod enroll;
mod forward;
use laneway_private as private;
mod proxy;
mod runtime;
mod setup;
mod stack;
mod system;
use lanewayd_rs::rootless as transport;

use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, IsTerminal, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};

const VERSION: &str = match option_env!("LANEWAY_PRODUCT_VERSION") {
    Some(version) => version,
    None => match option_env!("LANEWAY_NODE_RELEASE_VERSION") {
        Some(version) => version,
        None => env!("CARGO_PKG_VERSION"),
    },
};

#[derive(Parser)]
#[command(name = "lanewayd", version = VERSION, about = "Laneway userspace node")]
struct Cli {
    /// Private directory for the node identity and proxy credentials.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Redeem a single-use invitation read from standard input.
    Enroll {
        /// Store the invitation identity for Linux system networking.
        #[arg(long)]
        system: bool,
    },
    /// Configure this node using an existing identity or a single-use invitation.
    Configure {
        /// Configure the node for Linux system networking.
        #[arg(long)]
        system: bool,
        /// Abandon an interrupted enrollment without changing an existing identity.
        #[arg(long)]
        discard_pending: bool,
    },
    /// Run authenticated SOCKS5 and userspace subnet forwarding.
    #[command(visible_alias = "start")]
    Run(RunOptions),
    /// Manage local proxy credentials.
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
}

#[derive(Args, Default)]
struct RunOptions {
    /// Loopback socket for authenticated SOCKS5 clients (default 127.0.0.1:1080).
    #[arg(long, value_parser = loopback, conflicts_with = "system")]
    listen: Option<SocketAddr>,
    /// Serve assigned routes with the local SOCKS5 listener disabled.
    #[arg(long, conflicts_with_all = ["listen", "system"])]
    no_proxy: bool,
    /// Originate proxy flows only, even if the controller assigns a local subnet.
    #[arg(long, conflicts_with_all = ["no_proxy", "system"])]
    proxy_only: bool,
    /// Run with Linux system networking.
    #[arg(long)]
    system: bool,
    /// Load an explicit system node configuration instead of the enrolled identity.
    #[arg(long, requires = "system")]
    config: Option<PathBuf>,
    /// Validate system configuration and credentials, then exit.
    #[arg(long, requires = "system")]
    check_config: bool,
}

#[derive(Subcommand)]
enum CredentialCommand {
    /// Create a named credential. Prints a generated key once by default.
    Add {
        name: String,
        /// Read a chosen password from standard input.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Revoke a credential and disconnect its sessions.
    Remove { name: String },
    /// Print credential names.
    List,
}

fn loopback(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value.parse().map_err(|_| "expected IP:port")?;
    if !address.ip().is_loopback() {
        return Err("proxy listener must use an IPv4 or IPv6 loopback address".into());
    }
    Ok(address)
}

fn default_state_dir() -> Result<PathBuf> {
    let home = || {
        env::var_os("HOME")
            .map(PathBuf::from)
            .context("set --state-dir or HOME")
    };
    let base = if cfg!(windows) {
        PathBuf::from(env::var_os("LOCALAPPDATA").context("set --state-dir or LOCALAPPDATA")?)
    } else if cfg!(target_os = "macos") {
        home()?.join("Library/Application Support")
    } else if let Some(base) = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        base
    } else {
        home()?.join(".local/state")
    };
    Ok(base.join("laneway/rootless"))
}

fn secret(label: &str, limit: usize) -> Result<String> {
    let value = if io::stdin().is_terminal() {
        rpassword::prompt_password(format!("{label}: "))?
    } else {
        let mut bytes = Vec::new();
        io::stdin().take(limit as u64 + 3).read_to_end(&mut bytes)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        String::from_utf8(bytes).context("input must be UTF-8")?
    };
    ensure!(
        !value.is_empty() && value.len() <= limit && !value.contains(['\r', '\n']),
        "expected one bounded, nonempty input line"
    );
    Ok(value)
}

fn prepare_directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "--state-dir must be absolute");
    let parent = path.parent().context("state directory requires a parent")?;
    fs::create_dir_all(parent)?;
    private::ensure_directory(path).context("opening private Laneway state directory")
}

#[cfg(unix)]
async fn shutdown_signal() -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
use tokio::signal::ctrl_c as shutdown_signal;

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let cli = match Cli::try_parse_from(
        std::iter::once(OsString::from("lanewayd")).chain(args.iter().cloned()),
    ) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run_cli(cli))
}

async fn run_cli(cli: Cli) -> Result<()> {
    let command = cli
        .command
        .unwrap_or_else(|| Command::Run(RunOptions::default()));
    let system_mode = match &command {
        Command::Enroll { system } | Command::Configure { system, .. } => *system,
        Command::Run(options) => options.system,
        Command::Credential { .. } => false,
    };
    if system_mode {
        ensure!(
            cli.state_dir.is_none(),
            "--state-dir is only used in userspace mode"
        );
    }
    if let Command::Run(RunOptions {
        config: Some(path),
        check_config,
        ..
    }) = &command
    {
        return system::run_explicit(path, *check_config).await;
    }
    let state = if system_mode {
        system::state_dir()?
    } else {
        match cli.state_dir {
            Some(path) => path,
            None => default_state_dir()?,
        }
    };
    prepare_directory(&state)?;
    let database = state.join("credentials.json");
    match command {
        Command::Enroll { .. } => {
            let _lock = private::try_lock(&state.join("node.lock"))
                .context("state directory already in use")?;
            enroll::clean_staged_tls(&state)?;
            let token = secret("Single-use invitation", enroll::MAX_SETUP_TOKEN)?;
            let identity = enroll::activate(&state, &token).await?;
            println!("Enrolled {} ({})", identity.name, identity.node_id);
        }
        Command::Configure {
            discard_pending: true,
            ..
        } => {
            enroll::discard_pending_enrollment(&state)?;
        }
        Command::Configure {
            discard_pending: false,
            ..
        } => {
            setup::configure(&state, system_mode).await?;
        }
        Command::Run(options) if system_mode => {
            system::run_enrolled(&state, options.check_config).await?
        }
        Command::Run(RunOptions {
            listen,
            no_proxy,
            proxy_only,
            ..
        }) => {
            let _lock = private::try_lock(&state.join("node.lock"))
                .context("another node is using this state directory")?;
            enroll::clean_staged_tls(&state)?;
            let identity = enroll::Identity::load(&state)
                .context("load node identity; enroll before running")?;
            enroll::discard_completed_enrollment(&state);
            let listen = listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 1080)));
            tokio::select! {
                result = runtime::run(identity, database, (!no_proxy).then_some(listen), !proxy_only) => result?,
                signal = shutdown_signal() => signal?,
            }
        }
        Command::Credential { command } => match command {
            CredentialCommand::Add {
                name,
                password_stdin,
            } => {
                if password_stdin {
                    let password = secret("Proxy password", 255)?;
                    credentials::add(&database, &name, &password)?;
                } else {
                    println!("{}", credentials::add_generated(&database, &name)?);
                }
            }
            CredentialCommand::Remove { name } => credentials::remove(&database, &name)?,
            CredentialCommand::List => {
                for name in credentials::list(&database)? {
                    println!("{name}");
                }
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_is_local_and_optional() {
        for addr in ["0.0.0.0:1080", "[::]:1080", "192.0.2.1:1080"] {
            assert!(Cli::try_parse_from(["node", "run", "--listen", addr]).is_err());
        }
        assert!(Cli::try_parse_from(["node", "run", "--no-proxy"]).is_ok());
        assert!(Cli::try_parse_from(["node", "run", "--proxy-only", "--no-proxy"]).is_err());
        assert!(Cli::try_parse_from(["node", "run", "--listen", "[::1]:1080"]).is_ok());
    }

    #[test]
    fn starts_by_default_and_accepts_both_start_spellings() {
        assert!(Cli::try_parse_from(["lanewayd"]).unwrap().command.is_none());
        for verb in ["start", "run"] {
            let cli =
                Cli::try_parse_from(["lanewayd", verb, "--state-dir", "/tmp/node", "--proxy-only"])
                    .unwrap();
            assert!(matches!(
                cli.command,
                Some(Command::Run(RunOptions {
                    proxy_only: true,
                    ..
                }))
            ));
            assert_eq!(cli.state_dir, Some(PathBuf::from("/tmp/node")));
            assert!(Cli::try_parse_from(["lanewayd", verb, "--system"]).is_ok());
            assert!(Cli::try_parse_from(["lanewayd", verb, "--system", "--proxy-only"]).is_err());
            assert!(Cli::try_parse_from(["lanewayd", verb, "--config", "node.toml"]).is_err());
            assert!(
                Cli::try_parse_from([
                    "lanewayd",
                    verb,
                    "--system",
                    "--config",
                    "node.toml",
                    "--check-config"
                ])
                .is_ok()
            );
        }
    }
}
