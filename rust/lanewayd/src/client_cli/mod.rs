//! Native implementations used by the packaged Laneway CLI.
mod admin;
#[cfg(target_os = "linux")]
mod administrator;
mod bootstrap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod connect;
#[cfg(target_os = "linux")]
mod connector;
#[cfg(target_os = "linux")]
mod control;
mod enrollment;
#[cfg(target_os = "linux")]
mod ephemeral_exit;
#[cfg(target_os = "linux")]
mod exit;
mod inventory;
#[cfg(unix)]
mod join;
#[cfg(target_os = "linux")]
mod legacy;
#[cfg(unix)]
mod local;
#[cfg(target_os = "macos")]
pub(crate) mod macos_setup;
#[cfg(target_os = "linux")]
mod managed_install;
#[cfg(target_os = "linux")]
mod node_run;
#[cfg(unix)]
mod pki;
mod profiles;
#[cfg(target_os = "linux")]
mod renew;

use std::{ffi::OsString, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "laneway",
    disable_version_flag = true,
    after_help = "Rootless: configure, start, credential. Maintenance: update, version."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect bootstrap metadata or download a verified release artifact.
    Bootstrap {
        #[command(subcommand)]
        operation: bootstrap::Operation,
    },
    /// Activate and run an unprivileged Connector.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    Connector {
        #[command(subcommand)]
        operation: connector::Operation,
    },
    #[cfg(unix)]
    /// Create and verify Laneway identities.
    Pki {
        #[command(subcommand)]
        operation: pki::Operation,
    },
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    InstallNode(managed_install::Options),
    #[cfg(target_os = "linux")]
    #[command(subcommand)]
    /// Install, operate, and inspect this host.
    Node(NodeCommand),
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    UninstallNode(managed_install::Uninstall),
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    RenewNode,
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    EphemeralExitPrepare(ephemeral_exit::Options),
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    RunNode(node_run::Options),
    #[cfg(target_os = "linux")]
    #[command(subcommand)]
    Exit(exit::Operation),
    #[cfg(target_os = "linux")]
    #[command(hide = true, subcommand)]
    Config(legacy::Config),
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    Invite(legacy::Invite),
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    Renew(renew::Options),
    #[cfg(target_os = "linux")]
    /// Operate the installed Docker Compose control plane.
    Control {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    /// Manage controller resources.
    Controller {
        #[command(flatten)]
        connection: admin::Connection,
        #[command(subcommand)]
        operation: admin::Operation,
    },
    #[cfg(unix)]
    #[command(visible_alias = "up")]
    /// Show local node and transport status.
    Status(local::Options),
    #[cfg(unix)]
    /// List peers known to the local node.
    Peers(local::Options),
    #[cfg(unix)]
    /// List routes installed by the local node.
    Routes(local::Options),
    #[cfg(unix)]
    /// Enroll a node with a controller.
    Join(join::Options),
    #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
    #[command(hide = true)]
    EnrollExit(join::Options),
    /// Generate a random Laneway ID.
    Id,
    /// Save a renewable user login.
    Login {
        domain: String,
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    /// Connect using a saved login or an ephemeral invitation.
    Connect(connect::Options),
    /// Remove a saved user login.
    Logout { domain: String },
    #[command(hide = true)]
    SubmitEnrollment,
    #[command(hide = true)]
    Discover { domain: String },
}

#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum NodeCommand {
    /// Enroll and install a managed node.
    Install(managed_install::Options),
    /// Run the configured persistent node.
    Run(node_run::Options),
    /// Check certificate renewal for a managed node.
    Renew,
    /// Remove command-owned node state.
    Uninstall(managed_install::Uninstall),
    #[command(hide = true)]
    EphemeralExitPrepare(ephemeral_exit::Options),
    #[command(subcommand)]
    Exit(exit::Operation),
    #[command(visible_alias = "up")]
    Status(local::Options),
    Peers(local::Options),
    Routes(local::Options),
}

#[cfg(target_os = "linux")]
fn run_node(command: NodeCommand) -> Result<()> {
    match command {
        NodeCommand::Install(options) => runtime()?.block_on(managed_install::run(options)),
        NodeCommand::Run(options) => node_run::run(options),
        NodeCommand::Renew => managed_install::renew(),
        NodeCommand::Uninstall(options) => runtime()?.block_on(managed_install::uninstall(options)),
        NodeCommand::EphemeralExitPrepare(options) => ephemeral_exit::run(options),
        NodeCommand::Exit(operation) => runtime()?.block_on(exit::run(operation)),
        NodeCommand::Status(options) => {
            runtime()?.block_on(local::run(local::Query::Status, options))
        }
        NodeCommand::Peers(options) => {
            runtime()?.block_on(local::run(local::Query::Peers, options))
        }
        NodeCommand::Routes(options) => {
            runtime()?.block_on(local::run(local::Query::Routes, options))
        }
    }
}

pub(crate) fn run(args: impl Iterator<Item = OsString>) -> Result<()> {
    let cli = match Cli::try_parse_from(std::iter::once("laneway".into()).chain(args)) {
        Ok(cli) => cli,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            error.print()?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    match cli.command {
        #[cfg(unix)]
        Command::Status(options) => runtime()?.block_on(local::run(local::Query::Status, options)),
        #[cfg(unix)]
        Command::Peers(options) => runtime()?.block_on(local::run(local::Query::Peers, options)),
        #[cfg(unix)]
        Command::Routes(options) => runtime()?.block_on(local::run(local::Query::Routes, options)),
        #[cfg(unix)]
        Command::Join(options) => runtime()?.block_on(join::run(
            options,
            laneway_protocol::v1::EnrollmentClass::DurableNode,
        )),
        #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
        Command::EnrollExit(options) => runtime()?.block_on(join::run(
            options,
            laneway_protocol::v1::EnrollmentClass::EphemeralUser,
        )),
        Command::Id => {
            let mut bytes = [0; laneway_protocol::ID_LEN];
            loop {
                getrandom::fill(&mut bytes).context("generate Laneway ID")?;
                if let Ok(id) = laneway_protocol::Id::new(bytes) {
                    println!("{id}");
                    return Ok(());
                }
            }
        }
        #[cfg(target_os = "linux")]
        Command::Connector { operation } => runtime()?.block_on(connector::run(operation)),
        #[cfg(unix)]
        Command::Pki { operation } => pki::run(operation),
        #[cfg(target_os = "linux")]
        Command::InstallNode(options) => run_node(NodeCommand::Install(options)),
        #[cfg(target_os = "linux")]
        Command::Node(operation) => run_node(operation),
        #[cfg(target_os = "linux")]
        Command::UninstallNode(options) => run_node(NodeCommand::Uninstall(options)),
        #[cfg(target_os = "linux")]
        Command::RenewNode => run_node(NodeCommand::Renew),
        #[cfg(target_os = "linux")]
        Command::EphemeralExitPrepare(options) => ephemeral_exit::run(options),
        #[cfg(target_os = "linux")]
        Command::RunNode(options) => node_run::run(options),
        #[cfg(target_os = "linux")]
        Command::Exit(operation) => runtime()?.block_on(exit::run(operation)),
        #[cfg(target_os = "linux")]
        Command::Config(command) => legacy::config(command),
        #[cfg(target_os = "linux")]
        Command::Invite(options) => runtime()?.block_on(legacy::invite(options)),
        #[cfg(target_os = "linux")]
        Command::Renew(options) => runtime()?.block_on(renew::run(options)),
        #[cfg(target_os = "linux")]
        Command::Control { arguments } => control::run(&arguments),
        Command::Controller {
            connection,
            operation,
        } => runtime()?.block_on(admin::run(connection, operation)),
        Command::Bootstrap { operation } => runtime()?.block_on(bootstrap::run(operation)),
        Command::Login { domain, token_file } => {
            runtime()?.block_on(enrollment::login(&domain, token_file.as_deref()))
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Connect(options) => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(connect::run(options)),
        Command::Logout { domain } => profiles::Store::from_environment().logout(&domain),
        Command::SubmitEnrollment => runtime()?.block_on(enrollment::run()),
        Command::Discover { domain } => runtime()?.block_on(bootstrap::discover(&domain)),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

#[cfg(target_os = "macos")]
pub(crate) fn run_installed(args: Vec<OsString>) -> Result<()> {
    match args.as_slice() {
        [command, rest @ ..] if command == "configure" => {
            let mut system = false;
            let mut forwarded = Vec::new();
            let mut value_next = false;
            for arg in rest {
                if std::mem::take(&mut value_next) {
                    forwarded.push(arg.clone());
                    continue;
                }
                match arg.to_str() {
                    Some("--system" | "-system" | "--system=true" | "-system=true") => {
                        system = true
                    }
                    Some("--check" | "-check") => {
                        system = true;
                        forwarded.push("--check".into());
                    }
                    Some("--yes" | "-yes") => {
                        system = true;
                        forwarded.push("--yes".into());
                    }
                    Some("--state-dir" | "-state-dir") => {
                        forwarded.push(arg.clone());
                        value_next = true;
                    }
                    _ => forwarded.push(arg.clone()),
                }
            }
            if system {
                return macos_setup::run(std::env::current_exe()?, forwarded.into_iter());
            }
            crate::rootless_cli::run(&args)
        }
        [command, rest @ ..] if command == "connect" => {
            if !rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                macos_setup::verify_installed_client()?;
            }
            run_legacy_flags(args)
        }
        [command, rest @ ..] if command == "update" => {
            macos_setup::update(std::env::current_exe()?, rest, false)
        }
        [command, rest @ ..] if command == "_network-helper" => laneway_network_helper::run(rest),
        [command, ..] if matches!(command.to_str(), Some("start" | "credential")) => {
            crate::rootless_cli::run(&args)
        }
        _ => run_legacy_flags(args),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn run_installed(mut args: Vec<OsString>) -> Result<()> {
    match args.as_slice() {
        [] => return run(std::iter::once("--help".into())),
        [command, server, ..] if command == "configure" && server == "server" => {
            anyhow::bail!(
                "download the official release install.sh and run it on the Linux server with sudo env LANEWAY_DOMAIN=YOUR_DOMAIN sh install.sh"
            );
        }
        [command, rest @ ..] if command == "_network-helper" => {
            return laneway_network_helper::run(rest);
        }
        [command, ..] if command == "connect" && laneway_private::is_root() => {
            prepare_linux_environment(&[
                "HOME",
                "XDG_CONFIG_HOME",
                "LANEWAY_PROFILE_DIR",
                "TMPDIR",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
            ]);
        }
        [command, rest @ ..]
            if matches!(command.to_str(), Some("configure" | "start" | "credential")) =>
        {
            if command != "credential"
                && rest.iter().any(|arg| arg == "--system")
                && laneway_private::is_root()
            {
                prepare_linux_environment(&[]);
            }
            return crate::rootless_cli::run(&args);
        }
        [command, rest @ ..] if command == "update" => {
            return lanewayd_rs::deployment_update::update_client_command(
                &std::env::current_exe()?,
                rest,
            );
        }
        [command, ..] if command == "route" => args.insert(0, "controller".into()),
        [command, route, ..] if command == "node" && route == "route" => {
            args[0] = "controller".into();
        }
        _ => (),
    }
    run_legacy_flags(args)
}

#[cfg(target_os = "linux")]
fn prepare_linux_environment(keep: &[&str]) {
    use std::env;

    let keys: Vec<_> = env::vars_os().map(|(key, _)| key).collect();
    // SAFETY: installed command dispatch is single-threaded and runs before
    // constructing Tokio or starting DNS and network workers.
    unsafe {
        for key in keys {
            if !key.to_str().is_some_and(|key| keep.contains(&key)) {
                env::remove_var(key);
            }
        }
        env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        env::set_var("LANG", "C");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_legacy_flags(mut args: Vec<OsString>) -> Result<()> {
    use clap::CommandFactory;

    let mut cli = Cli::command();
    cli.build();
    let mut command = &cli;
    let mut value_next = false;
    for arg in &mut args {
        if std::mem::take(&mut value_next) {
            continue;
        }
        let Some(text) = arg.to_str() else {
            continue;
        };
        if text == "--" {
            break;
        }
        if let Some(subcommand) = command.get_subcommands().find(|item| {
            item.get_name() == text || item.get_all_aliases().any(|alias| alias == text)
        }) {
            command = subcommand;
        } else if let Some(flag) = text.strip_prefix('-') {
            let legacy = !flag.starts_with('-');
            let flag = flag.strip_prefix('-').unwrap_or(flag);
            let (name, inline_value) = flag.split_once('=').unwrap_or((flag, ""));
            if let Some(option) = command
                .get_arguments()
                .find(|arg| arg.get_long() == Some(name))
            {
                value_next = inline_value.is_empty()
                    && !flag.contains('=')
                    && option.get_action().takes_values()
                    && !option.is_require_equals_set();
                if legacy {
                    *arg = format!("--{flag}").into();
                }
            }
        }
    }
    run(args.into_iter())
}
