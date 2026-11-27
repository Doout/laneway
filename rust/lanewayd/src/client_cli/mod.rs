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
mod inventory;
#[cfg(unix)]
mod join;
#[cfg(unix)]
mod local;
#[cfg(target_os = "macos")]
pub(crate) mod macos_setup;
#[cfg(target_os = "linux")]
mod managed_install;
#[cfg(unix)]
mod pki;
mod profiles;

use std::{ffi::OsString, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "laneway", disable_version_flag = true)]
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
    #[command(hide = true)]
    UninstallNode(managed_install::Uninstall),
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    RenewNode,
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
        Command::Join(options) => runtime()?.block_on(join::run(options)),
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
        Command::InstallNode(options) => runtime()?.block_on(managed_install::run(options)),
        #[cfg(target_os = "linux")]
        Command::UninstallNode(options) => runtime()?.block_on(managed_install::uninstall(options)),
        #[cfg(target_os = "linux")]
        Command::RenewNode => managed_install::renew(),
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

#[cfg(target_os = "linux")]
pub(crate) fn run_installed(mut args: Vec<OsString>) -> Result<()> {
    use clap::CommandFactory;

    match args.as_slice() {
        [] => return run(std::iter::once("--help".into())),
        [command, server, ..] if command == "configure" && server == "server" => {
            anyhow::bail!(
                "download the official release install.sh and run it on the Linux server with sudo env LANEWAY_DOMAIN=YOUR_DOMAIN sh install.sh"
            );
        }
        [command, ..] if matches!(command.to_str(), Some("configure" | "start" | "credential")) => {
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
        [command, install, ..] if command == "node" && install == "install" => {
            args.remove(0);
            args[0] = "install-node".into();
        }
        [command, uninstall, ..] if command == "node" && uninstall == "uninstall" => {
            args.remove(0);
            args[0] = "uninstall-node".into();
        }
        [command, renew, ..] if command == "node" && renew == "renew" => {
            args.remove(0);
            args[0] = "renew-node".into();
        }
        [command, local, ..]
            if command == "node"
                && matches!(local.to_str(), Some("status" | "up" | "peers" | "routes")) =>
        {
            args.remove(0);
        }
        _ => (),
    }
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
        if let Some(subcommand) = command.find_subcommand(text) {
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
