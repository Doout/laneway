//! Native implementations used by the packaged Laneway CLI.
mod bootstrap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod connect;
mod enrollment;
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
    Profile {
        #[command(subcommand)]
        operation: profiles::Operation,
    },
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
        Command::Profile { operation } => runtime()?.block_on(profiles::run(operation)),
        Command::SubmitEnrollment => runtime()?.block_on(enrollment::run()),
        Command::Discover { domain } => runtime()?.block_on(bootstrap::discover(&domain)),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
