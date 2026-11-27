use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use lanewayd_rs::Config;

#[derive(Args)]
pub(super) struct Options {
    /// Configuration file. Defaults to the managed Rust configuration if present.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Bind loopback Prometheus diagnostics.
    #[arg(long)]
    diagnostics: Option<SocketAddr>,
    /// Print the Laneway build version.
    #[arg(long)]
    version: bool,
    #[arg(long)]
    check_config: bool,
}

pub(super) fn run(options: Options) -> Result<()> {
    if options.version {
        println!("{}", crate::build_version());
        return Ok(());
    }
    let path = match options.config {
        Some(path) => path,
        None => {
            let managed = PathBuf::from("/etc/laneway/node-rust.toml");
            match managed.try_exists() {
                Ok(true) => managed,
                Ok(false) => PathBuf::from("/etc/laneway/laneway.toml"),
                Err(error) => return Err(error).context("locate managed node configuration"),
            }
        }
    };
    let mut config = match Config::load(&path) {
        Ok(config) => config,
        Err(native) => Config::load_persistent_node(&path).with_context(|| {
            format!("load persistent node configuration {} as Rust TOML ({native:#}) or legacy node TOML", path.display())
        })?,
    };
    if let Some(listen) = options.diagnostics {
        config.diagnostics.listen = Some(listen);
    }
    let agent = lanewayd_rs::Agent::new(config)?;
    if options.check_config {
        println!("configuration is valid");
        return Ok(());
    }
    crate::init_tracing();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async { agent.run_until(crate::shutdown_signal()?).await })
}
