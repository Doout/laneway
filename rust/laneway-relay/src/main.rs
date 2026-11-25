#![forbid(unsafe_code)]

use std::{env, path::PathBuf};

use anyhow::{Context, Result, bail};
use laneway_relay::{Config, Server};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static ALLOCATOR: laneway_relay::allocator::CountingAllocator =
    laneway_relay::allocator::CountingAllocator::new();

const VERSION: &str = match option_env!("LANEWAY_RELAY_RELEASE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let arguments = parse_args()?;
    if arguments.version {
        println!("{VERSION}");
        return Ok(());
    }
    let mut config = Config::load(&arguments.config)?;
    if let Some(diagnostics) = arguments.diagnostics {
        config.relay.metrics_listen = diagnostics;
        config.metrics_listen_addr()?;
    }
    if arguments.check {
        println!("configuration is valid");
        return Ok(());
    }
    let server = Server::bind(config)?;
    let metrics = server.metrics();
    server.serve_until(shutdown_signal()).await?;
    info!(snapshot = ?metrics.snapshot(), "laneway Rust relay stopped");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.expect("install Ctrl-C handler"),
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install Ctrl-C handler");
}

struct Arguments {
    config: PathBuf,
    diagnostics: Option<String>,
    check: bool,
    version: bool,
}

fn parse_args() -> Result<Arguments> {
    parse_arguments(env::args_os().skip(1))
}

fn parse_arguments(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Arguments> {
    let mut args = arguments.into_iter();
    let mut config = PathBuf::from("/etc/laneway/laneway.toml");
    let mut diagnostics = None;
    let mut check = false;
    let mut version = false;
    while let Some(argument) = args.next() {
        if argument == "update" || argument == "configure" {
            bail!(
                "the deployment host manages this relay; on the host run sudo laneway {} server",
                argument.to_string_lossy()
            );
        }
        if argument == "--config" || argument == "-config" {
            config = args.next().context("--config requires a path")?.into();
        } else if let Some(value) = argument.to_str().and_then(|value| {
            value
                .strip_prefix("--config=")
                .or_else(|| value.strip_prefix("-config="))
        }) {
            config = value.into();
        } else if argument == "--diagnostics" || argument == "-diagnostics" {
            diagnostics = Some(
                args.next()
                    .context("--diagnostics requires an address")?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("--diagnostics address must be UTF-8"))?,
            );
        } else if let Some(value) = argument.to_str().and_then(|value| {
            value
                .strip_prefix("--diagnostics=")
                .or_else(|| value.strip_prefix("-diagnostics="))
        }) {
            diagnostics = Some(value.into());
        } else if argument == "-h" || argument == "--help" || argument == "-help" {
            println!(
                "laneway-relay [--config PATH] [--diagnostics ADDRESS] [--check-config] [--version]"
            );
            std::process::exit(0);
        } else if argument == "--version" || argument == "-version" {
            version = true;
        } else if argument == "--check-config" || argument == "-check-config" {
            check = true;
        } else {
            bail!("unknown argument {:?}", argument);
        }
    }
    Ok(Arguments {
        config,
        diagnostics,
        check,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_side_effect_free_config_check() {
        let parsed = parse_arguments([
            "--config".into(),
            "/tmp/relay.toml".into(),
            "--check-config".into(),
        ])
        .unwrap();
        assert_eq!(parsed.config, PathBuf::from("/tmp/relay.toml"));
        assert!(parsed.check);
    }

    #[test]
    fn accepts_existing_relay_flags() {
        let parsed = parse_arguments([
            "-config=/tmp/relay.toml".into(),
            "-diagnostics=localhost:6060".into(),
            "-version".into(),
            "-check-config".into(),
        ])
        .unwrap();
        assert_eq!(parsed.config, PathBuf::from("/tmp/relay.toml"));
        assert_eq!(parsed.diagnostics.as_deref(), Some("localhost:6060"));
        assert!(parsed.version);
        assert!(parsed.check);
    }
}
