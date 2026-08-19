use std::{env, path::PathBuf};

use anyhow::{Context, Result, bail};
use laneway_relay::{Config, Server};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static ALLOCATOR: laneway_relay::allocator::CountingAllocator =
    laneway_relay::allocator::CountingAllocator::new();

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let arguments = parse_args()?;
    let config = Config::load(&arguments.config)?;
    if arguments.check {
        println!("configuration is valid");
        return Ok(());
    }
    let server = Server::bind(config)?;
    info!(
        quic = %server.local_addr()?,
        tcp_fallback = ?server.tcp_fallback_addr()?,
        metrics = ?server.metrics_addr()?,
        "laneway Rust relay listening"
    );
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
    check: bool,
}

fn parse_args() -> Result<Arguments> {
    parse_arguments(env::args_os().skip(1))
}

fn parse_arguments(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Arguments> {
    let mut args = arguments.into_iter();
    let mut config = PathBuf::from("/etc/laneway/laneway.toml");
    let mut check = false;
    while let Some(argument) = args.next() {
        if argument == "--config" || argument == "-config" {
            config = args.next().context("--config requires a path")?.into();
        } else if argument == "-h" || argument == "--help" {
            println!("laneway-relay [--config PATH] [--check-config]");
            std::process::exit(0);
        } else if argument == "--check-config" {
            check = true;
        } else {
            bail!("unknown argument {argument:?}");
        }
    }
    Ok(Arguments { config, check })
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
}
