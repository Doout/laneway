use std::{env, path::PathBuf};

use anyhow::{Context, Result, bail};
use lanewayd_rs::{Agent, Config};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let arguments = arguments()?;
    let config = match arguments.profile {
        Profile::Connector => Config::load_connector_state(&arguments.config)?,
        Profile::ExitGateway => Config::load_exit_config(&arguments.config)?,
        Profile::Native => Config::load(&arguments.config)?,
    };
    let agent = Agent::new(config)?;
    if arguments.check {
        println!("configuration is valid");
        return Ok(());
    }
    agent.run_until(shutdown_signal()).await
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("install shutdown signal handler");
}

struct Arguments {
    config: PathBuf,
    profile: Profile,
    check: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Profile {
    Native,
    Connector,
    ExitGateway,
}

fn arguments() -> Result<Arguments> {
    parse_arguments(env::args_os())
}

fn parse_arguments(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Arguments> {
    let mut arguments = arguments.into_iter();
    let binary = arguments.next().unwrap_or_default();
    let Some(argument) = arguments.next() else {
        bail!(
            "usage: {} (--config PATH | --connector-state DIR | --exit-config PATH) [--check-config]",
            PathBuf::from(binary).display()
        );
    };
    let profile = match argument.to_str() {
        Some("--config") => Profile::Native,
        Some("--connector-state") => Profile::Connector,
        Some("--exit-config") => Profile::ExitGateway,
        _ => bail!("first argument must be --config, --connector-state, or --exit-config"),
    };
    let path = arguments
        .next()
        .context("configuration path or state directory is required")?;
    let mut check = false;
    for argument in arguments {
        if argument == "--check-config" {
            check = true;
        } else {
            bail!("unexpected argument {argument:?}");
        }
    }
    Ok(Arguments {
        config: path.into(),
        profile,
        check,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_side_effect_free_config_check() {
        let parsed = parse_arguments([
            "lanewayd-rs".into(),
            "--config".into(),
            "/tmp/node.toml".into(),
            "--check-config".into(),
        ])
        .unwrap();
        assert_eq!(parsed.config, PathBuf::from("/tmp/node.toml"));
        assert_eq!(parsed.profile, Profile::Native);
        assert!(parsed.check);
        let exit = parse_arguments([
            "lanewayd-rs".into(),
            "--exit-config".into(),
            "/etc/laneway/exit-node.toml".into(),
            "--check-config".into(),
        ])
        .unwrap();
        assert_eq!(exit.profile, Profile::ExitGateway);
        assert!(parse_arguments(["lanewayd-rs".into(), "--check-config".into()]).is_err());
    }
}
