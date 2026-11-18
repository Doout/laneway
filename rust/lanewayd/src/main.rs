use std::{env, future::Future, num::NonZeroU64, path::PathBuf};

use anyhow::{Context, Result, bail};
use lanewayd_rs::{Agent, Config};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    if matches!(
        env::args_os().nth(1).as_deref().and_then(|s| s.to_str()),
        Some("--version" | "-version")
    ) && env::args_os().nth(2).is_none()
    {
        println!(
            "{}",
            option_env!("LANEWAY_PRODUCT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }
    let arguments = arguments()?;
    #[cfg(target_os = "linux")]
    if arguments.profile == Profile::SharedHostExit {
        return shared_host_exit(arguments.check);
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(arguments))
}

async fn run(arguments: Arguments) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    if arguments.profile == Profile::WireGuard {
        #[cfg(target_os = "linux")]
        {
            let node = lanewayd_rs::WireGuardNode::new(
                Config::load(&arguments.config)?,
                arguments
                    .wireguard_key
                    .as_deref()
                    .context("missing WireGuard key")?,
                arguments.exit_generation,
            )?;
            if arguments.check {
                println!("configuration is valid");
                return Ok(());
            }
            return node.run_until(shutdown_signal()?).await;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (arguments.wireguard_key, arguments.exit_generation);
            bail!("native WireGuard requires Linux");
        }
    }
    let config = match arguments.profile {
        Profile::Connector => Config::load_connector_state(&arguments.config)?,
        Profile::ExitGateway => Config::load_exit_config(&arguments.config)?,
        Profile::Native => Config::load(&arguments.config)?,
        Profile::WireGuard => unreachable!("handled before selecting the raw agent"),
        Profile::SharedHostExit => bail!("the shared-host Exit requires Linux"),
    };
    let agent = Agent::new(config)?;
    if arguments.check {
        println!("configuration is valid");
        return Ok(());
    }
    agent.run_until(shutdown_signal()?).await
}

#[cfg(target_os = "linux")]
fn shared_host_exit(check: bool) -> Result<()> {
    let path: PathBuf = env::var_os("CREDENTIALS_DIRECTORY")
        .context("missing systemd credentials directory")?
        .into();
    lanewayd_rs::SharedHostExit::harden_process()?;
    let keys: Vec<_> = env::vars_os().map(|(key, _)| key).collect();
    // SAFETY: main is still single-threaded; the Tokio runtime and tracing
    // subscriber have not been constructed. No environment readers run here.
    unsafe {
        for key in keys {
            env::remove_var(key);
        }
        env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    }
    let node = lanewayd_rs::SharedHostExit::load(&path)?;
    if check {
        println!("configuration is valid");
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(async { node.run_until(shutdown_signal()?).await })
}

#[cfg(unix)]
fn shutdown_signal() -> Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

#[cfg(not(unix))]
fn shutdown_signal() -> Result<impl Future<Output = ()>> {
    Ok(async {
        tokio::signal::ctrl_c()
            .await
            .expect("install shutdown signal handler");
    })
}

struct Arguments {
    config: PathBuf,
    profile: Profile,
    check: bool,
    wireguard_key: Option<PathBuf>,
    exit_generation: Option<NonZeroU64>,
}

#[derive(Debug, PartialEq, Eq)]
enum Profile {
    Native,
    Connector,
    ExitGateway,
    WireGuard,
    SharedHostExit,
}

fn arguments() -> Result<Arguments> {
    parse_arguments(env::args_os())
}

fn parse_arguments(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Arguments> {
    let mut arguments = arguments.into_iter();
    let binary = arguments.next().unwrap_or_default();
    let Some(argument) = arguments.next() else {
        bail!(
            "usage: {} (--config PATH | --connector-state DIR | --exit-config PATH | --wireguard-config PATH --wireguard-key PATH [--exit-generation N] | --shared-host-exit) [--check-config]",
            PathBuf::from(binary).display()
        );
    };
    let profile = match argument.to_str() {
        Some("--config") => Profile::Native,
        Some("--connector-state") => Profile::Connector,
        Some("--exit-config") => Profile::ExitGateway,
        Some("--wireguard-config") => Profile::WireGuard,
        Some("--shared-host-exit") => Profile::SharedHostExit,
        _ => bail!("unknown configuration profile"),
    };
    let path = if profile == Profile::SharedHostExit {
        PathBuf::new()
    } else {
        arguments
            .next()
            .context("configuration path or state directory is required")?
            .into()
    };
    let mut check = false;
    let mut wireguard_key = None;
    let mut exit_generation = None;
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--check-config") if !check => check = true,
            Some("--wireguard-key") if profile == Profile::WireGuard && wireguard_key.is_none() => {
                wireguard_key = Some(
                    arguments
                        .next()
                        .context("WireGuard key path is required")?
                        .into(),
                );
            }
            Some("--exit-generation")
                if profile == Profile::WireGuard && exit_generation.is_none() =>
            {
                let value = arguments.next().context("exit generation is required")?;
                exit_generation = Some(
                    value
                        .to_str()
                        .context("exit generation is not UTF-8")?
                        .parse()
                        .context("exit generation must be a nonzero integer")?,
                );
            }
            _ => bail!("unexpected argument {argument:?}"),
        }
    }
    if profile == Profile::WireGuard && wireguard_key.is_none() {
        bail!("--wireguard-config requires --wireguard-key");
    }
    Ok(Arguments {
        config: path,
        profile,
        check,
        wireguard_key,
        exit_generation,
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
        let wg = parse_arguments(
            [
                "lanewayd-rs",
                "--wireguard-config",
                "/tmp/node.toml",
                "--wireguard-key",
                "/tmp/wg.key",
                "--exit-generation",
                "8",
                "--check-config",
            ]
            .map(Into::into),
        )
        .unwrap();
        assert_eq!(wg.profile, Profile::WireGuard);
        assert_eq!(wg.exit_generation, NonZeroU64::new(8));
        assert!(
            parse_arguments(
                ["lanewayd-rs", "--wireguard-config", "/tmp/node.toml"].map(Into::into)
            )
            .is_err()
        );
        assert!(
            parse_arguments(
                [
                    "lanewayd-rs",
                    "--config",
                    "/tmp/node.toml",
                    "--exit-generation",
                    "8"
                ]
                .map(Into::into)
            )
            .is_err()
        );
        assert!(parse_arguments(["lanewayd-rs".into(), "--check-config".into()]).is_err());
    }
}
