use anyhow::{Context, Result, bail, ensure};
use laneway_config::Config;
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::path::Path;

const USAGE: &str =
    "usage: laneway config <validate|inspect-controller-initial-network> [-config path]";

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let (command, rest) = args.split_first().context(USAGE)?;
    let (inspect, default) = match command.to_str() {
        Some("validate") => (false, "/etc/laneway/laneway.toml"),
        Some("inspect-controller-initial-network") => (true, "/etc/laneway/controller.toml"),
        Some("-h" | "--help") => {
            println!("{USAGE}");
            return Ok(());
        }
        _ => bail!("{USAGE}"),
    };
    let mut path = OsStr::new(default);
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        match arg.to_str() {
            Some("-config" | "--config") => {
                path = rest.next().context("-config requires a path")?
            }
            Some("-h" | "--help") => {
                println!("{USAGE}");
                return Ok(());
            }
            Some("--") => {
                ensure!(!inspect || rest.next().is_none(), "{USAGE}");
                break;
            }
            Some(flag) if flag.starts_with("-config=") || flag.starts_with("--config=") => {
                path = OsStr::new(flag.split_once('=').expect("flag prefix includes equals").1);
            }
            Some(flag) if flag.starts_with('-') && flag != "-" => {
                bail!("unknown configuration option {flag}")
            }
            _ if inspect => bail!("{USAGE}"),
            // Go config validate stops parsing when it meets a positional.
            _ => break,
        }
    }
    let config = Config::load(Path::new(path))?;
    if !inspect {
        println!("configuration is valid");
        return Ok(());
    }
    ensure!(
        config.mode == "controller",
        "configuration mode is {:?}, want \"controller\"",
        config.mode
    );
    let initial = &config.controller.initial_network;
    let response = InitialNetworkInspection {
        configured: !initial.network_id.is_empty(),
        network_id: &initial.network_id,
        name: &initial.name,
        ipv4_pool: &initial.ipv4_pool,
        ipv6_pool: &initial.ipv6_pool,
        bootstrap_network_id: &config.bootstrap.network_id,
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

#[derive(Serialize)]
struct InitialNetworkInspection<'a> {
    configured: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    network_id: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    ipv4_pool: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    ipv6_pool: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    bootstrap_network_id: &'a str,
}
