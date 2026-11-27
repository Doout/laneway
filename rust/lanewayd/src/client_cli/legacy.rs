//! Compatibility commands for configuration files already on disk.
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use laneway_protocol::{Id, Role, identity_from_certificate_der};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::admin::{self, Auth, Bearer, Client, Connection};

#[derive(Subcommand)]
pub(super) enum Config {
    Validate {
        #[arg(long, default_value = "/etc/laneway/laneway.toml")]
        config: PathBuf,
    },
    InspectControllerInitialNetwork {
        #[arg(long, default_value = "/etc/laneway/controller.toml")]
        config: PathBuf,
    },
}

pub(super) fn config(command: Config) -> Result<()> {
    match command {
        Config::Validate { config } => {
            match lanewayd_rs::Config::load(&config) {
                Ok(_) => (),
                Err(native) => {
                    let input = read(&config)?;
                    let kind: Kind = toml::from_str(&input)?;
                    match kind.mode.as_str() {
                        "controller" => {
                            let _ = inspect(&input)?;
                        }
                        "node" => {
                            lanewayd_rs::Config::load_persistent_node(&config)
                                .context(format!("validate native or controller-backed node configuration ({native:#})"))?;
                        }
                        _ => return Err(native),
                    }
                }
            }
            println!("configuration is valid");
            Ok(())
        }
        Config::InspectControllerInitialNetwork { config } => {
            admin::print_json(&serde_json::to_value(inspect(&read(&config)?)?)?)
        }
    }
}

fn read(path: &Path) -> Result<String> {
    Ok(String::from_utf8(admin::read_file(path, 256 << 10)?)?)
}

#[derive(Deserialize)]
struct Kind {
    mode: String,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct InitialNetwork {
    #[serde(skip_serializing_if = "String::is_empty")]
    network_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ipv4_pool: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ipv6_pool: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Settings {
    mode: String,
    tls: Tls,
    controller: Controller,
    bootstrap: Bootstrap,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Tls {
    ca: PathBuf,
    certificate: PathBuf,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Controller {
    listen: String,
    admin_token_file: PathBuf,
    initial_network: InitialNetwork,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Bootstrap {
    listen: String,
    network_id: String,
    controller_endpoint: String,
    controller_server_name: String,
}

#[derive(Serialize)]
struct Inspection {
    configured: bool,
    #[serde(flatten)]
    initial: InitialNetwork,
    #[serde(skip_serializing_if = "String::is_empty")]
    bootstrap_network_id: String,
}

fn inspect(input: &str) -> Result<Inspection> {
    let settings: Settings = toml::from_str(input)?;
    ensure!(
        settings.mode == "controller",
        "expected a controller configuration"
    );
    let initial = settings.controller.initial_network;
    let configured = !initial.network_id.is_empty();
    if configured {
        let _ = initial.network_id.parse::<Id>()?;
        let ipv4 = initial.ipv4_pool.parse::<ipnet::Ipv4Net>()?;
        ensure!(
            !initial.name.trim().is_empty() && ipv4 == ipv4.trunc(),
            "invalid initial network name or IPv4 pool"
        );
        if !initial.ipv6_pool.is_empty() {
            let ipv6 = initial.ipv6_pool.parse::<ipnet::Ipv6Net>()?;
            ensure!(ipv6 == ipv6.trunc(), "invalid initial IPv6 pool");
        }
    }
    Ok(Inspection {
        configured,
        initial,
        bootstrap_network_id: settings.bootstrap.network_id,
    })
}

#[derive(Args)]
pub(super) struct Invite {
    #[arg(long, default_value = "/etc/laneway/controller.toml")]
    config: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long, conflicts_with = "remembered")]
    ephemeral: bool,
    #[arg(long)]
    remembered: bool,
    #[arg(long, default_value = "10m", value_parser = admin::parse_duration)]
    expires_in: Duration,
    #[arg(long, requires = "ephemeral", value_parser = admin::parse_duration)]
    session_lifetime: Option<Duration>,
    #[arg(long)]
    json: bool,
}

pub(super) async fn invite(options: Invite) -> Result<()> {
    ensure!(
        !options.name.trim().is_empty()
            && !options.expires_in.is_zero()
            && options.expires_in <= Duration::from_secs(3600),
        "invite requires a name and a positive expiry of at most one hour"
    );
    let settings: Settings = toml::from_str(&read(&options.config)?)?;
    ensure!(
        settings.mode == "controller" && !settings.bootstrap.listen.is_empty(),
        "invite requires a controller configuration with public bootstrap enabled"
    );
    let network = settings.bootstrap.network_id.parse::<Id>()?;
    let chain_bytes = admin::read_file(&settings.tls.certificate, 1 << 20)?;
    let certs = crate::rootless_cli::enroll::certificates(&chain_bytes)?;
    let leaf = certs.first().context("missing controller certificate")?;
    let identity = identity_from_certificate_der(leaf.as_ref())?;
    ensure!(
        identity.network_id == network && identity.role == Role::Controller,
        "bootstrap and controller certificate identities do not match"
    );
    let endpoint =
        crate::rootless_cli::enroll::https_origin(&settings.bootstrap.controller_endpoint)?;
    let dial = settings
        .controller
        .listen
        .rsplit_once(':')
        .and_then(|(host, port)| {
            let port = port.parse::<u16>().ok()?;
            let host = host.trim_matches(['[', ']']);
            let ip = if host.is_empty() {
                "127.0.0.1".parse().ok()?
            } else {
                host.parse::<IpAddr>().ok()?
            };
            let ip = if ip.is_unspecified() {
                IpAddr::from([127, 0, 0, 1])
            } else {
                ip
            };
            Some(std::net::SocketAddr::new(ip, port))
        });
    let connection = Connection {
        controller: Some(endpoint.to_string()),
        ca: settings.tls.ca,
        server_name: Some(settings.bootstrap.controller_server_name),
        controller_network_id: Some(network),
        controller_service_id: Some(identity.subject_id),
    };
    let client = Client::with_dial_address(
        connection,
        Auth::Bearer(Bearer {
            admin_token_file: settings.controller.admin_token_file,
        }),
        dial,
    )?;
    let class = if options.ephemeral {
        "ephemeral"
    } else if options.remembered {
        "remembered"
    } else {
        "durable"
    };
    let mut body = json!({
        "network_id": network.to_string(),
        "label": options.name,
        "requested_name": options.name,
        "enrollment_class": class,
        "expires_at_unix_seconds": admin::deadline(options.expires_in)?,
    });
    if options.ephemeral {
        body["session_lifetime_seconds"] = json!(
            options
                .session_lifetime
                .unwrap_or(Duration::from_secs(8 * 3600))
                .as_secs()
        );
    }
    let response = client
        .request(
            reqwest::Method::POST,
            "/v1/admin/enrollment-tokens",
            Some(body),
        )
        .await?;
    if options.json {
        admin::print_json(&response)
    } else {
        let code = response["enrollment_token"]
            .as_str()
            .context("controller returned no invitation")?;
        eprintln!("Single-use {class} invite for {}:", options.name);
        println!("{code}");
        Ok(())
    }
}
