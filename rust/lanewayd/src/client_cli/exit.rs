use std::{collections::HashSet, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use laneway_protocol::Id;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    admin::{self, Auth, Client, Connection, NodeIdentity},
    local,
};

#[derive(Subcommand)]
pub(super) enum Operation {
    /// Advertise this gateway as an exit node.
    Enable(Enable),
    /// Select a controller-authorized exit node.
    Use {
        selector: String,
        #[command(flatten)]
        local: Local,
    },
    /// Return to split-tunnel routing.
    Disable(Local),
}

#[derive(Args)]
pub(super) struct Local {
    #[arg(long, default_value = "/etc/laneway/laneway.toml")]
    config: PathBuf,
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Args)]
pub(super) struct Enable {
    #[arg(long, default_value = "/etc/laneway/laneway.toml")]
    config: PathBuf,
    #[arg(long, value_enum, default_value = "dual")]
    family: Family,
    #[arg(long, value_enum, default_value = "nat")]
    mode: Mode,
    #[arg(long, default_value_t = 0)]
    metric: u32,
    #[arg(long, default_value = "0", value_parser = admin::parse_duration)]
    valid_for: Duration,
    #[arg(long)]
    controller: Option<String>,
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(long)]
    server_name: Option<String>,
    #[arg(long)]
    controller_network_id: Option<Id>,
    #[arg(long)]
    controller_service_id: Option<Id>,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Family {
    Dual,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Nat,
    Routed,
}

pub(super) async fn run(operation: Operation) -> Result<()> {
    match operation {
        Operation::Enable(options) => enable(options).await,
        Operation::Use { selector, local } => select(local, Some(selector)).await,
        Operation::Disable(local) => select(local, None).await,
    }
}

async fn select(options: Local, selector: Option<String>) -> Result<()> {
    let client = local::client(&options.config, options.socket)?;
    let node = match selector {
        None => None,
        Some(selector) => Some(match selector.parse::<Id>() {
            Ok(id) => id,
            Err(_) => {
                let response = client
                    .get("http://localhost/v1/peers")
                    .send()
                    .await?
                    .error_for_status()?;
                let peers: Vec<Peer> =
                    serde_json::from_slice(&admin::response_body(response).await?)?;
                let mut matches = HashSet::new();
                for peer in peers.iter().filter(|peer| peer.name == selector) {
                    matches.insert(
                        peer.node_id
                            .parse::<Id>()
                            .context("invalid exit peer identity")?,
                    );
                }
                ensure!(
                    matches.len() <= 1,
                    "exit name {selector:?} is ambiguous across {} node identities",
                    matches.len()
                );
                matches
                    .into_iter()
                    .next()
                    .with_context(|| format!("no peer has the exact name {selector:?}"))?
            }
        }),
    };
    let mut body = json!({"enabled": node.is_some()});
    if let Some(node) = node {
        body["selected_node_id"] = json!(node.to_string());
    }
    let response = client
        .post("http://localhost/v1/exit")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body)?)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let value: Value = serde_json::from_slice(&admin::response_body(response).await?)?;
        anyhow::bail!(
            "local daemon returned {status}: {}",
            value["detail"].as_str().unwrap_or_default()
        );
    }
    match node {
        Some(node) => println!("selected exit node {node}"),
        None => println!("exit routing disabled"),
    }
    Ok(())
}

#[derive(Deserialize)]
struct Peer {
    #[serde(default)]
    name: String,
    node_id: String,
}

#[derive(Deserialize)]
struct Settings {
    mode: String,
    tls: ExitTls,
    controller: Controller,
    #[serde(default)]
    identity: Option<lanewayd_rs::IdentityConfig>,
    #[serde(default)]
    exit: Option<LegacyExit>,
    #[serde(default)]
    forwarding: Option<lanewayd_rs::ForwardingConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitTls {
    certificate: PathBuf,
    private_key: PathBuf,
    ca: PathBuf,
    // The legacy Docker profile pins the relay here. Route requests use the
    // controller's separate TLS name.
    #[serde(default, rename = "server_name")]
    _relay_server_name: Option<String>,
}

#[derive(Deserialize)]
struct Controller {
    endpoint: String,
    server_name: String,
    network_id: Option<String>,
    service_id: String,
}

#[derive(Deserialize)]
struct LegacyExit {
    #[serde(default)]
    serve: bool,
}

async fn enable(options: Enable) -> Result<()> {
    let input = admin::read_file(&options.config, 128 << 10)?;
    let settings: Settings = toml::from_str(std::str::from_utf8(&input)?)
        .with_context(|| format!("read Exit Node settings from {}", options.config.display()))?;
    ensure!(
        settings.mode == "node"
            && (settings.exit.is_some_and(|exit| exit.serve)
                || settings
                    .forwarding
                    .is_some_and(|forwarding| forwarding.exit_gateway)),
        "exit enable requires node mode with exit.serve=true"
    );
    let network = match settings.controller.network_id {
        Some(id) => Some(id.parse()?),
        None => settings
            .identity
            .map(|identity| identity.network_id.parse())
            .transpose()?,
    };
    let connection = Connection {
        controller: options.controller.or(Some(settings.controller.endpoint)),
        ca: options.ca.unwrap_or(settings.tls.ca),
        server_name: options
            .server_name
            .or(Some(settings.controller.server_name)),
        controller_network_id: options.controller_network_id.or(network),
        controller_service_id: options
            .controller_service_id
            .or(Some(settings.controller.service_id.parse()?)),
    };
    let identity = NodeIdentity {
        cert: options.cert.unwrap_or(settings.tls.certificate),
        key: options.key.unwrap_or(settings.tls.private_key),
    };
    let client = Client::new(connection, Auth::Node(identity))?;
    let prefixes: &[&str] = match options.family {
        Family::Dual => &["0.0.0.0/0", "::/0"],
        Family::Ipv4 => &["0.0.0.0/0"],
        Family::Ipv6 => &["::/0"],
    };
    let mode = match options.mode {
        Mode::Nat => "nat",
        Mode::Routed => "routed",
    };
    let mut advertisements = Vec::with_capacity(prefixes.len());
    for prefix in prefixes {
        let mut body =
            json!({"prefix": prefix, "kind": "exit", "mode": mode, "metric": options.metric});
        if !options.valid_for.is_zero() {
            body["valid_until_unix_seconds"] = json!(admin::deadline(options.valid_for)?);
        }
        let advertisement = client
            .request(Method::POST, "/v1/routes", Some(body))
            .await
            .with_context(|| {
                format!(
                    "advertise exit prefix {prefix} after {} successful request(s)",
                    advertisements.len()
                )
            })?;
        advertisements.push(advertisement);
    }
    admin::print_json(&json!({"advertisements": advertisements, "approval_needed": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_enable_reads_the_packaged_durable_exit_profile() -> Result<()> {
        let profile =
            include_str!("../../../../deploy/compose/generated/config/exit-node.toml.example");
        let settings: Settings = toml::from_str(profile)?;
        assert!(settings.exit.is_some_and(|exit| exit.serve));
        assert_eq!(settings.controller.server_name, "controller.example.com");
        assert_eq!(settings.tls.ca, PathBuf::from("/run/laneway-secrets/ca.crt"));
        Ok(())
    }
}
