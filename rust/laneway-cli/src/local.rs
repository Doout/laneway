//! Operate the local daemon through its Linux management socket.
pub(crate) mod exit;
use std::{
    ffi::{OsStr, OsString},
    io::{Read, Write},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{StatusCode, blocking::Client};
use serde::{Serialize, de::DeserializeOwned};

use crate::node::{parse_bool, split_flag};

const MAX_RESPONSE: usize = 1 << 20;

pub(crate) fn command(args: &[OsString]) -> Option<&str> {
    let first = args.first()?.to_str()?;
    let leaf = if first == "node" {
        args.get(1)?.to_str()?
    } else {
        first
    };
    matches!(leaf, "status" | "up" | "peers" | "routes").then_some(leaf)
}

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let command = command(args).context("missing local node command")?;
    let nested = args[0] == OsStr::new("node");
    let invocation = if nested {
        format!("node {command}")
    } else {
        command.to_owned()
    };
    let usage = format!("laneway {invocation} [-config path | -socket path] [-json]");
    let mut positional = args[if nested { 2 } else { 1 }..].iter();
    let mut socket = None;
    let mut config = PathBuf::from("/etc/laneway/laneway.toml");
    let mut json = false;
    while let Some(arg) = positional.next() {
        let (name, value) = split_flag(arg);
        if name == "--" && value.is_none() {
            ensure!(positional.len() == 0, "usage: {usage}");
            break;
        }
        let name = name
            .strip_prefix("--")
            .or_else(|| name.strip_prefix('-'))
            .filter(|name| !name.is_empty())
            .with_context(|| format!("usage: {usage}"))?;
        match name {
            "h" | "help" => {
                println!(
                    "Usage: {usage}\n\n  -config path   Configuration file (default /etc/laneway/laneway.toml)\n  -socket path   Unix socket, bypassing configuration loading\n  -json          Emit JSON"
                );
                return Ok(());
            }
            "config" | "socket" => {
                let value = value
                    .or_else(|| positional.next().cloned())
                    .with_context(|| format!("flag needs an argument: -{name}"))?;
                if name == "socket" {
                    socket = (!value.is_empty()).then_some(value);
                } else {
                    config = value.into();
                }
            }
            "json" => {
                json = parse_bool(value.as_deref()).context("invalid boolean value for -json")?;
            }
            _ => bail!("flag provided but not defined: -{name}"),
        }
    }
    let client = local_client(socket, &config)?;
    let mut output = std::io::stdout().lock();
    match command {
        "status" | "up" => {
            let value = read::<Option<Status>>(&client, "status")?.unwrap_or_default();
            if json {
                print_json(&mut output, &value)
            } else {
                value.print(&mut output)
            }
        }
        "peers" => {
            let value = read::<Option<Vec<Peer>>>(&client, "peers")?;
            if json {
                return print_json(&mut output, &value);
            }
            for peer in value.into_iter().flatten() {
                if !peer.name.is_empty() {
                    write!(output, "{}\t", peer.name)?;
                }
                writeln!(
                    output,
                    "{}\t{}\t{}",
                    peer.node_id,
                    peer.path,
                    join(&peer.prefixes)
                )?;
            }
            Ok(())
        }
        "routes" => {
            let value = read::<Option<Vec<Route>>>(&client, "routes")?;
            if json {
                return print_json(&mut output, &value);
            }
            for route in value.into_iter().flatten() {
                writeln!(
                    output,
                    "{}\tvia {}\t{}",
                    route.prefix, route.via_node, route.kind
                )?;
            }
            Ok(())
        }
        _ => unreachable!("local command allowlist"),
    }
}

fn local_client(socket: Option<OsString>, config: &std::path::Path) -> Result<Client> {
    let socket = match socket {
        Some(path) => path,
        None => laneway_config::Config::load(config)?
            .local_socket()
            .as_os_str()
            .to_owned(),
    };
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .unix_socket(socket_path(socket))
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .context("create local API client")
}

fn socket_path(value: OsString) -> PathBuf {
    let mut bytes = value.into_vec();
    // Go's Unix dialer recognizes @ as the Linux abstract namespace prefix.
    if let Some(prefix @ b'@') = bytes.first_mut() {
        *prefix = 0;
    }
    PathBuf::from(OsString::from_vec(bytes))
}

fn read<T: DeserializeOwned>(client: &Client, endpoint: &str) -> Result<T> {
    let response = client
        .get(format!("http://lanewayd/v1/{endpoint}"))
        .send()
        .context("contact lanewayd")?;
    let status = response.status();
    if status != StatusCode::OK {
        bail!("lanewayd returned {status}");
    }
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_RESPONSE as u64),
        "lanewayd response is oversized"
    );
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut body)
        .context("read lanewayd response")?;
    ensure!(body.len() <= MAX_RESPONSE, "lanewayd response is oversized");
    serde_json::from_slice(&body).context("decode lanewayd response")
}

fn print_json(mut output: impl Write, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    // Go's JSON encoder escapes HTML entities and JavaScript line separators.
    let mut written = 0;
    for (index, character) in json.char_indices() {
        let escape = match character {
            '&' => "\\u0026",
            '<' => "\\u003c",
            '>' => "\\u003e",
            '\u{2028}' => "\\u2028",
            '\u{2029}' => "\\u2029",
            _ => continue,
        };
        output.write_all(&json.as_bytes()[written..index])?;
        output.write_all(escape.as_bytes())?;
        written = index + character.len_utf8();
    }
    writeln!(output, "{}", &json[written..])?;
    Ok(())
}

fn join(items: &Option<Vec<String>>) -> String {
    items.as_deref().unwrap_or_default().join(",")
}

#[derive(Default, serde::Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Status {
    running: bool,
    actor: String,
    product_version: String,
    control_version: String,
    packet_version: u8,
    capabilities: String,
    selected_path: String,
    network_id: String,
    node_id: String,
    name: String,
    overlay_addresses: Option<Vec<String>>,
    selected_routes: Option<Vec<String>>,
    interface: String,
    relay: String,
    mtu: isize,
    metrics: Metrics,
    exit: ExitStatus,
    controller: ControllerStatus,
}

impl Status {
    fn print(&self, mut output: impl Write) -> Result<()> {
        let actor = if self.actor.is_empty() {
            "node"
        } else {
            &self.actor
        };
        writeln!(
            output,
            "actor={} node={} name={} network={} overlay={} interface={} mtu={} relay={} running={}",
            actor,
            self.node_id,
            self.name,
            self.network_id,
            join(&self.overlay_addresses),
            self.interface,
            self.mtu,
            self.relay,
            self.running
        )?;
        writeln!(
            output,
            "version={} control={} packet={} capabilities={} path={}",
            self.product_version,
            self.control_version,
            self.packet_version,
            self.capabilities,
            self.selected_path
        )?;
        writeln!(output, "selected_routes={}", join(&self.selected_routes))?;
        let metrics = &self.metrics;
        writeln!(
            output,
            "connections={} reconnects={} sent={} received={} dropped={}",
            metrics.connections,
            metrics.reconnects,
            metrics.packets_sent,
            metrics.packets_received,
            metrics.packets_dropped
        )?;
        writeln!(
            output,
            "tcp_connections={} quic_failures={} tcp_failures={}",
            metrics.tcp_connections, metrics.quic_failures, metrics.tcp_failures
        )?;
        let controller = &self.controller;
        if controller.certificate_not_after_unix_seconds != 0
            || controller.identity_lease_expires_at_unix_seconds != 0
            || controller.configuration_lease_valid_until_unix_seconds != 0
        {
            writeln!(
                output,
                "controller_candidate_exchange={} configuration_lease_valid_until={} configuration_lease_expired={} certificate_renewal_needed={} certificate_renew_after={} certificate_not_after={} identity_lease_expires_at={}",
                controller.candidate_exchange_enabled,
                controller.configuration_lease_valid_until_unix_seconds,
                controller.configuration_lease_expired,
                controller.certificate_renewal_needed,
                controller.certificate_renew_after_unix_seconds,
                controller.certificate_not_after_unix_seconds,
                controller.identity_lease_expires_at_unix_seconds
            )?;
        }
        let exit = &self.exit;
        if exit.enabled || exit.serving {
            writeln!(
                output,
                "exit={} authorized={} serving={} forwarding_ready={} nat_ready={} forwarded_packets={} namespace_cleanup_failures={}",
                exit.selected_node_id,
                exit.authorized,
                exit.serving,
                exit.forwarding_ready,
                exit.nat_ready,
                exit.forwarded_packets,
                exit.namespace_cleanup_failures
            )?;
        }
        Ok(())
    }
}

#[derive(Default, serde::Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Metrics {
    connections: u64,
    reconnects: u64,
    packets_sent: u64,
    packets_received: u64,
    packets_dropped: u64,
    tcp_connections: u64,
    quic_failures: u64,
    tcp_failures: u64,
}

#[derive(Default, serde::Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct ExitStatus {
    enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    selected_node_id: String,
    authorized: bool,
    serving: bool,
    forwarding_ready: bool,
    nat_ready: bool,
    forwarded_packets: u64,
    namespace_cleanup_failures: u64,
}

#[derive(Default, serde::Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct ControllerStatus {
    candidate_exchange_enabled: bool,
    certificate_presented_serial: String,
    certificate_renewal_needed: bool,
    certificate_renew_after_unix_seconds: u64,
    certificate_not_after_unix_seconds: u64,
    identity_lease_expires_at_unix_seconds: u64,
    configuration_lease_valid_until_unix_seconds: u64,
    configuration_lease_expired: bool,
}

#[derive(Default, serde::Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Peer {
    node_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    prefixes: Option<Vec<String>>,
    path: String,
}

#[derive(Default, serde::Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Route {
    prefix: String,
    via_node: String,
    kind: String,
}
