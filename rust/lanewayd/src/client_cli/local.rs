use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{ArgAction, Args};
use serde::Deserialize;
use serde_json::Value;

use super::admin::{print_json, read_file, response_body};

#[derive(Args)]
pub(super) struct Options {
    #[arg(long, default_value = "/etc/laneway/laneway.toml")]
    config: PathBuf,
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
    json: bool,
}

pub(super) enum Query {
    Status,
    Peers,
    Routes,
}

#[derive(Deserialize)]
struct SocketConfig {
    #[serde(default = "default_socket")]
    socket_path: PathBuf,
}

fn default_socket() -> PathBuf {
    "/run/laneway/lanewayd.sock".into()
}

pub(super) async fn run(query: Query, options: Options) -> Result<()> {
    let client = client(&options.config, options.socket)?;
    let resource = match query {
        Query::Status => "status",
        Query::Peers => "peers",
        Query::Routes => "routes",
    };
    let response = client
        .get(format!("http://localhost/v1/{resource}"))
        .send()
        .await
        .context("request local daemon")?;
    let status = response.status();
    let value: Value = serde_json::from_slice(&response_body(response).await?)?;
    ensure!(
        status.is_success(),
        "local daemon returned {status}: {}",
        text(&value, "detail")
    );
    if options.json {
        return print_json(&value);
    }

    let mut output = io::stdout().lock();
    match query {
        Query::Status => print_status(&mut output, &value)?,
        Query::Peers => {
            for peer in value.as_array().into_iter().flatten() {
                let name = text(peer, "name");
                if !name.is_empty() {
                    write!(output, "{name}\t")?;
                }
                writeln!(
                    output,
                    "{}\t{}\t{}",
                    text(peer, "node_id"),
                    text(peer, "path"),
                    list(&peer["prefixes"])
                )?;
            }
        }
        Query::Routes => {
            for route in value.as_array().into_iter().flatten() {
                writeln!(
                    output,
                    "{}\tvia {}\t{}",
                    text(route, "prefix"),
                    text(route, "via_node"),
                    text(route, "kind")
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn client(config: &std::path::Path, socket: Option<PathBuf>) -> Result<reqwest::Client> {
    let socket = if let Some(socket) = socket {
        socket
    } else {
        match read_file(config, 128 << 10) {
            Ok(path) => toml::from_str::<SocketConfig>(std::str::from_utf8(&path)?)?.socket_path,
            Err(error)
                if config == std::path::Path::new("/etc/laneway/laneway.toml")
                    && error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                default_socket()
            }
            Err(error) => return Err(error),
        }
    };
    ensure!(socket.is_absolute(), "local socket path must be absolute");
    Ok(reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?)
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn list(value: &Value) -> String {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn print_status(output: &mut impl Write, status: &Value) -> io::Result<()> {
    let get = |key: &str| text(status, key);
    let actor = status["actor"]
        .as_str()
        .filter(|name| !name.is_empty())
        .unwrap_or("node");
    let packet = status["packet_version"].as_u64().unwrap_or_default();
    let running = status["running"].as_bool().unwrap_or_default();
    writeln!(
        output,
        "actor={actor} node={} name={} network={} overlay={} interface={} mtu={} relay={} running={running}",
        get("node_id"),
        get("name"),
        get("network_id"),
        list(&status["overlay_addresses"]),
        get("interface"),
        status["mtu"].as_u64().unwrap_or_default(),
        get("relay")
    )?;
    writeln!(
        output,
        "version={} control={} packet={packet} capabilities={} path={}",
        get("product_version"),
        get("control_version"),
        get("capabilities"),
        get("selected_path")
    )?;
    writeln!(
        output,
        "selected_routes={}",
        list(&status["selected_routes"])
    )?;
    let metrics = |key: &str| status["metrics"][key].as_u64().unwrap_or_default();
    writeln!(
        output,
        "connections={} reconnects={} sent={} received={} dropped={}",
        metrics("connections"),
        metrics("reconnects"),
        metrics("packets_sent"),
        metrics("packets_received"),
        metrics("packets_dropped")
    )?;
    writeln!(
        output,
        "tcp_connections={} quic_failures={} tcp_failures={}",
        metrics("tcp_connections"),
        metrics("quic_failures"),
        metrics("tcp_failures")
    )?;
    let controller = &status["controller"];
    let number = |key: &str| controller[key].as_u64().unwrap_or_default();
    let flag = |key: &str| controller[key].as_bool().unwrap_or_default();
    let certificate = number("certificate_not_after_unix_seconds");
    let lease = number("identity_lease_expires_at_unix_seconds");
    let configuration = number("configuration_lease_valid_until_unix_seconds");
    if certificate != 0 || lease != 0 || configuration != 0 {
        writeln!(
            output,
            "controller_candidate_exchange={} configuration_lease_valid_until={configuration} configuration_lease_expired={} certificate_renewal_needed={} certificate_renew_after={} certificate_not_after={certificate} identity_lease_expires_at={lease}",
            flag("candidate_exchange_enabled"),
            flag("configuration_lease_expired"),
            flag("certificate_renewal_needed"),
            number("certificate_renew_after_unix_seconds")
        )?;
    }
    let exit = &status["exit"];
    let flag = |key: &str| exit[key].as_bool().unwrap_or_default();
    if flag("enabled") || flag("serving") {
        writeln!(
            output,
            "exit={} authorized={} serving={} forwarding_ready={} nat_ready={} forwarded_packets={} namespace_cleanup_failures={}",
            text(exit, "selected_node_id"),
            flag("authorized"),
            flag("serving"),
            flag("forwarding_ready"),
            flag("nat_ready"),
            exit["forwarded_packets"].as_u64().unwrap_or_default(),
            exit["namespace_cleanup_failures"]
                .as_u64()
                .unwrap_or_default()
        )?;
    }
    Ok(())
}
