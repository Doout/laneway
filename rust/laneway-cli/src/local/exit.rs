//! Select a local exit via the same Unix API used by the daemon.
use super::{Peer, local_client, read};
use crate::node::split_flag;
use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::Id;
use reqwest::StatusCode;
use std::{ffi::OsString, io::Read, path::PathBuf};

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let leaf = if args[0] == "node" { &args[1..] } else { args };
    let enable = leaf[1] == "use";
    let usage = if enable {
        "laneway exit use NAME_OR_NODE_ID [-config path | -socket path]"
    } else {
        "laneway exit disable [-config path | -socket path]"
    };
    let mut args = leaf[2..].iter().peekable();
    let mut selector = None;
    if enable
        && args
            .peek()
            .is_some_and(|arg| !arg.as_encoded_bytes().starts_with(b"-"))
    {
        selector = args.next();
    }
    let mut socket = None;
    let mut config = PathBuf::from("/etc/laneway/laneway.toml");
    while let Some(arg) = args.next() {
        let (flag, inline) = split_flag(arg);
        match flag {
            "--help" | "-h" | "-help" => {
                println!("Usage: {usage}");
                return Ok(());
            }
            "--config" | "-config" | "--socket" | "-socket" => {
                let value = inline
                    .or_else(|| args.next().cloned())
                    .with_context(|| format!("{flag} requires a path"))?;
                if flag.ends_with("config") {
                    config = value.into()
                } else {
                    socket = (!value.is_empty()).then_some(value);
                }
            }
            "--" => {
                if enable && selector.is_none() {
                    selector = args.next();
                }
                ensure!(args.next().is_none(), "usage: {usage}");
                break;
            }
            _ if enable
                && !arg.as_encoded_bytes().starts_with(b"-")
                && selector.is_none()
                && args.peek().is_none() =>
            {
                selector = Some(arg)
            }
            _ => bail!("usage: {usage}"),
        }
    }
    ensure!(
        !enable || selector.is_some_and(|value| !value.is_empty()),
        "usage: {usage}"
    );
    let client = local_client(socket, &config)?;
    let selected = if let Some(selector) = selector {
        let name = selector.to_str().context("exit name is not UTF-8")?;
        match name.parse::<Id>() {
            Ok(id) => Some(id.to_string()),
            Err(_) => {
                let peers = read::<Option<Vec<Peer>>>(&client, "peers")
                    .context("resolve exit name")?
                    .unwrap_or_default();
                let mut ids = peers
                    .iter()
                    .filter(|peer| peer.name == name)
                    .map(|peer| peer.node_id.parse::<Id>())
                    .collect::<Result<std::collections::HashSet<_>, _>>()
                    .context("exit name maps to an invalid node identity")?;
                ensure!(!ids.is_empty(), "no peer has the exact name {name:?}");
                ensure!(
                    ids.len() == 1,
                    "exit name {name:?} is ambiguous across {} node identities",
                    ids.len()
                );
                ids.drain().next().map(|id| id.to_string())
            }
        }
    } else {
        None
    };
    #[derive(serde::Serialize)]
    struct Selection<'a> {
        enabled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        selected_node_id: Option<&'a str>,
    }
    let body = serde_json::to_vec(&Selection {
        enabled: enable,
        selected_node_id: selected.as_deref(),
    })?;
    let response = client
        .post("http://lanewayd/v1/exit")
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .context("contact lanewayd")?;
    let status = response.status();
    if status != StatusCode::NO_CONTENT {
        let mut message = Vec::new();
        response.take(4096).read_to_end(&mut message)?;
        bail!(
            "lanewayd returned {status}: {}",
            String::from_utf8_lossy(&message).trim()
        );
    }
    if let Some(id) = selected {
        println!("selected exit node {id}");
    } else {
        println!("exit routing disabled");
    }
    Ok(())
}
