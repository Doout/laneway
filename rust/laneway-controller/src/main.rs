use anyhow::{Context, Result, ensure};
use laneway_controller::{Inventory, Network, Node};
use serde::Serialize;
use std::{env, io, path::Path};

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Response {
    Networks(Vec<Network>),
    Nodes(Vec<Node>),
}

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    const USAGE: &str = "usage: laneway-controller inventory {networks DATABASE | nodes DATABASE NETWORK_ID} [LIMIT]";
    ensure!(args.next().as_deref() == Some("inventory".as_ref()), USAGE);
    let kind = args.next().context(USAGE)?;
    let path = args.next().context(USAGE)?;
    let network = match kind.to_str() {
        Some("networks") => None,
        Some("nodes") => Some(
            args.next()
                .context(USAGE)?
                .to_str()
                .context(USAGE)?
                .parse()?,
        ),
        _ => anyhow::bail!(USAGE),
    };
    let limit = args
        .next()
        .map(|s| s.to_string_lossy().parse::<usize>())
        .transpose()?
        .unwrap_or(100);
    ensure!(args.next().is_none(), USAGE);
    let mut store = Inventory::open(Path::new(&path))?;
    let response = match network {
        None => Response::Networks(store.networks(limit)?),
        Some(network) => Response::Nodes(store.nodes(network, limit)?),
    };
    serde_json::to_writer(io::stdout().lock(), &response)?;
    Ok(())
}
