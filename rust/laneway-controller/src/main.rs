use anyhow::{Context, Result, ensure};
use laneway_controller::{Inventory, InventoryList as Response, SessionStore};
use std::io::{IsTerminal, Read};
use std::{env, io, path::Path};

mod discovery_limit;
mod http;
mod server;

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    const USAGE: &str = "usage: laneway-controller {inventory|session-inventory} {networks DATABASE | nodes DATABASE NETWORK_ID} [LIMIT]";
    let scoped = match args.next().as_deref().and_then(|a| a.to_str()) {
        Some("serve") => return server::start(args),
        Some("inventory") => false,
        Some("session-inventory") => true,
        _ => anyhow::bail!(USAGE),
    };
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
    let response = if scoped {
        ensure!(!io::stdin().is_terminal(), "pass session token via stdin");
        let mut input = String::new();
        io::stdin().lock().take(46).read_to_string(&mut input)?;
        let token = input
            .strip_suffix("\r\n")
            .or_else(|| input.strip_suffix('\n'))
            .unwrap_or(&input);
        let mut store = SessionStore::open(Path::new(&path))?;
        store.inventory(token, Ok((network, limit)))?.list
    } else {
        let mut store = Inventory::open(Path::new(&path))?;
        match network {
            None => Response::Networks(store.networks(limit)?),
            Some(network) => Response::Nodes(store.nodes(network, limit)?),
        }
    };
    serde_json::to_writer(io::stdout().lock(), &response)?;
    Ok(())
}
