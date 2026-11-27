use std::{
    collections::HashMap,
    io::{self, Write},
    net::IpAddr,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use ipnet::IpNet;
use laneway_protocol::Id;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::admin::{Client, EXIT_NODE, SUBNET_ROUTER, deadline, print_json};

#[derive(Args)]
pub(super) struct Assignment {
    #[arg(long)]
    network_id: Id,
    #[arg(long)]
    connector: String,
    #[arg(long)]
    to: String,
    #[arg(long)]
    allow: Option<String>,
    #[arg(long, value_parser = ["nat", "routed"], default_value = "nat")]
    mode: String,
    #[arg(long, default_value_t = 0)]
    metric: u32,
}

#[derive(Deserialize)]
struct Nodes {
    nodes: Option<Vec<Node>>,
}

#[derive(Deserialize)]
struct Node {
    node_id: String,
    name: String,
    enrollment_class: String,
    enabled_capabilities: u64,
    ipv4_address: Option<String>,
    ipv6_address: Option<String>,
    revoked_at_unix_seconds: Option<u64>,
    lease_expires_at_unix_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct Routes {
    routes: Option<Vec<Route>>,
}

#[derive(Deserialize)]
struct Route {
    node_id: String,
    state: String,
    valid_until_unix_seconds: Option<u64>,
    #[serde(flatten)]
    forward: Forward,
}

#[derive(Deserialize, Serialize)]
struct Forward {
    prefix: String,
    mode: String,
    kind: String,
}

#[derive(Serialize)]
struct Entry {
    name: String,
    node_id: String,
    role: &'static str,
    enrollment: String,
    overlay_addresses: Vec<String>,
    forwarding: Option<Vec<Forward>>,
}

impl Node {
    fn role(&self) -> &'static str {
        if matches!(self.enrollment_class.as_str(), "ephemeral" | "remembered") {
            "user"
        } else if self.enabled_capabilities & SUBNET_ROUTER != 0 {
            "connector"
        } else if self.enabled_capabilities & EXIT_NODE != 0 {
            "exit-node"
        } else {
            "node"
        }
    }
}

async fn nodes(client: &Client, network: Id) -> Result<Vec<Node>> {
    let value = client
        .request(
            Method::GET,
            &format!("/v1/admin/networks/{network}/nodes?limit=1000"),
            None,
        )
        .await?;
    Ok(serde_json::from_value::<Nodes>(value)?
        .nodes
        .unwrap_or_default())
}

pub(super) async fn overview(client: &Client, network: Id, json_output: bool) -> Result<()> {
    let nodes = nodes(client, network).await?;
    let routes = client
        .request(
            Method::GET,
            &format!("/v1/admin/networks/{network}/routes?limit=1000"),
            None,
        )
        .await?;
    let now = deadline(Duration::ZERO)?;
    let mut forwarding: HashMap<_, Vec<_>> = HashMap::new();
    for route in serde_json::from_value::<Routes>(routes)?
        .routes
        .into_iter()
        .flatten()
    {
        if route.state == "approved"
            && matches!(route.forward.kind.as_str(), "subnet" | "exit")
            && route
                .valid_until_unix_seconds
                .is_none_or(|expiry| expiry > now)
        {
            forwarding
                .entry(route.node_id)
                .or_default()
                .push(route.forward);
        }
    }
    let mut entries = Vec::new();
    for node in nodes {
        if node.revoked_at_unix_seconds.is_some()
            || node
                .lease_expires_at_unix_seconds
                .is_some_and(|expiry| expiry <= now)
        {
            continue;
        }
        let role = node.role();
        let mut routes = forwarding.remove(&node.node_id);
        if let Some(routes) = &mut routes {
            routes.sort_by(|a, b| (&a.prefix, &a.kind).cmp(&(&b.prefix, &b.kind)));
        }
        entries.push(Entry {
            name: node.name,
            node_id: node.node_id,
            role,
            enrollment: node.enrollment_class,
            overlay_addresses: [node.ipv4_address, node.ipv6_address]
                .into_iter()
                .flatten()
                .filter(|address| !address.is_empty())
                .collect(),
            forwarding: routes,
        });
    }
    entries.sort_by(|a, b| (a.role, &a.name).cmp(&(b.role, &b.name)));
    if json_output {
        let nodes = (!entries.is_empty()).then_some(entries);
        return print_json(&json!({"network_id": network.to_string(), "nodes": nodes}));
    }

    let mut rows = vec![[
        "NAME".to_owned(),
        "ROLE".to_owned(),
        "OVERLAY".to_owned(),
        "FORWARDING".to_owned(),
    ]];
    for node in entries {
        let name = if node.name.is_empty() {
            node.node_id
        } else {
            node.name
        };
        let overlay = display_or_dash(node.overlay_addresses.join(","));
        let routes = display_or_dash(
            node.forwarding
                .into_iter()
                .flatten()
                .map(|route| format!("{} ({})", route.prefix, route.mode))
                .collect::<Vec<_>>()
                .join(", "),
        );
        rows.push([name, node.role.to_owned(), overlay, routes]);
    }
    if rows.len() == 1 {
        rows.push(std::array::from_fn(|_| "-".to_owned()));
    }
    let widths: [usize; 3] = std::array::from_fn(|index| {
        rows.iter()
            .map(|row| row[index].chars().count())
            .max()
            .unwrap_or(0)
    });
    let mut output = io::stdout().lock();
    writeln!(output, "\nActive enrollment inventory ({network})")?;
    for [name, role, overlay, routing] in rows {
        writeln!(
            output,
            "{name:<name_width$}  {role:<role_width$}  {overlay:<overlay_width$}  {routing}",
            name_width = widths[0],
            role_width = widths[1],
            overlay_width = widths[2]
        )?;
    }
    Ok(())
}

fn display_or_dash(value: String) -> String {
    if value.is_empty() {
        "-".to_owned()
    } else {
        value
    }
}

pub(super) async fn assign(client: &Client, options: Assignment) -> Result<()> {
    let network = options.network_id;
    let prefix = if let Ok(address) = options.to.parse::<IpAddr>() {
        IpNet::from(address)
    } else {
        let prefix = options
            .to
            .parse::<IpNet>()
            .context("--to must be an IP address or canonical non-default prefix")?;
        ensure!(
            prefix == prefix.trunc() && prefix.prefix_len() != 0,
            "--to must be an IP address or canonical non-default prefix"
        );
        prefix
    };
    ensure!(
        !options.connector.is_empty(),
        "route assign requires --connector"
    );
    let connector = options.connector.parse::<Id>();
    let user = options.allow.filter(|selector| !selector.is_empty());
    let user_id = user.as_deref().map(str::parse::<Id>);
    let enrolled = if connector.is_err() || user_id.as_ref().is_some_and(Result::is_err) {
        nodes(client, network).await?
    } else {
        Vec::new()
    };
    let target = connector.or_else(|_| by_name(&enrolled, &options.connector))?;
    let user_id = user
        .as_deref()
        .zip(user_id)
        .map(|(selector, parsed)| {
            parsed
                .or_else(|_| by_name(&enrolled, selector))
                .context("resolve --allow")
        })
        .transpose()?;

    let address = match prefix.addr() {
        IpAddr::V4(address) => STANDARD.encode(address.octets()),
        IpAddr::V6(address) => STANDARD.encode(address.octets()),
    };
    let mut selector = json!({
        "destination_prefixes": [{"address": address, "prefix_length": prefix.prefix_len()}],
        "ip_protocol": "IP_PROTOCOL_ANY",
    });
    let mut description = format!("managed route {prefix} via {}", options.connector);
    if let Some((name, id)) = user.zip(user_id) {
        selector["source_node_ids"] = json!([STANDARD.encode(id.as_bytes())]);
        description.push_str(&format!(" for {name}"));
    }
    let path = format!("/v1/admin/networks/{network}/acl-rules");
    let rules = client
        .request(Method::GET, &format!("{path}?limit=1000"), None)
        .await?;
    let existing = rules["acl_rules"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|rule| rule["action"] == "accept" && rule["selector"] == selector);

    let route = client
        .request(
            Method::POST,
            "/v1/admin/routes/assign",
            Some(json!({
                "network_id": network.to_string(), "node_id": target.to_string(),
                "prefix": prefix.to_string(), "mode": options.mode, "metric": options.metric,
            })),
        )
        .await?;
    let acl = match existing {
        Some(rule) => rule.clone(),
        None => client.request(Method::POST, &path, Some(json!({
            "priority": 100, "action": "accept", "selector": selector, "description": description,
        }))).await?,
    };
    print_json(&json!({"route": route, "acl_rule": acl}))
}

fn by_name(nodes: &[Node], selector: &str) -> Result<Id> {
    let short = selector
        .strip_prefix("laneway-connector-")
        .unwrap_or(selector);
    let mut matches = nodes.iter().filter(|node| {
        node.revoked_at_unix_seconds.is_none() && (node.name == selector || node.name == short)
    });
    let node = matches
        .next()
        .with_context(|| format!("no active Connector has the exact name {selector:?}"))?;
    ensure!(
        matches.next().is_none(),
        "Connector name {selector:?} is ambiguous"
    );
    node.node_id
        .parse()
        .context("controller returned an invalid node identity")
}
