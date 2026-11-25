use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_protocol::Id;
use reqwest::Method;
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{Operation, args::Flags, prefix::Prefix, transport::Client};
use crate::utility::parse_duration;

pub(super) fn execute(
    operation: Operation,
    flags: &Flags<'_>,
    positional: Option<&str>,
) -> Result<Value> {
    match operation {
        Operation::RouteAssign => assign(flags),
        Operation::RouteAdvertise => advertise(flags, positional),
        Operation::RouteApprove => {
            let id = flags.id("route-id")?;
            Client::new(flags, false)?.request(
                Method::POST,
                &format!("/v1/admin/routes/{id}/approve"),
                None,
            )
        }
        Operation::RouteWithdraw => {
            let id = flags.id("route-id")?;
            Client::new(flags, true)?.request(Method::DELETE, &format!("/v1/routes/{id}"), None)
        }
        _ => bail!("unsupported controller route operation"),
    }
}

fn assign(flags: &Flags<'_>) -> Result<Value> {
    let network = flags.id("network-id")?;
    let connector = flags.required("connector")?;
    let to = Prefix::assigned(flags.required("to")?)?;
    let allow = flags.text("allow")?;
    let mode = flags.enum_value("mode", "nat", &["nat", "routed"])?;
    let metric = flags.number("metric", "0")?;
    let client = Client::new(flags, false)?;
    let connector_id = resolve_node(&client, network, connector)?;
    let allowed = if allow.is_empty() {
        None
    } else {
        Some(resolve_node(&client, network, allow).context("resolve --allow")?)
    };
    let route = client.request(
        Method::POST,
        "/v1/admin/routes/assign",
        Some(json!({
            "network_id": network.to_string(), "node_id": connector_id.to_string(),
            "prefix": to.to_string(), "mode": mode, "metric": metric,
        })),
    )?;
    let mut selector = json!({
        "destination_prefixes": [{"address": STANDARD.encode(to.octets()), "prefix_length": to.bits}],
        "ip_protocol": "IP_PROTOCOL_ANY",
    });
    let mut description = format!("managed route {to} via {connector}");
    if let Some(node) = allowed {
        selector["source_node_ids"] = json!([STANDARD.encode(node.as_bytes())]);
        description.push_str(" for ");
        description.push_str(allow);
    }
    let acl_path = format!("/v1/admin/networks/{network}/acl-rules");
    let rules = client.get(&format!("{acl_path}?limit=1000"))?;
    let list = rules
        .get("acl_rules")
        .context("controller omitted the ACL rules")?;
    let existing = if list.is_null() {
        None
    } else {
        list.as_array()
            .context("controller returned invalid ACL rules")?
            .iter()
            .find(|rule| rule["action"] == "accept" && rule["selector"] == selector)
    };
    let rule = match existing {
        Some(rule) => rule.clone(),
        None => client.request(Method::POST, &acl_path, Some(json!({
            "priority": 100, "action": "accept", "selector": selector, "description": description,
        })))?,
    };
    Ok(json!({"route":route, "acl_rule":rule}))
}

fn advertise(flags: &Flags<'_>, positional: Option<&str>) -> Result<Value> {
    let flag = flags.text("prefix")?;
    ensure!(
        flag.is_empty() || positional.is_none(),
        "route advertise accepts either positional PREFIX or --prefix, not both"
    );
    let prefix: Prefix = positional
        .unwrap_or(flag)
        .parse()
        .context("route advertise requires a canonical PREFIX")?;
    let mode = flags.enum_value("mode", "nat", &["nat", "routed"])?;
    let kind = flags.enum_value("kind", "subnet", &["subnet", "exit"])?;
    let metric = flags.number("metric", "0")?;
    let valid = parse_duration(flags.text_or("valid-for", "0")?).context("--valid-for")?;
    ensure!(!valid.is_negative(), "invalid --valid-for");
    let mut body = json!({"prefix":prefix.to_string(), "kind":kind, "mode":mode, "metric":metric});
    if valid.is_positive() {
        body["valid_until_unix_seconds"] =
            json!((OffsetDateTime::now_utc() + valid).unix_timestamp());
    }
    Client::new(flags, true)?.request(Method::POST, "/v1/routes", Some(body))
}

fn resolve_node(client: &Client, network: Id, selector: &str) -> Result<Id> {
    if let Ok(id) = selector.parse() {
        return Ok(id);
    }
    let response = client.get(&format!("/v1/admin/networks/{network}/nodes?limit=1000"))?;
    let disclosed = response
        .get("nodes")
        .context("controller omitted the node list")?;
    let nodes = if disclosed.is_null() {
        &[][..]
    } else {
        disclosed
            .as_array()
            .context("controller returned an invalid node list")?
    };
    let alias = selector
        .strip_prefix("laneway-connector-")
        .unwrap_or(selector);
    let mut matches = nodes.iter().filter(|node| {
        node["revoked_at_unix_seconds"].is_null()
            && (node["name"] == selector || node["name"] == alias)
    });
    let node = matches
        .next()
        .with_context(|| format!("no active Connector has the exact name {selector:?}"))?;
    ensure!(
        matches.next().is_none(),
        "Connector name {selector:?} is ambiguous"
    );
    node["node_id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .context("controller returned an invalid node identity")
}
