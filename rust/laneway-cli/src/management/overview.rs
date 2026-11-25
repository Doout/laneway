use std::{
    ffi::OsString,
    io::{self, Write},
};

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{args::Flags, transport::Client};

pub(super) fn run(args: &[OsString]) -> Result<()> {
    let (flags, rest) = Flags::parse(args, &["network-id"], &["json"], false)?;
    ensure!(
        rest.is_empty(),
        "controller overview: unexpected positional arguments"
    );
    let network = flags.id("network-id")?;
    let client = Client::new(&flags, false)?;
    let path = format!("/v1/admin/networks/{network}");
    let node_list = client.get(&format!("{path}/nodes?limit=1000"))?;
    let route_list = client.get(&format!("{path}/routes?limit=1000"))?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let active = |value: &Value| value.as_i64().is_none_or(|deadline| deadline > now);
    let mut nodes = Vec::new();
    for node in node_list["nodes"].as_array().into_iter().flatten() {
        if !node["revoked_at_unix_seconds"].is_null()
            || !active(&node["lease_expires_at_unix_seconds"])
        {
            continue;
        }
        let mut forwards = Vec::new();
        for route in route_list["routes"].as_array().into_iter().flatten() {
            if route["node_id"] == node["node_id"]
                && route["state"] == "approved"
                && matches!(route["kind"].as_str(), Some("subnet" | "exit"))
                && active(&route["valid_until_unix_seconds"])
            {
                forwards.push(json!({"prefix": route["prefix"], "mode": route["mode"], "kind": route["kind"]}));
            }
        }
        forwards.sort_by(|a, b| {
            (a["prefix"].as_str(), a["kind"].as_str())
                .cmp(&(b["prefix"].as_str(), b["kind"].as_str()))
        });
        let mut overlay = Vec::new();
        for key in ["ipv4_address", "ipv6_address"] {
            if let Some(address) = node[key].as_str().filter(|address| !address.is_empty()) {
                overlay.push(address);
            }
        }
        let enrollment = node["enrollment_class"].as_str().unwrap_or_default();
        let cap = node["enabled_capabilities"].as_u64().unwrap_or_default();
        let role = if matches!(enrollment, "ephemeral" | "remembered") {
            "user"
        } else if cap & u64::from(super::resources::SUBNET_ROUTER) != 0 {
            "connector"
        } else if cap & u64::from(super::resources::EXIT_NODE) != 0 {
            "exit-node"
        } else {
            "node"
        };
        nodes.push(
            json!({"name": node["name"], "node_id": node["node_id"], "role": role,
            "enrollment": enrollment, "overlay_addresses": overlay,
            "forwarding": (!forwards.is_empty()).then_some(forwards)}),
        );
    }
    nodes.sort_by(|a, b| {
        (a["role"].as_str(), a["name"].as_str()).cmp(&(b["role"].as_str(), b["name"].as_str()))
    });
    if flags.boolean("json", false)? {
        return super::print(
            &json!({"network_id": network.to_string(), "nodes": (!nodes.is_empty()).then_some(nodes)}),
        );
    }

    let mut rows = vec![[
        "NAME".into(),
        "ROLE".into(),
        "OVERLAY".into(),
        "FORWARDING".into(),
    ]];
    for node in nodes {
        let name = node["name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .or_else(|| node["node_id"].as_str())
            .unwrap_or_default();
        let overlay = node["overlay_addresses"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let forwards = node["forwarding"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|route| {
                format!(
                    "{} ({})",
                    route["prefix"].as_str().unwrap_or_default(),
                    route["mode"].as_str().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        rows.push([
            name.into(),
            node["role"].as_str().unwrap_or_default().into(),
            dash(overlay),
            dash(forwards),
        ]);
    }
    if rows.len() == 1 {
        rows.push(std::array::from_fn(|_| "-".into()));
    }
    let mut out = io::stdout().lock();
    writeln!(out, "\nActive enrollment inventory ({network})")?;
    let widths: [usize; 3] = std::array::from_fn(|index| {
        rows.iter()
            .map(|row| row[index].chars().count())
            .max()
            .unwrap_or_default()
            + 2
    });
    for [name, role, overlay, forward] in rows {
        writeln!(
            out,
            "{name:<first$}{role:<second$}{overlay:<third$}{forward}",
            first = widths[0],
            second = widths[1],
            third = widths[2]
        )?;
    }
    Ok(())
}

fn dash(value: String) -> String {
    if value.is_empty() { "-".into() } else { value }
}
