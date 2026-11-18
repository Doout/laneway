use std::{collections::BTreeSet, time::Instant};

use ipnet::Ipv4Net;
use serde_json::Value;

use super::LinuxBackend;
use crate::{Egress, Network, Result, conflict};

#[derive(Debug)]
struct Rule {
    priority: u16,
    from: Option<Ipv4Net>,
    to: Option<Ipv4Net>,
    mark: Option<u32>,
    table: String,
}

pub(super) struct Plan {
    routes: Vec<String>,
    rules: Vec<Rule>,
}

impl LinuxBackend {
    pub(super) fn plan_routes(&self, network: &Network, deadline: Instant) -> Result<Plan> {
        let mut want = expected(network);
        if want.routes.is_empty() {
            return Ok(want);
        }
        let routes = self.routes(network, deadline)?;
        let mut existing = BTreeSet::new();
        for route in &routes {
            let matched = want
                .routes
                .iter()
                .find(|prefix| route_matches(route, prefix, &self.tunnel));
            if !matched.is_some_and(|prefix| existing.insert(prefix.clone())) {
                return Err(conflict(format!(
                    "routing table {} has unowned or ambiguous routes",
                    network.table
                )));
            }
        }
        want.routes.retain(|prefix| !existing.contains(prefix));
        let rules = self.rules(deadline)?;
        let mut missing = Vec::new();
        for rule in want.rules {
            let at_priority: Vec<_> = rules
                .iter()
                .filter(|record| record["priority"] == rule.priority)
                .collect();
            match at_priority.as_slice() {
                [] => missing.push(rule),
                [record] if rule.matches(record) => (),
                _ => {
                    return Err(conflict(format!(
                        "Linux policy rule priority {} is already in use",
                        rule.priority
                    )));
                }
            }
        }
        want.rules = missing;
        Ok(want)
    }

    pub(super) fn apply_routes(
        &self,
        network: &Network,
        plan: Plan,
        deadline: Instant,
    ) -> Result<()> {
        for route in plan.routes {
            self.change_route(network, "add", &route, deadline)?;
        }
        for rule in plan.rules {
            self.change_rule("add", &rule, deadline)?;
        }
        Ok(())
    }

    pub(super) fn remove_routes(&self, network: &Network, deadline: Instant) -> Result<()> {
        let expected = expected(network);
        if expected.routes.is_empty() {
            return Ok(());
        }
        let rules = self.rules(deadline)?;
        for rule in expected.rules {
            let count = rules.iter().filter(|record| rule.matches(record)).count();
            if count > 1 {
                return Err(conflict(
                    "refusing to delete ambiguous duplicate policy rule",
                ));
            }
            if count == 1 {
                self.change_rule("del", &rule, deadline)?;
            }
        }
        let routes = self.routes(network, deadline)?;
        for prefix in expected.routes {
            let count = routes
                .iter()
                .filter(|record| route_matches(record, &prefix, &self.tunnel))
                .count();
            if count > 1 {
                return Err(conflict(
                    "refusing to delete ambiguous duplicate tunnel route",
                ));
            }
            if count == 1 {
                self.change_route(network, "del", &prefix, deadline)?;
            }
        }
        Ok(())
    }

    fn routes(&self, network: &Network, deadline: Instant) -> Result<Vec<Value>> {
        let output = self.ip(
            &[
                "-N",
                "-j",
                "-4",
                "route",
                "show",
                "table",
                &network.table.to_string(),
            ],
            deadline,
        )?;
        if output.missing() {
            return Ok(Vec::new());
        }
        output.json("inspect network route table")
    }

    fn rules(&self, deadline: Instant) -> Result<Vec<Value>> {
        self.ip(&["-j", "-4", "rule", "show"], deadline)?
            .json("inspect Linux policy rules")
    }

    fn change_route(
        &self,
        network: &Network,
        op: &str,
        prefix: &str,
        deadline: Instant,
    ) -> Result<()> {
        self.ip(
            &[
                "-4",
                "route",
                op,
                "table",
                &network.table.to_string(),
                prefix,
                "dev",
                &self.tunnel,
                "proto",
                "99",
            ],
            deadline,
        )?
        .check("change owned network route")
    }

    fn change_rule(&self, op: &str, rule: &Rule, deadline: Instant) -> Result<()> {
        let mut args = vec![
            "-4".to_owned(),
            "rule".to_owned(),
            op.into(),
            "priority".into(),
            rule.priority.to_string(),
        ];
        if let Some(prefix) = rule.from {
            args.extend(["from".into(), prefix.to_string()]);
        }
        if let Some(prefix) = rule.to {
            args.extend(["to".into(), prefix.to_string()]);
        }
        if let Some(mark) = rule.mark {
            args.extend(["fwmark".into(), format!("0x{mark:x}")]);
        }
        args.extend(["lookup".into(), rule.table.clone()]);
        let borrowed: Vec<_> = args.iter().map(String::as_str).collect();
        self.ip(&borrowed, deadline)?
            .check("change exact network policy rule")
    }
}

impl Rule {
    fn matches(&self, record: &Value) -> bool {
        let Some(object) = record.as_object() else {
            return false;
        };
        if !object.keys().all(|key| {
            matches!(
                key.as_str(),
                "priority" | "src" | "srclen" | "dst" | "dstlen" | "table" | "fwmark" | "fwmask"
            )
        }) {
            return false;
        }
        record["priority"] == self.priority
            && record["table"] == self.table
            && selector(record, "src", "srclen", self.from)
            && selector(record, "dst", "dstlen", self.to)
            && match self.mark {
                None => record["fwmark"].is_null() && record["fwmask"].is_null(),
                Some(mark) => {
                    hex_value(&record["fwmark"]) == Some(mark)
                        && (record["fwmask"].is_null()
                            || hex_value(&record["fwmask"]) == Some(u32::MAX))
                }
            }
    }
}

fn selector(record: &Value, addr_key: &str, len_key: &str, expected: Option<Ipv4Net>) -> bool {
    let address = record[addr_key].as_str();
    match expected {
        Some(expected) => {
            address.and_then(|address| {
                if let Ok(parsed) = address.parse::<Ipv4Net>() {
                    return Some(parsed);
                }
                let length = record[len_key].as_u64().unwrap_or(32).try_into().ok()?;
                Ipv4Net::new(address.parse().ok()?, length).ok()
            }) == Some(expected)
        }
        None => matches!(address, None | Some("all")) && record[len_key].is_null(),
    }
}

fn hex_value(value: &Value) -> Option<u32> {
    u32::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok()
}

fn route_matches(record: &Value, prefix: &str, tunnel: &str) -> bool {
    let Some(object) = record.as_object() else {
        return false;
    };
    let reported = record["dst"].as_str().unwrap_or_default();
    let destination_matches = reported == prefix || format!("{reported}/32") == prefix;
    destination_matches
        && record["dev"] == tunnel
        && record["protocol"] == "99"
        && record["scope"] == "253"
        && record["flags"].as_array().is_some_and(Vec::is_empty)
        && object.keys().all(|key| {
            matches!(
                key.as_str(),
                "dst" | "dev" | "protocol" | "scope" | "flags" | "table"
            )
        })
}

fn expected(network: &Network) -> Plan {
    if network.policy.egress == Egress::Direct {
        return Plan {
            routes: vec![],
            rules: vec![],
        };
    }
    let table = network.table.to_string();
    let mut routes = vec!["default".into()];
    let mut rules = vec![Rule {
        priority: network.table - 10_000,
        from: None,
        to: None,
        mark: Some(0x4c_0000 | u32::from(network.table)),
        table: table.clone(),
    }];
    let mut push = |priority, to, table| {
        rules.push(Rule {
            priority,
            from: Some(network.subnet),
            to,
            mark: None,
            table,
        })
    };
    if network.policy.egress == Egress::FullTunnel {
        for (index, prefix) in network.bypass_cidrs.iter().enumerate() {
            push(network.table + index as u16, Some(*prefix), "main".into());
        }
        push(
            network.table + network.bypass_cidrs.len() as u16,
            None,
            table,
        );
    } else {
        for (index, prefix) in network.policy.egress_cidrs.iter().enumerate() {
            routes.push(prefix.to_string());
            push(network.table + index as u16, Some(*prefix), table.clone());
        }
    }
    Plan { routes, rules }
}
