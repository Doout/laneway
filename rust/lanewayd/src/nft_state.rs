use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Chain {
    pub(crate) name: String,
    pub(crate) kind: Option<String>,
    pub(crate) hook: Option<String>,
    pub(crate) policy: Option<String>,
    pub(crate) priority: i64,
}

impl Chain {
    pub(crate) fn regular(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: None,
            hook: None,
            policy: None,
            priority: 0,
        }
    }

    pub(crate) fn base(name: impl Into<String>, kind: &str, hook: &str, priority: i64) -> Self {
        Self {
            name: name.into(),
            kind: Some(kind.to_owned()),
            hook: Some(hook.to_owned()),
            policy: Some("accept".to_owned()),
            priority,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Rule {
    pub(crate) chain: String,
    pub(crate) comment: String,
    pub(crate) expressions: Vec<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct Shape {
    pub(crate) table: String,
    pub(crate) owner_chain: String,
    pub(crate) marker: String,
    pub(crate) session_prefix: String,
    pub(crate) chains: Vec<Chain>,
    pub(crate) rules: Vec<Rule>,
}

pub(crate) fn marker(role: &str, fields: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"laneway-rust-nft-state-v1\0");
    hash.update(role.as_bytes());
    for field in fields {
        hash.update([0]);
        hash.update(field.as_ref().as_bytes());
    }
    format!("laneway-rust-{role}-v1-{}", hex::encode(hash.finalize()))
}

pub(crate) fn match_meta(key: &str, value: &str) -> Value {
    json!({"match":{"op":"==","left":{"meta":{"key":key}},"right":value}})
}

pub(crate) fn match_prefix(protocol: &str, field: &str, address: &str, bits: u8) -> Value {
    json!({"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":field}},"right":{"prefix":{"addr":address,"len":bits}}}})
}

pub(crate) fn match_ct_states() -> Value {
    json!({"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}})
}

pub(crate) fn accept() -> Value {
    json!({"accept":null})
}

pub(crate) fn masquerade() -> Value {
    json!({"masquerade":null})
}

pub(crate) fn validate(raw: &[u8], shape: &Shape) -> Result<String> {
    let document: Value = serde_json::from_slice(raw).context("decode nftables JSON")?;
    let objects = document
        .get("nftables")
        .and_then(Value::as_array)
        .context("nftables document has no object list")?;
    ensure!(!objects.is_empty(), "empty nftables document");
    let mut tables = Vec::new();
    let mut chains = Vec::new();
    let mut rules = Vec::new();
    for object in objects {
        let object = object
            .as_object()
            .context("nftables entry is not an object")?;
        ensure!(object.len() == 1, "nftables object has unexpected fields");
        let (kind, value) = object.iter().next().expect("one field checked");
        if kind == "metainfo" {
            continue;
        }
        let entity = value
            .as_object()
            .with_context(|| format!("nftables {kind} is not an object"))?;
        match kind.as_str() {
            "table" => tables.push(entity),
            "chain" => chains.push(entity),
            "rule" => rules.push(entity),
            _ => bail!("unexpected nftables object {kind:?}"),
        }
    }
    ensure!(tables.len() == 1, "table count differs");
    let table = tables[0];
    ensure!(
        exact_keys(table, &["family", "name", "handle"])
            && string(table, "family") == "inet"
            && string(table, "name") == shape.table,
        "table identity or shape differs"
    );

    let expected_chains: BTreeMap<_, _> = shape
        .chains
        .iter()
        .map(|chain| (chain.name.as_str(), chain))
        .collect();
    ensure!(
        expected_chains.len() == shape.chains.len(),
        "duplicate expected chain"
    );
    ensure!(chains.len() == expected_chains.len(), "chain count differs");
    for actual in chains {
        let name = string(actual, "name");
        let expected = expected_chains
            .get(name)
            .with_context(|| format!("unexpected chain {name:?}"))?;
        ensure!(
            string(actual, "family") == "inet" && string(actual, "table") == shape.table,
            "chain identity differs"
        );
        if let Some(kind) = &expected.kind {
            ensure!(
                exact_keys(
                    actual,
                    &[
                        "family", "table", "name", "handle", "type", "hook", "prio", "policy",
                    ],
                ) && string(actual, "type") == kind
                    && Some(string(actual, "hook")) == expected.hook.as_deref()
                    && Some(string(actual, "policy")) == expected.policy.as_deref()
                    && integer(actual, "prio") == expected.priority,
                "base chain {name:?} differs"
            );
        } else {
            ensure!(
                exact_keys(actual, &["family", "table", "name", "handle"]),
                "regular chain {name:?} differs"
            );
        }
    }

    let mut actual_by_chain: BTreeMap<&str, Vec<&Map<String, Value>>> = BTreeMap::new();
    for rule in rules {
        ensure!(
            exact_keys(
                rule,
                &["family", "table", "chain", "handle", "comment", "expr",],
            ) && string(rule, "family") == "inet"
                && string(rule, "table") == shape.table,
            "rule identity or shape differs"
        );
        let chain = string(rule, "chain");
        ensure!(
            expected_chains.contains_key(chain),
            "rule uses unexpected chain"
        );
        actual_by_chain.entry(chain).or_default().push(rule);
    }
    let owner = actual_by_chain
        .remove(shape.owner_chain.as_str())
        .context("ownership chain has no rules")?;
    ensure!(
        owner.len() == 2
            && string(owner[0], "comment") == shape.marker
            && counter_only(owner[0].get("expr"))
            && string(owner[1], "comment").starts_with(&shape.session_prefix)
            && counter_only(owner[1].get("expr")),
        "ownership rules differ"
    );
    let session = string(owner[1], "comment").to_owned();

    let mut expected_by_chain: BTreeMap<&str, Vec<&Rule>> = BTreeMap::new();
    for rule in &shape.rules {
        expected_by_chain
            .entry(rule.chain.as_str())
            .or_default()
            .push(rule);
    }
    let non_owner: BTreeSet<_> = expected_chains
        .keys()
        .copied()
        .filter(|name| *name != shape.owner_chain)
        .collect();
    for chain in non_owner {
        let actual = actual_by_chain.remove(chain).unwrap_or_default();
        let expected = expected_by_chain.remove(chain).unwrap_or_default();
        ensure!(actual.len() == expected.len(), "rule count differs");
        for (actual, expected) in actual.into_iter().zip(expected) {
            ensure!(
                string(actual, "comment") == expected.comment
                    && actual.get("expr") == Some(&Value::Array(expected.expressions.clone())),
                "rule in chain {chain:?} differs"
            );
        }
    }
    ensure!(actual_by_chain.is_empty(), "unexpected rule chain remains");
    Ok(session)
}

fn exact_keys(value: &Map<String, Value>, keys: &[&str]) -> bool {
    value.len() == keys.len() && keys.iter().all(|key| value.contains_key(*key))
}

fn string<'a>(value: &'a Map<String, Value>, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn integer(value: &Map<String, Value>, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or_default()
}

fn counter_only(value: Option<&Value>) -> bool {
    let Some([expression]) = value.and_then(Value::as_array).map(Vec::as_slice) else {
        return false;
    };
    let Some(counter) = expression
        .as_object()
        .filter(|object| exact_keys(object, &["counter"]))
        .and_then(|object| object.get("counter"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    exact_keys(counter, &["packets", "bytes"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_is_stable_and_field_bound() {
        let first = marker("subnet", ["a", "b"]);
        assert_eq!(first, marker("subnet", ["a", "b"]));
        assert_ne!(first, marker("subnet", ["a", "c"]));
        assert_ne!(first, marker("exit", ["a", "b"]));
    }
}
