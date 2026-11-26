//! Decode the strict protojson ACL selectors persisted by Go.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose as b64};
use laneway_protocol::{
    DEFAULT_MAX_CONTROL_PAYLOAD, Id,
    policy::CompiledPolicy,
    v1::{
        IpPrefix, IpProtocol, PolicyAction, PolicyRule, PolicySnapshot, PortRange, TrafficSelector,
    },
};
use prost::Message;
use rusqlite::Transaction;
use serde::{Deserialize, Deserializer, de::Error as _};
use serde_json::{Value, json, value::RawValue};
use std::borrow::Cow;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Selector {
    #[serde(alias = "sourceNodeIds")]
    source_node_ids: Option<Vec<String>>,
    #[serde(alias = "destinationNodeIds")]
    destination_node_ids: Option<Vec<String>>,
    #[serde(alias = "sourcePrefixes")]
    source_prefixes: Option<Vec<Prefix>>,
    #[serde(alias = "destinationPrefixes")]
    destination_prefixes: Option<Vec<Prefix>>,
    #[serde(alias = "ipProtocol")]
    ip_protocol: Option<Box<RawValue>>,
    #[serde(alias = "destinationPorts")]
    destination_ports: Option<Vec<Range>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prefix {
    address: String,
    #[serde(default, alias = "prefixLength")]
    prefix_length: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    first: Option<Box<RawValue>>,
    last: Option<Box<RawValue>>,
}

fn number(value: Option<&RawValue>) -> Result<u32> {
    let Some(raw) = value.map(RawValue::get) else {
        return Ok(0);
    };
    let text;
    let raw = if raw.starts_with('"') {
        text = serde_json::from_str::<String>(raw)?;
        text.as_str()
    } else {
        raw
    };
    signed_integer(raw)
        .and_then(|number| u32::try_from(number).ok())
        .context("invalid selector unsigned integer")
}

// Protobuf JSON accepts integral exponents and decimals, but never rounds a
// fraction to an integer. Work on the token text to preserve that boundary.
fn signed_integer(raw: &str) -> Option<i64> {
    let (negative, raw) = raw
        .strip_prefix('-')
        .map_or((false, raw), |text| (true, text));
    let (mantissa, exponent) = raw.split_once(['e', 'E']).unwrap_or((raw, "0"));
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let decimal = mantissa.contains('.');
    let exponent_digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
    if whole.is_empty()
        || (whole.len() > 1 && whole.starts_with('0'))
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || (decimal && fraction.is_empty())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || exponent_digits.is_empty()
        || !exponent_digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.trim_start_matches('0');
    let fraction = fraction.trim_end_matches('0');
    if whole.is_empty() && fraction.is_empty() {
        return Some(0);
    }
    let exponent: i32 = exponent.parse().ok()?;
    let mut normalized = String::with_capacity(21);
    if negative {
        normalized.push('-');
    }
    if exponent >= 0 {
        let exponent = exponent as usize;
        if fraction.len() > exponent || whole.len().checked_add(exponent)? > 20 {
            return None;
        }
        normalized.push_str(whole);
        normalized.push_str(fraction);
        normalized.extend(std::iter::repeat_n('0', exponent - fraction.len()));
    } else {
        if !fraction.is_empty() {
            return None;
        }
        let end = whole.len().checked_sub(exponent.unsigned_abs() as usize)?;
        if end > 20 || !whole.as_bytes()[end..].iter().all(|byte| *byte == b'0') {
            return None;
        }
        normalized.push_str(&whole[..end]);
    }
    normalized.parse().ok()
}

fn bytes(v: &str) -> Result<Vec<u8>> {
    let v = if v.contains(['\r', '\n']) {
        Cow::Owned(v.replace(['\r', '\n'], ""))
    } else {
        Cow::Borrowed(v)
    };
    for engine in [
        b64::STANDARD,
        b64::STANDARD_NO_PAD,
        b64::URL_SAFE,
        b64::URL_SAFE_NO_PAD,
    ] {
        if let Ok(raw) = engine.decode(v.as_bytes()) {
            return Ok(raw);
        }
    }
    anyhow::bail!("invalid ACL bytes")
}

fn ids(v: Option<Vec<String>>) -> Result<Vec<Vec<u8>>> {
    v.unwrap_or_default()
        .into_iter()
        .map(|id| bytes(&id))
        .collect()
}
fn prefixes(v: Option<Vec<Prefix>>) -> Result<Vec<IpPrefix>> {
    v.unwrap_or_default()
        .into_iter()
        .map(|p| {
            Ok(IpPrefix {
                address: bytes(&p.address)?,
                prefix_length: number(p.prefix_length.as_deref())?,
            })
        })
        .collect()
}

fn parse(raw: &str) -> Result<TrafficSelector> {
    // Do not deserialize through a Value map: duplicate selector fields
    // would otherwise silently change the scope of authorization.
    serde_json::from_str::<AclSelector>(raw)
        .map(|selector| selector.0)
        .map_err(Into::into)
}

pub struct AclSelector(TrafficSelector);

impl<'de> Deserialize<'de> for AclSelector {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let fields = Selector::deserialize(d)?;
        selector_from_fields(fields)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

fn selector_from_fields(v: Selector) -> Result<TrafficSelector> {
    let ip_protocol = match v.ip_protocol.as_deref().map(RawValue::get) {
        Some(raw) if raw.starts_with('"') => {
            let name = serde_json::from_str::<String>(raw)?;
            IpProtocol::from_str_name(&name).context("unknown ACL protocol")? as i32
        }
        Some(raw) => signed_integer(raw)
            .and_then(|number| i32::try_from(number).ok())
            .context("invalid ACL protocol number")?,
        None => 0,
    };
    Ok(TrafficSelector {
        source_node_ids: ids(v.source_node_ids)?,
        destination_node_ids: ids(v.destination_node_ids)?,
        source_prefixes: prefixes(v.source_prefixes)?,
        destination_prefixes: prefixes(v.destination_prefixes)?,
        ip_protocol,
        destination_ports: v
            .destination_ports
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                Ok(PortRange {
                    first: number(r.first.as_deref())?,
                    last: number(r.last.as_deref())?,
                })
            })
            .collect::<Result<_>>()?,
    })
}

impl AclSelector {
    pub(super) fn validated_wire(self) -> Result<TrafficSelector> {
        Self(self.0.clone()).canonical_management_json()?;
        Ok(self.0)
    }

    pub(crate) fn canonical_management_json(self) -> Result<Value> {
        let v = self.0;
        let protocol = IpProtocol::try_from(v.ip_protocol)?;
        ensure!(
            protocol != IpProtocol::Unspecified,
            "selector ip_protocol must be explicit"
        );
        let mut result = json!({"ip_protocol":protocol.as_str_name()});
        for (name, nodes) in [
            ("source_node_ids", v.source_node_ids),
            ("destination_node_ids", v.destination_node_ids),
        ] {
            if nodes.is_empty() {
                continue;
            }
            let values = nodes
                .iter()
                .map(|id| {
                    Id::from_slice(id)?;
                    Ok(b64::STANDARD.encode(id))
                })
                .collect::<Result<Vec<_>>>()?;
            result[name] = json!(values);
        }
        for (name, prefixes) in [
            ("source_prefixes", v.source_prefixes),
            ("destination_prefixes", v.destination_prefixes),
        ] {
            if prefixes.is_empty() {
                continue;
            }
            let values = prefixes
                .into_iter()
                .map(|p| {
                    laneway_protocol::policy::prefix_from_wire(p.clone())?;
                    let mut encoded = json!({"address":b64::STANDARD.encode(p.address)});
                    if p.prefix_length != 0 {
                        encoded["prefix_length"] = json!(p.prefix_length);
                    }
                    Ok(encoded)
                })
                .collect::<Result<Vec<_>>>()?;
            result[name] = json!(values);
        }
        if !v.destination_ports.is_empty() {
            ensure!(
                matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp),
                "destination ports require TCP or UDP"
            );
            let ports = v
                .destination_ports
                .into_iter()
                .map(|p| {
                    ensure!(
                        p.first > 0 && p.first <= p.last && p.last <= 65535,
                        "invalid port range"
                    );
                    Ok(json!({"first":p.first,"last":p.last}))
                })
                .collect::<Result<Vec<_>>>()?;
            result["destination_ports"] = json!(ports);
        }
        Ok(result)
    }
}

pub(crate) fn compile(tx: &Transaction<'_>, net: Id, epoch: u64) -> Result<PolicySnapshot> {
    let mut stmt=tx.prepare("SELECT id,priority,action,selector_json,description FROM acl_rules WHERE network_id=? AND enabled=1 ORDER BY priority,id LIMIT 4097")?;
    let mut rows = stmt.query([net.as_bytes()])?;
    let mut policy = PolicySnapshot {
        network_id: net.as_bytes().to_vec(),
        configuration_epoch: epoch,
        default_action: PolicyAction::Deny as i32,
        rules: Vec::new(),
    };
    let mut bytes = 0;
    while let Some(r) = rows.next()? {
        ensure!(policy.rules.len() < 4096, "too many ACL rules");
        let raw: String = r.get(3)?;
        ensure!(raw.len() <= 131072, "oversized ACL selector");
        let action = match r.get::<_, String>(2)?.as_str() {
            "accept" => PolicyAction::Accept,
            "deny" => PolicyAction::Deny,
            _ => anyhow::bail!("invalid stored ACL action"),
        };
        let rule = PolicyRule {
            rule_id: r.get(0)?,
            priority: r.get(1)?,
            action: action as i32,
            selector: Some(parse(&raw)?),
            description: r.get(4)?,
        };
        bytes += rule.encoded_len() + 8;
        ensure!(
            bytes <= DEFAULT_MAX_CONTROL_PAYLOAD,
            "ACL rules exceed configuration frame limit"
        );
        policy.rules.push(rule);
    }
    CompiledPolicy::compile(policy.clone(), net, epoch)?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_protojson_integers() {
        let selector = parse(
            r#"{"ipProtocol":"IP_PROTOCOL_TCP","sourcePrefixes":[{"address":"CgA\nAAA==","prefixLength":8.0}],"destinationPorts":[{"first":"4.43e2","last":4430e-1}]}"#,
        )
        .unwrap();
        assert_eq!(selector.ip_protocol, IpProtocol::Tcp as i32);
        assert_eq!(
            parse(r#"{"ipProtocol":6e0}"#).unwrap().ip_protocol,
            selector.ip_protocol
        );
        assert_eq!(selector.source_prefixes[0].address, [10, 0, 0, 0]);
        assert_eq!(selector.source_prefixes[0].prefix_length, 8);
        assert_eq!(
            selector.destination_ports,
            [PortRange {
                first: 443,
                last: 443
            }]
        );
    }

    #[test]
    fn defaults_do_not_publish_incomplete_port_ranges() {
        for raw in [
            r#"{"ipProtocol":"IP_PROTOCOL_TCP","destinationPorts":[{"first":443}]}"#,
            r#"{"ipProtocol":"IP_PROTOCOL_TCP","destinationPorts":[{"first":443,"last":null}]}"#,
        ] {
            let selector = parse(raw).unwrap();
            assert_eq!(selector.destination_ports[0].last, 0);
            assert!(AclSelector(selector).canonical_management_json().is_err());
        }
    }

    #[test]
    fn rejects_rounded_overflow_and_duplicate_acl_fields() {
        for raw in [
            r#"{"destinationPorts":[{"first":443.000000000000000001}]}"#,
            r#"{"destinationPorts":[{"first":"4.4300000000000001e2"}]}"#,
            r#"{"destinationPorts":[{"first":4294967296}]}"#,
            r#"{"ipProtocol":"IP_PROTOCOL_TCP","ip_protocol":"IP_PROTOCOL_UDP"}"#,
        ] {
            assert!(parse(raw).is_err(), "{raw}");
        }
    }
}
