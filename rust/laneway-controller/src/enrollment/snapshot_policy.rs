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
use serde_json::{Value, json};

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
    ip_protocol: Value,
    #[serde(alias = "destinationPorts")]
    destination_ports: Option<Vec<Range>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prefix {
    address: String,
    #[serde(default, alias = "prefixLength")]
    prefix_length: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    first: Value,
    last: Value,
}

fn number(v: &Value) -> Result<u32> {
    match v {
        Value::Null => Ok(0),
        Value::String(v) => Ok(v.parse()?),
        v => Ok(v.as_u64().context("invalid ACL number")?.try_into()?),
    }
}

fn bytes(v: &str) -> Result<Vec<u8>> {
    for engine in [
        b64::STANDARD,
        b64::STANDARD_NO_PAD,
        b64::URL_SAFE,
        b64::URL_SAFE_NO_PAD,
    ] {
        if let Ok(raw) = engine.decode(v) {
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
                prefix_length: number(&p.prefix_length)?,
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
    let ip_protocol = match v.ip_protocol {
        Value::String(v) => IpProtocol::from_str_name(&v).context("unknown ACL protocol")? as i32,
        v => i32::try_from(number(&v)?)?,
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
                    first: number(&r.first)?,
                    last: number(&r.last)?,
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
