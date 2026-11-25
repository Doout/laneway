use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use ipnet::IpNet;
use laneway_protocol::{
    Id,
    v1::{IpPrefix, IpProtocol, PortRange, TrafficSelector},
};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

/// Deserialize the Go protobuf JSON spelling used by both old and new rows.
pub(crate) fn decode_selector_json(text: &str) -> Result<TrafficSelector> {
    serde_json::from_str::<Object<Input>>(text)
        .context("selector must be strict TrafficSelector protojson")?
        .0
        .try_into()
}

pub(super) struct Object<T>(pub(super) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }
        decoder.deserialize_map(ObjectVisitor(std::marker::PhantomData))
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Input {
    #[serde(alias = "sourceNodeIds")]
    source_node_ids: Option<Vec<String>>,
    #[serde(alias = "sourcePrefixes")]
    source_prefixes: Option<Vec<Object<Prefix>>>,
    #[serde(alias = "destinationNodeIds")]
    destination_node_ids: Option<Vec<String>>,
    #[serde(alias = "destinationPrefixes")]
    destination_prefixes: Option<Vec<Object<Prefix>>>,
    #[serde(alias = "ipProtocol")]
    ip_protocol: Option<Box<RawValue>>,
    #[serde(alias = "destinationPorts")]
    destination_ports: Option<Vec<Object<Ports>>>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Prefix {
    address: Option<String>,
    #[serde(alias = "prefixLength")]
    prefix_length: Option<Box<RawValue>>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Ports {
    first: Option<Box<RawValue>>,
    last: Option<Box<RawValue>>,
}

impl TryFrom<Input> for TrafficSelector {
    type Error = anyhow::Error;

    fn try_from(input: Input) -> Result<Self> {
        fn ids(values: Option<Vec<String>>) -> Result<Vec<Vec<u8>>> {
            values
                .unwrap_or_default()
                .into_iter()
                .map(|value| decode_bytes(&value))
                .collect()
        }
        fn prefixes(values: Option<Vec<Object<Prefix>>>) -> Result<Vec<IpPrefix>> {
            values
                .unwrap_or_default()
                .into_iter()
                .map(|Object(prefix)| {
                    Ok(IpPrefix {
                        address: decode_bytes(prefix.address.as_deref().unwrap_or_default())?,
                        prefix_length: unsigned(prefix.prefix_length.as_deref())?,
                    })
                })
                .collect()
        }
        let ip_protocol = match input.ip_protocol.as_deref().map(RawValue::get) {
            None => 0,
            Some(value) if value.starts_with('"') => {
                let name: String = serde_json::from_str(value)?;
                IpProtocol::from_str_name(&name).context("invalid selector protocol enum name")?
                    as i32
            }
            Some(value) => signed_integer(value)
                .and_then(|number| i32::try_from(number).ok())
                .context("invalid selector protocol enum number")?,
        };
        let destination_ports = input
            .destination_ports
            .unwrap_or_default()
            .into_iter()
            .map(|Object(ports)| {
                Ok(PortRange {
                    first: unsigned(ports.first.as_deref())?,
                    last: unsigned(ports.last.as_deref())?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            source_node_ids: ids(input.source_node_ids)?,
            source_prefixes: prefixes(input.source_prefixes)?,
            destination_node_ids: ids(input.destination_node_ids)?,
            destination_prefixes: prefixes(input.destination_prefixes)?,
            ip_protocol,
            destination_ports,
        })
    }
}

fn unsigned(value: Option<&RawValue>) -> Result<u32> {
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

fn decode_bytes(value: &str) -> Result<Vec<u8>> {
    // Go protojson accepts both base64 alphabets with and without padding.
    let value: String = value
        .chars()
        .filter(|ch| !matches!(ch, '\r' | '\n'))
        .collect();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&value).ok())
        .context("invalid selector base64 bytes")
}

pub(super) fn validate(selector: &TrafficSelector) -> Result<()> {
    for raw in selector
        .source_node_ids
        .iter()
        .chain(&selector.destination_node_ids)
    {
        if raw.len() != 16 {
            bail!("selector node IDs must be exactly 16 bytes");
        }
        Id::from_slice(raw).context("selector node IDs must be nonzero")?;
    }
    for prefix in selector
        .source_prefixes
        .iter()
        .chain(&selector.destination_prefixes)
    {
        let address = match prefix.address.as_slice() {
            [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
            raw if raw.len() == 16 => {
                let bytes: [u8; 16] = raw.try_into().expect("checked IPv6 length");
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => bail!("selector contains an invalid IP prefix"),
        };
        let length =
            u8::try_from(prefix.prefix_length).context("selector contains an invalid IP prefix")?;
        let parsed =
            IpNet::new(address, length).context("selector contains an invalid IP prefix")?;
        ensure!(
            parsed.addr() == parsed.network(),
            "selector IP prefixes must be canonical"
        );
    }
    let protocol = IpProtocol::try_from(selector.ip_protocol)
        .context("selector ip_protocol must be explicit")?;
    ensure!(
        protocol != IpProtocol::Unspecified,
        "selector ip_protocol must be explicit"
    );
    for range in &selector.destination_ports {
        ensure!(
            range.first > 0 && range.first <= range.last && range.last <= u32::from(u16::MAX),
            "selector contains an invalid destination port range"
        );
        ensure!(
            matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp),
            "selector destination ports require TCP or UDP"
        );
    }
    Ok(())
}

pub(super) fn canonical(selector: &TrafficSelector) -> Value {
    let mut out = Map::new();
    for (name, values) in [
        ("source_node_ids", &selector.source_node_ids),
        ("destination_node_ids", &selector.destination_node_ids),
    ] {
        if !values.is_empty() {
            out.insert(
                name.into(),
                json!(
                    values
                        .iter()
                        .map(|value| STANDARD.encode(value))
                        .collect::<Vec<_>>()
                ),
            );
        }
    }
    for (name, prefixes) in [
        ("source_prefixes", &selector.source_prefixes),
        ("destination_prefixes", &selector.destination_prefixes),
    ] {
        if !prefixes.is_empty() {
            out.insert(
                name.into(),
                Value::Array(
                    prefixes
                        .iter()
                        .map(|prefix| {
                            let mut map = Map::new();
                            if !prefix.address.is_empty() {
                                map.insert(
                                    "address".into(),
                                    json!(STANDARD.encode(&prefix.address)),
                                );
                            }
                            if prefix.prefix_length != 0 {
                                map.insert("prefix_length".into(), json!(prefix.prefix_length));
                            }
                            Value::Object(map)
                        })
                        .collect(),
                ),
            );
        }
    }
    if selector.ip_protocol != 0 {
        out.insert(
            "ip_protocol".into(),
            match IpProtocol::try_from(selector.ip_protocol) {
                Ok(protocol) => json!(protocol.as_str_name()),
                Err(_) => json!(selector.ip_protocol),
            },
        );
    }
    if !selector.destination_ports.is_empty() {
        out.insert(
            "destination_ports".into(),
            Value::Array(
                selector
                    .destination_ports
                    .iter()
                    .map(|range| {
                        let mut map = Map::new();
                        if range.first != 0 {
                            map.insert("first".into(), json!(range.first));
                        }
                        if range.last != 0 {
                            map.insert("last".into(), json!(range.last));
                        }
                        Value::Object(map)
                    })
                    .collect(),
            ),
        );
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_aliases_and_emits_go_proto_field_names() {
        let selector = decode_selector_json(r#"{"destinationPrefixes":[{"address":"CgAAAA","prefixLength":"8"}],"ipProtocol":6,"destinationPorts":[{"first":"443","last":443}]}"#).unwrap();
        validate(&selector).unwrap();
        assert_eq!(
            canonical(&selector),
            json!({
                "destination_prefixes":[{"address":"CgAAAA==","prefix_length":8}],
                "ip_protocol":"IP_PROTOCOL_TCP",
                "destination_ports":[{"first":443,"last":443}],
            })
        );
    }

    #[test]
    fn rejects_unknown_and_duplicate_aliases_and_invalid_selectors() {
        for raw in [
            "[]",
            r#"{"ipProtocol":6,"ip_protocol":6}"#,
            r#"{"source_node_ids":[null],"ip_protocol":6}"#,
            r#"{"destination_ports":[[443,443]],"ip_protocol":6}"#,
            r#"{"destination_prefixes":[{"address":"CgAAAA==","unexpected":8}],"ip_protocol":6}"#,
            r#"{"ip_protocol":6,"destination_ports":[{"first":4.0000000000000000001,"last":443}]}"#,
        ] {
            assert!(decode_selector_json(raw).is_err(), "{raw}");
        }
        for raw in [
            "{}",
            r#"{"ip_protocol":999}"#,
            r#"{"ip_protocol":6,"source_node_ids":["AAAAAAAAAAAAAAAAAAAAAA=="]}"#,
            r#"{"ip_protocol":6,"destination_prefixes":[{"address":"CgAAAQ==","prefix_length":8}]}"#,
            r#"{"ip_protocol":256,"destination_ports":[{"first":1,"last":1}]}"#,
            r#"{"ip_protocol":17,"destination_ports":[{"first":1,"last":65536}]}"#,
        ] {
            let selector = decode_selector_json(raw).unwrap();
            assert!(validate(&selector).is_err(), "{raw}");
        }
    }

    #[test]
    fn accepts_exact_integral_json_numbers_without_rounding() {
        let selector = decode_selector_json(
            r#"{"ip_protocol":60e-1,"destination_ports":[{"first":"4.43e2","last":443.0}]}"#,
        )
        .unwrap();
        validate(&selector).unwrap();
        assert_eq!(selector.ip_protocol, IpProtocol::Tcp as i32);
        assert_eq!(
            selector.destination_ports,
            [PortRange {
                first: 443,
                last: 443
            }]
        );
    }
}
