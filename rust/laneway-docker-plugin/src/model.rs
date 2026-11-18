use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{Error, Result, conflict, invalid};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Egress {
    #[default]
    Direct,
    Selective,
    FullTunnel,
    Isolated,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ingress {
    #[default]
    Deny,
    Established,
    Allow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub egress: Egress,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_cidrs: Vec<Ipv4Net>,
    pub ingress: Ingress,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress_sources: Vec<Ipv4Net>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exit: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
    pub fail_mode: String,
    pub mtu: u16,
    #[serde(default, skip_serializing_if = "is_false")]
    pub nat: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Policy {
    pub fn from_options(values: Option<&Value>) -> Result<Self> {
        let mut options = BTreeMap::new();
        fn flatten<'a>(value: &'a Value, options: &mut BTreeMap<&'a str, &'a str>) -> Result<()> {
            if let Some(object) = value.as_object() {
                for (key, value) in object {
                    if let Some(text) = value.as_str() {
                        if key.starts_with("laneway.")
                            && options
                                .insert(key, text.trim())
                                .is_some_and(|first| first != text.trim())
                        {
                            return Err(invalid(format!("conflicting Docker options for {key}")));
                        }
                    } else {
                        flatten(value, options)?;
                    }
                }
            }
            Ok(())
        }
        if let Some(values) = values {
            flatten(values, &mut options)?;
        }
        let text = |key, default| {
            options
                .get(key)
                .copied()
                .filter(|text| !text.is_empty())
                .unwrap_or(default)
        };
        let policy = Self {
            egress: match text("laneway.policy", "direct") {
                "direct" => Egress::Direct,
                "selective" => Egress::Selective,
                "full-tunnel" => Egress::FullTunnel,
                "isolated" => Egress::Isolated,
                _ => return Err(invalid("unknown egress policy")),
            },
            ingress: match text("laneway.ingress", "deny") {
                "deny" => Ingress::Deny,
                "established" => Ingress::Established,
                "allow" => Ingress::Allow,
                _ => return Err(invalid("unknown ingress policy")),
            },
            egress_cidrs: prefixes(text("laneway.egress-cidrs", ""))?,
            ingress_sources: prefixes(text("laneway.ingress-sources", ""))?,
            exit: text("laneway.exit", "").into(),
            dns: list(text("laneway.dns", ""))?,
            fail_mode: text("laneway.fail-mode", "closed").into(),
            mtu: text("laneway.mtu", "1380")
                .parse()
                .map_err(|_| invalid("invalid Docker MTU"))?,
            nat: match text("laneway.nat", "false") {
                "1" | "t" | "T" | "true" | "TRUE" | "True" => true,
                "0" | "f" | "F" | "false" | "FALSE" | "False" => false,
                _ => return Err(invalid("laneway.nat must be a boolean")),
            },
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        if self.fail_mode != "closed" || !(576..=9000).contains(&self.mtu) {
            return Err(invalid(
                "expected fail mode closed and MTU 576 through 9000",
            ));
        }
        if (self.egress == Egress::Selective && self.egress_cidrs.is_empty())
            || (self.egress == Egress::Direct && !self.egress_cidrs.is_empty())
            || (self.egress == Egress::FullTunnel) == self.exit.is_empty()
            || (self.ingress == Ingress::Allow) == self.ingress_sources.is_empty()
        {
            return Err(invalid(
                "egress, exit, and ingress options do not match the selected policy",
            ));
        }
        validate_prefixes(&self.egress_cidrs)?;
        validate_prefixes(&self.ingress_sources)?;
        Ok(())
    }

    pub fn needs_grant(&self) -> bool {
        self.egress != Egress::Direct || self.ingress == Ingress::Allow
    }
}

fn list<T: std::str::FromStr>(text: &str) -> Result<Vec<T>> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|raw| {
            raw.trim()
                .parse()
                .map_err(|_| invalid("invalid IPv4 option list"))
        })
        .collect()
}

fn prefixes(text: &str) -> Result<Vec<Ipv4Net>> {
    let unique: BTreeSet<_> = list::<Ipv4Net>(text)?
        .into_iter()
        .map(|prefix| prefix.trunc())
        .collect();
    let mut ordered: Vec<_> = unique.into_iter().collect();
    ordered.sort_by_key(ToString::to_string); // Match the Go v1 selection order.
    Ok(ordered)
}

fn validate_prefixes(values: &[Ipv4Net]) -> Result<()> {
    if values.len() > 256 {
        return Err(invalid("too many policy prefixes"));
    }
    for (index, prefix) in values.iter().enumerate() {
        if *prefix != prefix.trunc()
            || values[..index]
                .iter()
                .any(|other| overlaps(*other, *prefix))
        {
            return Err(invalid("policy has overlapping or non-canonical prefixes"));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Authorization {
    pub epoch: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub valid_until: OffsetDateTime,
    #[serde(deserialize_with = "null_list")]
    pub container_subnets: Vec<Ipv4Net>,
    #[serde(deserialize_with = "null_list")]
    pub egress_cidrs: Vec<Ipv4Net>,
    #[serde(deserialize_with = "null_list")]
    pub ingress_sources: Vec<Ipv4Net>,
    #[serde(deserialize_with = "null_list")]
    pub exits: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub bypass_cidrs: Vec<Ipv4Net>,
}

fn null_list<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(decoder)?.unwrap_or_default())
}

impl Authorization {
    pub fn authorize(&self, now: OffsetDateTime, subnet: Ipv4Net, policy: &Policy) -> Result<()> {
        let covered = |want, allowed: &[Ipv4Net]| {
            allowed
                .iter()
                .any(|prefix| *prefix == prefix.trunc() && prefix.contains(&want))
        };
        let deny = |message: &str| Error::Unauthorized(message.into());
        if self.epoch == 0 || self.valid_until <= now {
            return Err(deny("authorization lease is missing or expired"));
        }
        if !covered(subnet, &self.container_subnets) {
            return Err(deny("container subnet was not granted"));
        }
        if policy
            .egress_cidrs
            .iter()
            .any(|prefix| !covered(*prefix, &self.egress_cidrs))
        {
            return Err(deny("egress prefix was not granted"));
        }
        if policy
            .ingress_sources
            .iter()
            .any(|prefix| !covered(*prefix, &self.ingress_sources))
        {
            return Err(deny("ingress source was not granted"));
        }
        if !policy.exit.is_empty() && !self.exits.contains(&policy.exit) {
            return Err(deny("exit was not granted"));
        }
        check_bypasses(subnet, &self.bypass_cidrs)
    }
}

fn check_bypasses(subnet: Ipv4Net, bypasses: &[Ipv4Net]) -> Result<()> {
    if bypasses.len() > 256
        || bypasses.iter().any(|prefix| {
            prefix.prefix_len() == 0 || *prefix != prefix.trunc() || overlaps(subnet, *prefix)
        })
    {
        return Err(Error::Unauthorized(
            "unsafe controller bypass prefixes".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Creating,
    Active,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub id: String,
    pub bridge: String,
    pub table: u16,
    pub subnet: Ipv4Net,
    pub gateway: Ipv4Addr,
    pub policy: Policy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bypass_cidrs: Vec<Ipv4Net>,
    pub phase: Phase,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, Endpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub address: Ipv4Addr,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_veth: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub peer_veth: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sandbox: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub joined: bool,
    // Older Go readers ignore this field. Never report a joined endpoint
    // until the kernel backend has confirmed its link.
    #[serde(default, skip_serializing_if = "is_false")]
    pub join_pending: bool,
}

impl Endpoint {
    pub fn has_link_intent(&self) -> bool {
        self.joined || self.join_pending
    }
}

impl Network {
    pub(crate) fn validate(&self, id: &str) -> Result<()> {
        if !valid_id(id) || self.id != id || (self.bridge.clone(), self.table) != network_names(id)
        {
            return Err(conflict("invalid recorded network ownership identifiers"));
        }
        if self.subnet != self.subnet.trunc() || !usable(self.subnet, self.gateway) {
            return Err(invalid("invalid IPv4 pool or gateway"));
        }
        self.policy.validate()?;
        if self
            .policy
            .egress_cidrs
            .iter()
            .chain(&self.policy.ingress_sources)
            .any(|prefix| overlaps(self.subnet, *prefix))
        {
            return Err(invalid("policy prefix overlaps the container subnet"));
        }
        check_bypasses(self.subnet, &self.bypass_cidrs)?;
        let mut addresses = BTreeSet::new();
        for (id, endpoint) in &self.endpoints {
            let describes_owned_link = if endpoint.has_link_intent() {
                let (host, peer) = endpoint_names(id);
                endpoint.host_veth == host && endpoint.peer_veth == peer
            } else {
                endpoint.host_veth.is_empty()
                    && endpoint.peer_veth.is_empty()
                    && endpoint.sandbox.is_empty()
            };
            if !valid_id(id)
                || endpoint.id != *id
                || !usable(self.subnet, endpoint.address)
                || self.gateway == endpoint.address
                || !addresses.insert(endpoint.address)
                || !valid_sandbox(&endpoint.sandbox)
                || (endpoint.joined && endpoint.join_pending)
                || !describes_owned_link
            {
                return Err(conflict(
                    "invalid recorded endpoint ownership identifiers or address",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn valid_sandbox(path: &str) -> bool {
    path.len() <= 4096 && !path.bytes().any(|byte| byte.is_ascii_control())
}

pub(crate) fn usable(prefix: Ipv4Net, address: Ipv4Addr) -> bool {
    (1..=30).contains(&prefix.prefix_len())
        && prefix.contains(&address)
        && address != prefix.network()
        && address != prefix.broadcast()
}

pub(crate) fn overlaps(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.addr()) || right.contains(&left.addr())
}

pub(crate) fn network_names(id: &str) -> (String, u16) {
    let hash = Sha256::digest(id.as_bytes());
    (
        format!("lwbr{}", hex::encode(&hash[..5])),
        20_000 + u16::from_be_bytes([hash[5], hash[6]]) % 10_000,
    )
}

pub(crate) fn endpoint_names(id: &str) -> (String, String) {
    let hash = Sha256::digest(id.as_bytes());
    let suffix = hex::encode(&hash[..5]);
    (format!("lwh{suffix}"), format!("lwc{suffix}"))
}
