//! A network and its actor-attributed audit record commit together. Caller
//! credentials are verified against the same snapshot that accepts the write.
use crate::{Network, RootCredential, SessionReply, SessionStore, management_write::BrowserWrite};
use anyhow::{Result, ensure};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use laneway_protocol::Id;
use rusqlite::{Transaction, params};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, MapAccess, Visitor},
};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("{0}")]
    Malformed(&'static str),
    #[error("request conflicts with controller state")]
    Conflict,
}

#[derive(Default)]
pub struct CreateNetwork {
    network_id: Option<String>,
    name: Option<String>,
    ipv4_pool: Option<String>,
    ipv6_pool: Option<String>,
}

// The existing management API uses Go's encoding/json string fields:
// ASCII case-insensitive names, last non-null value wins, unknown keys fail.
impl<'de> Deserialize<'de> for CreateNetwork {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = CreateNetwork;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a network definition")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut form = CreateNetwork::default();
                while let Some(key) = map.next_key::<String>()? {
                    let slot = match key.to_ascii_lowercase().as_str() {
                        "name" => &mut form.name,
                        "network_id" => &mut form.network_id,
                        "ipv4_pool" => &mut form.ipv4_pool,
                        "ipv6_pool" => &mut form.ipv6_pool,
                        _ => return Err(A::Error::custom("unknown network field")),
                    };
                    if let Some(value) = map.next_value::<Option<String>>()? {
                        *slot = Some(value)
                    }
                }
                Ok(form)
            }
        }
        d.deserialize_map(Fields)
    }
}

fn canonical(s: &str, detail: &'static str) -> Result<IpNet> {
    s.parse::<IpNet>()
        .ok()
        .filter(|p| p.to_string() == s)
        .ok_or_else(|| NetworkError::Malformed(detail).into())
}

// Prefixes can cover a forbidden range even when the first address is not
// itself forbidden (e.g. 169.0.0.0/8 contains the link-local /16).
fn routable4(p: Ipv4Net) -> bool {
    (8..=30).contains(&p.prefix_len())
        && p == p.trunc()
        && ![
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(127, 0, 0, 0),
            Ipv4Addr::new(169, 254, 0, 0),
            Ipv4Addr::new(224, 0, 0, 0),
        ]
        .iter()
        .any(|ip| p.contains(ip))
        && !p.addr().is_loopback()
        && !p.addr().is_link_local()
        && !p.addr().is_multicast()
}
fn routable6(p: Ipv6Net) -> bool {
    let a = p.addr();
    (64..=120).contains(&p.prefix_len())
        && p == p.trunc()
        && a.to_ipv4_mapped().is_none()
        && !p.contains(&Ipv6Addr::UNSPECIFIED)
        && !p.contains(&Ipv6Addr::LOCALHOST)
        && !a.is_unicast_link_local()
        && !a.is_multicast()
}

impl CreateNetwork {
    fn pools(&self) -> Result<(IpNet, Option<IpNet>)> {
        let p4 = canonical(
            self.ipv4_pool.as_deref().unwrap_or_default(),
            "ipv4_pool must be a canonical CIDR prefix",
        )?;
        let p6 = self
            .ipv6_pool
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| canonical(s, "ipv6_pool must be a canonical CIDR prefix"))
            .transpose()?;
        Ok((p4, p6))
    }

    fn insert(
        self,
        tx: &Transaction<'_>,
        kind: &str,
        actor: Id,
        now: i64,
        pools: (IpNet, Option<IpNet>),
    ) -> Result<Network> {
        let (p4, p6) = pools;
        let id = match self.network_id.filter(|s| !s.is_empty()) {
            Some(s) => s.parse::<Id>().map_err(|_| {
                NetworkError::Malformed("network_id must be a canonical non-zero ID")
            })?,
            None => {
                let mut bytes = [0; 16];
                getrandom::fill(&mut bytes)?;
                Id::new(bytes)?
            }
        };
        let invalid = || NetworkError::Malformed("invalid request");
        let name = self.name.unwrap_or_default();
        ensure!(
            name.trim() == name && !name.is_empty() && name.len() <= 253 && !name.contains('\0'),
            invalid()
        );
        let IpNet::V4(p4) = p4 else {
            return Err(invalid().into());
        };
        ensure!(routable4(p4), invalid());
        let p6 = match p6 {
            None => None,
            Some(IpNet::V6(p)) if routable6(p) => Some(p),
            _ => return Err(invalid().into()),
        };
        let result=tx.execute("INSERT INTO networks(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length)
            VALUES(?1,?2,?3,?4,1,1,?5,?6,?7)",params![id.as_bytes(),name,p4.addr().octets(),p4.prefix_len(),now,p6.map(|p|p.addr().octets()),p6.map(|p|p.prefix_len())]);
        if let Err(e) = result {
            if e.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                return Err(NetworkError::Conflict.into());
            }
            return Err(e.into());
        }
        tx.execute("INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
            VALUES(randomblob(16),?1,?2,?3,'network.create','network',?1,'{}',?4)",(id.as_bytes(),kind,actor.as_bytes(),now))?;
        Ok(Network {
            network_id: id.to_string(),
            name,
            ipv4_pool: p4.to_string(),
            ipv6_pool: p6.map(|p| p.to_string()),
            configuration_epoch: 1,
            created_at_unix_seconds: now,
        })
    }
}

impl SessionStore {
    pub fn create_network(
        &mut self,
        token: &str,
        csrf: Option<&str>,
        form: Result<CreateNetwork>,
    ) -> Result<SessionReply<Network>> {
        self.browser_write(
            token,
            csrf,
            BrowserWrite::CreateNetwork,
            |tx, actor, _, now| {
                let form = form?;
                let pools = form.pools()?;
                form.insert(tx, "administrator", actor, now, pools)
            },
        )
    }
    pub fn bearer_create_network(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        form: Result<CreateNetwork>,
    ) -> Result<Network> {
        self.bearer_write(header, root, |tx, actor, now| {
            let form = form?;
            let pools = form.pools()?;
            actor.authorize(tx, "network.create", None)?;
            form.insert(tx, "service_principal", actor.id, now, pools)
        })
    }
}
