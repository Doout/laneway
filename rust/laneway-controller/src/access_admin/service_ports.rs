//! One service port format for writes, inventory, and policy compilation.
use super::AccessError;
use anyhow::{Result, ensure};
use laneway_protocol::{Id, v1::IpProtocol};
use rusqlite::{Statement, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Port {
    pub first: u16,
    pub last: u16,
}

impl ServiceProtocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
        }
    }
    pub fn supports_ports(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }
    pub(crate) fn from_stored(value: &str) -> Result<Self> {
        match value {
            "any" => Ok(Self::Any),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            "icmpv6" => Ok(Self::Icmpv6),
            _ => anyhow::bail!("invalid stored service protocol"),
        }
    }
    pub(crate) fn wire(self) -> IpProtocol {
        match self {
            Self::Any => IpProtocol::Any,
            Self::Tcp => IpProtocol::Tcp,
            Self::Udp => IpProtocol::Udp,
            Self::Icmp => IpProtocol::Icmp,
            Self::Icmpv6 => IpProtocol::Icmpv6,
        }
    }
}

pub(super) fn canonical(proto: ServiceProtocol, mut ports: Vec<Port>) -> Result<Vec<Port>> {
    ensure!(
        proto.supports_ports() != ports.is_empty()
            && ports.len() <= 256
            && ports.iter().all(|p| p.first > 0 && p.first <= p.last),
        AccessError::Invalid("invalid service port ranges or protocol")
    );
    ports.sort_unstable_by_key(|p| (p.first, p.last));
    let mut merged: Vec<Port> = Vec::with_capacity(ports.len());
    for port in ports {
        if let Some(last) = merged
            .last_mut()
            .filter(|p| port.first <= p.last.saturating_add(1))
        {
            last.last = last.last.max(port.last);
        } else {
            merged.push(port);
        }
    }
    Ok(merged)
}

pub(crate) fn prepare<'a>(tx: &'a Transaction<'_>) -> rusqlite::Result<Statement<'a>> {
    tx.prepare("SELECT first_port,last_port FROM access_service_ports WHERE service_id=? ORDER BY first_port,last_port LIMIT 257")
}

pub(crate) fn read(stmt: &mut Statement<'_>, id: Id, proto: ServiceProtocol) -> Result<Vec<Port>> {
    let mut rows = stmt.query([id.as_bytes()])?;
    let mut ports: Vec<Port> = Vec::new();
    while let Some(row) = rows.next()? {
        let port = Port {
            first: row.get(0)?,
            last: row.get(1)?,
        };
        ensure!(
            ports.len() < 256
                && port.first > 0
                && port.first <= port.last
                && ports
                    .last()
                    .is_none_or(|p| p.last.saturating_add(1) < port.first),
            "noncanonical stored service port ranges"
        );
        ports.push(port)
    }
    ensure!(
        proto.supports_ports() != ports.is_empty(),
        "incorrect port set for stored service protocol"
    );
    Ok(ports)
}
