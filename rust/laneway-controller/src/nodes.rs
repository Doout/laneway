use super::Inventory;
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Serialize)]
pub struct Node {
    pub node_id: String,
    pub network_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub name: String,
    pub enabled_capabilities: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<Ipv6Addr>,
    pub created_at_unix_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_seconds: Option<i64>,
    pub enrollment_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at_unix_seconds: Option<i64>,
}

impl Inventory {
    /// Includes historical nodes, but only the most recent unreleased address
    /// of each family. A missing network is distinct from an empty network.
    pub fn nodes(&mut self, network: Id, limit: usize) -> Result<Vec<Node>> {
        let tx = self.snapshot(limit)?;
        let result = read_nodes(&tx, network, limit)?;
        tx.commit()?;
        Ok(result)
    }
}

pub(super) fn read_nodes(
    tx: &rusqlite::Transaction<'_>,
    network: Id,
    limit: usize,
) -> Result<Vec<Node>> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
        [network.as_bytes()],
        |r| r.get(0),
    )?;
    ensure!(exists, "network not found");
    let mut stmt = tx.prepare(
        "SELECT n.id,n.user_id,n.name,n.enabled_capabilities,n.created_at,n.revoked_at,
              n.enrollment_class,n.lease_expires_at,n.wireguard_public_key,
              (SELECT address FROM overlay_addresses WHERE node_id=n.id AND released_at IS NULL
               AND length(address)=4 ORDER BY created_at DESC,id DESC LIMIT 1),
              (SELECT address FROM overlay_addresses WHERE node_id=n.id AND released_at IS NULL
               AND length(address)=16 ORDER BY created_at DESC,id DESC LIMIT 1)
             FROM nodes n WHERE n.network_id=?1 ORDER BY n.created_at,n.id LIMIT ?2",
    )?;
    let mut rows = stmt.query((network.as_bytes(), limit as i64))?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let enrollment_class: String = row.get(6)?;
        let lease: Option<i64> = row.get(7)?;
        ensure!(
            matches!(
                (enrollment_class.as_str(), lease),
                ("durable" | "remembered", None) | ("ephemeral", Some(_))
            ),
            "invalid node enrollment class or lease"
        );
        if let Some(key) = row.get::<_, Option<[u8; 32]>>(8)? {
            // Match the Go store's low-order X25519 input check. This
            // scalar is public and used only to validate a public key.
            ensure!(
                x25519_dalek::x25519([1; 32], key) != [0; 32],
                "invalid node WireGuard public key"
            );
        }
        let ipv6_address = row.get::<_, Option<[u8; 16]>>(10)?.map(Ipv6Addr::from);
        ensure!(
            ipv6_address.is_none_or(|a| a.to_ipv4_mapped().is_none()),
            "invalid mapped IPv6 overlay"
        );
        result.push(Node {
            node_id: Id::new(row.get(0)?)?.to_string(),
            network_id: network.to_string(),
            user_id: row
                .get::<_, Option<[u8; 16]>>(1)?
                .map(Id::new)
                .transpose()?
                .map(|id| id.to_string()),
            name: row.get(2)?,
            enabled_capabilities: u64::try_from(row.get::<_, i64>(3)?)?,
            created_at_unix_seconds: row.get(4)?,
            revoked_at_unix_seconds: row.get(5)?,
            enrollment_class,
            lease_expires_at_unix_seconds: lease,
            ipv4_address: row.get::<_, Option<[u8; 4]>>(9)?.map(Ipv4Addr::from),
            ipv6_address,
        });
    }
    Ok(result)
}
