//! Controller storage. Local operator inventory is deliberately separate from
//! network-facing authorization; do not wire it directly to an HTTP handler.
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::Id;
use rusqlite::{Connection, OpenFlags, Transaction};
use serde::Serialize;
mod bearer;
mod browser;
pub use bearer::{RootCredential, bearer_inventory};
pub use browser::auth_state;
mod nodes;
pub mod password;
mod sessions;
pub use nodes::Node;
pub use sessions::{ListError, SessionError, SessionReply, SessionStore};

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InventoryList {
    Networks(Vec<Network>),
    Nodes(Vec<Node>),
}

const SCHEMA_VERSION: i64 = 18;

pub struct Inventory {
    db: Connection,
}

#[derive(Debug, Serialize)]
pub struct Network {
    pub network_id: String,
    pub name: String,
    pub ipv4_pool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_pool: Option<String>,
    pub configuration_epoch: u64,
    pub created_at_unix_seconds: i64,
}

impl Inventory {
    pub fn open(path: &Path) -> Result<Self> {
        let db = open_existing(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        db.execute_batch("PRAGMA query_only=ON")?;
        Ok(Self { db })
    }

    fn snapshot(&mut self, limit: usize) -> Result<Transaction<'_>> {
        let tx = self.db.transaction()?;
        ensure!((1..=1000).contains(&limit), "limit must be 1..1000");
        check_snapshot(&tx)?;
        Ok(tx)
    }

    /// Full local inventory in the same order as Go Store.Networks.
    pub fn networks(&mut self, limit: usize) -> Result<Vec<Network>> {
        let tx = self.snapshot(limit)?;
        let result = read_networks(&tx, limit, None)?;
        tx.commit()?;
        Ok(result)
    }
}

fn open_existing(path: &Path, flags: OpenFlags) -> Result<Connection> {
    ensure!(
        path.is_file(),
        "expected an existing controller database file"
    );
    let db = Connection::open_with_flags(path, flags).context("open controller database")?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON")?;
    Ok(db)
}

fn check_snapshot(tx: &Transaction<'_>) -> Result<()> {
    // Check inside the read snapshot. A migration racing the query cannot
    // switch its schema between validation and data access.
    let versions: (i64, i64, i64) = tx.query_row(
            "SELECT count(*),coalesce(min(version),0),coalesce(max(version),0) FROM schema_versions",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).context("read controller migration history")?;
    ensure!(
        versions == (SCHEMA_VERSION, 1, SCHEMA_VERSION),
        "unsupported controller migration history {versions:?}"
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum Scope {
    Browser(Id),
    Automation(Id),
}

fn read_networks(
    tx: &Transaction<'_>,
    limit: usize,
    restricted: Option<Scope>,
) -> Result<Vec<Network>> {
    const COLUMNS: &str = "SELECT n.id,n.name,n.ipv4_address,n.ipv4_prefix_length,
            n.ipv6_address,n.ipv6_prefix_length,n.configuration_epoch,n.created_at FROM networks n";
    let scope_join = match restricted {
        Some(Scope::Browser(_)) => {
            " JOIN administrator_principal_networks g ON g.network_id=n.id AND g.principal_id=?2"
        }
        Some(Scope::Automation(_)) => {
            " JOIN automation_service_principal_networks g ON g.network_id=n.id AND g.principal_id=?2"
        }
        None => "",
    };
    let mut stmt = tx.prepare(&format!(
        "{COLUMNS}{scope_join} ORDER BY n.created_at,n.id LIMIT ?1"
    ))?;
    let mut rows = match &restricted {
        Some(Scope::Browser(id) | Scope::Automation(id)) => {
            stmt.query((limit as i64, id.as_bytes()))?
        }
        None => stmt.query([limit as i64])?,
    };
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let id = Id::new(row.get(0)?)?;
        let v4 = Ipv4Addr::from(row.get::<_, [u8; 4]>(2)?);
        let v4bits: u8 = row.get(3)?;
        ensure!(
            (8..=30).contains(&v4bits),
            "invalid network IPv4 prefix length"
        );
        let ipv6_pool = match (
            row.get::<_, Option<[u8; 16]>>(4)?,
            row.get::<_, Option<u8>>(5)?,
        ) {
            (None, None) => None,
            (Some(bytes), Some(bits @ 64..=120)) => {
                let addr = Ipv6Addr::from(bytes);
                ensure!(
                    addr.to_ipv4_mapped().is_none(),
                    "invalid mapped IPv6 network"
                );
                Some(format!("{addr}/{bits}"))
            }
            _ => bail!("invalid network IPv6 pool"),
        };
        result.push(Network {
            network_id: id.to_string(),
            name: row.get(1)?,
            ipv4_pool: format!("{v4}/{v4bits}"),
            ipv6_pool,
            configuration_epoch: u64::try_from(row.get::<_, i64>(6)?)?,
            created_at_unix_seconds: row.get(7)?,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_database_is_not_created() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.db");
        assert!(Inventory::open(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn reads_only_a_supported_snapshot_and_never_writes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("controller.db");
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE schema_versions(version INTEGER PRIMARY KEY);
            CREATE TABLE networks(id BLOB, name TEXT, ipv4_address BLOB, ipv4_prefix_length INTEGER,
            ipv6_address BLOB, ipv6_prefix_length INTEGER, configuration_epoch INTEGER, created_at INTEGER);").unwrap();
        let mut reader = Inventory::open(&path).unwrap();
        assert!(reader.networks(1).is_err());
        for version in 1..=SCHEMA_VERSION {
            writer
                .execute("INSERT INTO schema_versions VALUES (?)", [version])
                .unwrap();
        }
        assert!(reader.networks(100).unwrap().is_empty());
        assert!(reader.networks(0).is_err());
        assert!(reader.networks(1001).is_err());
        // SQLite itself must still deny writes if the connection-level guard is removed.
        reader.db.execute_batch("PRAGMA query_only=OFF").unwrap();
        assert_eq!(
            reader
                .db
                .execute("DELETE FROM schema_versions", [])
                .unwrap_err()
                .sqlite_error_code(),
            Some(rusqlite::ErrorCode::ReadOnly)
        );
        writer
            .execute(
                "INSERT INTO schema_versions VALUES (?)",
                [SCHEMA_VERSION + 1],
            )
            .unwrap();
        assert!(reader.networks(1).is_err());
    }
}
