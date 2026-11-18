//! Verify the exact supported schema and stored invariants before publication.
use crate::{
    access_admin::{ServiceProtocol, service_ports},
    automation,
};
use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use laneway_protocol::{Id, policy::prefix_from_wire, v1::IpPrefix};
use rusqlite::Transaction;
use sha2::{Digest, Sha256};

// Hashes of the complete sqlite_schema rows produced by the public Go
// migrations, followed by the additive fleet migration for schema 19.
const PUBLIC_SCHEMA: &str = "81b65788540fec2124e823e3da9fc472ba3e123231d8dfb6e13ea9f416f6193f";
const FLEET_SCHEMA: &str = "346b3f6fdbfc4dee1b1cc079aea8bf1ec39b0816b2e051a7771b4c407afbcda1";

pub(super) fn database(tx: &Transaction<'_>, fleet: bool) -> Result<()> {
    layout(tx, fleet)?;
    sqlite(tx)?;
    identity(tx)?;
    access_policy(tx)?;
    automation::validate_backup(tx)?;
    Ok(())
}

pub(super) fn sqlite(tx: &Transaction<'_>) -> Result<()> {
    let mut integrity = tx.prepare("PRAGMA integrity_check")?;
    let mut rows = integrity.query([])?;
    ensure!(
        rows.next()?.is_some_and(|row| row
            .get_ref(0)
            .and_then(|v| Ok(v.as_str()?))
            .is_ok_and(|s| s == "ok"))
            && rows.next()?.is_none(),
        "SQLite integrity check failed"
    );
    ensure!(
        tx.prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_none(),
        "SQLite foreign-key check failed"
    );
    Ok(())
}

fn layout(tx: &Transaction<'_>, fleet: bool) -> Result<()> {
    let want = if fleet { FLEET_SCHEMA } else { PUBLIC_SCHEMA };
    let mut hash = Sha256::new();
    let mut stmt = tx.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema
         WHERE name NOT IN ('sqlite_stat1','sqlite_stat4') ORDER BY type,name,tbl_name",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        for i in 0..3 {
            hash.update(row.get_ref(i)?.as_str()?.as_bytes());
            hash.update([0]);
        }
        let sql = row.get::<_, Option<String>>(3)?;
        let tag = if sql.is_some() { "true" } else { "false" };
        hash.update(tag.as_bytes());
        hash.update([0]);
        hash.update(sql.as_deref().unwrap_or("").as_bytes());
        hash.update([0]);
    }
    let actual = hex::encode(hash.finalize());
    ensure!(
        actual == want,
        "backup schema does not match the supported layout (fingerprint {actual})"
    );
    Ok(())
}

fn identity(tx: &Transaction<'_>) -> Result<()> {
    let root: [u8; 16] = tx
        .query_row(
            "SELECT root_service_principal_id FROM administrator_auth_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .context("read backup administrator auth state")?;
    Id::new(root).context("invalid backup root principal")?;
    let identities: i64 = tx.query_row(
        "SELECT count(*) FROM controller_identity_state",
        [],
        |row| row.get(0),
    )?;
    let audits: i64 = tx.query_row(
        "SELECT count(*) FROM audit_events WHERE action='controller.identity.bind'",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        identities == audits && identities <= 1,
        "controller identity binding history is inconsistent"
    );
    if identities == 0 {
        return Ok(());
    }
    let (network, service, created, network_created): ([u8; 16], [u8; 16], i64, i64) = tx
        .query_row(
            "SELECT c.network_id,c.controller_service_id,c.created_at,n.created_at
         FROM controller_identity_state c JOIN networks n ON n.id=c.network_id WHERE c.singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    Id::new(network)?;
    Id::new(service)?;
    ensure!(
        created >= network_created,
        "controller identity predates its network"
    );
    let matched: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM audit_events
         WHERE network_id=?1 AND actor_kind='system' AND actor_id IS NULL
         AND action='controller.identity.bind' AND target_type='controller_service'
         AND target_id=?2 AND created_at=?3)",
        (network, service, created),
        |row| row.get(0),
    )?;
    ensure!(
        matched,
        "controller identity binding audit does not match its state"
    );
    Ok(())
}

fn access_policy(tx: &Transaction<'_>) -> Result<()> {
    let mut services =
        tx.prepare("SELECT id,protocol,ports_sealed FROM access_services ORDER BY id")?;
    let mut ports = service_ports::prepare(tx)?;
    let mut rows = services.query([])?;
    while let Some(row) = rows.next()? {
        let service = Id::new(row.get(0)?)?;
        let protocol = ServiceProtocol::from_stored(row.get_ref(1)?.as_str()?)?;
        ensure!(
            row.get::<_, bool>(2)?,
            "backup named-service ports are not sealed"
        );
        service_ports::read(&mut ports, service, protocol)?;
    }
    let mut resources = tx.prepare(
        "SELECT a.route_node_id,a.route_prefix_address,a.route_prefix_length,a.prefix_address,
         a.prefix_length,r.node_id,r.prefix_address,r.prefix_length,r.kind
         FROM access_resources a LEFT JOIN routes r ON r.id=a.route_id AND r.network_id=a.network_id
         WHERE a.target_kind='prefix' ORDER BY a.id",
    )?;
    let mut rows = resources.query([])?;
    while let Some(row) = rows.next()? {
        let pinned_node = Id::new(row.get(0)?)?;
        let routed_node = Id::new(row.get(5)?)?;
        let pinned_prefix = prefix(row.get(1)?, row.get(2)?)?;
        let resource_prefix = prefix(row.get(3)?, row.get(4)?)?;
        let routed_prefix = prefix(row.get(6)?, row.get(7)?)?;
        ensure!(
            row.get_ref(8)?.as_str()? == "subnet"
                && pinned_node == routed_node
                && pinned_prefix == routed_prefix
                && routed_prefix.prefix_len() <= resource_prefix.prefix_len()
                && routed_prefix.contains(&resource_prefix.addr()),
            "backup named resource no longer matches its pinned route"
        );
    }
    Ok(())
}

fn prefix(address: Vec<u8>, prefix_length: u32) -> Result<IpNet> {
    ensure!(prefix_length != 0, "backup named prefix is a default route");
    Ok(prefix_from_wire(IpPrefix {
        address,
        prefix_length,
    })?)
}
