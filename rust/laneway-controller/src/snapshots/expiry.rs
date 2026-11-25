use anyhow::{Context, Result, ensure};
use laneway_protocol::Id;
use rusqlite::{Connection, params};

pub(super) const ROUTE_EXPIRY_BATCH: usize = 1024;

pub(super) fn expire_approved_routes(db: &Connection, network: Id, now: i64) -> Result<()> {
    let expired = {
        let mut statement = db.prepare(
            "UPDATE routes SET state='withdrawn',withdrawn_at=?1
             WHERE id IN (
                SELECT id FROM routes WHERE network_id=?2 AND state='approved' AND valid_until<=?1
                ORDER BY valid_until,id LIMIT ?3
             )
             RETURNING id",
        )?;
        statement
            .query_map(
                params![now, network.as_bytes().as_slice(), ROUTE_EXPIRY_BATCH],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !expired.is_empty() {
        advance_epoch(db, network)?;
        for route in expired {
            audit_route_expiration(db, network, Id::from_slice(&route)?, now)?;
        }
    }
    Ok(())
}

fn advance_epoch(db: &Connection, network: Id) -> Result<()> {
    let changed = db.execute(
        "UPDATE networks SET configuration_epoch=configuration_epoch+1
         WHERE id=?1 AND configuration_epoch < 9223372036854775807",
        params![network.as_bytes().as_slice()],
    )?;
    ensure!(changed == 1, "network missing or epoch exhausted");
    Ok(())
}

fn audit_route_expiration(db: &Connection, network: Id, id: Id, now: i64) -> Result<()> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow::anyhow!("create expiry audit ID: {error}"))?;
    let event = Id::new(random)?;
    db.execute(
        "INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
         VALUES(?1,?2,'system',NULL,'route.expire','route',?3,?4,?5)",
        params![event.as_bytes().as_slice(), network.as_bytes().as_slice(), id.as_bytes().as_slice(), r#"{"reason":"expired"}"#, now],
    )?;
    Ok(())
}

pub(super) fn pending_expiry(db: &Connection, network: Id, now: i64) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes WHERE network_id=?1 AND enrollment_class='ephemeral'
         AND revoked_at IS NULL AND lease_expires_at<=?2)
         OR EXISTS(SELECT 1 FROM routes WHERE network_id=?1 AND state='approved' AND valid_until<=?2)",
        params![network.as_bytes().as_slice(), now],
        |row| row.get(0),
    )?)
}

pub(super) fn lease_deadline(db: &Connection, network: Id, now: i64) -> Result<u64> {
    const DEFAULT_VALIDITY_SECONDS: i64 = 5 * 60;
    let earliest_identity: Option<i64> = db.query_row(
        "SELECT MIN(lease_expires_at) FROM nodes WHERE network_id=?1 AND enrollment_class='ephemeral'
         AND revoked_at IS NULL AND lease_expires_at>?2",
        params![network.as_bytes().as_slice(), now],
        |row| row.get(0),
    )?;
    let earliest_route: Option<i64> = db.query_row(
        "SELECT MIN(r.valid_until) FROM routes r JOIN nodes n ON (n.id=r.node_id AND n.network_id=r.network_id)
         WHERE r.network_id=?1 AND r.state='approved' AND r.valid_until>?2
         AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?2)",
        params![network.as_bytes().as_slice(), now],
        |row| row.get(0),
    )?;
    let max = now
        .checked_add(DEFAULT_VALIDITY_SECONDS)
        .context("snapshot validity overflow")?;
    let deadline = earliest_identity
        .into_iter()
        .chain(earliest_route)
        .fold(max, i64::min);
    Ok(u64::try_from(deadline)?)
}
