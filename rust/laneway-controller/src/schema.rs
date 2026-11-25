use anyhow::{Context, Result, bail};
#[cfg(target_os = "linux")]
use rusqlite::Transaction;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

pub(crate) const MAX_VERSION: i64 = 10;

#[cfg(any(target_os = "linux", test))]
pub(crate) fn published_migrations() -> impl Iterator<Item = &'static str> {
    include_str!("../../../go/internal/controller/migrations.sql")
        .split("\n-- Next Laneway schema migration --\n")
}

const CORE_TABLES: &[&str] = &[
    "networks",
    "nodes",
    "certificates",
    "overlay_addresses",
    "routes",
    "acl_rules",
    "relays",
    "enrollment_tokens",
    "audit_events",
    "schema_versions",
];

const ADMIN_TABLES: &[&str] = &[
    "administrator_principals",
    "administrator_principal_networks",
    "administrator_credentials",
    "administrator_sessions",
    "administrator_recovery_grants",
    "administrator_auth_state",
    "administrator_root_token_rotations",
    "controller_identity_state",
];

// Canonical fingerprints from the published Go migrations. Each includes all
// triggers and the exact SQLite DDL for every administrator table and index.
const FINGERPRINTS: &[(usize, &str)] = &[
    (
        30,
        "151e2387e5ca93860c768c4ea4d4fa67c1c2f64b5b2ae2889f8babb73b4c3c31",
    ),
    (
        38,
        "3cc1e9e0535a074cb78c52f132687d64b4c5421123dc33a1d6d9c156f8fc0603",
    ),
    (
        43,
        "037cd06ef1029fb767ed597334c00e07bb8665d373b4a45d29c81e17e4f70394",
    ),
];

#[cfg(target_os = "linux")]
pub(crate) fn migrate(tx: &Transaction<'_>, now: i64) -> Result<()> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_versions (
           version INTEGER PRIMARY KEY CHECK(version > 0),
           applied_at INTEGER NOT NULL
         ) STRICT",
    )?;
    let current: i64 = tx.query_row(
        "SELECT coalesce(max(version),0) FROM schema_versions",
        [],
        |row| row.get(0),
    )?;
    if !(0..=MAX_VERSION).contains(&current) {
        bail!("unsupported controller schema version {current} (maximum {MAX_VERSION})");
    }
    for (index, sql) in published_migrations().enumerate().skip(current as usize) {
        let version = index + 1;
        tx.execute_batch(sql)
            .with_context(|| format!("apply schema migration {version}"))?;
        tx.execute(
            "INSERT INTO schema_versions(version,applied_at) VALUES(?,?)",
            params![version, now],
        )?;
    }
    Ok(())
}

pub(crate) fn validate(db: &Connection) -> Result<()> {
    let integrity: String = db
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .context("run SQLite integrity check")?;
    if integrity != "ok" {
        bail!("SQLite integrity check failed: {integrity}");
    }
    let (version, first, history_len): (i64, i64, i64) = db.query_row(
        "SELECT COALESCE(MAX(version),0), COALESCE(MIN(version),0), count(*) FROM schema_versions",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).context("read backup schema history")?;
    if !(1..=MAX_VERSION).contains(&version) {
        bail!("unsupported backup schema version {version} (maximum {MAX_VERSION})");
    }
    if first != 1 || history_len != version {
        bail!("backup schema history is incomplete");
    }
    let administrator_tables = match version {
        8 => &ADMIN_TABLES[..6],
        9 => &ADMIN_TABLES[..7],
        10 => ADMIN_TABLES,
        _ => &[],
    };
    let mut table_query =
        db.prepare("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?")?;
    for table in CORE_TABLES.iter().chain(administrator_tables) {
        if table_query.query_row([table], |row| row.get::<_, i64>(0))? != 1 {
            bail!("backup schema is incomplete: required table {table} is missing");
        }
    }
    if version >= 8 {
        validate_admin(db, version)?;
    }
    if db
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some()
    {
        bail!("SQLite foreign-key check failed");
    }
    Ok(())
}

fn validate_admin(db: &Connection, version: i64) -> Result<()> {
    let mut schema_query = db.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE type IN ('table','index','trigger') ORDER BY type,name,tbl_name",
    )?;
    let mut rows = schema_query.query([])?;
    let mut hash = Sha256::new();
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let name: String = row.get(1)?;
        let table: String = row.get(2)?;
        let ddl: Option<String> = row.get(3)?;
        if kind == "trigger" || table == "audit_events" || ADMIN_TABLES.contains(&table.as_str()) {
            hash.update(format!(
                "{kind}\0{name}\0{table}\0{}\0{}\0",
                ddl.is_some(),
                ddl.as_deref().unwrap_or_default()
            ));
            count += 1;
        }
    }
    let (want_count, want_hash) = FINGERPRINTS[(version - 8) as usize];
    if count != want_count || format!("{:x}", hash.finalize()) != want_hash {
        bail!(
            "backup schema is incomplete: administrator schema does not match the canonical v{version} definition"
        );
    }
    let singleton_count: i64 = db.query_row(
        "SELECT count(*) FROM administrator_auth_state
         WHERE singleton=1 AND length(root_service_principal_id)=16 AND root_service_principal_id<>zeroblob(16)",
        [], |row| row.get(0),
    )?;
    if singleton_count != 1 {
        bail!("backup administrator auth state is missing or corrupt");
    }
    if version >= 10 {
        validate_controller_binding(db)?;
    }
    Ok(())
}

fn validate_controller_binding(db: &Connection) -> Result<()> {
    match db.query_row(
        "SELECT count(*) FROM controller_identity_state",
        [],
        |row| row.get::<_, i64>(0),
    )? {
        0 => return Ok(()),
        1 => {}
        _ => bail!("backup controller identity state is corrupt"),
    }
    let (network, service, binding_created, network_created): (Vec<u8>, Vec<u8>, i64, i64) =
        db.query_row(
            "SELECT c.network_id,c.controller_service_id,c.created_at,n.created_at
             FROM controller_identity_state c JOIN networks n ON n.id=c.network_id WHERE c.singleton=1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).context("validate controller identity binding")?;
    if [&network, &service]
        .iter()
        .any(|id| id.len() != 16 || id.iter().all(|byte| *byte == 0))
    {
        bail!("backup controller identity binding is corrupt");
    }
    if binding_created < network_created {
        bail!("backup controller identity binding predates its network");
    }
    let audit_count: i64 = db.query_row(
        "SELECT count(*) FROM audit_events
         WHERE network_id=? AND actor_kind='system' AND actor_id IS NULL
         AND action='controller.identity.bind' AND target_type='controller_service'
         AND target_id=? AND created_at=?",
        params![network, service, binding_created],
        |row| row.get(0),
    )?;
    if audit_count != 1 {
        bail!("backup controller identity binding audit is missing or corrupt");
    }
    Ok(())
}

#[cfg(test)]
#[test]
fn restore_migrations_cover_supported_versions() {
    assert_eq!(published_migrations().count(), MAX_VERSION as usize);
}
