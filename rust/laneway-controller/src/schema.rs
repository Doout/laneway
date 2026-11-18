//! Public schema 18 and the exact additive Go fleet schema 19.
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use std::path::Path;

pub(crate) const PUBLIC_VERSION: i64 = 18;
const FLEET_VERSION: i64 = 19;
const FLEET_DDL: &str = include_str!("../schema/fleet-v19.sql");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Public,
    Fleet,
}

pub(crate) fn check(tx: &Transaction<'_>) -> Result<()> {
    profile(tx).map(|_| ())
}

fn profile(tx: &Transaction<'_>) -> Result<Profile> {
    // SQLite transaction binds the version and DDL checks to the same view as the query.
    let versions: (i64, i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(min(version),0),coalesce(max(version),0) FROM schema_versions",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).context("read controller migration history")?;
    match versions {
        (PUBLIC_VERSION, 1, PUBLIC_VERSION) => Ok(Profile::Public),
        (FLEET_VERSION, 1, FLEET_VERSION) => {
            check_fleet_layout(tx)?;
            Ok(Profile::Fleet)
        }
        _ => bail!("unsupported controller migration history {versions:?}"),
    }
}

fn check_fleet_layout(tx: &Transaction<'_>) -> Result<()> {
    let mut schema = tx.prepare_cached("SELECT sql FROM sqlite_schema WHERE name=? AND type=?")?;
    // These fixed DDL statements contain no semicolons inside strings. SQLite
    // stores the statement without its trailing semicolon. Check named objects
    // independently so dump/restore may reorder them.
    for definition in FLEET_DDL
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut parts = definition.split_ascii_whitespace().skip(1);
        let kind = match parts.next() {
            Some("TABLE") => "table",
            Some("INDEX") => "index",
            _ => bail!("invalid embedded fleet DDL"),
        };
        let name = parts.next().context("missing fleet schema object name")?;
        let stored: Option<String> = schema.query_row((name, kind), |r| r.get(0)).optional()?;
        ensure!(
            stored.as_deref().map(str::trim) == Some(definition),
            "unsupported fleet schema object {name}"
        );
    }
    Ok(())
}

/// Look up the fleet flag only after the transaction has passed `check`.
pub(crate) fn is_fleet(tx: &Transaction<'_>) -> Result<bool> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_versions WHERE version=?)",
        [FLEET_VERSION],
        |r| r.get(0),
    )?)
}

/// Upgrade an existing database explicitly. `serve` never runs migrations.
pub fn migrate_fleet(path: &Path) -> Result<bool> {
    #[cfg(unix)]
    let canonical = crate::database_lock::existing_database(path)?;
    #[cfg(unix)]
    let path = canonical.as_path();
    #[cfg(unix)]
    let _lifecycle_lock = crate::database_lock::acquire(path)?;
    let mut db = crate::open_existing(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let applied = profile(&tx)? == Profile::Public;
    if applied {
        // Each DDL statement and the history entry belongs to the same transaction.
        tx.execute_batch(FLEET_DDL)
            .context("apply fleet schema 19")?;
        tx.execute(
            "INSERT INTO schema_versions(version,applied_at) VALUES(?,unixepoch())",
            [FLEET_VERSION],
        )?;
        check_fleet_layout(&tx)?;
    }
    tx.commit()?;
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn public_database(path: &Path) -> Result<Connection> {
        let db = Connection::open(path)?;
        db.execute_batch("CREATE TABLE schema_versions(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
            WITH RECURSIVE v(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM v WHERE i<18)
            INSERT INTO schema_versions SELECT i,1 FROM v;
            CREATE TABLE networks(id BLOB PRIMARY KEY);
            CREATE TABLE nodes(id BLOB PRIMARY KEY, network_id BLOB NOT NULL, UNIQUE(network_id,id));
            CREATE TABLE certificates(id BLOB PRIMARY KEY);")?;
        Ok(db)
    }

    #[test]
    fn migration_rolls_back_on_an_existing_conflicting_object() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("controller.db");
        let db = public_database(&path)?;
        db.execute("CREATE TABLE policy_revisions(unrelated TEXT)", [])?;
        assert!(migrate_fleet(&path).is_err());
        let result: (i64, i64) = db.query_row("SELECT max(version),(SELECT count(*) FROM sqlite_schema WHERE name='fleet_updates') FROM schema_versions", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
        assert_eq!(result, (PUBLIC_VERSION, 0));
        Ok(())
    }

    #[test]
    fn recognizes_exact_fleet_backup_but_not_same_version_with_schema_drift() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("controller.db");
        let mut db = public_database(&path)?;
        assert!(migrate_fleet(&path)?);
        assert!(!migrate_fleet(&path)?);
        check(&db.transaction()?)?;
        db.execute("DROP INDEX fleet_update_node_queue", [])?;
        db.execute(
            "CREATE INDEX fleet_update_node_queue ON fleet_update_targets(update_id,state)",
            [],
        )?;
        assert!(check(&db.transaction()?).is_err());
        assert!(migrate_fleet(&path).is_err());
        Ok(())
    }
}
