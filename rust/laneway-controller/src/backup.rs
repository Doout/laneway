//! Online SQLite backup and offline no-replace restore for the native controller.
use crate::{
    check_snapshot,
    database_lock::{acquire, existing_database, sidecar},
    open_existing,
    recovery::AuditActor,
    schema,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{
    Connection, OpenFlags, Transaction, TransactionBehavior,
    backup::{Backup, StepResult},
};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::ErrorKind,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    thread,
    time::{Duration, Instant},
};

mod verify;

/// Copy committed state from an existing controller while it remains online.
pub fn create(source: &Path, destination: &Path) -> Result<()> {
    copy(source, destination, false)
}

/// Restore into a missing target with the controller stopped on that target.
/// The source is never migrated, truncated, or edited by this operation.
pub fn restore(source: &Path, destination: &Path) -> Result<()> {
    check_new(destination)?;
    let _lock = acquire(destination).context("restore requires a stopped controller")?;
    copy(source, destination, true)
}

fn copy(source: &Path, destination: &Path, restore: bool) -> Result<()> {
    let parent = check_new(destination)?;
    let source_path = existing_database(source)?;
    let source = open_existing(
        &source_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    source.execute_batch("PRAGMA query_only=ON")?;

    // Private directory contains the scratch DB and any SQLite journal files.
    // Publication uses a hard link so a concurrent target is never replaced.
    let scratch = tempfile::Builder::new()
        .prefix(".laneway-database-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .context("create private backup staging directory")?;
    let candidate = scratch.path().join("database");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&candidate)
        .context("create private database copy")?;
    let mut output = open_existing(&candidate, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    copy_pages(&source, &mut output)?;
    drop(source);
    let mode: String = output.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    ensure!(mode == "delete", "database copy is not self-contained");

    {
        let tx = output.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let fleet = schema::is_fleet(&tx)?;
        verify::database(&tx, fleet).context("validate copied controller database")?;
        if restore {
            prepare_restore(&tx, fleet)?;
            verify::sqlite(&tx).context("validate restored SQLite state")?;
        }
        tx.commit()?;
    }
    output
        .close()
        .map_err(|(_, err)| err)
        .context("close copied database")?;
    file.sync_all().context("sync copied database")?;
    check_new(destination)?;
    fs::hard_link(&candidate, destination).context("publish database copy without overwriting")?;
    File::open(parent)?
        .sync_all()
        .context("database copy published but destination directory could not be synced")?;
    Ok(())
}

fn check_new(destination: &Path) -> Result<&Path> {
    ensure!(
        destination.file_name().is_some(),
        "destination must name a new database file"
    );
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(parent.is_dir(), "database destination parent must exist");
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = sidecar(destination, suffix);
        match fs::symlink_metadata(&path) {
            Ok(_) => anyhow::bail!(
                "database destination or sidecar already exists: {}",
                path.display()
            ),
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("inspect database destination"),
        }
    }
    Ok(parent)
}

fn copy_pages(source: &Connection, output: &mut Connection) -> Result<()> {
    let copy = Backup::new(source, output).context("start SQLite online backup")?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        ensure!(
            Instant::now() < deadline,
            "SQLite backup did not stabilize within 120 seconds"
        );
        match copy.step(256).context("copy SQLite pages")? {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            _ => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn prepare_restore(tx: &Transaction<'_>, fleet: bool) -> Result<()> {
    let now: i64 = tx.query_row("SELECT unixepoch()", [], |row| row.get(0))?;
    tx.execute_batch(
        "DELETE FROM administrator_sessions;
         DELETE FROM administrator_recovery_grants WHERE consumed_at IS NULL;",
    )?;
    if fleet {
        // Existing claims stay reserved until the operator reconciles the host.
        tx.execute_batch(
            "DELETE FROM node_credential_recovery_grants WHERE consumed_at IS NULL;
             DELETE FROM node_topology;
             DELETE FROM fleet_update_agents;
             UPDATE fleet_updates SET state='paused' WHERE state IN ('canary','rollout');",
        )?;
    }
    tx.execute(
        "UPDATE automation_service_access_tokens
         SET revoked_at=max(created_at,?1),revocation_reason='controller database restored'
         WHERE revoked_at IS NULL",
        [now],
    )?;
    ensure!(
        tx.execute(
            "UPDATE administrator_auth_state
             SET recovery_generation=recovery_generation+1,last_recovered_at=?1 WHERE singleton=1",
            [now],
        )
        .context("advance restored authentication generation")?
            == 1,
        "restored administrator auth state is missing"
    );
    AuditActor("system", None).write(
        tx,
        "controller.restore",
        "controller_database",
        None,
        json!({}),
        now,
    )?;
    Ok(())
}
