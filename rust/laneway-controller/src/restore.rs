use std::{path::Path, sync::atomic::AtomicBool};

use anyhow::{Result, bail};

#[cfg(target_os = "linux")]
use self::linux::restore as restore_on_linux;

pub(crate) fn database(
    source: &Path,
    destination: &Path,
    canceled: &'static AtomicBool,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        restore_on_linux(source, destination, canceled)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, destination, canceled);
        bail!("controller lifecycle locking is not supported on this platform");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use rusqlite::{Connection, TransactionBehavior, params};
    use std::fs::{self, DirBuilder};
    use std::io::ErrorKind;
    use std::os::unix::fs::DirBuilderExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{backup, schema, store::lock_database};

    pub(super) fn restore(
        source: &Path,
        destination: &Path,
        canceled: &'static AtomicBool,
    ) -> Result<()> {
        if destination.as_os_str().to_string_lossy().trim().is_empty() {
            bail!("database destination is empty");
        }
        let parent = destination
            .parent()
            .context("invalid database destination")?;
        if !parent.as_os_str().is_empty() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .context("create controller database directory")?;
        }
        let _lifecycle_lock =
            lock_database(destination).context("restore requires a stopped controller")?;
        // A stale journal for a missing database could become associated
        // with the newly published file when the controller opens it.
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = destination.as_os_str().to_os_string();
            sidecar.push(suffix);
            match fs::symlink_metadata(&sidecar) {
                Ok(_) => bail!(
                    "restore destination has an existing SQLite sidecar: {}",
                    Path::new(&sidecar).display()
                ),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect restore destination sidecar"),
            }
        }
        backup::copy_database(source, destination, canceled, prepare)
            .context("restore controller database")
    }

    fn prepare(db: &mut Connection) -> Result<()> {
        schema::validate(db).context("validate copied restore source")?;
        db.pragma_update(None, "journal_mode", "DELETE")?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.pragma_update(None, "secure_delete", true)?;
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        schema::migrate(&tx, now)?;

        tx.execute("DELETE FROM administrator_sessions", [])
            .context("invalidate restored administrator sessions")?;
        tx.execute(
            "DELETE FROM administrator_recovery_grants WHERE consumed_at IS NULL",
            [],
        )
        .context("invalidate restored administrator recovery grants")?;
        let updated = tx
            .execute(
                "UPDATE administrator_auth_state SET recovery_generation=recovery_generation+1,
                 last_recovered_at=? WHERE singleton=1",
                [now],
            )
            .context("advance restored authentication generation")?;
        if updated != 1 {
            bail!("restored administrator auth state is missing");
        }
        let id = loop {
            let mut id = [0u8; 16];
            getrandom::fill(&mut id)
                .map_err(|error| anyhow::anyhow!("generate audit event ID: {error}"))?;
            if id != [0; 16] {
                break id;
            }
        };
        tx.execute(
            "INSERT INTO audit_events
               (id,actor_kind,action,target_type,details_json,created_at)
               VALUES(?,'system','controller.restore','controller_database','{}',?)",
            params![id.as_slice(), now],
        )
        .context("record restore audit event")?;
        tx.commit()
            .context("commit restored authentication invalidation")?;
        // Rebuild the private copy so previously deleted session/grant bytes
        // cannot be recovered from its freelist or unused page space.
        db.execute_batch("VACUUM")
            .context("compact redacted database")?;
        Ok(())
    }
}
