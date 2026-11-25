use std::fs::{self, File};
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};

use crate::schema;

const PAGE_BATCH: i32 = 256;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BUSY_RETRY: Duration = Duration::from_millis(10);

pub(crate) fn database(
    source: &Path,
    destination: &Path,
    canceled: &'static AtomicBool,
) -> Result<()> {
    copy_database(source, destination, canceled, |_| Ok(()))
}

pub(crate) fn copy_database(
    source: &Path,
    destination: &Path,
    canceled: &'static AtomicBool,
    prepare: impl FnOnce(&mut Connection) -> Result<()>,
) -> Result<()> {
    if destination.as_os_str().to_string_lossy().trim().is_empty() {
        bail!("database destination is empty");
    }
    let source = open_source(source)?;
    configure_progress(&source, canceled);
    schema::validate(&source).context("validate controller database")?;

    let parent = destination.parent().context("invalid backup destination")?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    match fs::symlink_metadata(destination) {
        Ok(_) => bail!("destination already exists: {}", destination.display()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect destination"),
    }

    check_canceled(canceled)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(".laneway-database-");
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o700));
    // SQLite may create journal sidecars. A private directory protects and
    // cleans up the complete staging area, including a canceled transaction.
    let staging = builder
        .tempdir_in(parent)
        .context("create private backup directory")?;
    let temporary =
        tempfile::NamedTempFile::new_in(staging.path()).context("create private backup file")?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("restrict backup permissions")?;
    let mut destination_db =
        Connection::open_with_flags(temporary.path(), OpenFlags::SQLITE_OPEN_READ_WRITE)
            .context("open temporary backup")?;
    copy_pages(&source, &mut destination_db, canceled)?;
    configure_progress(&destination_db, canceled);
    prepare(&mut destination_db)?;
    destination_db
        .close()
        .map_err(|(_, error)| error)
        .context("close completed backup")?;

    let completed = open_source(temporary.path())?;
    configure_progress(&completed, canceled);
    schema::validate(&completed).context("validate completed backup")?;
    completed
        .close()
        .map_err(|(_, error)| error)
        .context("close validated backup")?;

    temporary
        .as_file()
        .sync_all()
        .context("sync completed backup")?;
    check_canceled(canceled)?;
    fs::hard_link(temporary.path(), destination).with_context(|| {
        format!(
            "publish backup without overwriting {}",
            destination.display()
        )
    })?;
    if let Err(error) = sync_directory(parent) {
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    temporary.close().context("remove private backup file")?;
    staging.close().context("remove private backup directory")?;
    Ok(())
}

fn open_source(path: &Path) -> Result<Connection> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect database {}", path.display()))?;
    if !metadata.is_file() {
        bail!("database is not a regular file: {}", path.display());
    }
    // Resolve only the parent. SQLite's NOFOLLOW then rejects a substituted
    // final symlink while allowing system paths such as Darwin's /var alias.
    let path = std::path::absolute(path)?;
    let directory = path.parent().context("database parent is missing")?;
    let filename = path.file_name().context("database filename is missing")?;
    let path = directory.canonicalize()?.join(filename);
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .with_context(|| format!("open database read-only {}", path.display()))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "query_only", true)?;
    // Leave busy handling to copy_pages so a contended writer cannot stall
    // cancellation for the duration of a SQLite busy handler.
    connection.busy_timeout(Duration::ZERO)?;
    Ok(connection)
}

fn configure_progress(connection: &Connection, canceled: &'static AtomicBool) {
    connection.progress_handler(1_000, Some(move || canceled.load(Ordering::Relaxed)));
}

fn copy_pages(
    source: &Connection,
    destination: &mut Connection,
    canceled: &AtomicBool,
) -> Result<()> {
    let backup = Backup::new(source, destination).context("start SQLite online backup")?;
    let mut busy_since = None;
    loop {
        check_canceled(canceled)?;
        match backup.step(PAGE_BATCH).context("copy SQLite pages")? {
            StepResult::Done => return Ok(()),
            StepResult::More => busy_since = None,
            StepResult::Busy | StepResult::Locked => {
                if busy_since.get_or_insert_with(Instant::now).elapsed() >= BUSY_TIMEOUT {
                    bail!("timed out waiting for SQLite backup lock");
                }
                thread::sleep(BUSY_RETRY);
            }
            _ => bail!("unexpected SQLite backup step result"),
        }
    }
}

fn check_canceled(canceled: &AtomicBool) -> Result<()> {
    if canceled.load(Ordering::Relaxed) {
        bail!("backup canceled");
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .context("sync backup directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    static RUNNING: AtomicBool = AtomicBool::new(false);
    static CANCELED: AtomicBool = AtomicBool::new(true);

    fn controller_database(path: &Path, version: usize) -> Connection {
        let db = Connection::open(path).unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE schema_versions (
               version INTEGER PRIMARY KEY CHECK(version > 0),
               applied_at INTEGER NOT NULL
             ) STRICT;",
        )
        .unwrap();
        for (index, sql) in schema::published_migrations().take(version).enumerate() {
            db.execute_batch(sql).unwrap();
            db.execute("INSERT INTO schema_versions VALUES(?,0)", [index + 1])
                .unwrap();
        }
        db
    }

    #[test]
    fn backs_up_canonical_versions_without_migrating_source() {
        for version in [1, 8, 9, 10] {
            let work = tempfile::tempdir().unwrap();
            let source = work.path().join("source.db");
            let backup = work.path().join("backup.db");
            let db = controller_database(&source, version);
            db.close().unwrap();
            let original = fs::read(&source).unwrap();

            database(&source, &backup, &RUNNING).unwrap();

            assert_eq!(fs::read(&source).unwrap(), original);
            let db = open_source(&backup).unwrap();
            let schema_version = db
                .query_row("SELECT MAX(version) FROM schema_versions", [], |row| {
                    row.get::<_, usize>(0)
                })
                .unwrap();
            assert_eq!(schema_version, version);
            #[cfg(unix)]
            assert_eq!(
                fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(fs::read_dir(work.path()).unwrap().count(), 2);
        }
    }

    #[test]
    fn backup_reads_committed_wal_while_writer_has_uncommitted_change() {
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source.db");
        let backup = work.path().join("backup.db");
        let db = controller_database(&source, 10);
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             INSERT INTO networks(id,name,ipv4_address,ipv4_prefix_length,created_at)
               VALUES(X'01000000000000000000000000000000','original',X'64600000',16,1);
             INSERT INTO controller_identity_state VALUES
               (1,X'01000000000000000000000000000000',X'02000000000000000000000000000000',2);
             INSERT INTO audit_events(id,network_id,actor_kind,action,target_type,target_id,created_at)
               VALUES(X'03000000000000000000000000000000',X'01000000000000000000000000000000',
                     'system','controller.identity.bind','controller_service',X'02000000000000000000000000000000',2);
             BEGIN IMMEDIATE;
             UPDATE networks SET name='uncommitted';",
        ).unwrap();

        database(&source, &backup, &RUNNING).unwrap();

        let backup_db = open_source(&backup).unwrap();
        let name: String = backup_db
            .query_row("SELECT name FROM networks", [], |row| row.get(0))
            .unwrap();
        assert_eq!(name, "original");
        let original_name: String = db
            .query_row("SELECT name FROM networks", [], |row| row.get(0))
            .unwrap();
        assert_eq!(original_name, "uncommitted");
    }

    #[test]
    fn rejects_existing_destination_and_schema_tampering() {
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source.db");
        let destination = work.path().join("destination.db");
        let db = controller_database(&source, 10);
        fs::write(&destination, b"existing").unwrap();
        let err = database(&source, &destination, &RUNNING).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read(&destination).unwrap(), b"existing");

        let fresh_destination = work.path().join("missing.db");
        db.execute_batch(
            "CREATE TRIGGER unrecognized_trigger BEFORE UPDATE ON networks BEGIN SELECT 1; END;",
        )
        .unwrap();
        let err = database(&source, &fresh_destination, &RUNNING).unwrap_err();
        assert!(format!("{err:#}").contains("canonical v10"));
        assert!(!fresh_destination.exists());
    }

    #[test]
    fn canceled_backup_creates_no_destination() {
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source.db");
        drop(controller_database(&source, 10));
        let destination = work.path().join("destination.db");
        assert!(database(&source, &destination, &CANCELED).is_err());
        assert_eq!(fs::read_dir(work.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restore_migrates_older_database_and_rejects_symlinked_lifecycle_lock() {
        use std::os::unix::fs::symlink;

        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source.db");
        drop(controller_database(&source, 1));
        let original = fs::read(&source).unwrap();
        let destination = work.path().join("nested").join("destination.db");
        let lock = destination.with_extension("db.lock");
        fs::create_dir(destination.parent().unwrap()).unwrap();
        symlink(&source, &lock).unwrap();
        assert!(crate::restore::database(&source, &destination, &RUNNING).is_err());
        assert!(!destination.exists());
        fs::remove_file(lock).unwrap();
        let stale_wal = destination.with_extension("db-wal");
        fs::write(&stale_wal, b"old WAL").unwrap();
        assert!(crate::restore::database(&source, &destination, &RUNNING).is_err());
        assert!(!destination.exists());
        assert_eq!(fs::read(&stale_wal).unwrap(), b"old WAL");
        fs::remove_file(stale_wal).unwrap();

        crate::restore::database(&source, &destination, &RUNNING).unwrap();

        let db = open_source(&destination).unwrap();
        let version: i64 = db
            .query_row("SELECT MAX(version) FROM schema_versions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, schema::MAX_VERSION);
        let generation: i64 = db
            .query_row(
                "SELECT recovery_generation FROM administrator_auth_state",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(generation, 1);
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_database_and_destination_symlinks() {
        use std::os::unix::fs::symlink;

        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("source.db");
        drop(controller_database(&source, 10));
        let link = work.path().join("link.db");
        let destination = work.path().join("destination.db");
        symlink(&source, &link).unwrap();
        assert!(database(&link, &destination, &RUNNING).is_err());
        fs::remove_file(&link).unwrap();
        symlink(&destination, &link).unwrap();
        assert!(database(&source, &link, &RUNNING).is_err());
        assert!(!destination.exists());
    }
}
