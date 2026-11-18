//! The same controller lifecycle lock file and flock mode as the Go service.
use anyhow::{Context, Result, ensure};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

pub(crate) fn existing_database(path: &Path) -> Result<PathBuf> {
    // Canonicalize the parent only: SQLite's NOFOLLOW also rejects symlinked
    // ancestors (for example macOS /var), while the leaf must be a real file.
    let name = path.file_name().context("database path must name a file")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let path = fs::canonicalize(parent)?.join(name);
    ensure!(
        fs::symlink_metadata(&path)?.is_file(),
        "source database must be a regular file, not a symlink"
    );
    Ok(path)
}

pub(crate) fn sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}

/// The caller keeps the handle for the full controller or maintenance lifetime.
pub fn acquire(database: &Path) -> Result<File> {
    let path = sidecar(database, ".lock");
    let fd = open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
    .context("open controller lifecycle lock")?;
    let file = File::from(fd);
    ensure!(
        file.metadata()?.is_file(),
        "controller lifecycle lock is not a regular file"
    );
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => {
            anyhow::bail!("controller database is already in use")
        }
        Err(err) => Err(err).context("lock controller lifecycle"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn locks_exclusively_and_rejects_symlinked_locks() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("controller.db");
        let lock = acquire(&path)?;
        assert!(
            acquire(&path)
                .unwrap_err()
                .to_string()
                .contains("already in use")
        );
        drop(lock);
        assert!(acquire(&path).is_ok());

        let linked = dir.path().join("linked.db");
        symlink(sidecar(&path, ".lock"), sidecar(&linked, ".lock"))?;
        assert!(acquire(&linked).is_err());
        Ok(())
    }

    #[test]
    fn canonicalizes_database_parent_but_not_the_leaf() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let actual = dir.path().join("actual");
        fs::create_dir(&actual)?;
        let db = actual.join("controller.db");
        File::create(&db)?;
        let alias = dir.path().join("alias");
        symlink(&actual, &alias)?;
        assert_eq!(
            existing_database(&alias.join("controller.db"))?,
            fs::canonicalize(&db)?
        );
        symlink(db, actual.join("linked.db"))?;
        assert!(existing_database(&alias.join("linked.db")).is_err());
        Ok(())
    }
}
