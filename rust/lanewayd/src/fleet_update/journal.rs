use super::{RuntimeIdentity, stable_tag};
use anyhow::{Context, Result, ensure};
use laneway_protocol::{Id, fleet_updates::Report};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_JOURNAL: usize = 4096;

#[cfg(not(test))]
fn trusted_owner() -> u32 {
    0
}

#[cfg(test)]
fn trusted_owner() -> u32 {
    // Tests own their isolated fixtures; the shipped binary always checks UID zero.
    // SAFETY: this call reads the effective UID and does not mutate process state.
    unsafe { libc::geteuid() }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Entry {
    Intent {
        identity: RuntimeIdentity,
        previous: String,
    },
    Claimed {
        identity: RuntimeIdentity,
        id: String,
        previous: String,
        target: String,
    },
    Terminal {
        identity: RuntimeIdentity,
        id: String,
        report: Report,
    },
}

pub(super) struct Journal {
    root: PathBuf,
    file: PathBuf,
    _lock: File,
}

impl Journal {
    pub(super) fn open(path: &Path) -> Result<Self> {
        Self::open_named(path, None)
    }

    pub(super) fn open_named(path: &Path, connector: Option<&str>) -> Result<Self> {
        if let Err(err) = DirBuilder::new().mode(0o700).create(path) {
            ensure!(
                err.kind() == io::ErrorKind::AlreadyExists,
                "create private updater directory"
            );
        }
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == trusted_owner()
                && metadata.mode() & 0o7777 == 0o700,
            "updater state directory must be root-owned mode 0700"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join("lock"))
            .context("open updater lock")?;
        verify_file(&lock, 0o077)?;
        lock.try_lock()
            .context("another managed updater holds the lock")?;
        ensure!(
            absent(&path.join("journal.json"))?,
            "reconcile the legacy updater journal before using the Rust updater"
        );
        Ok(Self {
            root: path.into(),
            file: match connector {
                None => path.join("rust-journal.json"),
                Some(name) => path.join(format!("rust-{name}-journal.json")),
            },
            _lock: lock,
        })
    }

    pub(super) fn read(&self) -> Result<Option<Entry>> {
        if absent(&self.file)? {
            return Ok(None);
        }
        let value: Entry = serde_json::from_slice(&root_file(&self.file, 0o077, MAX_JOURNAL)?)
            .context("read the durable update journal")?;
        match &value {
            Entry::Intent { identity, previous } => {
                identity.checked()?;
                stable_tag(previous)?;
            }
            Entry::Claimed {
                identity,
                previous,
                target,
                id,
            } => {
                identity.checked()?;
                stable_tag(previous)?;
                stable_tag(target)?;
                id.parse::<Id>()?;
            }
            Entry::Terminal {
                identity,
                id,
                report,
            } => {
                identity.checked()?;
                id.parse::<Id>()?;
                ensure!(
                    report.runtime_network_id == identity.network
                        && report.runtime_node_id == identity.node,
                    "terminal result identity does not match its durable claim"
                );
            }
        }
        Ok(Some(value))
    }

    pub(super) fn save(&self, entry: &Entry) -> Result<()> {
        let mut staged = tempfile::NamedTempFile::new_in(&self.root)?;
        staged.write_all(&serde_json::to_vec(entry)?)?;
        staged.as_file().sync_all()?;
        staged.persist(&self.file)?;
        sync_dir(&self.root)
    }

    pub(super) fn clear(&self) -> Result<()> {
        fs::remove_file(&self.file)?;
        sync_dir(&self.root)
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }
}

pub(super) fn verify_file(file: &File, forbidden_bits: u32) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == trusted_owner()
            && metadata.nlink() == 1
            && metadata.mode() & (0o7000 | forbidden_bits) == 0,
        "update file must be regular, root-owned and protected"
    );
    Ok(())
}

pub(super) fn root_file(path: &Path, forbidden_bits: u32, max: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    verify_file(&file, forbidden_bits)?;
    let mut data = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut data)?;
    ensure!(data.len() <= max, "update file exceeds its size limit");
    Ok(data)
}

pub(super) fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

pub(super) fn protect_parents(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "protected updater paths must be absolute"
    );
    for directory in path
        .parent()
        .context("updater path is missing its parent")?
        .ancestors()
    {
        let data = fs::symlink_metadata(directory)?;
        ensure!(
            data.is_dir() && data.uid() == 0 && data.mode() & 0o022 == 0,
            "updater paths need root-owned, non-writable, non-symlink parents"
        );
    }
    Ok(())
}
