use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Network, Result, conflict, model::overlaps};

pub(crate) type Networks = BTreeMap<String, Network>;
const MAX_JOURNAL_BYTES: usize = 16 << 20;

#[derive(Deserialize, Serialize)]
struct Disk {
    version: u8,
    networks: Networks,
}

/// Single-writer, private, atomic ownership journal compatible with Go v1.
pub struct Store {
    path: PathBuf,
    networks: Networks,
    _lock: File,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let directory = fs::symlink_metadata(parent)?;
        if !directory.is_dir()
            || directory.mode() & 0o022 != 0
            || directory.uid() != effective_uid()
        {
            return Err(conflict(
                "ownership journal must be in a protected directory",
            ));
        }
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(lock_path)?;
        require_private_file(&lock)?;
        // SAFETY: the open file is held for the lifetime of the Store.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(conflict(format!(
                "ownership journal already locked: {}",
                io::Error::last_os_error()
            )));
        }
        let networks = match read_private::<Disk>(path, MAX_JOURNAL_BYTES as u64) {
            Ok(disk) if disk.version == 1 => disk.networks,
            Ok(_) => return Err(conflict("unsupported ownership journal version")),
            Err(crate::Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Networks::new()
            }
            Err(error) => return Err(error),
        };
        validate(&networks)?;
        Ok(Self {
            path: path.into(),
            networks,
            _lock: lock,
        })
    }

    pub fn networks(&self) -> &Networks {
        &self.networks
    }

    pub(crate) fn update(
        &mut self,
        mutation: impl FnOnce(&mut Networks) -> Result<()>,
    ) -> Result<()> {
        let mut next = self.networks.clone();
        mutation(&mut next)?;
        validate(&next)?;
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = File::open(parent)?;
        let mut stage = tempfile::NamedTempFile::new_in(parent)?;
        let body = serde_json::to_vec(&Disk {
            version: 1,
            networks: next.clone(),
        })?;
        write_journal(&mut stage, &body)?;
        stage.as_file().sync_all()?;
        stage.persist(&self.path).map_err(|error| error.error)?;
        self.networks = next;
        // Once renamed, update memory even if the filesystem reports trouble
        // syncing its directory. A later retry works with the published state.
        directory.sync_all()?;
        Ok(())
    }
}

fn write_journal(writer: &mut impl Write, body: &[u8]) -> Result<()> {
    // Reserve one byte for the newline written after the JSON body.
    if body.len() >= MAX_JOURNAL_BYTES {
        return Err(conflict("ownership journal exceeds its size limit"));
    }
    writer.write_all(body)?;
    writer.write_all(b"\n")?;
    Ok(())
}

use std::os::unix::fs::DirBuilderExt;

pub(crate) fn read_private<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    require_private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(conflict("private state file exceeds its size limit"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn require_private_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(conflict(
            "state must be a private regular file owned by the plugin",
        ));
    }
    Ok(())
}

fn validate(networks: &Networks) -> Result<()> {
    let mut bridges = BTreeSet::new();
    let mut tables = BTreeSet::new();
    let mut subnets = BTreeSet::new();
    let mut links = BTreeSet::new();
    for (id, network) in networks {
        network.validate(id)?;
        if !bridges.insert(&network.bridge)
            || !tables.insert(network.table)
            || subnets.iter().any(|prior| overlaps(network.subnet, *prior))
        {
            return Err(conflict(
                "overlapping subnets or derived ownership identifiers",
            ));
        }
        subnets.insert(network.subnet);
        for endpoint in network
            .endpoints
            .values()
            .filter(|endpoint| endpoint.has_link_intent())
        {
            if !links.insert(&endpoint.host_veth) || !links.insert(&endpoint.peer_veth) {
                return Err(conflict("derived endpoint link collision"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_limit_includes_the_final_newline() {
        let mut stage = tempfile::NamedTempFile::new().unwrap();
        let mut body = br#"{"version":1,"networks":{}}"#.to_vec();
        body.resize(MAX_JOURNAL_BYTES - 1, b' ');
        write_journal(&mut stage, &body).unwrap();
        assert_eq!(
            stage.as_file().metadata().unwrap().len(),
            MAX_JOURNAL_BYTES as u64
        );
        let parsed: Disk = read_private(stage.path(), MAX_JOURNAL_BYTES as u64).unwrap();
        assert_eq!(parsed.version, 1);

        body.push(b' ');
        let mut next = Vec::new();
        assert!(write_journal(&mut next, &body).is_err());
        assert!(next.is_empty());
    }
}
