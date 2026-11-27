//! Signed client package staging and per-user installation for Linux and macOS.
use std::{
    cmp::Ordering,
    env,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

use crate::signed_release::{self as release, ClientArchive};

const DAEMON: &str = "lanewayd-rs";

/// Return the per-user installation directory only for its owning user.
pub fn user_bin(source: &Path, uid: u32) -> Result<Option<PathBuf>> {
    if uid != 0
        && let Some(home) = env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_absolute())
        && let Ok(bin) = home.join(".local/bin").canonicalize()
        && source == bin.join("laneway")
    {
        check_user_file(source, uid)?;
        return Ok(Some(bin));
    }
    Ok(None)
}

/// Stage an authenticated matching pair from the latest stable release.
pub async fn prepare(directory: &Path, previous: &str) -> Result<(String, ClientArchive)> {
    let tag = release::latest_tag().await?;
    prevent_downgrade(&tag, previous)?;
    let archive = release::client_archive(&tag, directory)
        .await
        .with_context(|| format!("prepare the signed client release {tag}"))?;
    let version = tag.strip_prefix('v').context("invalid release tag")?;
    for (candidate, flag) in [(&archive.cli, "version"), (&archive.daemon, "--version")] {
        ensure!(
            read_version(candidate, flag).await? == version,
            "downloaded executable must match release {tag}"
        );
    }
    Ok((tag, archive))
}

/// Authenticate and install a client package owned by the invoking user.
pub async fn update_user(bin: &Path, uid: u32) -> Result<()> {
    let cli = bin.join("laneway");
    let daemon = bin.join(DAEMON);
    check_user_file(&cli, uid)?;
    check_user_file(&daemon, uid)?;
    let stage = tempfile::Builder::new()
        .prefix(".laneway-client-update-")
        .tempdir_in("/tmp")?;
    let (tag, archive) = prepare(stage.path(), &read_version(&cli, "version").await?).await?;
    let mut lock = InstallLock::acquire(bin)?;
    check_user_file(&cli, uid)?;
    check_user_file(&daemon, uid)?;
    prevent_downgrade(&tag, &read_version(&cli, "version").await?)?;
    install_user(&mut lock, &archive, &cli, &daemon)?;
    report(&tag, &archive);
    Ok(())
}

pub(crate) fn report(tag: &str, archive: &ClientArchive) {
    println!(
        "updated CLI and Rust runtime to {tag} sha256={}",
        hex::encode(archive.checksum)
    );
}

fn check_user_file(path: &Path, uid: u32) -> Result<()> {
    let metadata = path.symlink_metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o100 != 0,
        "refusing to use unsafe client file {}",
        path.display()
    );
    Ok(())
}

/// Reject a stable package older than the installed release.
pub fn prevent_downgrade(candidate: &str, previous: &str) -> Result<()> {
    ensure!(
        release::compare_versions(candidate, previous)? != Ordering::Less,
        "latest stable release {candidate} would downgrade installed {previous}"
    );
    Ok(())
}

/// Run a protected executable's version probe with a bounded reply.
pub async fn read_version(executable: &Path, flag: &str) -> Result<String> {
    let version = timeout(Duration::from_secs(5), async {
        let mut child = Command::new(executable)
            .arg(flag)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("read client version")?
            .take(129)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 128 && child.wait().await?.success(),
            "cannot determine stable version at {}",
            executable.display()
        );
        Ok::<_, anyhow::Error>(String::from_utf8(bytes)?.trim().to_owned())
    })
    .await??;
    ensure!(
        laneway_protocol::fleet_updates::valid_version(&format!("v{version}")),
        "cannot determine stable version at {}",
        executable.display()
    );
    Ok(version)
}

/// Scoped lock for a protected installation directory.
pub struct InstallLock {
    path: PathBuf,
    retain: bool,
}

impl InstallLock {
    /// Acquire the lock used by the package installer.
    pub fn acquire(directory: &Path) -> Result<Self> {
        let path = directory.join(".laneway-install.lock");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("acquire Laneway install lock {}", path.display()))?;
        Ok(Self {
            path,
            retain: false,
        })
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        if !self.retain {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn copy_binary(source: &Path, destination: &Path) -> Result<()> {
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(destination)?;
    io::copy(&mut File::open(source)?, &mut to)?;
    to.sync_all()?;
    Ok(())
}

fn install_user(
    lock: &mut InstallLock,
    archive: &ClientArchive,
    cli: &Path,
    daemon: &Path,
) -> Result<()> {
    let cli_stage = lock.path.join("laneway");
    let daemon_stage = lock.path.join(DAEMON);
    let backup = lock.path.join("previous-daemon");
    for (source, target) in [
        (archive.cli.as_path(), &cli_stage),
        (archive.daemon.as_path(), &daemon_stage),
        (daemon, &backup),
    ] {
        copy_binary(source, target)?;
    }
    File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(lock.path.join("publishing"))?
        .sync_all()?;
    File::open(&lock.path)?.sync_all()?;
    fs::rename(daemon_stage, daemon)?;
    if let Err(error) = fs::rename(cli_stage, cli) {
        if let Err(restore) = fs::rename(&backup, daemon) {
            lock.retain = true;
            return Err(error).context(format!(
                "also failed to restore the previous daemon from {}: {restore}",
                backup.display()
            ));
        }
        return Err(error).context("publish client");
    }
    File::open(
        cli.parent()
            .context("missing user installation directory")?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_install_restores_daemon_if_cli_cannot_be_published() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let daemon = root.join(DAEMON);
        fs::write(&daemon, b"previous daemon")?;
        let cli = root.join("laneway");
        fs::create_dir(&cli)?;
        let archive = ClientArchive {
            archive: root.join("unused archive"),
            cli: root.join("candidate CLI"),
            daemon: root.join("candidate daemon"),
            checksum: [0; 32],
        };
        fs::write(&archive.cli, b"new client")?;
        fs::write(&archive.daemon, b"new daemon")?;
        let mut lock = InstallLock {
            path: root.join(".laneway-install.lock"),
            retain: false,
        };
        fs::create_dir(&lock.path)?;

        assert!(install_user(&mut lock, &archive, &cli, &daemon).is_err());
        assert_eq!(fs::read(&daemon)?, b"previous daemon");
        drop(lock);
        assert!(!root.join(".laneway-install.lock").exists());
        Ok(())
    }
}
