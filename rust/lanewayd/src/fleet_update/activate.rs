//! Atomic executable activation; the runtime and its credentials live outside this directory.
use super::{
    LiveStatus, Runtime, checked_command, clean_command,
    journal::{absent, sync_dir, verify_file},
};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) struct Install {
    binary: PathBuf,
    previous: PathBuf,
    next: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Activated {
    Healthy,
    RolledBack,
}

impl Install {
    pub(super) fn new(binary: &Path) -> Self {
        Self {
            binary: binary.into(),
            previous: binary.with_file_name(".lanewayd-rs-update-previous"),
            next: binary.with_file_name(".lanewayd-rs-update-next"),
        }
    }

    pub(super) fn ready(&self) -> Result<()> {
        ensure!(
            absent(&self.previous)? && absent(&self.next)?,
            "interrupted activation: inspect the previous and staged node executables"
        );
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.binary)?;
        verify_file(&file, 0o022)
    }

    pub(super) async fn apply(
        &self,
        source: &Path,
        runtime: &impl Runtime,
        before: &LiveStatus,
        target: &str,
    ) -> Result<Activated> {
        self.ready()?;
        let dir = self
            .binary
            .parent()
            .context("node executable has no install directory")?;
        let previous = before.version()?;
        // Do not take down a service that changed between claim and download.
        let current = runtime.status().await?;
        ensure!(
            current.healthy(&before.identity, &previous)?
                && current.daemon_instance_id == before.daemon_instance_id,
            "daemon changed while preparing its update"
        );

        fs::hard_link(&self.binary, &self.previous)?;
        sync_dir(dir)?;
        let mut candidate = tempfile::NamedTempFile::new_in(dir)?;
        io::copy(&mut File::open(source)?, &mut candidate)?;
        candidate
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
        candidate.as_file().sync_all()?;
        candidate.persist_noclobber(&self.next)?;
        fs::rename(&self.next, &self.binary)?;
        sync_dir(dir)?;

        let failure = if runtime.restart().await.is_ok() {
            if runtime.await_restarted(before, target).await {
                self.finish(dir)?;
                return Ok(Activated::Healthy);
            }
            "replacement did not regain authenticated controller health"
        } else {
            "replacement restart failed"
        };
        eprintln!("{failure}; restoring the previous executable");
        // Keep the old inode and recovery markers until the old release
        // actually restarts as the same node with renewed authority.
        let rejected = runtime
            .status()
            .await
            .ok()
            .map(|value| value.daemon_instance_id);
        fs::hard_link(&self.previous, &self.next)?;
        fs::rename(&self.next, &self.binary)?;
        sync_dir(dir)?;
        runtime
            .restart()
            .await
            .context("rollback restart was not confirmed")?;
        ensure!(
            runtime
                .await_rollback(before, &previous, rejected.as_deref())
                .await,
            "previous executable restored, but rollback health is unconfirmed"
        );
        self.finish(dir)?;
        Ok(Activated::RolledBack)
    }

    fn finish(&self, dir: &Path) -> Result<()> {
        fs::remove_file(&self.previous)?;
        sync_dir(dir)
    }
}

pub(super) async fn restart_systemd() -> Result<()> {
    let mut command = clean_command("/usr/bin/systemctl");
    command.args([
        "--no-pager",
        "--no-ask-password",
        "restart",
        "lanewayd-rs.service",
    ]);
    checked_command(command, Duration::from_secs(45)).await
}
