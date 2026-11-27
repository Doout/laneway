use std::{
    cmp::Ordering,
    env,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{io::AsyncReadExt, process::Command as AsyncCommand, time::timeout};

use crate::fleet_update::release::{self, ClientArchive};

const SYSTEM_CLI: &str = "/usr/local/bin/laneway";
const DAEMON: &str = "lanewayd-rs";

pub(super) enum Scope {
    User { bin: PathBuf, uid: u32 },
    System { source: PathBuf, uid: u32 },
}

impl Scope {
    pub(super) fn detect(source: &Path) -> Result<Self> {
        let uid = super::effective_uid()?;
        let source = source
            .canonicalize()
            .context("locate the installed Laneway command")?;
        if uid != 0
            && let Some(home) = env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|home| home.is_absolute())
            && let Ok(bin) = home.join(".local/bin").canonicalize()
            && source == bin.join("laneway")
        {
            check_user_file(&source, uid)?;
            return Ok(Self::User { bin, uid });
        }
        Ok(Self::System { source, uid })
    }

    pub(super) fn is_user(&self) -> bool {
        matches!(self, Self::User { .. })
    }
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

pub(super) async fn update(scope: Scope) -> Result<()> {
    let (bin, executable) = match &scope {
        Scope::User { bin, .. } => (bin.as_path(), bin.join("laneway")),
        Scope::System { source, uid } => {
            ensure!(
                source == Path::new(SYSTEM_CLI),
                "update from the installed laneway in ~/.local/bin or /usr/local/bin"
            );
            ensure!(
                *uid == 0,
                "run 'sudo /usr/local/bin/laneway update client' to update the system client"
            );
            super::protected_file(source, true)?;
            super::protected_file(Path::new("/usr/local/sbin/lanewayd-rs"), true)?;
            (
                source
                    .parent()
                    .context("missing system installation directory")?,
                source.clone(),
            )
        }
    };

    let previous = read_version(&executable, "version").await?;
    let tag = release::latest_tag().await?;
    prevent_downgrade(&tag, &previous)?;
    let stage = tempfile::Builder::new()
        .prefix(".laneway-client-update-")
        .tempdir_in(if scope.is_user() {
            Path::new("/tmp")
        } else {
            bin
        })?;
    let archive = release::client_archive(&tag, stage.path())
        .await
        .with_context(|| format!("prepare the signed Linux client release {tag}"))?;
    let version = tag.strip_prefix('v').context("invalid release tag")?;
    for (candidate, flag) in [(&archive.cli, "version"), (&archive.daemon, "--version")] {
        ensure!(
            read_version(candidate, flag).await? == version,
            "downloaded executable must match release {tag}"
        );
    }

    let lock_path = bin.join(".laneway-install.lock");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&lock_path)
        .with_context(|| format!("acquire Laneway install lock {}", lock_path.display()))?;
    let mut lock = InstallLock {
        path: lock_path,
        retain: false,
    };
    if let Scope::User { uid, .. } = scope {
        check_user_file(&executable, uid)?;
        let daemon = bin.join(DAEMON);
        check_user_file(&daemon, uid)?;
        prevent_downgrade(&tag, &read_version(&executable, "version").await?)?;
        install_user(&mut lock, &archive, &executable, &daemon)?;
    } else {
        super::protected_file(&executable, true)?;
        prevent_downgrade(&tag, &read_version(&executable, "version").await?)?;
        install_system(stage.path(), &archive.archive)?;
    }
    println!(
        "updated CLI and Rust runtime to {tag} sha256={}",
        hex::encode(archive.checksum)
    );
    Ok(())
}

fn prevent_downgrade(candidate: &str, previous: &str) -> Result<()> {
    ensure!(
        release::compare_versions(candidate, previous)? != Ordering::Less,
        "latest stable release {candidate} would downgrade installed {previous}"
    );
    Ok(())
}

async fn read_version(executable: &Path, flag: &str) -> Result<String> {
    let version = timeout(Duration::from_secs(5), async {
        let mut child = AsyncCommand::new(executable)
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

struct InstallLock {
    path: PathBuf,
    retain: bool,
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

fn install_system(directory: &Path, archive: &Path) -> Result<()> {
    super::run_helper(
        Command::new("/usr/bin/tar")
            .args(["--no-same-owner", "--no-same-permissions", "-xzf"])
            .arg(archive)
            .arg("-C")
            .arg(directory),
    )
    .context("extract verified system package")?;
    let installer = directory.join("laneway/install.sh");
    ensure!(
        installer.symlink_metadata()?.is_file(),
        "verified Linux package is missing its regular installer"
    );
    super::run_helper(Command::new("/bin/sh").arg(installer).arg("--rust-preview"))
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
