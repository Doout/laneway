use crate::client_package::{self, InstallLock, prevent_downgrade, read_version};
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const SYSTEM_CLI: &str = "/usr/local/bin/laneway";

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
        if let Some(bin) = client_package::user_bin(&source, uid)? {
            return Ok(Self::User { bin, uid });
        }
        Ok(Self::System { source, uid })
    }

    pub(super) fn is_user(&self) -> bool {
        matches!(self, Self::User { .. })
    }
}

pub(super) async fn update(scope: Scope) -> Result<()> {
    let (source, uid) = match scope {
        Scope::User { bin, uid } => return client_package::update_user(&bin, uid).await,
        Scope::System { source, uid } => (source, uid),
    };
    ensure!(
        source == Path::new(SYSTEM_CLI),
        "update from the installed laneway in ~/.local/bin or /usr/local/bin"
    );
    ensure!(
        uid == 0,
        "run 'sudo /usr/local/bin/laneway update client' to update the system client"
    );
    super::protected_file(&source, true)?;
    super::protected_file(Path::new("/usr/local/sbin/lanewayd-rs"), true)?;
    let bin = source
        .parent()
        .context("missing system installation directory")?;
    let stage = tempfile::Builder::new()
        .prefix(".laneway-client-update-")
        .tempdir_in(bin)?;
    let (tag, archive) =
        client_package::prepare(stage.path(), &read_version(&source, "version").await?).await?;
    let _lock = InstallLock::acquire(bin)?;
    super::protected_file(&source, true)?;
    prevent_downgrade(&tag, &read_version(&source, "version").await?)?;
    install_system(stage.path(), &archive.archive)?;
    client_package::report(&tag, &archive);
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
