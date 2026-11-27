use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};

const SYSTEM_PATHS: [&str; 2] = [
    "/usr/local/sbin/laneway-control",
    "/opt/laneway/laneway-control",
];
const OPERATIONS: &[&str] = &[
    "init",
    "user-token",
    "invite",
    "route",
    "status",
    "update",
    "production-check",
    "readiness",
    "backup",
    "restore",
    "upgrade",
    "rollback",
    "administrator",
];

pub(super) fn run(args: &[OsString]) -> Result<()> {
    let operation = args.first().and_then(|arg| arg.to_str());
    if operation.is_none() || matches!(operation, Some("help" | "--help" | "-h")) {
        println!(
            "Usage: laneway control <{}> [options]",
            OPERATIONS.join("|")
        );
        return Ok(());
    }
    ensure!(
        operation.is_some_and(|operation| OPERATIONS.contains(&operation)),
        "unknown control-plane command"
    );
    let path = if let Some(override_path) =
        env::var_os("LANEWAY_CONTROL_COMMAND").filter(|path| !path.is_empty())
    {
        resolve(&override_path)
            .with_context(|| format!("find control-plane command {override_path:?}"))?
    } else {
        SYSTEM_PATHS
            .into_iter()
            .map(PathBuf::from)
            .find(|path| executable(path))
            .or_else(|| resolve(OsStr::new("laneway-control")))
            .context("control plane is not installed; expected /usr/local/sbin/laneway-control")?
    };
    let error = Command::new(&path).args(args).exec();
    Err(error).with_context(|| format!("execute {}", path.display()))
}

fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|data| data.is_file() && data.permissions().mode() & 0o111 != 0)
}

fn resolve(command: &OsStr) -> Option<PathBuf> {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return executable(path).then(|| path.to_path_buf());
    }
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join(command))
            .find(|path| executable(path))
    })
}
