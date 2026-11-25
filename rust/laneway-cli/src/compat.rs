//! Execute the installed companion without consulting the working directory or PATH.
use anyhow::{Context, Result, ensure};
use std::{env, ffi::OsString, fs, process::Command};

#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
pub fn trusted_executable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    path.is_absolute()
        && path.ancestors().all(|entry| {
            fs::symlink_metadata(entry).is_ok_and(|meta| {
                meta.uid() == 0
                    && meta.mode() & 0o022 == 0
                    && if entry == path {
                        meta.is_file() && meta.mode() & 0o100 != 0
                    } else {
                        meta.is_dir()
                    }
            })
        })
}

#[cfg(not(target_os = "macos"))]
pub fn run(args: &[OsString]) -> Result<()> {
    execute(&mut command(args)?)
}

pub(crate) fn command(args: &[OsString]) -> Result<Command> {
    let public = env::current_exe().context("locate the installed Laneway CLI")?;
    let path = public.with_file_name(format!("laneway-compat{}", env::consts::EXE_SUFFIX));
    let guidance = || {
        format!(
            "install the matching Laneway package to restore {}",
            path.display()
        )
    };
    let metadata = fs::symlink_metadata(&path).with_context(guidance)?;
    ensure!(metadata.is_file(), "{}", guidance());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current = fs::metadata(&public)?;
        ensure!(
            (metadata.dev(), metadata.ino()) != (current.dev(), current.ino()),
            "invalid Laneway compatibility executable"
        );
        if nix::unistd::Uid::effective().is_root() {
            ensure!(
                trusted_executable(&path),
                "unsafe compatibility executable: {}",
                guidance()
            );
        }
    }
    let mut command = Command::new(path);
    command.args(args);
    Ok(command)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_linux_network_helper_bridge(executable: &Path) -> Result<()> {
    ensure!(
        trusted_executable(executable),
        "install a protected root-owned Laneway package before starting the Linux network helper"
    );
    let release = Command::new(executable)
        .arg("_network-helper-bridge-version")
        .output()
        .context("verify the protected Laneway networking bridge")?;
    ensure!(
        release.status.success() && release.stdout == format!("{}\n", crate::VERSION).as_bytes(),
        "Laneway executable files do not provide matching native networking; reinstall the signed Laneway package"
    );
    Ok(())
}

pub fn execute(command: &mut Command) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec()).with_context(|| format!("execute {:?}", command.get_program()))
    }
    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .with_context(|| format!("execute {:?}", command.get_program()))?;
        std::process::exit(status.code().unwrap_or(1))
    }
}
