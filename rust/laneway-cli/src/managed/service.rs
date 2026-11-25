use std::{
    ffi::CString,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use nix::unistd::{Group, User, getgrouplist};

const UNIT: &str = "lanewayd.service";
const DEADLINE: Duration = Duration::from_secs(45);

pub(super) struct Systemd {
    program: PathBuf,
}

impl Systemd {
    pub(super) fn installed() -> Result<Self> {
        for candidate in ["/usr/bin/systemctl", "/bin/systemctl"] {
            if let Ok(path) = fs::canonicalize(candidate)
                && crate::compat::trusted_executable(&path)
            {
                return Ok(Self { program: path });
            }
        }
        bail!("a protected installed systemctl is required for managed node commands")
    }

    pub(super) fn start(&self, enable: bool) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        if enable {
            self.command(&["enable", "--now", UNIT], deadline, false)?;
        } else {
            self.command(&["start", UNIT], deadline, false)?;
        }
        for probe in 0..10 {
            self.command(&["is-active", "--quiet", UNIT], deadline, true)
                .context("lanewayd did not remain active after start")?;
            if probe < 9 {
                thread::sleep(Duration::from_millis(200));
            }
        }
        Ok(())
    }

    pub(super) fn stop(&self) -> Result<()> {
        self.command(&["stop", UNIT], Instant::now() + DEADLINE, false)
    }

    pub(super) fn reset_failed(&self) {
        let _ = self.command(&["reset-failed", UNIT], Instant::now() + DEADLINE, true);
    }

    pub(super) fn cleanup(&self) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        let _ = self.command(&["reset-failed", UNIT], deadline, true);
        let stopped = self.command(&["stop", UNIT], deadline, false);
        let disabled = self.command(&["disable", UNIT], deadline, false);
        match stopped {
            Ok(()) => disabled,
            Err(error) => Err(failures(error, [disabled])),
        }
    }

    fn command(&self, arguments: &[&str], deadline: Instant, quiet: bool) -> Result<()> {
        ensure!(Instant::now() < deadline, "systemctl operation timed out");
        let mut command = Command::new(&self.program);
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null());
        if quiet {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("run systemctl {}", arguments[0]))?;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    ensure!(
                        status.success(),
                        "systemctl {} failed: {status}",
                        arguments[0]
                    );
                    return Ok(());
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                outcome => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return match outcome {
                        Err(error) => Err(error).context("wait for systemctl"),
                        _ => Err(anyhow::anyhow!("systemctl {} timed out", arguments[0])),
                    };
                }
            }
        }
    }
}

pub(super) fn failures(
    primary: anyhow::Error,
    secondary: impl IntoIterator<Item = Result<()>>,
) -> anyhow::Error {
    let secondary: Vec<_> = secondary
        .into_iter()
        .filter_map(Result::err)
        .map(|error| format!("{error:#}"))
        .collect();
    if secondary.is_empty() {
        primary
    } else {
        primary.context(format!(
            "additional cleanup failures: {}",
            secondary.join("; ")
        ))
    }
}

pub(super) fn preflight() -> Result<u32> {
    ensure!(
        crate::compat::trusted_executable(Path::new("/usr/local/bin/laneway")),
        "managed node requires a trusted /usr/local/bin/laneway; install the release package first"
    );
    let unit = Path::new("/usr/local/lib/systemd/system").join(UNIT);
    for path in unit.ancestors() {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("read installed unit path {}", path.display()))?;
        ensure!(
            metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && if path == unit {
                    metadata.is_file()
                } else {
                    metadata.is_dir()
                },
            "unsafe installed unit path {}",
            path.display()
        );
    }
    let account = User::from_name("laneway")?
        .context("laneway service account is missing; install the release package first")?;
    let group = Group::from_name("laneway")?.context("laneway service group is missing")?;
    ensure!(
        account.gid == group.gid
            && account.uid.as_raw() < 1000
            && group.gid.as_raw() < 1000
            && account.dir == Path::new("/var/lib/laneway")
            && matches!(
                account.shell.file_name().and_then(|part| part.to_str()),
                Some("nologin" | "false")
            ),
        "laneway service account does not match the hardened package account"
    );
    ensure!(
        group.mem.iter().all(|member| member == "laneway")
            && getgrouplist(&CString::new(account.name)?, account.gid)? == [group.gid],
        "laneway service account has unexpected supplementary groups or group members"
    );
    Ok(group.gid.as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn systemd_cleanup_attempts_disable_after_stop_failure() {
        let root = tempfile::tempdir().unwrap();
        let fake = root.path().join("systemctl");
        let trace = root.path().join("trace");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\n[ \"$1\" != stop ]\n",
                trace.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let systemd = Systemd { program: fake };
        assert!(systemd.cleanup().is_err());
        assert_eq!(
            fs::read_to_string(trace).unwrap(),
            "reset-failed\nstop\ndisable\n"
        );
    }
}
