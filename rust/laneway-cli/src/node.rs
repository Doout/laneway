use std::{
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};

const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const DAEMON: &str = if cfg!(windows) {
    "lanewayd.exe"
} else {
    "lanewayd"
};

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("credential") => run_userspace(None, args),
        Some("configure") => {
            let Some(flags) = Flags::parse("configure", &args[1..])? else {
                return print_help(&args[..1]);
            };
            if flags.system || flags.check || flags.yes {
                ensure!(
                    flags.state.is_none(),
                    "--state-dir is only used in userspace mode"
                );
                configure_system(args, flags.check, flags.yes)
            } else {
                run_userspace(flags.state, &["configure".into()])
            }
        }
        Some("start") => {
            let Some(flags) = Flags::parse("start", &args[1..])? else {
                return print_help(&args[..1]);
            };
            if flags.system {
                ensure!(
                    flags.state.is_none(),
                    "--state-dir is only used in userspace mode"
                );
                ensure!(
                    flags.listen.is_none() && !flags.no_proxy && !flags.proxy_only,
                    "--listen, --no-proxy and --proxy-only are only used in userspace mode"
                );
                start_system(args, flags.config)
            } else {
                ensure!(flags.config.is_none(), "--config requires --system");
                ensure!(
                    !flags.no_proxy || (flags.listen.is_none() && !flags.proxy_only),
                    "--no-proxy cannot be used with --listen or --proxy-only"
                );
                run_userspace(
                    flags.state,
                    &userspace_start_args(flags.listen, flags.no_proxy, flags.proxy_only),
                )
            }
        }
        _ => bail!("unknown node command"),
    }
}

fn print_help(command: &[OsString]) -> Result<()> {
    let usage = crate::product_usage(command).context("missing node command help")?;
    println!("Usage: {usage}");
    Ok(())
}

fn userspace_start_args(
    listen: Option<OsString>,
    no_proxy: bool,
    proxy_only: bool,
) -> Vec<OsString> {
    let mut args = vec!["run".into()];
    if let Some(listen) = listen {
        args.extend(["--listen".into(), listen]);
    }
    if no_proxy {
        args.push("--no-proxy".into());
    }
    if proxy_only {
        args.push("--proxy-only".into());
    }
    args
}

fn run_userspace(state: Option<OsString>, args: &[OsString]) -> Result<()> {
    guard_managed_node()?;
    let privileged = is_root();
    let path = if privileged {
        trusted_daemon()?
    } else {
        user_daemon()?
    };
    let mut command = Command::new(path);
    if let Some(state) = state {
        command.args([OsStr::new("--state-dir"), &state]);
    }
    command.args(args);
    if privileged {
        command.env("PATH", SYSTEM_PATH);
    }
    crate::compat::execute(&mut command)
}

#[cfg(target_os = "macos")]
fn configure_system(_: &[OsString], check: bool, yes: bool) -> Result<()> {
    crate::macos::configure(check, yes)
}

#[cfg(target_os = "linux")]
fn configure_system(_: &[OsString], check: bool, yes: bool) -> Result<()> {
    ensure!(
        !check && !yes,
        "--check and --yes configure the macOS network helper"
    );
    run_linux_system("configure", None)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn configure_system(_: &[OsString], _: bool, _: bool) -> Result<()> {
    bail!("native system configuration is available on Linux and macOS");
}

#[cfg(target_os = "macos")]
fn start_system(_: &[OsString], config: Option<OsString>) -> Result<()> {
    ensure!(
        config.is_none(),
        "--config is only available for Linux system networking"
    );
    crate::connect::run(&["connect".into()])
}

#[cfg(target_os = "linux")]
fn start_system(_: &[OsString], config: Option<OsString>) -> Result<()> {
    run_linux_system("run", config)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn start_system(_: &[OsString], _: Option<OsString>) -> Result<()> {
    bail!("native system networking is available on Linux and macOS");
}

#[cfg(target_os = "linux")]
fn run_linux_system(subcommand: &str, config: Option<OsString>) -> Result<()> {
    guard_managed_node()?;
    ensure!(
        config.is_some() || is_root(),
        "system enrollment uses host-owned credentials; run this command with sudo"
    );
    let mut command = Command::new(trusted_daemon()?);
    command
        .args([subcommand, "--system"])
        .env("PATH", SYSTEM_PATH);
    if let Some(config) = config {
        command.args([OsStr::new("--config"), &config]);
    }
    crate::compat::execute(&mut command)
}

fn guard_managed_node() -> Result<()> {
    #[cfg(target_os = "linux")]
    match crate::host::container_role() {
        Some(("connector", _)) => bail!(
            "this Connector is already managed by its container; reconfigure or restart it on the deployment host"
        ),
        Some(("server", _)) => bail!(
            "this service is already managed by the control plane; reconfigure or restart it on the deployment host"
        ),
        _ => (),
    }
    Ok(())
}

#[cfg(unix)]
fn is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

fn user_daemon() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(executable) = env::current_exe()
        && let Some(directory) = executable.parent()
    {
        candidates.push(directory.join(DAEMON));
        if cfg!(target_os = "linux") && directory == Path::new("/usr/local/bin") {
            candidates.push(PathBuf::from("/usr/local/sbin/lanewayd"));
        }
    }
    if cfg!(windows) {
        if let Some(data) = env::var_os("LOCALAPPDATA").filter(|data| !data.is_empty()) {
            candidates.push(PathBuf::from(data).join("Laneway").join("bin").join(DAEMON));
        }
    } else if let Some(home) = env::var_os("HOME").filter(|home| !home.is_empty()) {
        candidates.push(PathBuf::from(home).join(".local").join("bin").join(DAEMON));
    }
    if let Some(path) = env::var_os("PATH") {
        candidates.extend(env::split_paths(&path).map(|directory| directory.join(DAEMON)));
    }
    if !cfg!(windows) {
        candidates
            .extend(["/usr/local/bin/lanewayd", "/usr/local/sbin/lanewayd"].map(PathBuf::from));
    }
    candidates
        .into_iter()
        .find(|path| usable_daemon(path))
        .with_context(|| format!("{DAEMON} executable was not found; install the Laneway node"))
}

fn usable_daemon(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let Ok(resolved) = path.canonicalize() else {
        return false;
    };
    let name = resolved
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if name.eq_ignore_ascii_case("laneway") || name.eq_ignore_ascii_case("laneway.exe") {
        return false;
    }
    if !resolved.is_file() {
        return false;
    }
    #[cfg(unix)]
    return nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok();
    #[cfg(not(unix))]
    true
}

fn trusted_daemon() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(executable) = env::current_exe() {
        candidates.push(executable.with_file_name("lanewayd"));
    }
    candidates.extend(
        [
            "/usr/local/sbin/lanewayd",
            "/usr/local/bin/lanewayd",
            "/usr/bin/lanewayd",
        ]
        .map(PathBuf::from),
    );
    candidates
        .into_iter()
        .find(|path| trusted_system_daemon(path))
        .context("no system-owned lanewayd executable found; install the Laneway system package")
}

#[cfg(unix)]
fn trusted_system_daemon(path: &Path) -> bool {
    crate::compat::trusted_executable(path)
}

#[cfg(not(unix))]
fn trusted_system_daemon(_: &Path) -> bool {
    false
}

#[derive(Default)]
struct Flags {
    system: bool,
    check: bool,
    yes: bool,
    state: Option<OsString>,
    config: Option<OsString>,
    listen: Option<OsString>,
    no_proxy: bool,
    proxy_only: bool,
}

impl Flags {
    fn parse(command: &str, args: &[OsString]) -> Result<Option<Self>> {
        let usage = match command {
            "configure" => "usage: laneway configure [--state-dir PATH | --system]",
            _ => "usage: laneway start [--state-dir PATH | --system [--config PATH]]",
        };
        let mut flags = Self::default();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let (name, value) = split_flag(arg);
            if name == "--" && value.is_none() {
                ensure!(args.len() == 0, "{usage}");
                break;
            }
            let name = name
                .strip_prefix("--")
                .or_else(|| name.strip_prefix('-'))
                .filter(|name| !name.is_empty())
                .context(usage)?;
            let mut value_arg = || -> Result<Option<OsString>> {
                let value = value
                    .clone()
                    .or_else(|| args.next().cloned())
                    .with_context(|| format!("flag needs an argument: -{name}"))?;
                Ok((!value.is_empty()).then_some(value))
            };
            let boolean = || {
                parse_bool(value.as_deref())
                    .with_context(|| format!("invalid boolean value for -{name}"))
            };
            match name {
                "h" | "help" => return Ok(None),
                "system" => flags.system = boolean()?,
                "check" if command == "configure" => flags.check = boolean()?,
                "yes" if command == "configure" => flags.yes = boolean()?,
                "state-dir" => flags.state = value_arg()?,
                "config" if command == "start" => flags.config = value_arg()?,
                "listen" if command == "start" => flags.listen = value_arg()?,
                "no-proxy" if command == "start" => flags.no_proxy = boolean()?,
                "proxy-only" if command == "start" => flags.proxy_only = boolean()?,
                _ => bail!("flag provided but not defined: -{name}"),
            }
        }
        Ok(Some(flags))
    }
}

pub(crate) fn parse_bool(value: Option<&OsStr>) -> Result<bool> {
    if value.is_none() {
        return Ok(true);
    }
    match value.and_then(OsStr::to_str) {
        Some("1" | "t" | "T" | "TRUE" | "True" | "true") => Ok(true),
        Some("0" | "f" | "F" | "FALSE" | "False" | "false") => Ok(false),
        _ => bail!("expected true or false"),
    }
}

#[cfg(unix)]
pub(crate) fn split_flag(arg: &OsStr) -> (&str, Option<OsString>) {
    use std::os::unix::ffi::OsStrExt;

    let bytes = arg.as_bytes();
    match bytes.iter().position(|byte| *byte == b'=') {
        Some(index) => (
            std::str::from_utf8(&bytes[..index]).unwrap_or_default(),
            Some(OsStr::from_bytes(&bytes[index + 1..]).to_owned()),
        ),
        None => (arg.to_str().unwrap_or_default(), None),
    }
}

#[cfg(not(unix))]
pub(crate) fn split_flag(arg: &OsStr) -> (&str, Option<OsString>) {
    match arg.to_str().unwrap_or_default().split_once('=') {
        Some((name, value)) => (name, Some(value.into())),
        None => (arg.to_str().unwrap_or_default(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn forwards_userspace_options_in_daemon_order() {
        let flags = Flags::parse(
            "start",
            &argv(&[
                "--proxy-only=TRUE",
                "-state-dir=/tmp/a b",
                "--listen",
                "127.0.0.1:8000",
                "--system=false",
            ]),
        )
        .unwrap()
        .unwrap();
        assert!(!flags.system);
        assert_eq!(flags.state.as_deref(), Some(OsStr::new("/tmp/a b")));
        assert_eq!(
            userspace_start_args(flags.listen, flags.no_proxy, flags.proxy_only),
            argv(&["run", "--listen", "127.0.0.1:8000", "--proxy-only"]),
        );
    }

    #[test]
    fn rejects_mixed_mode_options_before_daemon_discovery() {
        for (args, message) in [
            (
                &["configure", "--system", "--state-dir", "/tmp/user"][..],
                "--state-dir is only used",
            ),
            (
                &["start", "--config", "node.toml"][..],
                "--config requires --system",
            ),
            (
                &["start", "--system", "--no-proxy"][..],
                "only used in userspace mode",
            ),
            (
                &["start", "--system", "--listen", "127.0.0.1:8000"][..],
                "only used in userspace mode",
            ),
            (
                &["start", "--no-proxy", "--proxy-only"][..],
                "--no-proxy cannot be used",
            ),
            (&["start", "--config"][..], "flag needs an argument"),
        ] {
            let error = run(&argv(args)).unwrap_err().to_string();
            assert!(error.contains(message), "{args:?}: {error}");
        }
    }

    #[test]
    fn recognizes_help_after_flags_and_keeps_flag_like_values() {
        assert!(
            Flags::parse("start", &argv(&["--system", "--help"]))
                .unwrap()
                .is_none()
        );
        assert!(
            Flags::parse("configure", &argv(&["--check", "-h"]))
                .unwrap()
                .is_none()
        );
        let flags = Flags::parse("start", &argv(&["--state-dir", "--help"]))
            .unwrap()
            .unwrap();
        assert_eq!(flags.state.as_deref(), Some(OsStr::new("--help")));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_config_and_state_paths() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let non_utf8 = OsString::from_vec(vec![b'n', 0xff]);
        let flags = Flags::parse(
            "start",
            &[
                OsString::from_vec(b"--state-dir=\xff".to_vec()),
                "--config".into(),
                non_utf8.clone(),
            ],
        )
        .unwrap()
        .unwrap();

        assert_eq!(flags.state.unwrap().as_bytes(), b"\xff");
        assert_eq!(flags.config, Some(non_utf8));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_relative_paths_symlinks_and_writable_ancestors_for_root() {
        use std::{
            fs,
            os::unix::{fs::PermissionsExt, fs::symlink},
        };
        let unique = format!("laneway-daemon-trust-{}", std::process::id());
        let directory = env::temp_dir().join(unique);
        fs::create_dir(&directory).unwrap();
        let daemon = directory.join("lanewayd");
        fs::write(&daemon, b"test fixture").unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o700)).unwrap();
        let symlinked = directory.join("laneway-link");
        symlink(&daemon, &symlinked).unwrap();
        assert!(!trusted_system_daemon(Path::new("lanewayd")));
        assert!(!trusted_system_daemon(&symlinked));
        assert!(!trusted_system_daemon(&daemon));
        fs::remove_dir_all(directory).unwrap();
    }
}
