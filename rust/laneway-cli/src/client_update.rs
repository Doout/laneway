use std::ffi::OsString;

use anyhow::{Result, bail};

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let options = args
        .strip_prefix(&[OsString::from("update")])
        .unwrap_or(args);
    let options = options
        .strip_prefix(&[OsString::from("client")])
        .unwrap_or(options);
    let mut yes = false;
    let mut flags = options.iter();
    while let Some(arg) = flags.next() {
        let (name, value) = crate::node::split_flag(arg);
        match name {
            "-yes" | "--yes" => yes = crate::node::parse_bool(value.as_deref())?,
            "-h" | "-help" | "--help" => {
                println!("usage: laneway update client [--yes]");
                return Ok(());
            }
            "--" if flags.len() == 0 && value.is_none() => break,
            _ => bail!("usage: laneway update client [--yes]"),
        }
    }
    platform_run(args, yes)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_run(args: &[OsString], _: bool) -> Result<()> {
    crate::compat::run(args)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn platform_run(_: &[OsString], yes: bool) -> Result<()> {
    unix::run(yes)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "client_update_unix.rs"]
pub(crate) mod unix;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[path = "client_update_release.rs"]
pub(crate) mod release;

#[cfg(target_os = "windows")]
#[path = "client_update_windows.rs"]
mod windows;

#[cfg(target_os = "windows")]
fn platform_run(_: &[OsString], yes: bool) -> Result<()> {
    windows::run(yes)
}
