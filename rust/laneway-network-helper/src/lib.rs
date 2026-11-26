//! Privileged network setup over the Laneway inherited socket protocol.

#![cfg(any(target_os = "linux", target_os = "macos"))]

mod entry;
mod server;

use std::ffi::OsString;

/// Runs the privileged helper before starting the application's async runtime.
/// Pass only the arguments after the `_network-helper` command. Keep the
/// inherited descriptor open while the helper starts. The helper owns its
/// duplicate and marks the original close-on-exec without taking ownership.
pub fn run(args: &[OsString]) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let serve = server::linux::serve;
    #[cfg(target_os = "macos")]
    let serve = server::serve_darwin;
    entry::run(args, serve)
}

fn is_root() -> bool {
    // SAFETY: geteuid reads the calling process identity without accessing memory.
    unsafe { libc::geteuid() == 0 }
}
