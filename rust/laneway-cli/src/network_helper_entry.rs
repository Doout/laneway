//! Command-line adapter for the inherited privileged helper channel.

use std::{ffi::OsString, os::fd::BorrowedFd};

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::libc;

const USAGE: &str = "Usage of _network-helper:\n  -control-fd int\n    \tinherited control socket descriptor (default -1)";

enum Invocation {
    Help,
    Serve(i32),
}

fn parse(args: &[OsString]) -> Result<Invocation> {
    let mut args = args.iter();
    let mut descriptor = None;
    while let Some(arg) = args.next() {
        let arg = arg
            .to_str()
            .context("invalid privileged helper invocation")?;
        if arg == "--" && args.len() == 0 {
            break;
        }
        let flag = arg
            .strip_prefix("--")
            .or_else(|| arg.strip_prefix('-'))
            .context("invalid privileged helper invocation")?;
        let (name, inline) = flag
            .split_once('=')
            .map_or((flag, None), |(name, value)| (name, Some(value)));
        match name {
            "h" | "help" => return Ok(Invocation::Help),
            "control-fd" => {
                let value = inline
                    .or_else(|| args.next().and_then(|value| value.to_str()))
                    .context("missing -control-fd value")?;
                descriptor = Some(value.parse::<i32>().context("invalid -control-fd value")?);
            }
            _ => bail!("invalid privileged helper option: {arg}"),
        }
    }
    descriptor
        .filter(|fd| *fd >= 0)
        .map(Invocation::Serve)
        .ok_or_else(|| anyhow!("invalid privileged helper invocation"))
}

pub fn run(args: &[OsString], serve: impl FnOnce(BorrowedFd<'_>) -> Result<()>) -> Result<()> {
    match parse(args)? {
        Invocation::Help => eprintln!("{USAGE}"),
        Invocation::Serve(raw) => {
            ensure!(
                nix::unistd::Uid::effective().is_root(),
                "the network helper requires root"
            );
            // SAFETY: F_GETFD accepts any integer, returning EBADF for a closed descriptor.
            if unsafe { libc::fcntl(raw, libc::F_GETFD) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("inspect inherited control descriptor");
            }
            // SAFETY: The descriptor is open and this startup path has not spawned
            // threads. This function borrows it only while the helper serves.
            serve(unsafe { BorrowedFd::borrow_raw(raw) })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn accepts_existing_helper_arguments_and_offline_help() {
        for args in [args(&["--control-fd=0"]), args(&["-control-fd", "0", "--"])] {
            assert!(matches!(parse(&args).unwrap(), Invocation::Serve(0)));
        }
        assert!(matches!(
            parse(&args(&["--help"])).unwrap(),
            Invocation::Help
        ));
        run(&args(&["--help"]), |_| {
            panic!("help must not start a helper")
        })
        .unwrap();
    }

    #[test]
    fn rejects_positionals_and_malformed_descriptors() {
        for args in [
            args(&[]),
            args(&["--control-fd"]),
            args(&["--control-fd=-1"]),
            args(&["--control-fd=0", "--", "extra"]),
            args(&["--control-fd=999999999999999999"]),
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
}
