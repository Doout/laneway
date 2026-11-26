//! Command-line adapter for the inherited privileged helper channel.

use std::{
    ffi::OsString,
    io,
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

use anyhow::{Context, Result, anyhow, bail, ensure};

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

pub fn run(args: &[OsString], serve: impl FnOnce(OwnedFd) -> Result<()>) -> Result<()> {
    match parse(args)? {
        Invocation::Help => eprintln!("{USAGE}"),
        Invocation::Serve(raw) => {
            ensure!(crate::is_root(), "the network helper requires root");
            serve(duplicate_inherited(raw)?)?;
        }
    }
    Ok(())
}

fn duplicate_inherited(raw: RawFd) -> Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC accepts integer arguments and atomically
    // allocates a fresh close-on-exec descriptor on success.
    let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error()).context("duplicate helper control descriptor");
    }
    // SAFETY: The kernel returned a new descriptor owned by this call.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };

    // The launching process supplied the original descriptor. Leave it open,
    // but ensure helper child processes do not inherit it.
    // SAFETY: F_GETFD and F_SETFD only take integer arguments.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error())
            .context("protect inherited helper control descriptor");
    }
    Ok(duplicate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn owns_only_a_close_on_exec_duplicate() {
        use std::{
            io::{Read, Write},
            os::{fd::AsRawFd, unix::net::UnixStream},
        };

        let (original, mut peer) = UnixStream::pair().unwrap();
        let raw = original.as_raw_fd();
        // SAFETY: The live socket has only integer descriptor flags.
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_SETFD, 0) }, 0);
        let duplicate = duplicate_inherited(raw).unwrap();
        assert_ne!(duplicate.as_raw_fd(), raw);
        let flags = |fd| {
            // SAFETY: F_GETFD accepts an integer and has no pointer arguments.
            unsafe { libc::fcntl(fd, libc::F_GETFD) }
        };
        assert_eq!(flags(raw), libc::FD_CLOEXEC);
        assert_eq!(flags(duplicate.as_raw_fd()), libc::FD_CLOEXEC);

        // Dropping the duplicate leaves the original socket usable.
        drop(duplicate);
        (&original).write_all(b"a").unwrap();
        let mut bytes = [0];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"a");

        // The duplicate is usable even after the original closes.
        let mut duplicate = UnixStream::from(duplicate_inherited(raw).unwrap());
        drop(original);
        duplicate.write_all(b"b").unwrap();
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"b");
    }

    #[test]
    fn rejects_invalid_inherited_descriptor() {
        let error = duplicate_inherited(-1).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EBADF)
        );
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
