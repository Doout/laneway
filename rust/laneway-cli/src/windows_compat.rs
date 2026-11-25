//! Preserve the Windows signed installer's versioned companion contract.
mod version;

use std::{env, ffi::OsString, process::ExitCode};

const USAGE: &str = "Usage of _network-helper:\n  -control-fd int\n    \tinherited control socket descriptor (default -1)";
const UNSUPPORTED: &str = "platform: operation unsupported on this operating system";
const INVALID: &str = "invalid privileged helper invocation";
const PUBLIC_COMMAND: &str = "use the laneway command for client and server operations";

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Version,
    HelperHelp,
    Reject(&'static str),
}

fn invocation(args: &[OsString]) -> Invocation {
    match args {
        [arg] if arg == "version" || arg == "-version" || arg == "--version" => Invocation::Version,
        [command, option]
            if command == "_network-helper"
                && ["-h", "--help", "-help", "--h"]
                    .iter()
                    .any(|help| option == help) =>
        {
            Invocation::HelperHelp
        }
        [command, option @ ..] if command == "_network-helper" => {
            let descriptor = match option {
                [inline] => inline.to_str().and_then(|option| {
                    option
                        .strip_prefix("--control-fd=")
                        .or_else(|| option.strip_prefix("-control-fd="))
                }),
                [flag, value] if flag == "--control-fd" || flag == "-control-fd" => value.to_str(),
                _ => None,
            };
            if descriptor
                .and_then(|value| value.parse::<i64>().ok())
                .is_some_and(|fd| fd >= 0)
            {
                Invocation::Reject(UNSUPPORTED)
            } else {
                Invocation::Reject(INVALID)
            }
        }
        _ => Invocation::Reject(PUBLIC_COMMAND),
    }
}

fn main() -> ExitCode {
    match invocation(&env::args_os().skip(1).collect::<Vec<_>>()) {
        Invocation::Version => println!("{}", version::VERSION),
        Invocation::HelperHelp => eprintln!("{USAGE}"),
        Invocation::Reject(error) => {
            eprintln!("laneway: {error}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(args: &[&str]) -> Invocation {
        invocation(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn versions_and_public_refusal() {
        for version in ["version", "--version", "-version"] {
            assert_eq!(classify(&[version]), Invocation::Version);
        }
        for args in [&[][..], &["configure", "--help"], &["version", "extra"]] {
            assert_eq!(classify(args), Invocation::Reject(PUBLIC_COMMAND));
        }
    }

    #[test]
    fn helper_offers_help_and_refuses_operations() {
        assert_eq!(classify(&["_network-helper", "-h"]), Invocation::HelperHelp);
        for args in [
            &["_network-helper", "--control-fd=0"][..],
            &["_network-helper", "-control-fd", "0"],
        ] {
            assert_eq!(classify(args), Invocation::Reject(UNSUPPORTED));
        }
        for args in [
            &["_network-helper"][..],
            &["_network-helper", "--control-fd=-1"],
            &["_network-helper", "--control-fd=0", "unexpected"],
        ] {
            assert_eq!(classify(args), Invocation::Reject(INVALID));
        }
    }
}
