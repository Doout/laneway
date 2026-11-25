//! Public connect orchestration. Policy and credentials are verified before
//! the foreground networking backend takes ownership of the session.
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
};

use anyhow::{Context, Result, bail, ensure};

use crate::node::{parse_bool, split_flag};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod filter;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod session;

const COMMON_USAGE: &str =
    "laneway connect [DOMAIN] [--route PREFIX] [--remembered | --ephemeral] [--token-file PATH]";
const LINUX_OPTIONS: &str =
    " [--exit NAME_OR_NODE_ID] [--failure-mode open|closed] [--dns ADDRESS] [--local-lan PREFIX]";

#[cfg(target_os = "linux")]
pub(crate) use session::SessionOptions;

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    ensure!(
        args.first().is_some_and(|arg| arg == "connect"),
        "usage: {COMMON_USAGE}"
    );
    let Some(options) = Options::parse(&args[1..], cfg!(target_os = "linux"))? else {
        println!(
            "Usage: {COMMON_USAGE}{}",
            if cfg!(target_os = "linux") {
                LINUX_OPTIONS
            } else {
                ""
            }
        );
        return Ok(());
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        session::run(options)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        options.authority()?;
        options.failure_mode()?;
        bail!("foreground connect currently requires Linux or macOS")
    }
}

#[derive(Debug, Default)]
struct Options {
    authority: Option<String>,
    token_file: Option<PathBuf>,
    remembered: bool,
    ephemeral: bool,
    routes: Vec<String>,
    exit: String,
    failure_mode: Option<String>,
    dns: Vec<String>,
    local_lan: Vec<String>,
}

impl Options {
    fn parse(args: &[OsString], platform_exit: bool) -> Result<Option<Self>> {
        let mut options = Self::default();
        let mut args = args.iter();
        if args
            .as_slice()
            .first()
            .is_some_and(|arg| !arg.as_encoded_bytes().starts_with(b"-"))
        {
            options.authority = Some(string(args.next().unwrap(), "DOMAIN")?);
        }
        while let Some(arg) = args.next() {
            let (name, attached) = split_flag(arg);
            if arg == "--" {
                if let Some(domain) = args.next() {
                    ensure!(options.authority.is_none(), "usage: {COMMON_USAGE}");
                    options.authority = Some(string(domain, "DOMAIN")?);
                }
                ensure!(args.len() == 0, "usage: {COMMON_USAGE}");
                break;
            }
            if arg == "-" || !arg.as_encoded_bytes().starts_with(b"-") {
                ensure!(
                    options.authority.is_none() && args.len() == 0,
                    "usage: {COMMON_USAGE}"
                );
                options.authority = Some(string(arg, "DOMAIN")?);
                break;
            }
            let name = name
                .strip_prefix("--")
                .or_else(|| name.strip_prefix('-'))
                .filter(|value| !value.is_empty())
                .context("invalid connect flag")?;
            let mut value = || {
                attached
                    .clone()
                    .or_else(|| args.next().cloned())
                    .with_context(|| format!("flag needs an argument: -{name}"))
            };
            let boolean = || {
                parse_bool(attached.as_deref())
                    .with_context(|| format!("invalid boolean value for -{name}"))
            };
            match name {
                "h" | "help" => return Ok(None),
                "token-file" => {
                    let value = value()?;
                    options.token_file = (!value.is_empty()).then(|| value.into());
                }
                "remembered" => options.remembered = boolean()?,
                "ephemeral" => options.ephemeral = boolean()?,
                "route" => options.routes.push(string(&value()?, "route")?),
                "exit" if platform_exit => options.exit = string(&value()?, "exit")?,
                "failure-mode" if platform_exit => {
                    options.failure_mode = Some(string(&value()?, "failure-mode")?)
                }
                "dns" if platform_exit => options.dns.push(string(&value()?, "dns")?),
                "local-lan" if platform_exit => {
                    options.local_lan.push(string(&value()?, "local-lan")?)
                }
                _ => bail!("flag provided but not defined: -{name}"),
            }
        }
        ensure!(
            !(options.remembered && options.ephemeral),
            "usage: {COMMON_USAGE}"
        );
        Ok(Some(options))
    }

    fn authority(&self) -> Result<String> {
        match self.authority.as_deref().filter(|value| !value.is_empty()) {
            Some(value) => Ok(value.to_owned()),
            None => crate::profile::default_authority().map_err(|error| {
                if crate::profile::is_missing(&error) {
                    anyhow::anyhow!("no saved login; run 'laneway login DOMAIN' or specify DOMAIN for an ephemeral connection")
                } else {
                    error
                }
            }),
        }
    }

    fn failure_mode(&self) -> Result<&str> {
        let mode = self.failure_mode.as_deref().unwrap_or("closed");
        ensure!(
            matches!(mode, "closed" | "open"),
            "--failure-mode must be closed or open"
        );
        ensure!(
            !self.exit.is_empty()
                || (self.dns.is_empty()
                    && self.local_lan.is_empty()
                    && self.failure_mode.is_none()),
            "--dns, --local-lan, and --failure-mode require --exit"
        );
        Ok(mode)
    }
}

fn string(value: &OsStr, name: &str) -> Result<String> {
    value
        .to_str()
        .map(str::to_owned)
        .with_context(|| format!("{name} must be valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str], exit: bool) -> Result<Option<Options>> {
        Options::parse(&args.iter().map(OsString::from).collect::<Vec<_>>(), exit)
    }

    #[test]
    fn accepts_domain_first_and_go_flag_spellings() {
        let options = parse(
            &[
                "laneway.test",
                "-ephemeral=1",
                "--token-file",
                "/tmp/private token",
                "-route=10.0.0.0/8",
                "--route",
                "192.168.1.0/24",
            ],
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(options.authority.as_deref(), Some("laneway.test"));
        assert_eq!(
            options.token_file,
            Some(PathBuf::from("/tmp/private token"))
        );
        assert!(options.ephemeral);
        assert_eq!(options.routes, ["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(options.failure_mode().unwrap(), "closed");
    }

    #[test]
    fn rejects_conflicting_modes_and_platform_options() {
        assert!(parse(&["--remembered", "--ephemeral"], true).is_err());
        assert!(parse(&["--exit", "gateway"], false).is_err());
        assert!(
            parse(
                &["--ephemeral", "laneway.test", "--route", "10.0.0.0/8"],
                true
            )
            .is_err()
        );
        assert!(
            parse(&["--failure-mode", "closed"], true)
                .unwrap()
                .unwrap()
                .failure_mode()
                .is_err()
        );
        assert!(
            parse(&["--exit", "gateway", "--failure-mode", "broken"], true)
                .unwrap()
                .unwrap()
                .failure_mode()
                .is_err()
        );
        assert!(
            parse(&["laneway.test", "--ephemeral", "-h"], true)
                .unwrap()
                .is_none()
        );
    }
}
