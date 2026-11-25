#[cfg(not(target_os = "linux"))]
pub(crate) fn run(_: &[std::ffi::OsString]) -> anyhow::Result<()> {
    anyhow::bail!("the Docker Compose control plane is supported on Linux")
}

#[cfg(target_os = "linux")]
pub(crate) use linux::run;

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        env,
        ffi::{OsStr, OsString},
        fs,
        io::ErrorKind,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        path::{Component, Path, PathBuf},
        process::Command,
    };

    use anyhow::{Context, Result, bail, ensure};
    use nix::unistd::{AccessFlags, access, geteuid};

    const SYSTEM_HELPERS: [&str; 2] = [
        "/usr/local/sbin/laneway-control",
        "/opt/laneway/laneway-control",
    ];
    const FIXED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    const OVERRIDE: &str = "LANEWAY_CONTROL_COMMAND";
    const USAGE: &str = "Usage: laneway control <command> [options]\n\nCommands:\n  init               Initialize or validate the control plane\n  user-token         Create a one-time local-user login token\n  invite             Create a single-use enrollment command\n  route              Assign an approved destination to a Connector\n  status             Show service health, active enrollments, and forwarding\n  administrator      Bootstrap or recover administrator access\n  update             Update to the latest stable release\n  production-check   Run production checks\n  backup             Create an encrypted recovery bundle\n  restore            Restore an encrypted recovery bundle\n  upgrade            Upgrade using a prepared release environment\n  rollback           Roll back to the previous release selection";

    const ADMIN_USAGE: &str =
        "Usage: laneway control administrator <bootstrap|recover|root-token> [options]";
    const ROOT_TOKEN_USAGE: &str = "Usage: laneway control administrator root-token rotate";

    enum Invocation {
        Help(String),
        Helper(Vec<OsString>),
    }

    pub(crate) fn run(args: &[OsString]) -> Result<()> {
        ensure!(
            args.first().is_some_and(|arg| arg == "control"),
            "expected the control command"
        );
        let arguments = match parse(&args[1..])? {
            Invocation::Help(usage) => {
                println!("{usage}");
                return Ok(());
            }
            Invocation::Helper(arguments) => arguments,
        };
        let elevated = geteuid().is_root();
        let override_path = env::var_os(OVERRIDE).filter(|value| !value.is_empty());
        let path = resolve_helper(
            elevated,
            override_path.as_deref(),
            env::var_os("PATH").as_deref(),
        )?;
        let status = helper_command(&path, arguments, elevated)
            .status()
            .with_context(|| format!("execute control-plane command {}", path.display()))?;
        ensure!(
            status.success(),
            "control-plane command failed with {status}"
        );
        Ok(())
    }

    fn helper_command(path: &Path, args: Vec<OsString>, elevated: bool) -> Command {
        let mut command = Command::new(path);
        command.args(args).env_remove(OVERRIDE);
        if elevated {
            command.env("PATH", FIXED_PATH);
            for key in ["ENV", "BASH_ENV", "CDPATH", "IFS"] {
                command.env_remove(key);
            }
        }
        command
    }

    fn parse(args: &[OsString]) -> Result<Invocation> {
        let Some((name, rest)) = args.split_first() else {
            return help(USAGE);
        };
        match name.to_str() {
            Some("help") => match rest.first().and_then(|arg| arg.to_str()) {
                Some("administrator") => {
                    let mut path = rest[1..].to_vec();
                    path.push("--help".into());
                    parse_administrator(&path)
                }
                Some(command) => operator_usage(command).map_or_else(|| help(USAGE), help),
                None => help(USAGE),
            },
            Some("-h" | "--help") => help(USAGE),
            Some("administrator") => parse_administrator(rest),
            command => {
                let Some(usage) = command.and_then(operator_usage) else {
                    bail!("unknown control command {name:?}\n{USAGE}");
                };
                match rest {
                    [flag] if is_help(flag) => help(usage),
                    [verb, flag] if name == "route" && verb == "add" && is_help(flag) => {
                        help(usage)
                    }
                    _ => Ok(Invocation::Helper(args.to_vec())),
                }
            }
        }
    }

    fn operator_usage(command: &str) -> Option<&'static str> {
        Some(match command {
            "init" => "Usage: laneway control init [--issuer OFFLINE_BUNDLE | --dev]",
            "user-token" => "Usage: laneway control user-token --name NAME [--expires-in 10m]",
            "api-token" => "Usage: laneway control api-token --name NAME [--expires-in 10m]",
            "invite" => {
                "Usage: laneway control invite --name NAME [--ephemeral|--remembered] [--native [--connector] | --docker --connector [--bootstrap]]"
            }
            "route" => {
                "Usage: laneway control route add --connector NAME --to IP_OR_PREFIX [--allow USER] [--mode nat|routed] [--metric NUMBER]"
            }
            "status" => "Usage: laneway control status [--json]",
            "update" => "Usage: laneway control update",
            "production-check" => "Usage: laneway control production-check",
            "backup" => "Usage: laneway control backup [NAME.age]",
            "restore" => "Usage: laneway control restore BUNDLE.age --identity AGE_IDENTITY_FILE",
            "upgrade" => "Usage: laneway control upgrade CANDIDATE.env [MIGRATION_DIR]",
            "rollback" => "Usage: laneway control rollback",
            _ => return None,
        })
    }

    fn is_help(arg: &OsStr) -> bool {
        arg == "--help" || arg == "-h"
    }

    fn parse_administrator(args: &[OsString]) -> Result<Invocation> {
        let Some((name, rest)) = args.split_first() else {
            return help(ADMIN_USAGE);
        };
        match name.to_str() {
            Some("-h" | "--help") => help(ADMIN_USAGE),
            Some(action @ ("bootstrap" | "recover")) => {
                if rest.iter().any(|arg| is_help(arg)) {
                    return help(&format!(
                        "Usage: laneway control administrator {action} --username USERNAME"
                    ));
                }
                let username = parse_username(rest).with_context(|| {
                    format!("administrator {action} requires a valid --username")
                })?;
                Ok(Invocation::Helper(
                    ["administrator", action, "--username", username]
                        .into_iter()
                        .map(OsString::from)
                        .collect(),
                ))
            }
            Some("root-token") => match rest {
                [] => help(ROOT_TOKEN_USAGE),
                [flag] if is_help(flag) => help(ROOT_TOKEN_USAGE),
                [verb] if verb == "rotate" => Ok(Invocation::Helper(
                    ["administrator", "root-token", "rotate"]
                        .into_iter()
                        .map(OsString::from)
                        .collect(),
                )),
                [verb, flag] if verb == "rotate" && is_help(flag) => help(ROOT_TOKEN_USAGE),
                _ => bail!("{ROOT_TOKEN_USAGE}"),
            },
            _ => bail!("{ADMIN_USAGE}"),
        }
    }

    fn help(usage: &str) -> Result<Invocation> {
        Ok(Invocation::Help(usage.to_owned()))
    }

    fn parse_username(args: &[OsString]) -> Option<&str> {
        let mut args = args.iter();
        let mut username = None;
        while let Some(argument) = args.next() {
            let argument = argument.to_str()?;
            if argument == "--username" {
                username = Some(args.next()?.to_str()?);
            } else if let Some(value) = argument.strip_prefix("--username=") {
                username = Some(value);
            } else if argument != "--" || args.next().is_some() {
                return None;
            }
        }
        let username = username?;
        let bytes = username.as_bytes();
        ((3..=64).contains(&bytes.len())
            && bytes.iter().enumerate().all(|(index, &byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && index + 1 < bytes.len() && matches!(byte, b'.' | b'_' | b'-'))
            }))
        .then_some(username)
    }

    fn resolve_helper(
        elevated: bool,
        custom: Option<&OsStr>,
        path: Option<&OsStr>,
    ) -> Result<PathBuf> {
        if let Some(custom) = custom {
            return if elevated {
                protected_helper(Path::new(custom))
                    .with_context(|| format!("unsafe {OVERRIDE} helper"))
            } else {
                user_helper(custom, path)
                    .with_context(|| format!("find control-plane command {custom:?}"))
            };
        }
        for candidate in SYSTEM_HELPERS.map(Path::new) {
            if elevated {
                match fs::symlink_metadata(candidate) {
                    Ok(_) => return protected_helper(candidate),
                    Err(error) if error.kind() == ErrorKind::NotFound => (),
                    Err(error) => {
                        return Err(error).context("inspect installed control-plane command");
                    }
                }
            } else if executable(candidate) {
                return Ok(candidate.to_path_buf());
            }
        }
        if !elevated && let Ok(helper) = user_helper(OsStr::new("laneway-control"), path) {
            return Ok(helper);
        }
        bail!(
            "control plane is not installed; expected {}",
            SYSTEM_HELPERS[0]
        )
    }

    fn user_helper(name: &OsStr, path: Option<&OsStr>) -> Result<PathBuf> {
        let explicit_path = name.as_bytes().contains(&b'/');
        let name = Path::new(name);
        if explicit_path {
            ensure!(executable(name), "helper is not executable");
            return Ok(name.to_path_buf());
        }
        for directory in path.into_iter().flat_map(env::split_paths) {
            let candidate = directory.join(name);
            if executable(&candidate) {
                ensure!(
                    candidate.is_absolute(),
                    "cannot run helper found through a relative PATH entry"
                );
                return Ok(candidate);
            }
        }
        bail!("helper is not executable or was not found on PATH")
    }

    fn executable(path: &Path) -> bool {
        path.is_file() && access(path, AccessFlags::X_OK).is_ok()
    }

    fn protected_helper(path: &Path) -> Result<PathBuf> {
        let mut target = path.to_path_buf();
        for _ in 0..16 {
            ensure!(
                target.is_absolute() && !target.components().any(|c| c == Component::ParentDir),
                "expected an absolute helper path without parent traversal"
            );
            for parent in target.ancestors().skip(1) {
                let metadata = fs::symlink_metadata(parent)
                    .with_context(|| format!("inspect helper directory {}", parent.display()))?;
                ensure!(
                    metadata.is_dir() && root_owned(&metadata) && metadata.mode() & 0o022 == 0,
                    "unsafe control-plane helper directory {}",
                    parent.display()
                );
            }
            let metadata = fs::symlink_metadata(&target)
                .with_context(|| format!("inspect control-plane helper {}", target.display()))?;
            ensure!(
                root_owned(&metadata),
                "control-plane helper must be owned by root"
            );
            if metadata.is_symlink() {
                let link = fs::read_link(&target)?;
                target = if link.is_absolute() {
                    link
                } else {
                    target.with_file_name(link)
                };
            } else {
                ensure!(
                    metadata.is_file()
                        && metadata.mode() & 0o022 == 0
                        && metadata.mode() & 0o100 != 0,
                    "control-plane helper must be a protected executable file"
                );
                return Ok(target);
            }
        }
        bail!("too many symbolic links resolving the control-plane helper")
    }

    fn root_owned(metadata: &fs::Metadata) -> bool {
        metadata.uid() == 0 && metadata.gid() == 0
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn argv(args: &[&str]) -> Vec<OsString> {
            args.iter().map(OsString::from).collect()
        }

        #[test]
        fn forwards_operator_arguments_without_reinterpreting_them() {
            for arguments in [
                argv(&["status", "--json"]),
                argv(&["backup", "a b.age"]),
                argv(&["restore", "recovery.age", "--identity", "/tmp/key"]),
                argv(&["api-token", "--name", "legacy"]),
                vec![
                    "status".into(),
                    OsString::from(std::ffi::OsStr::from_bytes(b"\xff")),
                ],
            ] {
                match parse(&arguments).unwrap() {
                    Invocation::Helper(parsed) => assert_eq!(parsed, arguments),
                    Invocation::Help(_) => panic!("expected delegated invocation"),
                }
            }
        }

        #[test]
        fn leaf_help_is_available_without_running_the_operator() {
            for path in [
                &["init"][..],
                &["user-token"],
                &["api-token"],
                &["invite"],
                &["route"],
                &["route", "add"],
                &["status"],
                &["update"],
                &["production-check"],
                &["backup"],
                &["restore"],
                &["upgrade"],
                &["rollback"],
                &["administrator", "bootstrap"],
                &["administrator", "recover"],
                &["administrator", "root-token", "rotate"],
            ] {
                for flag in ["--help", "-h"] {
                    let mut arguments = argv(path);
                    arguments.push(flag.into());
                    assert!(
                        matches!(parse(&arguments).unwrap(), Invocation::Help(_)),
                        "{arguments:?}"
                    );
                }
                let arguments: Vec<_> = std::iter::once("help".into()).chain(argv(path)).collect();
                let expected = path.join(" ");
                assert!(
                    matches!(parse(&arguments).unwrap(), Invocation::Help(usage) if usage.contains(expected.as_str())),
                    "{arguments:?}"
                );
            }
        }

        #[test]
        fn administrator_normalizes_username_and_rejects_extra_arguments() {
            for action in ["bootstrap", "recover"] {
                match parse(&argv(&["administrator", action, "--username=site-owner"])).unwrap() {
                    Invocation::Helper(args) => assert_eq!(
                        args,
                        argv(&["administrator", action, "--username", "site-owner"])
                    ),
                    Invocation::Help(_) => panic!("expected delegated invocation"),
                }
                for name in ["ab", "Owner", "owner name", "_owner", "owner.", "øwner"] {
                    assert!(parse(&argv(&["administrator", action, "--username", name])).is_err());
                }
                assert!(
                    parse(&argv(&[
                        "administrator",
                        action,
                        "--username",
                        "owner",
                        "--password",
                        "extra"
                    ]))
                    .is_err()
                );
            }
            assert!(matches!(
                parse(&argv(&["administrator", "root-token", "rotate"])).unwrap(),
                Invocation::Helper(_)
            ));
            assert!(parse(&argv(&["administrator", "root-token", "rotate", "extra"])).is_err());
            assert!(matches!(
                parse(&argv(&["help", "administrator", "recover"])).unwrap(),
                Invocation::Help(_)
            ));
        }

        #[test]
        fn helper_selection_does_not_use_untrusted_paths_for_root() {
            let directory = tempfile::tempdir().unwrap();
            let helper = directory.path().join("operator");
            fs::write(&helper, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
            let unprivileged = resolve_helper(
                false,
                Some(OsStr::new("operator")),
                Some(directory.path().as_os_str()),
            )
            .unwrap();
            assert_eq!(unprivileged, helper);
            assert!(
                resolve_helper(
                    true,
                    Some(OsStr::new("operator")),
                    Some(directory.path().as_os_str())
                )
                .is_err()
            );
            let untrusted = directory.path().join("writable");
            fs::create_dir(&untrusted).unwrap();
            fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777)).unwrap();
            let untrusted_helper = untrusted.join("operator");
            fs::copy(&helper, &untrusted_helper).unwrap();
            assert!(resolve_helper(true, Some(untrusted_helper.as_os_str()), None).is_err());

            let command = helper_command(&helper, argv(&["status", "--json"]), true);
            assert_eq!(command.get_current_dir(), None);
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                argv(&["status", "--json"])
            );
            assert!(
                command
                    .get_envs()
                    .any(|(name, value)| name == OVERRIDE && value.is_none())
            );
            assert!(
                command
                    .get_envs()
                    .any(|(name, value)| name == "PATH" && value == Some(OsStr::new(FIXED_PATH)))
            );
        }
    }
}
