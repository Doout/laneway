//! Linux host discovery and routing for the product update command.

use std::{
    env,
    ffi::OsString,
    fs::{self, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};

mod docker;

const CONTROL: &str = "/usr/local/sbin/laneway-control";
const CONNECTOR_UPDATER: &str = "/usr/local/sbin/laneway-update-connector";
const TRUSTED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Client,
    Server,
    Connector,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Connector => "connector",
        }
    }
}

/// Detect a deployment on the host or dispatch to a protected host updater.
pub fn run(args: &[OsString]) -> Result<()> {
    let (operation, args) = args
        .split_first()
        .context("expected a deployment update operation")?;
    let operation = operation
        .to_str()
        .context("invalid deployment update operation")?;
    let target = match operation {
        "client-check" if args.is_empty() => Some(Target::Client),
        "detect" if args.is_empty() => None,
        "server" => Some(Target::Server),
        "connector" => Some(Target::Connector),
        _ => bail!("expected deployment update detection, client-check, server, or connector"),
    };
    if running_in_container() {
        return Err(container_error(operation));
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            match target {
                None => {
                    println!("{}", detect_update_target().await?.name());
                    Ok(())
                }
                Some(target) => update_deployment(target, args).await,
            }
        })
}

fn container_error(operation: &str) -> anyhow::Error {
    let (role, name) = container_role();
    let command = match (if role.is_empty() { operation } else { role }, name) {
        ("server", _) => "sudo laneway update server".to_owned(),
        ("connector", Some(name)) => format!("sudo laneway update connector {name}"),
        ("connector", None) => "sudo laneway update connector laneway-connector-NAME".to_owned(),
        ("client-check", _) => "sudo laneway update client".to_owned(),
        _ => "sudo laneway update".to_owned(),
    };
    anyhow::anyhow!("this container is managed by its deployment; on the host run: {command}")
}

fn validate_server_args(args: &[OsString]) -> Result<()> {
    let valid = match args {
        [] => true,
        [tag] => tag
            .to_str()
            .is_some_and(laneway_protocol::fleet_updates::valid_version),
        _ => false,
    };
    ensure!(valid, "usage: laneway update server [vMAJOR.MINOR.PATCH]");
    Ok(())
}

fn effective_uid() -> Result<u32> {
    let status =
        fs::read_to_string("/proc/self/status").context("read Linux process credentials")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|uid| uid.parse().ok())
        .context("determine the effective Linux user ID")
}

fn running_in_container() -> bool {
    [
        "/.dockerenv",
        "/run/.containerenv",
        "/run/systemd/container",
    ]
    .iter()
    .any(|marker| fs::symlink_metadata(marker).is_ok())
        || fs::read_to_string("/proc/self/cgroup").is_ok_and(|data| container_cgroup(&data))
}

fn container_cgroup(cgroup: &str) -> bool {
    cgroup.split(['/', ':', '\n']).any(|field| {
        matches!(field, "docker" | "kubepods" | "lxc")
            || (field.starts_with("docker-") || field.starts_with("libpod-"))
                && field.ends_with(".scope")
            || field.starts_with("kubepods-") && field.ends_with(".slice")
    })
}

fn container_role() -> (&'static str, Option<String>) {
    let cmdline = fs::read_to_string("/proc/1/cmdline").unwrap_or_default();
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let state = Path::new("/var/lib/laneway/connector").is_dir();
    classify_container(&cmdline, hostname.trim_end(), state)
}

fn classify_container(
    cmdline: &str,
    hostname: &str,
    connector_state: bool,
) -> (&'static str, Option<String>) {
    let mut argv = cmdline.split('\0');
    let binary = Path::new(argv.next().unwrap_or_default())
        .file_name()
        .and_then(|name| name.to_str());
    let first = argv.next().unwrap_or_default();
    let second = argv.next().unwrap_or_default();
    if matches!(
        binary,
        Some("laneway-controller" | "laneway-relay" | "laneway-controller-rs" | "laneway-relay-rs")
    ) || matches!(binary, Some("laneway" | "laneway-compat" | "lanewayd"))
        && matches!(first, "-config" | "--config")
        && matches!(
            second,
            "/etc/laneway/controller.toml" | "/etc/laneway/relay.toml"
        )
    {
        return ("server", None);
    }
    let connector = matches!(
        (binary, first, second),
        (Some("laneway" | "laneway-compat"), "connector", "run")
            | (Some("lanewayd" | "lanewayd-rs"), "--connector-state", _)
            | (
                Some("lanewayd" | "lanewayd-rs"),
                "_rootless",
                "connector-run"
            )
    );
    if connector || connector_state {
        return (
            "connector",
            crate::fleet_update::connector::valid_name(hostname).then(|| hostname.to_owned()),
        );
    }
    ("", None)
}

async fn detect_update_target() -> Result<Target> {
    let server = installed_server(effective_uid()?)?;
    select_update_target(server, docker::local_managed_connectors(None).await)
}

fn select_update_target(server: bool, connectors: Result<Vec<String>>) -> Result<Target> {
    let connectors = match connectors {
        Ok(connectors) => connectors,
        Err(error) if server && error.is::<docker::Unavailable>() => return Ok(Target::Server),
        Err(error) => bail!(
            "cannot determine the update target: {error:#}. Choose laneway update client, sudo laneway update server, or sudo laneway update connector laneway-connector-NAME"
        ),
    };
    match (server, connectors.as_slice()) {
        (true, []) => Ok(Target::Server),
        (true, _) => bail!(
            "both a control plane and managed Connectors are installed; run sudo laneway update server or sudo laneway update connector laneway-connector-NAME"
        ),
        (false, []) => Ok(Target::Client),
        (false, [_]) => Ok(Target::Connector),
        (false, names) => Err(multiple_connectors(names)),
    }
}

async fn update_deployment(target: Target, args: &[OsString]) -> Result<()> {
    let uid = effective_uid()?;
    match target {
        Target::Client => {
            ensure!(
                uid == 0,
                "on the client host run: sudo laneway update client"
            );
            Ok(())
        }
        Target::Server => {
            validate_server_args(args)?;
            ensure!(
                uid == 0,
                "on the control-plane host run: sudo laneway update server"
            );
            for key in [
                "LANEWAY_CONTROL_COMMAND",
                "LANEWAY_RELEASE_BASE_URL",
                "LANEWAY_REPOSITORY",
                "LANEWAY_COSIGN_BIN",
            ] {
                ensure!(
                    env::var_os(key).is_none(),
                    "{key} is not allowed for control-plane updates"
                );
            }
            ensure!(
                installed_server(uid)?,
                "no managed control plane found via {CONTROL}"
            );
            run_helper(Command::new(CONTROL).arg("update").args(args))
        }
        Target::Connector => {
            let name = connector_update_name(args)?;
            if uid != 0 {
                if let Some(name) = &name {
                    bail!("on the Connector host run: sudo laneway update connector {name}");
                }
                bail!("on the Connector host run: sudo laneway update connector");
            }
            let connectors = docker::local_managed_connectors(name.as_deref()).await?;
            match connectors.as_slice() {
                [] if name.is_some() => {
                    bail!(
                        "{} is not a running standard managed Connector on the local Docker Engine",
                        name.unwrap_or_default()
                    )
                }
                [] => bail!("no running standard managed Connector on the local Docker Engine"),
                [selected] => {
                    protected_file(Path::new(CONNECTOR_UPDATER), true)
                        .with_context(|| format!("managed Connector updater is missing or unsafe at {CONNECTOR_UPDATER}; install the signed Laneway Linux host package first"))?;
                    run_helper(Command::new(CONNECTOR_UPDATER).arg(selected))
                }
                names => Err(multiple_connectors(names)),
            }
        }
    }
}

fn connector_update_name(args: &[OsString]) -> Result<Option<String>> {
    let name = match args {
        [] => return Ok(None),
        [name] => name
            .to_str()
            .map(|name| name.strip_prefix("--name=").unwrap_or(name)),
        [flag, name] if flag == "--name" => name.to_str(),
        _ => bail!("usage: laneway update connector [NAME]"),
    }
    .context("Connector name must be valid UTF-8")?;
    let name = if name.starts_with(docker::CONNECTOR_PREFIX) {
        name.to_owned()
    } else {
        format!("{}{name}", docker::CONNECTOR_PREFIX)
    };
    ensure!(
        crate::fleet_update::connector::valid_name(&name),
        "Connector name must be NAME or laneway-connector-NAME using letters, digits, dots, underscores or hyphens"
    );
    Ok(Some(name))
}

fn multiple_connectors(names: &[String]) -> anyhow::Error {
    anyhow::anyhow!(
        "multiple managed Connectors found ({}); choose one with sudo laneway update connector laneway-connector-NAME",
        names.join(", ")
    )
}

fn installed_server(uid: u32) -> Result<bool> {
    let Some(operator) = resolve_operator(Path::new(CONTROL))? else {
        return Ok(false);
    };
    protected_parents(&operator)?;
    let base = operator
        .parent()
        .context("control-plane operator has no deployment directory")?;
    let mut helper = operator.clone();
    if helper.file_name().is_some_and(|name| name == "lane") {
        match fs::symlink_metadata(&helper) {
            Err(err) if uid != 0 && err.kind() == io::ErrorKind::PermissionDenied => {
                return Ok(true);
            }
            Ok(info) if info.is_symlink() => {
                let target = fs::read_link(&helper)?;
                let expected = base.join("laneway-control");
                ensure!(
                    info.uid() == 0
                        && (target == Path::new("laneway-control") || target == expected),
                    "legacy control-plane command link is unsafe: {}",
                    helper.display()
                );
                helper = expected;
            }
            _ => {}
        }
    }
    for (file, executable) in [
        (helper, true),
        (base.join("compose.yaml"), false),
        (base.join(".env"), false),
    ] {
        match protected_file(&file, executable) {
            Ok(()) => {}
            // The installer's root-only deployment remains identifiable by the
            // protected system link. Actual updates revalidate as root.
            Err(err) if uid != 0 && io_kind(&err) == Some(io::ErrorKind::PermissionDenied) => {
                return Ok(true);
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "managed control-plane file is missing or unsafe: {}",
                        file.display()
                    )
                });
            }
        }
    }
    Ok(true)
}

fn resolve_operator(path: &Path) -> Result<Option<PathBuf>> {
    let info = match fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("inspect installed control-plane operator"),
    };
    protected_parents(path)?;
    ensure!(
        path == Path::new(CONTROL) && info.is_symlink() && info.uid() == 0 && info.gid() == 0,
        "control-plane command {} must be an installed root-owned symlink",
        path.display()
    );
    let target = fs::read_link(path).context("read control-plane command link")?;
    ensure!(
        canonical_absolute(&target)
            && target
                .file_name()
                .is_some_and(|name| name == "laneway-control" || name == "lane"),
        "control-plane command {} has an unsupported installation target",
        path.display()
    );
    Ok(Some(target))
}

fn run_helper(command: &mut Command) -> Result<()> {
    let status = command
        .env_clear()
        .env("PATH", TRUSTED_PATH)
        .env("HOME", "/root")
        .env("LANG", "C")
        .current_dir("/")
        .status()
        .with_context(|| format!("run {}", command.get_program().to_string_lossy()))?;
    ensure!(
        status.success(),
        "{} failed: {status}",
        command.get_program().to_string_lossy()
    );
    Ok(())
}

fn canonical_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| !matches!(part, Component::ParentDir))
        && path.components().collect::<PathBuf>().as_os_str() == path.as_os_str()
}

fn protected_root(info: &Metadata) -> bool {
    info.uid() == 0 && info.gid() == 0 && info.mode() & 0o022 == 0
}

fn protected_parents(path: &Path) -> Result<()> {
    ensure!(
        canonical_absolute(path),
        "expected a canonical absolute path: {}",
        path.display()
    );
    for parent in path.ancestors().skip(1) {
        let info = fs::symlink_metadata(parent)
            .with_context(|| format!("inspect update path {}", parent.display()))?;
        ensure!(
            info.is_dir() && protected_root(&info),
            "expected a protected root-owned directory at {}",
            parent.display()
        );
    }
    Ok(())
}

fn protected_file(path: &Path, executable: bool) -> Result<()> {
    protected_parents(path)?;
    let info = fs::symlink_metadata(path)
        .with_context(|| format!("inspect update helper {}", path.display()))?;
    ensure!(
        info.is_file() && protected_root(&info) && (!executable || info.mode() & 0o100 != 0),
        "expected a protected root-owned file at {}",
        path.display()
    );
    Ok(())
}

fn io_kind(error: &anyhow::Error) -> Option<io::ErrorKind> {
    error.downcast_ref::<io::Error>().map(io::Error::kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_real_container_roles() {
        assert!(container_cgroup("0::/system.slice/docker-abc.scope"));
        assert!(!container_cgroup("0::/system.slice/docker.service"));
        assert_eq!(
            classify_container(
                "/usr/local/bin/laneway\0-config\0/etc/laneway/controller.toml\0",
                "",
                false
            ),
            ("server", None)
        );
        assert_eq!(
            classify_container(
                "/usr/local/bin/laneway\0connector\0run\0",
                "laneway-connector-office",
                false
            ),
            ("connector", Some("laneway-connector-office".to_owned()))
        );
    }

    #[test]
    fn recognizes_a_connector_after_exec_into_compat_before_enrollment() {
        assert_eq!(
            classify_container(
                "/usr/local/bin/laneway-compat\0connector\0run\0",
                "unknown",
                false
            ),
            ("connector", None)
        );
    }

    #[test]
    fn only_selects_unambiguous_deployments() {
        assert_eq!(
            select_update_target(false, Ok(Vec::new())).unwrap(),
            Target::Client
        );
        assert_eq!(
            select_update_target(true, Ok(Vec::new())).unwrap(),
            Target::Server
        );
        assert_eq!(
            select_update_target(false, Ok(vec!["laneway-connector-office".into()])).unwrap(),
            Target::Connector
        );
        assert!(select_update_target(true, Ok(vec!["laneway-connector-office".into()])).is_err());
        assert_eq!(
            select_update_target(
                true,
                Err(docker::Unavailable("socket missing".into()).into())
            )
            .unwrap(),
            Target::Server
        );
        assert!(
            select_update_target(
                false,
                Err(docker::Unavailable("socket missing".into()).into())
            )
            .is_err()
        );
    }

    #[test]
    fn server_accepts_an_optional_exact_stable_tag() {
        assert!(validate_server_args(&[]).is_ok());
        assert!(validate_server_args(&["v0.3.42".into()]).is_ok());
        for tag in ["--help", "latest", "0.3.42", "v0.03.42", "v0.3.42-rc1"] {
            assert!(validate_server_args(&[tag.into()]).is_err());
        }
        assert!(validate_server_args(&["v0.3.42".into(), "--help".into()]).is_err());
    }

    #[test]
    fn accepts_only_the_standard_connector_names() {
        assert_eq!(
            connector_update_name(&["office".into()])
                .unwrap()
                .as_deref(),
            Some("laneway-connector-office")
        );
        assert_eq!(
            connector_update_name(&["--name=laneway-connector-office".into()])
                .unwrap()
                .as_deref(),
            Some("laneway-connector-office")
        );
        assert!(connector_update_name(&["--name".into(), "../../bad".into()]).is_err());
    }
}
