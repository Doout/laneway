use std::{
    env,
    ffi::OsString,
    fs::{self, File, Metadata},
    io::{self, BufRead, BufReader},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};

use super::{Target, docker};

const CONTROL: &str = "/usr/local/sbin/laneway-control";
const DEFAULT_OPERATOR: &str = "/opt/laneway/laneway-control";
const CONNECTOR_UPDATER: &str = "/usr/local/sbin/laneway-update-connector";
const PACKAGE_INSTALLER: &str = "/usr/local/share/laneway/deploy/compose/install-control-plane.sh";
const RELEASE_INSTALLER: &str = "/usr/local/share/laneway/install-control-plane-release.sh";
const VERIFIER: &str = "/usr/local/libexec/laneway/cosign-v3.1.3";
const TRUSTED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub(super) fn effective_uid() -> Result<u32> {
    let status =
        fs::read_to_string("/proc/self/status").context("read Linux process credentials")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|uid| uid.parse().ok())
        .context("determine the effective Linux user ID")
}

pub(super) fn running_in_container() -> bool {
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

pub(super) fn container_role() -> (&'static str, Option<String>) {
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
    if matches!(binary, Some("laneway-controller" | "laneway-relay"))
        || matches!(binary, Some("laneway" | "laneway-compat" | "lanewayd"))
            && matches!(first, "-config" | "--config")
            && matches!(
                second,
                "/etc/laneway/controller.toml" | "/etc/laneway/relay.toml"
            )
    {
        return ("server", None);
    }
    let connector = matches!(binary, Some("laneway" | "laneway-compat" | "lanewayd"))
        && first == "connector"
        && second == "run";
    if connector || connector_state {
        return (
            "connector",
            docker::standard_name(hostname).then(|| hostname.to_owned()),
        );
    }
    ("", None)
}

pub(super) fn detect_update_target() -> Result<Target> {
    let uid = effective_uid()?;
    let server = installed_server(uid)?;
    // A per-user CLI does not need privilege or Docker access for a native update.
    if !server && uid != 0 && installed_user_cli(uid) {
        return Ok(Target::Client);
    }
    select_update_target(server, docker::local_managed_connectors(None))
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

pub(super) fn update_deployment(target: Target, args: &[OsString]) -> Result<()> {
    let uid = effective_uid()?;
    match target {
        Target::Client => unreachable!("client update uses the native updater"),
        Target::Server => {
            ensure!(args.is_empty(), "usage: laneway update server");
            ensure!(
                uid == 0,
                "on the control-plane host run: sudo laneway update server"
            );
            ensure!(
                env::var_os("LANEWAY_CONTROL_COMMAND").is_none(),
                "LANEWAY_CONTROL_COMMAND is not allowed for control-plane updates"
            );
            ensure!(
                installed_server(uid)?,
                "no managed control plane found via {CONTROL}"
            );
            run(Command::new(CONTROL).arg("update"))
        }
        Target::Connector => {
            let name = connector_update_name(args)?;
            if uid != 0 {
                if let Some(name) = &name {
                    bail!("on the Connector host run: sudo laneway update connector {name}");
                }
                bail!("on the Connector host run: sudo laneway update connector");
            }
            let connectors = docker::local_managed_connectors(name.as_deref())?;
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
                    run(Command::new(CONNECTOR_UPDATER).arg(selected))
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
        docker::standard_name(&name),
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

fn installed_user_cli(uid: u32) -> bool {
    let Some(home) = env::var_os("HOME") else {
        return false;
    };
    let home = Path::new(&home);
    if !home.is_absolute() {
        return false;
    }
    let installed = home.join(".local/bin/laneway");
    env::current_exe().is_ok_and(|path| path == installed)
        && fs::symlink_metadata(installed)
            .is_ok_and(|info| info.is_file() && info.uid() == uid && info.mode() & 0o022 == 0)
}

fn installed_server(uid: u32) -> Result<bool> {
    let Some(operator) = resolve_operator(Path::new(CONTROL), true)? else {
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

pub(super) fn configure_server(domain: Option<&str>) -> Result<()> {
    let operator = match resolve_operator(Path::new(CONTROL), false)? {
        Some(operator) => Some(operator),
        None => resolve_operator(Path::new(DEFAULT_OPERATOR), false)?,
    };
    let Some(operator) = operator else {
        return install_server(domain);
    };
    protected_file(&operator, true).context("unsafe installed control-plane operator")?;
    if let Some(domain) = domain {
        let base = operator
            .parent()
            .context("control-plane operator has no deployment directory")?;
        check_server_domain(&base.join(".env"), domain)?;
    }
    run_configure_helper(&operator, None, false, &["init"])?;
    run_configure_helper(&operator, None, false, &["production-check"])
}

fn resolve_operator(path: &Path, require_link: bool) -> Result<Option<PathBuf>> {
    let info = match fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("inspect installed control-plane operator"),
    };
    protected_parents(path)?;
    if !info.is_symlink() && !require_link {
        return Ok(Some(path.to_owned()));
    }
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

fn check_server_domain(path: &Path, domain: &str) -> Result<()> {
    protected_file(path, false).context("read installed server domain")?;
    let mut configured = None;
    for line in BufReader::new(File::open(path)?).lines() {
        if let Some(value) = line?.strip_prefix("LANEWAY_CONTROLLER_SERVER_NAME=") {
            ensure!(
                configured.is_none(),
                "installed control-plane configuration contains multiple server names"
            );
            configured = Some(value.to_owned());
        }
    }
    ensure!(
        configured.is_some_and(|name| name.eq_ignore_ascii_case(domain)),
        "domain {domain:?} differs from the installed control-plane domain in {}",
        path.display()
    );
    Ok(())
}

fn install_server(domain: Option<&str>) -> Result<()> {
    for path in [PACKAGE_INSTALLER, VERIFIER] {
        match protected_file(Path::new(path), true) {
            Ok(()) => {}
            Err(err) if io_kind(&err) == Some(io::ErrorKind::NotFound) => {
                let fallback = Path::new(RELEASE_INSTALLER);
                match protected_file(fallback, true) {
                    Ok(()) => {
                        return run_configure_helper(
                            fallback,
                            domain,
                            false,
                            &["--control-plane", "--production"],
                        );
                    }
                    Err(err) if io_kind(&err) == Some(io::ErrorKind::NotFound) => {
                        let environment = domain
                            .map(|name| format!("env LANEWAY_DOMAIN={name} "))
                            .unwrap_or_default();
                        bail!(
                            "control-plane setup component is missing at {path}; download https://github.com/Doout/laneway/releases/latest/download/install.sh and run sudo {environment}sh ./install.sh --control-plane --production"
                        );
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) => return Err(err),
        }
    }
    run_configure_helper(Path::new(PACKAGE_INSTALLER), domain, true, &[])
}

fn run_configure_helper(
    path: &Path,
    domain: Option<&str>,
    production_mode: bool,
    args: &[&str],
) -> Result<()> {
    let mut process = Command::new(path);
    process.args(args).current_dir("/").env_clear().envs([
        ("HOME", "/root"),
        ("LC_ALL", "C"),
        ("PATH", TRUSTED_PATH),
    ]);
    if production_mode {
        process.env("LANEWAY_PRODUCTION_MODE", "true");
    }
    if let Some(domain) = domain {
        process.env("LANEWAY_DOMAIN", domain);
    }
    run(&mut process)
}

fn run(command: &mut Command) -> Result<()> {
    let status = command
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
