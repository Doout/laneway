//! Host deployment orchestration. Existing protected shell operators own the
//! signed installation and replacement transactions.

use std::ffi::OsString;

use anyhow::{Result, bail};

#[cfg(target_os = "linux")]
mod docker;
#[cfg(target_os = "linux")]
mod linux;

const UPDATE_USAGE: &str = "usage: laneway update [client | server | connector [NAME]]";
const CONFIGURE_USAGE: &str =
    "usage: laneway configure server [DOMAIN] (use a fully qualified DNS name)";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    Client,
    Server,
    Connector,
}

#[cfg(not(target_os = "linux"))]
impl Target {
    fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Connector => "connector",
        }
    }
}

/// Runs a public update command. Arguments start with `update`.
pub fn update(args: &[OsString]) -> Result<()> {
    if args.first().is_none_or(|arg| arg != "update") {
        bail!(UPDATE_USAGE);
    }
    let requested = match args.get(1).and_then(|arg| arg.to_str()) {
        Some("client") => Some(Target::Client),
        Some("server") => Some(Target::Server),
        Some("connector") => Some(Target::Connector),
        Some("--yes") if args.len() == 2 => None,
        None if args.len() == 1 => None,
        _ => bail!(UPDATE_USAGE),
    };
    if let Some((role, name)) = container_role() {
        bail!(
            "{}",
            container_update_message(requested, role, name.as_deref())
        );
    }
    #[cfg(target_os = "linux")]
    let target = match requested {
        Some(target) => target,
        None => linux::detect_update_target()?,
    };
    #[cfg(not(target_os = "linux"))]
    let target = requested.unwrap_or(Target::Client);

    if target == Target::Client {
        return crate::client_update::run(args);
    }
    #[cfg(target_os = "linux")]
    {
        let options = if requested.is_some() {
            &args[2..]
        } else {
            &args[1..]
        };
        linux::update_deployment(target, options)
    }
    #[cfg(not(target_os = "linux"))]
    bail!(
        "run sudo laneway update {} on the Linux Docker host",
        target.name()
    )
}

fn container_update_message(requested: Option<Target>, role: &str, name: Option<&str>) -> String {
    let target = match role {
        "server" => Some(Target::Server),
        "connector" => Some(Target::Connector),
        _ => requested,
    };
    let handoff = "this container is managed by its deployment; on the host run";
    match target {
        Some(Target::Server) => format!("{handoff}: sudo laneway update server"),
        Some(Target::Connector) if name.is_some() => {
            format!(
                "{handoff}: sudo laneway update connector {}",
                name.unwrap_or_default()
            )
        }
        Some(Target::Connector) => format!(
            "{handoff} sudo docker container ls to find its name, then run: sudo laneway update connector laneway-connector-NAME"
        ),
        Some(Target::Client) => {
            "update the client on its host with: laneway update client".to_owned()
        }
        None => format!("{handoff}: sudo laneway update"),
    }
}

/// Configures the Linux Docker Compose control plane via its installed
/// operator, or runs the protected production installer on a new host.
pub fn configure_server(args: &[OsString]) -> Result<()> {
    if args.len() < 2 || args[0] != "configure" || args[1] != "server" {
        bail!(CONFIGURE_USAGE);
    }
    let domain = match &args[2..] {
        [] => None,
        [domain] => Some(
            domain
                .to_str()
                .filter(|name| valid_domain(name))
                .ok_or_else(|| anyhow::anyhow!(CONFIGURE_USAGE))?,
        ),
        _ => bail!(CONFIGURE_USAGE),
    };
    let mut handoff = "sudo laneway configure server".to_owned();
    if let Some(domain) = domain {
        handoff.push(' ');
        handoff.push_str(domain);
    }
    #[cfg(target_os = "linux")]
    {
        if running_in_container() {
            bail!(
                "server configuration runs on the Linux host; exit the container and run {handoff}"
            );
        }
        if linux::effective_uid()? != 0 {
            bail!("server configuration requires root; run {handoff}");
        }
        linux::configure_server(domain)
    }
    #[cfg(not(target_os = "linux"))]
    bail!("run {handoff} on the Linux Docker host")
}

fn valid_domain(name: &str) -> bool {
    if name.len() > 253 || !name.contains('.') {
        return false;
    }
    let (labels, tld) = name.rsplit_once('.').unwrap_or_default();
    fn valid_label(label: &str) -> bool {
        let Some(first) = label.as_bytes().first() else {
            return false;
        };
        label.len() <= 63
            && first.is_ascii_alphanumeric()
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }
    tld.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && valid_label(tld)
        && labels.split('.').all(valid_label)
}

/// Identifies container boundaries independently of deployment role.
pub fn running_in_container() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::running_in_container()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Returns no role outside containers. Inside a container an empty role means
/// the deployment is unknown, and the name is available for a standard Connector.
pub fn container_role() -> Option<(&'static str, Option<String>)> {
    if !running_in_container() {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(linux::container_role())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_dns_names_and_rejects_shell_input() {
        for valid in ["lane.example.com", "Lane.Example.Com", "my-lane.example"] {
            assert!(valid_domain(valid), "{valid}");
        }
        for invalid in [
            "localhost",
            "192.0.2.1",
            "https://lane.example",
            "-lane.example",
            "lane.example.",
            "lane.123",
            "lane.example;id",
            "a..example",
        ] {
            assert!(!valid_domain(invalid), "{invalid}");
        }
    }

    #[test]
    fn container_handoff_uses_an_exact_host_command() {
        assert!(
            container_update_message(Some(Target::Client), "server", None)
                .ends_with("sudo laneway update server")
        );
        assert!(
            container_update_message(None, "connector", Some("laneway-connector-office"))
                .ends_with("sudo laneway update connector laneway-connector-office")
        );
        assert!(container_update_message(None, "", None).ends_with("sudo laneway update"));
    }
}
