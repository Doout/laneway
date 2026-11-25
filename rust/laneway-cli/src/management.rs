//! CLI management operations backed by the controller's pinned HTTPS JSON API.

use std::{
    ffi::OsString,
    io::{self, Write},
};

use anyhow::{Context, Result};

mod administrator;
mod args;
mod local;
mod overview;
mod prefix;
mod resources;
mod route;
mod transport;

use args::Flags;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    NetworkCreate,
    NetworkGet,
    NetworkList,
    RelayRegister,
    RelayUpdate,
    RelayDisable,
    RelayList,
    AclAdd,
    AclDelete,
    AclList,
    NodeRevoke,
    NodeCapabilities,
    NodeList,
    CertificateRevoke,
    CertificateList,
    EnrollmentIssue,
    BootstrapCreate,
    RouteAssign,
    RouteAdvertise,
    RouteApprove,
    RouteWithdraw,
    RouteList,
    Audit,
}

impl Operation {
    fn identify(family: &str, action: &str) -> Option<Self> {
        use Operation::*;
        Some(match (family, action) {
            ("network", "create") => NetworkCreate,
            ("network", "get") => NetworkGet,
            ("network", "list") => NetworkList,
            ("relay", "register") => RelayRegister,
            ("relay", "update") => RelayUpdate,
            ("relay", "disable") => RelayDisable,
            ("relay", "list") => RelayList,
            ("acl", "add") => AclAdd,
            ("acl", "delete") => AclDelete,
            ("acl", "list") => AclList,
            ("node", "revoke") => NodeRevoke,
            ("node", "capabilities") => NodeCapabilities,
            ("node", "list") => NodeList,
            ("certificate", "revoke") => CertificateRevoke,
            ("certificate", "list") => CertificateList,
            ("enrollment-token", "issue") => EnrollmentIssue,
            ("bootstrap-bundle", "create") => BootstrapCreate,
            ("route", "assign") => RouteAssign,
            ("route", "advertise") => RouteAdvertise,
            ("route", "approve") => RouteApprove,
            ("route", "withdraw") => RouteWithdraw,
            ("route", "list") => RouteList,
            ("audit", "") => Audit,
            _ => return None,
        })
    }

    fn network_collection(self) -> Option<&'static str> {
        use Operation::*;
        match self {
            RelayList => Some("relays"),
            AclList => Some("acl-rules"),
            NodeList => Some("nodes"),
            CertificateList => Some("certificates"),
            RouteList => Some("routes"),
            Audit => Some("audit"),
            _ => None,
        }
    }

    fn option_names(self) -> (&'static [&'static str], &'static [&'static str]) {
        use Operation::*;
        if self.network_collection().is_some() {
            return (&["network-id", "limit"], &[]);
        }
        match self {
            NetworkCreate => (&["network-id", "name", "ipv4-pool", "ipv6-pool"], &[]),
            NetworkGet => (&["network-id"], &[]),
            NetworkList => (&["limit"], &[]),
            RelayRegister => (
                &["network-id", "service-id", "node-id", "name", "endpoint"],
                &[],
            ),
            RelayUpdate => (&["relay-id", "name", "endpoint"], &["enabled"]),
            RelayDisable => (&["relay-id"], &[]),
            AclAdd => (
                &[
                    "network-id",
                    "priority",
                    "action",
                    "selector",
                    "selector-file",
                    "description",
                ],
                &[],
            ),
            AclDelete => (&["rule-id"], &[]),
            NodeRevoke => (&["node-id", "reason"], &[]),
            NodeCapabilities => (&["node-id"], &["subnet-router", "exit-node"]),
            CertificateRevoke => (&["network-id", "serial", "reason"], &[]),
            EnrollmentIssue => (
                &[
                    "network-id",
                    "label",
                    "class",
                    "expires-in",
                    "session-lifetime",
                    "requested-name",
                ],
                &["connector", "exit-node"],
            ),
            BootstrapCreate => (&["payload-file", "expires-at"], &[]),
            RouteAssign => (
                &["network-id", "connector", "to", "allow", "mode", "metric"],
                &[],
            ),
            RouteAdvertise => (&["prefix", "kind", "mode", "metric", "valid-for"], &[]),
            RouteApprove | RouteWithdraw => (&["route-id"], &[]),
            _ => unreachable!("network collections handled above"),
        }
    }
}

pub fn run(args: &[OsString]) -> Result<()> {
    let word = |index: usize| {
        args.get(index)
            .and_then(|value| value.to_str())
            .unwrap_or_default()
    };
    if let Some(index) = args
        .iter()
        .position(|arg| arg == "--help" || arg == "-h" || arg == "-help")
    {
        let path = &args[..index];
        let command_end = path
            .iter()
            .position(|arg| arg.to_string_lossy().starts_with('-'))
            .unwrap_or(index);
        let path = &path[..command_end];
        let max_parts = match (word(0), word(1)) {
            ("invite", _) => 1,
            ("route", _) => 2,
            ("node" | "controller", "route") => 3,
            _ => path.len(),
        };
        let path = &path[..path.len().min(max_parts)];
        return help(path);
    }
    match (word(0), word(1)) {
        ("controller", "overview") => return overview::run(&args[2..]),
        ("controller", "administrator")
            if args.len() == 2 || args.len() == 3 && args[2] == "root-token" =>
        {
            return help(args);
        }
        ("controller", "administrator") => return administrator::run(&args[2..]),
        ("invite", _) => return local::invite(&args[1..]),
        ("exit", "enable") => return local::exit_enable(&args[2..]),
        ("node", "exit") if word(2) == "enable" => return local::exit_enable(&args[3..]),
        ("controller", _) | ("route", "") | ("node", "route") if args.len() <= 2 => {
            return help(args);
        }
        _ => {}
    }
    let (family, action, options) = match (word(0), word(1)) {
        ("controller", "audit") => ("audit", "", &args[2..]),
        ("controller", family) if args.len() >= 3 => (family, word(2), &args[3..]),
        ("route", action) if args.len() >= 2 => ("route", action, &args[2..]),
        ("node", "route") if args.len() >= 3 => ("route", word(2), &args[3..]),
        _ => anyhow::bail!("unknown Laneway management command"),
    };
    let Some(operation) = Operation::identify(family, action) else {
        if action.is_empty() {
            return help(args);
        }
        anyhow::bail!("unknown management command {family} {action}");
    };
    let (positional, options) = match options {
        [first, rest @ ..]
            if operation == Operation::RouteAdvertise
                && !first.to_string_lossy().starts_with('-') =>
        {
            (
                Some(first.to_str().context("route prefix must be valid UTF-8")?),
                rest,
            )
        }
        _ => (None, options),
    };
    let (fields, booleans) = operation.option_names();
    let node = matches!(
        operation,
        Operation::RouteAdvertise | Operation::RouteWithdraw
    );
    let (flags, trailing) = Flags::parse(options, fields, booleans, node)?;
    let positional = match trailing {
        [] => positional,
        [value] if operation == Operation::RouteAdvertise && positional.is_none() => {
            Some(value.to_str().context("route prefix must be valid UTF-8")?)
        }
        _ => anyhow::bail!("{family} {action}: unexpected positional arguments"),
    };
    let output = match operation {
        Operation::RouteAssign
        | Operation::RouteAdvertise
        | Operation::RouteApprove
        | Operation::RouteWithdraw => route::execute(operation, &flags, positional)?,
        _ => resources::execute(operation, &flags)?,
    };
    print(&output)
}

pub(crate) fn completion_flags(path: &[&str]) -> Vec<&'static str> {
    let special: (&[&str], Option<bool>) = match path {
        ["controller", "overview"] => (&["network-id", "json"], Some(false)),
        ["controller", "administrator", "bootstrap" | "recover"] => (&["username"], Some(false)),
        ["controller", "administrator", "root-token", "generate"] => (&["out-file"], None),
        [
            "controller",
            "administrator",
            "root-token",
            "authentication-check",
        ] => (&["expect"], Some(false)),
        [
            "controller",
            "administrator",
            "root-token",
            "rotation-begin" | "rotation-complete",
        ] => (&["rotation-id"], Some(false)),
        ["invite"] => (
            &[
                "config",
                "name",
                "expires-in",
                "session-lifetime",
                "ephemeral",
                "remembered",
                "json",
            ],
            None,
        ),
        ["exit", "enable"] | ["node", "exit", "enable"] => (
            &["config", "family", "mode", "metric", "valid-for"],
            Some(true),
        ),
        _ => {
            let (family, action) = match path {
                ["controller", "audit"] => ("audit", ""),
                ["controller", family, action] => (*family, *action),
                ["route", action] | ["node", "route", action] => ("route", *action),
                _ => return Vec::new(),
            };
            let Some(operation) = Operation::identify(family, action) else {
                return Vec::new();
            };
            let (fields, booleans) = operation.option_names();
            let node = matches!(
                operation,
                Operation::RouteAdvertise | Operation::RouteWithdraw
            );
            let mut flags = fields.to_vec();
            flags.extend(booleans);
            add_connection_flags(&mut flags, node);
            return flags;
        }
    };
    let mut flags = special.0.to_vec();
    if let Some(node) = special.1 {
        add_connection_flags(&mut flags, node);
    }
    flags
}

fn add_connection_flags(flags: &mut Vec<&'static str>, node: bool) {
    flags.extend([
        "controller",
        "ca",
        "server-name",
        "controller-network-id",
        "controller-service-id",
    ]);
    if node {
        flags.extend(["cert", "key"]);
    } else {
        flags.push("admin-token-file");
    }
}

pub fn help(path: &[OsString]) -> Result<()> {
    let words: Vec<&str> = path
        .iter()
        .map(|word| word.to_str().context("invalid help topic"))
        .collect::<Result<_>>()?;
    let (family, action) = match words.as_slice() {
        ["controller"] => {
            return usage(
                "controller <overview|administrator|network|relay|acl|node|certificate|enrollment-token|bootstrap-bundle|route|audit>",
            );
        }
        ["controller", "overview"] => {
            return usage("controller overview --network-id ID [--json] [connection options]");
        }
        ["controller", "administrator"] => {
            return usage("controller administrator <bootstrap|recover|root-token>");
        }
        ["controller", "administrator", "bootstrap" | "recover"] => {
            return usage(&format!(
                "controller administrator {} --username NAME [connection options]",
                words[2]
            ));
        }
        ["controller", "administrator", "root-token"] => {
            return usage(
                "controller administrator root-token <generate|authentication-check|rotation-begin|rotation-complete>",
            );
        }
        ["controller", "administrator", "root-token", "generate"] => {
            return usage("controller administrator root-token generate --out-file ABSOLUTE_PATH");
        }
        [
            "controller",
            "administrator",
            "root-token",
            "authentication-check",
        ] => {
            return usage(
                "controller administrator root-token authentication-check --expect <accepted|rejected> [connection options]",
            );
        }
        [
            "controller",
            "administrator",
            "root-token",
            "rotation-begin" | "rotation-complete",
        ] => {
            return usage(&format!(
                "controller administrator root-token {} --rotation-id ID [connection options]",
                words[3]
            ));
        }
        ["invite"] => {
            return usage(
                "invite --name NAME [--config PATH] [--ephemeral|--remembered] [--expires-in DURATION] [--session-lifetime DURATION] [--json]",
            );
        }
        ["exit", "enable"] | ["node", "exit", "enable"] => {
            return usage(
                "exit enable [--config PATH] [--family dual|ipv4|ipv6] [--mode nat|routed] [--metric NUMBER] [--valid-for DURATION] [connection options]",
            );
        }
        ["route"] | ["node", "route"] => ("route", ""),
        ["route", action] | ["node", "route", action] => ("route", *action),
        ["controller", family] => (*family, ""),
        ["controller", family, action] => (*family, *action),
        _ => anyhow::bail!("unknown Laneway management help topic"),
    };
    if let Some(operation) = Operation::identify(family, action) {
        let heading = words.join(" ");
        let (fields, booleans) = operation.option_names();
        print!("Usage: laneway {heading}");
        for field in fields {
            print!(" [--{field} VALUE]");
        }
        for flag in booleans {
            print!(" [--{flag}]");
        }
        if operation == Operation::RouteAdvertise {
            print!(" [PREFIX]");
        }
        print!(
            " --controller HTTPS_ORIGIN --controller-network-id ID --controller-service-id ID [--ca PATH] [--server-name NAME]"
        );
        if matches!(
            operation,
            Operation::RouteAdvertise | Operation::RouteWithdraw
        ) {
            println!(" [--cert PATH] [--key PATH]");
        } else {
            println!(" [--admin-token-file PATH]");
        }
        return Ok(());
    }
    if action.is_empty() {
        let choices = match family {
            "network" => "create|get|list",
            "relay" => "register|update|disable|list",
            "acl" => "add|delete|list",
            "node" => "revoke|capabilities|list",
            "certificate" => "revoke|list",
            "enrollment-token" => "issue",
            "bootstrap-bundle" => "create",
            "route" => "assign|advertise|approve|withdraw|list",
            _ => anyhow::bail!("unknown controller management command {family}"),
        };
        return usage(&format!("{} <{choices}>", words.join(" ")));
    }
    anyhow::bail!("unknown management command {family} {action}")
}

fn usage(command: &str) -> Result<()> {
    println!("Usage: laneway {command}");
    Ok(())
}

fn print(output: &serde_json::Value) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, output)?;
    writeln!(stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_preserve_go_spellings_and_bound_limits() {
        let arguments = [
            "-network-id",
            "21000000000000000000000000000001",
            "--limit=0x12",
            "--enabled=false",
        ]
        .map(OsString::from);
        let (flags, trailing) =
            Flags::parse(&arguments, &["network-id", "limit"], &["enabled"], false).unwrap();
        assert!(trailing.is_empty());
        assert_eq!(flags.limit().unwrap(), 18);
        assert!(!flags.boolean("enabled", true).unwrap());
        assert!(flags.id("network-id").is_ok());
    }

    #[test]
    fn assigned_routes_only_accept_canonical_non_default_prefixes() {
        assert_eq!(
            prefix::Prefix::assigned("192.0.2.1").unwrap().to_string(),
            "192.0.2.1/32"
        );
        assert_eq!(
            prefix::Prefix::assigned("2001:db8::").unwrap().to_string(),
            "2001:db8::/128"
        );
        for invalid in [
            "0.0.0.0/0",
            "::/0",
            "192.0.2.1/24",
            "2001:db8::1/64",
            "::ffff:192.0.2.1",
        ] {
            assert!(prefix::Prefix::assigned(invalid).is_err(), "{invalid}");
        }
    }
}
