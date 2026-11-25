use std::ffi::OsString;

use anyhow::{Result, bail};

#[path = "completion/groups.rs"]
mod groups;

const CONFIG: &[&str] = &["--state-dir", "--system"];
const START: &[&str] = &[
    "--config",
    "--listen",
    "--no-proxy",
    "--proxy-only",
    "--state-dir",
    "--system",
];
const FILE_FLAGS: &[&str] = &[
    "-config",
    "-out-dir",
    "--ca",
    "--ca-cert",
    "--ca-key",
    "--cert",
    "--config",
    "--envelope-file",
    "--identity",
    "--issuer",
    "--key",
    "--out",
    "--out-cert",
    "--out-file",
    "--out-key",
    "--payload-file",
    "--root",
    "--selector-file",
    "--setup-token-file",
    "--state-dir",
    "--token-file",
];

pub fn run(args: &[OsString]) -> Result<()> {
    let [_, shell, flags @ ..] = args else {
        println!("usage: laneway completion <bash|zsh|fish|powershell>");
        return Ok(());
    };
    if flags.iter().any(|flag| flag == "--help" || flag == "-h")
        || shell == "--help"
        || shell == "-h"
    {
        println!("usage: laneway completion <bash|zsh|fish|powershell> [--no-descriptions]");
        return Ok(());
    }
    if flags.iter().any(|flag| {
        flag != "--no-descriptions"
            && flag != "--no-descriptions=true"
            && flag != "--no-descriptions=false"
    }) {
        bail!("usage: laneway completion <bash|zsh|fish|powershell> [--no-descriptions]");
    }
    let script = match shell.to_str() {
        Some("bash") => include_str!("completion/bash.sh"),
        Some("zsh") => include_str!("completion/zsh.sh"),
        Some("fish") => include_str!("completion/fish.sh"),
        Some("powershell") => include_str!("completion/powershell.ps1"),
        _ => bail!("unsupported completion shell {}", shell.to_string_lossy()),
    };
    print!("{script}");
    Ok(())
}

/// Cobra-compatible callback format, also used by previously installed
/// completion scripts. A final directive tells the shell about file matches.
pub fn callback(args: &[OsString]) -> Result<()> {
    let mut words = args[1..].iter().map(|word| word.to_str().unwrap_or(""));
    let prefix = words.next_back().unwrap_or("");
    let path: Vec<&str> = words.collect();
    if path.last().is_some_and(|word| FILE_FLAGS.contains(word)) {
        println!(":0");
        return Ok(());
    }
    let mut matches = candidates(&path);
    matches.sort_unstable();
    for item in matches.into_iter().filter(|item| item.starts_with(prefix)) {
        println!("{item}");
    }
    println!(":4");
    Ok(())
}

pub(crate) fn group_usage(path: &[OsString]) -> Option<String> {
    use std::fmt::Write;
    let names = path
        .iter()
        .map(|word| word.to_str())
        .collect::<Option<Vec<_>>>()?;
    let commands = groups::commands(&names)?;
    let mut result = format!(
        "Usage: laneway {} <command> [options]\n\nCommands:",
        names.join(" ")
    );
    for (name, description) in commands {
        let _ = write!(result, "\n  {name:<22} {description}");
    }
    Some(result)
}

fn candidates(path: &[&str]) -> Vec<String> {
    let path = path.strip_prefix(&["help"]).unwrap_or(path);
    if let Some(commands) = groups::commands(path) {
        let mut names: Vec<_> = commands.iter().map(|(name, _)| name.to_string()).collect();
        if path == ["update"] {
            names.push("--yes".to_owned());
        }
        return names;
    }
    #[cfg(target_os = "linux")]
    {
        let node_exit = path.starts_with(&["node", "exit"]);
        let management_path = if node_exit { &path[1..] } else { path };
        if let Some(flags) = (1..=management_path.len())
            .rev()
            .map(|length| crate::management::completion_flags(&management_path[..length]))
            .find(|flags| !flags.is_empty())
        {
            return flags.iter().map(|flag| format!("--{flag}")).collect();
        }
    }
    let words = match path {
        [] => {
            let mut items = groups::CLIENT.to_vec();
            if cfg!(target_os = "linux") {
                items.extend_from_slice(groups::LINUX);
            }
            items.extend(["--help", "--version"]);
            items
        }
        ["configure"] => {
            let mut items = CONFIG.to_vec();
            if cfg!(target_os = "linux") {
                items.push("server");
            }
            if cfg!(target_os = "macos") {
                items.extend(["--check", "--yes"]);
            }
            items
        }
        ["start", ..] if path.contains(&"--system") => vec!["--config"],
        ["start", ..] => START.to_vec(),
        ["credential", "add", ..] => vec!["--password-stdin"],
        ["completion", ..] => vec!["--no-descriptions"],
        ["update", "client", ..] => vec!["--yes"],
        ["update", "connector", ..] => vec!["--name"],
        ["login" | "join", ..] => vec!["--token-file"],
        ["connect", ..] => vec!["--ephemeral", "--remembered", "--route", "--token-file"],
        ["bootstrap", "download", ..] => vec!["--out"],
        [
            "config",
            "validate" | "inspect-controller-initial-network",
            ..,
        ] => vec!["-config"],
        ["connector", "configure" | "validate", ..] => vec!["--state-dir"],
        ["connector", "run", ..] => vec!["--state-dir", "--setup-token-file"],
        ["connector", "activate", ..] => vec!["--setup-token", "--state-dir"],
        ["connector", "bootstrap-seal", ..] => vec!["--out", "--expires-at"],
        ["connector", "bootstrap-activate", ..] => vec!["--state-dir", "--envelope-file"],
        ["control", "init", ..] => vec!["--issuer", "--dev"],
        ["control", "user-token" | "api-token", ..] => vec!["--name", "--expires-in"],
        ["control", "invite", ..] => vec![
            "--name",
            "--ephemeral",
            "--remembered",
            "--native",
            "--docker",
            "--connector",
            "--bootstrap",
        ],
        ["control", "route", "add", ..] => {
            vec!["--connector", "--to", "--allow", "--mode", "--metric"]
        }
        ["control", "status", ..] => vec!["--json"],
        ["control", "restore", ..] => vec!["--identity"],
        ["control", "administrator", "bootstrap" | "recover", ..] => vec!["--username"],
        ["node", "run", ..] => vec!["-config", "-diagnostics"],
        ["pki", "init", ..] => vec!["-out-dir"],
        ["pki", "verify-authority", ..] => vec!["--root", "--issuer", "--key"],
        ["pki", "intermediate" | "node" | "relay" | "controller", ..] => {
            let mut flags = vec![
                "--ca-cert",
                "--ca-key",
                "--out-cert",
                "--out-key",
                "--validity",
            ];
            match path[1] {
                "intermediate" => flags.push("--name"),
                "node" => flags.extend(["--network-id", "--node-id"]),
                _ => flags.extend(["--network-id", "--service-id", "--dns", "--ip"]),
            }
            flags
        }
        _ => Vec::new(),
    };
    words.into_iter().map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_public_and_nested_product_commands() {
        assert!(candidates(&[]).iter().any(|item| item == "configure"));
        assert_eq!(
            candidates(&["help", "completion"]),
            ["bash", "fish", "powershell", "zsh"]
        );
        assert_eq!(candidates(&["start", "--system"]), ["--config"]);
        assert_eq!(candidates(&["update", "client"]), ["--yes"]);
        assert!(!candidates(&[]).iter().any(|item| item == "laneway-compat"));
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn group_help_and_completion_share_real_controller_and_connector_actions() {
    let groups: &[(&[&str], &str)] = &[
        (
            &["controller", "administrator", "root-token"],
            "rotation-begin",
        ),
        (&["controller", "acl"], "delete"),
        (&["connector"], "bootstrap-activate"),
        (&["pki"], "verify-authority"),
        (&["control"], "production-check"),
    ];
    for (path, action) in groups {
        assert!(candidates(path).iter().any(|item| item == action));
        let path: Vec<_> = path.iter().map(OsString::from).collect();
        assert!(group_usage(&path).unwrap().contains(action));
    }
    assert!(!candidates(&["control"]).iter().any(|item| item == "doctor"));
    assert!(!candidates(&["exit"]).iter().any(|item| item == "list"));
    assert!(
        candidates(&["controller", "acl", "add"])
            .iter()
            .any(|item| item == "--network-id")
    );
}
