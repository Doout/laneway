#![forbid(unsafe_code)]

mod bootstrap;
mod client_update;
mod compat;
mod completion;
#[cfg(target_os = "linux")]
mod config;
mod connect;
#[cfg(target_os = "linux")]
mod connect_linux;
#[cfg(target_os = "linux")]
mod connector;
#[cfg(target_os = "linux")]
mod control;
mod enrollment;
mod host;
#[cfg(target_os = "linux")]
mod local;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod managed;
#[cfg(target_os = "linux")]
mod management;
mod node;
#[cfg(target_os = "linux")]
mod node_run;
mod profile;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod session_runtime;
#[cfg(target_os = "linux")]
mod utility;
mod version;

use anyhow::{Result, bail};
use std::{env, ffi::OsString, process::ExitCode};

use version::VERSION;

fn root_help() {
    println!(
        "Usage: laneway <command> [options]\n\nClient commands:
  configure   Set up this node (userspace by default)
  start       Start the node and its local proxy
  credential  Manage local SOCKS5 credentials
  login       Save a renewable user login
  connect     Connect using a saved login
  logout      Remove a saved user login"
    );
    #[cfg(target_os = "linux")]
    println!(
        "\nHost and server commands:
  node        Install, operate, and inspect this host
  control     Operate the Docker Compose control plane"
    );
    println!(
        "\nOther commands:
  update      Update the detected local installation
  version     Print the Laneway version
  completion  Generate shell completion
  help        Show help for a command\n\nRun 'laneway help <command>' for details."
    );
}

// Return help before touching local state or probing Docker.
fn product_usage(path: &[OsString]) -> Option<&'static str> {
    let first = path.first()?.to_str()?;
    let child = path.get(1).and_then(|arg| arg.to_str());
    if path.len() > 2 {
        return None;
    }
    match (first, child) {
        ("configure", None) => Some(
            "laneway configure [--state-dir PATH | --system]\n       laneway configure server [DOMAIN]\n\nPaste your invitation at the prompt. First-time userspace setup creates a local proxy login.",
        ),
        ("configure", Some("server")) => Some(
            "laneway configure server [DOMAIN]\n\nConfigure the managed Docker Compose control plane on its Linux host.",
        ),
        ("start", None) => Some(
            "laneway start [--state-dir PATH] [--listen ADDRESS | --no-proxy] [--proxy-only]\n       laneway start --system [--config PATH]\n\nStart in the foreground. The local SOCKS5 listener defaults to 127.0.0.1:1080.",
        ),
        ("credential", None) => Some(
            "laneway credential <add|list|remove> [options]\n\nManage users of the local SOCKS5 proxy.",
        ),
        ("update", None) => Some(
            "laneway update [client | server | connector [NAME]]\n\nUpdate the local installation. On hosts with multiple roles, select a target.",
        ),
        ("update", Some("client")) => {
            Some("laneway update client [--yes]\n\nInstall the signed client update.")
        }
        ("update", Some("server")) => Some(
            "laneway update server\n\nUpdate the managed control plane on its Linux Docker host.",
        ),
        ("update", Some("connector")) => Some(
            "laneway update connector [NAME]\n\nUpdate a managed connector on its Linux Docker host.",
        ),
        ("version", None) => Some("laneway version"),
        _ => None,
    }
}

// Help topics are command names only. Never pass a user's operands to a
// configuration or maintenance action while looking up its documentation.
fn help_topic(path: &[OsString]) -> Result<()> {
    if let Some(usage) = completion::group_usage(path) {
        println!("{usage}");
        return Ok(());
    }
    let name = path[0].to_str().unwrap_or("");
    let mut leaf = path.to_vec();
    leaf.push("--help".into());
    #[cfg(target_os = "linux")]
    match name {
        "controller" | "route" | "invite" => return management::help(path),
        "node" if path.get(1).is_some_and(|word| word == "route") => return management::help(path),
        "exit" if path.len() == 2 && path[1] == "enable" => return management::help(path),
        "node" if path.len() == 3 && path[1] == "exit" && path[2] == "enable" => {
            return management::help(path);
        }
        "exit" if path.len() == 2 && (path[1] == "disable" || path[1] == "use") => {
            return local::exit::run(&leaf);
        }
        "node"
            if path.len() == 3
                && path[1] == "exit"
                && (path[2] == "disable" || path[2] == "use") =>
        {
            return local::exit::run(&leaf);
        }
        "node"
            if path.len() == 2
                && matches!(path[1].to_str(), Some("install" | "renew" | "uninstall")) =>
        {
            return managed::run(&leaf);
        }
        "config" if path.len() <= 2 => return config::run(&leaf[1..]),
        "join" | "renew" if path.len() == 1 => return enrollment::legacy_command(&leaf),
        "connector" if path.len() <= 2 => return connector::run(&leaf),
        "control" => {
            let mut args = vec![OsString::from("control"), "help".into()];
            args.extend_from_slice(&path[1..]);
            return control::run(&args);
        }
        "id" if path.len() == 1 => {
            println!("Usage: laneway id");
            return Ok(());
        }
        "pki" if path.len() == 2 && (path[1] == "init" || utility::is_issuer_command(&path[1])) => {
            return utility::run(&leaf);
        }
        _ if local::command(path).is_some() && path.len() == if name == "node" { 2 } else { 1 } => {
            return local::run(&leaf);
        }
        _ => {}
    }
    if name == "completion" {
        return completion::run(&leaf);
    }
    if name == "login" && path.len() == 1 {
        return profile::login(&leaf);
    }
    if name == "connect" && path.len() == 1 {
        return connect::run(&leaf);
    }
    if name == "bootstrap"
        && (path.len() == 1
            || (path.len() == 2 && matches!(path[1].to_str(), Some("inspect" | "download"))))
    {
        return bootstrap::run(&leaf);
    }
    if name == "logout" && path.len() == 1 {
        return profile::run(&leaf);
    }
    if name == "help" {
        root_help();
        return Ok(());
    }
    if name == "_network-helper" && path.len() == 1 {
        return network_helper(&leaf);
    }
    #[cfg(target_os = "linux")]
    if path.len() == 2 && path[0] == "node" && path[1] == "run" {
        return node_run::run(&leaf);
    }
    bail!("unknown help topic {:?}; run 'laneway help'", path);
}

fn run(args: &[OsString]) -> Result<()> {
    let Some(first) = args.first() else {
        root_help();
        return Ok(());
    };
    let command = first.to_str().unwrap_or("");
    if args.len() == 1 {
        match command {
            "-h" | "--help" | "help" => {
                root_help();
                return Ok(());
            }
            "version" | "-version" => {
                println!("{VERSION}");
                return Ok(());
            }
            "-v" | "--version" => {
                println!("laneway version {VERSION}");
                return Ok(());
            }
            _ => {}
        }
    }
    let help = if command == "help" {
        Some(&args[1..])
    } else if args.last().is_some_and(|s| s == "--help" || s == "-h") {
        Some(&args[..args.len() - 1])
    } else {
        None
    };
    if let Some(usage) = help.and_then(product_usage) {
        println!("Usage: {usage}");
        return Ok(());
    }
    if let Some(usage) = help.and_then(completion::group_usage) {
        println!("{usage}");
        return Ok(());
    }
    if !matches!(command, "configure" | "update" | "credential")
        && let Some(usage) = completion::group_usage(args)
    {
        println!("{usage}");
        return Ok(());
    }
    if command == "help" {
        return help_topic(&args[1..]);
    }
    match command {
        "configure" if args.get(1).is_some_and(|arg| arg == "server") => {
            host::configure_server(args)
        }
        "configure" | "start" | "credential" => node::run(args),
        "update" => host::update(args),
        "completion" => completion::run(args),
        "__complete" | "__completeNoDesc" => completion::callback(args),
        #[cfg(target_os = "linux")]
        "exit"
            if args
                .get(1)
                .is_some_and(|arg| arg == "use" || arg == "disable") =>
        {
            local::exit::run(args)
        }
        #[cfg(target_os = "linux")]
        "node"
            if args.get(1).is_some_and(|arg| arg == "exit")
                && args
                    .get(2)
                    .is_some_and(|arg| arg == "use" || arg == "disable") =>
        {
            local::exit::run(args)
        }
        #[cfg(target_os = "linux")]
        "join" | "renew" => enrollment::legacy_command(args),
        #[cfg(target_os = "linux")]
        "config" => config::run(&args[1..]),
        #[cfg(target_os = "linux")]
        "connector" => connector::run(args),
        #[cfg(target_os = "linux")]
        "node"
            if matches!(
                args.get(1).and_then(|arg| arg.to_str()),
                Some("install" | "renew" | "uninstall")
            ) =>
        {
            managed::run(args)
        }
        #[cfg(target_os = "linux")]
        "node" if args.get(1).is_some_and(|arg| arg == "run") => node_run::run(args),
        #[cfg(target_os = "linux")]
        "exit" if args.get(1).is_some_and(|arg| arg == "enable") => management::run(args),
        #[cfg(target_os = "linux")]
        "node"
            if args.get(1).is_some_and(|arg| arg == "exit")
                && args.get(2).is_some_and(|arg| arg == "enable") =>
        {
            management::run(args)
        }
        #[cfg(target_os = "linux")]
        "invite" | "controller" | "route" => management::run(args),
        #[cfg(target_os = "linux")]
        "node" if args.get(1).is_some_and(|arg| arg == "route") => management::run(args),
        "bootstrap" => bootstrap::run(args),
        "login" => profile::login(args),
        "connect" => connect::run(args),
        "logout" => profile::run(args),
        #[cfg(target_os = "linux")]
        "control" => control::run(args),
        #[cfg(target_os = "linux")]
        "id" => utility::run(args),
        #[cfg(target_os = "linux")]
        "pki"
            if args
                .get(1)
                .is_some_and(|arg| arg == "init" || utility::is_issuer_command(arg)) =>
        {
            utility::run(args)
        }
        #[cfg(target_os = "linux")]
        _ if local::command(args).is_some() => local::run(args),
        "_network-helper" => network_helper(args),
        #[cfg(target_os = "linux")]
        "_network-helper-native" => {
            if args.len() == 2 && args[1] == "--version" {
                println!("{VERSION}");
                Ok(())
            } else {
                network_helper(args)
            }
        }
        _ => bail!(
            "unknown command {:?} for laneway; run 'laneway help'",
            first
        ),
    }
}

#[cfg(target_os = "linux")]
fn network_helper(args: &[OsString]) -> Result<()> {
    laneway_cli::network_helper_entry::run(
        &args[1..],
        laneway_cli::network_helper_server::linux::serve,
    )
}

#[cfg(target_os = "macos")]
fn network_helper(args: &[OsString]) -> Result<()> {
    laneway_cli::network_helper_entry::run(
        &args[1..],
        laneway_cli::network_helper_server::serve_darwin,
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn network_helper(args: &[OsString]) -> Result<()> {
    compat::run(args)
}

#[cfg(target_os = "macos")]
fn from_installed_helper() -> bool {
    env::current_exe()
        .ok()
        .is_some_and(|executable| executable == std::path::Path::new(macos::HELPER))
}

#[cfg(target_os = "macos")]
fn run_installed_helper(args: &[OsString]) -> Result<()> {
    match args {
        [command, ..] if command == "_network-helper" => network_helper(args),
        [command] if command == "version" || command == "-version" || command == "--version" => {
            println!("{VERSION}");
            Ok(())
        }
        _ => bail!("use the laneway command for client and server operations"),
    }
}

fn main() -> ExitCode {
    match dispatch(&env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("laneway: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[OsString]) -> Result<()> {
    #[cfg(target_os = "macos")]
    if from_installed_helper() {
        return run_installed_helper(args);
    }
    run(args)
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn dedicated_helper_exposes_only_its_reserved_commands() {
    assert!(run_installed_helper(&["version".into()]).is_ok());
    assert!(run_installed_helper(&["_network-helper".into(), "--help".into()]).is_ok());
    assert!(run_installed_helper(&["configure".into(), "--help".into()]).is_err());
    assert!(run_installed_helper(&["connect".into()]).is_err());
}
