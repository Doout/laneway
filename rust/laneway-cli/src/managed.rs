//! Managed Linux node installation and credential rotation.

use std::{ffi::OsString, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::{Id, v1::NodeConfiguration};
use lanewayd_rs::ControllerConfig;
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};

use crate::{
    bootstrap::{self, Metadata},
    enrollment::{self, Controller, Credentials},
    node::{parse_bool, split_flag},
    profile,
};

mod files;
mod service;

use files::{Paths, StagedCredentials};
use service::Systemd;

const INSTALL_USAGE: &str =
    "laneway node install DOMAIN [--token-file PATH] [--name NAME] [--no-direct] [--no-start]";
const RENEW_USAGE: &str = "laneway node renew";
const UNINSTALL_USAGE: &str = "laneway node uninstall [--keep-state]";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    authority: String,
    network_id: String,
    node_id: String,
    #[serde(rename = "direct_enabled")]
    direct: bool,
}

#[derive(Default)]
struct Options {
    authority: String,
    token_file: Option<PathBuf>,
    name: String,
    no_direct: bool,
    no_start: bool,
    keep_state: bool,
}

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let args = if args.first().is_some_and(|value| value == "node") {
        &args[1..]
    } else {
        args
    };
    let (operation, args) = args
        .split_first()
        .context("expected node install, renew, or uninstall")?;
    let operation = operation.to_str().context("invalid managed node command")?;
    let usage = match operation {
        "install" => INSTALL_USAGE,
        "renew" => RENEW_USAGE,
        "uninstall" => UNINSTALL_USAGE,
        _ => bail!("unknown managed node command {operation}"),
    };
    let Some(options) = Options::parse(operation, args, usage)? else {
        println!("Usage: {usage}");
        return Ok(());
    };
    ensure!(
        Uid::effective().is_root(),
        "node {operation} requires root on Linux"
    );
    let systemd = Systemd::installed()?;
    let paths = Paths::installed();
    match operation {
        "install" => install(&paths, &systemd, options),
        "renew" => renew(&paths, &systemd),
        "uninstall" => uninstall(&paths, &systemd, options.keep_state),
        _ => unreachable!(),
    }
}

impl Options {
    fn parse(operation: &str, args: &[OsString], usage: &str) -> Result<Option<Self>> {
        let mut options = Self::default();
        let mut args = args.iter();
        if operation == "install"
            && args
                .as_slice()
                .first()
                .is_some_and(|value| !value.as_encoded_bytes().starts_with(b"-"))
        {
            options.authority = args
                .next()
                .and_then(|value| value.to_str())
                .context("invalid DOMAIN")?
                .to_owned();
        }
        while let Some(arg) = args.next() {
            let (flag, attachment) = split_flag(arg);
            if arg == "--" || !arg.as_encoded_bytes().starts_with(b"-") {
                let positional = if arg == "--" { args.next() } else { Some(arg) };
                if let Some(value) = positional {
                    ensure!(
                        operation == "install" && options.authority.is_empty(),
                        "usage: {usage}"
                    );
                    options.authority = value.to_str().context("invalid DOMAIN")?.to_owned();
                }
                ensure!(args.as_slice().is_empty(), "usage: {usage}");
                break;
            }
            let flag = flag
                .strip_prefix("--")
                .or_else(|| flag.strip_prefix('-'))
                .context("invalid flag")?;
            if matches!(flag, "help" | "h") {
                return Ok(None);
            }
            match (operation, flag) {
                ("install", "token-file" | "name") => {
                    let value = attachment
                        .or_else(|| args.next().cloned())
                        .with_context(|| format!("flag needs an argument: --{flag}"))?;
                    if flag == "name" {
                        options.name = value
                            .into_string()
                            .map_err(|_| anyhow::anyhow!("invalid node name"))?;
                    } else {
                        options.token_file = (!value.is_empty()).then(|| value.into());
                    }
                }
                ("install", "no-direct") => options.no_direct = parse_bool(attachment.as_deref())?,
                ("install", "no-start") => options.no_start = parse_bool(attachment.as_deref())?,
                ("uninstall", "keep-state") => {
                    options.keep_state = parse_bool(attachment.as_deref())?
                }
                _ => bail!("flag provided but not defined: -{flag}"),
            }
        }
        if operation == "install" {
            ensure!(
                !options.authority.is_empty()
                    && options.name.trim() == options.name
                    && options.name.len() <= 253,
                "usage: {usage}"
            );
        }
        Ok(Some(options))
    }
}

fn install(paths: &Paths, systemd: &Systemd, options: Options) -> Result<()> {
    let gid = service::preflight()?;
    let _lock = paths.lock(Some(gid))?;
    if let Some(manifest) = paths.manifest()? {
        ensure!(
            manifest.authority == options.authority && manifest.direct != options.no_direct,
            "existing managed node was installed with different authority or dataplane settings"
        );
        paths.validate_files(gid)?;
        if !options.no_start
            && let Err(start) = systemd.start(true)
        {
            let cleanup = systemd.cleanup();
            return Err(service::failures(start, [cleanup])).context("start existing managed node");
        }
        println!(
            "managed node already installed network={} node={} direct={}",
            manifest.network_id, manifest.node_id, manifest.direct
        );
        return Ok(());
    }
    paths.check_unmanaged_absent()?;
    let metadata = bootstrap::fetch(&options.authority)?;
    profile::validate_platform_artifact(&metadata)?;
    let controller = controller(&metadata)?;
    let code = profile::read_managed_enrollment_code(options.token_file.as_deref())?;
    let credentials = enrollment::enroll_durable(&controller, code.as_str(), &options.name)?;
    drop(code);
    let staged = paths.stage_enrollment(&metadata, &credentials)?;
    let initial = initial_configuration(&metadata, &controller, &staged, credentials.node_id)?;
    let (relay, name) = initial_settings(&initial, credentials.node_id)?;
    let manifest = Manifest {
        version: 1,
        authority: options.authority,
        network_id: controller.network_id.to_string(),
        node_id: credentials.node_id.to_string(),
        direct: !options.no_direct,
    };
    let config = paths.render_config(&metadata, &name, relay, manifest.direct)?;
    paths.install(gid, &metadata, &credentials, config.as_bytes(), &manifest)?;
    if !options.no_start
        && let Err(start) = systemd.start(true)
    {
        let stop = systemd.cleanup();
        let remove = if stop.is_ok() {
            paths.remove(false)
        } else {
            Err(anyhow::anyhow!(
                "credentials retained because stopping the service could not be confirmed"
            ))
        };
        return Err(service::failures(start, [stop, remove]))
            .context("start managed node; issue a new invite before retrying enrollment");
    }
    println!(
        "managed node installed network={} node={} name={} direct={}",
        manifest.network_id, manifest.node_id, name, manifest.direct
    );
    Ok(())
}

fn uninstall(paths: &Paths, systemd: &Systemd, keep_state: bool) -> Result<()> {
    let _lock = paths.lock(None)?;
    let manifest = paths
        .manifest()?
        .context("managed node manifest is missing or unsafe")?;
    paths.check_removal(!keep_state)?;
    systemd.cleanup().context("gracefully stop managed node")?;
    paths.remove(!keep_state)?;
    println!(
        "managed node uninstalled network={} node={}",
        manifest.network_id, manifest.node_id
    );
    Ok(())
}

fn renew(paths: &Paths, systemd: &Systemd) -> Result<()> {
    let gid = service::preflight()?;
    let _lock = paths.lock(None)?;
    let manifest = paths
        .manifest()?
        .context("managed node manifest is missing or unsafe")?;
    let config = paths.validate_files(gid)?;
    let ca = paths.read_ca()?;
    let network = manifest.network_id.parse::<Id>()?;
    let node = manifest.node_id.parse::<Id>()?;
    let controller = Controller {
        endpoint: &config.controller.endpoint,
        quic_endpoint: &config.controller.quic_endpoint,
        server_name: &config.controller.server_name,
        network_id: network,
        service_id: config
            .controller
            .service_id
            .parse()
            .context("invalid managed controller identity")?,
        ca_pem: &ca,
    };
    ensure!(
        config.controller.network_id.parse::<Id>()? == network,
        "managed configuration does not match the saved network identity"
    );
    let staged = paths.stage_current()?;
    let credentials = enrollment::renew(
        &controller,
        node,
        &staged.tls.ca,
        &staged.tls.certificate,
        &staged.tls.private_key,
    )
    .context("renew managed node credentials")?;
    if let Err(stop) = systemd.stop() {
        // Renewal commits the new WireGuard key on the controller. If the
        // daemon cannot stop, keep the old TLS pair and make its next restart
        // use the committed WireGuard key.
        let reconcile = paths.reconcile_wireguard(gid, &credentials);
        return Err(service::failures(stop, [reconcile]))
            .context("stop managed node for credential rotation");
    }
    if let Err(promotion) = paths.promote(gid, &credentials) {
        let wireguard = paths.reconcile_wireguard(gid, &credentials);
        let tls = paths.restore_tls(gid, &staged);
        let restart = if wireguard.is_ok() && tls.is_ok() {
            systemd.start(false)
        } else {
            Ok(())
        };
        return Err(service::failures(promotion, [wireguard, tls, restart])).context(
            "could not promote renewed credential; reconciled controller-bound WireGuard key and previous TLS pair"
        );
    }
    if let Err(start) = systemd.start(false) {
        let stop = systemd.stop();
        let restore = if stop.is_ok() {
            paths.restore_tls(gid, &staged)
        } else {
            Err(anyhow::anyhow!(
                "retained new TLS files because stopping the service could not be confirmed"
            ))
        };
        let restart = if restore.is_ok() {
            systemd.reset_failed();
            systemd.start(false)
        } else {
            Ok(())
        };
        return Err(service::failures(start, [stop, restore, restart])).context(
            "renewed credential failed to start; controller-bound WireGuard key retained",
        );
    }
    println!(
        "managed node renewed network={} node={}",
        manifest.network_id, manifest.node_id
    );
    Ok(())
}

fn controller(metadata: &Metadata) -> Result<Controller<'_>> {
    Ok(Controller {
        endpoint: &metadata.controller.enrollment_endpoint,
        quic_endpoint: &metadata.controller.quic_endpoint,
        server_name: &metadata.controller.server_name,
        network_id: metadata.network_id.parse()?,
        service_id: metadata.controller.service_id.parse()?,
        ca_pem: metadata.trust.ca_pem.as_bytes(),
    })
}

fn initial_configuration(
    metadata: &Metadata,
    controller: &Controller<'_>,
    staged: &StagedCredentials,
    node: Id,
) -> Result<NodeConfiguration> {
    let options = ControllerConfig {
        endpoint: metadata.controller.enrollment_endpoint.clone(),
        quic_endpoint: Some(metadata.controller.quic_endpoint.clone()),
        server_name: metadata.controller.server_name.clone(),
        service_id: metadata.controller.service_id.clone(),
        poll_interval: Duration::from_secs(30),
        timeout: Duration::from_secs(20),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(async {
            tokio::time::timeout(
                options.timeout,
                lanewayd_rs::rootless::get_configuration(
                    &options,
                    controller.network_id,
                    node,
                    &staged.tls,
                ),
            )
            .await
            .context("read initial managed configuration timed out")?
        })
        .context("fetch initial managed-node configuration")
}

fn initial_settings(configuration: &NodeConfiguration, node: Id) -> Result<((Id, &str), String)> {
    let relay = configuration
        .relays
        .iter()
        .min_by(|a, b| {
            a.service_id
                .cmp(&b.service_id)
                .then_with(|| a.endpoint.cmp(&b.endpoint))
        })
        .context("controller authorized no relay for the managed node")?;
    let service = Id::from_slice(&relay.service_id)
        .context("controller returned an invalid relay identity")?;
    ensure!(
        !relay.endpoint.is_empty(),
        "controller returned an invalid relay endpoint"
    );
    let name = configuration
        .peers
        .iter()
        .find(|record| record.node_id == node.as_bytes())
        .map(|record| record.name.as_str())
        .unwrap_or("temporary-user");
    Ok(((service, &relay.endpoint), name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::{NodePeer, RelayEndpoint};

    #[test]
    fn managed_flags_respect_domains_and_explicit_booleans() {
        let args = [
            "lane.test",
            "--name",
            "workstation",
            "--no-direct=false",
            "--no-start",
        ]
        .map(OsString::from);
        let options = Options::parse("install", &args, INSTALL_USAGE)
            .unwrap()
            .unwrap();
        assert_eq!(options.authority, "lane.test");
        assert_eq!(options.name, "workstation");
        assert!(!options.no_direct);
        assert!(options.no_start);
        assert!(Options::parse("renew", &["--keep-state".into()], RENEW_USAGE).is_err());
    }

    #[test]
    fn chooses_authoritative_relay_and_round_trips_go_config() {
        let node = Id::new([1; 16]).unwrap();
        let mut snapshot = NodeConfiguration::default();
        snapshot.peers.push(NodePeer {
            node_id: node.as_bytes().to_vec(),
            name: "managed-node".into(),
            ..Default::default()
        });
        for (id, endpoint) in [(10, "later.test:4433"), (9, "relay.test:4433")] {
            snapshot.relays.push(RelayEndpoint {
                service_id: vec![id; 16],
                endpoint: endpoint.into(),
                ..Default::default()
            });
        }
        let (relay, name) = initial_settings(&snapshot, node).unwrap();
        assert_eq!(relay.1, "relay.test:4433");
        let metadata = Metadata {
            network_id: "11111111111111111111111111111111".into(),
            controller: bootstrap::Controller {
                enrollment_endpoint: "https://controller.test".into(),
                quic_endpoint: "controller.test:8443".into(),
                server_name: "controller.test".into(),
                service_id: "22222222222222222222222222222222".into(),
            },
            ..Default::default()
        };
        let config = Paths::installed()
            .render_config(&metadata, &name, relay, false)
            .unwrap();
        let config = laneway_config::Config::parse(&config).unwrap();
        assert_eq!(config.node.name, "managed-node");
        assert_eq!(config.node.relay_address, "relay.test:4433");
        assert_eq!(
            config.node.relay_service_id,
            Id::new([9; 16]).unwrap().to_string()
        );
        assert_eq!(config.tls.private_key, "/etc/laneway/node.key");
        assert_eq!(config.wireguard.private_key, "/etc/laneway/wireguard.key");
        assert_eq!(config.direct.enabled, Some(false));
    }
}
