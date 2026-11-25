//! Run a Go-shaped persistent node configuration on the native Linux agent
//! when every enabled data-plane role can be represented.
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, BufReader},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use laneway_config::{Config as Legacy, GoDuration};
use laneway_protocol::{AuthenticatedIdentity, Role, identity_from_certificate_der};
use lanewayd_rs::{
    Agent, Config, ControllerConfig, DiagnosticsConfig, DirectConfig, DirectPeerConfig,
    ExitFailureMode, ForwardMode, ForwardingConfig, IdentityConfig, RelayConfig, RouteConfig,
    RouteKind, SubnetForwardConfig, TcpFallbackConfig, TlsConfig, TunConfig,
};
use serde::Deserialize;
use tokio::signal::unix::{SignalKind, signal};

use crate::node::{parse_bool, split_flag};

const DEFAULT_CONFIG: &str = "/etc/laneway/laneway.toml";
const EXIT_INTENT: &str = "exit-intent-v1.json";
const USAGE: &str = "laneway node run [-config path] [-diagnostics 127.0.0.1:PORT] [-version]";

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let Some(options) = Options::parse(&args[2..])? else {
        println!("Usage: {USAGE}\n\nRun the persistent Linux node service.");
        return Ok(());
    };
    if options.version {
        println!("{}", crate::VERSION);
        return Ok(());
    }
    let legacy = match Legacy::load(&options.config) {
        Ok(config) => config,
        // Keep the legacy loader for schema variants it still owns.
        Err(_) => return crate::compat::run(args),
    };
    if let Some(reason) = compatibility_reason(&legacy, &options) {
        eprintln!("laneway node run: using compatibility runtime for {reason}");
        return crate::compat::run(args);
    }

    let state_dir = Path::new(&legacy.state_dir);
    let intent_path = state_dir.join(EXIT_INTENT);
    let intent = load_intent(&intent_path)?;
    let config = convert(&legacy, intent.as_ref())?;
    if let Err(error) = config.validate() {
        eprintln!(
            "laneway node run: using compatibility runtime for configuration bounds ({error})"
        );
        return crate::compat::run(args);
    }
    let socket_parent = config
        .socket_path
        .parent()
        .context("local node socket has no parent directory")?
        .to_owned();
    let agent = Agent::new(config)?;
    let runtime = tokio::runtime::Runtime::new().context("create persistent node runtime")?;
    runtime.block_on(async {
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        create_directory(state_dir, 0o700).context("create node state directory")?;
        create_directory(&socket_parent, 0o755)
            .context("create local management socket directory")?;
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .try_init()
            .ok();
        agent
            .run_until(async {
                tokio::select! {
                    _ = interrupt.recv() => (),
                    _ = terminate.recv() => (),
                }
            })
            .await
    })
}

struct Options {
    config: PathBuf,
    diagnostics: OsString,
    version: bool,
}

impl Options {
    fn parse(args: &[OsString]) -> Result<Option<Self>> {
        let mut options = Self {
            config: DEFAULT_CONFIG.into(),
            diagnostics: OsString::new(),
            version: false,
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            if arg == "--" {
                if let Some(extra) = args.next() {
                    bail!("unexpected node run argument {extra:?}");
                }
                break;
            }
            let (name, attached) = split_flag(arg);
            let name = name
                .strip_prefix("--")
                .or_else(|| name.strip_prefix('-'))
                .filter(|name| !name.is_empty())
                .with_context(|| format!("unexpected node run argument {arg:?}"))?;
            let mut value = || {
                attached
                    .clone()
                    .or_else(|| args.next().cloned())
                    .with_context(|| format!("flag needs an argument: -{name}"))
            };
            match name {
                "h" | "help" => return Ok(None),
                "version" => {
                    options.version =
                        parse_bool(attached.as_deref()).context("invalid version flag")?
                }
                "config" => options.config = value()?.into(),
                "diagnostics" => options.diagnostics = value()?,
                _ => bail!("flag provided but not defined: -{name}"),
            }
        }
        Ok(Some(options))
    }
}

fn compatibility_reason(config: &Legacy, options: &Options) -> Option<&'static str> {
    if config.mode != "node" {
        Some("non-node configuration validation")
    } else if config.connector.userspace {
        Some("userspace Connector packet handling")
    } else if config.wireguard.enabled {
        Some("the WireGuard device backend")
    } else if !options.diagnostics.is_empty() {
        Some("the requested Go pprof and legacy Prometheus diagnostics")
    } else if config.exit.serve {
        Some("managed Exit Node forwarding")
    } else if !Path::new(&config.state_dir).is_absolute()
        || !Path::new(&config.socket_path).is_absolute()
    {
        Some("relative state or socket paths")
    } else if config
        .exit
        .dns_servers
        .iter()
        .any(|address| address.contains('%'))
    {
        Some("scoped IPv6 exit DNS")
    } else if (config.direct.enabled.unwrap_or(true) && config.direct.listen.contains('%'))
        || [&config.node.relay_address, &config.tcp_fallback.address]
            .into_iter()
            .any(|endpoint| endpoint.contains('%'))
    {
        Some("scoped IPv6 transport endpoints")
    } else if config.controller.endpoint.is_empty() && config.peers.is_empty() {
        Some("a static node without peer routes")
    } else if !config.tcp_fallback.address.is_empty()
        && config.tls.server_name.is_empty()
        && endpoint_host(&config.tcp_fallback.address) != endpoint_host(&config.node.relay_address)
    {
        Some("separate implicit QUIC and TCP certificate names")
    } else {
        None
    }
}

fn endpoint_host(endpoint: &str) -> Option<&str> {
    let (host, _) = endpoint.rsplit_once(':')?;
    Some(
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host),
    )
}

fn endpoint(endpoint: &str, passive: bool) -> Result<SocketAddr> {
    if passive && let Some(port) = endpoint.strip_prefix(':') {
        return format!("[::]:{port}")
            .parse()
            .context("invalid UDP listen port");
    }
    let mut addresses = endpoint
        .to_socket_addrs()
        .with_context(|| format!("resolve {endpoint}"))?;
    addresses
        .find(|address| {
            let ip = address.ip().to_canonical();
            passive
                || (!ip.is_unspecified()
                    && !ip.is_multicast()
                    && ip != IpAddr::from(std::net::Ipv4Addr::BROADCAST))
        })
        .map(|address| SocketAddr::new(address.ip().to_canonical(), address.port()))
        .with_context(|| format!("no IP address for {endpoint}"))
}

fn duration(duration: GoDuration) -> Result<Duration> {
    Ok(Duration::from_nanos(
        u64::try_from(duration.nanos()).context("negative configuration duration")?,
    ))
}

fn certificate_identity(path: &Path) -> Result<AuthenticatedIdentity> {
    let file = File::open(path).context("open node certificate")?;
    let pem = laneway_protocol::read_bounded(file, 1 << 20).context("read node certificate")?;
    let certificate = rustls_pemfile::certs(&mut BufReader::new(pem.as_slice()))
        .next()
        .context("missing node certificate")??;
    let identity = identity_from_certificate_der(certificate.as_ref())
        .context("parse node certificate identity")?;
    ensure!(
        identity.role == Role::Node,
        "certificate identity is not a node"
    );
    Ok(identity)
}

fn convert(legacy: &Legacy, intent: Option<&ExitIntent>) -> Result<Config> {
    let identity = certificate_identity(Path::new(&legacy.tls.certificate))?;
    let local = identity.subject_id.to_string();
    let network = identity.network_id.to_string();
    ensure!(
        network == legacy.node.relay_network_id,
        "configured relay network ID does not match the node certificate network"
    );
    let controller = if legacy.controller.endpoint.is_empty() {
        None
    } else {
        ensure!(
            network == legacy.controller.network_id,
            "configured controller network ID does not match the node certificate network"
        );
        Some(ControllerConfig {
            endpoint: legacy.controller.endpoint.clone(),
            quic_endpoint: Some(legacy.controller.quic_endpoint.clone()),
            server_name: legacy.controller.server_name.clone(),
            service_id: legacy.controller.service_id.clone(),
            poll_interval: duration(legacy.controller.poll_interval)?,
            timeout: Duration::from_secs(15),
        })
    };

    let addresses: Vec<IpNet> = legacy
        .node
        .overlay_addresses
        .iter()
        .map(|value| {
            let prefix: IpNet = value.parse()?;
            let address = prefix.addr();
            let link_local = match address {
                IpAddr::V4(address) => address.is_link_local(),
                IpAddr::V6(address) => address.is_unicast_link_local(),
            };
            ensure!(
                prefix == IpNet::from(address)
                    && address.to_canonical() == address
                    && !address.is_unspecified()
                    && !address.is_multicast()
                    && !address.is_loopback()
                    && !link_local,
                "overlay address {value:?} must be a canonical unicast IPv4 /32 or IPv6 /128"
            );
            Ok(prefix)
        })
        .collect::<Result<_>>()?;
    let routes = peer_routes(legacy, &network, &local)?;
    let direct_enabled = legacy.direct.enabled.unwrap_or(true);
    let direct_peers = if direct_enabled {
        routes
            .iter()
            .map(|route| {
                (
                    route.via_node.clone(),
                    DirectPeerConfig {
                        node_id: route.via_node.clone(),
                        address: None,
                        server_name: String::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>()
            .into_values()
            .collect()
    } else {
        Vec::new()
    };
    let direct = if direct_enabled {
        DirectConfig {
            listen: endpoint(&legacy.direct.listen, true)?,
            probe_interval: duration(legacy.direct.probe_interval)?,
            probe_timeout: duration(legacy.direct.probe_timeout)?,
            candidate_refresh_interval: duration(legacy.direct.rendezvous_interval)?,
            max_candidates: Some(usize::try_from(legacy.direct.max_candidates)?),
            candidate_ttl: Some(duration(legacy.direct.candidate_ttl)?),
            allow_loopback: legacy.direct.allow_loopback,
            allow_link_local: legacy.direct.allow_link_local,
            ..Default::default()
        }
    } else {
        DirectConfig {
            enabled: false,
            ..Default::default()
        }
    };

    let static_relay = endpoint(&legacy.node.relay_address, false)?;
    let relay_name = if legacy.tls.server_name.is_empty() {
        endpoint_host(&legacy.node.relay_address)
            .context("invalid relay endpoint")?
            .to_owned()
    } else {
        legacy.tls.server_name.clone()
    };
    let idle = duration(legacy.relay.idle_timeout)?;
    let mut forwarding = forwarding(legacy, controller.is_some(), intent)?;
    let relay_address = if controller.is_some() && legacy.tls.server_name.is_empty() {
        // Controller-advertised relays retain their own TLS names when the
        // operator has not pinned a single name. Keep the bootstrap IP in
        // the host-route bypass set independently of that dial policy.
        forwarding
            .exit_client
            .transport_bypass
            .push(static_relay.ip());
        None
    } else {
        Some(static_relay)
    };
    forwarding.dns_state_file = Path::new(&legacy.state_dir).join("dns-state-v1.json");

    Ok(Config {
        mode: "node".to_owned(),
        socket_path: (&legacy.socket_path).into(),
        exit_intent_path: Path::new(&legacy.state_dir).join(EXIT_INTENT),
        identity: IdentityConfig {
            name: Some(legacy.node.name.clone()),
            product_version: Some(crate::VERSION.to_owned()),
            network_id: network,
            node_id: local,
        },
        tls: TlsConfig {
            certificate: (&legacy.tls.certificate).into(),
            private_key: (&legacy.tls.private_key).into(),
            ca: (&legacy.tls.ca).into(),
        },
        controller,
        tun: TunConfig {
            name: "lane0".to_owned(),
            mtu: if !legacy.controller.endpoint.is_empty()
                || addresses.iter().any(|address| address.addr().is_ipv6())
            {
                1280
            } else {
                1200
            },
            addresses,
            configure: true,
        },
        relay: RelayConfig {
            address: relay_address,
            display_address: Some(legacy.node.relay_address.clone()),
            server_name: relay_name,
            service_id: legacy.node.relay_service_id.clone(),
            queue_depth: 256,
            max_routes: 4096,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: idle,
            keepalive: Duration::from_secs(15).min(idle / 2),
            reconnect_min: duration(legacy.node.reconnect_min)?,
            reconnect_max: duration(legacy.node.reconnect_max)?,
            quic_recovery_interval: duration(legacy.tcp_fallback.quic_probe_interval)?,
        },
        tcp_fallback: fallback(legacy)?,
        direct,
        routes,
        direct_peers,
        forwarding,
        diagnostics: DiagnosticsConfig::default(),
    })
}

fn peer_routes(legacy: &Legacy, network: &str, local: &str) -> Result<Vec<RouteConfig>> {
    let mut routes = Vec::new();
    for peer in &legacy.peers {
        ensure!(
            peer.network_id == network,
            "static peer belongs to a different network"
        );
        if peer.node_id == local {
            continue;
        }
        for prefix in &peer.prefixes {
            routes.push(RouteConfig {
                prefix: prefix.parse()?,
                via_node: peer.node_id.clone(),
                metric: 0,
                kind: RouteKind::Overlay,
            });
        }
    }
    Ok(routes)
}

fn fallback(legacy: &Legacy) -> Result<Option<TcpFallbackConfig>> {
    let fallback = &legacy.tcp_fallback;
    if fallback.address.is_empty() {
        return Ok(None);
    }
    Ok(Some(TcpFallbackConfig {
        address: endpoint(&fallback.address, false)?,
        handshake_timeout: duration(fallback.handshake_timeout)?,
        write_timeout: duration(fallback.write_timeout)?,
        idle_timeout: duration(fallback.idle_timeout)?,
        keepalive_period: duration(fallback.keepalive_period)?,
        queue_depth: usize::try_from(fallback.queue_depth)?,
    }))
}

fn forwarding(
    legacy: &Legacy,
    dynamic: bool,
    intent: Option<&ExitIntent>,
) -> Result<ForwardingConfig> {
    let mut forwarding = ForwardingConfig {
        require_controller_subnet_interface: dynamic,
        ..ForwardingConfig::default()
    };
    let routing = &legacy.routing;
    if dynamic && !routing.output_interface.is_empty() {
        forwarding.controller_subnet_interface = Some(routing.output_interface.clone());
    } else if !dynamic {
        forwarding.owned_prefixes = routing
            .advertise
            .iter()
            .map(|value| value.parse())
            .collect::<Result<_, _>>()?;
        forwarding.subnet_router = !forwarding.owned_prefixes.is_empty();
        forwarding.subnet_routes = forwarding
            .owned_prefixes
            .iter()
            .map(|prefix| SubnetForwardConfig {
                prefix: *prefix,
                mode: if routing.nat {
                    ForwardMode::Nat
                } else {
                    ForwardMode::Routed
                },
                output_interface: routing.output_interface.clone(),
            })
            .collect();
    }
    let exit = &legacy.exit;
    let selected = &mut forwarding.exit_client;
    selected.authorized = dynamic;
    selected.enabled = intent.map_or(exit.enabled, |intent| intent.enabled);
    selected.selected_node = if let Some(intent) = intent {
        intent.selected_node_id.clone()
    } else if selected.enabled {
        Some(exit.selected_node_id.clone())
    } else {
        None
    };
    let mode = intent
        .and_then(|intent| intent.failure_mode.as_deref())
        .unwrap_or(&exit.failure_mode);
    selected.failure_mode = match mode {
        "open" => ExitFailureMode::Open,
        "closed" | "" => ExitFailureMode::Closed,
        _ => bail!("unsupported exit failure mode {mode:?}"),
    };
    selected.dns_servers = exit
        .dns_servers
        .iter()
        .map(|value| value.parse::<IpAddr>())
        .collect::<Result<_, _>>()?;
    selected.local_lan_bypass = exit
        .local_lan_bypasses
        .iter()
        .map(|value| value.parse())
        .collect::<Result<_, _>>()?;
    Ok(forwarding)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitIntent {
    version: u32,
    enabled: bool,
    #[serde(default, deserialize_with = "intent_string")]
    selected_node_id: Option<String>,
    #[serde(default, deserialize_with = "intent_string")]
    failure_mode: Option<String>,
}

fn intent_string<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Option<String>, D::Error> {
    String::deserialize(value).map(Some)
}

fn load_intent(path: &Path) -> Result<Option<ExitIntent>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(info) => info,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect persisted exit intent"),
    };
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o777 == 0o600,
        "persisted exit intent must be a mode-0600 regular file"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .context("open persisted exit intent")?;
    let opened = file.metadata()?;
    ensure!(
        opened.is_file()
            && opened.permissions().mode() & 0o777 == 0o600
            && (opened.dev(), opened.ino()) == (metadata.dev(), metadata.ino()),
        "persisted exit intent changed while opening"
    );
    let contents =
        laneway_protocol::read_bounded(file, 4096).context("read persisted exit intent")?;
    let intent: ExitIntent =
        serde_json::from_slice(&contents).context("decode persisted exit intent")?;
    ensure!(
        intent.version == 1,
        "unsupported persisted exit intent version"
    );
    if intent.enabled {
        intent
            .selected_node_id
            .as_deref()
            .context("persisted exit intent omitted selected_node_id")?
            .parse::<laneway_protocol::Id>()
            .context("invalid persisted exit node")?;
        ensure!(
            matches!(intent.failure_mode.as_deref(), Some("open" | "closed")),
            "persisted exit intent requires an explicit failure mode"
        );
    } else {
        ensure!(
            intent.selected_node_id.is_none() && intent.failure_mode.is_none(),
            "disabled exit intent must be neutral"
        );
    }
    Ok(Some(intent))
}

fn create_directory(path: &Path, mode: u32) -> io::Result<()> {
    DirBuilder::new().mode(mode).recursive(true).create(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy(managed: bool) -> (tempfile::TempDir, Legacy) {
        let sample = if managed {
            include_str!("../../../deploy/examples/node-controller.toml")
        } else {
            include_str!("../../../deploy/examples/node.toml")
        };
        let mut config = Legacy::parse(sample).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut parameters = rcgen::CertificateParams::new(Vec::new()).unwrap();
        let uri = format!(
            "spiffe://laneway/network/{}/node/101112131415161718191a1b1c1d1e1f",
            config.node.relay_network_id
        );
        parameters
            .subject_alt_names
            .push(rcgen::SanType::URI(uri.try_into().unwrap()));
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = directory.path().join("node.pem");
        fs::write(&certificate, parameters.self_signed(&key).unwrap().pem()).unwrap();
        config.tls.certificate = certificate.to_str().unwrap().to_owned();
        config.node.relay_address = "127.0.0.1:4433".to_owned();
        config.tcp_fallback.address = "127.0.0.1:443".to_owned();
        config.state_dir = directory.path().to_str().unwrap().to_owned();
        config.socket_path = directory
            .path()
            .join("node.sock")
            .to_str()
            .unwrap()
            .to_owned();
        (directory, config)
    }

    #[test]
    fn converts_managed_and_static_go_configs() {
        let (_directory, managed) = legacy(true);
        let config = convert(&managed, None).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.forwarding.controller_subnet_interface.as_deref(),
            Some("eth0")
        );
        assert!(config.forwarding.exit_client.authorized);
        assert!(config.routes.is_empty() && config.tun.addresses.is_empty());
        assert!(config.tun.configure);
        assert_eq!(
            config.controller.unwrap().poll_interval,
            Duration::from_secs(30)
        );
        assert_eq!(config.relay.server_name, "relay.example.com");
        assert_eq!(config.relay.reconnect_min, Duration::from_secs(1));
        assert_eq!(
            config.tcp_fallback.unwrap().address,
            "127.0.0.1:443".parse().unwrap()
        );
        assert_eq!(config.direct.max_candidates, Some(8));
        let mut managed = managed;
        managed.tls.server_name.clear();
        let dynamic_relays = convert(&managed, None).unwrap();
        assert_eq!(dynamic_relays.relay.address, None);
        assert_eq!(
            dynamic_relays.forwarding.exit_client.transport_bypass,
            [IpAddr::from([127, 0, 0, 1])]
        );

        let (_directory, mut legacy) = legacy(false);
        legacy.routing.advertise = vec!["172.16.1.0/24".to_owned()];
        legacy.routing.nat = false;
        let config = convert(&legacy, None).unwrap();
        config.validate().unwrap();
        assert_eq!(config.tun.mtu, 1200);
        assert_eq!(config.tun.addresses, ["100.96.0.1/32".parse().unwrap()]);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.direct_peers.len(), 1);
        legacy.direct.enabled = Some(false);
        legacy.direct.listen = "ignored invalid listen setting".to_owned();
        let relay_only = convert(&legacy, None).unwrap();
        relay_only.validate().unwrap();
        assert!(!relay_only.direct.enabled && relay_only.direct_peers.is_empty());
        assert_eq!(relay_only.routes.len(), 1);
        assert_eq!(config.forwarding.subnet_routes[0].mode, ForwardMode::Routed);
        legacy.node.overlay_addresses = vec!["100.96.0.0/24".to_owned()];
        assert!(convert(&legacy, None).is_err());
    }

    #[test]
    fn persisted_go_exit_selection_overrides_the_configured_default() {
        let (directory, legacy) = legacy(true);
        let path = directory.path().join(EXIT_INTENT);
        fs::write(&path, br#"{"version":1,"enabled":true,"selected_node_id":"11111111111111111111111111111111","failure_mode":"open"}"#).unwrap();
        fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let intent = load_intent(&path).unwrap().unwrap();
        let config = convert(&legacy, Some(&intent)).unwrap();
        config.validate().unwrap();
        assert!(config.forwarding.exit_client.enabled);
        assert_eq!(
            config.forwarding.exit_client.failure_mode,
            ExitFailureMode::Open
        );
        fs::write(
            &path,
            br#"{"version":1,"enabled":false,"failure_mode":null}"#,
        )
        .unwrap();
        assert!(load_intent(&path).is_err());
    }

    #[test]
    fn runtime_only_selects_supported_roles_and_parses_legacy_flags() {
        let options = Options::parse(&["-config=/tmp/with space".into(), "--version=false".into()])
            .unwrap()
            .unwrap();
        assert_eq!(options.config, Path::new("/tmp/with space"));
        assert!(!options.version);
        let (_directory, mut config) = legacy(true);
        assert!(compatibility_reason(&config, &options).is_none());
        config.connector.userspace = true;
        assert_eq!(
            compatibility_reason(&config, &options),
            Some("userspace Connector packet handling")
        );
        assert!(Options::parse(&["--diagnostics".into()]).is_err());
        assert!(
            Options::parse(&["--version".into(), "-h".into()])
                .unwrap()
                .is_none()
        );
    }
}
