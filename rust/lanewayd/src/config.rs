use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use laneway_protocol::Id;
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 1 << 20;

fn default_mtu() -> u16 {
    1280
}
fn default_queue_depth() -> usize {
    256
}
fn default_tcp_queue_depth() -> usize {
    128
}
fn default_max_routes() -> u32 {
    4096
}
fn default_route_metric() -> u32 {
    100
}
fn default_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_idle_timeout() -> Duration {
    Duration::from_secs(45)
}
fn default_keepalive() -> Duration {
    Duration::from_secs(15)
}
fn default_write_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_reconnect_min() -> Duration {
    Duration::from_millis(250)
}
fn default_reconnect_max() -> Duration {
    Duration::from_secs(15)
}
fn default_quic_recovery_interval() -> Duration {
    Duration::from_secs(5)
}
fn default_probe_interval() -> Duration {
    Duration::from_millis(200)
}
fn default_probe_timeout() -> Duration {
    Duration::from_secs(3)
}
fn default_probe_attempts() -> usize {
    3
}
fn default_candidate_refresh_interval() -> Duration {
    Duration::from_secs(30)
}
fn default_shutdown_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_max_kernel_rules() -> usize {
    4096
}
fn default_nft_command() -> String {
    "nft".to_owned()
}
fn default_ip_command() -> String {
    "ip".to_owned()
}
fn default_sysctl_command() -> String {
    "sysctl".to_owned()
}
fn default_resolvectl_command() -> String {
    "resolvectl".to_owned()
}
fn default_dns_state_file() -> PathBuf {
    PathBuf::from("/run/laneway/lanewayd-rs-dns-state.json")
}
fn default_subnet_table() -> String {
    "laneway_rs_subnet".to_owned()
}
fn default_exit_table() -> String {
    "laneway_rs_exit".to_owned()
}
fn default_exit_route_table() -> u32 {
    51_820
}
fn default_exit_route_protocol() -> u8 {
    251
}
fn default_exit_rule_priority() -> u32 {
    11_000
}
fn default_controller_poll_interval() -> Duration {
    Duration::from_secs(10)
}
fn default_controller_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/laneway/lanewayd.sock")
}
fn default_exit_intent_path() -> PathBuf {
    PathBuf::from("/var/lib/laneway/exit-intent-v1.json")
}

/// Strict top-level configuration for the native Linux agent.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Must be `node`.
    pub mode: String,
    /// Protected local-management Unix socket shared with the Go CLI.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    /// Crash-safe explicit exit-selection intent journal.
    #[serde(default = "default_exit_intent_path")]
    pub exit_intent_path: PathBuf,
    /// Exact local network and node identity.
    pub identity: IdentityConfig,
    /// Certificate, private key, and trust anchor.
    pub tls: TlsConfig,
    /// Optional authoritative Go controller. When present, overlays, routes,
    /// peers, policy, capabilities, and revocations come only from its lease.
    #[serde(default)]
    pub controller: Option<ControllerConfig>,
    /// Linux TUN interface settings.
    pub tun: TunConfig,
    /// Primary relay path and reconnect policy.
    pub relay: RelayConfig,
    /// Optional stable-v1 TLS/TCP fallback carrier.
    #[serde(default)]
    pub tcp_fallback: Option<TcpFallbackConfig>,
    /// Local direct-path QUIC listener.
    #[serde(default)]
    pub direct: DirectConfig,
    /// Immutable forwarding table.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Pre-authorized direct peers, with optional static endpoints.
    #[serde(default)]
    pub direct_peers: Vec<DirectPeerConfig>,
    /// Transactionally owned subnet, exit-gateway, and exit-client kernel state.
    #[serde(default)]
    pub forwarding: ForwardingConfig,
    /// Optional loopback-only diagnostics listener.
    #[serde(default)]
    pub diagnostics: DiagnosticsConfig,
}

/// Local Prometheus diagnostics endpoint.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsConfig {
    /// Loopback TCP address. Omit to disable the HTTP endpoint.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
}

/// Strict controller authority and lease polling settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    /// HTTPS origin of the Go controller, without an API path.
    pub endpoint: String,
    /// Required reliable mTLS QUIC controller endpoint in host:port form.
    /// Authenticated snapshots use QUIC; HTTPS remains enrollment-only.
    #[serde(default)]
    pub quic_endpoint: Option<String>,
    /// TLS DNS name; it must exactly equal the endpoint host.
    pub server_name: String,
    /// Exact controller service ID pinned from its SPIFFE URI SAN.
    pub service_id: String,
    /// Normal successful polling cadence.
    #[serde(default = "default_controller_poll_interval", with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Complete HTTPS request deadline.
    #[serde(default = "default_controller_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_direct_listen() -> SocketAddr {
    "0.0.0.0:0".parse().expect("constant socket address")
}

/// Shared UDP endpoint used for direct peers and outbound relay QUIC.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConfig {
    /// Local UDP address. Port zero asks the OS for an ephemeral shared port.
    #[serde(default = "default_direct_listen")]
    pub listen: SocketAddr,
    /// Simultaneous rendezvous probe cadence.
    #[serde(default = "default_probe_interval", with = "humantime_serde")]
    pub probe_interval: Duration,
    /// Overall reachability and direct-QUIC promotion deadline.
    #[serde(default = "default_probe_timeout", with = "humantime_serde")]
    pub probe_timeout: Duration,
    /// Bounded probe rounds per relay-issued candidate.
    #[serde(default = "default_probe_attempts")]
    pub probe_attempts: usize,
    /// Periodic relay candidate publication interval for direct-path recovery.
    #[serde(
        default = "default_candidate_refresh_interval",
        with = "humantime_serde"
    )]
    pub candidate_refresh_interval: Duration,
    /// Permit loopback candidates in isolated local deployments.
    #[serde(default)]
    pub allow_loopback: bool,
    /// Permit link-local candidates in explicitly scoped deployments.
    #[serde(default)]
    pub allow_link_local: bool,
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            listen: default_direct_listen(),
            probe_interval: default_probe_interval(),
            probe_timeout: default_probe_timeout(),
            probe_attempts: default_probe_attempts(),
            candidate_refresh_interval: default_candidate_refresh_interval(),
            allow_loopback: false,
            allow_link_local: false,
        }
    }
}

/// Local certificate identity.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Lowercase 32-character network identifier.
    pub network_id: String,
    /// Lowercase 32-character node identifier.
    pub node_id: String,
}

/// PEM credential paths.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Leaf certificate chain.
    pub certificate: PathBuf,
    /// Matching private key.
    pub private_key: PathBuf,
    /// Network CA bundle.
    pub ca: PathBuf,
}

/// Linux TUN settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    /// Interface name, normally `lane0`.
    pub name: String,
    /// Interface MTU. Laneway v1 defaults to the IPv6 minimum of 1280.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Host prefixes assigned to the interface.
    #[serde(default)]
    pub addresses: Vec<IpNet>,
    /// Install interface addresses and routes with `ip(8)`.
    #[serde(default)]
    pub configure: bool,
}

/// Relay connection bounds and liveness.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Relay UDP socket address.
    #[serde(default)]
    pub address: Option<SocketAddr>,
    /// TLS DNS name for WebPKI verification.
    pub server_name: String,
    /// Exact relay service identifier from its SPIFFE certificate.
    pub service_id: String,
    /// Bounded TUN-to-carrier packet queue.
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
    /// Maximum route handles requested from the relay.
    #[serde(default = "default_max_routes")]
    pub max_routes: u32,
    /// TLS and control handshake deadline.
    #[serde(default = "default_handshake_timeout", with = "humantime_serde")]
    pub handshake_timeout: Duration,
    /// QUIC idle timeout.
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// QUIC keepalive interval.
    #[serde(default = "default_keepalive", with = "humantime_serde")]
    pub keepalive: Duration,
    /// First reconnect delay.
    #[serde(default = "default_reconnect_min", with = "humantime_serde")]
    pub reconnect_min: Duration,
    /// Maximum reconnect delay.
    #[serde(default = "default_reconnect_max", with = "humantime_serde")]
    pub reconnect_max: Duration,
    /// Retry cadence for promoting a healthy TCP session back to QUIC.
    #[serde(default = "default_quic_recovery_interval", with = "humantime_serde")]
    pub quic_recovery_interval: Duration,
}

/// Bounded stable-v1 TLS/TCP fallback carrier settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpFallbackConfig {
    /// Relay TCP fallback socket address.
    pub address: SocketAddr,
    /// TLS handshake deadline.
    #[serde(default = "default_handshake_timeout", with = "humantime_serde")]
    pub handshake_timeout: Duration,
    /// Finite deadline for each complete record write.
    #[serde(default = "default_write_timeout", with = "humantime_serde")]
    pub write_timeout: Duration,
    /// Maximum period in which the relay may send no records.
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Quiet write period after which an empty ping is sent.
    #[serde(default = "default_keepalive", with = "humantime_serde")]
    pub keepalive_period: Duration,
    /// Independent control and packet receive queue depth.
    #[serde(default = "default_tcp_queue_depth")]
    pub queue_depth: usize,
}

/// One destination prefix and its authenticated next-hop node.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Canonical destination prefix.
    pub prefix: IpNet,
    /// Exact next-hop node identifier.
    pub via_node: String,
    /// Lower values win when multiple routes have the same prefix length.
    #[serde(default = "default_route_metric")]
    pub metric: u32,
    /// Operational route class used for audit and hook decisions.
    #[serde(default)]
    pub kind: RouteKind,
}

/// Route purpose. All classes share the same native packet hot path.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// A node overlay host route.
    #[default]
    Overlay,
    /// A routed or NATed subnet behind a node.
    Subnet,
    /// A default route through an exit node.
    Exit,
}

/// One pre-authorized direct QUIC peer and optional static endpoint.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectPeerConfig {
    /// Expected certificate node ID.
    pub node_id: String,
    /// Optional static peer UDP socket address; rendezvous may supply it.
    #[serde(default)]
    pub address: Option<SocketAddr>,
    /// Deprecated TLS label retained for configuration compatibility. Direct
    /// authentication uses the CA chain and exact node SPIFFE identity.
    #[serde(default)]
    pub server_name: String,
}

/// Per-prefix private-LAN forwarding policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetForwardConfig {
    /// Exact locally reachable private prefix.
    pub prefix: IpNet,
    /// NAT is the operational default; routed mode preserves overlay sources.
    #[serde(default)]
    pub mode: ForwardMode,
    /// Native interface that reaches this prefix.
    pub output_interface: String,
}

/// Private-subnet forwarding mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardMode {
    /// Masquerade traffic toward the private subnet.
    #[default]
    Nat,
    /// Preserve overlay source addresses; the LAN must route return traffic.
    Routed,
}

/// Exit-client leak behavior when its selected path is unavailable.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitFailureMode {
    /// Invalid for an enabled exit selection.
    #[default]
    Unspecified,
    /// Remove exit policy if the selected path becomes unavailable.
    Open,
    /// Retain policy routes, failing traffic closed through the tunnel.
    Closed,
}

/// Explicit local full-tunnel selection and dedicated policy-routing bounds.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitClientConfig {
    /// Explicit local selection switch.
    #[serde(default)]
    pub enabled: bool,
    /// Explicit configuration/controller authorization switch.
    #[serde(default)]
    pub authorized: bool,
    /// Exact selected exit node; must match every exit route next hop.
    #[serde(default)]
    pub selected_node: Option<String>,
    /// Required leak behavior while enabled.
    #[serde(default)]
    pub failure_mode: ExitFailureMode,
    /// Native LAN prefixes which bypass the tunnel.
    #[serde(default)]
    pub local_lan_bypass: Vec<IpNet>,
    /// Controller/service endpoints not otherwise present in relay/direct config.
    #[serde(default)]
    pub controller_bypass: Vec<IpAddr>,
    /// Additional explicit unicast transport bypass endpoints.
    #[serde(default)]
    pub transport_bypass: Vec<IpAddr>,
    /// DNS servers owned on lane0 while the selected exit policy is active.
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    /// Dedicated non-system route table.
    #[serde(default = "default_exit_route_table")]
    pub route_table: u32,
    /// Owned route protocol marker.
    #[serde(default = "default_exit_route_protocol")]
    pub route_protocol: u8,
    /// Dedicated policy-rule priority.
    #[serde(default = "default_exit_rule_priority")]
    pub rule_priority: u32,
}

impl Default for ExitClientConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            authorized: false,
            selected_node: None,
            failure_mode: ExitFailureMode::Unspecified,
            local_lan_bypass: Vec::new(),
            controller_bypass: Vec::new(),
            transport_bypass: Vec::new(),
            dns_servers: Vec::new(),
            route_table: default_exit_route_table(),
            route_protocol: default_exit_route_protocol(),
            rule_priority: default_exit_rule_priority(),
        }
    }
}

/// Owned Linux subnet/exit forwarding and policy-routing configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardingConfig {
    /// Enables transactional private-subnet forwarding.
    #[serde(default)]
    pub subnet_router: bool,
    /// Enables source-scoped exit NAT/NAT66.
    #[serde(default)]
    pub exit_gateway: bool,
    /// Additional local LAN prefixes whose packets may be injected from or
    /// emitted to the TUN device (subnet-router and exit-client hooks).
    #[serde(default)]
    pub owned_prefixes: Vec<IpNet>,
    /// Exact private prefixes and their native interfaces/modes.
    #[serde(default)]
    pub subnet_routes: Vec<SubnetForwardConfig>,
    /// Exact overlay sources permitted to use this exit gateway.
    #[serde(default)]
    pub exit_gateway_sources: Vec<IpNet>,
    /// Native public interface for exit NAT/NAT66.
    #[serde(default)]
    pub exit_output_interface: Option<String>,
    /// Explicit local exit-client selection.
    #[serde(default)]
    pub exit_client: ExitClientConfig,
    /// Bounded nftables rules across owned tables.
    #[serde(default = "default_max_kernel_rules")]
    pub max_rules: usize,
    /// Rollback/cleanup deadline.
    #[serde(default = "default_shutdown_timeout", with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Owned subnet nftables table name.
    #[serde(default = "default_subnet_table")]
    pub subnet_table: String,
    /// Owned exit nftables table name.
    #[serde(default = "default_exit_table")]
    pub exit_table: String,
    /// Executable overrides used by disposable/test environments.
    #[serde(default = "default_nft_command")]
    pub nft_command: String,
    /// `iproute2` executable path/name.
    #[serde(default = "default_ip_command")]
    pub ip_command: String,
    /// Sysctl executable path/name.
    #[serde(default = "default_sysctl_command")]
    pub sysctl_command: String,
    /// `resolvectl` executable used for transactional per-link DNS ownership.
    #[serde(default = "default_resolvectl_command")]
    pub resolvectl_command: String,
    /// Crash-recovery journal for exact per-link DNS ownership.
    #[serde(default = "default_dns_state_file")]
    pub dns_state_file: PathBuf,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            subnet_router: false,
            exit_gateway: false,
            owned_prefixes: Vec::new(),
            subnet_routes: Vec::new(),
            exit_gateway_sources: Vec::new(),
            exit_output_interface: None,
            exit_client: ExitClientConfig::default(),
            max_rules: default_max_kernel_rules(),
            shutdown_timeout: default_shutdown_timeout(),
            subnet_table: default_subnet_table(),
            exit_table: default_exit_table(),
            nft_command: default_nft_command(),
            ip_command: default_ip_command(),
            sysctl_command: default_sysctl_command(),
            resolvectl_command: default_resolvectl_command(),
            dns_state_file: default_dns_state_file(),
        }
    }
}

impl Config {
    /// Reads a bounded TOML file and fully validates it before opening devices.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata =
            fs::metadata(path).with_context(|| format!("stat configuration {}", path.display()))?;
        ensure!(
            metadata.len() <= MAX_CONFIG_BYTES,
            "configuration exceeds {MAX_CONFIG_BYTES} bytes"
        );
        let source = fs::read_to_string(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        let config: Self = toml::from_str(&source).context("decode configuration")?;
        config.validate()?;
        Ok(config)
    }

    /// Returns validated binary network and node identifiers.
    pub fn ids(&self) -> Result<(Id, Id)> {
        Ok((
            Id::from_str(&self.identity.network_id).context("identity.network_id")?,
            Id::from_str(&self.identity.node_id).context("identity.node_id")?,
        ))
    }

    /// Validates all static bounds, identifiers, and route relationships.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.mode == "node", "mode must be \"node\"");
        ensure!(
            valid_absolute_path(&self.socket_path, 107),
            "socket_path must be an absolute bounded path"
        );
        ensure!(
            valid_absolute_path(&self.exit_intent_path, 4096),
            "exit_intent_path must be an absolute bounded path"
        );
        ensure!(
            self.socket_path != self.exit_intent_path,
            "socket_path and exit_intent_path must differ"
        );
        if let Some(listen) = self.diagnostics.listen {
            ensure!(
                listen.ip().is_loopback() && listen.port() != 0,
                "diagnostics.listen must be a nonzero loopback socket"
            );
        }
        let (network_id, node_id) = self.ids()?;
        ensure!(network_id != node_id, "network and node IDs must differ");
        ensure!(
            !self.tun.name.is_empty()
                && self.tun.name.len() < 16
                && self
                    .tun
                    .name
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || value == b'_' || value == b'-'),
            "tun.name must be a simple Linux interface name"
        );
        ensure!(
            (576..=1280).contains(&self.tun.mtu),
            "tun.mtu must be between 576 and the stable-v1 carrier limit 1280"
        );
        ensure!(
            self.controller.is_some() || !self.tun.addresses.is_empty(),
            "tun.addresses must not be empty without controller authority"
        );
        if let Some(controller) = &self.controller {
            ensure!(
                self.tun.addresses.is_empty()
                    && self.routes.is_empty()
                    && self.direct_peers.is_empty(),
                "controller authority cannot be mixed with static addresses, routes, or direct peers"
            );
            ensure!(
                !controller.endpoint.is_empty()
                    && controller.quic_endpoint.is_some()
                    && !controller.server_name.is_empty()
                    && !controller.poll_interval.is_zero()
                    && controller.poll_interval <= Duration::from_secs(300)
                    && !controller.timeout.is_zero()
                    && controller.timeout <= Duration::from_secs(300),
                "controller HTTPS enrollment origin, QUIC endpoint, server_name, and timing bounds are invalid"
            );
            if let Some(endpoint) = &controller.quic_endpoint {
                ensure!(
                    endpoint.parse::<SocketAddr>().is_ok()
                        || endpoint.rsplit_once(':').is_some_and(|(host, port)| {
                            !host.is_empty() && port.parse::<u16>().is_ok_and(|value| value != 0)
                        }),
                    "controller.quic_endpoint must be host:port"
                );
            }
            Id::from_str(&controller.service_id).context("controller.service_id")?;
        }
        let carries_ipv6 = self
            .tun
            .addresses
            .iter()
            .chain(self.routes.iter().map(|route| &route.prefix))
            .chain(self.forwarding.owned_prefixes.iter())
            .any(|prefix| matches!(prefix, IpNet::V6(_)));
        ensure!(
            !carries_ipv6 || self.tun.mtu >= 1280,
            "tun.mtu must be at least 1280 when IPv6 is configured"
        );
        for address in &self.tun.addresses {
            ensure!(
                address.trunc() == *address,
                "TUN prefix {address} is not canonical"
            );
        }
        ensure!(
            !self.relay.server_name.is_empty(),
            "relay.server_name is required"
        );
        Id::from_str(&self.relay.service_id).context("relay.service_id")?;
        ensure!(
            self.relay.address.is_some() || self.tcp_fallback.is_some(),
            "at least one relay carrier must be configured"
        );
        if let Some(address) = self.relay.address {
            ensure!(address.port() != 0, "relay.address port must be nonzero");
        }
        ensure!(
            (1..=65_536).contains(&self.relay.queue_depth),
            "relay.queue_depth must be between 1 and 65536"
        );
        ensure!(
            self.relay.max_routes > 0 && self.relay.max_routes <= 65_536,
            "relay.max_routes must be between 1 and 65536"
        );
        ensure!(
            !self.relay.handshake_timeout.is_zero()
                && !self.relay.idle_timeout.is_zero()
                && !self.relay.keepalive.is_zero()
                && self.relay.keepalive < self.relay.idle_timeout,
            "relay liveness values are invalid"
        );
        ensure!(
            !self.relay.reconnect_min.is_zero()
                && self.relay.reconnect_min <= self.relay.reconnect_max
                && self.relay.reconnect_max <= Duration::from_secs(300),
            "relay reconnect bounds are invalid"
        );
        ensure!(
            self.relay.quic_recovery_interval >= Duration::from_millis(100)
                && self.relay.quic_recovery_interval <= Duration::from_secs(300),
            "relay.quic_recovery_interval must be in [100ms,5m]"
        );
        if let Some(tcp) = &self.tcp_fallback {
            ensure!(
                tcp.address.port() != 0
                    && tcp.handshake_timeout <= Duration::from_secs(300)
                    && tcp.write_timeout <= Duration::from_secs(300)
                    && tcp.idle_timeout <= Duration::from_secs(300)
                    && tcp.keepalive_period <= Duration::from_secs(300)
                    && !tcp.handshake_timeout.is_zero()
                    && !tcp.write_timeout.is_zero()
                    && !tcp.idle_timeout.is_zero()
                    && !tcp.keepalive_period.is_zero()
                    && tcp.keepalive_period < tcp.idle_timeout,
                "tcp_fallback liveness values are invalid"
            );
            ensure!(
                (1..=4096).contains(&tcp.queue_depth),
                "tcp_fallback.queue_depth must be between 1 and 4096"
            );
        }
        ensure!(
            (1..=8).contains(&self.direct.probe_attempts)
                && !self.direct.probe_interval.is_zero()
                && self.direct.probe_interval <= Duration::from_secs(1)
                && !self.direct.probe_timeout.is_zero()
                && self.direct.probe_timeout <= Duration::from_secs(30)
                && self.direct.candidate_refresh_interval >= Duration::from_millis(100)
                && self.direct.candidate_refresh_interval <= Duration::from_secs(300),
            "direct probe bounds are invalid"
        );
        ensure!(
            self.controller.is_some() || !self.routes.is_empty(),
            "routes must not be empty without controller authority"
        );
        let mut prefixes = HashSet::new();
        let mut route_peers = HashSet::new();
        for (index, route) in self.routes.iter().enumerate() {
            ensure!(
                route.prefix.trunc() == route.prefix,
                "routes[{index}] prefix is not canonical"
            );
            ensure!(
                prefixes.insert((route.prefix, route.metric)),
                "routes[{index}] duplicates prefix {} at metric {}",
                route.prefix,
                route.metric
            );
            let peer = Id::from_str(&route.via_node)
                .with_context(|| format!("routes[{index}].via_node"))?;
            ensure!(peer != node_id, "routes[{index}] points to the local node");
            route_peers.insert(peer);
            if route.kind == RouteKind::Exit {
                ensure!(
                    route.prefix.prefix_len() == 0,
                    "exit route must be a default prefix"
                );
            } else {
                ensure!(
                    route.prefix.prefix_len() != 0,
                    "default prefixes must use kind = \"exit\""
                );
            }
        }
        let mut direct = HashSet::new();
        for (index, peer) in self.direct_peers.iter().enumerate() {
            let id = Id::from_str(&peer.node_id)
                .with_context(|| format!("direct_peers[{index}].node_id"))?;
            ensure!(id != node_id, "direct peer cannot be the local node");
            ensure!(
                route_peers.contains(&id),
                "direct_peers[{index}] has no route"
            );
            ensure!(direct.insert(id), "duplicate direct peer {id}");
        }
        for prefix in &self.forwarding.owned_prefixes {
            ensure!(
                prefix.trunc() == *prefix,
                "forwarding owned prefix {prefix} is not canonical"
            );
        }
        let forwarding = &self.forwarding;
        ensure!(
            (1..=16_384).contains(&forwarding.max_rules)
                && !forwarding.shutdown_timeout.is_zero()
                && forwarding.shutdown_timeout <= Duration::from_secs(60),
            "forwarding resource bounds are invalid"
        );
        ensure!(
            safe_nft_name(&forwarding.subnet_table)
                && safe_nft_name(&forwarding.exit_table)
                && forwarding.subnet_table != forwarding.exit_table,
            "forwarding nftables table names are invalid or duplicate"
        );
        for (label, command) in [
            ("nft_command", &forwarding.nft_command),
            ("ip_command", &forwarding.ip_command),
            ("sysctl_command", &forwarding.sysctl_command),
            ("resolvectl_command", &forwarding.resolvectl_command),
        ] {
            ensure!(
                !command.is_empty() && command.len() <= 4096,
                "forwarding.{label} is invalid"
            );
        }
        let owned: HashSet<_> = forwarding.owned_prefixes.iter().copied().collect();
        let mut subnet_prefixes = HashSet::new();
        for (index, route) in forwarding.subnet_routes.iter().enumerate() {
            ensure!(
                route.prefix.trunc() == route.prefix && route.prefix.prefix_len() != 0,
                "forwarding.subnet_routes[{index}] prefix is invalid"
            );
            ensure!(
                subnet_prefixes.insert(route.prefix),
                "forwarding.subnet_routes[{index}] duplicates a prefix"
            );
            ensure!(
                owned.contains(&route.prefix),
                "forwarding.subnet_routes[{index}] is not in owned_prefixes"
            );
            ensure!(
                safe_interface(&route.output_interface) && route.output_interface != self.tun.name,
                "forwarding.subnet_routes[{index}] output interface is invalid"
            );
        }
        if forwarding.subnet_router {
            ensure!(
                !forwarding.subnet_routes.is_empty(),
                "subnet_router requires forwarding.subnet_routes"
            );
        }
        let mut exit_sources = HashSet::new();
        for (index, prefix) in forwarding.exit_gateway_sources.iter().enumerate() {
            ensure!(
                prefix.trunc() == *prefix && prefix.prefix_len() != 0,
                "forwarding.exit_gateway_sources[{index}] is invalid"
            );
            ensure!(
                exit_sources.insert(*prefix),
                "forwarding.exit_gateway_sources[{index}] is duplicate"
            );
        }
        if forwarding.exit_gateway {
            ensure!(
                !forwarding.exit_gateway_sources.is_empty(),
                "exit_gateway requires forwarding.exit_gateway_sources"
            );
            let interface = forwarding
                .exit_output_interface
                .as_deref()
                .context("exit_gateway requires forwarding.exit_output_interface")?;
            ensure!(
                safe_interface(interface) && interface != self.tun.name,
                "forwarding.exit_output_interface is invalid"
            );
        }
        let exit = &forwarding.exit_client;
        let exit_routes: Vec<_> = self
            .routes
            .iter()
            .filter(|route| route.kind == RouteKind::Exit)
            .collect();
        if exit.enabled {
            ensure!(
                exit.authorized,
                "exit client is not configuration-authorized"
            );
            ensure!(
                matches!(
                    exit.failure_mode,
                    ExitFailureMode::Open | ExitFailureMode::Closed
                ),
                "enabled exit client requires an explicit failure_mode"
            );
            let selected = Id::from_str(
                exit.selected_node
                    .as_deref()
                    .context("enabled exit client requires selected_node")?,
            )
            .context("forwarding.exit_client.selected_node")?;
            ensure!(
                self.controller.is_some() || !exit_routes.is_empty(),
                "enabled exit client has no exit route"
            );
            for route in &exit_routes {
                ensure!(
                    Id::from_str(&route.via_node)? == selected,
                    "exit route does not use the explicitly selected node"
                );
            }
            ensure!(
                exit.route_table > 0
                    && !matches!(exit.route_table, 253..=255)
                    && exit.route_protocol > 0
                    && (1..=32_765).contains(&exit.rule_priority),
                "exit client policy-routing identifiers are invalid"
            );
            for (index, prefix) in exit.local_lan_bypass.iter().enumerate() {
                ensure!(
                    prefix.trunc() == *prefix && prefix.prefix_len() != 0,
                    "exit_client.local_lan_bypass[{index}] is invalid"
                );
            }
            for (index, address) in exit
                .controller_bypass
                .iter()
                .chain(exit.transport_bypass.iter())
                .enumerate()
            {
                ensure!(
                    valid_unicast(*address),
                    "exit client bypass address {index} is invalid"
                );
            }
            let mut dns_servers = HashSet::new();
            for (index, address) in exit.dns_servers.iter().enumerate() {
                ensure!(
                    valid_unicast(*address) && dns_servers.insert(*address),
                    "exit_client.dns_servers[{index}] is invalid or duplicated"
                );
            }
            if !exit.dns_servers.is_empty() {
                ensure!(
                    self.forwarding.dns_state_file.is_absolute(),
                    "forwarding.dns_state_file must be absolute when exit DNS is enabled"
                );
            }
        } else {
            ensure!(
                exit_routes.is_empty(),
                "exit routes require explicit forwarding.exit_client.enabled"
            );
        }
        let subnet_rules = forwarding.subnet_routes.len().saturating_mul(3);
        let exit_rules = forwarding.exit_gateway_sources.len().saturating_mul(3);
        ensure!(
            subnet_rules.saturating_add(exit_rules) <= forwarding.max_rules,
            "forwarding rules exceed max_rules"
        );
        Ok(())
    }

    /// Complete native transport bypass set for explicit exit policy routing.
    pub fn exit_transport_bypass(&self) -> Vec<IpAddr> {
        let mut values = Vec::new();
        if let Some(address) = self.relay.address {
            values.push(address.ip());
        }
        if let Some(fallback) = &self.tcp_fallback {
            values.push(fallback.address.ip());
        }
        values.extend(
            self.direct_peers
                .iter()
                .filter_map(|peer| peer.address.map(|v| v.ip())),
        );
        values.extend(
            self.forwarding
                .exit_client
                .controller_bypass
                .iter()
                .copied(),
        );
        values.extend(self.forwarding.exit_client.transport_bypass.iter().copied());
        values.sort_unstable();
        values.dedup();
        values
    }
}

fn safe_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn safe_nft_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_absolute_path(value: &Path, maximum: usize) -> bool {
    value.is_absolute()
        && value.as_os_str().as_encoded_bytes().len() <= maximum
        && !value.as_os_str().as_encoded_bytes().contains(&0)
}

fn valid_unicast(value: IpAddr) -> bool {
    if value.is_unspecified() || value.is_multicast() {
        return false;
    }
    match value {
        IpAddr::V4(value) => !value.is_broadcast(),
        IpAddr::V6(value) => value.to_ipv4_mapped().is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
mode = "node"
[identity]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
[tls]
certificate = "node.crt"
private_key = "node.key"
ca = "ca.crt"
[tun]
name = "lane0"
addresses = ["100.96.0.1/32"]
[relay]
address = "127.0.0.1:4433"
server_name = "relay.test"
service_id = "303132333435363738393a3b3c3d3e3f"
[tcp_fallback]
address = "127.0.0.1:443"
[[routes]]
prefix = "100.96.0.2/32"
via_node = "202122232425262728292a2b2c2d2e2f"
"#;

    #[test]
    fn strict_config_validates() {
        let config: Config = toml::from_str(VALID).unwrap();
        config.validate().unwrap();
        assert_eq!(config.relay.queue_depth, 256);
        assert_eq!(
            config.socket_path,
            PathBuf::from("/run/laneway/lanewayd.sock")
        );
        assert_eq!(
            config.exit_intent_path,
            PathBuf::from("/var/lib/laneway/exit-intent-v1.json")
        );
        assert_eq!(config.relay.quic_recovery_interval, Duration::from_secs(5));
        assert_eq!(
            config.direct.candidate_refresh_interval,
            Duration::from_secs(30)
        );
        assert_eq!(config.tcp_fallback.unwrap().queue_depth, 128);
    }

    #[test]
    fn local_management_paths_are_absolute_and_bounded() {
        let mut config: Config = toml::from_str(VALID).unwrap();
        config.socket_path = "relative.sock".into();
        assert!(config.validate().is_err());
        config.socket_path = PathBuf::from(format!("/{}", "x".repeat(108)));
        assert!(config.validate().is_err());
        config.socket_path = "/run/laneway/lanewayd.sock".into();
        config.exit_intent_path = "relative.json".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn controller_mode_requires_controller_only_authority_inputs() {
        let source = VALID
            .replace("addresses = [\"100.96.0.1/32\"]\n", "")
            .replace(
                "[[routes]]\nprefix = \"100.96.0.2/32\"\nvia_node = \"202122232425262728292a2b2c2d2e2f\"\n",
                "",
            );
        let source = format!(
            "{source}\n[controller]\nendpoint = \"https://controller.test:8443\"\nquic_endpoint = \"controller.test:8443\"\nserver_name = \"controller.test\"\nservice_id = \"404142434445464748494a4b4c4d4e4f\"\npoll_interval = \"2s\"\ntimeout = \"3s\"\n"
        );
        let config: Config = toml::from_str(&source).unwrap();
        config.validate().unwrap();
        let mut without_quic = config.clone();
        without_quic.controller.as_mut().unwrap().quic_endpoint = None;
        assert!(without_quic.validate().is_err());
        let mut mixed = config.clone();
        mixed.tun.addresses.push("100.96.0.1/32".parse().unwrap());
        assert!(mixed.validate().is_err());
    }

    #[test]
    fn rejects_unknown_duplicate_and_noncanonical_values() {
        assert!(
            toml::from_str::<Config>(&VALID.replace("[identity]", "unknown = 1\n[identity]"))
                .is_err()
        );
        let duplicate = format!(
            "{VALID}\n[[routes]]\nprefix = \"100.96.0.2/32\"\nvia_node = \"303132333435363738393a3b3c3d3e3f\"\n"
        );
        assert!(
            toml::from_str::<Config>(&duplicate)
                .unwrap()
                .validate()
                .is_err()
        );
        let noncanonical = VALID.replace("100.96.0.2/32", "100.96.0.2/24");
        assert!(
            toml::from_str::<Config>(&noncanonical)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn allows_same_prefix_at_distinct_metrics_only() {
        let distinct = format!(
            "{VALID}\n[[routes]]\nprefix = \"100.96.0.2/32\"\nvia_node = \"303132333435363738393a3b3c3d3e3f\"\nmetric = 200\n"
        );
        toml::from_str::<Config>(&distinct)
            .unwrap()
            .validate()
            .unwrap();
        let equal = distinct.replace("metric = 200", "metric = 100");
        assert!(
            toml::from_str::<Config>(&equal)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn ipv6_requires_protocol_minimum_mtu() {
        let source = VALID
            .replace(
                "addresses = [\"100.96.0.1/32\"]",
                "mtu = 1200\naddresses = [\"fd00::1/128\"]",
            )
            .replace("100.96.0.2/32", "fd00::2/128");
        let config: Config = toml::from_str(&source).unwrap();
        assert!(config.validate().is_err());

        let config: Config = toml::from_str(&source.replace("mtu = 1200", "mtu = 1280")).unwrap();
        config.validate().unwrap();

        let oversized: Config =
            toml::from_str(&VALID.replace("name = \"lane0\"", "name = \"lane0\"\nmtu = 1281"))
                .unwrap();
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn rejects_unbounded_carrier_recovery_and_candidate_refresh() {
        let recovery = VALID.replace("[relay]", "[relay]\nquic_recovery_interval = \"99ms\"");
        assert!(
            toml::from_str::<Config>(&recovery)
                .unwrap()
                .validate()
                .is_err()
        );
        let refresh = VALID.replace(
            "[[routes]]",
            "[direct]\ncandidate_refresh_interval = \"301s\"\n[[routes]]",
        );
        assert!(
            toml::from_str::<Config>(&refresh)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn deployment_example_decodes_and_validates() {
        let config: Config =
            toml::from_str(include_str!("../../../deploy/examples/node-rust.toml")).unwrap();
        config.validate().unwrap();
        let controller: Config = toml::from_str(include_str!(
            "../../../deploy/examples/node-rust-controller.toml"
        ))
        .unwrap();
        controller.validate().unwrap();
    }

    #[test]
    fn exit_requires_explicit_authorized_selection() {
        let source = VALID.replace(
            "[[routes]]\nprefix = \"100.96.0.2/32\"",
            "[forwarding.exit_client]\nenabled = true\nauthorized = true\nselected_node = \"202122232425262728292a2b2c2d2e2f\"\nfailure_mode = \"closed\"\n\n[[routes]]\nprefix = \"0.0.0.0/0\"\nkind = \"exit\"",
        );
        let config: Config = toml::from_str(&source).unwrap();
        config.validate().unwrap();

        let unauthorized = source.replace("authorized = true", "authorized = false");
        assert!(
            toml::from_str::<Config>(&unauthorized)
                .unwrap()
                .validate()
                .is_err()
        );
        let wrong = source.replace(
            "selected_node = \"202122232425262728292a2b2c2d2e2f\"",
            "selected_node = \"303132333435363738393a3b3c3d3e3f\"",
        );
        assert!(
            toml::from_str::<Config>(&wrong)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn exit_dns_and_diagnostics_are_strict() {
        let source = VALID.replace(
            "[[routes]]\nprefix = \"100.96.0.2/32\"",
            "[forwarding.exit_client]\nenabled = true\nauthorized = true\nselected_node = \"202122232425262728292a2b2c2d2e2f\"\nfailure_mode = \"closed\"\ndns_servers = [\"1.1.1.1\"]\n\n[[routes]]\nprefix = \"0.0.0.0/0\"\nkind = \"exit\"",
        );
        let mut config: Config = toml::from_str(&source).unwrap();
        config.diagnostics.listen = Some("127.0.0.1:6062".parse().unwrap());
        config.validate().unwrap();

        config
            .forwarding
            .exit_client
            .dns_servers
            .push("1.1.1.1".parse().unwrap());
        assert!(config.validate().is_err());
        config.forwarding.exit_client.dns_servers.pop();
        config.forwarding.dns_state_file = "relative.json".into();
        assert!(config.validate().is_err());
        config.forwarding.dns_state_file = "/run/laneway/dns.json".into();
        config.diagnostics.listen = Some("0.0.0.0:6062".parse().unwrap());
        assert!(config.validate().is_err());
    }

    #[test]
    fn subnet_and_exit_gateway_require_exact_scopes() {
        let source = format!(
            "{VALID}\n[forwarding]\nsubnet_router = true\nexit_gateway = true\nowned_prefixes = [\"192.168.50.0/24\"]\nexit_gateway_sources = [\"100.96.0.0/24\"]\nexit_output_interface = \"eth0\"\n\n[[forwarding.subnet_routes]]\nprefix = \"192.168.50.0/24\"\nmode = \"nat\"\noutput_interface = \"lan0\"\n"
        );
        toml::from_str::<Config>(&source)
            .unwrap()
            .validate()
            .unwrap();
        let missing = source.replace(
            "owned_prefixes = [\"192.168.50.0/24\"]",
            "owned_prefixes = []",
        );
        assert!(
            toml::from_str::<Config>(&missing)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
