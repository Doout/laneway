use crate::GoDuration;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: String,
    pub state_dir: String,
    pub socket_path: String,
    pub tls: Tls,
    pub node: Node,
    pub relay: Relay,
    pub controller: Controller,
    pub bootstrap: Bootstrap,
    pub public_https: PublicHttps,
    pub routing: Routing,
    pub connector: Connector,
    pub exit: Exit,
    pub tcp_fallback: TcpFallback,
    pub direct: Direct,
    pub wireguard: WireGuard,
    pub peers: Vec<AuthorizedPeer>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Default::default(),
            state_dir: "/var/lib/laneway".into(),
            socket_path: "/run/laneway/lanewayd.sock".into(),
            tls: Default::default(),
            node: Default::default(),
            relay: Default::default(),
            controller: Default::default(),
            bootstrap: Default::default(),
            public_https: Default::default(),
            routing: Default::default(),
            connector: Default::default(),
            exit: Default::default(),
            tcp_fallback: Default::default(),
            direct: Default::default(),
            wireguard: Default::default(),
            peers: Default::default(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Tls {
    pub certificate: String,
    pub private_key: String,
    pub ca: String,
    pub server_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Node {
    pub name: String,
    pub relay_address: String,
    pub relay_network_id: String,
    pub relay_service_id: String,
    pub overlay_addresses: Vec<String>,
    pub reconnect_min: GoDuration,
    pub reconnect_max: GoDuration,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            name: Default::default(),
            relay_address: Default::default(),
            relay_network_id: Default::default(),
            relay_service_id: Default::default(),
            overlay_addresses: Default::default(),
            reconnect_min: GoDuration(1000000000),
            reconnect_max: GoDuration(30000000000),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Relay {
    pub listen: String,
    pub queue_depth: i64,
    pub packet_rate_bits_per_second: u64,
    pub packet_burst_bytes: i64,
    pub handshake_timeout: GoDuration,
    pub idle_timeout: GoDuration,
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            listen: ":4433".into(),
            queue_depth: 256,
            packet_rate_bits_per_second: Default::default(),
            packet_burst_bytes: Default::default(),
            handshake_timeout: GoDuration(10000000000),
            idle_timeout: GoDuration(45000000000),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TcpFallback {
    pub address: String,
    pub listen: String,
    pub handshake_timeout: GoDuration,
    pub write_timeout: GoDuration,
    pub idle_timeout: GoDuration,
    pub keepalive_period: GoDuration,
    pub quic_probe_interval: GoDuration,
    pub queue_depth: i64,
}

impl Default for TcpFallback {
    fn default() -> Self {
        Self {
            address: Default::default(),
            listen: Default::default(),
            handshake_timeout: GoDuration(10000000000),
            write_timeout: GoDuration(10000000000),
            idle_timeout: GoDuration(30000000000),
            keepalive_period: GoDuration(5000000000),
            quic_probe_interval: GoDuration(15000000000),
            queue_depth: 128,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Direct {
    pub enabled: Option<bool>,
    pub listen: String,
    pub candidate_ttl: GoDuration,
    pub probe_interval: GoDuration,
    pub probe_timeout: GoDuration,
    pub rendezvous_interval: GoDuration,
    pub max_candidates: i64,
    pub allow_loopback: bool,
    pub allow_link_local: bool,
}

impl Default for Direct {
    fn default() -> Self {
        Self {
            enabled: Default::default(),
            listen: ":0".into(),
            candidate_ttl: GoDuration(120000000000),
            probe_interval: GoDuration(200000000),
            probe_timeout: GoDuration(3000000000),
            rendezvous_interval: GoDuration(30000000000),
            max_candidates: 8,
            allow_loopback: Default::default(),
            allow_link_local: Default::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WireGuard {
    pub enabled: bool,
    pub private_key: String,
    pub interface: String,
    pub listen_port: u16,
    pub mtu: i64,
}

impl Default for WireGuard {
    fn default() -> Self {
        Self {
            enabled: Default::default(),
            private_key: Default::default(),
            interface: "lane0".into(),
            listen_port: Default::default(),
            mtu: 1280,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Controller {
    pub listen: String,
    pub quic_listen: String,
    pub endpoint: String,
    pub quic_endpoint: String,
    pub server_name: String,
    pub network_id: String,
    pub service_id: String,
    pub database: String,
    pub ca_private_key: String,
    pub initial_network: ControllerInitialNetwork,
    pub issuer_certificate: String,
    pub admin_token_file: String,
    pub leaf_validity: GoDuration,
    pub poll_interval: GoDuration,
}

impl Default for Controller {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".into(),
            quic_listen: Default::default(),
            endpoint: Default::default(),
            quic_endpoint: Default::default(),
            server_name: Default::default(),
            network_id: Default::default(),
            service_id: Default::default(),
            database: Default::default(),
            ca_private_key: Default::default(),
            initial_network: Default::default(),
            issuer_certificate: Default::default(),
            admin_token_file: Default::default(),
            leaf_validity: GoDuration(2592000000000000),
            poll_interval: GoDuration(30000000000),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ControllerInitialNetwork {
    pub network_id: String,
    pub name: String,
    pub ipv4_pool: String,
    pub ipv6_pool: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Bootstrap {
    pub listen: String,
    pub certificate: String,
    pub private_key: String,
    pub network_id: String,
    pub controller_endpoint: String,
    pub controller_quic_endpoint: String,
    pub controller_server_name: String,
    pub artifacts: Vec<BootstrapArtifact>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PublicHttps {
    pub server_name: String,
    pub cache_dir: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct BootstrapArtifact {
    pub os: String,
    pub arch: String,
    pub url: String,
    pub sha256: String,
    pub size_bytes: i64,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    pub advertise: Vec<String>,
    pub nat: bool,
    pub output_interface: String,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            advertise: Default::default(),
            nat: true,
            output_interface: Default::default(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Connector {
    pub userspace: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Exit {
    pub enabled: bool,
    pub serve: bool,
    pub selected_node_id: String,
    pub failure_mode: String,
    pub dns_servers: Vec<String>,
    pub local_lan_bypasses: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorizedPeer {
    pub network_id: String,
    pub node_id: String,
    pub name: String,
    pub prefixes: Vec<String>,
}
