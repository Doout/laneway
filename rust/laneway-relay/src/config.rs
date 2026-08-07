use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use laneway_protocol::{AuthenticatedIdentity, Id, Role};
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 1 << 20;

fn default_queue_depth() -> usize {
    256
}
fn default_tcp_queue_depth() -> usize {
    128
}
fn default_max_sessions() -> usize {
    4096
}
fn default_max_routes() -> u32 {
    4096
}
fn default_handshake_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_idle_timeout() -> Duration {
    Duration::from_secs(45)
}
fn default_write_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_keepalive_period() -> Duration {
    Duration::from_secs(15)
}
fn default_metrics_interval() -> Duration {
    Duration::from_secs(30)
}
fn default_candidate_republish_floor() -> Duration {
    Duration::from_secs(5)
}

/// Top-level Rust relay configuration compatible with the Go relay's static
/// and controller-backed stable-v1 operating modes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    mode: String,
    #[serde(default)]
    state_dir: Option<PathBuf>,
    #[serde(default)]
    socket_path: Option<PathBuf>,
    /// TLS credentials and trust anchor.
    pub tls: TlsConfig,
    /// QUIC relay bounds and liveness settings.
    pub relay: RelayConfig,
    /// Optional TLS/TCP fallback listener and bounded-resource settings.
    #[serde(default)]
    pub tcp_fallback: Option<TcpFallbackConfig>,
    #[serde(default)]
    pub(crate) controller: Option<ControllerConfig>,
    /// Statically authorized node identities and owned prefixes.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

/// TLS credential paths.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Relay certificate chain in PEM form.
    #[serde(rename = "certificate")]
    pub certificate_file: PathBuf,
    /// Relay private key in PEM form.
    #[serde(rename = "private_key")]
    pub private_key_file: PathBuf,
    /// Network CA certificate bundle in PEM form.
    #[serde(rename = "ca")]
    pub ca_file: PathBuf,
    #[serde(default)]
    server_name: String,
}

/// QUIC listener and bounded-resource settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// UDP address. Go-style `:4433` is accepted as `0.0.0.0:4433`.
    pub listen: String,
    /// Per-session outbound packet queue depth.
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,
    /// Aggregate packet-data rate shared by QUIC and TCP fallback, in bits/s.
    #[serde(default)]
    pub packet_rate_bits_per_second: u64,
    /// Maximum token-bucket burst in framed packet bytes.
    #[serde(default)]
    pub packet_burst_bytes: usize,
    /// Maximum authenticated concurrent sessions.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    /// Maximum directional route handles requested by a session.
    #[serde(default = "default_max_routes")]
    pub max_routes: u32,
    /// TLS, QUIC, control-preface, and registration deadline.
    #[serde(default = "default_handshake_timeout", with = "humantime_serde")]
    pub handshake_timeout: Duration,
    /// QUIC maximum idle timeout.
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Interval for structured metric snapshots; zero disables periodic logs.
    #[serde(default = "default_metrics_interval", with = "humantime_serde")]
    pub metrics_interval: Duration,
    /// Optional loopback-only Prometheus HTTP listener. Empty disables HTTP diagnostics.
    #[serde(default)]
    pub metrics_listen: String,
    /// Minimum interval between direct candidate publications per session.
    #[serde(
        default = "default_candidate_republish_floor",
        with = "humantime_serde"
    )]
    pub candidate_republish_floor: Duration,
}

/// Stable-v1 TLS/TCP fallback listener and bounded-resource settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpFallbackConfig {
    /// TCP address. Go-style `:443` is accepted as `0.0.0.0:443`.
    #[serde(default)]
    pub listen: String,
    /// TLS, control-preface, and registration deadline.
    #[serde(default = "default_handshake_timeout", with = "humantime_serde")]
    pub handshake_timeout: Duration,
    /// Finite deadline applied to every complete fallback record write.
    #[serde(default = "default_write_timeout", with = "humantime_serde")]
    pub write_timeout: Duration,
    /// Maximum interval in which the peer may send no records.
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Quiet write period after which an empty ping is sent.
    #[serde(default = "default_keepalive_period", with = "humantime_serde")]
    pub keepalive_period: Duration,
    /// Independent control and packet receive queue depth.
    #[serde(default = "default_tcp_queue_depth")]
    pub queue_depth: usize,
}

/// One static mTLS identity authorization.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Exact 128-bit network identifier in lowercase hex.
    pub network_id: String,
    /// Exact 128-bit node identifier in lowercase hex.
    pub node_id: String,
    /// Canonical source and destination prefixes owned by the node.
    pub prefixes: Vec<IpNet>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControllerConfig {
    pub(crate) endpoint: String,
    #[serde(default)]
    pub(crate) quic_endpoint: Option<String>,
    #[serde(default)]
    pub(crate) allow_legacy_https: bool,
    pub(crate) network_id: String,
    pub(crate) service_id: String,
    #[serde(default)]
    pub(crate) server_name: String,
    #[serde(default = "default_controller_poll", with = "humantime_serde")]
    pub(crate) poll_interval: Duration,
    #[serde(default = "default_controller_timeout", with = "humantime_serde")]
    pub(crate) timeout: Duration,
}

fn default_controller_poll() -> Duration {
    Duration::from_secs(30)
}

fn default_controller_timeout() -> Duration {
    Duration::from_secs(15)
}

/// Fully validated static authorization attached to one certificate identity.
#[derive(Clone, Debug)]
pub(crate) struct Authorization {
    pub(crate) prefixes: Vec<IpNet>,
    pub(crate) overlay_addresses: Vec<IpAddr>,
}

impl Config {
    /// Reads at most one MiB and validates all relay settings before opening a socket.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = fs::File::open(path)
            .with_context(|| format!("open configuration {}", path.display()))?;
        let mut source = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut source)
            .with_context(|| format!("read configuration {}", path.display()))?;
        ensure!(
            source.len() as u64 <= MAX_CONFIG_BYTES,
            "configuration exceeds {MAX_CONFIG_BYTES} bytes"
        );
        let config: Self = toml::from_str(&source).context("decode configuration")?;
        config.validate()?;
        Ok(config)
    }

    /// Returns the normalized UDP listen address.
    pub fn listen_addr(&self) -> Result<SocketAddr> {
        let value = if self.relay.listen.starts_with(':') {
            format!("0.0.0.0{}", self.relay.listen)
        } else {
            self.relay.listen.clone()
        };
        value
            .parse()
            .with_context(|| format!("invalid relay.listen {:?}", self.relay.listen))
    }

    /// Returns the normalized optional TCP fallback listen address.
    pub fn tcp_fallback_addr(&self) -> Result<Option<SocketAddr>> {
        let Some(tcp) = &self.tcp_fallback else {
            return Ok(None);
        };
        if tcp.listen.is_empty() {
            return Ok(None);
        }
        let value = if tcp.listen.starts_with(':') {
            format!("0.0.0.0{}", tcp.listen)
        } else {
            tcp.listen.clone()
        };
        value
            .parse()
            .with_context(|| format!("invalid tcp_fallback.listen {:?}", tcp.listen))
            .map(Some)
    }

    /// Returns the optional loopback-only Prometheus diagnostics address.
    pub fn metrics_listen_addr(&self) -> Result<Option<SocketAddr>> {
        if self.relay.metrics_listen.is_empty() {
            return Ok(None);
        }
        let address: SocketAddr = self.relay.metrics_listen.parse().with_context(|| {
            format!(
                "invalid relay.metrics_listen {:?}",
                self.relay.metrics_listen
            )
        })?;
        ensure!(
            address.ip().is_loopback(),
            "relay.metrics_listen must use a loopback IP address"
        );
        Ok(Some(address))
    }

    pub(crate) fn authorizations(&self) -> Result<HashMap<AuthenticatedIdentity, Authorization>> {
        let mut result = HashMap::with_capacity(self.peers.len());
        for (index, peer) in self.peers.iter().enumerate() {
            let network_id = Id::from_str(&peer.network_id)
                .with_context(|| format!("peers[{index}].network_id"))?;
            let node_id =
                Id::from_str(&peer.node_id).with_context(|| format!("peers[{index}].node_id"))?;
            let identity = AuthenticatedIdentity {
                network_id,
                role: Role::Node,
                subject_id: node_id,
            };
            let mut overlay_addresses = Vec::new();
            for prefix in &peer.prefixes {
                ensure!(
                    prefix.trunc() == *prefix,
                    "peers[{index}] prefix {prefix} is not canonical"
                );
                if prefix.prefix_len() == prefix.max_prefix_len() {
                    overlay_addresses.push(prefix.addr());
                }
            }
            ensure!(
                !overlay_addresses.is_empty(),
                "peers[{index}] has no overlay host prefix"
            );
            if result
                .insert(
                    identity,
                    Authorization {
                        prefixes: peer.prefixes.clone(),
                        overlay_addresses,
                    },
                )
                .is_some()
            {
                bail!("peers[{index}] duplicates an authenticated identity");
            }
        }
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.mode == "relay", "mode must be \"relay\"");
        ensure!(!self.relay.listen.is_empty(), "relay.listen is required");
        self.listen_addr()?;
        self.metrics_listen_addr()?;
        ensure!(
            (1..=65_536).contains(&self.relay.queue_depth),
            "relay.queue_depth must be between 1 and 65536"
        );
        ensure!(
            (self.relay.packet_rate_bits_per_second == 0) == (self.relay.packet_burst_bytes == 0)
                && self.relay.packet_rate_bits_per_second <= 1_000_000_000_000
                && self.relay.packet_burst_bytes <= 64 << 20
                && (self.relay.packet_burst_bytes == 0 || self.relay.packet_burst_bytes >= 1_285),
            "relay packet limiter requires rate and burst together, rate <= 1Tbps, and burst from 1285 bytes through 64MiB"
        );
        ensure!(
            (1..=65_536).contains(&self.relay.max_sessions),
            "relay.max_sessions must be between 1 and 65536"
        );
        ensure!(
            self.relay.max_routes > 0 && self.relay.max_routes <= 65_536,
            "relay.max_routes must be between 1 and 65536"
        );
        ensure!(
            !self.relay.handshake_timeout.is_zero() && !self.relay.idle_timeout.is_zero(),
            "relay timeout values must be positive"
        );
        ensure!(
            self.relay.candidate_republish_floor >= Duration::from_millis(100)
                && self.relay.candidate_republish_floor <= Duration::from_secs(300),
            "relay.candidate_republish_floor must be in [100ms,5m]"
        );
        let controller_enabled = self
            .controller
            .as_ref()
            .is_some_and(|controller| !controller.endpoint.is_empty());
        ensure!(
            controller_enabled || !self.peers.is_empty(),
            "static peers or a controller endpoint are required"
        );
        if let Some(controller) = self
            .controller
            .as_ref()
            .filter(|value| !value.endpoint.is_empty())
        {
            ensure!(
                controller.endpoint.starts_with("https://"),
                "controller.endpoint must use https"
            );
            ensure!(
                controller.quic_endpoint.is_some() || controller.allow_legacy_https,
                "controller.quic_endpoint is required unless legacy HTTPS is explicitly enabled"
            );
            Id::from_str(&controller.network_id).context("controller.network_id")?;
            Id::from_str(&controller.service_id).context("controller.service_id")?;
            ensure!(
                !controller.poll_interval.is_zero()
                    && controller.poll_interval <= Duration::from_secs(300),
                "controller.poll_interval must be in (0,5m]"
            );
            ensure!(
                !controller.timeout.is_zero() && controller.timeout <= Duration::from_secs(300),
                "controller.timeout must be in (0,5m]"
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
        }
        self.tcp_fallback_addr()?;
        if let Some(tcp) = &self.tcp_fallback {
            ensure!(
                !tcp.handshake_timeout.is_zero()
                    && !tcp.write_timeout.is_zero()
                    && !tcp.idle_timeout.is_zero()
                    && !tcp.keepalive_period.is_zero()
                    && tcp.keepalive_period < tcp.idle_timeout,
                "tcp_fallback timeouts must be positive and keepalive_period shorter than idle_timeout"
            );
            ensure!(
                (1..=4096).contains(&tcp.queue_depth),
                "tcp_fallback.queue_depth must be between 1 and 4096"
            );
        }
        let _ = (&self.state_dir, &self.socket_path);
        let _ = (
            &self.tls.server_name,
            self.controller.as_ref().map(|c| &c.server_name),
        );
        self.authorizations()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_controller_example_decodes_and_validates() {
        let config: Config = toml::from_str(include_str!(
            "../../../deploy/examples/relay-controller.toml"
        ))
        .expect("decode controller-backed deployment example");
        config
            .validate()
            .expect("validate controller-backed deployment example");
        let mut without_quic = config.clone();
        without_quic.controller.as_mut().unwrap().quic_endpoint = None;
        assert!(without_quic.validate().is_err());
        let controller = config.controller.expect("controller configuration");
        assert_eq!(controller.network_id, "000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn normalizes_go_style_listen_and_builds_authorization() {
        let config: Config = toml::from_str(
            r#"
mode = "relay"
[tls]
certificate = "relay.crt"
private_key = "relay.key"
ca = "ca.crt"
[relay]
listen = ":4433"
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/32", "10.0.0.0/24"]
"#,
        )
        .expect("decode");
        config.validate().expect("validate");
        assert_eq!(
            config.relay.candidate_republish_floor,
            Duration::from_secs(5)
        );
        assert_eq!(
            config.listen_addr().unwrap(),
            "0.0.0.0:4433".parse().unwrap()
        );
        let auth = config.authorizations().unwrap();
        let value = auth.values().next().unwrap();
        assert_eq!(
            value.overlay_addresses,
            ["100.96.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn rejects_noncanonical_and_duplicate_peers() {
        let source = r#"
mode = "relay"
[tls]
certificate = "relay.crt"
private_key = "relay.key"
ca = "ca.crt"
[relay]
listen = "127.0.0.1:4433"
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/24"]
"#;
        let config: Config = toml::from_str(source).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_incomplete_or_undersized_packet_limiter() {
        let template = |settings: &str| {
            format!(
                r#"
mode = "relay"
[tls]
certificate = "relay.crt"
private_key = "relay.key"
ca = "ca.crt"
[relay]
listen = "127.0.0.1:4433"
{settings}
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/32"]
"#
            )
        };
        for settings in [
            "packet_rate_bits_per_second = 1000",
            "packet_burst_bytes = 1285",
            "packet_rate_bits_per_second = 1000\npacket_burst_bytes = 1284",
        ] {
            let config: Config = toml::from_str(&template(settings)).unwrap();
            assert!(config.validate().is_err(), "accepted {settings}");
        }
    }

    #[test]
    fn rejects_candidate_republish_floor_outside_bounds() {
        let source = r#"
mode = "relay"
[tls]
certificate = "relay.crt"
private_key = "relay.key"
ca = "ca.crt"
[relay]
listen = "127.0.0.1:4433"
candidate_republish_floor = "99ms"
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/32"]
"#;
        assert!(
            toml::from_str::<Config>(source)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn accepts_and_normalizes_tcp_fallback() {
        let source = r#"
mode = "relay"
[tls]
certificate = "relay.crt"
private_key = "relay.key"
ca = "ca.crt"
[relay]
listen = "127.0.0.1:4433"
[tcp_fallback]
listen = ":443"
write_timeout = "4s"
queue_depth = 64
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/32"]
"#;
        let config: Config = toml::from_str(source).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.tcp_fallback_addr().unwrap(),
            Some("0.0.0.0:443".parse().unwrap())
        );
        let tcp = config.tcp_fallback.unwrap();
        assert_eq!(tcp.write_timeout, Duration::from_secs(4));
        assert_eq!(tcp.queue_depth, 64);
    }

    #[test]
    fn rejects_unbounded_tcp_fallback_settings() {
        let source = r#"
mode = "relay"
[tls]
certificate = "relay.crt"
private_key = "relay.key"
ca = "ca.crt"
[relay]
listen = "127.0.0.1:4433"
[tcp_fallback]
listen = ":443"
idle_timeout = "10s"
keepalive_period = "10s"
queue_depth = 4097
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/32"]
"#;
        let config: Config = toml::from_str(source).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_only_loopback_metrics_listener() {
        let source = r#"
mode = "relay"
[tls]
certificate = "relay.crt"
private_key = "relay.key"
ca = "ca.crt"
[relay]
listen = "127.0.0.1:4433"
metrics_listen = "127.0.0.1:9090"
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/32"]
"#;
        let config: Config = toml::from_str(source).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.metrics_listen_addr().unwrap(),
            Some("127.0.0.1:9090".parse().unwrap())
        );

        let non_loopback = source.replace("127.0.0.1:9090", "0.0.0.0:9090");
        let error = toml::from_str::<Config>(&non_loopback)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(error.to_string().contains("loopback"));
    }
}
