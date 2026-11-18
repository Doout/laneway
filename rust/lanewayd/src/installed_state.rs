//! Read installed Docker node roles without editing their Go configuration.
use super::*;
use laneway_protocol::{Role, relay_endpoint::canonical_host_port};
use rustls::pki_types::ServerName;
use std::io::Read;

#[derive(Deserialize)]
struct Stored {
    mode: String,
    #[serde(default = "legacy_state_dir")]
    state_dir: PathBuf,
    #[serde(default = "default_socket_path")]
    socket_path: PathBuf,
    tls: StoredTls,
    node: StoredNode,
    controller: StoredController,
    #[serde(default)]
    connector: ConnectorConfig,
    #[serde(default)]
    direct: StoredDirect,
    #[serde(default)]
    routing: StoredRouting,
    #[serde(default)]
    exit: StoredExit,
    #[serde(default)]
    wireguard: StoredWireGuard,
    #[serde(default)]
    tcp_fallback: StoredTcp,
    #[serde(default)]
    peers: Vec<toml::Value>,
}

#[derive(Deserialize)]
struct StoredTls {
    certificate: PathBuf,
    private_key: PathBuf,
    ca: PathBuf,
    server_name: String,
}

#[derive(Deserialize)]
struct StoredNode {
    relay_address: String,
    relay_network_id: String,
    relay_service_id: String,
    #[serde(default)]
    overlay_addresses: Vec<String>,
    #[serde(
        default = "legacy_reconnect_min",
        deserialize_with = "StoredDuration::required"
    )]
    reconnect_min: Duration,
    #[serde(
        default = "legacy_reconnect_max",
        deserialize_with = "StoredDuration::required"
    )]
    reconnect_max: Duration,
}

#[derive(Deserialize)]
struct StoredController {
    endpoint: String,
    quic_endpoint: String,
    server_name: String,
    network_id: String,
    service_id: String,
    #[serde(default = "legacy_poll", deserialize_with = "StoredDuration::required")]
    poll_interval: Duration,
}

#[derive(Deserialize)]
#[serde(default)]
struct StoredDirect {
    enabled: bool,
    #[serde(default)]
    listen: String,
    #[serde(default)]
    allow_loopback: bool,
    #[serde(default)]
    allow_link_local: bool,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    probe_interval: Option<Duration>,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    probe_timeout: Option<Duration>,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    rendezvous_interval: Option<Duration>,
}

impl Default for StoredDirect {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: String::new(),
            allow_loopback: false,
            allow_link_local: false,
            probe_interval: None,
            probe_timeout: None,
            rendezvous_interval: None,
        }
    }
}

#[derive(Default, Deserialize)]
struct StoredRouting {
    #[serde(default)]
    advertise: Vec<String>,
    #[serde(default)]
    output_interface: String,
    #[serde(default)]
    nat: Option<bool>,
}

#[derive(Default, Deserialize)]
struct StoredExit {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    serve: bool,
    #[serde(default)]
    selected_node_id: String,
    #[serde(default)]
    lease_generation: u64,
    #[cfg(target_os = "linux")]
    #[serde(default)]
    failure_mode: String,
}

#[derive(Default, Deserialize)]
struct StoredWireGuard {
    #[serde(default)]
    enabled: bool,
    #[cfg(target_os = "linux")]
    #[serde(default)]
    private_key: PathBuf,
    #[cfg(target_os = "linux")]
    #[serde(default)]
    interface: String,
    #[cfg(target_os = "linux")]
    #[serde(default)]
    mtu: u16,
    #[cfg(target_os = "linux")]
    #[serde(default)]
    listen_port: u16,
}

#[derive(Default, Deserialize)]
struct StoredTcp {
    #[serde(default)]
    address: String,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    handshake_timeout: Option<Duration>,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    write_timeout: Option<Duration>,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    idle_timeout: Option<Duration>,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    keep_alive_period: Option<Duration>,
    #[serde(default, deserialize_with = "StoredDuration::optional")]
    quic_probe_interval: Option<Duration>,
    #[serde(default)]
    queue_depth: Option<usize>,
}

// The Go installer marshals time.Duration as signed integer nanoseconds.
// Hand-authored legacy configs use strings such as "10s" instead.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredDuration {
    Nanoseconds(u64),
    Text(#[serde(with = "humantime_serde")] Duration),
}

impl StoredDuration {
    fn into_duration<E: serde::de::Error>(self) -> Result<Duration, E> {
        match self {
            Self::Nanoseconds(value) if i64::try_from(value).is_ok() => {
                Ok(Duration::from_nanos(value))
            }
            Self::Nanoseconds(_) => Err(E::custom("installed duration exceeds Go's range")),
            Self::Text(value) => Ok(value),
        }
    }

    fn required<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Duration, D::Error> {
        Self::deserialize(value)?.into_duration()
    }

    fn optional<'de, D: serde::Deserializer<'de>>(value: D) -> Result<Option<Duration>, D::Error> {
        Option::<Self>::deserialize(value)?
            .map(Self::into_duration)
            .transpose()
    }
}

fn legacy_reconnect_min() -> Duration {
    Duration::from_secs(1)
}
fn legacy_reconnect_max() -> Duration {
    Duration::from_secs(30)
}
fn legacy_poll() -> Duration {
    Duration::from_secs(30)
}

fn legacy_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/laneway")
}

enum InstalledRole<'a> {
    Connector(&'a Path),
    ExitGateway,
    #[cfg(target_os = "linux")]
    SharedHost,
}

impl Config {
    /// Loads a previously activated Docker Connector into the Rust runtime.
    /// No network or write is needed: authentication uses the saved CA, key,
    /// and node leaf, and onboarding files stay usable by the Go image.
    pub fn load_connector_state(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref();
        ensure!(
            valid_absolute_path(directory, 4096) && fs::symlink_metadata(directory)?.is_dir(),
            "connector state must be an absolute directory, not a link"
        );
        let certificate = regular(directory, "node.crt")?;
        let private_key = regular(directory, "node.key")?;
        let ca = regular(directory, "ca.crt")?;
        // Kept for rollback but never read or copied by the Rust runtime.
        regular(directory, "wireguard.key")?;
        let config_path = regular(directory, "connector.toml")?;
        let stored = Stored::read(&config_path)?;
        ensure!(
            stored.tls.certificate == certificate
                && stored.tls.private_key == private_key
                && stored.tls.ca == ca,
            "connector TLS paths must refer to its activated state files"
        );
        stored.convert(
            TlsConfig {
                certificate,
                private_key,
                ca,
            },
            InstalledRole::Connector(directory),
        )
    }

    /// Load the durable Docker Exit Node's existing read-only Go configuration.
    pub fn load_exit_config(path: impl AsRef<Path>) -> Result<Self> {
        let stored = Stored::read(path.as_ref())?;
        let tls = TlsConfig {
            certificate: stored.tls.certificate.clone(),
            private_key: stored.tls.private_key.clone(),
            ca: stored.tls.ca.clone(),
        };
        for path in [&tls.certificate, &tls.private_key, &tls.ca] {
            ensure!(
                valid_absolute_path(path, 4096) && fs::symlink_metadata(path)?.is_file(),
                "exit TLS paths must refer to absolute regular files"
            );
        }
        stored.convert(tls, InstalledRole::ExitGateway)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn load_shared_host_config(
        file: fs::File,
        tls: TlsConfig,
        runtime_dir: &Path,
    ) -> Result<(Self, std::num::NonZeroU64)> {
        let stored = Stored::read_file(file)?;
        ensure!(
            stored.tls.ca == Path::new("@credential/ca.crt")
                && stored.tls.certificate == Path::new("@credential/node.crt")
                && stored.tls.private_key == Path::new("@credential/node.key")
                && stored.wireguard.private_key == Path::new("@credential/wireguard.key")
                && stored.state_dir == runtime_dir.join("state")
                && stored.socket_path == runtime_dir.join("lanewayd.sock"),
            "shared-host config does not match its protected credentials and runtime"
        );
        let generation = std::num::NonZeroU64::new(stored.exit.lease_generation)
            .context("shared-host Exit lease generation is missing")?;
        ensure!(
            generation.get() <= i64::MAX as u64,
            "invalid shared-host lease generation"
        );
        Ok((stored.convert(tls, InstalledRole::SharedHost)?, generation))
    }
}

impl Stored {
    fn read(path: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(path)?.is_file(),
            "installed node configuration is not a regular file"
        );
        Self::read_file(fs::File::open(path)?)
    }

    fn read_file(file: fs::File) -> Result<Self> {
        let mut source = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut source)
            .context("read installed node configuration")?;
        ensure!(
            source.len() as u64 <= MAX_CONFIG_BYTES,
            "installed node configuration is too large"
        );
        // Do not include raw configuration text in an error that might reach
        // container logs.
        toml::from_str(&source).map_err(|error| {
            anyhow::anyhow!("invalid installed node configuration: {}", error.message())
        })
    }

    fn convert(self, tls: TlsConfig, role: InstalledRole<'_>) -> Result<Config> {
        let nat = self
            .routing
            .nat
            .unwrap_or(!self.routing.output_interface.is_empty());
        let modern = self.connector.userspace
            && !self.exit.serve
            && self.routing.output_interface.is_empty()
            && !nat;
        let legacy = !self.connector.userspace
            && self.exit.serve
            && nat
            && !self.routing.output_interface.is_empty()
            && self.direct.enabled;
        #[cfg(target_os = "linux")]
        let shared_host = matches!(role, InstalledRole::SharedHost);
        #[cfg(not(target_os = "linux"))]
        let shared_host = false;
        let (userspace, state_dir, supported) = match role {
            InstalledRole::Connector(directory) => (true, directory, modern || legacy),
            InstalledRole::ExitGateway => (false, self.state_dir.as_path(), legacy),
            #[cfg(target_os = "linux")]
            InstalledRole::SharedHost => (
                false,
                self.state_dir.as_path(),
                self.wireguard.enabled
                    && self.wireguard.interface == "lane0"
                    && self.wireguard.mtu == 1280
                    && self.wireguard.listen_port == 0
                    && self.exit.serve
                    && self.exit.failure_mode == "closed"
                    && nat
                    && !self.direct.enabled
                    && !self.connector.userspace
                    && self.routing.output_interface == "uplink0",
            ),
        };
        ensure!(
            self.mode == "node"
                && supported
                && self.wireguard.enabled == shared_host
                && !self.exit.enabled
                && self.exit.selected_node_id.is_empty()
                && (self.exit.lease_generation != 0) == shared_host
                && self.peers.is_empty()
                && self.node.overlay_addresses.is_empty()
                && self.routing.advertise.is_empty(),
            "saved configuration does not match the requested node role"
        );
        ensure!(
            valid_absolute_path(state_dir, 4096),
            "installed state_dir must be absolute"
        );
        let identity = crate::tls::verify_installed_node(&tls)?;
        ensure!(identity.role == Role::Node, "installed leaf is not a node");
        let network = identity.network_id.to_string();
        ensure!(
            network == self.node.relay_network_id && network == self.controller.network_id,
            "installed node network differs from certificate identity"
        );
        let controller_name = self.controller.server_name;
        crate::controller::controller_origins(&self.controller.endpoint, &controller_name)?;
        let quic_endpoint = canonical_host_port(&self.controller.quic_endpoint)
            .context("invalid installed controller QUIC endpoint")?;
        let relay = canonical_host_port(&self.node.relay_address)
            .context("invalid saved relay endpoint")?;
        let relay_name = if shared_host && self.tls.server_name.is_empty() {
            relay
                .rsplit_once(':')
                .context("invalid shared-host relay")?
                .0
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned()
        } else {
            self.tls.server_name
        };
        ServerName::try_from(relay_name.as_str()).context("invalid relay TLS name")?;
        let tcp = self.tcp_fallback;
        let tcp_fallback = if tcp.address.is_empty() {
            None
        } else {
            Some(TcpFallbackConfig {
                address: canonical_host_port(&tcp.address)
                    .context("invalid TCP fallback endpoint")?,
                handshake_timeout: tcp
                    .handshake_timeout
                    .unwrap_or_else(default_handshake_timeout),
                write_timeout: tcp.write_timeout.unwrap_or_else(default_write_timeout),
                idle_timeout: tcp.idle_timeout.unwrap_or_else(default_idle_timeout),
                keepalive_period: tcp.keep_alive_period.unwrap_or_else(default_keepalive),
                queue_depth: tcp.queue_depth.unwrap_or_else(default_tcp_queue_depth),
            })
        };
        let listen = if (userspace && legacy)
            || !self.direct.enabled
            || matches!(self.direct.listen.as_str(), "" | ":0")
        {
            default_direct_listen()
        } else {
            let listen = if self.direct.listen.starts_with(':') {
                format!("0.0.0.0{}", self.direct.listen)
            } else {
                self.direct.listen
            };
            listen.parse().context("invalid saved UDP bind address")?
        };
        let config = Config {
            foreground_routes: None,
            mode: self.mode,
            socket_path: self.socket_path,
            exit_intent_path: state_dir.join("exit-intent-v1.json"),
            identity: IdentityConfig {
                network_id: network,
                node_id: identity.subject_id.to_string(),
            },
            tls,
            controller: Some(ControllerConfig {
                auto_renew_certificate: false, // Keep identity bytes intact for a reversible image swap.
                disable_status_reporting: shared_host,
                endpoint: self.controller.endpoint,
                quic_endpoint: Some(quic_endpoint),
                server_name: controller_name,
                service_id: self.controller.service_id,
                poll_interval: self.controller.poll_interval,
                timeout: default_controller_timeout(),
            }),
            tun: TunConfig {
                name: if userspace { "userspace" } else { "lane0" }.to_owned(),
                // Match the old Go TUN limit on IPv4-only networks. An
                // initial IPv6 overlay raises it to the IPv6 minimum.
                mtu: if userspace || shared_host { 1280 } else { 1200 },
                addresses: vec![],
                configure: !userspace,
            },
            connector: ConnectorConfig { userspace },
            relay: RelayConfig {
                address: relay.parse().ok(), // DNS relay targets are resolved from live controller authority.
                server_name: relay_name,
                service_id: self.node.relay_service_id,
                queue_depth: default_queue_depth(),
                max_routes: default_max_routes(),
                handshake_timeout: default_handshake_timeout(),
                idle_timeout: default_idle_timeout(),
                keepalive: default_keepalive(),
                reconnect_min: self.node.reconnect_min,
                reconnect_max: self.node.reconnect_max,
                quic_recovery_interval: tcp
                    .quic_probe_interval
                    .unwrap_or_else(default_quic_recovery_interval),
            },
            tcp_fallback,
            direct: DirectConfig {
                listen,
                probe_interval: self
                    .direct
                    .probe_interval
                    .unwrap_or_else(default_probe_interval),
                probe_timeout: self
                    .direct
                    .probe_timeout
                    .unwrap_or_else(default_probe_timeout),
                candidate_refresh_interval: self
                    .direct
                    .rendezvous_interval
                    .unwrap_or_else(default_candidate_refresh_interval),
                allow_loopback: self.direct.allow_loopback,
                allow_link_local: self.direct.allow_link_local,
                ..DirectConfig::default()
            },
            routes: vec![],
            direct_peers: vec![],
            forwarding: if userspace {
                ForwardingConfig::default()
            } else {
                ForwardingConfig {
                    exit_gateway: true,
                    exit_gateway_controller_sources: true,
                    exit_output_interface: Some(self.routing.output_interface),
                    ..ForwardingConfig::default()
                }
            },
            diagnostics: DiagnosticsConfig::default(),
        };
        config.validate()?;
        Ok(config)
    }
}

fn regular(directory: &Path, name: &str) -> Result<PathBuf> {
    let path = directory.join(name);
    ensure!(
        fs::symlink_metadata(&path)
            .with_context(|| format!("inspect Connector {name}"))?
            .is_file(),
        "Connector {name} is not a regular file"
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use std::os::unix::fs::PermissionsExt;

    const NETWORK: &str = "71000000000000000000000000000001";
    const NODE: &str = "71000000000000000000000000000002";

    fn write_fixture(directory: &Path) -> Result<String> {
        let mut root = CertificateParams::default();
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_key = KeyPair::generate()?;
        let ca = root.self_signed(&root_key)?;
        let issuer = Issuer::new(root, root_key);
        let key = KeyPair::generate()?;
        let mut leaf = CertificateParams::default();
        leaf.subject_alt_names = vec![SanType::URI(
            format!("spiffe://laneway/network/{NETWORK}/node/{NODE}").try_into()?,
        )];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let certificate = leaf.signed_by(&key, &issuer)?;
        for (name, data, mode) in [
            ("ca.crt", ca.pem(), 0o444),
            ("node.crt", certificate.pem(), 0o444),
            ("node.key", key.serialize_pem(), 0o400),
            ("wireguard.key", "unused by Rust".into(), 0o400),
        ] {
            let path = directory.join(name);
            fs::write(&path, data)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        }
        let path = directory.display();
        Ok(format!(
            r#"
mode = "node"
state_dir = "{path}"
socket_path = "/run/laneway/lanewayd.sock"
[tls]
certificate = "{path}/node.crt"
private_key = "{path}/node.key"
ca = "{path}/ca.crt"
server_name = "offline.example.test"
[node]
name = "fixture"
relay_address = "offline.example.test:4433"
relay_network_id = "{NETWORK}"
relay_service_id = "71000000000000000000000000000003"
[controller]
endpoint = "https://offline.example.test"
quic_endpoint = "offline.example.test:8443"
server_name = "offline.example.test"
network_id = "{NETWORK}"
service_id = "71000000000000000000000000000004"
[tcp_fallback]
address = "offline.example.test:443"
[direct]
enabled = true
listen = ":0"
"#
        ))
    }

    #[test]
    fn installed_durations_accept_go_nanoseconds_and_existing_strings() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let base = write_fixture(fixture.path())?;
        let text = base
            .replace(
                "[node]",
                "[node]\nreconnect_min = 1000000000\nreconnect_max = \"10s\"",
            )
            .replace("[controller]", "[controller]\npoll_interval = 10000000000")
            .replace("[direct]", "[direct]\nprobe_interval = 200000000")
            .replace(
                "[tcp_fallback]",
                "[tcp_fallback]\nhandshake_timeout = 10000000000",
            );
        let stored: Stored = toml::from_str(&text)?;
        assert_eq!(stored.node.reconnect_min, Duration::from_secs(1));
        assert_eq!(stored.node.reconnect_max, Duration::from_secs(10));
        assert_eq!(stored.controller.poll_interval, Duration::from_secs(10));
        assert_eq!(
            stored.direct.probe_interval,
            Some(Duration::from_millis(200))
        );
        assert_eq!(stored.direct.probe_timeout, None);
        assert_eq!(
            stored.tcp_fallback.handshake_timeout,
            Some(Duration::from_secs(10))
        );
        assert!(
            toml::from_str::<Stored>(
                &text.replace("poll_interval = 10000000000", "poll_interval = -1")
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn valid_and_previous_connector_profiles_preserve_identity_without_dns() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let base = write_fixture(fixture.path())?;
        let path = fixture.path().join("connector.toml");
        for suffix in [
            "[connector]\nuserspace = true\n",
            "[routing]\noutput_interface = \"eth0\"\nnat = true\n[exit]\nserve = true\n",
        ] {
            let source = format!("{base}{suffix}");
            fs::write(&path, &source)?;
            let config = Config::load_connector_state(fixture.path())?;
            assert_eq!(config.identity.network_id, NETWORK);
            assert_eq!(config.identity.node_id, NODE);
            assert!(config.connector.userspace);
            assert!(!config.tun.configure);
            assert!(!config.forwarding.exit_gateway);
            assert_eq!(
                config.tcp_fallback.unwrap().address,
                "offline.example.test:443"
            );
            assert_eq!(fs::read_to_string(&path)?, source);
        }
        let safe = format!("{base}[connector]\nuserspace = true\n");
        fs::write(&path, format!("{safe}[exit]\nenabled = true\n"))?;
        assert!(Config::load_connector_state(fixture.path()).is_err());
        fs::write(
            &path,
            safe.replace(NETWORK, "71000000000000000000000000000005"),
        )?;
        assert!(Config::load_connector_state(fixture.path()).is_err());
        fs::write(&path, safe)?;
        let wrong_key = fixture.path().join("wrong.key");
        fs::write(&wrong_key, KeyPair::generate()?.serialize_pem())?;
        fs::set_permissions(&wrong_key, fs::Permissions::from_mode(0o400))?;
        fs::rename(wrong_key, fixture.path().join("node.key"))?;
        assert!(Config::load_connector_state(fixture.path()).is_err());
        Ok(())
    }

    #[test]
    fn supports_the_existing_durable_exit_profile_without_editing_its_files() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        write_fixture(fixture.path())?;
        let deployed =
            include_str!("../../../deploy/compose/generated/config/exit-node.toml.example")
                .replace(
                    "/run/laneway-secrets/exit-node.",
                    &format!("{}/node.", fixture.path().display()),
                )
                .replace(
                    "/run/laneway-secrets/ca.crt",
                    &format!("{}/ca.crt", fixture.path().display()),
                )
                .replace("REPLACE_NETWORK_ID", NETWORK)
                .replace(
                    "REPLACE_RELAY_SERVICE_ID",
                    "71000000000000000000000000000003",
                )
                .replace(
                    "REPLACE_CONTROLLER_SERVICE_ID",
                    "71000000000000000000000000000004",
                );
        let path = fixture.path().join("exit-node.toml");
        fs::write(&path, &deployed)?;
        let key = fs::read(fixture.path().join("node.key"))?;
        let config = Config::load_exit_config(&path)?;
        assert_eq!(config.identity.node_id, NODE);
        assert_eq!(config.socket_path, Path::new("/run/laneway/lanewayd.sock"));
        assert_eq!(config.direct.listen, "0.0.0.0:4434".parse().unwrap());
        assert_eq!(
            config.controller.unwrap().server_name,
            "controller.example.com"
        );
        assert_eq!(config.tcp_fallback.unwrap().address, "relay:8443");
        assert!(config.tun.configure);
        assert_eq!(config.tun.mtu, 1200);
        assert!(!config.connector.userspace);
        assert!(config.forwarding.exit_gateway);
        assert!(config.forwarding.exit_gateway_controller_sources);
        assert_eq!(
            config.forwarding.exit_output_interface.as_deref(),
            Some("eth0")
        );
        assert_eq!(fs::read_to_string(&path)?, deployed);
        assert_eq!(fs::read(fixture.path().join("node.key"))?, key);
        for wrong_role in [
            deployed.replace("serve = true", "serve = false"),
            deployed.replace("nat = true", "nat = false"),
            deployed.replace("serve = true", "serve = true\nlease_generation = 1"),
            format!("{deployed}\n[wireguard]\nenabled = true\n"),
        ] {
            fs::write(&path, wrong_role)?;
            assert!(Config::load_exit_config(&path).is_err());
        }
        Ok(())
    }
}
