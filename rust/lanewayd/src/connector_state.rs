//! Read the installed Connector identity without editing its Go configuration.
use super::*;
use laneway_protocol::{Role, relay_endpoint::canonical_host_port};
use rustls::pki_types::ServerName;
use std::io::Read;

#[derive(Deserialize)]
struct Stored {
    mode: String,
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
    #[serde(default = "legacy_reconnect_min", with = "humantime_serde")]
    reconnect_min: Duration,
    #[serde(default = "legacy_reconnect_max", with = "humantime_serde")]
    reconnect_max: Duration,
}

#[derive(Deserialize)]
struct StoredController {
    endpoint: String,
    quic_endpoint: String,
    server_name: String,
    network_id: String,
    service_id: String,
    #[serde(default = "legacy_poll", with = "humantime_serde")]
    poll_interval: Duration,
}

#[derive(Default, Deserialize)]
struct StoredDirect {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    listen: String,
    #[serde(default)]
    allow_loopback: bool,
    #[serde(default)]
    allow_link_local: bool,
    #[serde(default, with = "humantime_serde")]
    probe_interval: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    probe_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    rendezvous_interval: Option<Duration>,
}

#[derive(Default, Deserialize)]
struct StoredRouting {
    #[serde(default)]
    advertise: Vec<String>,
    #[serde(default)]
    output_interface: String,
    #[serde(default)]
    nat: bool,
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
}

#[derive(Default, Deserialize)]
struct StoredWireGuard {
    #[serde(default)]
    enabled: bool,
}

#[derive(Default, Deserialize)]
struct StoredTcp {
    #[serde(default)]
    address: String,
    #[serde(default, with = "humantime_serde")]
    handshake_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    write_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    idle_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    keep_alive_period: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    quic_probe_interval: Option<Duration>,
    #[serde(default)]
    queue_depth: Option<usize>,
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
        let mut source = String::new();
        fs::File::open(config_path)?
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut source)
            .context("read installed Connector configuration")?;
        ensure!(
            source.len() as u64 <= MAX_CONFIG_BYTES,
            "connector configuration is too large"
        );
        // Do not include raw configuration text in an error that might reach
        // container logs.
        let stored: Stored = toml::from_str(&source).map_err(|error| {
            anyhow::anyhow!(
                "invalid installed Connector configuration: {}",
                error.message()
            )
        })?;
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
            directory,
        )
    }
}

impl Stored {
    fn convert(self, tls: TlsConfig, directory: &Path) -> Result<Config> {
        let modern = self.connector.userspace
            && !self.exit.serve
            && self.routing.output_interface.is_empty()
            && !self.routing.nat;
        let legacy = !self.connector.userspace
            && self.exit.serve
            && self.routing.nat
            && !self.routing.output_interface.is_empty()
            && self.direct.enabled;
        ensure!(
            self.mode == "node"
                && (modern || legacy)
                && !self.wireguard.enabled
                && !self.exit.enabled
                && self.exit.selected_node_id.is_empty()
                && self.exit.lease_generation == 0
                && self.peers.is_empty()
                && self.node.overlay_addresses.is_empty()
                && self.routing.advertise.is_empty(),
            "saved configuration is not a supported Docker Connector"
        );
        let identity = crate::tls::verify_installed_connector(&tls)?;
        ensure!(
            identity.role == Role::Node,
            "installed Connector leaf is not a node"
        );
        let network = identity.network_id.to_string();
        ensure!(
            network == self.node.relay_network_id && network == self.controller.network_id,
            "installed Connector network differs from certificate identity"
        );
        let controller_name = self.controller.server_name;
        let endpoint = reqwest::Url::parse(&self.controller.endpoint)
            .context("invalid Connector controller origin")?;
        ensure!(
            endpoint.scheme() == "https"
                && endpoint.host_str() == Some(controller_name.as_str())
                && endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.username().is_empty()
                && endpoint.password().is_none(),
            "Connector controller origin does not match the pinned TLS host"
        );
        let quic_endpoint = canonical_host_port(&self.controller.quic_endpoint)
            .context("invalid Connector controller QUIC endpoint")?;
        let relay = canonical_host_port(&self.node.relay_address)
            .context("invalid saved Connector relay endpoint")?;
        let relay_name = self.tls.server_name;
        ServerName::try_from(relay_name.as_str()).context("invalid Connector relay TLS name")?;
        let tcp = self.tcp_fallback;
        let tcp_fallback = if tcp.address.is_empty() {
            None
        } else {
            Some(TcpFallbackConfig {
                address: canonical_host_port(&tcp.address)
                    .context("invalid Connector TCP fallback endpoint")?,
                handshake_timeout: tcp
                    .handshake_timeout
                    .unwrap_or_else(default_handshake_timeout),
                write_timeout: tcp.write_timeout.unwrap_or_else(default_write_timeout),
                idle_timeout: tcp.idle_timeout.unwrap_or_else(default_idle_timeout),
                keepalive_period: tcp.keep_alive_period.unwrap_or_else(default_keepalive),
                queue_depth: tcp.queue_depth.unwrap_or_else(default_tcp_queue_depth),
            })
        };
        let listen =
            if legacy || !self.direct.enabled || matches!(self.direct.listen.as_str(), "" | ":0") {
                default_direct_listen()
            } else {
                self.direct
                    .listen
                    .parse()
                    .context("invalid saved Connector UDP bind address")?
            };
        let config = Config {
            mode: self.mode,
            socket_path: self.socket_path,
            exit_intent_path: directory.join("exit-intent-v1.json"),
            identity: IdentityConfig {
                network_id: network,
                node_id: identity.subject_id.to_string(),
            },
            tls,
            controller: Some(ControllerConfig {
                auto_renew_certificate: false, // Keep identity bytes intact for a reversible image swap.
                disable_status_reporting: false,
                endpoint: self.controller.endpoint,
                quic_endpoint: Some(quic_endpoint),
                server_name: controller_name,
                service_id: self.controller.service_id,
                poll_interval: self.controller.poll_interval,
                timeout: default_controller_timeout(),
            }),
            tun: TunConfig {
                name: "userspace".to_owned(),
                mtu: 1280,
                addresses: vec![],
                configure: false,
            },
            connector: ConnectorConfig { userspace: true },
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
            forwarding: ForwardingConfig::default(),
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
}
