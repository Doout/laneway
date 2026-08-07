use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use laneway_protocol::{
    AuthenticatedIdentity, Id, Role, identity_from_certificate_der,
    policy::{CompiledPolicy, prefix_from_wire},
    v1::{
        Capability, ConfigurationRequest, EnrollmentClass, NodeConfiguration,
        RouteAdvertisementMode, RouteKind,
    },
};
use prost::Message;
use quinn::{Endpoint, TransportConfig, VarInt, crypto::rustls::QuicClientConfig};
use reqwest::{Certificate, Identity, StatusCode};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::sync::Mutex;

use crate::tls::LocalCertificateHealth;

const MAX_RESPONSE: usize = 1 << 20;
const VALID_UNTIL_HEADER: &str = "X-Laneway-Configuration-Valid-Until";
const MAX_PEERS: usize = 65_536;
const MAX_ROUTES: usize = 65_536;
const MAX_RELAYS: usize = 32;
const MAX_RELAY_ADDRESSES: usize = 16;
const MAX_RESOLVED_RELAY_TARGETS: usize = 128;
const RELAY_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Fully pinned controller connection material for one node.
#[derive(Clone, Debug)]
pub(crate) struct ClientOptions {
    pub(crate) endpoint: String,
    pub(crate) quic_endpoint: Option<String>,
    pub(crate) server_name: String,
    pub(crate) network: Id,
    pub(crate) service: Id,
    pub(crate) certificate: PathBuf,
    pub(crate) private_key: PathBuf,
    pub(crate) ca: PathBuf,
    pub(crate) timeout: Duration,
}

/// One bounded conditional controller response.
#[derive(Debug)]
pub(crate) enum PollResult {
    Modified(Box<NodeConfiguration>),
    NotModified { valid_until: u64 },
}

/// Strict HTTPS/protobuf controller snapshot client.
pub(crate) struct Client {
    endpoint: String,
    http: reqwest::Client,
    expected_controller: AuthenticatedIdentity,
    resolved: Vec<SocketAddr>,
    quic: Option<QuicControl>,
}

struct QuicControl {
    endpoint: Endpoint,
    addresses: Vec<SocketAddr>,
    server_name: String,
    expected: AuthenticatedIdentity,
    timeout: Duration,
    connection: Mutex<Option<quinn::Connection>>,
    request_id: AtomicU64,
}

impl Client {
    pub(crate) async fn new(options: ClientOptions) -> Result<Self> {
        ensure!(
            !options.timeout.is_zero() && options.timeout <= Duration::from_secs(300),
            "controller timeout must be in (0,5m]"
        );
        let url = reqwest::Url::parse(&options.endpoint).context("parse controller endpoint")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && matches!(url.path(), "" | "/"),
            "controller endpoint must be an HTTPS origin"
        );
        if !options.server_name.is_empty() {
            ensure!(
                url.host_str() == Some(options.server_name.as_str()),
                "controller server_name must match endpoint host"
            );
        }
        let host = url
            .host_str()
            .context("controller endpoint host is missing")?;
        let port = url
            .port_or_known_default()
            .context("controller endpoint port is unknown")?;
        let mut resolved: Vec<SocketAddr> = if let Ok(address) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(address, port)]
        } else {
            tokio::time::timeout(options.timeout, tokio::net::lookup_host((host, port)))
                .await
                .context("controller DNS resolution timed out")?
                .context("resolve controller endpoint")?
                .take(17)
                .collect()
        };
        resolved.sort_unstable();
        resolved.dedup();
        ensure!(
            !resolved.is_empty() && resolved.len() <= 16,
            "controller endpoint resolved outside the bounded 1..=16 address set"
        );
        let mut identity = bounded_read(&options.certificate, 4 << 20, "node certificate")?;
        identity.extend_from_slice(&bounded_read(
            &options.private_key,
            1 << 20,
            "node private key",
        )?);
        let ca = bounded_read(&options.ca, 4 << 20, "controller CA")?;
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .identity(Identity::from_pem(&identity).context("load node controller identity")?)
            .add_root_certificate(Certificate::from_pem(&ca).context("load controller CA")?)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .timeout(options.timeout)
            .tls_info(true);
        if host.parse::<IpAddr>().is_err() {
            builder = builder.resolve_to_addrs(host, &resolved);
        }
        let http = builder
            .build()
            .context("build node controller HTTP client")?;
        let quic = if let Some(endpoint) = options.quic_endpoint.as_deref() {
            Some(
                QuicControl::new(
                    endpoint,
                    &options,
                    expected_controller(options.network, options.service),
                )
                .await?,
            )
        } else {
            None
        };
        if let Some(control) = &quic {
            resolved.extend(control.addresses.iter().copied());
            resolved.sort_unstable();
            resolved.dedup();
        }
        Ok(Self {
            endpoint: format!(
                "{}/v1/configuration",
                options.endpoint.trim_end_matches('/')
            ),
            http,
            expected_controller: expected_controller(options.network, options.service),
            resolved,
            quic,
        })
    }

    pub(crate) fn resolved_ips(&self) -> Vec<IpAddr> {
        self.resolved.iter().map(SocketAddr::ip).collect()
    }

    pub(crate) async fn poll(&self, known_epoch: u64) -> Result<PollResult> {
        if let Some(control) = &self.quic {
            return control.poll(known_epoch).await;
        }
        let request = ConfigurationRequest {
            known_configuration_epoch: known_epoch,
        }
        .encode_to_vec();
        let mut response = self
            .http
            .post(&self.endpoint)
            .header("content-type", "application/x-protobuf")
            .body(request)
            .send()
            .await
            .context("request node configuration")?;
        let peer = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(reqwest::tls::TlsInfo::peer_certificate)
            .context("controller TLS peer certificate is unavailable")?;
        ensure!(
            identity_from_certificate_der(peer).context("controller SPIFFE identity")?
                == self.expected_controller,
            "controller SPIFFE identity differs from configured network/service ID"
        );
        if response.status() == StatusCode::NOT_MODIFIED {
            let valid_until = response
                .headers()
                .get(VALID_UNTIL_HEADER)
                .context("304 omitted snapshot deadline")?
                .to_str()
                .context("304 snapshot deadline is not ASCII")?
                .parse::<u64>()
                .context("304 snapshot deadline is invalid")?;
            ensure!(!expired(valid_until), "304 renewed an expired snapshot");
            return Ok(PollResult::NotModified { valid_until });
        }
        ensure!(
            response.status().is_success(),
            "controller returned {}",
            response.status()
        );
        if let Some(length) = response.content_length() {
            ensure!(
                length <= MAX_RESPONSE as u64,
                "controller response exceeds limit"
            );
        }
        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or(0)
                .min(MAX_RESPONSE as u64) as usize,
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read node configuration chunk")?
        {
            ensure!(
                body.len() <= MAX_RESPONSE.saturating_sub(chunk.len()),
                "controller response exceeds limit"
            );
            body.extend_from_slice(&chunk);
        }
        ensure!(
            !body.is_empty(),
            "controller returned an empty configuration"
        );
        Ok(PollResult::Modified(Box::new(
            NodeConfiguration::decode(body.as_slice()).context("decode node configuration")?,
        )))
    }
}

fn expected_controller(network: Id, service: Id) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        network_id: network,
        role: Role::Controller,
        subject_id: service,
    }
}

impl QuicControl {
    async fn new(
        address: &str,
        options: &ClientOptions,
        expected: AuthenticatedIdentity,
    ) -> Result<Self> {
        let (host, port) = split_host_port(address)?;
        let mut addresses: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            tokio::time::timeout(
                options.timeout,
                tokio::net::lookup_host((host.as_str(), port)),
            )
            .await
            .context("controller QUIC DNS resolution timed out")?
            .context("resolve controller QUIC endpoint")?
            .take(17)
            .collect()
        };
        addresses.sort_unstable();
        addresses.dedup();
        ensure!(
            !addresses.is_empty() && addresses.len() <= 16,
            "controller QUIC endpoint resolved outside the bounded 1..=16 address set"
        );

        let certificate_pem = bounded_read(&options.certificate, 4 << 20, "node certificate")?;
        let mut cursor = std::io::Cursor::new(certificate_pem);
        let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
            .collect::<std::result::Result<_, _>>()
            .context("parse node controller certificate")?;
        ensure!(
            !certificates.is_empty(),
            "node controller certificate chain is empty"
        );
        let key_pem = bounded_read(&options.private_key, 1 << 20, "node private key")?;
        let mut cursor = std::io::Cursor::new(key_pem);
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut cursor)
            .context("parse node controller private key")?
            .context("node controller private key is missing")?;
        let ca_pem = bounded_read(&options.ca, 4 << 20, "controller CA")?;
        let mut cursor = std::io::Cursor::new(ca_pem);
        let roots_der: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
            .collect::<std::result::Result<_, _>>()
            .context("parse controller CA")?;
        let mut roots = RootCertStore::empty();
        let (accepted, rejected) = roots.add_parsable_certificates(roots_der);
        ensure!(
            accepted > 0 && rejected == 0,
            "controller CA contains an invalid certificate"
        );
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, key)
            .context("load node QUIC controller identity")?;
        crypto.alpn_protocols = vec![b"laneway-control/1".to_vec()];
        crypto.enable_early_data = false;
        let crypto = QuicClientConfig::try_from(crypto).context("build controller QUIC TLS")?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(VarInt::from_u32(1))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .max_idle_timeout(Some(
                Duration::from_secs(60)
                    .try_into()
                    .expect("constant timeout"),
            ))
            .keep_alive_interval(Some(Duration::from_secs(20)));
        client.transport_config(Arc::new(transport));
        let bind = if addresses.iter().any(SocketAddr::is_ipv4) {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let mut endpoint = Endpoint::client(bind.parse().expect("constant controller bind"))?;
        endpoint.set_default_client_config(client);
        Ok(Self {
            endpoint,
            addresses,
            server_name: options.server_name.clone(),
            expected,
            timeout: options.timeout,
            connection: Mutex::new(None),
            request_id: AtomicU64::new(0),
        })
    }

    async fn poll(&self, known_epoch: u64) -> Result<PollResult> {
        use laneway_protocol::v1::{ControllerEnvelope, controller_envelope};
        let envelope = ControllerEnvelope {
            schema_version: 1,
            request_id: self.next_request_id(),
            body: Some(controller_envelope::Body::ConfigurationRequest(
                ConfigurationRequest {
                    known_configuration_epoch: known_epoch,
                },
            )),
        };
        let response = self.exchange(envelope).await?;
        match response.body {
            Some(controller_envelope::Body::NodeConfiguration(configuration)) => {
                Ok(PollResult::Modified(Box::new(configuration)))
            }
            Some(controller_envelope::Body::ConfigurationLease(lease)) => {
                ensure!(
                    lease.configuration_epoch == known_epoch
                        && lease.valid_until_unix_seconds != 0
                        && !expired(lease.valid_until_unix_seconds),
                    "controller QUIC lease is expired"
                );
                Ok(PollResult::NotModified {
                    valid_until: lease.valid_until_unix_seconds,
                })
            }
            Some(controller_envelope::Body::Error(error)) => {
                if matches!(
                    error.code(),
                    laneway_protocol::v1::ErrorCode::Unauthenticated
                        | laneway_protocol::v1::ErrorCode::PermissionDenied
                ) {
                    self.invalidate().await;
                }
                bail!(
                    "controller QUIC error {:?}: {} (retryable={})",
                    error.code(),
                    error.detail,
                    error.retryable
                )
            }
            _ => bail!("controller QUIC returned an unexpected node response"),
        }
    }

    fn next_request_id(&self) -> u64 {
        loop {
            let id = self
                .request_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if id != 0 {
                return id;
            }
        }
    }

    async fn invalidate(&self) {
        if let Some(connection) = self.connection.lock().await.take() {
            connection.close(0_u32.into(), b"controller authorization rejected");
        }
    }

    async fn exchange(
        &self,
        request: laneway_protocol::v1::ControllerEnvelope,
    ) -> Result<laneway_protocol::v1::ControllerEnvelope> {
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            let mut last = None;
            for address in &self.addresses {
                let connecting = match self.endpoint.connect(*address, &self.server_name) {
                    Ok(value) => value,
                    Err(error) => {
                        last = Some(anyhow::Error::from(error));
                        continue;
                    }
                };
                match tokio::time::timeout(self.timeout, connecting).await {
                    Ok(Ok(value)) => {
                        let identity = value
                            .peer_identity()
                            .context("controller QUIC peer certificate is unavailable")?;
                        let chain = identity
                            .downcast::<Vec<CertificateDer<'static>>>()
                            .map_err(|_| {
                                anyhow::anyhow!("unexpected controller QUIC peer identity type")
                            })?;
                        let leaf = chain
                            .first()
                            .context("controller QUIC certificate chain is empty")?;
                        ensure!(
                            identity_from_certificate_der(leaf.as_ref())
                                .context("controller QUIC SPIFFE identity")?
                                == self.expected,
                            "controller QUIC SPIFFE identity differs from configured network/service ID"
                        );
                        *connection = Some(value);
                        break;
                    }
                    Ok(Err(error)) => last = Some(anyhow::Error::from(error)),
                    Err(error) => last = Some(anyhow::Error::from(error)),
                }
            }
            if connection.is_none() {
                return Err(last.unwrap_or_else(|| {
                    anyhow::anyhow!("controller QUIC has no resolved address")
                }))
                .context("connect controller QUIC");
            }
        }
        let active = connection.as_ref().expect("connection installed").clone();
        let result = tokio::time::timeout(self.timeout, async {
            let (mut send, mut receive) = active
                .open_bi()
                .await
                .context("open controller QUIC request stream")?;
            let payload = request.encode_to_vec();
            ensure!(
                !payload.is_empty() && payload.len() <= MAX_RESPONSE,
                "controller QUIC request exceeds limit"
            );
            send.write_all(&(payload.len() as u32).to_be_bytes())
                .await?;
            send.write_all(&payload).await?;
            send.finish()?;
            let mut prefix = [0_u8; 4];
            receive.read_exact(&mut prefix).await?;
            let length = u32::from_be_bytes(prefix) as usize;
            ensure!(
                length != 0 && length <= MAX_RESPONSE,
                "controller QUIC response exceeds limit"
            );
            let mut response = vec![0_u8; length];
            receive.read_exact(&mut response).await?;
            ensure!(
                receive.read_to_end(0).await?.is_empty(),
                "controller QUIC response has trailing bytes"
            );
            let envelope = laneway_protocol::v1::ControllerEnvelope::decode(response.as_slice())
                .context("decode controller QUIC envelope")?;
            ensure!(
                envelope.schema_version == 1
                    && envelope.request_id == request.request_id
                    && envelope.body.is_some(),
                "controller QUIC response schema or request ID mismatch"
            );
            Ok::<_, anyhow::Error>(envelope)
        })
        .await;
        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => {
                active.close(0_u32.into(), b"reconnect");
                *connection = None;
                Err(error)
            }
            Err(error) => {
                active.close(0_u32.into(), b"request timeout");
                *connection = None;
                Err(error.into())
            }
        }
    }
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    let (host, port) = value
        .rsplit_once(':')
        .context("controller QUIC endpoint must be host:port")?;
    let port = port
        .parse::<u16>()
        .context("controller QUIC endpoint port")?;
    ensure!(
        !host.is_empty() && port != 0,
        "controller QUIC endpoint must be host:port"
    );
    Ok((host.to_owned(), port))
}

/// One controller-authorized peer used for names, ownership, and direct paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub(crate) node: Id,
    pub(crate) name: String,
    pub(crate) overlays: Vec<IpAddr>,
}

/// One fully validated controller route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) id: Id,
    pub(crate) destination: IpNet,
    pub(crate) via: Id,
    pub(crate) kind: RouteKind,
    pub(crate) mode: RouteAdvertisementMode,
    pub(crate) metric: u32,
}

/// Immutable authorization snapshot prepared before any native mutation.
#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) epoch: u64,
    pub(crate) valid_until: u64,
    pub(crate) overlays: Vec<IpNet>,
    pub(crate) peers: HashMap<Id, Peer>,
    pub(crate) routes: Vec<Route>,
    pub(crate) policy: CompiledPolicy,
    pub(crate) enabled_capabilities: u64,
    pub(crate) revoked_serials: HashSet<Vec<u8>>,
    pub(crate) local_certificate_revoked: bool,
    pub(crate) relays: HashMap<Id, RelayAuthority>,
    pub(crate) candidate_exchange: CandidateExchangeAuthority,
    pub(crate) authorized_exits: HashSet<Id>,
    pub(crate) certificate_renew_after: u64,
    pub(crate) certificate_not_after: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct RelayAuthority {
    pub(crate) endpoint: String,
    pub(crate) resolved: Vec<SocketAddr>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CandidateExchangeAuthority {
    pub(crate) enabled: bool,
    pub(crate) max_candidates: u32,
    pub(crate) ttl: Duration,
}

impl Snapshot {
    /// Validates a complete node configuration without publishing or mutating
    /// native state. The caller may therefore apply it transactionally.
    pub(crate) fn compile(
        configuration: NodeConfiguration,
        network: Id,
        local_node: Id,
        local_certificate: &LocalCertificateHealth,
    ) -> Result<Self> {
        let epoch = configuration.configuration_epoch;
        ensure!(epoch > 0, "controller configuration epoch is zero");
        ensure!(
            !expired(configuration.valid_until_unix_seconds),
            "controller configuration lease is expired"
        );
        let enrollment_class = EnrollmentClass::try_from(configuration.enrollment_class)
            .context("controller enrollment class is unknown")?;
        let identity_lease_expires_at = configuration.identity_lease_expires_at_unix_seconds;
        match enrollment_class {
            EnrollmentClass::Unspecified
            | EnrollmentClass::DurableNode
            | EnrollmentClass::RememberedUser => ensure!(
                identity_lease_expires_at == 0,
                "non-ephemeral controller identity has an unexpected lease"
            ),
            EnrollmentClass::EphemeralUser => {
                ensure!(
                    identity_lease_expires_at != 0 && !expired(identity_lease_expires_at),
                    "ephemeral controller identity lease is missing or expired"
                );
                ensure!(
                    configuration.valid_until_unix_seconds <= identity_lease_expires_at,
                    "controller snapshot exceeds the ephemeral identity lease"
                );
            }
        }
        ensure!(
            configuration.peers.len() <= MAX_PEERS,
            "controller peer snapshot exceeds limit"
        );
        ensure!(
            !configuration.relays.is_empty() && configuration.relays.len() <= MAX_RELAYS,
            "controller relay snapshot is outside bounds"
        );
        let mut relays = HashMap::with_capacity(configuration.relays.len());
        let mut relay_names = HashSet::with_capacity(configuration.relays.len());
        for (index, relay) in configuration.relays.iter().enumerate() {
            let service = Id::from_slice(&relay.service_id)
                .with_context(|| format!("controller relay {index} service ID"))?;
            ensure!(
                !relay.name.is_empty()
                    && relay.name.trim() == relay.name
                    && relay.name.len() <= 253
                    && relay_names.insert(relay.name.clone()),
                "controller relay {index} name is invalid or duplicate"
            );
            let (endpoint, resolved) = parse_relay_endpoint(&relay.endpoint)
                .with_context(|| format!("controller relay {index} endpoint"))?;
            ensure!(
                relays
                    .insert(service, RelayAuthority { endpoint, resolved })
                    .is_none(),
                "controller relay {index} is invalid or duplicate"
            );
        }
        let candidate = configuration
            .candidate_exchange
            .as_ref()
            .context("controller configuration omitted candidate exchange policy")?;
        ensure!(
            candidate.max_candidates <= 32
                && candidate.candidate_ttl_seconds <= 600
                && (!candidate.enabled
                    || (candidate.max_candidates > 0 && candidate.candidate_ttl_seconds > 0)),
            "controller candidate exchange policy is outside bounds"
        );
        let candidate_exchange = CandidateExchangeAuthority {
            enabled: candidate.enabled,
            max_candidates: candidate.max_candidates,
            ttl: Duration::from_secs(u64::from(candidate.candidate_ttl_seconds)),
        };
        let route_snapshot = configuration
            .routes
            .context("controller configuration omitted routes")?;
        ensure!(
            route_snapshot.network_id == network.as_bytes()
                && route_snapshot.configuration_epoch == epoch,
            "controller route identity or epoch mismatch"
        );
        ensure!(
            route_snapshot.routes.len() <= MAX_ROUTES,
            "controller route snapshot exceeds limit"
        );
        let policy_snapshot = configuration
            .policy
            .context("controller configuration omitted policy")?;
        ensure!(
            policy_snapshot.default_action == laneway_protocol::v1::PolicyAction::Deny as i32,
            "controller node policy must default deny"
        );
        let policy = CompiledPolicy::compile(policy_snapshot, network, epoch)
            .context("compile controller policy")?;

        let overlays = configuration
            .overlay_addresses
            .into_iter()
            .map(parse_host_prefix)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !overlays.is_empty(),
            "controller assigned no overlay address"
        );
        ensure!(
            unique(&overlays),
            "controller assigned duplicate overlay address"
        );

        let mut peers = HashMap::with_capacity(configuration.peers.len());
        let mut names = HashSet::with_capacity(configuration.peers.len());
        let mut overlay_owners = HashMap::new();
        for (index, input) in configuration.peers.into_iter().enumerate() {
            let node = Id::from_slice(&input.node_id)
                .with_context(|| format!("controller peer {index} node ID"))?;
            ensure!(
                !input.name.is_empty()
                    && input.name.trim() == input.name
                    && input.name.len() <= 253
                    && names.insert(input.name.clone()),
                "controller peer {index} name is invalid or duplicate"
            );
            let peer_overlays = input
                .overlay_addresses
                .into_iter()
                .map(parse_address)
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                !peer_overlays.is_empty() && unique(&peer_overlays),
                "controller peer {index} overlays are missing or duplicate"
            );
            for address in &peer_overlays {
                ensure!(
                    overlay_owners.insert(*address, node).is_none(),
                    "controller overlay address has multiple owners"
                );
            }
            ensure!(
                peers
                    .insert(
                        node,
                        Peer {
                            node,
                            name: input.name,
                            overlays: peer_overlays,
                        },
                    )
                    .is_none(),
                "controller peer node ID is duplicate"
            );
        }
        let local_peer = peers
            .get(&local_node)
            .context("controller peer snapshot omitted local node")?;
        let assigned: HashSet<_> = overlays.iter().map(IpNet::addr).collect();
        ensure!(
            assigned == local_peer.overlays.iter().copied().collect(),
            "controller local overlay assignment differs from peer ownership"
        );

        let allowed_policy_capabilities =
            Capability::LanewaySubnetRouterV1 as u64 | Capability::LanewayExitNodeV1 as u64;
        ensure!(
            configuration.enabled_capabilities & !allowed_policy_capabilities == 0,
            "controller enabled non-policy node capabilities"
        );

        let mut route_ids = HashSet::with_capacity(route_snapshot.routes.len());
        let mut route_keys = HashSet::with_capacity(route_snapshot.routes.len());
        let mut routes = Vec::with_capacity(route_snapshot.routes.len());
        let mut self_hosts = HashSet::new();
        let mut route_exits = HashSet::new();
        for (index, input) in route_snapshot.routes.into_iter().enumerate() {
            let id = Id::from_slice(&input.route_id)
                .with_context(|| format!("controller route {index} ID"))?;
            ensure!(route_ids.insert(id), "controller route ID is duplicate");
            let destination = prefix_from_wire(
                input
                    .destination
                    .context("controller route omitted destination")?,
            )
            .with_context(|| format!("controller route {index} prefix"))?;
            let via = Id::from_slice(&input.via_node_id)
                .with_context(|| format!("controller route {index} next hop"))?;
            ensure!(
                peers.contains_key(&via),
                "controller route next hop is not an active peer"
            );
            let kind = RouteKind::try_from(input.kind)
                .map_err(|_| anyhow::anyhow!("controller route kind is unknown"))?;
            let mode = RouteAdvertisementMode::try_from(input.mode)
                .map_err(|_| anyhow::anyhow!("controller route mode is unknown"))?;
            match kind {
                RouteKind::Overlay => {
                    ensure!(
                        destination.prefix_len() == destination.max_prefix_len()
                            && mode == RouteAdvertisementMode::Unspecified
                            && overlay_owners.get(&destination.addr()) == Some(&via),
                        "controller overlay route is not an owned host route"
                    );
                    if via == local_node {
                        self_hosts.insert(destination.addr());
                    }
                }
                RouteKind::Subnet => {
                    ensure!(
                        destination.prefix_len() > 0
                            && matches!(
                                mode,
                                RouteAdvertisementMode::Nat | RouteAdvertisementMode::Routed
                            ),
                        "controller subnet route is invalid"
                    );
                    if via == local_node {
                        ensure!(
                            configuration.enabled_capabilities
                                & Capability::LanewaySubnetRouterV1 as u64
                                != 0,
                            "local subnet route is not capability-authorized"
                        );
                    }
                }
                RouteKind::Exit => {
                    ensure!(
                        destination.prefix_len() == 0
                            && matches!(
                                mode,
                                RouteAdvertisementMode::Nat | RouteAdvertisementMode::Routed
                            ),
                        "controller exit route is invalid"
                    );
                    if via == local_node {
                        ensure!(
                            configuration.enabled_capabilities
                                & Capability::LanewayExitNodeV1 as u64
                                != 0,
                            "local exit route is not capability-authorized"
                        );
                    }
                    route_exits.insert(via);
                }
                RouteKind::Unspecified => bail!("controller route kind is unspecified"),
            }
            ensure!(
                route_keys.insert((destination, input.metric)),
                "controller route has an ambiguous equal-prefix/equal-metric duplicate"
            );
            routes.push(Route {
                id,
                destination,
                via,
                kind,
                mode,
                metric: input.metric,
            });
        }
        ensure!(
            self_hosts == assigned,
            "controller routes do not exactly own the local overlay assignment"
        );

        let exit_policy = configuration
            .exit_policy
            .as_ref()
            .context("controller configuration omitted exit policy")?;
        let mut authorized_exits = HashSet::with_capacity(exit_policy.authorized_node_ids.len());
        for (index, raw) in exit_policy.authorized_node_ids.iter().enumerate() {
            let node = Id::from_slice(raw)
                .with_context(|| format!("controller exit policy node {index}"))?;
            ensure!(
                authorized_exits.insert(node),
                "controller exit policy node is duplicate"
            );
        }
        ensure!(
            authorized_exits == route_exits,
            "controller exit policy disagrees with approved exit routes"
        );

        let mut revoked_serials = HashSet::new();
        for serial in configuration.revoked_certificate_serials {
            ensure!(
                canonical_serial(&serial) && revoked_serials.insert(serial),
                "controller certificate revocation is invalid or duplicate"
            );
        }
        let local_certificate_revoked = revoked_serials.contains(&local_certificate.serial);
        let health = configuration
            .certificate_health
            .as_ref()
            .context("controller configuration omitted certificate health")?;
        ensure!(
            health.presented_serial == local_certificate.serial
                && health.not_after_unix_seconds == local_certificate.not_after
                && health.renew_after_unix_seconds == local_certificate.renew_after
                && health.revoked == local_certificate_revoked,
            "controller certificate health does not match the presented certificate"
        );
        let certificate_not_after = health.not_after_unix_seconds;
        let certificate_renew_after = health.renew_after_unix_seconds;
        ensure!(
            certificate_not_after > unix_now(),
            "local certificate is expired"
        );
        Ok(Self {
            epoch,
            valid_until: configuration.valid_until_unix_seconds,
            overlays,
            peers,
            routes,
            policy,
            enabled_capabilities: configuration.enabled_capabilities,
            revoked_serials,
            local_certificate_revoked,
            relays,
            candidate_exchange,
            authorized_exits,
            certificate_renew_after,
            certificate_not_after,
        })
    }

    pub(crate) fn expired(&self) -> bool {
        expired(self.valid_until)
    }

    pub(crate) fn renew(&self, valid_until: u64) -> Result<Self> {
        ensure!(!expired(valid_until), "controller renewed an expired lease");
        ensure!(
            valid_until >= self.valid_until,
            "controller lease deadline moved backward"
        );
        Ok(Self {
            valid_until,
            ..self.clone()
        })
    }

    pub(crate) fn authorizes_relay(&self, service: Id, address: Option<SocketAddr>) -> bool {
        self.relays
            .get(&service)
            .is_some_and(|relay| address.is_none_or(|address| relay.resolved.contains(&address)))
    }

    pub(crate) async fn resolve_relays(mut self) -> Result<Self> {
        let mut pending = tokio::task::JoinSet::new();
        for (service, relay) in &self.relays {
            if relay.resolved.is_empty() {
                let endpoint = relay.endpoint.clone();
                let service = *service;
                pending.spawn(async move {
                    let result =
                        tokio::net::lookup_host(endpoint.as_str())
                            .await
                            .map(|addresses| {
                                addresses.take(MAX_RELAY_ADDRESSES + 1).collect::<Vec<_>>()
                            });
                    (service, result)
                });
            }
        }
        let mut results = Vec::new();
        let collect = async {
            while let Some(result) = pending.join_next().await {
                if let Ok((service, Ok(addresses))) = result
                    && addresses.len() <= MAX_RELAY_ADDRESSES
                {
                    results.push((service, addresses));
                }
            }
        };
        if tokio::time::timeout(RELAY_DNS_TIMEOUT, collect)
            .await
            .is_err()
        {
            pending.abort_all();
            while pending.join_next().await.is_some() {}
        }
        merge_relay_resolutions(&mut self.relays, results)?;
        Ok(self)
    }
}

fn parse_relay_endpoint(value: &str) -> Result<(String, Vec<SocketAddr>)> {
    ensure!(
        !value.is_empty() && value.trim() == value,
        "relay endpoint is empty or padded"
    );
    if let Ok(address) = value.parse::<SocketAddr>() {
        ensure!(
            canonical_relay_socket(address).is_some_and(|canonical| canonical == address),
            "relay endpoint address class or port is invalid"
        );
        return Ok((address.to_string(), vec![address]));
    }
    let (host, port) = value
        .rsplit_once(':')
        .context("relay endpoint must be host:port")?;
    ensure!(
        !host.is_empty() && !host.contains(':'),
        "relay DNS host is invalid"
    );
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    ensure!(valid_dns_name(&host), "relay DNS host is invalid");
    let port = port.parse::<u16>().context("relay endpoint port")?;
    ensure!(port != 0, "relay endpoint port is zero");
    Ok((format!("{host}:{port}"), Vec::new()))
}

fn canonical_relay_socket(address: SocketAddr) -> Option<SocketAddr> {
    if address.port() == 0 {
        return None;
    }
    let ip = match address.ip() {
        IpAddr::V4(ip) => {
            if ip.is_unspecified() || ip.is_multicast() || ip.octets() == [255, 255, 255, 255] {
                return None;
            }
            IpAddr::V4(ip)
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return canonical_relay_socket(SocketAddr::new(IpAddr::V4(mapped), address.port()));
            }
            if ip.is_unspecified() || ip.is_multicast() {
                return None;
            }
            IpAddr::V6(ip)
        }
    };
    Some(SocketAddr::new(ip, address.port()))
}

fn valid_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn merge_relay_resolutions(
    relays: &mut HashMap<Id, RelayAuthority>,
    results: Vec<(Id, Vec<SocketAddr>)>,
) -> Result<()> {
    for (service, addresses) in results {
        if let Some(relay) = relays.get_mut(&service) {
            relay
                .resolved
                .extend(addresses.into_iter().filter_map(canonical_relay_socket));
            relay.resolved.sort_unstable();
            relay.resolved.dedup();
        }
    }
    let total = relays
        .values()
        .map(|relay| relay.resolved.len())
        .sum::<usize>();
    ensure!(
        total > 0 && total <= MAX_RESOLVED_RELAY_TARGETS,
        "controller relay authority resolved outside target bounds"
    );
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn bounded_read(path: &std::path::Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("stat {label} {}", path.display()))?;
    ensure!(metadata.len() <= maximum, "{label} exceeds size limit");
    fs::read(path).with_context(|| format!("read {label} {}", path.display()))
}

fn parse_host_prefix(raw: Vec<u8>) -> Result<IpNet> {
    let address = parse_address(raw)?;
    Ok(match address {
        IpAddr::V4(address) => IpNet::V4(Ipv4Net::new(address, 32)?),
        IpAddr::V6(address) => IpNet::V6(Ipv6Net::new(address, 128)?),
    })
}

fn parse_address(raw: Vec<u8>) -> Result<IpAddr> {
    let address = match raw.as_slice() {
        bytes @ [_, _, _, _] => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).expect("length checked"),
        )),
        bytes if bytes.len() == 16 => {
            let address = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).expect("length checked"));
            ensure!(
                address.to_ipv4_mapped().is_none(),
                "mapped IPv4 overlay address is noncanonical"
            );
            IpAddr::V6(address)
        }
        _ => bail!("overlay address length is invalid"),
    };
    ensure!(
        !address.is_unspecified() && !address.is_multicast(),
        "overlay address class is invalid"
    );
    Ok(address)
}

fn canonical_serial(serial: &[u8]) -> bool {
    !serial.is_empty() && serial.len() <= 32 && (serial.len() == 1 || serial[0] != 0)
}

fn unique<T: Eq + std::hash::Hash + Copy>(values: &[T]) -> bool {
    values.iter().copied().collect::<HashSet<_>>().len() == values.len()
}

fn expired(deadline: u64) -> bool {
    deadline
        <= SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::{
        CandidateExchangePolicy, CertificateHealth, ExitNodePolicy, IpPrefix, NodePeer,
        PolicyAction, PolicySnapshot, RelayEndpoint, Route as WireRoute, RouteSnapshot,
    };

    fn id(value: u8) -> Id {
        Id::new([value; 16]).unwrap()
    }

    fn host(address: [u8; 4]) -> IpPrefix {
        IpPrefix {
            address: address.to_vec(),
            prefix_length: 32,
        }
    }

    fn local_certificate() -> LocalCertificateHealth {
        LocalCertificateHealth {
            serial: vec![8],
            not_after: 4_000_000_000,
            renew_after: 3_000_000_000,
        }
    }

    fn valid() -> NodeConfiguration {
        let network = id(1);
        let local = id(2);
        let peer = id(3);
        NodeConfiguration {
            configuration_epoch: 7,
            overlay_addresses: vec![vec![100, 96, 0, 1]],
            routes: Some(RouteSnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: 7,
                routes: vec![
                    WireRoute {
                        destination: Some(host([100, 96, 0, 1])),
                        via_node_id: local.as_bytes().to_vec(),
                        kind: RouteKind::Overlay as i32,
                        metric: 100,
                        route_id: id(10).as_bytes().to_vec(),
                        mode: RouteAdvertisementMode::Unspecified as i32,
                    },
                    WireRoute {
                        destination: Some(host([100, 96, 0, 2])),
                        via_node_id: peer.as_bytes().to_vec(),
                        kind: RouteKind::Overlay as i32,
                        metric: 100,
                        route_id: id(11).as_bytes().to_vec(),
                        mode: RouteAdvertisementMode::Unspecified as i32,
                    },
                ],
            }),
            policy: Some(PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: 7,
                rules: vec![],
                default_action: PolicyAction::Deny as i32,
            }),
            enabled_capabilities: 0,
            valid_until_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            revoked_certificate_serials: vec![vec![9]],
            peers: vec![
                NodePeer {
                    node_id: local.as_bytes().to_vec(),
                    name: "local".to_owned(),
                    overlay_addresses: vec![vec![100, 96, 0, 1]],
                },
                NodePeer {
                    node_id: peer.as_bytes().to_vec(),
                    name: "peer".to_owned(),
                    overlay_addresses: vec![vec![100, 96, 0, 2]],
                },
            ],
            relays: vec![RelayEndpoint {
                service_id: id(4).as_bytes().to_vec(),
                name: "relay-a".to_owned(),
                endpoint: "127.0.0.1:4433".to_owned(),
            }],
            candidate_exchange: Some(CandidateExchangePolicy {
                enabled: true,
                max_candidates: 8,
                candidate_ttl_seconds: 120,
            }),
            exit_policy: Some(ExitNodePolicy {
                authorized_node_ids: vec![],
            }),
            certificate_health: Some(CertificateHealth {
                presented_serial: vec![8],
                not_after_unix_seconds: 4_000_000_000,
                renew_after_unix_seconds: 3_000_000_000,
                revoked: false,
            }),
            enrollment_class: EnrollmentClass::DurableNode as i32,
            identity_lease_expires_at_unix_seconds: 0,
        }
    }

    #[test]
    fn compiles_complete_default_deny_snapshot() {
        let snapshot = Snapshot::compile(valid(), id(1), id(2), &local_certificate()).unwrap();
        assert_eq!(snapshot.epoch, 7);
        assert_eq!(snapshot.peers.len(), 2);
        assert_eq!(snapshot.routes.len(), 2);
        assert!(!snapshot.policy.default_accepts());
        assert!(!snapshot.local_certificate_revoked);
        assert!(!snapshot.expired());
        assert_eq!(snapshot.certificate_renew_after, 3_000_000_000);
        assert_eq!(snapshot.certificate_not_after, 4_000_000_000);
        assert_eq!(snapshot.renew(snapshot.valid_until + 1).unwrap().epoch, 7);
    }

    #[test]
    fn rejects_cross_snapshot_mismatch_and_local_revocation_is_explicit() {
        let mut configuration = valid();
        configuration.routes.as_mut().unwrap().configuration_epoch = 8;
        assert!(Snapshot::compile(configuration, id(1), id(2), &local_certificate()).is_err());

        let mut configuration = valid();
        configuration.revoked_certificate_serials.push(vec![8]);
        configuration.certificate_health.as_mut().unwrap().revoked = true;
        let snapshot =
            Snapshot::compile(configuration, id(1), id(2), &local_certificate()).unwrap();
        assert!(snapshot.local_certificate_revoked);
    }

    #[test]
    fn enforces_ephemeral_identity_lease() {
        let now = unix_now();
        let mut configuration = valid();
        configuration.enrollment_class = EnrollmentClass::EphemeralUser as i32;
        configuration.valid_until_unix_seconds = now + 60;
        configuration.identity_lease_expires_at_unix_seconds = now + 120;
        Snapshot::compile(configuration.clone(), id(1), id(2), &local_certificate()).unwrap();

        configuration.valid_until_unix_seconds = now + 121;
        assert!(
            Snapshot::compile(configuration.clone(), id(1), id(2), &local_certificate()).is_err()
        );
        configuration.valid_until_unix_seconds = now + 60;
        configuration.identity_lease_expires_at_unix_seconds = now;
        assert!(
            Snapshot::compile(configuration.clone(), id(1), id(2), &local_certificate()).is_err()
        );
        configuration.enrollment_class = EnrollmentClass::DurableNode as i32;
        assert!(Snapshot::compile(configuration, id(1), id(2), &local_certificate()).is_err());
    }

    #[test]
    fn rejects_missing_self_route_and_ambiguous_route() {
        let mut configuration = valid();
        configuration.routes.as_mut().unwrap().routes.remove(0);
        assert!(Snapshot::compile(configuration, id(1), id(2), &local_certificate()).is_err());

        let mut configuration = valid();
        let duplicate = configuration.routes.as_ref().unwrap().routes[1].clone();
        let mut duplicate = WireRoute {
            route_id: id(12).as_bytes().to_vec(),
            ..duplicate
        };
        duplicate.metric = 100;
        configuration
            .routes
            .as_mut()
            .unwrap()
            .routes
            .push(duplicate);
        assert!(Snapshot::compile(configuration, id(1), id(2), &local_certificate()).is_err());
    }

    #[test]
    fn relay_endpoint_dns_is_canonical_and_resolution_is_bounded() {
        let (endpoint, resolved) = parse_relay_endpoint("Relay-New.Example.:4433").unwrap();
        assert_eq!(endpoint, "relay-new.example:4433");
        assert!(resolved.is_empty());
        let (endpoint, resolved) = parse_relay_endpoint("[2001:db8::1]:4433").unwrap();
        assert_eq!(endpoint, "[2001:db8::1]:4433");
        assert_eq!(resolved, vec!["[2001:db8::1]:4433".parse().unwrap()]);
        for invalid in [
            "bad_host:4433",
            "-bad.example:4433",
            "bad..example:4433",
            "example:0",
            "0.0.0.0:4433",
            "224.0.0.1:4433",
            "255.255.255.255:4433",
            "[::]:4433",
            "[ff02::1]:4433",
            "[::ffff:192.0.2.1]:4433",
        ] {
            assert!(parse_relay_endpoint(invalid).is_err(), "accepted {invalid}");
        }

        let dns = id(4);
        let numeric = id(5);
        let numeric_address: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let mut relays = HashMap::from([
            (
                dns,
                RelayAuthority {
                    endpoint: "relay.example:4433".to_owned(),
                    resolved: Vec::new(),
                },
            ),
            (
                numeric,
                RelayAuthority {
                    endpoint: numeric_address.to_string(),
                    resolved: vec![numeric_address],
                },
            ),
        ]);
        let dns_address: SocketAddr = "192.0.2.10:4433".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.11]:4433".parse().unwrap();
        let mapped_canonical: SocketAddr = "192.0.2.11:4433".parse().unwrap();
        let unusable = [
            "0.0.0.0:4433",
            "224.0.0.1:4433",
            "255.255.255.255:4433",
            "[::]:4433",
            "[ff02::1]:4433",
        ]
        .into_iter()
        .map(str::parse)
        .collect::<std::result::Result<Vec<SocketAddr>, _>>()
        .unwrap();
        let mut answers = vec![dns_address, dns_address, mapped];
        answers.extend(unusable);
        merge_relay_resolutions(&mut relays, vec![(dns, answers)]).unwrap();
        assert_eq!(relays[&dns].resolved, vec![dns_address, mapped_canonical]);

        // One unresolved authority does not suppress another usable target.
        relays.get_mut(&dns).unwrap().resolved.clear();
        merge_relay_resolutions(&mut relays, Vec::new()).unwrap();
        relays.get_mut(&numeric).unwrap().resolved.clear();
        assert!(merge_relay_resolutions(&mut relays, Vec::new()).is_err());
    }
}
