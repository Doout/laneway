use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU64,
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
    relay_endpoint::{MAX_RELAY_ENDPOINTS, canonical_host_port},
    v1::{
        Capability, ConfigurationRequest, EnrollmentClass, NodeConfiguration,
        RouteAdvertisementMode, RouteKind,
    },
};
use prost::Message;
use quinn::{Endpoint, TransportConfig, VarInt, crypto::rustls::QuicClientConfig};
use reqwest::StatusCode;
#[cfg(test)]
use rustls::RootCertStore;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::tls::LocalCertificateHealth;

const MAX_RESPONSE: usize = 1 << 20;
const VALID_UNTIL_HEADER: &str = "X-Laneway-Configuration-Valid-Until";
const MAX_PEERS: usize = 65_536;
const MAX_ROUTES: usize = 65_536;
const MAX_RELAY_ADDRESSES: usize = 16;
const MAX_RESOLVED_RELAY_TARGETS: usize = 128;
const RELAY_DNS_TIMEOUT: Duration = Duration::from_secs(5);
const EXIT_REVOKE_AFTER_SUSPECT_SECONDS: u64 = 40;

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
    pub(crate) exit_generation: Option<NonZeroU64>,
}

/// One bounded conditional controller response.
#[derive(Debug)]
pub(crate) enum PollResult {
    Modified(Box<NodeConfiguration>),
    NotModified { valid_until: u64 },
}

#[derive(Debug)]
pub(crate) struct AuthorityRejected(laneway_protocol::v1::ErrorCode);

impl std::fmt::Display for AuthorityRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "controller rejected node authority: {:?}", self.0)
    }
}

impl std::error::Error for AuthorityRejected {}

/// Strict HTTPS/protobuf controller snapshot client.
pub(crate) struct Client {
    options: ClientOptions,
    http_origin: reqwest::Url,
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
        ensure!(
            options.exit_generation.is_none() || options.quic_endpoint.is_some(),
            "ephemeral Exit authority requires controller QUIC"
        );
        let (url, http_origin) = controller_origins(&options.endpoint, &options.server_name)?;
        let host = origin_host(&url);
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
        let expected = expected_controller(options.network, options.service);
        let mut https = controller_tls(&options, expected)?;
        https.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .use_preconfigured_tls(https)
            .timeout(options.timeout)
            .tls_info(true);
        let tls_host = origin_host(&http_origin);
        if tls_host.parse::<IpAddr>().is_err() {
            builder = builder.resolve_to_addrs(tls_host, &resolved);
        }
        let http = builder
            .build()
            .context("build node controller HTTP client")?;
        let quic = if let Some(endpoint) = options.quic_endpoint.as_deref() {
            Some(QuicControl::new(endpoint, &options, expected).await?)
        } else {
            None
        };
        if let Some(control) = &quic {
            resolved.extend(control.addresses.iter().copied());
            resolved.sort_unstable();
            resolved.dedup();
        }
        Ok(Self {
            options: options.clone(),
            http_origin,
            http,
            expected_controller: expected,
            resolved,
            quic,
        })
    }

    pub(crate) fn resolved_ips(&self) -> Vec<IpAddr> {
        self.resolved.iter().map(SocketAddr::ip).collect()
    }

    pub(crate) fn exit_generation(&self) -> Option<NonZeroU64> {
        self.options.exit_generation
    }

    pub(crate) fn begin_quic_shutdown(&self) {
        if let Some(control) = &self.quic {
            control
                .endpoint
                .close(0_u32.into(), b"node control shutdown");
        }
    }

    pub(crate) async fn close_quic(&self) {
        self.begin_quic_shutdown();
        if let Some(control) = &self.quic {
            let _ =
                tokio::time::timeout(Duration::from_secs(2), control.endpoint.wait_idle()).await;
        }
    }

    pub(crate) async fn reconnect_quic(&self) {
        if let Some(control) = &self.quic {
            control
                .invalidate(b"ephemeral Exit proof of possession required")
                .await;
        }
    }

    pub(crate) async fn report_status(
        &self,
        report: &laneway_protocol::endpoint_status::Report,
    ) -> Result<()> {
        report.validate().map_err(anyhow::Error::msg)?;
        let response = self
            .http
            .put(self.http_origin.join("/v1/status")?)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(report)?)
            .send()
            .await
            .context("send endpoint health report")?;
        ensure!(
            response.status() == StatusCode::NO_CONTENT,
            "controller endpoint health returned {}",
            response.status()
        );
        Ok(())
    }

    pub(crate) async fn with_certificate(&self, path: PathBuf) -> Result<Self> {
        let mut options = self.options.clone();
        options.certificate = path;
        Self::new(options).await
    }

    pub(crate) async fn renew_certificate(
        &self,
        csr: Vec<u8>,
    ) -> Result<laneway_protocol::v1::RenewalResponse> {
        ensure!(
            self.exit_generation().is_none(),
            "ephemeral Exit certificates cannot be renewed by the runtime"
        );
        use laneway_protocol::v1::{ControllerEnvelope, RenewalRequest, controller_envelope::Body};
        let control = self
            .quic
            .as_ref()
            .context("renewal requires authenticated controller QUIC")?;
        // Omitting the WireGuard key is the protocol's preserve-current-binding
        // operation. Certificate maintenance must never rotate dataplane keys.
        let request = ControllerEnvelope {
            schema_version: 1,
            request_id: control.next_request_id(),
            body: Some(Body::RenewalRequest(RenewalRequest {
                pkcs10_csr_der: csr,
                wireguard_public_key: Vec::new(),
            })),
        };
        match control.exchange(request).await?.body {
            Some(Body::RenewalResponse(reply)) => Ok(reply),
            Some(Body::Error(e)) => bail!("controller refused node renewal: {:?}", e.code()),
            _ => bail!("unexpected controller renewal response"),
        }
    }

    pub(crate) async fn poll(&self, known_epoch: u64) -> Result<PollResult> {
        if let Some(control) = &self.quic {
            return control.poll(known_epoch, self.exit_generation()).await;
        }
        let request = ConfigurationRequest {
            known_configuration_epoch: known_epoch,
            ephemeral_exit_lease_generation: 0,
        }
        .encode_to_vec();
        let mut response = self
            .http
            .post(self.http_origin.join("/v1/configuration")?)
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

pub(crate) fn controller_origins(
    endpoint: &str,
    tls_name: &str,
) -> Result<(reqwest::Url, reqwest::Url)> {
    let dial = reqwest::Url::parse(endpoint).context("parse controller endpoint")?;
    ensure!(
        dial.scheme() == "https"
            && dial.host_str().is_some()
            && dial.username().is_empty()
            && dial.password().is_none()
            && dial.query().is_none()
            && dial.fragment().is_none()
            && matches!(dial.path(), "" | "/"),
        "controller endpoint must be an HTTPS origin"
    );
    let mut https = dial.clone();
    if !tls_name.is_empty() && origin_host(&dial) != tls_name {
        // Resolve only the configured dial endpoint; present the certificate's
        // DNS name as SNI. This permits the Docker service alias without DNS
        // queries to the public certificate name or relaxing its verification.
        ensure!(
            matches!(ServerName::try_from(tls_name), Ok(ServerName::DnsName(_))),
            "a distinct controller TLS name must be a DNS name"
        );
        https
            .set_host(Some(tls_name))
            .context("set controller TLS host")?;
        ensure!(
            origin_host(&https) == tls_name && tls_name.parse::<IpAddr>().is_err(),
            "controller TLS name must be a canonical DNS name"
        );
    }
    Ok((dial, https))
}

fn origin_host(url: &reqwest::Url) -> &str {
    url.host_str()
        .expect("validated controller origin")
        .trim_matches(['[', ']'])
}

fn expected_controller(network: Id, service: Id) -> AuthenticatedIdentity {
    AuthenticatedIdentity {
        network_id: network,
        role: Role::Controller,
        subject_id: service,
    }
}

#[derive(Debug)]
struct PinnedController {
    expected: AuthenticatedIdentity,
    web: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for PinnedController {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let valid = self
            .web
            .verify_server_cert(leaf, intermediates, server_name, ocsp, now)?;
        // The normal chain and host checks are necessary but not sufficient.
        // Verify the exact controller role/network/service before sending
        // the client's certificate or any HTTP request body.
        let identity = identity_from_certificate_der(leaf.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if identity != self.expected {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(valid)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.web.verify_tls12_signature(message, cert, signed)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.web.verify_tls13_signature(message, cert, signed)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.web.supported_verify_schemes()
    }
}

fn controller_tls(
    options: &ClientOptions,
    expected: AuthenticatedIdentity,
) -> Result<rustls::ClientConfig> {
    let certificates = crate::tls::load_certificates(&options.certificate)?;
    let key = crate::tls::load_private_key(&options.private_key)?;
    let roots = crate::tls::root_store(&options.ca)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let web = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
        .build()?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedController { expected, web }))
        .with_client_auth_cert(certificates, key)
        .context("load node controller identity")?;
    if options.exit_generation.is_some() {
        config.resumption = rustls::client::Resumption::disabled();
    }
    Ok(config)
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

        let mut crypto = controller_tls(options, expected)?;
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

    async fn poll(&self, known_epoch: u64, generation: Option<NonZeroU64>) -> Result<PollResult> {
        use laneway_protocol::v1::{ControllerEnvelope, controller_envelope};
        let envelope = ControllerEnvelope {
            schema_version: 1,
            request_id: self.next_request_id(),
            body: Some(controller_envelope::Body::ConfigurationRequest(
                ConfigurationRequest {
                    known_configuration_epoch: known_epoch,
                    ephemeral_exit_lease_generation: generation.map_or(0, NonZeroU64::get),
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
                    generation.is_none()
                        && lease.ephemeral_exit_lease_generation == 0
                        && lease.ephemeral_exit_suspect_at_unix_seconds == 0
                        && lease.ephemeral_exit_revoke_at_unix_seconds == 0,
                    "ephemeral Exit heartbeat requires a complete snapshot"
                );
                ensure!(
                    known_epoch != 0
                        && lease.configuration_epoch == known_epoch
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
                    self.invalidate(b"controller authorization rejected").await;
                    return Err(AuthorityRejected(error.code()).into());
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

    async fn invalidate(&self, reason: &'static [u8]) {
        if let Some(connection) = self.connection.lock().await.take() {
            connection.close(0_u32.into(), reason);
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
    pub(crate) wireguard_key: Option<[u8; 32]>,
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
    pub(crate) identity_lease_expires_at: u64,
    pub(crate) ephemeral_exit: Option<EphemeralExitLease>,
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
pub(crate) struct EphemeralExitLease {
    generation: NonZeroU64,
    suspect_at: u64,
    revoke_at: u64,
    snapshot_digest: [u8; 32],
}

impl EphemeralExitLease {
    fn from_wire(
        configuration: &mut NodeConfiguration,
        generation: Option<NonZeroU64>,
        class: EnrollmentClass,
    ) -> Result<Option<Self>> {
        let wire_generation = configuration.ephemeral_exit_lease_generation;
        let suspect_at = configuration.ephemeral_exit_suspect_at_unix_seconds;
        let revoke_at = configuration.ephemeral_exit_revoke_at_unix_seconds;
        let exit_capability = Capability::LanewayExitNodeV1 as u64;
        let Some(generation) = generation else {
            ensure!(
                wire_generation == 0
                    && suspect_at == 0
                    && revoke_at == 0
                    && !(class == EnrollmentClass::EphemeralUser
                        && configuration.enabled_capabilities & exit_capability != 0),
                "ordinary node received ephemeral Exit authority"
            );
            return Ok(None);
        };
        ensure!(
            class == EnrollmentClass::EphemeralUser
                && configuration.enabled_capabilities == exit_capability
                && wire_generation == generation.get(),
            "ephemeral Exit enrollment or lease generation differs from bootstrap"
        );
        ensure!(
            !expired(suspect_at)
                && revoke_at.checked_sub(suspect_at) == Some(EXIT_REVOKE_AFTER_SUSPECT_SECONDS)
                && revoke_at <= i64::MAX as u64
                && configuration.valid_until_unix_seconds <= suspect_at,
            "invalid ephemeral Exit heartbeat deadlines"
        );
        // Renewals may change only these clocks at the same epoch. Hash all
        // other wire fields, including keys and policy not used by this actor.
        let valid_until = std::mem::take(&mut configuration.valid_until_unix_seconds);
        configuration.ephemeral_exit_suspect_at_unix_seconds = 0;
        configuration.ephemeral_exit_revoke_at_unix_seconds = 0;
        let snapshot_digest = Sha256::digest(configuration.encode_to_vec()).into();
        configuration.valid_until_unix_seconds = valid_until;
        configuration.ephemeral_exit_suspect_at_unix_seconds = suspect_at;
        configuration.ephemeral_exit_revoke_at_unix_seconds = revoke_at;
        Ok(Some(Self {
            generation,
            suspect_at,
            revoke_at,
            snapshot_digest,
        }))
    }
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
        Self::compile_for(configuration, network, local_node, local_certificate, None)
    }

    pub(crate) fn compile_for(
        mut configuration: NodeConfiguration,
        network: Id,
        local_node: Id,
        local_certificate: &LocalCertificateHealth,
        exit_generation: Option<NonZeroU64>,
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
                    identity_lease_expires_at <= i64::MAX as u64
                        && !expired(identity_lease_expires_at),
                    "ephemeral controller identity lease is missing or expired"
                );
                ensure!(
                    configuration.valid_until_unix_seconds <= identity_lease_expires_at,
                    "controller snapshot exceeds the ephemeral identity lease"
                );
            }
        }
        let ephemeral_exit =
            EphemeralExitLease::from_wire(&mut configuration, exit_generation, enrollment_class)?;
        ensure!(
            configuration.peers.len() <= MAX_PEERS,
            "controller peer snapshot exceeds limit"
        );
        ensure!(
            !configuration.relays.is_empty() && configuration.relays.len() <= MAX_RELAY_ENDPOINTS,
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
        let mut wireguard_keys = HashSet::new();
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
            let wireguard_key = if input.wireguard_public_key.is_empty() {
                None
            } else {
                let key: [u8; 32] = input
                    .wireguard_public_key
                    .as_slice()
                    .try_into()
                    .context("controller WireGuard public key has the wrong length")?;
                ensure!(
                    key != [0; 32] && wireguard_keys.insert(key),
                    "controller WireGuard public key is zero or has multiple owners"
                );
                Some(key)
            };
            ensure!(
                peers
                    .insert(
                        node,
                        Peer {
                            node,
                            name: input.name,
                            overlays: peer_overlays,
                            wireguard_key,
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
        ensure!(
            ephemeral_exit.is_none()
                || configuration.valid_until_unix_seconds <= certificate_not_after,
            "ephemeral Exit configuration exceeds the certificate lifetime"
        );
        Ok(Self {
            epoch,
            valid_until: configuration.valid_until_unix_seconds,
            identity_lease_expires_at,
            ephemeral_exit,
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

    pub(crate) fn wireguard_authority_expired(&self) -> bool {
        self.expired() || expired(self.certificate_not_after)
    }

    /// A shorter snapshot lease can mean an earlier peer or route deadline.
    /// Only the explicit heartbeat boundary is eligible for disconnect drain.
    pub(crate) fn wireguard_drain_eligible(&self) -> bool {
        self.ephemeral_exit.as_ref().is_some_and(|lease| {
            self.valid_until == lease.suspect_at
                && self.expired()
                && self
                    .exit_terminal_at()
                    .is_some_and(|deadline| !expired(deadline))
                && !self.local_certificate_revoked
        })
    }

    pub(crate) fn renew(&self, valid_until: u64) -> Result<Self> {
        ensure!(
            self.ephemeral_exit.is_none(),
            "ephemeral Exit cannot renew from a bare lease"
        );
        ensure!(
            self.identity_lease_expires_at == 0 || valid_until <= self.identity_lease_expires_at,
            "controller renewal exceeds the identity lease"
        );
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

    pub(crate) fn exit_terminal_at(&self) -> Option<u64> {
        self.ephemeral_exit.as_ref().map(|lease| {
            lease
                .revoke_at
                .min(self.identity_lease_expires_at)
                .min(self.certificate_not_after)
        })
    }

    pub(crate) fn exit_generation(&self) -> Option<NonZeroU64> {
        self.ephemeral_exit.as_ref().map(|lease| lease.generation)
    }

    pub(crate) fn validate_exit_successor(&self, next: &Self) -> Result<()> {
        let (Some(old), Some(new)) = (&self.ephemeral_exit, &next.ephemeral_exit) else {
            ensure!(
                self.ephemeral_exit.is_none() && next.ephemeral_exit.is_none(),
                "node cannot switch into or out of ephemeral Exit authority"
            );
            return Ok(());
        };
        ensure!(
            !expired(
                self.exit_terminal_at()
                    .expect("ephemeral Exit has terminal deadline")
            ) && old.generation == new.generation
                && self.identity_lease_expires_at == next.identity_lease_expires_at
                && self.overlays == next.overlays
                && next.epoch >= self.epoch
                && new.suspect_at >= old.suspect_at
                && new.revoke_at >= old.revoke_at
                && !next.expired(),
            "ephemeral Exit authority moved backward or changed its enrollment"
        );
        if next.epoch == self.epoch {
            ensure!(
                next.valid_until >= self.valid_until && old.snapshot_digest == new.snapshot_digest,
                "ephemeral Exit heartbeat changed configuration without a newer epoch"
            );
        }
        Ok(())
    }

    /// Keep the already installed routing table on a heartbeat at the same epoch.
    pub(crate) fn renew_exit(&self, next: Self) -> Result<Self> {
        self.validate_exit_successor(&next)?;
        ensure!(
            self.ephemeral_exit.is_some() && self.epoch == next.epoch,
            "expected a same-epoch ephemeral Exit heartbeat"
        );
        Ok(Self {
            valid_until: next.valid_until,
            ephemeral_exit: next.ephemeral_exit,
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
    let canonical = canonical_host_port(value).context("invalid relay endpoint")?;
    let addresses = canonical.parse::<SocketAddr>().into_iter().collect();
    Ok((canonical, addresses))
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
pub(crate) mod tests {
    use super::*;
    use laneway_protocol::v1::{
        CandidateExchangePolicy, CertificateHealth, ExitNodePolicy, IpPrefix, NodePeer,
        PolicyAction, PolicySnapshot, RelayEndpoint, Route as WireRoute, RouteSnapshot,
    };

    pub(crate) fn id(value: u8) -> Id {
        Id::new([value; 16]).unwrap()
    }

    #[test]
    fn controller_dial_origin_can_differ_from_the_authenticated_dns_name() {
        let (dial, https) =
            controller_origins("https://controller:8443", "internal.example.test").unwrap();
        assert_eq!(dial.as_str(), "https://controller:8443/");
        assert_eq!(https.as_str(), "https://internal.example.test:8443/");
        assert!(controller_origins("https://controller:8443", "10.0.0.3").is_err());
        assert!(
            controller_origins("https://controller:8443", "internal.example.test/api").is_err()
        );
        assert!(
            controller_origins("https://user@controller:8443", "internal.example.test").is_err()
        );
        assert!(
            controller_origins("https://controller:8443/api", "internal.example.test").is_err()
        );
        let (_, ipv6) = controller_origins("https://[::1]:8443", "::1").unwrap();
        assert_eq!(ipv6.as_str(), "https://[::1]:8443/");
    }

    #[test]
    fn controller_requires_both_hostname_and_exact_service_identity() {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            SanType,
        };
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&key).unwrap();
        let issuer = Issuer::new(ca_params, key);
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let web = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let (network, service) = (id(1), id(2));
        let pinned = PinnedController {
            expected: expected_controller(network, service),
            web,
        };
        let name = ServerName::try_from("controller.test").unwrap();
        for (host, role, subject, accepted) in [
            ("controller.test", "controller", service, true),
            ("controller.test", "relay", service, false),
            ("controller.test", "controller", id(3), false),
            ("other.test", "controller", service, false),
        ] {
            let mut params = CertificateParams::new(vec![host.to_owned()]).unwrap();
            params.subject_alt_names.push(SanType::URI(
                format!("spiffe://laneway/network/{network}/{role}/{subject}")
                    .try_into()
                    .unwrap(),
            ));
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let leaf = params
                .signed_by(&KeyPair::generate().unwrap(), &issuer)
                .unwrap();
            assert_eq!(
                pinned
                    .verify_server_cert(leaf.der(), &[], &name, &[], UnixTime::now())
                    .is_ok(),
                accepted
            );
        }
    }

    fn host(address: [u8; 4]) -> IpPrefix {
        IpPrefix {
            address: address.to_vec(),
            prefix_length: 32,
        }
    }

    pub(crate) fn local_certificate() -> LocalCertificateHealth {
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
                    wireguard_public_key: vec![1; 32],
                },
                NodePeer {
                    node_id: peer.as_bytes().to_vec(),
                    name: "peer".to_owned(),
                    overlay_addresses: vec![vec![100, 96, 0, 2]],
                    wireguard_public_key: vec![2; 32],
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
            ephemeral_exit_lease_generation: 0,
            ephemeral_exit_suspect_at_unix_seconds: 0,
            ephemeral_exit_revoke_at_unix_seconds: 0,
        }
    }

    pub(crate) const EXIT_TEST_GENERATION: u64 = 17;

    #[test]
    fn wireguard_drain_is_only_for_the_heartbeat_boundary_and_before_terminal() -> Result<()> {
        let wire = ephemeral_configuration();
        let now = unix_now();
        let mut snapshot = Snapshot::compile_for(
            wire,
            id(1),
            id(2),
            &local_certificate(),
            NonZeroU64::new(EXIT_TEST_GENERATION),
        )?;
        assert!(!snapshot.wireguard_drain_eligible());
        snapshot
            .ephemeral_exit
            .as_mut()
            .expect("test lease")
            .suspect_at = now;
        snapshot.valid_until = now - 1;
        assert!(
            !snapshot.wireguard_drain_eligible(),
            "an earlier deadline fails closed"
        );
        snapshot.valid_until = now;
        assert!(
            snapshot.wireguard_drain_eligible(),
            "the heartbeat boundary can drain"
        );
        snapshot.identity_lease_expires_at = now;
        assert!(
            !snapshot.wireguard_drain_eligible(),
            "the enrollment lease ends drain"
        );
        Ok(())
    }

    pub(crate) fn ephemeral_configuration() -> NodeConfiguration {
        let mut configuration = valid();
        let now = unix_now();
        configuration.enrollment_class = EnrollmentClass::EphemeralUser as i32;
        configuration.enabled_capabilities = Capability::LanewayExitNodeV1 as u64;
        configuration.identity_lease_expires_at_unix_seconds = now + 120;
        configuration.valid_until_unix_seconds = now + 20;
        configuration.ephemeral_exit_lease_generation = EXIT_TEST_GENERATION;
        configuration.ephemeral_exit_suspect_at_unix_seconds = now + 20;
        configuration.ephemeral_exit_revoke_at_unix_seconds = now + 60;
        configuration
    }

    #[test]
    fn ephemeral_heartbeat_only_renews_the_bound_exit_and_unchanged_snapshot() {
        let wire = ephemeral_configuration();
        let cert = local_certificate();
        let compile = |wire| {
            Snapshot::compile_for(
                wire,
                id(1),
                id(2),
                &cert,
                NonZeroU64::new(EXIT_TEST_GENERATION),
            )
        };
        assert!(Snapshot::compile(wire.clone(), id(1), id(2), &cert).is_err());
        assert!(
            Snapshot::compile_for(
                wire.clone(),
                id(1),
                id(2),
                &cert,
                NonZeroU64::new(EXIT_TEST_GENERATION + 1)
            )
            .is_err()
        );
        let initial = compile(wire.clone()).unwrap();
        assert!(initial.renew(initial.valid_until + 1).is_err());
        assert_eq!(
            initial.exit_terminal_at(),
            Some(wire.ephemeral_exit_revoke_at_unix_seconds)
        );
        let mut next = wire.clone();
        next.valid_until_unix_seconds += 5;
        next.ephemeral_exit_suspect_at_unix_seconds += 5;
        next.ephemeral_exit_revoke_at_unix_seconds += 5;
        let renewed = initial.renew_exit(compile(next.clone()).unwrap()).unwrap();
        assert_eq!(renewed.valid_until, initial.valid_until + 5);
        assert!(renewed.renew_exit(compile(wire.clone()).unwrap()).is_err());
        let mut peers_changed = next.clone();
        peers_changed.peers[1].wireguard_public_key[0] ^= 1;
        assert!(initial.renew_exit(compile(peers_changed).unwrap()).is_err());
        let mut extended = next.clone();
        extended.identity_lease_expires_at_unix_seconds += 1;
        assert!(initial.renew_exit(compile(extended).unwrap()).is_err());
        next.ephemeral_exit_revoke_at_unix_seconds += 1;
        assert!(compile(next).is_err());
        let mut inconsistent = wire;
        inconsistent.valid_until_unix_seconds =
            inconsistent.ephemeral_exit_suspect_at_unix_seconds + 1;
        assert!(compile(inconsistent).is_err());
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
        let snapshot =
            Snapshot::compile(configuration.clone(), id(1), id(2), &local_certificate()).unwrap();
        assert!(snapshot.renew(now + 121).is_err());

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
