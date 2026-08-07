use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use arc_swap::ArcSwapOption;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use laneway_protocol::{
    AuthenticatedIdentity, Id, Role, certificate_serial_from_der, identity_from_certificate_der,
    policy::CompiledPolicy,
    v1::{IpPrefix, PolicySnapshot, RelayConfiguration, RelayConfigurationRequest},
};
use prost::Message;
use quinn::{Endpoint, TransportConfig, VarInt, crypto::rustls::QuicClientConfig};
use reqwest::{Certificate, Identity, StatusCode};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep;
use x509_parser::parse_x509_certificate;

use crate::Metrics;
use crate::config::{Authorization, Config, ControllerConfig};

const MAX_RESPONSE: usize = 1 << 20;
const VALID_UNTIL_HEADER: &str = "X-Laneway-Configuration-Valid-Until";

#[derive(Clone)]
pub(crate) struct Snapshot {
    pub(crate) epoch: u64,
    valid_until: u64,
    authorizations: HashMap<AuthenticatedIdentity, Authorization>,
    policy: Policy,
    revoked_serials: HashSet<Vec<u8>>,
    certificate_renew_after: u64,
    certificate_not_after: u64,
}

#[derive(Clone)]
struct LocalCertificateHealth {
    serial: Vec<u8>,
    not_after: u64,
    renew_after: u64,
}

pub(crate) struct State {
    network: Id,
    current: ArcSwapOption<Snapshot>,
    update: Mutex<()>,
    local_certificate: Option<LocalCertificateHealth>,
    metrics: Option<Arc<Metrics>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketRejection {
    Credential,
    Source,
    Destination,
    Policy,
}

pub(crate) struct PacketPeer<'a> {
    pub(crate) identity: &'a AuthenticatedIdentity,
    pub(crate) certificate_serial: &'a [u8],
    pub(crate) fallback: &'a Authorization,
    pub(crate) address: IpAddr,
}

pub(crate) struct PacketAuthorization<'a> {
    pub(crate) source: PacketPeer<'a>,
    pub(crate) destination: PacketPeer<'a>,
    pub(crate) packet: &'a [u8],
}

impl State {
    pub(crate) fn static_snapshot(
        authorizations: HashMap<AuthenticatedIdentity, Authorization>,
    ) -> Arc<Self> {
        let network = authorizations
            .keys()
            .next()
            .map_or_else(|| Id::new([1; 16]).unwrap(), |id| id.network_id);
        Arc::new(Self {
            network,
            current: ArcSwapOption::from(Some(Arc::new(Snapshot {
                epoch: 1,
                valid_until: u64::MAX,
                authorizations,
                policy: Policy::Accept,
                revoked_serials: HashSet::new(),
                certificate_renew_after: 0,
                certificate_not_after: 0,
            }))),
            update: Mutex::new(()),
            local_certificate: None,
            metrics: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn controller(network: Id) -> Arc<Self> {
        Arc::new(Self {
            network,
            current: ArcSwapOption::empty(),
            update: Mutex::new(()),
            local_certificate: None,
            metrics: None,
        })
    }

    pub(crate) fn controller_with_certificate(
        network: Id,
        certificate: &PathBuf,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<Self>> {
        let certificates = read_certificates(certificate, 4 << 20, "relay certificate")?;
        let der = certificates
            .first()
            .context("relay certificate chain is empty")?
            .as_ref();
        let (_, parsed) = parse_x509_certificate(der)
            .map_err(|_| anyhow::anyhow!("parse relay certificate health"))?;
        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();
        ensure!(
            not_before > 0 && not_after > not_before,
            "relay certificate validity is invalid"
        );
        Ok(Arc::new(Self {
            network,
            current: ArcSwapOption::empty(),
            update: Mutex::new(()),
            local_certificate: Some(LocalCertificateHealth {
                serial: certificate_serial_from_der(der).context("relay certificate serial")?,
                not_after: u64::try_from(not_after)?,
                renew_after: u64::try_from(not_before + (not_after - not_before) * 2 / 3)?,
            }),
            metrics: Some(metrics),
        }))
    }

    pub(crate) fn authorize_credential(
        &self,
        identity: &AuthenticatedIdentity,
        certificate_serial: &[u8],
    ) -> Option<Authorization> {
        let snapshot = self.current.load_full()?;
        if identity.network_id != self.network || expired(snapshot.valid_until) {
            return None;
        }
        if snapshot.revoked_serials.contains(certificate_serial) {
            return None;
        }
        snapshot.authorizations.get(identity).cloned()
    }

    pub(crate) fn credential_authorized_with_fallback(
        &self,
        identity: &AuthenticatedIdentity,
        certificate_serial: &[u8],
    ) -> bool {
        let Some(snapshot) = self.current.load_full() else {
            return false;
        };
        if expired(snapshot.valid_until) {
            return false;
        }
        if !certificate_serial.is_empty() && snapshot.revoked_serials.contains(certificate_serial) {
            return false;
        }
        if snapshot.authorizations.is_empty() && matches!(snapshot.policy, Policy::Accept) {
            return identity.network_id == self.network;
        }
        snapshot.authorizations.contains_key(identity)
    }

    pub(crate) fn authorize_packet(
        &self,
        request: PacketAuthorization<'_>,
    ) -> std::result::Result<(), PacketRejection> {
        let snapshot = self
            .current
            .load_full()
            .ok_or(PacketRejection::Credential)?;
        if request.source.identity.network_id != self.network
            || request.destination.identity.network_id != self.network
            || expired(snapshot.valid_until)
            || (!request.source.certificate_serial.is_empty()
                && snapshot
                    .revoked_serials
                    .contains(request.source.certificate_serial))
            || (!request.destination.certificate_serial.is_empty()
                && snapshot
                    .revoked_serials
                    .contains(request.destination.certificate_serial))
        {
            return Err(PacketRejection::Credential);
        }
        let static_fallback =
            snapshot.authorizations.is_empty() && matches!(snapshot.policy, Policy::Accept);
        let source_authorization = if static_fallback {
            request.source.fallback
        } else {
            snapshot
                .authorizations
                .get(request.source.identity)
                .ok_or(PacketRejection::Credential)?
        };
        let destination_authorization = if static_fallback {
            request.destination.fallback
        } else {
            snapshot
                .authorizations
                .get(request.destination.identity)
                .ok_or(PacketRejection::Credential)?
        };
        if !source_authorization
            .prefixes
            .iter()
            .any(|prefix| prefix.contains(&request.source.address))
        {
            return Err(PacketRejection::Source);
        }
        if !destination_authorization
            .prefixes
            .iter()
            .any(|prefix| prefix.contains(&request.destination.address))
        {
            return Err(PacketRejection::Destination);
        }
        if !snapshot.policy.allow(
            request.source.identity.subject_id,
            request.destination.identity.subject_id,
            request.packet,
        ) {
            return Err(PacketRejection::Policy);
        }
        Ok(())
    }

    pub(crate) fn replace(&self, configuration: RelayConfiguration) -> Result<()> {
        let snapshot = compile(configuration, self.network, self.local_certificate.as_ref())?;
        let _update = self
            .update
            .lock()
            .map_err(|_| anyhow::anyhow!("controller snapshot update lock poisoned"))?;
        let current = self.current.load_full();
        if let Some(previous) = current.as_ref() {
            ensure!(
                snapshot.epoch > previous.epoch,
                "controller epoch did not advance"
            );
        }
        self.current.store(Some(Arc::new(snapshot)));
        if let (Some(metrics), Some(current)) = (&self.metrics, self.current.load().as_ref()) {
            metrics.controller_certificate_renew_after_seconds.store(
                current.certificate_renew_after,
                std::sync::atomic::Ordering::Release,
            );
            metrics.controller_certificate_not_after_seconds.store(
                current.certificate_not_after,
                std::sync::atomic::Ordering::Release,
            );
            metrics
                .controller_certificate_renewal_forced
                .store(0, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    fn renew(&self, valid_until: u64) -> Result<()> {
        ensure!(
            !expired(valid_until),
            "controller renewed snapshot with expired deadline"
        );
        let _update = self
            .update
            .lock()
            .map_err(|_| anyhow::anyhow!("controller snapshot update lock poisoned"))?;
        let previous = self
            .current
            .load_full()
            .context("controller returned 304 before initial snapshot")?;
        ensure!(
            valid_until >= previous.valid_until,
            "controller lease deadline moved backwards"
        );
        self.current.store(Some(Arc::new(Snapshot {
            valid_until,
            ..(*previous).clone()
        })));
        Ok(())
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.current
            .load_full()
            .map(|snapshot| snapshot.epoch)
            .unwrap_or(0)
    }
}

pub(crate) struct Client {
    endpoint: String,
    poll_interval: Duration,
    http: reqwest::Client,
    expected_controller: AuthenticatedIdentity,
    quic: Option<QuicControl>,
}

struct QuicControl {
    client_config: quinn::ClientConfig,
    host: String,
    port: u16,
    server_name: String,
    expected: AuthenticatedIdentity,
    timeout: Duration,
    connection: AsyncMutex<Option<(Endpoint, quinn::Connection)>>,
    request_id: std::sync::atomic::AtomicU64,
}

impl Client {
    pub(crate) fn new(config: &Config, controller: &ControllerConfig, network: Id) -> Result<Self> {
        ensure!(
            controller
                .network_id
                .parse::<Id>()
                .context("controller.network_id")?
                == network,
            "controller.network_id differs from relay certificate network"
        );
        let mut identity_pem = fs::read(&config.tls.certificate_file)
            .context("read relay certificate for controller")?;
        identity_pem.extend_from_slice(
            &fs::read(&config.tls.private_key_file).context("read relay key for controller")?,
        );
        let root = fs::read(&config.tls.ca_file).context("read controller CA")?;
        let url = reqwest::Url::parse(&controller.endpoint).context("parse controller endpoint")?;
        if !controller.server_name.is_empty() {
            ensure!(
                url.host_str() == Some(controller.server_name.as_str()),
                "Rust relay requires controller.server_name to match endpoint host"
            );
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .identity(Identity::from_pem(&identity_pem).context("load relay controller identity")?)
            .add_root_certificate(Certificate::from_pem(&root).context("load controller CA")?)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .timeout(Duration::from_secs(15))
            .tls_info(true)
            .build()
            .context("build controller HTTP client")?;
        let expected_controller = AuthenticatedIdentity {
            network_id: network,
            role: Role::Controller,
            subject_id: controller
                .service_id
                .parse()
                .context("controller.service_id")?,
        };
        let quic = controller
            .quic_endpoint
            .as_deref()
            .map(|endpoint| {
                QuicControl::new(
                    endpoint,
                    controller.server_name.clone(),
                    expected_controller,
                    controller.timeout,
                    &config.tls.certificate_file,
                    &config.tls.private_key_file,
                    &config.tls.ca_file,
                )
            })
            .transpose()?;
        Ok(Self {
            endpoint: format!(
                "{}/v1/relay/configuration",
                controller.endpoint.trim_end_matches('/')
            ),
            poll_interval: controller.poll_interval,
            http,
            expected_controller,
            quic,
        })
    }

    pub(crate) async fn run(&self, state: Arc<State>) -> Result<()> {
        let mut delay = Duration::from_millis(250);
        loop {
            match self.poll(&state).await {
                Ok(()) => {
                    delay = self.poll_interval;
                }
                Err(error) => {
                    tracing::warn!(%error, "controller relay snapshot poll failed");
                    delay = delay.saturating_mul(2).min(self.poll_interval);
                }
            }
            sleep(delay).await;
        }
    }

    pub(crate) async fn initialize(&self, state: &State) -> Result<()> {
        self.poll(state).await
    }

    async fn poll(&self, state: &State) -> Result<()> {
        if let Some(control) = &self.quic {
            return control.poll(state).await;
        }
        let body = RelayConfigurationRequest {
            known_configuration_epoch: state.epoch(),
        }
        .encode_to_vec();
        let mut response = self
            .http
            .post(&self.endpoint)
            .header("content-type", "application/x-protobuf")
            .body(body)
            .send()
            .await
            .context("request relay configuration")?;
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
            let deadline = response
                .headers()
                .get(VALID_UNTIL_HEADER)
                .context("304 omitted snapshot deadline")?
                .to_str()?
                .parse()?;
            return state.renew(deadline);
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
        let mut bytes = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or(0)
                .min(MAX_RESPONSE as u64) as usize,
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read relay configuration chunk")?
        {
            ensure!(
                bytes.len() <= MAX_RESPONSE.saturating_sub(chunk.len()),
                "controller response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        state.replace(
            RelayConfiguration::decode(bytes.as_slice()).context("decode relay configuration")?,
        )
    }
}

impl QuicControl {
    fn new(
        address: &str,
        server_name: String,
        expected: AuthenticatedIdentity,
        timeout: Duration,
        certificate: &PathBuf,
        private_key: &PathBuf,
        ca: &PathBuf,
    ) -> Result<Self> {
        let (host, port) = split_host_port(address)?;
        let certificates = read_certificates(certificate, 4 << 20, "relay controller certificate")?;
        ensure!(
            !certificates.is_empty(),
            "relay controller certificate chain is empty"
        );
        let key = read_private_key(private_key, 1 << 20, "relay controller private key")?;
        let roots_der = read_certificates(ca, 4 << 20, "controller CA")?;
        let mut roots = RootCertStore::empty();
        let (accepted, rejected) = roots.add_parsable_certificates(roots_der);
        ensure!(
            accepted > 0 && rejected == 0,
            "controller CA contains an invalid certificate"
        );
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, key)
            .context("load relay QUIC controller identity")?;
        crypto.alpn_protocols = vec![b"laneway-control/1".to_vec()];
        crypto.enable_early_data = false;
        let crypto =
            QuicClientConfig::try_from(crypto).context("build relay controller QUIC TLS")?;
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
        Ok(Self {
            client_config: client,
            host,
            port,
            server_name,
            expected,
            timeout,
            connection: AsyncMutex::new(None),
            request_id: std::sync::atomic::AtomicU64::new(0),
        })
    }

    async fn poll(&self, state: &State) -> Result<()> {
        use laneway_protocol::v1::{ControllerEnvelope, controller_envelope};
        let request_id = self.next_request_id();
        let known_epoch = state.epoch();
        let request = ControllerEnvelope {
            schema_version: 1,
            request_id,
            body: Some(controller_envelope::Body::RelayConfigurationRequest(
                RelayConfigurationRequest {
                    known_configuration_epoch: known_epoch,
                },
            )),
        };
        let response = self.exchange(request).await?;
        match response.body {
            Some(controller_envelope::Body::RelayConfiguration(configuration)) => {
                state.replace(configuration)
            }
            Some(controller_envelope::Body::ConfigurationLease(lease)) => {
                ensure!(
                    lease.configuration_epoch == known_epoch,
                    "controller QUIC lease epoch mismatch"
                );
                state.renew(lease.valid_until_unix_seconds)
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
            _ => bail!("controller QUIC returned an unexpected relay response"),
        }
    }

    fn next_request_id(&self) -> u64 {
        use std::sync::atomic::Ordering;
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
        if let Some((_endpoint, connection)) = self.connection.lock().await.take() {
            connection.close(0_u32.into(), b"controller authorization rejected");
        }
    }

    async fn exchange(
        &self,
        request: laneway_protocol::v1::ControllerEnvelope,
    ) -> Result<laneway_protocol::v1::ControllerEnvelope> {
        const MAX_QUIC_CONTROL: usize = 1 << 20;
        let mut connection = self.connection.lock().await;
        if connection.is_none() {
            let mut addresses: Vec<SocketAddr> = if let Ok(ip) = self.host.parse::<IpAddr>() {
                vec![SocketAddr::new(ip, self.port)]
            } else {
                tokio::time::timeout(
                    self.timeout,
                    tokio::net::lookup_host((self.host.as_str(), self.port)),
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
                "controller QUIC endpoint resolved outside bounded address set"
            );
            let mut last = None;
            for address in addresses {
                let bind: SocketAddr = if address.is_ipv6() {
                    "[::]:0".parse().expect("constant controller bind")
                } else {
                    "0.0.0.0:0".parse().expect("constant controller bind")
                };
                let mut endpoint = Endpoint::client(bind)?;
                endpoint.set_default_client_config(self.client_config.clone());
                let connecting = match endpoint.connect(address, &self.server_name) {
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
                        *connection = Some((endpoint, value));
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
        let active = connection.as_ref().expect("connection installed").1.clone();
        let result = tokio::time::timeout(self.timeout, async {
            let (mut send, mut receive) = active
                .open_bi()
                .await
                .context("open controller QUIC request stream")?;
            let payload = request.encode_to_vec();
            ensure!(
                !payload.is_empty() && payload.len() <= MAX_QUIC_CONTROL,
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
                length != 0 && length <= MAX_QUIC_CONTROL,
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

fn read_certificates(
    path: &PathBuf,
    maximum: usize,
    label: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = bounded_read(path, maximum, label)?;
    rustls_pemfile::certs(&mut std::io::Cursor::new(bytes))
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parse {label}"))
}

fn bounded_read(path: &PathBuf, maximum: usize, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {label}"))?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "{label} exceeds limit or is not a regular file"
    );
    let bytes = fs::read(path).with_context(|| format!("read {label}"))?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "{label} is empty or exceeds limit"
    );
    Ok(bytes)
}

fn read_private_key(path: &PathBuf, maximum: usize, label: &str) -> Result<PrivateKeyDer<'static>> {
    let bytes = bounded_read(path, maximum, label)?;
    rustls_pemfile::private_key(&mut std::io::Cursor::new(bytes))
        .with_context(|| format!("parse {label}"))?
        .with_context(|| format!("{label} is missing"))
}

fn compile(
    configuration: RelayConfiguration,
    network: Id,
    local: Option<&LocalCertificateHealth>,
) -> Result<Snapshot> {
    ensure!(
        configuration.configuration_epoch > 0 && configuration.network_id == network.as_bytes(),
        "controller snapshot identity or epoch is invalid"
    );
    ensure!(
        !expired(configuration.valid_until_unix_seconds),
        "controller snapshot is expired"
    );
    let mut certificate_renew_after = 0;
    let mut certificate_not_after = 0;
    if let Some(health) = &configuration.certificate_health {
        ensure!(
            !health.presented_serial.is_empty()
                && health.presented_serial.len() <= 32
                && !health.revoked
                && !expired(health.not_after_unix_seconds)
                && health.renew_after_unix_seconds != 0
                && health.renew_after_unix_seconds <= health.not_after_unix_seconds,
            "controller relay certificate health is invalid"
        );
        if let Some(local) = local {
            let revoked = configuration
                .revoked_certificate_serials
                .iter()
                .any(|serial| serial == &local.serial);
            ensure!(
                health.presented_serial == local.serial
                    && health.not_after_unix_seconds == local.not_after
                    && health.renew_after_unix_seconds == local.renew_after
                    && health.revoked == revoked
                    && !revoked,
                "controller relay certificate health does not match local certificate"
            );
        }
        certificate_renew_after = health.renew_after_unix_seconds;
        certificate_not_after = health.not_after_unix_seconds;
    }
    ensure!(
        local.is_none() || configuration.certificate_health.is_some(),
        "controller snapshot omitted relay certificate health"
    );
    let policy_snapshot = configuration
        .policy
        .context("controller snapshot omitted policy")?;
    ensure!(
        policy_snapshot.default_action == laneway_protocol::v1::PolicyAction::Deny as i32,
        "controller relay policy must default deny"
    );
    let policy = Policy::compile(policy_snapshot, network, configuration.configuration_epoch)?;
    let mut revoked_serials = HashSet::new();
    for serial in configuration.revoked_certificate_serials {
        ensure!(
            !serial.is_empty() && serial.len() <= 32 && revoked_serials.insert(serial),
            "invalid or duplicate revoked certificate serial"
        );
    }
    let mut authorizations = HashMap::new();
    let mut overlay_owners = HashSet::new();
    for peer in configuration.peers {
        let node = Id::from_slice(&peer.node_id).context("controller peer node ID")?;
        let identity = AuthenticatedIdentity {
            network_id: network,
            role: Role::Node,
            subject_id: node,
        };
        let overlays = peer
            .overlay_addresses
            .into_iter()
            .map(parse_address)
            .collect::<Result<Vec<_>>>()?;
        let prefixes = peer
            .authorized_prefixes
            .into_iter()
            .map(parse_prefix)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !overlays.is_empty() && !prefixes.is_empty(),
            "controller peer authorization is incomplete"
        );
        for address in &overlays {
            ensure!(
                overlay_owners.insert(*address),
                "controller overlay has duplicate owners"
            );
            let owned = prefixes.iter().any(|prefix| {
                prefix.prefix_len() == prefix.max_prefix_len() && prefix.addr() == *address
            });
            ensure!(owned, "controller peer does not own overlay host prefix");
        }
        ensure!(
            authorizations
                .insert(
                    identity,
                    Authorization {
                        prefixes,
                        overlay_addresses: overlays
                    }
                )
                .is_none(),
            "controller peer is duplicated"
        );
    }
    Ok(Snapshot {
        epoch: configuration.configuration_epoch,
        valid_until: configuration.valid_until_unix_seconds,
        authorizations,
        policy,
        revoked_serials,
        certificate_renew_after,
        certificate_not_after,
    })
}

fn expired(deadline: u64) -> bool {
    deadline
        <= SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
}

fn parse_address(raw: Vec<u8>) -> Result<IpAddr> {
    match raw.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(raw).expect("length checked"),
        ))),
        16 => {
            let value = Ipv6Addr::from(<[u8; 16]>::try_from(raw).expect("length checked"));
            ensure!(
                value.to_ipv4_mapped().is_none(),
                "noncanonical mapped IPv4 address"
            );
            Ok(IpAddr::V6(value))
        }
        _ => bail!("invalid IP address length"),
    }
}

fn parse_prefix(value: IpPrefix) -> Result<IpNet> {
    let address = parse_address(value.address)?;
    ensure!(
        value.prefix_length <= address_max_bits(address),
        "invalid prefix length"
    );
    let prefix = match address {
        IpAddr::V4(v) => IpNet::V4(Ipv4Net::new(v, value.prefix_length as u8)?),
        IpAddr::V6(v) => IpNet::V6(Ipv6Net::new(v, value.prefix_length as u8)?),
    };
    ensure!(prefix.trunc() == prefix, "noncanonical prefix");
    Ok(prefix)
}
fn address_max_bits(value: IpAddr) -> u32 {
    if value.is_ipv4() { 32 } else { 128 }
}

#[derive(Clone)]
enum Policy {
    Accept,
    Compiled(CompiledPolicy),
}

impl Policy {
    fn compile(snapshot: PolicySnapshot, network: Id, epoch: u64) -> Result<Self> {
        Ok(Self::Compiled(
            CompiledPolicy::compile(snapshot, network, epoch).context("compile relay policy")?,
        ))
    }
    fn allow(&self, source: Id, destination: Id, packet: &[u8]) -> bool {
        match self {
            Self::Accept => true,
            Self::Compiled(policy) => policy.allows(source, destination, packet),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::{
        IpProtocol, PolicyAction, PolicyRule, PortRange, RelayPeerAuthorization, TrafficSelector,
    };

    fn prefix(address: [u8; 4], prefix_length: u32) -> IpPrefix {
        IpPrefix {
            address: address.to_vec(),
            prefix_length,
        }
    }

    fn packet(port: u16) -> Vec<u8> {
        let mut value = vec![0_u8; 28];
        value[0] = 0x45;
        value[2..4].copy_from_slice(&28_u16.to_be_bytes());
        value[9] = 17;
        value[12..16].copy_from_slice(&[100, 96, 0, 1]);
        value[16..20].copy_from_slice(&[100, 96, 0, 2]);
        value[22..24].copy_from_slice(&port.to_be_bytes());
        value
    }

    #[test]
    fn snapshot_enforces_acl_and_authorization() {
        let network = Id::new([1; 16]).unwrap();
        let first = Id::new([2; 16]).unwrap();
        let second = Id::new([3; 16]).unwrap();
        let deadline = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let selector = TrafficSelector {
            source_node_ids: vec![first.as_bytes().to_vec()],
            destination_node_ids: vec![second.as_bytes().to_vec()],
            ip_protocol: IpProtocol::Udp as i32,
            destination_ports: vec![PortRange {
                first: 443,
                last: 443,
            }],
            ..TrafficSelector::default()
        };
        let mut configuration = RelayConfiguration {
            network_id: network.as_bytes().to_vec(),
            configuration_epoch: 7,
            valid_until_unix_seconds: deadline,
            peers: vec![
                RelayPeerAuthorization {
                    node_id: first.as_bytes().to_vec(),
                    overlay_addresses: vec![vec![100, 96, 0, 1]],
                    authorized_prefixes: vec![prefix([100, 96, 0, 1], 32)],
                },
                RelayPeerAuthorization {
                    node_id: second.as_bytes().to_vec(),
                    overlay_addresses: vec![vec![100, 96, 0, 2]],
                    authorized_prefixes: vec![prefix([100, 96, 0, 2], 32)],
                },
            ],
            policy: Some(PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: 7,
                default_action: PolicyAction::Deny as i32,
                rules: vec![PolicyRule {
                    rule_id: vec![9; 16],
                    priority: 1,
                    action: PolicyAction::Accept as i32,
                    selector: Some(selector),
                    description: String::new(),
                }],
            }),
            revoked_certificate_serials: vec![vec![0x80, 7]],
            certificate_health: None,
        };
        let local = LocalCertificateHealth {
            serial: vec![7],
            not_after: 4_000_000_000,
            renew_after: 3_000_000_000,
        };
        assert!(compile(configuration.clone(), network, Some(&local)).is_err());
        configuration.certificate_health = Some(laneway_protocol::v1::CertificateHealth {
            presented_serial: local.serial.clone(),
            not_after_unix_seconds: local.not_after,
            renew_after_unix_seconds: local.renew_after,
            revoked: false,
        });
        let mut permissive = configuration.clone();
        permissive.policy.as_mut().unwrap().default_action = PolicyAction::Accept as i32;
        assert!(
            compile(permissive, network, Some(&local)).is_err(),
            "controller relay accepted a permissive policy default"
        );
        let snapshot = compile(configuration.clone(), network, Some(&local)).unwrap();
        assert_eq!(snapshot.certificate_renew_after, local.renew_after);
        assert_eq!(snapshot.certificate_not_after, local.not_after);
        let state = State::controller(network);
        state.replace(configuration).unwrap();
        assert!(
            state.renew(deadline - 1).is_err(),
            "controller relay accepted a shorter lease deadline"
        );
        assert_eq!(
            state.current.load_full().unwrap().valid_until,
            deadline,
            "rejected lease changed the published deadline"
        );
        let a = AuthenticatedIdentity {
            network_id: network,
            role: Role::Node,
            subject_id: first,
        };
        let b = AuthenticatedIdentity {
            network_id: network,
            role: Role::Node,
            subject_id: second,
        };
        assert!(state.authorize_credential(&a, &[]).is_some());
        assert!(state.authorize_credential(&a, &[0x80, 7]).is_none());
        let fallback = Authorization {
            prefixes: Vec::new(),
            overlay_addresses: Vec::new(),
        };
        assert_eq!(
            state.authorize_packet(PacketAuthorization {
                source: PacketPeer {
                    identity: &a,
                    certificate_serial: &[],
                    fallback: &fallback,
                    address: "100.96.0.1".parse().unwrap(),
                },
                destination: PacketPeer {
                    identity: &b,
                    certificate_serial: &[],
                    fallback: &fallback,
                    address: "100.96.0.2".parse().unwrap(),
                },
                packet: &packet(443),
            }),
            Ok(())
        );
        assert_eq!(
            state.authorize_packet(PacketAuthorization {
                source: PacketPeer {
                    identity: &a,
                    certificate_serial: &[],
                    fallback: &fallback,
                    address: "100.96.0.1".parse().unwrap(),
                },
                destination: PacketPeer {
                    identity: &b,
                    certificate_serial: &[],
                    fallback: &fallback,
                    address: "100.96.0.2".parse().unwrap(),
                },
                packet: &packet(53),
            }),
            Err(PacketRejection::Policy)
        );
    }
}
