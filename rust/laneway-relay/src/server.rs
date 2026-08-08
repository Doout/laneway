use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use laneway_protocol::{
    AuthenticatedIdentity, Id,
    v1::{Capability, Hello, RelayRegister, Welcome, control_envelope, relay_envelope},
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use tracing::{debug, info, warn};

use crate::{
    Config, Metrics,
    codec::{
        ControlReader, RelayReader, SCHEMA_VERSION, encode_message, write_control, write_relay,
    },
    config::{Authorization, TcpFallbackConfig},
    controller::{Client as ControllerClient, State as ControllerState},
    diagnostics,
    packet_pool::PacketPool,
    registry::{Registry, Session, SessionCapabilities, SessionChannels},
    tcp, tls,
};

const CONTROL_PREFACE: &[u8] = b"LWC1";
const MAX_CONTROL_PAYLOAD: usize = 1 << 20;
const MAX_PACKET_PAYLOAD: u32 = 2048;
const REQUIRED_RELAY_CAPABILITIES: u64 =
    Capability::LanewayRelayV1 as u64 | Capability::LanewayQuicDatagramV1 as u64;
const REQUIRED_TCP_CAPABILITIES: u64 =
    Capability::LanewayRelayV1 as u64 | Capability::LanewayTcpFallbackV1 as u64;
const RELAY_CAPABILITIES: u64 = Capability::LanewayRelayV1 as u64
    | Capability::LanewayQuicDatagramV1 as u64
    | Capability::LanewayTcpFallbackV1 as u64
    | Capability::LanewayDirectPeerV1 as u64
    | Capability::LanewaySubnetRouterV1 as u64
    | Capability::LanewayExitNodeV1 as u64
    | Capability::LanewayIpv6V1 as u64
    | Capability::LanewayE2ePacketV1 as u64;
const PROTOCOL_ERROR: u32 = 0x100;

struct Inner {
    authorizations: Arc<ControllerState>,
    registry: Registry,
    metrics: Arc<Metrics>,
    handshake_timeout: Duration,
    max_sessions: usize,
    tcp_tls: Option<Arc<rustls::ServerConfig>>,
    tcp_config: Option<TcpFallbackConfig>,
    tcp_packet_pool: Option<PacketPool>,
}

/// Bound Rust QUIC relay server.
pub struct Server {
    endpoint: Endpoint,
    tcp_listener: Option<TcpListener>,
    inner: Arc<Inner>,
    metrics_interval: Duration,
    controller: Option<ControllerClient>,
    diagnostics: Option<diagnostics::Server>,
}

impl Server {
    /// Validates credentials and static authorization before binding the UDP socket.
    pub fn bind(config: Config) -> Result<Self> {
        // reqwest's `rustls-tls-no-provider` feature deliberately leaves the
        // process-wide crypto provider to the embedding binary. Install the
        // same ring provider used by Quinn before controller client creation;
        // a provider already installed by another Rust component is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let metrics = Arc::new(Metrics::default());
        let static_authorizations = config.authorizations()?;
        let (authorizations, controller) = if let Some(controller_config) = config
            .controller
            .as_ref()
            .filter(|value| !value.endpoint.is_empty())
        {
            let relay_identity = tls::local_identity(&config)?;
            (
                ControllerState::controller_with_certificate(
                    relay_identity.network_id,
                    &config.tls.certificate_file,
                    Arc::clone(&metrics),
                )?,
                Some(ControllerClient::new(
                    &config,
                    controller_config,
                    relay_identity.network_id,
                )?),
            )
        } else {
            (
                ControllerState::static_snapshot(static_authorizations),
                None,
            )
        };
        let server_config = tls::server_config(&config)?;
        let endpoint = Endpoint::server(server_config, config.listen_addr()?)
            .context("bind QUIC relay endpoint")?;
        let tcp_address = config.tcp_fallback_addr()?;
        let tcp_listener = if let Some(address) = tcp_address {
            let listener = std::net::TcpListener::bind(address)
                .with_context(|| format!("bind TCP fallback endpoint {address}"))?;
            listener
                .set_nonblocking(true)
                .context("make TCP fallback listener nonblocking")?;
            Some(TcpListener::from_std(listener).context("create Tokio TCP fallback listener")?)
        } else {
            None
        };
        let tcp_tls = if tcp_listener.is_some() {
            Some(tls::tcp_server_config(&config)?)
        } else {
            None
        };
        let tcp_config = config
            .tcp_fallback
            .as_ref()
            .filter(|tcp| !tcp.listen.is_empty())
            .cloned();
        let tcp_packet_pool = tcp_config
            .as_ref()
            .map(|tcp| PacketPool::prewarmed(tcp.queue_depth, MAX_PACKET_PAYLOAD as usize + 5));
        let diagnostics = config
            .metrics_listen_addr()?
            .map(|address| diagnostics::Server::bind(address, Arc::clone(&metrics)))
            .transpose()?;
        let registry = Registry::new_with_controller(
            config.relay.queue_depth,
            config.relay.max_sessions,
            config.relay.max_routes,
            Arc::clone(&metrics),
            Arc::clone(&authorizations),
            config.relay.candidate_republish_floor,
            (
                config.relay.packet_rate_bits_per_second,
                config.relay.packet_burst_bytes,
            ),
        );
        Ok(Self {
            endpoint,
            tcp_listener,
            inner: Arc::new(Inner {
                authorizations,
                registry,
                metrics,
                handshake_timeout: config.relay.handshake_timeout,
                max_sessions: config.relay.max_sessions,
                tcp_tls,
                tcp_config,
                tcp_packet_pool,
            }),
            metrics_interval: config.relay.metrics_interval,
            controller,
            diagnostics,
        })
    }

    /// Returns the actual bound UDP address, including an assigned ephemeral port.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("query relay local address")
    }

    /// Returns the actual TCP fallback address when that carrier is enabled.
    pub fn tcp_fallback_addr(&self) -> Result<Option<SocketAddr>> {
        self.tcp_listener
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()
            .context("query TCP fallback local address")
    }

    /// Returns the shared metrics registry.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.inner.metrics)
    }

    /// Returns the actual Prometheus diagnostics address when enabled.
    pub fn metrics_addr(&self) -> Result<Option<SocketAddr>> {
        self.diagnostics
            .as_ref()
            .map(diagnostics::Server::local_addr)
            .transpose()
    }

    /// Serves until `shutdown` resolves, then closes all QUIC connections and waits for cleanup.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()>,
    {
        let slots = Arc::new(Semaphore::new(self.inner.max_sessions));
        let mut tasks = JoinSet::new();
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let mut diagnostics_task = self
            .diagnostics
            .map(|server| tokio::spawn(server.run(stopped.clone())));
        if let Some(controller) = self.controller.as_ref() {
            controller.initialize(&self.inner.authorizations).await?;
        }
        let mut controller_task = self.controller.map(|controller| {
            let state = Arc::clone(&self.inner.authorizations);
            tokio::spawn(async move { controller.run(state).await })
        });
        let mut metrics_task = if self.metrics_interval.is_zero() {
            None
        } else {
            let metrics = Arc::clone(&self.inner.metrics);
            let interval = self.metrics_interval;
            Some(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    info!(?interval, snapshot = ?metrics.snapshot(), "relay metrics");
                }
            }))
        };
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    self.inner.metrics.quic_connection_attempts.fetch_add(1, Ordering::Relaxed);
                    let permit = match Arc::clone(&slots).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            self.inner.metrics.quic_connection_failures.fetch_add(1, Ordering::Relaxed);
                            incoming.refuse();
                            warn!("refused QUIC connection: session limit reached");
                            continue;
                        }
                    };
                    let inner = Arc::clone(&self.inner);
                    let metrics = Arc::clone(&self.inner.metrics);
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = serve_incoming(inner, incoming).await {
                            metrics.quic_connection_failures.fetch_add(1, Ordering::Relaxed);
                            debug!(%error, "relay connection ended");
                        }
                    });
                }
                accepted = async {
                    match self.tcp_listener.as_ref() {
                        Some(listener) => listener.accept().await.map(Some),
                        None => std::future::pending().await,
                    }
                } => {
                    let (stream, peer) = match accepted {
                        Ok(Some(value)) => value,
                        Ok(None) => continue,
                        Err(error) => {
                            warn!(%error, "TCP fallback accept failed");
                            continue;
                        }
                    };
                    self.inner.metrics.tcp_connection_attempts.fetch_add(1, Ordering::Relaxed);
                    let permit = match Arc::clone(&slots).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            self.inner.metrics.tcp_connection_failures.fetch_add(1, Ordering::Relaxed);
                            warn!(%peer, "refused TCP fallback connection: session limit reached");
                            continue;
                        }
                    };
                    let inner = Arc::clone(&self.inner);
                    let metrics = Arc::clone(&self.inner.metrics);
                    let shutdown = stopped.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = serve_tcp_incoming(inner, stream, shutdown).await {
                            metrics.tcp_connection_failures.fetch_add(1, Ordering::Relaxed);
                            debug!(%peer, %error, "TCP fallback connection ended");
                        }
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        warn!(%error, "relay connection task panicked");
                    }
                }
            }
        }
        let _ = stop.send(true);
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
        self.endpoint.wait_idle().await;
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                warn!(%error, "relay connection task panicked during shutdown");
            }
        }
        if let Some(task) = diagnostics_task.take() {
            task.await.context("relay diagnostics task panicked")??;
        }
        if let Some(task) = metrics_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = controller_task.take() {
            task.abort();
            let _ = task.await;
        }
        Ok(())
    }
}

async fn serve_incoming(inner: Arc<Inner>, incoming: quinn::Incoming) -> Result<()> {
    let connection = timeout(inner.handshake_timeout, incoming)
        .await
        .context("QUIC handshake timed out")?
        .context("QUIC handshake failed")?;
    let result = serve_connection(Arc::clone(&inner), connection.clone()).await;
    if let Err(error) = &result {
        connection.close(
            VarInt::from_u32(PROTOCOL_ERROR),
            safe_close_reason(error).as_bytes(),
        );
    } else {
        connection.close(VarInt::from_u32(0), b"session complete");
    }
    result
}

async fn serve_tcp_incoming(
    inner: Arc<Inner>,
    stream: tokio::net::TcpStream,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let tls = inner
        .tcp_tls
        .as_ref()
        .context("TCP fallback TLS configuration is unavailable")?;
    let config = inner
        .tcp_config
        .as_ref()
        .context("TCP fallback configuration is unavailable")?;
    let packet_pool = inner
        .tcp_packet_pool
        .as_ref()
        .context("TCP fallback packet pool is unavailable")?
        .clone();
    let mut connection = tokio::select! {
        result = tcp::accept(
            stream,
            Arc::clone(tls),
            config,
            packet_pool,
            Arc::clone(&inner.metrics),
        ) => result?,
        _ = wait_shutdown(&mut shutdown) => bail!("relay shutting down"),
    };
    let result = serve_tcp_connection(Arc::clone(&inner), &mut connection, shutdown).await;
    connection.shutdown("session complete").await;
    result
}

async fn serve_tcp_connection(
    inner: Arc<Inner>,
    connection: &mut tcp::Parts,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let identity = connection.identity;
    let certificate_serial = connection.certificate_serial.clone();
    let authorization = inner
        .authorizations
        .authorize_credential(&identity, &certificate_serial)
        .context("authenticated node is not authorized by the active snapshot")?;
    let handshake = timeout(
        inner
            .tcp_config
            .as_ref()
            .context("TCP fallback configuration is unavailable")?
            .handshake_timeout,
        perform_tcp_handshake(
            &identity,
            &authorization,
            inner.authorizations.epoch(),
            connection,
        ),
    )
    .await
    .context("TCP fallback control handshake timed out")??;
    let channels = inner.registry.register_credential(
        identity,
        certificate_serial,
        authorization,
        handshake.requested_max_routes,
        SessionCapabilities {
            allow_ipv6: handshake.allow_ipv6,
            allow_e2e: handshake.allow_e2e,
        },
        None,
    )?;
    let session = Arc::clone(&channels.session);
    let result = run_tcp_session(
        &inner.registry,
        connection,
        handshake.relay_reader,
        channels,
        shutdown,
        Arc::clone(&inner.metrics),
    )
    .await;
    inner.registry.unregister(&session);
    result
}

async fn perform_tcp_handshake(
    identity: &AuthenticatedIdentity,
    authorization: &Authorization,
    configuration_epoch: u64,
    connection: &mut tcp::Parts,
) -> Result<HandshakeResult> {
    let mut control_reader = ControlReader::new();
    let hello_payload = connection
        .control
        .recv()
        .await
        .context("TCP fallback control queue closed before Hello")?;
    let hello_envelope = control_reader.decode(&hello_payload)?;
    let hello = match hello_envelope.body {
        Some(control_envelope::Body::Hello(hello)) => hello,
        _ => bail!("Hello must be the first control message"),
    };
    let negotiated_capabilities = validate_hello(
        identity,
        &hello,
        REQUIRED_TCP_CAPABILITIES,
        "relay TCP fallback",
    )? & !(Capability::LanewayDirectPeerV1 as u64);
    let session_id = random_id()?;
    let welcome = laneway_protocol::v1::ControlEnvelope {
        schema_version: SCHEMA_VERSION,
        sequence: 1,
        body: Some(control_envelope::Body::Welcome(Welcome {
            session_id: session_id.as_bytes().to_vec(),
            configuration_epoch,
            overlay_addresses: authorization
                .overlay_addresses
                .iter()
                .filter(|address| {
                    !address.is_ipv6()
                        || negotiated_capabilities & Capability::LanewayIpv6V1 as u64 != 0
                })
                .map(|address| match address {
                    std::net::IpAddr::V4(value) => value.octets().to_vec(),
                    std::net::IpAddr::V6(value) => value.octets().to_vec(),
                })
                .collect(),
            capabilities: negotiated_capabilities,
            max_control_payload: MAX_CONTROL_PAYLOAD as u32,
            max_packet_payload: MAX_PACKET_PAYLOAD,
        })),
    };
    connection
        .writer
        .control(encode_message(&welcome, MAX_CONTROL_PAYLOAD)?)
        .await?;

    let mut relay_reader = RelayReader::new();
    let register_payload = connection
        .control
        .recv()
        .await
        .context("TCP fallback control queue closed before RelayRegister")?;
    let register_envelope = relay_reader.decode(&register_payload)?;
    let register = match register_envelope.body {
        Some(relay_envelope::Body::Register(register)) => register,
        _ => bail!("RelayRegister must be the first relay message"),
    };
    validate_register(&session_id, &register)?;
    Ok(HandshakeResult {
        requested_max_routes: register.requested_max_routes,
        allow_ipv6: negotiated_capabilities & Capability::LanewayIpv6V1 as u64 != 0,
        allow_e2e: negotiated_capabilities & Capability::LanewayE2ePacketV1 as u64 != 0,
        direct_capable: false,
        relay_reader,
    })
}

async fn run_tcp_session(
    registry: &Registry,
    connection: &mut tcp::Parts,
    mut relay_reader: RelayReader,
    channels: SessionChannels,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let session = Arc::clone(&channels.session);
    let mut outbound = TrackedOutbound::new(channels.outbound, metrics);
    let mut control_out = channels.control;
    let canceled = wait_canceled(channels.canceled);
    let unauthorized = wait_unauthorized(registry, Arc::clone(&session));
    tokio::pin!(canceled);
    tokio::pin!(unauthorized);
    let mut sequence = 1_u64;
    loop {
        tokio::select! {
            payload = connection.control.recv() => {
                let payload = payload.context("TCP fallback control receive queue closed")?;
                let envelope = relay_reader.decode(&payload)?;
                match envelope.body {
                    Some(relay_envelope::Body::RouteHandleRelease(release)) if release.route_handle != 0 => {
                        registry.release(&session, release.route_handle)?;
                    }
                    _ => bail!("unexpected relay control message"),
                }
            }
            frame = connection.packets.recv() => {
                let frame = frame.context("TCP fallback packet receive queue closed")?;
                // Structurally valid but unauthorized packets are authenticated drops.
                let _ = registry.forward(&session, frame);
            }
            body = control_out.recv() => {
                let body = body.context("relay control queue closed")?;
                let envelope = laneway_protocol::v1::RelayEnvelope {
                    schema_version: SCHEMA_VERSION,
                    sequence,
                    body: Some(body),
                };
                connection.writer.control(encode_message(&envelope, MAX_CONTROL_PAYLOAD)?).await?;
                sequence = sequence.checked_add(1).context("relay sequence exhausted")?;
            }
            frame = outbound.recv() => {
                connection.writer.packet(frame.context("relay packet queue closed")?).await?;
            }
            result = &mut canceled => return result,
            result = &mut unauthorized => return result,
            reason = tcp::wait_done(&mut connection.done) => bail!("TCP fallback session ended: {reason}"),
            _ = wait_shutdown(&mut shutdown) => bail!("relay shutting down"),
        }
    }
}

async fn wait_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn serve_connection(inner: Arc<Inner>, connection: Connection) -> Result<()> {
    tls::validate_negotiation(&connection)?;
    let identity = tls::peer_identity(&connection)?;
    let certificate_serial = tls::peer_certificate_serial(&connection)?;
    let authorization = inner
        .authorizations
        .authorize_credential(&identity, &certificate_serial)
        .context("authenticated node is not authorized by the active snapshot")?;
    let (mut send, mut receive) = timeout(inner.handshake_timeout, connection.accept_bi())
        .await
        .context("control stream timed out")?
        .context("accept control stream")?;
    let handshake = timeout(
        inner.handshake_timeout,
        perform_handshake(
            &identity,
            &authorization,
            inner.authorizations.epoch(),
            &mut send,
            &mut receive,
        ),
    )
    .await
    .context("control handshake timed out")??;
    let channels = inner.registry.register_credential(
        identity,
        certificate_serial,
        authorization,
        handshake.requested_max_routes,
        SessionCapabilities {
            allow_ipv6: handshake.allow_ipv6,
            allow_e2e: handshake.allow_e2e,
        },
        handshake
            .direct_capable
            .then(|| connection.remote_address()),
    )?;
    let session = Arc::clone(&channels.session);
    let result = run_session(
        Arc::clone(&inner),
        connection,
        send,
        receive,
        handshake.relay_reader,
        channels,
    )
    .await;
    inner.registry.unregister(&session);
    result
}

struct HandshakeResult {
    requested_max_routes: u32,
    allow_ipv6: bool,
    allow_e2e: bool,
    direct_capable: bool,
    relay_reader: RelayReader,
}

async fn perform_handshake(
    identity: &AuthenticatedIdentity,
    authorization: &Authorization,
    configuration_epoch: u64,
    send: &mut SendStream,
    receive: &mut RecvStream,
) -> Result<HandshakeResult> {
    let mut preface = [0_u8; 4];
    receive
        .read_exact(&mut preface)
        .await
        .context("read control preface")?;
    ensure!(preface == CONTROL_PREFACE, "invalid control stream preface");

    let mut control_reader = ControlReader::new();
    let hello_envelope = control_reader.read(receive, MAX_CONTROL_PAYLOAD).await?;
    let hello = match hello_envelope.body {
        Some(control_envelope::Body::Hello(hello)) => hello,
        _ => bail!("Hello must be the first control message"),
    };
    let negotiated_capabilities =
        validate_hello(identity, &hello, REQUIRED_RELAY_CAPABILITIES, "relay QUIC")?;
    let session_id = random_id()?;
    write_control(
        send,
        1,
        control_envelope::Body::Welcome(Welcome {
            session_id: session_id.as_bytes().to_vec(),
            configuration_epoch,
            overlay_addresses: authorization
                .overlay_addresses
                .iter()
                .filter(|address| {
                    !address.is_ipv6()
                        || negotiated_capabilities & Capability::LanewayIpv6V1 as u64 != 0
                })
                .map(|address| match address {
                    std::net::IpAddr::V4(value) => value.octets().to_vec(),
                    std::net::IpAddr::V6(value) => value.octets().to_vec(),
                })
                .collect(),
            capabilities: negotiated_capabilities,
            max_control_payload: MAX_CONTROL_PAYLOAD as u32,
            max_packet_payload: MAX_PACKET_PAYLOAD,
        }),
        MAX_CONTROL_PAYLOAD,
    )
    .await?;

    let mut relay_reader = RelayReader::new();
    let register_envelope = relay_reader.read(receive, MAX_CONTROL_PAYLOAD).await?;
    let register = match register_envelope.body {
        Some(relay_envelope::Body::Register(register)) => register,
        _ => bail!("RelayRegister must be the first relay message"),
    };
    validate_register(&session_id, &register)?;
    Ok(HandshakeResult {
        requested_max_routes: register.requested_max_routes,
        allow_ipv6: negotiated_capabilities & Capability::LanewayIpv6V1 as u64 != 0,
        allow_e2e: negotiated_capabilities & Capability::LanewayE2ePacketV1 as u64 != 0,
        direct_capable: negotiated_capabilities & Capability::LanewayDirectPeerV1 as u64 != 0,
        relay_reader,
    })
}

fn validate_hello(
    identity: &AuthenticatedIdentity,
    hello: &Hello,
    required_capabilities: u64,
    carrier: &str,
) -> Result<u64> {
    ensure!(
        hello.network_id.as_slice() == identity.network_id.as_bytes(),
        "Hello network ID differs from certificate"
    );
    ensure!(
        hello.node_id.as_slice() == identity.subject_id.as_bytes(),
        "Hello node ID differs from certificate"
    );
    Id::from_slice(&hello.boot_id).context("invalid Hello boot ID")?;
    ensure!(hello.protocol_major == 1, "unsupported protocol major");
    ensure!(
        hello.capabilities & required_capabilities == required_capabilities,
        "Hello lacks {carrier} capabilities"
    );
    Ok(hello.capabilities & RELAY_CAPABILITIES)
}

fn validate_register(session_id: &Id, register: &RelayRegister) -> Result<()> {
    ensure!(
        register.session_id.as_slice() == session_id.as_bytes(),
        "RelayRegister session ID mismatch"
    );
    ensure!(
        register.requested_max_routes > 0,
        "RelayRegister route limit is zero"
    );
    Ok(())
}

async fn run_session(
    inner: Arc<Inner>,
    connection: Connection,
    send: SendStream,
    receive: RecvStream,
    relay_reader: RelayReader,
    channels: SessionChannels,
) -> Result<()> {
    let session = Arc::clone(&channels.session);
    let control_writer = control_writer(send, channels.control);
    let control_reader =
        control_reader(&inner.registry, Arc::clone(&session), receive, relay_reader);
    let packet_reader = packet_reader(&inner.registry, Arc::clone(&session), connection.clone());
    let packet_writer = packet_writer(
        connection.clone(),
        TrackedOutbound::new(channels.outbound, Arc::clone(&inner.metrics)),
        Arc::clone(&inner.metrics),
    );
    let canceled = wait_canceled(channels.canceled);
    let unauthorized = wait_unauthorized(&inner.registry, Arc::clone(&session));
    tokio::pin!(
        control_writer,
        control_reader,
        packet_reader,
        packet_writer,
        canceled,
        unauthorized
    );
    tokio::select! {
        result = &mut control_writer => result,
        result = &mut control_reader => result,
        result = &mut packet_reader => result,
        result = &mut packet_writer => result,
        result = &mut canceled => result,
        result = &mut unauthorized => result,
        error = connection.closed() => Err(error.into()),
    }
}

async fn wait_unauthorized(registry: &Registry, session: Arc<Session>) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Admission already checked the current snapshot, so avoid an immediate
    // duplicate check and poll for subsequent replacement or lease expiry.
    interval.tick().await;
    loop {
        interval.tick().await;
        if !registry.session_authorized(&session) {
            bail!("relay session authorization expired or was revoked");
        }
    }
}

async fn control_writer(
    mut send: SendStream,
    mut control: tokio::sync::mpsc::Receiver<relay_envelope::Body>,
) -> Result<()> {
    let mut sequence = 1_u64;
    while let Some(body) = control.recv().await {
        timeout(
            Duration::from_secs(5),
            write_relay(&mut send, sequence, body, MAX_CONTROL_PAYLOAD),
        )
        .await
        .context("control write timed out")??;
        sequence = sequence
            .checked_add(1)
            .context("relay sequence exhausted")?;
    }
    bail!("control writer closed")
}

async fn control_reader(
    registry: &Registry,
    session: Arc<Session>,
    mut receive: RecvStream,
    mut reader: RelayReader,
) -> Result<()> {
    loop {
        let envelope = reader.read(&mut receive, MAX_CONTROL_PAYLOAD).await?;
        match envelope.body {
            Some(relay_envelope::Body::RouteHandleRelease(release))
                if release.route_handle != 0 =>
            {
                registry.release(&session, release.route_handle)?;
            }
            Some(relay_envelope::Body::EndpointCandidate(candidate)) => {
                registry.publish_candidate(&session, &candidate)?;
            }
            _ => bail!("unexpected relay control message"),
        }
    }
}

async fn packet_reader(
    registry: &Registry,
    session: Arc<Session>,
    connection: Connection,
) -> Result<()> {
    loop {
        let frame = connection
            .read_datagram()
            .await
            .context("read QUIC datagram")?;
        // Packet errors are authenticated drops, not session-fatal protocol errors.
        let _ = registry.forward(&session, frame);
    }
}

async fn packet_writer(
    connection: Connection,
    mut outbound: TrackedOutbound,
    metrics: Arc<Metrics>,
) -> Result<()> {
    while let Some(frame) = outbound.recv().await {
        match connection.send_datagram_wait(frame).await {
            Ok(()) => {}
            // Quinn can report TooLarge transiently before path-MTU discovery
            // raises the usable DATAGRAM size. This is a packet drop, not a
            // reason to tear down an otherwise authenticated relay session.
            Err(error) if datagram_error_is_packet_drop(&error) => {
                metrics
                    .dropped_too_large
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(error) => return Err(error).context("write QUIC datagram"),
        }
    }
    bail!("packet writer closed")
}

struct TrackedOutbound {
    receiver: tokio::sync::mpsc::Receiver<Bytes>,
    metrics: Arc<Metrics>,
}

impl TrackedOutbound {
    fn new(receiver: tokio::sync::mpsc::Receiver<Bytes>, metrics: Arc<Metrics>) -> Self {
        Self { receiver, metrics }
    }

    async fn recv(&mut self) -> Option<Bytes> {
        let frame = self.receiver.recv().await;
        if frame.is_some() {
            self.metrics.queue_removed(1);
        }
        frame
    }
}

impl Drop for TrackedOutbound {
    fn drop(&mut self) {
        self.metrics.queue_removed(self.receiver.len() as u64);
    }
}

fn datagram_error_is_packet_drop(error: &quinn::SendDatagramError) -> bool {
    matches!(error, quinn::SendDatagramError::TooLarge)
}

async fn wait_canceled(mut canceled: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    loop {
        if *canceled.borrow_and_update() {
            bail!("session replaced");
        }
        canceled
            .changed()
            .await
            .context("session cancellation channel closed")?;
    }
}

fn random_id() -> Result<Id> {
    loop {
        let mut value = [0_u8; 16];
        getrandom::fill(&mut value).context("generate session ID")?;
        if let Ok(id) = Id::new(value) {
            return Ok(id);
        }
    }
}

fn safe_close_reason(error: &anyhow::Error) -> String {
    let reason = error.to_string();
    reason.chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, sync::Arc};

    use laneway_protocol::{PacketHeader, encode_packet, v1::ControlEnvelope};
    use quinn::crypto::rustls::QuicClientConfig;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    };
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::oneshot,
    };
    use tokio_rustls::{TlsConnector, client::TlsStream};

    use crate::codec::{read_message, write_message};

    use super::*;

    struct Credential {
        certificate: rcgen::Certificate,
        key: KeyPair,
    }

    struct Fixture {
        directory: TempDir,
        ca: rcgen::Certificate,
        relay: Credential,
        first: Credential,
        second: Credential,
    }

    struct ClientSession {
        _endpoint: Endpoint,
        connection: Connection,
        welcome: Welcome,
        _send: SendStream,
        receive: RecvStream,
        relay_reader: RelayReader,
    }

    #[test]
    fn transient_path_mtu_limit_is_a_packet_drop_not_a_session_failure() {
        assert!(datagram_error_is_packet_drop(
            &quinn::SendDatagramError::TooLarge
        ));
    }

    #[tokio::test]
    async fn tracked_outbound_decrements_on_receive_and_teardown() {
        let metrics = Arc::new(Metrics::default());
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        for value in [1_u8, 2] {
            let depth = metrics.queue_enqueue_started();
            sender.send(Bytes::from(vec![value])).await.unwrap();
            metrics.queue_enqueue_completed(depth);
        }
        assert_eq!(metrics.snapshot().queue_depth, 2);
        assert_eq!(metrics.snapshot().queue_depth_peak, 2);

        let mut outbound = TrackedOutbound::new(receiver, Arc::clone(&metrics));
        assert!(outbound.recv().await.is_some());
        assert_eq!(metrics.snapshot().queue_depth, 1);
        drop(outbound);
        assert_eq!(metrics.snapshot().queue_depth, 0);
    }

    struct TcpClientSession {
        stream: TlsStream<TcpStream>,
        welcome: Welcome,
        relay_reader: RelayReader,
    }

    impl Fixture {
        fn new() -> Self {
            let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
            ];
            let ca_key = KeyPair::generate().unwrap();
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let issuer = Issuer::new(ca_params, ca_key);
            let network = "000102030405060708090a0b0c0d0e0f";
            Self {
                directory: tempfile::tempdir().unwrap(),
                ca,
                relay: leaf(
                    &issuer,
                    &format!(
                        "spiffe://laneway/network/{network}/relay/303132333435363738393a3b3c3d3e3f"
                    ),
                    ExtendedKeyUsagePurpose::ServerAuth,
                    true,
                ),
                first: leaf(
                    &issuer,
                    &format!(
                        "spiffe://laneway/network/{network}/node/101112131415161718191a1b1c1d1e1f"
                    ),
                    ExtendedKeyUsagePurpose::ClientAuth,
                    false,
                ),
                second: leaf(
                    &issuer,
                    &format!(
                        "spiffe://laneway/network/{network}/node/202122232425262728292a2b2c2d2e2f"
                    ),
                    ExtendedKeyUsagePurpose::ClientAuth,
                    false,
                ),
            }
        }

        fn config(&self) -> Config {
            let ca = self.directory.path().join("ca.pem");
            let cert = self.directory.path().join("relay.pem");
            let key = self.directory.path().join("relay.key");
            fs::write(&ca, self.ca.pem()).unwrap();
            fs::write(&cert, self.relay.certificate.pem()).unwrap();
            fs::write(&key, self.relay.key.serialize_pem()).unwrap();
            toml::from_str(&format!(
                r#"
mode = "relay"
[tls]
certificate = "{}"
private_key = "{}"
ca = "{}"
[relay]
listen = "127.0.0.1:0"
queue_depth = 4
max_sessions = 4
max_routes = 4
handshake_timeout = "2s"
idle_timeout = "10s"
metrics_interval = "0s"
[tcp_fallback]
listen = "127.0.0.1:0"
handshake_timeout = "2s"
write_timeout = "2s"
idle_timeout = "10s"
keepalive_period = "3s"
queue_depth = 4
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.1/32", "fd00::1/128"]
[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "202122232425262728292a2b2c2d2e2f"
prefixes = ["100.96.0.2/32", "fd00::2/128"]
"#,
                cert.display(),
                key.display(),
                ca.display()
            ))
            .unwrap()
        }
    }

    fn leaf(
        issuer: &Issuer<'static, KeyPair>,
        uri: &str,
        usage: ExtendedKeyUsagePurpose,
        server: bool,
    ) -> Credential {
        let mut params = CertificateParams::new(if server {
            vec!["localhost".to_string()]
        } else {
            Vec::new()
        })
        .unwrap();
        params
            .subject_alt_names
            .push(SanType::URI(uri.try_into().unwrap()));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, issuer).unwrap();
        Credential { certificate, key }
    }

    fn client_endpoint(ca: &rcgen::Certificate, credential: &Credential) -> quinn::Endpoint {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(credential.key.serialize_der()));
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(credential.certificate.der().to_vec())],
                key,
            )
            .unwrap();
        crypto.alpn_protocols = vec![tls::ALPN.to_vec()];
        crypto.enable_early_data = false;
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).unwrap(),
        )));
        endpoint
    }

    fn tcp_client_config(
        ca: &rcgen::Certificate,
        credential: &Credential,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(credential.key.serialize_der()));
        let mut crypto =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![CertificateDer::from(credential.certificate.der().to_vec())],
                    key,
                )
                .unwrap();
        crypto.alpn_protocols = vec![tls::TCP_FALLBACK_ALPN.to_vec()];
        crypto.enable_early_data = false;
        Arc::new(crypto)
    }

    async fn write_tcp_record(stream: &mut TlsStream<TcpStream>, kind: u8, payload: &[u8]) {
        stream
            .write_u32(u32::try_from(payload.len() + 1).unwrap())
            .await
            .unwrap();
        stream.write_u8(kind).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn read_tcp_record(stream: &mut TlsStream<TcpStream>, expected: u8) -> Vec<u8> {
        loop {
            let length = stream.read_u32().await.unwrap() as usize;
            assert!(length > 0 && length <= MAX_CONTROL_PAYLOAD + 1);
            let kind = stream.read_u8().await.unwrap();
            let mut payload = vec![0; length - 1];
            stream.read_exact(&mut payload).await.unwrap();
            if kind == 3 {
                assert!(payload.is_empty());
                write_tcp_record(stream, 4, &[]).await;
                continue;
            }
            assert_eq!(kind, expected);
            return payload;
        }
    }

    async fn connect_tcp_node(
        address: SocketAddr,
        ca: &rcgen::Certificate,
        credential: &Credential,
        node_id: u8,
        capabilities: u64,
    ) -> TcpClientSession {
        let raw = TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap().to_owned();
        let mut stream = TlsConnector::from(tcp_client_config(ca, credential))
            .connect(server_name, raw)
            .await
            .unwrap();
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(tls::TCP_FALLBACK_ALPN)
        );
        let hello = laneway_protocol::v1::ControlEnvelope {
            schema_version: 1,
            sequence: 1,
            body: Some(control_envelope::Body::Hello(Hello {
                network_id: (0_u8..16).collect(),
                node_id: (node_id..node_id + 16).collect(),
                boot_id: vec![node_id.wrapping_add(64); 16],
                protocol_major: 1,
                protocol_minor: 0,
                capabilities,
            })),
        };
        write_tcp_record(
            &mut stream,
            1,
            &encode_message(&hello, MAX_CONTROL_PAYLOAD).unwrap(),
        )
        .await;
        let welcome_payload = read_tcp_record(&mut stream, 1).await;
        let welcome_envelope = ControlReader::new().decode(&welcome_payload).unwrap();
        let welcome = match welcome_envelope.body.unwrap() {
            control_envelope::Body::Welcome(welcome) => welcome,
            body => panic!("expected Welcome, got {body:?}"),
        };
        let register = laneway_protocol::v1::RelayEnvelope {
            schema_version: 1,
            sequence: 1,
            body: Some(relay_envelope::Body::Register(RelayRegister {
                session_id: welcome.session_id.clone(),
                requested_max_routes: 4,
            })),
        };
        write_tcp_record(
            &mut stream,
            1,
            &encode_message(&register, MAX_CONTROL_PAYLOAD).unwrap(),
        )
        .await;
        TcpClientSession {
            stream,
            welcome,
            relay_reader: RelayReader::new(),
        }
    }

    async fn read_tcp_relay(client: &mut TcpClientSession) -> relay_envelope::Body {
        let payload = read_tcp_record(&mut client.stream, 1).await;
        client.relay_reader.decode(&payload).unwrap().body.unwrap()
    }

    async fn connect_node(
        address: SocketAddr,
        ca: &rcgen::Certificate,
        credential: &Credential,
        node_id: u8,
        capabilities: u64,
    ) -> ClientSession {
        let endpoint = client_endpoint(ca, credential);
        let connection = endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        send.write_all(CONTROL_PREFACE).await.unwrap();
        let hello = ControlEnvelope {
            schema_version: 1,
            sequence: 1,
            body: Some(control_envelope::Body::Hello(Hello {
                network_id: (0_u8..16).collect(),
                node_id: (node_id..node_id + 16).collect(),
                boot_id: vec![node_id.wrapping_add(64); 16],
                protocol_major: 1,
                protocol_minor: 0,
                capabilities,
            })),
        };
        write_message(&mut send, &hello, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap();
        let welcome: ControlEnvelope = read_message(&mut receive, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap();
        let welcome = match welcome.body.unwrap() {
            control_envelope::Body::Welcome(welcome) => welcome,
            body => panic!("expected Welcome, got {body:?}"),
        };
        let register = laneway_protocol::v1::RelayEnvelope {
            schema_version: 1,
            sequence: 1,
            body: Some(relay_envelope::Body::Register(RelayRegister {
                session_id: welcome.session_id.clone(),
                requested_max_routes: 4,
            })),
        };
        write_message(&mut send, &register, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap();
        ClientSession {
            _endpoint: endpoint,
            connection,
            welcome,
            _send: send,
            receive,
            relay_reader: RelayReader::new(),
        }
    }

    fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[test]
    fn hello_ignores_unknown_capabilities_in_the_intersection() {
        let identity = AuthenticatedIdentity {
            network_id: Id::new([1; 16]).unwrap(),
            role: laneway_protocol::Role::Node,
            subject_id: Id::new([2; 16]).unwrap(),
        };
        let hello = Hello {
            network_id: vec![1; 16],
            node_id: vec![2; 16],
            boot_id: vec![3; 16],
            protocol_major: 1,
            protocol_minor: 0,
            capabilities: RELAY_CAPABILITIES | (1_u64 << 63),
        };
        validate_hello(&identity, &hello, REQUIRED_RELAY_CAPABILITIES, "relay QUIC").unwrap();
        let mut mismatch = hello;
        mismatch.network_id = vec![9; 16];
        assert!(
            validate_hello(
                &identity,
                &mismatch,
                REQUIRED_RELAY_CAPABILITIES,
                "relay QUIC"
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_role_validation_rejects_a_relay_as_a_node() {
        let fixture = Fixture::new();
        assert!(tls::authenticated_node_identity(fixture.first.certificate.der()).is_ok());
        assert!(tls::authenticated_node_identity(fixture.relay.certificate.der()).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_quic_clients_exchange_a_datagram() {
        let fixture = Fixture::new();
        let server = Server::bind(fixture.config()).unwrap();
        let address = server.local_addr().unwrap();
        let metrics = server.metrics();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        let mut first = connect_node(
            address,
            &fixture.ca,
            &fixture.first,
            0x10,
            RELAY_CAPABILITIES,
        )
        .await;
        let mut second = connect_node(
            address,
            &fixture.ca,
            &fixture.second,
            0x20,
            RELAY_CAPABILITIES,
        )
        .await;
        let first_binding = first
            .relay_reader
            .read(&mut first.receive, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap();
        let second_binding = second
            .relay_reader
            .read(&mut second.receive, MAX_CONTROL_PAYLOAD)
            .await
            .unwrap();
        let first_handle = match first_binding.body.unwrap() {
            relay_envelope::Body::RouteHandleBinding(value) => value.route_handle,
            body => panic!("expected binding, got {body:?}"),
        };
        let second_handle = match second_binding.body.unwrap() {
            relay_envelope::Body::RouteHandleBinding(value) => value.route_handle,
            body => panic!("expected binding, got {body:?}"),
        };
        let mut frame = Vec::new();
        encode_packet(
            PacketHeader {
                version: 1,
                flags: 0,
                route_handle: first_handle,
            },
            &ipv4([100, 96, 0, 1], [100, 96, 0, 2]),
            &mut frame,
        )
        .unwrap();
        first
            .connection
            .send_datagram_wait(Bytes::from(frame))
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(2), second.connection.read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            PacketHeader::decode(&received).unwrap().route_handle,
            second_handle
        );
        assert_eq!(metrics.snapshot().forwarded_packets, 1);
        assert_eq!(metrics.snapshot().quic_connection_attempts, 2);

        let _ = stop.send(());
        task.await.unwrap().unwrap();
        assert_eq!(metrics.snapshot().sessions, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stable_v1_tcp_clients_exchange_a_framed_packet() {
        let fixture = Fixture::new();
        let server = Server::bind(fixture.config()).unwrap();
        let address = server.tcp_fallback_addr().unwrap().unwrap();
        let metrics = server.metrics();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        let capabilities = REQUIRED_TCP_CAPABILITIES | Capability::LanewayIpv6V1 as u64;
        let mut first =
            connect_tcp_node(address, &fixture.ca, &fixture.first, 0x10, capabilities).await;
        let mut second =
            connect_tcp_node(address, &fixture.ca, &fixture.second, 0x20, capabilities).await;
        assert_eq!(first.welcome.capabilities, capabilities);
        assert_eq!(
            first.welcome.capabilities & Capability::LanewayQuicDatagramV1 as u64,
            0
        );
        let first_handle = match read_tcp_relay(&mut first).await {
            relay_envelope::Body::RouteHandleBinding(binding) => binding.route_handle,
            body => panic!("expected binding, got {body:?}"),
        };
        let second_handle = match read_tcp_relay(&mut second).await {
            relay_envelope::Body::RouteHandleBinding(binding) => binding.route_handle,
            body => panic!("expected binding, got {body:?}"),
        };
        let mut frame = Vec::new();
        encode_packet(
            PacketHeader {
                version: 1,
                flags: 0,
                route_handle: first_handle,
            },
            &ipv4([100, 96, 0, 1], [100, 96, 0, 2]),
            &mut frame,
        )
        .unwrap();
        write_tcp_record(&mut first.stream, 2, &frame).await;
        let received = timeout(
            Duration::from_secs(2),
            read_tcp_record(&mut second.stream, 2),
        )
        .await
        .unwrap();
        assert_eq!(
            PacketHeader::decode(&received).unwrap().route_handle,
            second_handle
        );
        assert_eq!(metrics.snapshot().forwarded_packets, 1);
        assert_eq!(metrics.snapshot().tcp_connection_attempts, 2);
        assert_eq!(metrics.snapshot().tcp_packet_pool_misses, 0);
        assert_eq!(metrics.snapshot().queue_depth, 0);
        assert!(metrics.snapshot().queue_depth_peak >= 1);

        let _ = stop.send(());
        task.await.unwrap().unwrap();
        assert_eq!(metrics.snapshot().sessions, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_replaces_the_same_identity_across_carriers() {
        let fixture = Fixture::new();
        let server = Server::bind(fixture.config()).unwrap();
        let quic_address = server.local_addr().unwrap();
        let tcp_address = server.tcp_fallback_addr().unwrap().unwrap();
        let metrics = server.metrics();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        let quic = connect_node(
            quic_address,
            &fixture.ca,
            &fixture.first,
            0x10,
            REQUIRED_RELAY_CAPABILITIES,
        )
        .await;
        let tcp = connect_tcp_node(
            tcp_address,
            &fixture.ca,
            &fixture.first,
            0x10,
            REQUIRED_TCP_CAPABILITIES,
        )
        .await;
        assert_eq!(tcp.welcome.capabilities, REQUIRED_TCP_CAPABILITIES);
        timeout(Duration::from_secs(2), async {
            while metrics.snapshot().sessions_replaced == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        timeout(Duration::from_secs(2), quic.connection.closed())
            .await
            .unwrap();
        assert_eq!(metrics.snapshot().sessions, 1);

        let _ = stop.send(());
        task.await.unwrap().unwrap();
        assert_eq!(metrics.snapshot().sessions, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ipv4_only_negotiation_filters_ipv6_overlay_addresses() {
        let fixture = Fixture::new();
        let server = Server::bind(fixture.config()).unwrap();
        let address = server.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        let capabilities = REQUIRED_RELAY_CAPABILITIES;
        let client = connect_node(address, &fixture.ca, &fixture.first, 0x10, capabilities).await;
        assert_eq!(client.welcome.capabilities, capabilities);
        assert_eq!(client.welcome.overlay_addresses, vec![vec![100, 96, 0, 1]]);

        let _ = stop.send(());
        task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_exposes_actual_metrics_address_and_stops_diagnostics() {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        config.relay.metrics_listen = "127.0.0.1:0".to_owned();
        let server = Server::bind(config).unwrap();
        let address = server.metrics_addr().unwrap().unwrap();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.serve_until(async move {
            let _ = stopped.await;
        }));

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        timeout(Duration::from_secs(2), client.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("laneway_relay_quic_connection_attempts_total 0\n"));
        assert!(response.contains("laneway_relay_tcp_packet_pool_misses_total 0\n"));

        let _ = stop.send(());
        task.await.unwrap().unwrap();
    }

    #[test]
    fn fixture_paths_are_private_test_material() {
        let fixture = Fixture::new();
        let config = fixture.config();
        for path in [
            &config.tls.ca_file,
            &config.tls.certificate_file,
            &config.tls.private_key_file,
        ] {
            assert!(Path::new(path).starts_with(fixture.directory.path()));
        }
    }
}
