use std::{
    future::Future,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use laneway_protocol::{
    Id, PacketHeader, Role, decode_packet,
    v1::{
        Capability, ControlEnvelope, EndpointCandidate, EndpointTransport, Hello, RelayEnvelope,
        RelayRegister, Welcome, control_envelope, relay_envelope,
    },
};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::{
    sync::mpsc,
    time::{Instant, interval_at, sleep, timeout},
};
use tracing::{info, warn};

use crate::{
    codec::{
        MAX_CONTROL_PAYLOAD, SCHEMA_VERSION, decode_message, encode_message, next_sequence,
        read_message, write_message,
    },
    config::Config,
    metrics::Metrics,
    packet_pool::{PacketPool, PooledPacket},
    routing::{locally_owned, packet_meta},
    state::{Handle, State},
    tcp_fallback, tls,
};

const CONTROL_PREFACE: &[u8] = b"LWC1";
const REQUIRED_CAPABILITIES: u64 =
    Capability::LanewayRelayV1 as u64 | Capability::LanewayQuicDatagramV1 as u64;
const REQUIRED_TCP_CAPABILITIES: u64 =
    Capability::LanewayRelayV1 as u64 | Capability::LanewayTcpFallbackV1 as u64;
const KNOWN_CAPABILITIES: u64 = REQUIRED_CAPABILITIES
    | Capability::LanewayDirectPeerV1 as u64
    | Capability::LanewaySubnetRouterV1 as u64
    | Capability::LanewayExitNodeV1 as u64
    | Capability::LanewayTcpFallbackV1 as u64
    | Capability::LanewayIpv6V1 as u64
    | Capability::LanewayE2ePacketV1 as u64;

/// One packet queued from the TUN reader toward the relay.
#[derive(Debug)]
pub(crate) struct OutboundPacket {
    /// Authenticated next-hop node selected by the route snapshot.
    pub peer: Id,
    /// Complete raw IP packet.
    packet: PooledPacket,
}

impl OutboundPacket {
    /// Wraps an independently owned packet buffer.
    #[cfg(test)]
    pub(crate) fn new(peer: Id, packet: Vec<u8>) -> Self {
        Self {
            peer,
            packet: PooledPacket::unpooled(packet),
        }
    }

    pub(crate) fn pooled(peer: Id, packet: &[u8], pool: &PacketPool) -> (Self, bool) {
        let (packet, miss) = pool.copy(packet);
        (Self { peer, packet }, miss)
    }
}

/// Reconnecting QUIC relay client.
pub struct RelayClient {
    endpoint: Endpoint,
    config: Arc<Config>,
    state: Arc<State>,
    metrics: Arc<Metrics>,
    network: Id,
    node: Id,
    boot: Id,
    owned: Arc<Vec<ipnet::IpNet>>,
    inject: mpsc::Sender<Bytes>,
    candidates: mpsc::Sender<EndpointCandidate>,
    relay_cursor: AtomicUsize,
}

struct QuicSession {
    connection: Connection,
    send: SendStream,
    receive: RecvStream,
    negotiated: u64,
    inbound_sequence: u64,
    outbound_sequence: u64,
    relay_service: Id,
    relay_address: std::net::SocketAddr,
}

struct TcpSession {
    connection: tcp_fallback::Session,
    negotiated: u64,
    inbound_sequence: u64,
}

type QuicRecovery<'a> = Pin<Box<dyn Future<Output = Result<QuicSession>> + Send + 'a>>;

impl RelayClient {
    /// Constructs a relay client around a shared direct/relay QUIC endpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: Endpoint,
        config: Arc<Config>,
        state: Arc<State>,
        metrics: Arc<Metrics>,
        network: Id,
        node: Id,
        boot: Id,
        owned: Arc<Vec<ipnet::IpNet>>,
        inject: mpsc::Sender<Bytes>,
        candidates: mpsc::Sender<EndpointCandidate>,
    ) -> Self {
        Self {
            endpoint,
            config,
            state,
            metrics,
            network,
            node,
            boot,
            owned,
            inject,
            candidates,
            relay_cursor: AtomicUsize::new(0),
        }
    }

    /// Reconnects forever until canceled by task shutdown.
    pub async fn run(self, mut outbound: mpsc::Receiver<OutboundPacket>) -> Result<()> {
        let mut delay = self.config.relay.reconnect_min;
        let mut connected_once = false;
        loop {
            Metrics::increment(&self.metrics.quic_attempts);
            match self.prepare_quic().await {
                Ok(session) => {
                    record_connection(&self.metrics, &mut connected_once);
                    Metrics::set(&self.metrics.quic_active, true);
                    delay = self.config.relay.reconnect_min;
                    info!(remote = ?self.config.relay.address, "Rust agent relay connected");
                    if let Err(error) = self.run_quic_session(session, &mut outbound).await {
                        Metrics::increment(&self.metrics.quic_failures);
                        warn!(%error, "relay session ended; reconnecting");
                    }
                    Metrics::set(&self.metrics.quic_active, false);
                    self.state.clear_handles();
                }
                Err(quic_error) => {
                    Metrics::increment(&self.metrics.quic_failures);
                    if let Some(fallback) = &self.config.tcp_fallback {
                        Metrics::increment(&self.metrics.tcp_attempts);
                        match self.prepare_tcp().await {
                            Ok(session) => {
                                record_connection(&self.metrics, &mut connected_once);
                                Metrics::increment(&self.metrics.tcp_connections_total);
                                Metrics::set(&self.metrics.tcp_active, true);
                                delay = self.config.relay.reconnect_min;
                                info!(remote = %fallback.address, "Rust agent relay TCP fallback connected");
                                match self.run_tcp_until_quic(session, &mut outbound).await {
                                    Ok(quic) => {
                                        Metrics::set(&self.metrics.tcp_active, false);
                                        Metrics::set(&self.metrics.quic_active, true);
                                        self.state.clear_handles();
                                        info!(remote = ?self.config.relay.address, "promoted healthy TCP fallback to relay QUIC");
                                        if let Err(error) =
                                            self.run_quic_session(quic, &mut outbound).await
                                        {
                                            Metrics::increment(&self.metrics.quic_failures);
                                            warn!(%error, "promoted relay QUIC session ended; reconnecting");
                                        }
                                        Metrics::set(&self.metrics.quic_active, false);
                                    }
                                    Err(error) => {
                                        Metrics::increment(&self.metrics.tcp_failures);
                                        warn!(%error, "relay TCP fallback session ended; reconnecting")
                                    }
                                }
                                Metrics::set(&self.metrics.tcp_active, false);
                                self.state.clear_handles();
                            }
                            Err(tcp_error) => {
                                Metrics::increment(&self.metrics.tcp_failures);
                                warn!(%quic_error, %tcp_error, ?delay, "relay QUIC and TCP fallback failed")
                            }
                        }
                    } else {
                        warn!(error = %quic_error, ?delay, "relay connection failed");
                    }
                }
            }
            sleep(jitter(delay)).await;
            delay = delay
                .checked_mul(2)
                .unwrap_or(self.config.relay.reconnect_max)
                .min(self.config.relay.reconnect_max);
        }
    }

    async fn prepare_quic(&self) -> Result<QuicSession> {
        let (connection, relay_service, relay_address) = self.connect().await?;
        let result = timeout(self.config.relay.handshake_timeout, async {
            let offered = hello_capabilities_for(&self.config, REQUIRED_CAPABILITIES);
            let (mut send, mut receive) = connection
                .open_bi()
                .await
                .context("open relay control stream")?;
            send.write_all(CONTROL_PREFACE).await?;
            write_message(
                &mut send,
                &ControlEnvelope {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    body: Some(control_envelope::Body::Hello(self.hello(offered))),
                },
                MAX_CONTROL_PAYLOAD,
            )
            .await?;
            let welcome: ControlEnvelope = read_message(&mut receive, MAX_CONTROL_PAYLOAD).await?;
            let (welcome, negotiated) =
                validate_control_welcome(welcome, offered, REQUIRED_CAPABILITIES)?;
            write_message(
                &mut send,
                &RelayEnvelope {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    body: Some(relay_envelope::Body::Register(RelayRegister {
                        session_id: welcome.session_id,
                        requested_max_routes: self.config.relay.max_routes,
                    })),
                },
                MAX_CONTROL_PAYLOAD,
            )
            .await?;
            let mut outbound_sequence = 2;
            if negotiated & Capability::LanewayDirectPeerV1 as u64 != 0
                && self.state.candidate_exchange_enabled()
            {
                self.publish_candidate(&mut send, outbound_sequence).await?;
                outbound_sequence = 3;
            }
            Result::<_>::Ok(QuicSession {
                connection: connection.clone(),
                send,
                receive,
                negotiated,
                inbound_sequence: 1,
                outbound_sequence,
                relay_service,
                relay_address,
            })
        })
        .await
        .context("relay QUIC control handshake timed out")?;
        if result.is_err() {
            connection.close(0_u32.into(), b"relay control handshake failed");
        }
        result
    }

    async fn prepare_tcp(&self) -> Result<TcpSession> {
        if self.state.relay_targets().is_some() {
            let service =
                Id::from_str(&self.config.relay.service_id).context("relay.service_id")?;
            let address = self
                .config
                .relay
                .address
                .context("relay QUIC address is disabled")?;
            ensure!(
                self.state.relay_authorized(service, address),
                "configured TCP fallback relay is no longer controller-authorized"
            );
        }
        let mut connection = tcp_fallback::connect(&self.config, self.network).await?;
        let offered = hello_capabilities_for(&self.config, REQUIRED_TCP_CAPABILITIES);
        let hello = ControlEnvelope {
            schema_version: SCHEMA_VERSION,
            sequence: 1,
            body: Some(control_envelope::Body::Hello(self.hello(offered))),
        };
        connection
            .writer
            .control(encode_message(&hello, MAX_CONTROL_PAYLOAD)?)
            .await?;
        let payload = timeout(
            self.config
                .tcp_fallback
                .as_ref()
                .context("TCP fallback disabled")?
                .handshake_timeout,
            connection.control.recv(),
        )
        .await
        .context("TCP fallback Welcome timed out")?
        .context("TCP fallback control queue closed")?;
        let welcome: ControlEnvelope = decode_message(&payload)?;
        let (welcome, negotiated) =
            validate_control_welcome(welcome, offered, REQUIRED_TCP_CAPABILITIES)?;
        connection
            .writer
            .control(encode_message(
                &RelayEnvelope {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    body: Some(relay_envelope::Body::Register(RelayRegister {
                        session_id: welcome.session_id,
                        requested_max_routes: self.config.relay.max_routes,
                    })),
                },
                MAX_CONTROL_PAYLOAD,
            )?)
            .await?;
        Ok(TcpSession {
            connection,
            negotiated,
            inbound_sequence: 1,
        })
    }

    fn hello(&self, capabilities: u64) -> Hello {
        Hello {
            network_id: self.network.as_bytes().to_vec(),
            node_id: self.node.as_bytes().to_vec(),
            boot_id: self.boot.as_bytes().to_vec(),
            protocol_major: 1,
            protocol_minor: 0,
            capabilities,
        }
    }

    async fn connect(&self) -> Result<(Connection, Id, std::net::SocketAddr)> {
        let targets = if let Some(targets) = self.state.relay_targets() {
            ensure!(
                !targets.is_empty(),
                "controller authorized no relay targets"
            );
            targets
        } else {
            vec![(
                Id::from_str(&self.config.relay.service_id).context("relay.service_id")?,
                self.config
                    .relay
                    .address
                    .context("relay QUIC address is disabled")?,
            )]
        };
        let start = self.relay_cursor.fetch_add(1, Ordering::Relaxed) % targets.len();
        let mut failures = Vec::new();
        for offset in 0..targets.len() {
            let (service, address) = targets[(start + offset) % targets.len()];
            let attempt = async {
                let client =
                    tls::client_config(&self.config.tls, &self.config.relay, tls::RELAY_ALPN)?;
                let connecting = self
                    .endpoint
                    .connect_with(client, address, &self.config.relay.server_name)
                    .context("start relay QUIC connection")?;
                let connection = timeout(self.config.relay.handshake_timeout, connecting)
                    .await
                    .context("relay QUIC handshake timed out")?
                    .context("relay QUIC handshake")?;
                tls::validate_peer(
                    &connection,
                    tls::RELAY_ALPN,
                    self.network,
                    Role::Relay,
                    Some(service),
                )?;
                Result::<_>::Ok(connection)
            }
            .await;
            match attempt {
                Ok(connection) => return Ok((connection, service, address)),
                Err(error) => failures.push(format!("{service}@{address}: {error:#}")),
            }
        }
        bail!(
            "all authorized relay QUIC targets failed: {}",
            failures.join("; ")
        )
    }

    async fn run_quic_session(
        &self,
        mut session: QuicSession,
        outbound: &mut mpsc::Receiver<OutboundPacket>,
    ) -> Result<()> {
        let refresh = self.config.direct.candidate_refresh_interval;
        let mut candidate_refresh = interval_at(Instant::now() + refresh, refresh);
        let authority_cadence = Duration::from_millis(250);
        let mut authority_check =
            interval_at(Instant::now() + authority_cadence, authority_cadence);
        loop {
            tokio::select! {
                packet = outbound.recv() => {
                    self.metrics.set_outbound_queue_depth(
                        outbound.max_capacity().saturating_sub(outbound.capacity()),
                    );
                    let packet = packet.context("outbound packet queue closed")?;
                    self.send_packet(&session.connection, packet, session.negotiated)?;
                }
                frame = session.connection.read_datagram() => {
                    let frame = frame.context("read relay datagram")?;
                    self.receive_packet(frame, session.negotiated).await;
                }
                envelope = read_message::<_, RelayEnvelope>(&mut session.receive, MAX_CONTROL_PAYLOAD) => {
                    let envelope = envelope?;
                    let expected = next_sequence(&mut session.inbound_sequence)?;
                    ensure!(envelope.schema_version == SCHEMA_VERSION && envelope.sequence == expected, "invalid relay envelope sequence");
                    self.control(envelope, session.negotiated)?;
                }
                _ = candidate_refresh.tick(), if session.negotiated & Capability::LanewayDirectPeerV1 as u64 != 0
                    && self.state.candidate_exchange_enabled() => {
                    let sequence = next_sequence(&mut session.outbound_sequence)?;
                    timeout(
                        self.config.relay.handshake_timeout,
                        self.publish_candidate(&mut session.send, sequence),
                    )
                    .await
                    .context("periodic candidate publication timed out")??;
                }
                _ = authority_check.tick() => {
                    ensure!(
                        self.state.relay_authorized(session.relay_service, session.relay_address),
                        "active relay was withdrawn by controller"
                    );
                }
                error = session.connection.closed() => return Err(error.into()),
            }
        }
    }

    async fn run_tcp_until_quic(
        &self,
        mut session: TcpSession,
        outbound: &mut mpsc::Receiver<OutboundPacket>,
    ) -> Result<QuicSession> {
        let cadence = self.config.relay.quic_recovery_interval;
        let mut retries = interval_at(Instant::now() + cadence, cadence);
        let authority_cadence = Duration::from_millis(250);
        let mut authority_check =
            interval_at(Instant::now() + authority_cadence, authority_cadence);
        let mut recovery: Option<QuicRecovery<'_>> = None;
        let mut ready_quic: Option<QuicSession> = None;
        let result = async {
            loop {
                tokio::select! {
                    packet = outbound.recv() => {
                        self.metrics.set_outbound_queue_depth(
                            outbound.max_capacity().saturating_sub(outbound.capacity()),
                        );
                        if let Some(frame) = self.frame_packet(packet.context("outbound packet queue closed")?, session.negotiated)? {
                            session.connection.writer.packet(Bytes::from_owner(frame)).await?;
                        }
                    }
                    frame = session.connection.packets.recv() => {
                        self.receive_packet(frame.context("TCP fallback packet queue closed")?, session.negotiated).await;
                    }
                    payload = session.connection.control.recv() => {
                        let envelope: RelayEnvelope = decode_message(&payload.context("TCP fallback control queue closed")?)?;
                        let expected = next_sequence(&mut session.inbound_sequence)?;
                        ensure!(envelope.schema_version == SCHEMA_VERSION && envelope.sequence == expected, "invalid relay envelope sequence");
                        self.control(envelope, session.negotiated)?;
                    }
                    _ = retries.tick(), if recovery.is_none() && ready_quic.is_none() => {
                        Metrics::increment(&self.metrics.quic_attempts);
                        recovery = Some(Box::pin(self.prepare_quic()));
                    }
                    _ = authority_check.tick() => {
                        let service = Id::from_str(&self.config.relay.service_id).context("relay.service_id")?;
                        let address = self.config.relay.address.context("relay QUIC address is disabled")?;
                        ensure!(self.state.relay_authorized(service, address), "active TCP relay was withdrawn by controller");
                    }
                    prepared = async { recovery.as_mut().expect("recovery future exists").await }, if recovery.is_some() => {
                        match prepared {
                            Ok(quic) => {
                                // Do not close the sole active packet carrier merely
                                // because registration was written. The relay proves
                                // it installed the replacement by canceling the old
                                // duplicate-identity TCP session.
                                ready_quic = Some(quic);
                                recovery = None;
                            }
                            Err(error) => {
                                Metrics::increment(&self.metrics.quic_failures);
                                warn!(%error, "relay QUIC recovery attempt failed; retaining TCP fallback");
                                recovery = None;
                            }
                        }
                    }
                    error = async { ready_quic.as_ref().expect("ready QUIC exists").connection.closed().await }, if ready_quic.is_some() => {
                        warn!(%error, "prepared relay QUIC closed before replacing TCP; retaining fallback");
                        ready_quic = None;
                    }
                    reason = tcp_fallback::wait_done(&mut session.connection.done) => {
                        if let Some(quic) = ready_quic.take() {
                            break Ok(quic);
                        }
                        if let Some(preparing) = recovery.take() {
                            match preparing.await {
                                Ok(quic) => break Ok(quic),
                                Err(error) => {
                                    break Err(anyhow::anyhow!(
                                        "TCP fallback ended: {reason}; concurrent QUIC recovery failed: {error}"
                                    ));
                                }
                            }
                        }
                        break Err(anyhow::anyhow!("TCP fallback ended: {reason}"));
                    }
                }
            }
        }
        .await;
        session.connection.close().await;
        result
    }

    async fn publish_candidate(&self, send: &mut SendStream, sequence: u64) -> Result<()> {
        let local = self
            .endpoint
            .local_addr()
            .context("read shared UDP endpoint")?;
        let ip_address = match local.ip() {
            std::net::IpAddr::V4(value) => value.octets().to_vec(),
            std::net::IpAddr::V6(value) => value.octets().to_vec(),
        };
        write_message(
            send,
            &RelayEnvelope {
                schema_version: SCHEMA_VERSION,
                sequence,
                body: Some(relay_envelope::Body::EndpointCandidate(EndpointCandidate {
                    node_id: self.node.as_bytes().to_vec(),
                    ip_address,
                    port: u32::from(local.port()),
                    transport: EndpointTransport::QuicUdp as i32,
                    priority: 0,
                    rendezvous_token: Vec::new(),
                    probe_start_unix_nano: 0,
                })),
            },
            MAX_CONTROL_PAYLOAD,
        )
        .await
    }

    fn send_packet(
        &self,
        connection: &Connection,
        outbound: OutboundPacket,
        negotiated_capabilities: u64,
    ) -> Result<()> {
        let Some(frame) = self.frame_packet(outbound, negotiated_capabilities)? else {
            return Ok(());
        };
        connection
            .send_datagram(Bytes::from_owner(frame))
            .context("send relay datagram")?;
        Ok(())
    }

    fn frame_packet(
        &self,
        outbound: OutboundPacket,
        negotiated_capabilities: u64,
    ) -> Result<Option<PooledPacket>> {
        let Ok(meta) = packet_meta(&outbound.packet) else {
            Metrics::increment(&self.metrics.invalid_drops);
            return Ok(None);
        };
        if !self
            .state
            .allows(self.node, outbound.peer, &outbound.packet)
        {
            Metrics::increment(&self.metrics.invalid_drops);
            return Ok(None);
        }
        if !packet_capabilities_allow(
            &self.config,
            &self.state.routes.load(),
            meta,
            negotiated_capabilities,
            false,
        ) {
            Metrics::increment(&self.metrics.invalid_drops);
            return Ok(None);
        }
        let handles = self.state.handles.load();
        let Some(handle) = handles.outbound.get(&outbound.peer) else {
            Metrics::increment(&self.metrics.no_path_drops);
            return Ok(None);
        };
        if outbound.packet.len() > handle.max_payload {
            Metrics::increment(&self.metrics.invalid_drops);
            return Ok(None);
        }
        let mut frame = outbound.packet;
        let packet_length = frame.len();
        frame.reserve(5);
        frame.resize(packet_length + 5, 0);
        frame.copy_within(..packet_length, 5);
        frame[..5].copy_from_slice(
            &PacketHeader {
                version: 1,
                flags: 0,
                route_handle: handle.value,
            }
            .encode()?,
        );
        Metrics::increment(&self.metrics.relay_packets);
        Ok(Some(frame))
    }

    async fn receive_packet(&self, frame: Bytes, negotiated_capabilities: u64) {
        let Ok((header, packet)) = decode_packet(&frame) else {
            Metrics::increment(&self.metrics.invalid_drops);
            Metrics::increment(&self.metrics.malformed_drops);
            return;
        };
        let handles = self.state.handles.load();
        let Some(peer) = handles.inbound.get(&header.route_handle).copied() else {
            Metrics::increment(&self.metrics.invalid_drops);
            return;
        };
        let Ok(meta) = packet_meta(packet) else {
            Metrics::increment(&self.metrics.invalid_drops);
            Metrics::increment(&self.metrics.malformed_drops);
            return;
        };
        if !self.state.allows(peer, self.node, packet) {
            Metrics::increment(&self.metrics.invalid_drops);
            Metrics::increment(&self.metrics.policy_drops);
            return;
        }
        let routes = self.state.routes.load();
        if !packet_capabilities_allow(&self.config, &routes, meta, negotiated_capabilities, true) {
            Metrics::increment(&self.metrics.invalid_drops);
            Metrics::increment(&self.metrics.policy_drops);
            return;
        }
        if !routes.authorizes_source(peer, meta.source)
            || (!self.state.owns(&self.owned, meta.destination)
                && !self.config.forwarding.exit_gateway)
        {
            Metrics::increment(&self.metrics.invalid_drops);
            Metrics::increment(&self.metrics.auth_drops);
            return;
        }
        let payload_offset = frame.len() - packet.len();
        let sent = self.inject.try_send(frame.slice(payload_offset..));
        let depth = self
            .inject
            .max_capacity()
            .saturating_sub(self.inject.capacity());
        self.metrics.set_inject_queue_depth(depth);
        if sent.is_err() {
            Metrics::increment(&self.metrics.queue_drops);
        }
    }

    fn control(&self, envelope: RelayEnvelope, negotiated_capabilities: u64) -> Result<()> {
        match envelope.body {
            Some(relay_envelope::Body::RouteHandleBinding(binding)) => {
                ensure!(binding.route_handle != 0, "relay bound zero handle");
                let peer = Id::from_slice(&binding.peer_node_id).context("binding peer ID")?;
                ensure!(peer != self.node, "relay bound local node as peer");
                ensure!(
                    binding.max_packet_payload >= 576
                        && binding.max_packet_payload <= u32::from(self.config.tun.mtu),
                    "invalid binding packet limit"
                );
                ensure!(
                    self.state
                        .routes
                        .load()
                        .routes()
                        .iter()
                        .any(|route| route.via == peer),
                    "relay bound an unconfigured peer"
                );
                self.state.bind(
                    peer,
                    Handle {
                        value: binding.route_handle,
                        max_payload: binding.max_packet_payload as usize,
                    },
                );
            }
            Some(relay_envelope::Body::RouteHandleRelease(release)) => {
                ensure!(release.route_handle != 0, "relay released zero handle");
                self.state.release(release.route_handle);
            }
            Some(relay_envelope::Body::EndpointCandidate(candidate)) => {
                ensure!(
                    negotiated_capabilities & Capability::LanewayDirectPeerV1 as u64 != 0,
                    "relay sent endpoint candidate without direct-path negotiation"
                );
                if self.state.candidate_exchange_enabled() {
                    self.candidates
                        .try_send(candidate)
                        .context("direct candidate queue is full or closed")?;
                }
            }
            Some(relay_envelope::Body::Error(error)) => {
                bail!("relay protocol error {}: {}", error.code, error.detail)
            }
            _ => bail!("unexpected relay control message"),
        }
        Ok(())
    }
}

fn record_connection(metrics: &Metrics, connected_once: &mut bool) {
    Metrics::increment(&metrics.connections_total);
    if *connected_once {
        Metrics::increment(&metrics.reconnects_total);
    }
    *connected_once = true;
}

#[cfg(test)]
fn hello_capabilities(config: &Config) -> u64 {
    hello_capabilities_for(config, REQUIRED_CAPABILITIES)
}

fn hello_capabilities_for(config: &Config, required: u64) -> u64 {
    let mut capabilities = required;
    if required & Capability::LanewayQuicDatagramV1 as u64 != 0
        && (config.controller.is_some() || !config.direct_peers.is_empty())
    {
        capabilities |= Capability::LanewayDirectPeerV1 as u64;
    }
    if config.forwarding.subnet_router
        || config
            .routes
            .iter()
            .any(|route| route.kind == crate::config::RouteKind::Subnet)
    {
        capabilities |= Capability::LanewaySubnetRouterV1 as u64;
    }
    if config.forwarding.exit_gateway
        || config
            .routes
            .iter()
            .any(|route| route.kind == crate::config::RouteKind::Exit)
    {
        capabilities |= Capability::LanewayExitNodeV1 as u64;
    }
    if config.controller.is_some() {
        // Controller snapshots may add these route families after this relay
        // session is established. Negotiation declares implementation support;
        // the leased snapshot remains the independent authorization source.
        capabilities |= Capability::LanewaySubnetRouterV1 as u64
            | Capability::LanewayExitNodeV1 as u64
            | Capability::LanewayIpv6V1 as u64;
    }
    if config
        .tun
        .addresses
        .iter()
        .chain(config.routes.iter().map(|route| &route.prefix))
        .chain(config.forwarding.owned_prefixes.iter())
        .any(|prefix| matches!(prefix, ipnet::IpNet::V6(_)))
    {
        capabilities |= Capability::LanewayIpv6V1 as u64;
    }
    capabilities
}

fn packet_capabilities_allow(
    config: &Config,
    routes: &crate::routing::RoutingTable,
    meta: crate::routing::PacketMeta,
    capabilities: u64,
    inbound: bool,
) -> bool {
    if meta.source.is_ipv6() && capabilities & Capability::LanewayIpv6V1 as u64 == 0 {
        return false;
    }
    let route_address = if inbound {
        meta.source
    } else {
        meta.destination
    };
    if let Some(route) = routes.lookup(route_address) {
        let required = match route.kind {
            crate::config::RouteKind::Overlay => 0,
            crate::config::RouteKind::Subnet => Capability::LanewaySubnetRouterV1 as u64,
            crate::config::RouteKind::Exit => Capability::LanewayExitNodeV1 as u64,
        };
        if capabilities & required != required {
            return false;
        }
    }
    if config.forwarding.subnet_router
        && !locally_owned(&config.tun.addresses, meta.source)
        && locally_owned(&config.forwarding.owned_prefixes, meta.source)
        && capabilities & Capability::LanewaySubnetRouterV1 as u64 == 0
    {
        return false;
    }
    if inbound
        && config.forwarding.exit_gateway
        && !locally_owned(&config.tun.addresses, meta.destination)
        && !locally_owned(&config.forwarding.owned_prefixes, meta.destination)
        && capabilities & Capability::LanewayExitNodeV1 as u64 == 0
    {
        return false;
    }
    true
}

fn validate_welcome(
    welcome: &Welcome,
    offered_capabilities: u64,
    required_capabilities: u64,
) -> Result<u64> {
    Id::from_slice(&welcome.session_id).context("Welcome session ID")?;
    ensure!(
        welcome.capabilities & !KNOWN_CAPABILITIES == 0
            && welcome.capabilities & !offered_capabilities == 0,
        "Welcome capabilities are not a known subset of Hello"
    );
    ensure!(
        welcome.capabilities & required_capabilities == required_capabilities,
        "relay lacks required capabilities"
    );
    for address in &welcome.overlay_addresses {
        ensure!(
            address.len() == 4 || address.len() == 16,
            "invalid Welcome overlay address"
        );
        ensure!(
            address.len() != 16 || welcome.capabilities & Capability::LanewayIpv6V1 as u64 != 0,
            "Welcome includes IPv6 without IPv6 capability"
        );
    }
    ensure!(
        welcome.max_control_payload > 0
            && welcome.max_control_payload as usize <= MAX_CONTROL_PAYLOAD,
        "invalid Welcome control limit"
    );
    ensure!(
        welcome.max_packet_payload >= 576 && welcome.max_packet_payload <= 65_535,
        "invalid Welcome packet limit"
    );
    Ok(welcome.capabilities)
}

fn validate_control_welcome(
    envelope: ControlEnvelope,
    offered_capabilities: u64,
    required_capabilities: u64,
) -> Result<(Welcome, u64)> {
    ensure!(
        envelope.schema_version == SCHEMA_VERSION && envelope.sequence == 1,
        "invalid Welcome envelope"
    );
    let welcome = match envelope.body {
        Some(control_envelope::Body::Welcome(value)) => value,
        _ => bail!("relay did not send Welcome"),
    };
    let negotiated = validate_welcome(&welcome, offered_capabilities, required_capabilities)?;
    Ok((welcome, negotiated))
}

fn jitter(delay: Duration) -> Duration {
    let mut byte = [0_u8; 1];
    if getrandom::fill(&mut byte).is_err() {
        return delay;
    }
    let percent = 75_u128 + u128::from(byte[0] % 51);
    Duration::from_nanos(
        (delay.as_nanos().saturating_mul(percent) / 100).min(u64::MAX.into()) as u64,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::SocketAddr,
        str::FromStr,
        sync::atomic::{AtomicBool, Ordering},
    };

    use ipnet::IpNet;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream, UdpSocket},
        sync::oneshot,
    };

    use super::*;
    use crate::{config::Config, routing::RoutingTable};

    #[test]
    fn reconnect_jitter_is_bounded() {
        let base = Duration::from_secs(4);
        for _ in 0..100 {
            let value = jitter(base);
            assert!(value >= Duration::from_secs(3));
            assert!(value <= Duration::from_secs(5));
        }
    }

    #[test]
    fn rejects_invalid_welcome() {
        let welcome = Welcome {
            session_id: vec![1; 16],
            capabilities: Capability::LanewayRelayV1 as u64,
            max_control_payload: 1024,
            max_packet_payload: 1200,
            ..Welcome::default()
        };
        assert!(validate_welcome(&welcome, REQUIRED_CAPABILITIES, REQUIRED_CAPABILITIES).is_err());

        let unexpected = Welcome {
            session_id: vec![1; 16],
            capabilities: REQUIRED_CAPABILITIES | Capability::LanewayIpv6V1 as u64,
            max_control_payload: 1024,
            max_packet_payload: 1280,
            ..Welcome::default()
        };
        assert!(
            validate_welcome(&unexpected, REQUIRED_CAPABILITIES, REQUIRED_CAPABILITIES).is_err()
        );

        let unknown = Welcome {
            capabilities: REQUIRED_CAPABILITIES | (1_u64 << 63),
            ..unexpected
        };
        assert!(validate_welcome(&unknown, u64::MAX, REQUIRED_CAPABILITIES).is_err());
    }

    #[test]
    fn hello_advertises_only_configured_implemented_features() {
        let mut config: Config =
            toml::from_str(include_str!("../../../deploy/examples/node-rust.toml")).unwrap();
        let capabilities = hello_capabilities(&config);
        assert_eq!(
            capabilities,
            REQUIRED_CAPABILITIES | Capability::LanewayDirectPeerV1 as u64
        );

        config.forwarding.subnet_router = true;
        config.forwarding.exit_gateway = true;
        config.tun.addresses.push("fd00::1/128".parse().unwrap());
        let capabilities = hello_capabilities(&config);
        assert_ne!(capabilities & Capability::LanewaySubnetRouterV1 as u64, 0);
        assert_ne!(capabilities & Capability::LanewayExitNodeV1 as u64, 0);
        assert_ne!(capabilities & Capability::LanewayIpv6V1 as u64, 0);
        assert_ne!(capabilities & Capability::LanewayDirectPeerV1 as u64, 0);

        let controller: Config = toml::from_str(include_str!(
            "../../../deploy/examples/node-rust-controller.toml"
        ))
        .unwrap();
        let capabilities = hello_capabilities(&controller);
        assert_ne!(capabilities & Capability::LanewaySubnetRouterV1 as u64, 0);
        assert_ne!(capabilities & Capability::LanewayExitNodeV1 as u64, 0);
        assert_ne!(capabilities & Capability::LanewayIpv6V1 as u64, 0);
        assert_ne!(capabilities & Capability::LanewayDirectPeerV1 as u64, 0);
    }

    #[test]
    fn welcome_cannot_attach_ipv6_without_negotiation() {
        let welcome = Welcome {
            session_id: vec![1; 16],
            capabilities: REQUIRED_CAPABILITIES,
            overlay_addresses: vec![vec![0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
            max_control_payload: 1024,
            max_packet_payload: 1280,
            ..Welcome::default()
        };
        assert!(validate_welcome(&welcome, REQUIRED_CAPABILITIES, REQUIRED_CAPABILITIES).is_err());
    }

    #[test]
    fn packet_features_are_gated_by_the_negotiated_set() {
        let mut config: Config =
            toml::from_str(include_str!("../../../deploy/examples/node-rust.toml")).unwrap();
        let routes = RoutingTable::compile(&config.routes).unwrap();
        let ipv6 = crate::routing::PacketMeta {
            source: "fd00::1".parse().unwrap(),
            destination: "fd00::2".parse().unwrap(),
        };
        assert!(!packet_capabilities_allow(
            &config,
            &routes,
            ipv6,
            REQUIRED_CAPABILITIES,
            false,
        ));

        config.forwarding.subnet_router = true;
        config
            .forwarding
            .owned_prefixes
            .push("10.20.0.0/24".parse().unwrap());
        let subnet = crate::routing::PacketMeta {
            source: "10.20.0.1".parse().unwrap(),
            destination: "100.96.0.2".parse().unwrap(),
        };
        assert!(!packet_capabilities_allow(
            &config,
            &routes,
            subnet,
            REQUIRED_CAPABILITIES,
            false,
        ));
        assert!(packet_capabilities_allow(
            &config,
            &routes,
            subnet,
            REQUIRED_CAPABILITIES | Capability::LanewaySubnetRouterV1 as u64,
            false,
        ));
    }

    struct Credential {
        certificate: rcgen::Certificate,
        key: KeyPair,
    }

    fn leaf(
        issuer: &Issuer<'static, KeyPair>,
        uri: &str,
        usage: ExtendedKeyUsagePurpose,
        dns: bool,
    ) -> Credential {
        let mut params = CertificateParams::new(if dns {
            vec!["localhost".to_owned()]
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

    async fn relay_service_identity_case(
        expected_service: &str,
        expect_connected: bool,
        force_tcp_fallback: bool,
        periodic_direct: bool,
    ) {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("laneway_relay=debug,lanewayd_rs=debug")
            .with_test_writer()
            .try_init();
        let directory = tempfile::tempdir().unwrap();
        let network = "000102030405060708090a0b0c0d0e0f";
        let node = "101112131415161718191a1b1c1d1e1f";
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
        let relay = leaf(
            &issuer,
            &format!("spiffe://laneway/network/{network}/relay/303132333435363738393a3b3c3d3e3f"),
            ExtendedKeyUsagePurpose::ServerAuth,
            true,
        );
        let node_credential = leaf(
            &issuer,
            &format!("spiffe://laneway/network/{network}/node/{node}"),
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        );
        let ca_path = directory.path().join("ca.pem");
        let relay_cert = directory.path().join("relay.pem");
        let relay_key = directory.path().join("relay.key");
        let node_cert = directory.path().join("node.pem");
        let node_key = directory.path().join("node.key");
        fs::write(&ca_path, ca.pem()).unwrap();
        fs::write(&relay_cert, relay.certificate.pem()).unwrap();
        fs::write(&relay_key, relay.key.serialize_pem()).unwrap();
        fs::write(&node_cert, node_credential.certificate.pem()).unwrap();
        fs::write(&node_key, node_credential.key.serialize_pem()).unwrap();

        let relay_config: laneway_relay::Config = toml::from_str(&format!(
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
candidate_republish_floor = "100ms"
[tcp_fallback]
listen = "127.0.0.1:0"
handshake_timeout = "2s"
write_timeout = "2s"
idle_timeout = "10s"
keepalive_period = "2s"
queue_depth = 4
[[peers]]
network_id = "{network}"
node_id = "{node}"
prefixes = ["100.96.0.1/32"]
"#,
            relay_cert.display(),
            relay_key.display(),
            ca_path.display(),
        ))
        .unwrap();
        let server = laneway_relay::Server::bind(relay_config).unwrap();
        let relay_address = server.local_addr().unwrap();
        let tcp_address = server.tcp_fallback_addr().unwrap().unwrap();
        let server_metrics = server.metrics();
        let (stop_tx, stop_rx) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = stop_rx.await;
        }));

        let node_relay_address = if force_tcp_fallback {
            "127.0.0.1:1".parse().unwrap()
        } else {
            relay_address
        };
        let tcp_config = if force_tcp_fallback {
            format!(
                r#"[tcp_fallback]
address = "{tcp_address}"
handshake_timeout = "2s"
write_timeout = "2s"
idle_timeout = "10s"
keepalive_period = "2s"
queue_depth = 4
"#
            )
        } else {
            String::new()
        };
        let direct_config = if periodic_direct {
            r#"
[direct]
candidate_refresh_interval = "150ms"
[[direct_peers]]
node_id = "202122232425262728292a2b2c2d2e2f"
server_name = "peer.test"
"#
        } else {
            ""
        };
        let config: Config = toml::from_str(&format!(
            r#"
mode = "node"
[identity]
network_id = "{network}"
node_id = "{node}"
[tls]
certificate = "{}"
private_key = "{}"
ca = "{}"
[tun]
name = "lane0"
addresses = ["100.96.0.1/32"]
[relay]
address = "{node_relay_address}"
server_name = "localhost"
service_id = "{expected_service}"
max_routes = 4
handshake_timeout = "250ms"
idle_timeout = "10s"
keepalive = "2s"
{tcp_config}
{direct_config}
[[routes]]
prefix = "100.96.0.2/32"
via_node = "202122232425262728292a2b2c2d2e2f"
"#,
            node_cert.display(),
            node_key.display(),
            ca_path.display(),
        ))
        .unwrap();
        config.validate().unwrap();
        let state = Arc::new(State::new(RoutingTable::compile(&config.routes).unwrap()));
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let metrics = Arc::new(Metrics::default());
        let (inject_tx, _inject_rx) = mpsc::channel(4);
        let (candidate_tx, _candidate_rx) = mpsc::channel(4);
        let (_outbound_tx, outbound_rx) = mpsc::channel(4);
        let client = RelayClient::new(
            endpoint,
            Arc::new(config),
            state,
            metrics,
            Id::from_str(network).unwrap(),
            Id::from_str(node).unwrap(),
            Id::new([9; 16]).unwrap(),
            Arc::new(vec!["100.96.0.1/32".parse::<IpNet>().unwrap()]),
            inject_tx,
            candidate_tx,
        );
        let client_task = tokio::spawn(client.run(outbound_rx));
        if expect_connected {
            timeout(Duration::from_secs(3), async {
                while server_metrics.snapshot().sessions != 1 {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("agent did not complete relay control handshake");
            if periodic_direct {
                timeout(Duration::from_secs(2), async {
                    while server_metrics.snapshot().candidate_publications < 2 {
                        sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("agent did not refresh its direct candidate");
                let snapshot = server_metrics.snapshot();
                assert_eq!(snapshot.registrations, 1);
                assert_eq!(snapshot.sessions_replaced, 0);
            }
        } else {
            sleep(Duration::from_millis(500)).await;
            assert_eq!(
                server_metrics.snapshot().sessions,
                0,
                "agent registered through a relay with the wrong service identity"
            );
        }

        client_task.abort();
        let _ = client_task.await;
        let _ = stop_tx.send(());
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_control_handshake_interoperates_with_rust_relay() {
        relay_service_identity_case("303132333435363738393a3b3c3d3e3f", true, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unavailable_udp_uses_stable_v1_tcp_fallback() {
        relay_service_identity_case("303132333435363738393a3b3c3d3e3f", true, true, false).await;
    }

    async fn udp_gate(
        socket: UdpSocket,
        relay: SocketAddr,
        enabled: Arc<AtomicBool>,
        mut stop: oneshot::Receiver<()>,
    ) {
        let mut client = None;
        let mut buffer = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                _ = &mut stop => return,
                received = socket.recv_from(&mut buffer) => {
                    let Ok((length, source)) = received else { return };
                    if source == relay {
                        if enabled.load(Ordering::Acquire)
                            && let Some(destination) = client
                        {
                            let _ = socket.send_to(&buffer[..length], destination).await;
                        }
                    } else {
                        client = Some(source);
                        if enabled.load(Ordering::Acquire) {
                            let _ = socket.send_to(&buffer[..length], relay).await;
                        }
                    }
                }
            }
        }
    }

    async fn tcp_close_gate(listener: TcpListener, relay: SocketAddr, release: Arc<AtomicBool>) {
        let (downstream, _) = listener.accept().await.unwrap();
        let upstream = TcpStream::connect(relay).await.unwrap();
        let (mut downstream_read, mut downstream_write) = downstream.into_split();
        let (mut upstream_read, mut upstream_write) = upstream.into_split();
        let hold = async move {
            let _ = tokio::io::copy(&mut downstream_read, &mut upstream_write).await;
            while !release.load(Ordering::Acquire) {
                sleep(Duration::from_millis(10)).await;
            }
            let _ = upstream_write.shutdown().await;
        };
        let reverse = async move {
            let _ = tokio::io::copy(&mut upstream_read, &mut downstream_write).await;
        };
        tokio::join!(hold, reverse);
    }

    fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn healthy_tcp_session_promotes_to_quic_without_node_restart() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("laneway_relay=debug,lanewayd_rs=debug")
            .with_test_writer()
            .try_init();
        let directory = tempfile::tempdir().unwrap();
        let network = "000102030405060708090a0b0c0d0e0f";
        let first_node = "101112131415161718191a1b1c1d1e1f";
        let second_node = "202122232425262728292a2b2c2d2e2f";
        let service = "303132333435363738393a3b3c3d3e3f";
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
        let relay = leaf(
            &issuer,
            &format!("spiffe://laneway/network/{network}/relay/{service}"),
            ExtendedKeyUsagePurpose::ServerAuth,
            true,
        );
        let first = leaf(
            &issuer,
            &format!("spiffe://laneway/network/{network}/node/{first_node}"),
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        );
        let second = leaf(
            &issuer,
            &format!("spiffe://laneway/network/{network}/node/{second_node}"),
            ExtendedKeyUsagePurpose::ClientAuth,
            false,
        );
        let ca_path = directory.path().join("ca.pem");
        let relay_cert = directory.path().join("relay.pem");
        let relay_key = directory.path().join("relay.key");
        let first_cert = directory.path().join("first.pem");
        let first_key = directory.path().join("first.key");
        let second_cert = directory.path().join("second.pem");
        let second_key = directory.path().join("second.key");
        fs::write(&ca_path, ca.pem()).unwrap();
        fs::write(&relay_cert, relay.certificate.pem()).unwrap();
        fs::write(&relay_key, relay.key.serialize_pem()).unwrap();
        fs::write(&first_cert, first.certificate.pem()).unwrap();
        fs::write(&first_key, first.key.serialize_pem()).unwrap();
        fs::write(&second_cert, second.certificate.pem()).unwrap();
        fs::write(&second_key, second.key.serialize_pem()).unwrap();

        let relay_config: laneway_relay::Config = toml::from_str(&format!(
            r#"
mode = "relay"
[tls]
certificate = "{}"
private_key = "{}"
ca = "{}"
[relay]
listen = "127.0.0.1:0"
queue_depth = 8
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
keepalive_period = "2s"
queue_depth = 8
[[peers]]
network_id = "{network}"
node_id = "{first_node}"
prefixes = ["100.96.0.1/32"]
[[peers]]
network_id = "{network}"
node_id = "{second_node}"
prefixes = ["100.96.0.2/32"]
"#,
            relay_cert.display(),
            relay_key.display(),
            ca_path.display(),
        ))
        .unwrap();
        let server = laneway_relay::Server::bind(relay_config).unwrap();
        let relay_address = server.local_addr().unwrap();
        let tcp_address = server.tcp_fallback_addr().unwrap().unwrap();
        let server_metrics = server.metrics();
        let (server_stop, server_stopped) = oneshot::channel();
        let server_task = tokio::spawn(server.serve_until(async move {
            let _ = server_stopped.await;
        }));

        let tcp_gate_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_gate_address = tcp_gate_listener.local_addr().unwrap();
        let tcp_gate_release = Arc::new(AtomicBool::new(false));
        let tcp_gate_task = tokio::spawn(tcp_close_gate(
            tcp_gate_listener,
            tcp_address,
            Arc::clone(&tcp_gate_release),
        ));

        let gate_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gate_address = gate_socket.local_addr().unwrap();
        let gate_enabled = Arc::new(AtomicBool::new(false));
        let (gate_stop, gate_stopped) = oneshot::channel();
        let gate_task = tokio::spawn(udp_gate(
            gate_socket,
            relay_address,
            Arc::clone(&gate_enabled),
            gate_stopped,
        ));

        let first_config: Config = toml::from_str(&format!(
            r#"
mode = "node"
[identity]
network_id = "{network}"
node_id = "{first_node}"
[tls]
certificate = "{}"
private_key = "{}"
ca = "{}"
[tun]
name = "lane0"
addresses = ["100.96.0.1/32"]
[relay]
address = "{gate_address}"
server_name = "localhost"
service_id = "{service}"
max_routes = 4
handshake_timeout = "250ms"
idle_timeout = "10s"
keepalive = "2s"
reconnect_min = "100ms"
reconnect_max = "200ms"
quic_recovery_interval = "100ms"
[tcp_fallback]
address = "{tcp_gate_address}"
handshake_timeout = "2s"
write_timeout = "2s"
idle_timeout = "10s"
keepalive_period = "2s"
queue_depth = 8
[[routes]]
prefix = "100.96.0.2/32"
via_node = "{second_node}"
"#,
            first_cert.display(),
            first_key.display(),
            ca_path.display(),
        ))
        .unwrap();
        first_config.validate().unwrap();
        let first_state = Arc::new(State::new(
            RoutingTable::compile(&first_config.routes).unwrap(),
        ));
        let first_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let (first_inject_tx, _first_inject_rx) = mpsc::channel(8);
        let (first_candidate_tx, _first_candidate_rx) = mpsc::channel(8);
        let (first_outbound_tx, first_outbound_rx) = mpsc::channel(8);
        let first_client = RelayClient::new(
            first_endpoint,
            Arc::new(first_config),
            Arc::clone(&first_state),
            Arc::new(Metrics::default()),
            Id::from_str(network).unwrap(),
            Id::from_str(first_node).unwrap(),
            Id::new([1; 16]).unwrap(),
            Arc::new(vec!["100.96.0.1/32".parse().unwrap()]),
            first_inject_tx,
            first_candidate_tx,
        );
        let first_task = tokio::spawn(first_client.run(first_outbound_rx));

        timeout(Duration::from_secs(3), async {
            while server_metrics.snapshot().sessions != 1 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("first node did not establish TCP while UDP was gated");
        assert_eq!(server_metrics.snapshot().sessions_replaced, 0);

        let second_config: Config = toml::from_str(&format!(
            r#"
mode = "node"
[identity]
network_id = "{network}"
node_id = "{second_node}"
[tls]
certificate = "{}"
private_key = "{}"
ca = "{}"
[tun]
name = "lane1"
addresses = ["100.96.0.2/32"]
[relay]
address = "{relay_address}"
server_name = "localhost"
service_id = "{service}"
max_routes = 4
handshake_timeout = "2s"
idle_timeout = "10s"
keepalive = "2s"
reconnect_min = "100ms"
reconnect_max = "200ms"
quic_recovery_interval = "100ms"
[[routes]]
prefix = "100.96.0.1/32"
via_node = "{first_node}"
"#,
            second_cert.display(),
            second_key.display(),
            ca_path.display(),
        ))
        .unwrap();
        second_config.validate().unwrap();
        let second_state = Arc::new(State::new(
            RoutingTable::compile(&second_config.routes).unwrap(),
        ));
        let second_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let (second_inject_tx, mut second_inject_rx) = mpsc::channel(8);
        let (second_candidate_tx, _second_candidate_rx) = mpsc::channel(8);
        let (_second_outbound_tx, second_outbound_rx) = mpsc::channel(8);
        let second_client = RelayClient::new(
            second_endpoint,
            Arc::new(second_config),
            Arc::clone(&second_state),
            Arc::new(Metrics::default()),
            Id::from_str(network).unwrap(),
            Id::from_str(second_node).unwrap(),
            Id::new([2; 16]).unwrap(),
            Arc::new(vec!["100.96.0.2/32".parse().unwrap()]),
            second_inject_tx,
            second_candidate_tx,
        );
        let second_task = tokio::spawn(second_client.run(second_outbound_rx));
        timeout(Duration::from_secs(3), async {
            while server_metrics.snapshot().sessions != 2 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second node did not establish its QUIC session");

        gate_enabled.store(true, Ordering::Release);
        timeout(Duration::from_secs(5), async {
            while server_metrics.snapshot().sessions_replaced == 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("TCP session was not promoted to QUIC");
        tcp_gate_release.store(true, Ordering::Release);

        let second_id = Id::from_str(second_node).unwrap();
        let first_id = Id::from_str(first_node).unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                let first_bound = first_state.handles.load().outbound.contains_key(&second_id);
                let second_bound = second_state.handles.load().outbound.contains_key(&first_id);
                if first_bound && second_bound {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("promoted control stream did not restore route bindings");
        assert_eq!(server_metrics.snapshot().sessions, 2);

        let packet = ipv4([100, 96, 0, 1], [100, 96, 0, 2]);
        first_outbound_tx
            .send(OutboundPacket::new(second_id, packet.clone()))
            .await
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), second_inject_rx.recv())
                .await
                .expect("post-promotion packet was not delivered")
                .expect("second injection queue closed"),
            packet
        );
        assert_eq!(server_metrics.snapshot().forwarded_packets, 1);

        first_task.abort();
        second_task.abort();
        let _ = first_task.await;
        let _ = second_task.await;
        tcp_gate_task.await.unwrap();
        let _ = gate_stop.send(());
        gate_task.await.unwrap();
        let _ = server_stop.send(());
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn long_lived_quic_session_refreshes_direct_candidate_within_relay_floor() {
        relay_service_identity_case("303132333435363738393a3b3c3d3e3f", true, false, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_rejects_wrong_relay_service_identity() {
        relay_service_identity_case("404142434445464748494a4b4c4d4e4f", false, false, false).await;
    }
}
