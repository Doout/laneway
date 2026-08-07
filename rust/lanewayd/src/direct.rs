use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use laneway_protocol::{
    Id, Role,
    v1::{EndpointCandidate, EndpointTransport},
};
use quinn::{Connection, Endpoint};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    time::{sleep, timeout},
};
use tracing::{debug, info};

use crate::{
    config::{Config, DirectPeerConfig},
    kernel::KernelManager,
    metrics::Metrics,
    packet_pool::PacketPool,
    probe::ProbeSocket,
    routing::packet_meta,
    state::State,
    tls,
};

const IDENTITY_PREFACE_LEN: usize = 37;
// Quinn requires a syntactically valid DNS ServerName even though Laneway's
// custom direct verifier authenticates the exact network/node SPIFFE identity.
const DIRECT_PLACEHOLDER_SERVER_NAME: &str = "direct.invalid";

/// Runs static direct peer dialing and authenticated inbound acceptance.
pub struct DirectManager {
    endpoint: Endpoint,
    config: Arc<Config>,
    state: Arc<State>,
    metrics: Arc<Metrics>,
    network: Id,
    node: Id,
    owned: Arc<Vec<ipnet::IpNet>>,
    inject: mpsc::Sender<Bytes>,
    peers: HashMap<Id, DirectPeerConfig>,
    candidates: Option<mpsc::Receiver<EndpointCandidate>>,
    probe: Arc<ProbeSocket>,
    handshake_slots: Arc<Semaphore>,
    candidate_slots: Arc<Semaphore>,
    candidate_inflight: Arc<StdMutex<HashSet<Id>>>,
    kernel: Arc<StdMutex<Option<KernelManager>>>,
    dynamic_bypasses: Arc<StdMutex<BTreeMap<IpAddr, usize>>>,
}

impl DirectManager {
    /// Builds a manager after validating all direct peer identifiers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: Endpoint,
        config: Arc<Config>,
        state: Arc<State>,
        metrics: Arc<Metrics>,
        network: Id,
        node: Id,
        owned: Arc<Vec<ipnet::IpNet>>,
        inject: mpsc::Sender<Bytes>,
        candidates: mpsc::Receiver<EndpointCandidate>,
        probe: Arc<ProbeSocket>,
        kernel: Arc<StdMutex<Option<KernelManager>>>,
        dynamic_bypasses: Arc<StdMutex<BTreeMap<IpAddr, usize>>>,
    ) -> Result<Self> {
        let mut peers = HashMap::new();
        for peer in &config.direct_peers {
            peers.insert(peer.node_id.parse()?, peer.clone());
        }
        let concurrency = direct_concurrency_limit(config.relay.max_routes);
        Ok(Self {
            endpoint,
            config,
            state,
            metrics,
            network,
            node,
            owned,
            inject,
            peers,
            candidates: Some(candidates),
            probe,
            handshake_slots: Arc::new(Semaphore::new(concurrency)),
            candidate_slots: Arc::new(Semaphore::new(concurrency)),
            candidate_inflight: Arc::new(StdMutex::new(HashSet::new())),
            kernel,
            dynamic_bypasses,
        })
    }

    /// Runs inbound acceptance and deterministic outbound dials. The node with
    /// the lexicographically smaller ID dials, preventing duplicate path churn.
    pub async fn run(mut self) -> Result<()> {
        let mut candidates = self
            .candidates
            .take()
            .context("direct candidate queue missing")?;
        let manager = Arc::new(self);
        let mut tasks = tokio::task::JoinSet::new();
        {
            let manager = Arc::clone(&manager);
            tasks.spawn(async move { manager.accept_loop().await });
        }
        for (&peer, config) in &manager.peers {
            if manager.node < peer
                && let Some(address) = config.address
            {
                let manager = Arc::clone(&manager);
                tasks.spawn(async move { manager.dial_loop(peer, address).await });
            }
        }
        loop {
            tokio::select! {
                result = tasks.join_next() => {
                    result.context("all direct tasks stopped")?.context("direct peer task panicked")??;
                }
                candidate = candidates.recv() => {
                    let candidate = candidate.context("direct candidate queue closed")?;
                    if !manager.state.candidate_exchange_enabled() {
                        continue;
                    }
                    let peer = match Id::from_slice(&candidate.node_id) {
                        Ok(peer) => peer,
                        Err(_) => {
                            Metrics::increment(&manager.metrics.invalid_drops);
                            continue;
                        }
                    };
                    let controller_maximum = manager
                        .state
                        .candidate_exchange_authority()
                        .map_or(usize::MAX, |policy| policy.max_candidates as usize);
                    let Some((_permit, _inflight)) = reserve_candidate(
                        Arc::clone(&manager.candidate_slots),
                        Arc::clone(&manager.candidate_inflight),
                        peer,
                        controller_maximum,
                        &manager.metrics,
                    ) else {
                        continue;
                    };
                    let manager = Arc::clone(&manager);
                    tasks.spawn(async move {
                        let _permit = _permit;
                        let _inflight = _inflight;
                        Metrics::increment(&manager.metrics.direct_attempts);
                        if let Err(error) = manager.probe_and_connect(candidate).await {
                            Metrics::increment(&manager.metrics.direct_failures);
                            debug!(%error, "direct rendezvous attempt failed; retaining relay path");
                        }
                        Ok(())
                    });
                }
            }
        }
    }

    async fn accept_loop(self: Arc<Self>) -> Result<()> {
        loop {
            let incoming = self
                .endpoint
                .accept()
                .await
                .context("direct endpoint closed")?;
            let Ok(permit) = Arc::clone(&self.handshake_slots).try_acquire_owned() else {
                incoming.refuse();
                Metrics::increment(&self.metrics.direct_saturation_drops);
                continue;
            };
            let manager = Arc::clone(&self);
            tokio::spawn(async move {
                let _permit = permit;
                Metrics::increment(&manager.metrics.direct_attempts);
                let result = async {
                    let connection = timeout(manager.config.relay.handshake_timeout, incoming)
                        .await
                        .context("direct inbound handshake timed out")?
                        .context("direct inbound handshake")?;
                    let identity = tls::validate_peer(
                        &connection,
                        tls::DIRECT_ALPN,
                        manager.network,
                        Role::Node,
                        None,
                    )?;
                    let serial = tls::peer_certificate_serial(&connection)?;
                    ensure!(
                        manager.peers.contains_key(&identity.subject_id)
                            || manager
                                .state
                                .direct_authorized(identity.subject_id, &serial),
                        "direct peer is not controller-authorized"
                    );
                    manager
                        .accept_identity_binding(&connection, identity.subject_id)
                        .await?;
                    let _bypass = TransportBypassReservation::new(
                        Arc::clone(&manager.kernel),
                        Arc::clone(&manager.dynamic_bypasses),
                        connection.remote_address().ip(),
                    )?;
                    manager
                        .run_connection(identity.subject_id, serial, connection)
                        .await
                }
                .await;
                if let Err(error) = result {
                    Metrics::increment(&manager.metrics.direct_failures);
                    debug!(%error, "inbound direct connection ended");
                }
            });
        }
    }

    async fn dial_loop(self: Arc<Self>, peer: Id, address: SocketAddr) -> Result<()> {
        let mut delay = self.config.relay.reconnect_min;
        loop {
            if self.state.direct.load().contains_key(&peer) {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
            Metrics::increment(&self.metrics.direct_attempts);
            let result = self.dial(peer, address).await;
            match result {
                Ok((connection, serial)) => {
                    delay = self.config.relay.reconnect_min;
                    if let Err(error) = self.run_connection(peer, serial, connection).await {
                        debug!(%peer, %error, "direct connection ended");
                    }
                }
                Err(error) => {
                    Metrics::increment(&self.metrics.direct_failures);
                    debug!(%peer, %error, ?delay, "direct dial failed")
                }
            }
            sleep(delay).await;
            delay = delay
                .checked_mul(2)
                .unwrap_or(self.config.relay.reconnect_max)
                .min(self.config.relay.reconnect_max);
        }
    }

    async fn dial(&self, peer: Id, address: SocketAddr) -> Result<(Connection, Vec<u8>)> {
        let _bypass = TransportBypassReservation::new(
            Arc::clone(&self.kernel),
            Arc::clone(&self.dynamic_bypasses),
            address.ip(),
        )?;
        let client =
            tls::direct_client_config(&self.config.tls, &self.config.relay, self.network, peer)?;
        let connecting = self
            .endpoint
            .connect_with(client, address, DIRECT_PLACEHOLDER_SERVER_NAME)
            .context("start direct QUIC connection")?;
        let connection = timeout(self.config.relay.handshake_timeout, connecting)
            .await
            .context("direct QUIC handshake timed out")?
            .context("direct QUIC handshake")?;
        tls::validate_peer(
            &connection,
            tls::DIRECT_ALPN,
            self.network,
            Role::Node,
            Some(peer),
        )?;
        let serial = tls::peer_certificate_serial(&connection)?;
        ensure!(
            self.state.direct_authorized(peer, &serial),
            "direct certificate is revoked or peer is removed"
        );
        self.dial_identity_binding(&connection, peer).await?;
        Ok((connection, serial))
    }

    async fn probe_and_connect(&self, candidate: EndpointCandidate) -> Result<()> {
        let peer = Id::from_slice(&candidate.node_id).context("candidate peer ID")?;
        ensure!(peer != self.node, "candidate identifies the local node");
        ensure!(
            self.peers.contains_key(&peer) || self.state.direct_authorized(peer, &[]),
            "candidate peer is not controller-authorized"
        );
        ensure!(
            candidate.transport == EndpointTransport::QuicUdp as i32
                && candidate.port > 0
                && candidate.port <= u32::from(u16::MAX)
                && candidate.rendezvous_token.len() == 16
                && candidate.rendezvous_token.iter().any(|byte| *byte != 0),
            "candidate rendezvous fields are invalid"
        );
        let address = candidate_address(&candidate, &self.config)?;
        let _bypass = TransportBypassReservation::new(
            Arc::clone(&self.kernel),
            Arc::clone(&self.dynamic_bypasses),
            address.ip(),
        )?;
        let start = UNIX_EPOCH
            .checked_add(Duration::from_nanos(candidate.probe_start_unix_nano))
            .context("candidate probe start overflow")?;
        let now = SystemTime::now();
        let controller_ttl = self
            .state
            .candidate_exchange_authority()
            .map_or(Duration::from_secs(1), |policy| policy.ttl);
        ensure!(
            start >= now.checked_sub(controller_ttl).unwrap_or(UNIX_EPOCH)
                && start
                    <= now
                        .checked_add(controller_ttl.min(Duration::from_secs(30)))
                        .context("clock overflow")?,
            "candidate probe start is outside the accepted window"
        );
        let token: [u8; 16] = candidate
            .rendezvous_token
            .as_slice()
            .try_into()
            .context("candidate token length")?;
        if self.state.direct.load().contains_key(&peer) {
            return Ok(());
        }
        let mut probes = self.probe.subscribe();
        let request = probe_packet(false, token, self.node, peer)?;
        let probe = Arc::clone(&self.probe);
        let attempts = self.config.direct.probe_attempts;
        let interval = self.config.direct.probe_interval;
        let sender = tokio::spawn(async move {
            let initial = start.duration_since(SystemTime::now()).unwrap_or_default();
            sleep(initial).await;
            for round in 0..attempts {
                if round != 0 {
                    sleep(interval).await;
                }
                probe.send_to(&request, address).await?;
            }
            Result::<()>::Ok(())
        });
        let reachable = timeout(self.config.direct.probe_timeout, async {
            loop {
                let datagram = probes.recv().await.context("probe receiver lagged")?;
                if datagram.source != address {
                    continue;
                }
                let response = parse_probe(&datagram.payload, token, peer, self.node)?;
                if !response {
                    let reply = probe_packet(true, token, self.node, peer)?;
                    self.probe.send_to(&reply, address).await?;
                }
                return Result::<()>::Ok(());
            }
        })
        .await
        .context("direct probe timed out")?;
        sender.abort();
        let _ = sender.await;
        reachable?;
        if self.node < peer && !self.state.direct.load().contains_key(&peer) {
            let (connection, serial) = self.dial(peer, address).await?;
            self.run_connection(peer, serial, connection).await?;
        }
        Ok(())
    }

    async fn dial_identity_binding(&self, connection: &Connection, peer: Id) -> Result<()> {
        timeout(self.config.relay.handshake_timeout, async {
            let (mut send, mut receive) = connection.open_bi().await?;
            send.write_all(&identity_preface(self.network, self.node))
                .await?;
            let mut response = [0_u8; IDENTITY_PREFACE_LEN];
            receive.read_exact(&mut response).await?;
            validate_identity_preface(&response, self.network, peer)?;
            send.finish()?;
            Result::<()>::Ok(())
        })
        .await
        .context("direct identity binding timed out")??;
        Ok(())
    }

    async fn accept_identity_binding(&self, connection: &Connection, peer: Id) -> Result<()> {
        timeout(self.config.relay.handshake_timeout, async {
            let (mut send, mut receive) = connection.accept_bi().await?;
            let mut request = [0_u8; IDENTITY_PREFACE_LEN];
            receive.read_exact(&mut request).await?;
            validate_identity_preface(&request, self.network, peer)?;
            send.write_all(&identity_preface(self.network, self.node))
                .await?;
            send.finish()?;
            Result::<()>::Ok(())
        })
        .await
        .context("direct identity binding timed out")??;
        Ok(())
    }

    async fn run_connection(
        &self,
        peer: Id,
        certificate_serial: Vec<u8>,
        connection: Connection,
    ) -> Result<()> {
        let stable_id = connection.stable_id();
        ensure!(
            self.state.direct_authorized(peer, &certificate_serial),
            "direct certificate is revoked or peer is removed"
        );
        self.state
            .attach_direct(peer, connection.clone(), certificate_serial.clone());
        Metrics::increment(&self.metrics.direct_switches);
        Metrics::set_value(
            &self.metrics.direct_active_paths,
            self.state.direct.load().len(),
        );
        info!(%peer, remote = %connection.remote_address(), "direct path attached");
        let result = loop {
            let packet = match connection.read_datagram().await {
                Ok(packet) => packet,
                Err(error) => break Err(error.into()),
            };
            if packet.len() > usize::from(self.config.tun.mtu) {
                Metrics::increment(&self.metrics.invalid_drops);
                continue;
            }
            let Ok(meta) = packet_meta(&packet) else {
                Metrics::increment(&self.metrics.invalid_drops);
                Metrics::increment(&self.metrics.malformed_drops);
                continue;
            };
            if !self.state.direct_authorized(peer, &certificate_serial)
                || !self.state.allows(peer, self.node, &packet)
            {
                Metrics::increment(&self.metrics.invalid_drops);
                Metrics::increment(&self.metrics.policy_drops);
                continue;
            }
            let routes = self.state.routes.load();
            if !routes.authorizes_source(peer, meta.source)
                || (!self.state.owns(&self.owned, meta.destination)
                    && !self.config.forwarding.exit_gateway)
            {
                Metrics::increment(&self.metrics.invalid_drops);
                Metrics::increment(&self.metrics.auth_drops);
                continue;
            }
            let sent = self.inject.try_send(packet);
            let depth = self
                .inject
                .max_capacity()
                .saturating_sub(self.inject.capacity());
            self.metrics.set_inject_queue_depth(depth);
            if sent.is_err() {
                Metrics::increment(&self.metrics.queue_drops);
            }
        };
        self.state.detach_direct(peer, stable_id);
        Metrics::set_value(
            &self.metrics.direct_active_paths,
            self.state.direct.load().len(),
        );
        result
    }
}

struct TransportBypassReservation {
    kernel: Arc<StdMutex<Option<KernelManager>>>,
    dynamic_bypasses: Arc<StdMutex<BTreeMap<IpAddr, usize>>>,
    address: IpAddr,
}

impl TransportBypassReservation {
    fn new(
        kernel: Arc<StdMutex<Option<KernelManager>>>,
        dynamic_bypasses: Arc<StdMutex<BTreeMap<IpAddr, usize>>>,
        address: IpAddr,
    ) -> Result<Self> {
        let mut bypasses = dynamic_bypasses
            .lock()
            .map_err(|_| anyhow::anyhow!("dynamic bypass lock poisoned"))?;
        let previous = bypasses.get(&address).copied().unwrap_or(0);
        bypasses.insert(address, previous + 1);
        if let Some(manager) = kernel
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel manager lock poisoned"))?
            .as_mut()
            && let Err(error) = manager.reserve_transport_bypass(address)
        {
            if previous == 0 {
                bypasses.remove(&address);
            } else {
                bypasses.insert(address, previous);
            }
            return Err(error);
        }
        drop(bypasses);
        Ok(Self {
            kernel,
            dynamic_bypasses,
            address,
        })
    }
}

impl Drop for TransportBypassReservation {
    fn drop(&mut self) {
        let result = self
            .dynamic_bypasses
            .lock()
            .map_err(|_| anyhow::anyhow!("dynamic bypass lock poisoned"))
            .and_then(|mut bypasses| {
                let count = bypasses.get(&self.address).copied().unwrap_or(0);
                if count > 1 {
                    bypasses.insert(self.address, count - 1);
                } else {
                    bypasses.remove(&self.address);
                }
                let result = self
                    .kernel
                    .lock()
                    .map_err(|_| anyhow::anyhow!("kernel manager lock poisoned"))
                    .and_then(|mut slot| {
                        slot.as_mut().map_or(Ok(()), |manager| {
                            manager.release_transport_bypass(self.address)
                        })
                    });
                if result.is_err() && count > 0 {
                    bypasses.insert(self.address, count);
                }
                result
            });
        if let Err(error) = result {
            tracing::error!(%error, address = %self.address, "release direct transport bypass");
        }
    }
}

fn direct_concurrency_limit(max_routes: u32) -> usize {
    usize::try_from(max_routes).unwrap_or(4096).clamp(1, 4096)
}

struct CandidateReservation {
    peer: Id,
    inflight: Arc<StdMutex<HashSet<Id>>>,
}

impl Drop for CandidateReservation {
    fn drop(&mut self) {
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.remove(&self.peer);
        }
    }
}

fn reserve_candidate(
    slots: Arc<Semaphore>,
    inflight: Arc<StdMutex<HashSet<Id>>>,
    peer: Id,
    maximum: usize,
    metrics: &Metrics,
) -> Option<(OwnedSemaphorePermit, CandidateReservation)> {
    if maximum == 0 || inflight.lock().ok()?.len() >= maximum {
        Metrics::increment(&metrics.direct_saturation_drops);
        return None;
    }
    let permit = match slots.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            Metrics::increment(&metrics.direct_saturation_drops);
            return None;
        }
    };
    let inserted = inflight.lock().ok()?.insert(peer);
    if !inserted {
        Metrics::increment(&metrics.direct_saturation_drops);
        return None;
    }
    Some((permit, CandidateReservation { peer, inflight }))
}

fn candidate_address(candidate: &EndpointCandidate, config: &Config) -> Result<SocketAddr> {
    let ip = match candidate.ip_address.as_slice() {
        bytes @ [_, _, _, _] => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes)?)),
        bytes if bytes.len() == 16 => {
            let address = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes)?);
            ensure!(
                address.to_ipv4_mapped().is_none(),
                "candidate IPv4-mapped IPv6 address is not canonical"
            );
            IpAddr::V6(address)
        }
        _ => bail!("candidate IP length is invalid"),
    };
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast(),
        "candidate IP class is invalid"
    );
    if let IpAddr::V4(value) = ip {
        ensure!(value != Ipv4Addr::BROADCAST, "candidate is broadcast");
    }
    ensure!(
        config.direct.allow_loopback || !ip.is_loopback(),
        "loopback candidate is disabled"
    );
    let link_local = match ip {
        IpAddr::V4(value) => value.is_link_local(),
        IpAddr::V6(value) => value.is_unicast_link_local(),
    };
    ensure!(
        config.direct.allow_link_local || !link_local,
        "link-local candidate is disabled"
    );
    Ok(SocketAddr::new(ip, candidate.port as u16))
}

fn probe_packet(response: bool, token: [u8; 16], sender: Id, recipient: Id) -> Result<[u8; 54]> {
    ensure!(
        token != [0; 16] && sender != recipient,
        "invalid direct probe identity"
    );
    let mut packet = [0_u8; 54];
    packet[..4].copy_from_slice(b"\x0cWHP");
    packet[4] = 1;
    packet[5] = if response { 2 } else { 1 };
    packet[6..22].copy_from_slice(&token);
    packet[22..38].copy_from_slice(sender.as_bytes());
    packet[38..54].copy_from_slice(recipient.as_bytes());
    Ok(packet)
}

fn parse_probe(packet: &[u8], token: [u8; 16], sender: Id, recipient: Id) -> Result<bool> {
    ensure!(
        packet.len() == 54
            && &packet[..5] == b"\x0cWHP\x01"
            && matches!(packet[5], 1 | 2)
            && packet[6..22] == token
            && packet[22..38] == *sender.as_bytes()
            && packet[38..54] == *recipient.as_bytes(),
        "invalid direct probe"
    );
    Ok(packet[5] == 2)
}

/// Sends a raw packet over an attached direct connection. Returns false when
/// no direct path exists, allowing the caller to fall back to the relay.
pub(crate) fn try_send_direct(
    state: &State,
    metrics: &Metrics,
    source: Id,
    peer: Id,
    packet: &[u8],
    pool: &PacketPool,
) -> bool {
    if !state.allows(source, peer, packet) {
        Metrics::increment(&metrics.invalid_drops);
        return true;
    }
    let paths = state.direct.load();
    let Some(path) = paths.get(&peer) else {
        return false;
    };
    if !state.direct_authorized(peer, &path.certificate_serial) {
        return false;
    }
    let (pooled, miss) = pool.copy(packet);
    if miss {
        Metrics::increment(&metrics.packet_pool_misses);
    }
    match path.connection.send_datagram(Bytes::from_owner(pooled)) {
        Ok(()) => {
            Metrics::increment(&metrics.direct_packets);
            true
        }
        Err(error) => {
            if record_direct_send_failure(metrics, &path.send_failure_reported) {
                debug!(%peer, %error, "direct carrier send failed; using relay fallback");
            }
            false
        }
    }
}

/// Counts every failed direct send while allowing only one diagnostic for the
/// lifetime of a carrier. The connection task owns the eventual detach and its
/// lifecycle log; packet traffic must not produce a log for every failure.
fn record_direct_send_failure(metrics: &Metrics, reported: &AtomicBool) -> bool {
    Metrics::increment(&metrics.direct_failures);
    !reported.swap(true, Ordering::Relaxed)
}

fn identity_preface(network: Id, node: Id) -> [u8; IDENTITY_PREFACE_LEN] {
    let mut value = [0_u8; IDENTITY_PREFACE_LEN];
    value[..4].copy_from_slice(b"LWPD");
    value[4] = 1;
    value[5..21].copy_from_slice(network.as_bytes());
    value[21..].copy_from_slice(node.as_bytes());
    value
}

fn validate_identity_preface(value: &[u8], network: Id, node: Id) -> Result<()> {
    ensure!(
        value.len() == IDENTITY_PREFACE_LEN,
        "invalid direct identity length"
    );
    ensure!(
        &value[..5] == b"LWPD\x01",
        "invalid direct identity preface"
    );
    ensure!(
        constant_time_equal(&value[5..21], network.as_bytes())
            && constant_time_equal(&value[21..37], node.as_bytes()),
        "direct identity binding differs from certificate"
    );
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut different = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        different |= left ^ right;
    }
    different == 0
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::OpenOptionsExt, path::Path, str::FromStr};

    use ipnet::IpNet;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use tokio::time::timeout;

    use super::*;
    use crate::RoutingTable;

    fn write_private_key(path: &Path, pem: &str) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, pem.as_bytes()).unwrap();
    }

    #[test]
    fn identity_binding_matches_go_format_and_is_strict() {
        let network = Id::from_str("000102030405060708090a0b0c0d0e0f").unwrap();
        let node = Id::from_str("101112131415161718191a1b1c1d1e1f").unwrap();
        let mut value = identity_preface(network, node);
        assert_eq!(&value[..5], b"LWPD\x01");
        validate_identity_preface(&value, network, node).unwrap();
        value[36] ^= 1;
        assert!(validate_identity_preface(&value, network, node).is_err());
    }

    #[test]
    fn candidate_work_is_deduplicated_and_saturation_is_counted() {
        let slots = Arc::new(Semaphore::new(1));
        let inflight = Arc::new(StdMutex::new(HashSet::new()));
        let metrics = Metrics::default();
        let first = Id::from_str("101112131415161718191a1b1c1d1e1f").unwrap();
        let second = Id::from_str("202122232425262728292a2b2c2d2e2f").unwrap();
        let reservation = reserve_candidate(
            Arc::clone(&slots),
            Arc::clone(&inflight),
            first,
            8,
            &metrics,
        )
        .unwrap();
        assert!(
            reserve_candidate(
                Arc::clone(&slots),
                Arc::clone(&inflight),
                second,
                8,
                &metrics,
            )
            .is_none()
        );
        drop(reservation);
        let dedupe_slots = Arc::new(Semaphore::new(2));
        let duplicate = reserve_candidate(
            Arc::clone(&dedupe_slots),
            Arc::clone(&inflight),
            first,
            8,
            &metrics,
        )
        .unwrap();
        assert!(
            reserve_candidate(dedupe_slots, Arc::clone(&inflight), first, 8, &metrics).is_none()
        );
        assert_eq!(metrics.snapshot().direct_saturation_drops, 2);
        assert!(inflight.lock().unwrap().contains(&first));
        drop(duplicate);
        assert!(inflight.lock().unwrap().is_empty());
        assert_eq!(direct_concurrency_limit(u32::MAX), 4096);
    }

    #[test]
    fn direct_send_failures_are_counted_but_reported_once_per_connection() {
        let metrics = Metrics::default();
        let first_connection = AtomicBool::new(false);
        let reports = (0..64)
            .filter(|_| record_direct_send_failure(&metrics, &first_connection))
            .count();
        assert_eq!(metrics.snapshot().direct_failures, 64);
        assert_eq!(reports, 1, "packet failures must share one connection log");

        let replacement_connection = AtomicBool::new(false);
        assert!(record_direct_send_failure(
            &metrics,
            &replacement_connection
        ));
        assert_eq!(metrics.snapshot().direct_failures, 65);
    }

    #[test]
    fn dynamic_transport_bypass_is_refcounted_for_reservation_lifetime() {
        let kernel = Arc::new(StdMutex::new(None));
        let bypasses = Arc::new(StdMutex::new(BTreeMap::new()));
        let address: IpAddr = "198.51.100.77".parse().unwrap();
        let first =
            TransportBypassReservation::new(Arc::clone(&kernel), Arc::clone(&bypasses), address)
                .unwrap();
        let second =
            TransportBypassReservation::new(kernel, Arc::clone(&bypasses), address).unwrap();
        assert_eq!(bypasses.lock().unwrap().get(&address), Some(&2));
        drop(first);
        assert_eq!(bypasses.lock().unwrap().get(&address), Some(&1));
        drop(second);
        assert!(!bypasses.lock().unwrap().contains_key(&address));
    }

    struct Credential {
        certificate: rcgen::Certificate,
        key: KeyPair,
    }

    fn credential(issuer: &Issuer<'static, KeyPair>, network: &str, node: &str) -> Credential {
        // Go `laneway pki node` intentionally emits URI SANs and no DNS SAN.
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.subject_alt_names.push(SanType::URI(
            format!("spiffe://laneway/network/{network}/node/{node}")
                .try_into()
                .unwrap(),
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, issuer).unwrap();
        Credential { certificate, key }
    }

    #[allow(clippy::too_many_arguments)]
    fn config(
        directory: &Path,
        ca: &rcgen::Certificate,
        local: &Credential,
        network: &str,
        node: &str,
        peer: &str,
        local_ip: &str,
        peer_ip: &str,
    ) -> Config {
        let ca_path = directory.join(format!("{node}-ca.pem"));
        let cert_path = directory.join(format!("{node}.pem"));
        let key_path = directory.join(format!("{node}.key"));
        fs::write(&ca_path, ca.pem()).unwrap();
        fs::write(&cert_path, local.certificate.pem()).unwrap();
        write_private_key(&key_path, &local.key.serialize_pem());
        toml::from_str(&format!(
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
addresses = ["{local_ip}/32"]
[relay]
address = "127.0.0.1:9"
server_name = "localhost"
service_id = "303132333435363738393a3b3c3d3e3f"
handshake_timeout = "2s"
idle_timeout = "10s"
keepalive = "2s"
[direct]
listen = "127.0.0.1:0"
probe_interval = "20ms"
probe_timeout = "2s"
probe_attempts = 3
allow_loopback = true
[[routes]]
prefix = "{peer_ip}/32"
via_node = "{peer}"
[[direct_peers]]
node_id = "{peer}"
server_name = "localhost"
"#,
            cert_path.display(),
            key_path.display(),
            ca_path.display(),
        ))
        .unwrap()
    }

    fn packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refreshed_rendezvous_recovers_a_failed_live_direct_packet_path() {
        let directory = tempfile::tempdir().unwrap();
        let network = "000102030405060708090a0b0c0d0e0f";
        // All-numeric hexadecimal IDs are not valid DNS names. The direct
        // carrier must still connect because identity is pinned by SPIFFE.
        let first = "10111213141516171819101112131415";
        let second = "20212223242526272829202122232425";
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
        let first_credential = credential(&issuer, network, first);
        let second_credential = credential(&issuer, network, second);
        let first_config = Arc::new(config(
            directory.path(),
            &ca,
            &first_credential,
            network,
            first,
            second,
            "100.96.0.1",
            "100.96.0.2",
        ));
        let second_config = Arc::new(config(
            directory.path(),
            &ca,
            &second_credential,
            network,
            second,
            first,
            "100.96.0.2",
            "100.96.0.1",
        ));
        first_config.validate().unwrap();
        second_config.validate().unwrap();
        let (first_endpoint, first_probe) = ProbeSocket::bind(
            first_config.direct.listen,
            tls::direct_server_config(&first_config.tls, &first_config.relay).unwrap(),
        )
        .unwrap();
        let (second_endpoint, second_probe) = ProbeSocket::bind(
            second_config.direct.listen,
            tls::direct_server_config(&second_config.tls, &second_config.relay).unwrap(),
        )
        .unwrap();
        let first_address = first_endpoint.local_addr().unwrap();
        let second_address = second_endpoint.local_addr().unwrap();
        let first_id = Id::from_str(first).unwrap();
        let second_id = Id::from_str(second).unwrap();
        let network_id = Id::from_str(network).unwrap();
        let first_state = Arc::new(State::new(
            RoutingTable::compile(&first_config.routes).unwrap(),
        ));
        let second_state = Arc::new(State::new(
            RoutingTable::compile(&second_config.routes).unwrap(),
        ));
        let (first_candidate_tx, first_candidate_rx) = mpsc::channel(4);
        let (second_candidate_tx, second_candidate_rx) = mpsc::channel(4);
        let (first_inject, _first_packets) = mpsc::channel(4);
        let (second_inject, mut second_packets) = mpsc::channel(4);
        let first_manager = DirectManager::new(
            first_endpoint.clone(),
            Arc::clone(&first_config),
            Arc::clone(&first_state),
            Arc::new(Metrics::default()),
            network_id,
            first_id,
            Arc::new(vec!["100.96.0.1/32".parse::<IpNet>().unwrap()]),
            first_inject,
            first_candidate_rx,
            first_probe,
            Arc::new(StdMutex::new(None)),
            Arc::new(StdMutex::new(BTreeMap::new())),
        )
        .unwrap();
        let second_manager = DirectManager::new(
            second_endpoint.clone(),
            Arc::clone(&second_config),
            Arc::clone(&second_state),
            Arc::new(Metrics::default()),
            network_id,
            second_id,
            Arc::new(vec!["100.96.0.2/32".parse::<IpNet>().unwrap()]),
            second_inject,
            second_candidate_rx,
            second_probe,
            Arc::new(StdMutex::new(None)),
            Arc::new(StdMutex::new(BTreeMap::new())),
        )
        .unwrap();
        let first_task = tokio::spawn(first_manager.run());
        let second_task = tokio::spawn(second_manager.run());
        let token = vec![0x80; 16];
        let start: u64 = SystemTime::now()
            .checked_add(Duration::from_millis(100))
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .try_into()
            .unwrap();
        let candidate = |peer: Id, address: SocketAddr| EndpointCandidate {
            node_id: peer.as_bytes().to_vec(),
            ip_address: match address.ip() {
                IpAddr::V4(value) => value.octets().to_vec(),
                IpAddr::V6(value) => value.octets().to_vec(),
            },
            port: u32::from(address.port()),
            transport: EndpointTransport::QuicUdp as i32,
            priority: 0,
            rendezvous_token: token.clone(),
            probe_start_unix_nano: start,
        };
        first_candidate_tx
            .send(candidate(second_id, second_address))
            .await
            .unwrap();
        second_candidate_tx
            .send(candidate(first_id, first_address))
            .await
            .unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                if first_state.direct.load().contains_key(&second_id)
                    && second_state.direct.load().contains_key(&first_id)
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("direct path was not promoted");
        let payload = packet([100, 96, 0, 1], [100, 96, 0, 2]);
        let direct_pool = PacketPool::prewarmed(1, 1285);
        let direct_metrics = Metrics::default();
        assert!(try_send_direct(
            &first_state,
            &direct_metrics,
            first_id,
            second_id,
            &payload,
            &direct_pool,
        ));
        assert_eq!(
            timeout(Duration::from_secs(2), second_packets.recv())
                .await
                .unwrap()
                .unwrap(),
            payload
        );
        let (_, miss) = direct_pool.copy(&payload);
        assert!(!miss, "direct send did not return its warmed buffer");
        assert_eq!(direct_metrics.snapshot().packet_pool_misses, 0);

        first_state
            .direct
            .load()
            .get(&second_id)
            .unwrap()
            .connection
            .close(0_u32.into(), b"exercise rendezvous recovery");
        timeout(Duration::from_secs(2), async {
            loop {
                if first_state.direct.load().is_empty() && second_state.direct.load().is_empty() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("failed direct path was not detached");

        let refreshed_token = vec![0x81; 16];
        let refreshed_start: u64 = SystemTime::now()
            .checked_add(Duration::from_millis(100))
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .try_into()
            .unwrap();
        let refreshed_candidate = |peer: Id, address: SocketAddr| EndpointCandidate {
            node_id: peer.as_bytes().to_vec(),
            ip_address: match address.ip() {
                IpAddr::V4(value) => value.octets().to_vec(),
                IpAddr::V6(value) => value.octets().to_vec(),
            },
            port: u32::from(address.port()),
            transport: EndpointTransport::QuicUdp as i32,
            priority: 0,
            rendezvous_token: refreshed_token.clone(),
            probe_start_unix_nano: refreshed_start,
        };
        first_candidate_tx
            .send(refreshed_candidate(second_id, second_address))
            .await
            .unwrap();
        second_candidate_tx
            .send(refreshed_candidate(first_id, first_address))
            .await
            .unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                if first_state.direct.load().contains_key(&second_id)
                    && second_state.direct.load().contains_key(&first_id)
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("refreshed rendezvous did not recover the direct path");
        let mut recovered = packet([100, 96, 0, 1], [100, 96, 0, 2]);
        recovered[8] = 63;
        assert!(try_send_direct(
            &first_state,
            &Metrics::default(),
            first_id,
            second_id,
            &recovered,
            &PacketPool::prewarmed(1, 1285),
        ));
        assert_eq!(
            timeout(Duration::from_secs(2), second_packets.recv())
                .await
                .unwrap()
                .unwrap(),
            recovered
        );
        first_endpoint.close(0_u32.into(), b"test complete");
        second_endpoint.close(0_u32.into(), b"test complete");
        first_task.abort();
        second_task.abort();
    }
}
