use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, atomic::Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use arc_swap::ArcSwap;
use bytes::Bytes;
use laneway_protocol::{
    AuthenticatedIdentity, PacketHeader, decode_packet,
    v1::{
        EndpointCandidate, EndpointTransport, RouteHandleBinding, RouteHandleRelease,
        relay_envelope,
    },
};
use tokio::sync::{mpsc, watch};

use crate::{
    Metrics,
    config::Authorization,
    controller::{PacketAuthorization, PacketPeer, PacketRejection, State as ControllerState},
    packet_pool::{PacketBuffer, PacketPool},
};

const MAX_PACKET_PAYLOAD: usize = 1280;

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) identity: AuthenticatedIdentity,
    certificate_serial: Vec<u8>,
    authorization: Authorization,
    allow_ipv6: bool,
    direct_endpoint: Option<SocketAddr>,
    max_routes: u32,
    outbound: mpsc::Sender<Bytes>,
    control: mpsc::Sender<relay_envelope::Body>,
    cancel: watch::Sender<bool>,
}

pub(crate) struct SessionChannels {
    pub(crate) session: Arc<Session>,
    pub(crate) outbound: mpsc::Receiver<Bytes>,
    pub(crate) control: mpsc::Receiver<relay_envelope::Body>,
    pub(crate) canceled: watch::Receiver<bool>,
}

struct Entry {
    session: Arc<Session>,
    by_handle: HashMap<u32, AuthenticatedIdentity>,
    by_peer: HashMap<AuthenticatedIdentity, u32>,
    next_handle: u64,
    candidate_published: Option<std::time::Instant>,
    candidate_paired: HashMap<AuthenticatedIdentity, std::time::Instant>,
}

#[derive(Default)]
struct State {
    sessions: HashMap<AuthenticatedIdentity, Entry>,
}

#[derive(Default)]
struct ForwardingSnapshot {
    sessions: HashMap<AuthenticatedIdentity, ForwardingEntry>,
}

struct ForwardingEntry {
    session: Arc<Session>,
    routes: HashMap<u32, ForwardingTarget>,
}

struct ForwardingTarget {
    recipient: Arc<Session>,
    return_handle: u32,
}

pub(crate) struct Registry {
    state: Mutex<State>,
    forwarding: ArcSwap<ForwardingSnapshot>,
    queue_depth: usize,
    max_sessions: usize,
    max_routes: u32,
    candidate_republish_floor: Duration,
    metrics: Arc<Metrics>,
    controller: Arc<ControllerState>,
    limiter: Option<Mutex<PacketLimiter>>,
}

struct PacketLimiter {
    rate_bits_per_second: u64,
    capacity_bits: u64,
    tokens_bits: u64,
    refill_remainder: u64,
    last_refill: Instant,
    last_sender: Option<AuthenticatedIdentity>,
    consecutive_bits: u64,
    last_sender_change: Instant,
    fairness_window: Duration,
}

impl PacketLimiter {
    fn new(rate_bits_per_second: u64, burst_bytes: usize) -> Option<Self> {
        if rate_bits_per_second == 0 || burst_bytes == 0 {
            return None;
        }
        let capacity_bits = burst_bytes as u64 * 8;
        let half_burst_nanos =
            u128::from(capacity_bits / 2) * 1_000_000_000 / u128::from(rate_bits_per_second);
        let fairness_window = Duration::from_nanos(half_burst_nanos.max(1) as u64);
        let now = Instant::now();
        Some(Self {
            rate_bits_per_second,
            capacity_bits,
            tokens_bits: capacity_bits,
            refill_remainder: 0,
            last_refill: now,
            last_sender: None,
            consecutive_bits: 0,
            last_sender_change: now,
            fairness_window,
        })
    }

    fn allow(
        &mut self,
        sender: AuthenticatedIdentity,
        bytes: usize,
        multiple_sessions: bool,
    ) -> bool {
        let now = Instant::now();
        self.refill(now);
        let needed = bytes as u64 * 8;
        if self.last_sender != Some(sender) {
            self.last_sender = Some(sender);
            self.consecutive_bits = 0;
            self.last_sender_change = now;
        } else if multiple_sessions
            && self.consecutive_bits.saturating_add(needed) > self.capacity_bits / 2
            && now.duration_since(self.last_sender_change) < self.fairness_window
        {
            return false;
        }
        if needed > self.tokens_bits {
            return false;
        }
        self.tokens_bits -= needed;
        self.consecutive_bits = self.consecutive_bits.saturating_add(needed);
        true
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill);
        let numerator = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.rate_bits_per_second))
            .saturating_add(u128::from(self.refill_remainder));
        let added = numerator / 1_000_000_000;
        self.refill_remainder = (numerator % 1_000_000_000) as u64;
        self.tokens_bits = self.capacity_bits.min(
            self.tokens_bits
                .saturating_add(added.min(u128::from(u64::MAX)) as u64),
        );
        if self.tokens_bits == self.capacity_bits {
            self.refill_remainder = 0;
        }
        self.last_refill = now;
    }
}

pub(crate) struct BenchmarkForwarder {
    registry: Registry,
    sender: Arc<Session>,
    recipient_outbound: mpsc::Receiver<Bytes>,
    pool: PacketPool,
}

impl BenchmarkForwarder {
    pub(crate) fn new(flows: usize, queue_depth: usize) -> Result<Self> {
        ensure!(
            (1..=100).contains(&flows),
            "benchmark flows must be in [1,100]"
        );
        ensure!(queue_depth > 0, "benchmark queue depth is zero");
        let network = laneway_protocol::Id::new([1; 16])?;
        let sender_identity = AuthenticatedIdentity {
            network_id: network,
            role: laneway_protocol::Role::Node,
            subject_id: laneway_protocol::Id::new([2; 16])?,
        };
        let recipient_identity = AuthenticatedIdentity {
            network_id: network,
            role: laneway_protocol::Role::Node,
            subject_id: laneway_protocol::Id::new([3; 16])?,
        };
        let sender_authorization = Authorization {
            prefixes: (1..=flows)
                .map(|flow| format!("100.96.0.{flow}/32").parse())
                .collect::<std::result::Result<Vec<_>, _>>()?,
            overlay_addresses: (1..=flows)
                .map(|flow| format!("100.96.0.{flow}").parse())
                .collect::<std::result::Result<Vec<_>, _>>()?,
        };
        let recipient_authorization = Authorization {
            prefixes: (1..=flows)
                .map(|flow| format!("100.97.0.{flow}/32").parse())
                .collect::<std::result::Result<Vec<_>, _>>()?,
            overlay_addresses: (1..=flows)
                .map(|flow| format!("100.97.0.{flow}").parse())
                .collect::<std::result::Result<Vec<_>, _>>()?,
        };
        let (sender_outbound, _sender_outbound) = mpsc::channel(queue_depth);
        let (recipient_outbound, recipient_receiver) = mpsc::channel(queue_depth);
        let (sender_control, _) = mpsc::channel(1);
        let (recipient_control, _) = mpsc::channel(1);
        let (sender_cancel, _) = watch::channel(false);
        let (recipient_cancel, _) = watch::channel(false);
        let sender = Arc::new(Session {
            identity: sender_identity,
            certificate_serial: Vec::new(),
            authorization: sender_authorization,
            allow_ipv6: true,
            direct_endpoint: None,
            max_routes: flows as u32,
            outbound: sender_outbound,
            control: sender_control,
            cancel: sender_cancel,
        });
        let recipient = Arc::new(Session {
            identity: recipient_identity,
            certificate_serial: Vec::new(),
            authorization: recipient_authorization,
            allow_ipv6: true,
            direct_endpoint: None,
            max_routes: flows as u32,
            outbound: recipient_outbound,
            control: recipient_control,
            cancel: recipient_cancel,
        });
        let metrics = Arc::new(Metrics::default());
        let registry = Registry::new_with_controller(
            queue_depth,
            2,
            flows as u32,
            Arc::clone(&metrics),
            ControllerState::static_snapshot(HashMap::new()),
            Duration::from_millis(100),
            (0, 0),
        );
        registry.forwarding.store(Arc::new(ForwardingSnapshot {
            sessions: HashMap::from([(
                sender_identity,
                ForwardingEntry {
                    session: Arc::clone(&sender),
                    routes: (1..=flows)
                        .map(|flow| {
                            (
                                flow as u32,
                                ForwardingTarget {
                                    recipient: Arc::clone(&recipient),
                                    return_handle: flow as u32,
                                },
                            )
                        })
                        .collect(),
                },
            )]),
        }));
        Ok(Self {
            registry,
            sender,
            recipient_outbound: recipient_receiver,
            pool: PacketPool::prewarmed(queue_depth, MAX_PACKET_PAYLOAD + 5),
        })
    }

    pub(crate) fn forward(&mut self, frame: &[u8]) -> bool {
        let (mut pooled, miss) = self.pool.take();
        if miss || frame.len() > pooled.capacity() {
            return false;
        }
        pooled.extend_from_slice(frame);
        if self.registry.forward(&self.sender, pooled).is_err() {
            return false;
        }
        let Ok(forwarded) = self.recipient_outbound.try_recv() else {
            return false;
        };
        self.registry.metrics.queue_removed(1);
        PacketHeader::decode(&forwarded).is_ok()
    }
}

impl Registry {
    #[cfg(test)]
    pub(crate) fn new(
        queue_depth: usize,
        max_sessions: usize,
        max_routes: u32,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::new_with_controller(
            queue_depth,
            max_sessions,
            max_routes,
            metrics,
            ControllerState::static_snapshot(HashMap::new()),
            Duration::from_millis(100),
            (0, 0),
        )
    }

    pub(crate) fn new_with_controller(
        queue_depth: usize,
        max_sessions: usize,
        max_routes: u32,
        metrics: Arc<Metrics>,
        controller: Arc<ControllerState>,
        candidate_republish_floor: Duration,
        packet_limiter: (u64, usize),
    ) -> Self {
        Self {
            state: Mutex::new(State::default()),
            forwarding: ArcSwap::from_pointee(ForwardingSnapshot::default()),
            queue_depth,
            max_sessions,
            max_routes,
            candidate_republish_floor,
            metrics,
            controller,
            limiter: PacketLimiter::new(packet_limiter.0, packet_limiter.1).map(Mutex::new),
        }
    }

    #[cfg(test)]
    pub(crate) fn register(
        &self,
        identity: AuthenticatedIdentity,
        authorization: Authorization,
        requested_max_routes: u32,
        allow_ipv6: bool,
    ) -> Result<SessionChannels> {
        self.register_credential(
            identity,
            Vec::new(),
            authorization,
            requested_max_routes,
            allow_ipv6,
            None,
        )
    }

    pub(crate) fn register_credential(
        &self,
        identity: AuthenticatedIdentity,
        certificate_serial: Vec<u8>,
        authorization: Authorization,
        requested_max_routes: u32,
        allow_ipv6: bool,
        direct_endpoint: Option<SocketAddr>,
    ) -> Result<SessionChannels> {
        ensure!(
            requested_max_routes > 0 && requested_max_routes <= self.max_routes,
            "requested route limit is invalid"
        );
        let (outbound_tx, outbound) = mpsc::channel(self.queue_depth);
        let (control_tx, control) = mpsc::channel(requested_max_routes as usize + 16);
        let (cancel_tx, canceled) = watch::channel(false);
        let session = Arc::new(Session {
            identity,
            certificate_serial,
            authorization,
            allow_ipv6,
            direct_endpoint,
            max_routes: requested_max_routes,
            outbound: outbound_tx,
            control: control_tx,
            cancel: cancel_tx,
        });

        let mut notifications = Vec::new();
        let mut old = None;
        {
            let mut state = self.lock();
            if state.sessions.contains_key(&identity) {
                let released = binding_count_for(&state, identity);
                let (removed, releases) = detach_locked(&mut state, identity);
                old = removed;
                self.metrics
                    .bindings_released
                    .fetch_add(released, Ordering::Relaxed);
                notifications.extend(releases);
                self.metrics
                    .sessions_replaced
                    .fetch_add(1, Ordering::Relaxed);
            }
            ensure!(
                state.sessions.len() < self.max_sessions,
                "relay session limit reached"
            );
            state.sessions.insert(
                identity,
                Entry {
                    session: Arc::clone(&session),
                    by_handle: HashMap::new(),
                    by_peer: HashMap::new(),
                    next_handle: 1,
                    candidate_published: None,
                    candidate_paired: HashMap::new(),
                },
            );
            let peers: Vec<_> = state
                .sessions
                .keys()
                .copied()
                .filter(|peer| *peer != identity && peer.network_id == identity.network_id)
                .collect();
            for peer in peers {
                if let Some(pair) = bind_locked(&mut state, identity, peer) {
                    notifications.extend(pair);
                    self.metrics
                        .bindings_created
                        .fetch_add(2, Ordering::Relaxed);
                }
            }
            self.publish_forwarding(&state);
            self.metrics
                .sessions
                .store(state.sessions.len() as u64, Ordering::Release);
            self.metrics.registrations.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(old) = old {
            let _ = old.cancel.send(true);
        }
        send_notifications(notifications);
        Ok(SessionChannels {
            session,
            outbound,
            control,
            canceled,
        })
    }

    pub(crate) fn unregister(&self, session: &Arc<Session>) {
        let notifications = {
            let mut state = self.lock();
            let current = state
                .sessions
                .get(&session.identity)
                .is_some_and(|entry| Arc::ptr_eq(&entry.session, session));
            if !current {
                return;
            }
            let released = binding_count_for(&state, session.identity);
            let (_, notifications) = detach_locked(&mut state, session.identity);
            self.publish_forwarding(&state);
            self.metrics
                .bindings_released
                .fetch_add(released, Ordering::Relaxed);
            self.metrics
                .sessions
                .store(state.sessions.len() as u64, Ordering::Release);
            self.metrics.unregistrations.fetch_add(1, Ordering::Relaxed);
            notifications
        };
        send_notifications(notifications);
    }

    /// Revalidates an established carrier against the current controller
    /// snapshot. This intentionally does not reuse the admission-time result:
    /// snapshot replacement, lease expiry, and certificate revocation must all
    /// take effect for already-open sessions.
    pub(crate) fn session_authorized(&self, session: &Arc<Session>) -> bool {
        self.controller
            .credential_authorized_with_fallback(&session.identity, &session.certificate_serial)
    }

    pub(crate) fn publish_candidate(
        &self,
        session: &Arc<Session>,
        _candidate: &EndpointCandidate,
    ) -> Result<()> {
        // Publication is only a signal. As in the Go relay, every claimed
        // endpoint field is discarded in favor of the authenticated identity
        // and UDP source observed on this QUIC carrier.
        let endpoint = session
            .direct_endpoint
            .context("direct-path capability was not negotiated on QUIC")?;
        ensure!(
            endpoint.port() != 0
                && !endpoint.ip().is_unspecified()
                && !endpoint.ip().is_multicast(),
            "relay-observed endpoint is invalid"
        );
        let mut notifications = Vec::new();
        {
            let mut state = self.lock();
            let now = std::time::Instant::now();
            let current = state
                .sessions
                .get_mut(&session.identity)
                .filter(|entry| Arc::ptr_eq(&entry.session, session))
                .context("relay session is stale")?;
            if let Some(previous) = current.candidate_published {
                ensure!(
                    now.duration_since(previous) >= self.candidate_republish_floor,
                    "endpoint candidate was republished too quickly"
                );
            }
            current.candidate_published = Some(now);
            self.metrics
                .candidate_publications
                .fetch_add(1, Ordering::Relaxed);
            let peers: Vec<_> = current.by_peer.keys().copied().collect();
            for peer_id in peers {
                let Some(peer) = state.sessions.get(&peer_id) else {
                    continue;
                };
                let Some(peer_endpoint) = peer.session.direct_endpoint else {
                    continue;
                };
                if peer.candidate_published.is_none() {
                    continue;
                }
                if state
                    .sessions
                    .get(&session.identity)
                    .and_then(|entry| entry.candidate_paired.get(&peer_id))
                    .is_some_and(|previous| {
                        now.duration_since(*previous) < self.candidate_republish_floor
                    })
                {
                    continue;
                }
                let token = random_token()?;
                let start = SystemTime::now()
                    .checked_add(Duration::from_millis(250))
                    .context("rendezvous start overflow")?
                    .duration_since(UNIX_EPOCH)?
                    .as_nanos()
                    .try_into()
                    .context("rendezvous start exceeds fixed64")?;
                notifications.push(Notification {
                    sender: session.control.clone(),
                    cancel: session.cancel.clone(),
                    body: candidate_body(peer_id, peer_endpoint, &token, start),
                });
                notifications.push(Notification {
                    sender: peer.session.control.clone(),
                    cancel: peer.session.cancel.clone(),
                    body: candidate_body(session.identity, endpoint, &token, start),
                });
                state
                    .sessions
                    .get_mut(&session.identity)
                    .expect("current session exists")
                    .candidate_paired
                    .insert(peer_id, now);
                state
                    .sessions
                    .get_mut(&peer_id)
                    .expect("peer session exists")
                    .candidate_paired
                    .insert(session.identity, now);
                self.metrics.candidate_pairs.fetch_add(1, Ordering::Relaxed);
            }
        }
        send_notifications(notifications);
        Ok(())
    }

    pub(crate) fn release(&self, session: &Arc<Session>, handle: u32) -> Result<()> {
        ensure!(handle != 0, "route handle is zero");
        let mut state = self.lock();
        let entry = state
            .sessions
            .get_mut(&session.identity)
            .filter(|entry| Arc::ptr_eq(&entry.session, session))
            .ok_or_else(|| anyhow::anyhow!("relay session is stale"))?;
        let peer = entry
            .by_handle
            .remove(&handle)
            .ok_or_else(|| anyhow::anyhow!("unknown route handle"))?;
        entry.by_peer.remove(&peer);
        self.publish_forwarding(&state);
        self.metrics
            .bindings_released
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn forward(
        &self,
        session: &Arc<Session>,
        frame: impl Into<PacketBuffer>,
    ) -> Result<()> {
        let frame = frame.into();
        let length = frame.as_ref().len() as u64;
        let result = self.forward_inner(session, frame);
        if result.is_err() {
            self.metrics.dropped_packets.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .dropped_bytes
                .fetch_add(length, Ordering::Relaxed);
        }
        result
    }

    fn forward_inner(&self, session: &Arc<Session>, frame: PacketBuffer) -> Result<()> {
        let (header, packet) = match decode_packet(frame.as_ref()) {
            Ok(value) => value,
            Err(error) => {
                self.metrics
                    .dropped_malformed
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error.into());
            }
        };
        let (source, destination) = packet_addresses(packet)?;
        let (recipient, return_handle) = {
            let forwarding = self.forwarding.load();
            let sender = match forwarding
                .sessions
                .get(&session.identity)
                .filter(|entry| Arc::ptr_eq(&entry.session, session))
            {
                Some(sender) => sender,
                None => {
                    self.metrics.dropped_closed.fetch_add(1, Ordering::Relaxed);
                    bail!("relay session is stale");
                }
            };
            let target = match sender.routes.get(&header.route_handle) {
                Some(target) => target,
                None => {
                    self.metrics
                        .dropped_unknown_handle
                        .fetch_add(1, Ordering::Relaxed);
                    bail!("unknown route handle");
                }
            };
            if packet.len() > MAX_PACKET_PAYLOAD {
                self.metrics
                    .dropped_too_large
                    .fetch_add(1, Ordering::Relaxed);
                bail!("packet exceeds negotiated payload limit");
            }
            if source.is_ipv6() && (!session.allow_ipv6 || !target.recipient.allow_ipv6) {
                self.metrics
                    .dropped_capability
                    .fetch_add(1, Ordering::Relaxed);
                bail!("IPv6 packet capability was not negotiated");
            }
            if let Err(rejection) = self.controller.authorize_packet(PacketAuthorization {
                source: PacketPeer {
                    identity: &session.identity,
                    certificate_serial: &session.certificate_serial,
                    fallback: &session.authorization,
                    address: source,
                },
                destination: PacketPeer {
                    identity: &target.recipient.identity,
                    certificate_serial: &target.recipient.certificate_serial,
                    fallback: &target.recipient.authorization,
                    address: destination,
                },
                packet,
            }) {
                match rejection {
                    PacketRejection::Credential => {
                        bail!("sender or recipient authorization is expired or revoked")
                    }
                    PacketRejection::Source => {
                        self.metrics.dropped_source.fetch_add(1, Ordering::Relaxed);
                        bail!("packet source is not authorized")
                    }
                    PacketRejection::Destination => {
                        self.metrics
                            .dropped_destination
                            .fetch_add(1, Ordering::Relaxed);
                        bail!("packet destination is not authorized")
                    }
                    PacketRejection::Policy => {
                        self.metrics
                            .dropped_capability
                            .fetch_add(1, Ordering::Relaxed);
                        bail!("packet denied by controller policy")
                    }
                }
            }
            (Arc::clone(&target.recipient), target.return_handle)
        };

        if let Some(limiter) = &self.limiter {
            let multiple_sessions = self.forwarding.load().sessions.len() > 1;
            if !limiter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .allow(session.identity, frame.as_ref().len(), multiple_sessions)
            {
                self.metrics
                    .throttled_packets
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .throttled_bytes
                    .fetch_add(frame.as_ref().len() as u64, Ordering::Relaxed);
                self.metrics
                    .limiter_saturated_until_millis
                    .store(unix_millis().saturating_add(1_000), Ordering::Relaxed);
                bail!("relay aggregate packet-data limit exhausted");
            }
        }

        // QUIC and TCP readers both hand over uniquely owned storage. Retag
        // the five-byte route header in place and transfer that allocation to
        // the recipient writer instead of copying every warmed packet.
        let prefix = PacketHeader {
            version: 1,
            flags: 0,
            route_handle: return_handle,
        }
        .encode()?;
        // Reserve real bounded channel capacity before accounting. Failed
        // Full/Closed attempts never inflate the queue gauge or peak.
        let permit = match recipient.outbound.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                self.metrics
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                bail!("recipient queue is full")
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.metrics.dropped_closed.fetch_add(1, Ordering::Relaxed);
                bail!("recipient queue is closed")
            }
        };
        let output = frame.retag(&prefix)?;
        let length = output.len() as u64;
        // Account before publishing through the permit so a fast receiver can
        // never decrement the gauge before the producer increment is visible.
        let queue_depth = self.metrics.queue_enqueue_started();
        permit.send(output);
        self.metrics.queue_enqueue_completed(queue_depth);
        self.metrics
            .forwarded_packets
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .forwarded_bytes
            .fetch_add(length, Ordering::Relaxed);
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn publish_forwarding(&self, state: &State) {
        self.forwarding
            .store(Arc::new(ForwardingSnapshot::from_state(state)));
    }
}

impl ForwardingSnapshot {
    fn from_state(state: &State) -> Self {
        let sessions = state
            .sessions
            .iter()
            .map(|(identity, entry)| {
                let routes = entry
                    .by_handle
                    .iter()
                    .filter_map(|(handle, recipient_id)| {
                        let recipient = state.sessions.get(recipient_id)?;
                        let return_handle = *recipient.by_peer.get(identity)?;
                        Some((
                            *handle,
                            ForwardingTarget {
                                recipient: Arc::clone(&recipient.session),
                                return_handle,
                            },
                        ))
                    })
                    .collect();
                (
                    *identity,
                    ForwardingEntry {
                        session: Arc::clone(&entry.session),
                        routes,
                    },
                )
            })
            .collect();
        Self { sessions }
    }
}

fn random_token() -> Result<[u8; 16]> {
    loop {
        let mut token = [0_u8; 16];
        getrandom::fill(&mut token)?;
        if token != [0; 16] {
            return Ok(token);
        }
    }
}

fn candidate_body(
    peer: AuthenticatedIdentity,
    endpoint: SocketAddr,
    token: &[u8; 16],
    start: u64,
) -> relay_envelope::Body {
    let ip_address = match endpoint.ip() {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or_else(
            || value.octets().to_vec(),
            |mapped| mapped.octets().to_vec(),
        ),
    };
    relay_envelope::Body::EndpointCandidate(EndpointCandidate {
        node_id: peer.subject_id.as_bytes().to_vec(),
        ip_address,
        port: u32::from(endpoint.port()),
        transport: EndpointTransport::QuicUdp as i32,
        priority: 0,
        rendezvous_token: token.to_vec(),
        probe_start_unix_nano: start,
    })
}

struct Notification {
    sender: mpsc::Sender<relay_envelope::Body>,
    cancel: watch::Sender<bool>,
    body: relay_envelope::Body,
}

fn bind_locked(
    state: &mut State,
    first: AuthenticatedIdentity,
    second: AuthenticatedIdentity,
) -> Option<[Notification; 2]> {
    let first_entry = state.sessions.get(&first)?;
    let second_entry = state.sessions.get(&second)?;
    if first_entry.by_handle.len() >= first_entry.session.max_routes as usize
        || second_entry.by_handle.len() >= second_entry.session.max_routes as usize
    {
        return None;
    }
    let first_handle = u32::try_from(first_entry.next_handle).ok()?;
    let second_handle = u32::try_from(second_entry.next_handle).ok()?;
    if first_handle == 0 || second_handle == 0 {
        return None;
    }
    let first_control = first_entry.session.control.clone();
    let first_cancel = first_entry.session.cancel.clone();
    let second_control = second_entry.session.control.clone();
    let second_cancel = second_entry.session.cancel.clone();
    let first_peer_id = second.subject_id.as_bytes().to_vec();
    let second_peer_id = first.subject_id.as_bytes().to_vec();

    let first_entry = state.sessions.get_mut(&first)?;
    first_entry.next_handle += 1;
    first_entry.by_handle.insert(first_handle, second);
    first_entry.by_peer.insert(second, first_handle);
    let second_entry = state.sessions.get_mut(&second)?;
    second_entry.next_handle += 1;
    second_entry.by_handle.insert(second_handle, first);
    second_entry.by_peer.insert(first, second_handle);

    Some([
        Notification {
            sender: first_control,
            cancel: first_cancel,
            body: relay_envelope::Body::RouteHandleBinding(RouteHandleBinding {
                route_handle: first_handle,
                peer_node_id: first_peer_id,
                max_packet_payload: MAX_PACKET_PAYLOAD as u32,
            }),
        },
        Notification {
            sender: second_control,
            cancel: second_cancel,
            body: relay_envelope::Body::RouteHandleBinding(RouteHandleBinding {
                route_handle: second_handle,
                peer_node_id: second_peer_id,
                max_packet_payload: MAX_PACKET_PAYLOAD as u32,
            }),
        },
    ])
}

fn detach_locked(
    state: &mut State,
    identity: AuthenticatedIdentity,
) -> (Option<Arc<Session>>, Vec<Notification>) {
    let removed = state.sessions.remove(&identity);
    let Some(removed) = removed else {
        return (None, Vec::new());
    };
    let mut notifications = Vec::new();
    for peer in state.sessions.values_mut() {
        peer.candidate_paired.remove(&identity);
        if let Some(handle) = peer.by_peer.remove(&identity) {
            peer.by_handle.remove(&handle);
            notifications.push(Notification {
                sender: peer.session.control.clone(),
                cancel: peer.session.cancel.clone(),
                body: relay_envelope::Body::RouteHandleRelease(RouteHandleRelease {
                    route_handle: handle,
                }),
            });
        }
    }
    (Some(removed.session), notifications)
}

fn binding_count_for(state: &State, identity: AuthenticatedIdentity) -> u64 {
    let local = state
        .sessions
        .get(&identity)
        .map_or(0, |entry| entry.by_handle.len());
    let remote = state
        .sessions
        .values()
        .filter(|entry| entry.by_peer.contains_key(&identity))
        .count();
    (local + remote) as u64
}

fn send_notifications(notifications: Vec<Notification>) {
    for notification in notifications {
        if notification.sender.try_send(notification.body).is_err() {
            // The stream writer is either gone or has exceeded its explicit
            // bounded control backlog. Cancel the session to trigger cleanup.
            let _ = notification.cancel.send(true);
        }
    }
}

pub(crate) fn packet_addresses(packet: &[u8]) -> Result<(IpAddr, IpAddr)> {
    match packet[0] >> 4 {
        4 => Ok((
            IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
            IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
        )),
        6 => {
            let source: [u8; 16] = packet[8..24].try_into()?;
            let destination: [u8; 16] = packet[24..40].try_into()?;
            Ok((
                IpAddr::V6(Ipv6Addr::from(source)),
                IpAddr::V6(Ipv6Addr::from(destination)),
            ))
        }
        _ => bail!("invalid IP packet"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::{Id, Role, encode_packet};
    use std::{sync::mpsc as std_mpsc, time::Duration};

    fn identity(node: u8) -> AuthenticatedIdentity {
        AuthenticatedIdentity {
            network_id: Id::new([1; 16]).unwrap(),
            role: Role::Node,
            subject_id: Id::new([node; 16]).unwrap(),
        }
    }

    fn authorization(address: &str) -> Authorization {
        Authorization {
            prefixes: vec![address.parse().unwrap()],
            overlay_addresses: vec![address.split('/').next().unwrap().parse().unwrap()],
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
    fn packet_limiter_is_global_and_reserves_fairness_for_another_sender() {
        let mut limiter = PacketLimiter::new(8_000_000, 2_000).unwrap();
        assert!(limiter.allow(identity(1), 1_000, true));
        assert!(!limiter.allow(identity(1), 1, true));
        assert!(limiter.allow(identity(2), 1_000, true));
        limiter.tokens_bits = 0;
        limiter.last_refill = Instant::now();
        assert!(!limiter.allow(identity(3), 1_000, false));
    }

    #[test]
    fn packet_limiter_preserves_fractional_refills() {
        let mut limiter = PacketLimiter::new(8, 1_285).unwrap();
        let start = Instant::now();
        limiter.tokens_bits = 0;
        limiter.last_refill = start;
        for tenth in 1..=10 {
            limiter.refill(start + Duration::from_millis(tenth * 100));
        }
        assert_eq!(limiter.tokens_bits, 8);
    }

    fn ipv6(source: [u8; 16], destination: [u8; 16]) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet
    }

    async fn next_binding(channels: &mut SessionChannels) -> u32 {
        loop {
            match channels.control.recv().await.unwrap() {
                relay_envelope::Body::RouteHandleBinding(binding) => {
                    return binding.route_handle;
                }
                relay_envelope::Body::RouteHandleRelease(_) => {}
                body => panic!("unexpected control body {body:?}"),
            }
        }
    }

    fn framed(handle: u32, source: [u8; 4], destination: [u8; 4]) -> Bytes {
        let mut frame = Vec::new();
        encode_packet(
            PacketHeader {
                version: 1,
                flags: 0,
                route_handle: handle,
            },
            &ipv4(source, destination),
            &mut frame,
        )
        .unwrap();
        Bytes::from(frame)
    }

    #[tokio::test]
    async fn binds_forwards_rewrites_and_cleans_up() {
        let metrics = Arc::new(Metrics::default());
        let registry = Registry::new(2, 4, 4, Arc::clone(&metrics));
        let mut first = registry
            .register(identity(2), authorization("100.96.0.1/32"), 4, true)
            .unwrap();
        let mut second = registry
            .register(identity(3), authorization("100.96.0.2/32"), 4, true)
            .unwrap();
        let first_binding = first.control.recv().await.unwrap();
        let second_binding = second.control.recv().await.unwrap();
        let first_handle = match first_binding {
            relay_envelope::Body::RouteHandleBinding(binding) => binding.route_handle,
            _ => panic!("wrong control body"),
        };
        let second_handle = match second_binding {
            relay_envelope::Body::RouteHandleBinding(binding) => binding.route_handle,
            _ => panic!("wrong control body"),
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
        registry
            .forward(&first.session, Bytes::from(frame))
            .unwrap();
        let forwarded = second.outbound.recv().await.unwrap();
        assert_eq!(
            PacketHeader::decode(&forwarded).unwrap().route_handle,
            second_handle
        );

        registry.unregister(&first.session);
        assert!(
            registry
                .forward(
                    &first.session,
                    framed(first_handle, [100, 96, 0, 1], [100, 96, 0, 2]),
                )
                .is_err()
        );
        assert!(matches!(
            second.control.recv().await,
            Some(relay_envelope::Body::RouteHandleRelease(_))
        ));
        assert_eq!(metrics.snapshot().forwarded_packets, 1);
        assert_eq!(metrics.snapshot().sessions, 1);
        assert_eq!(metrics.snapshot().bindings_released, 2);
    }

    #[tokio::test]
    async fn rejects_spoofed_source_and_queue_overflow() {
        let metrics = Arc::new(Metrics::default());
        let registry = Registry::new(1, 4, 4, Arc::clone(&metrics));
        let mut first = registry
            .register(identity(2), authorization("100.96.0.1/32"), 4, true)
            .unwrap();
        let mut second = registry
            .register(identity(3), authorization("100.96.0.2/32"), 4, true)
            .unwrap();
        let handle = match first.control.recv().await.unwrap() {
            relay_envelope::Body::RouteHandleBinding(binding) => binding.route_handle,
            _ => unreachable!(),
        };
        let _ = second.control.recv().await;
        let mut frame = Vec::new();
        encode_packet(
            PacketHeader {
                version: 1,
                flags: 0,
                route_handle: handle,
            },
            &ipv4([100, 96, 9, 9], [100, 96, 0, 2]),
            &mut frame,
        )
        .unwrap();
        assert!(
            registry
                .forward(&first.session, Bytes::from(frame))
                .is_err()
        );
        assert_eq!(metrics.snapshot().dropped_source, 1);

        registry
            .forward(
                &first.session,
                framed(handle, [100, 96, 0, 1], [100, 96, 0, 2]),
            )
            .unwrap();
        assert!(
            registry
                .forward(
                    &first.session,
                    framed(handle, [100, 96, 0, 1], [100, 96, 0, 2]),
                )
                .is_err()
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.queue_depth, 1);
        assert_eq!(snapshot.queue_depth_peak, 1);
        assert_eq!(snapshot.dropped_queue_full, 1);
        assert_eq!(snapshot.forwarded_packets, 1);
    }

    #[tokio::test]
    async fn rejects_ipv6_when_either_session_lacks_the_capability() {
        for (sender_ipv6, recipient_ipv6) in [(false, true), (true, false)] {
            let metrics = Arc::new(Metrics::default());
            let registry = Registry::new(2, 4, 4, Arc::clone(&metrics));
            let mut first = registry
                .register(identity(2), authorization("fd00::1/128"), 4, sender_ipv6)
                .unwrap();
            let mut second = registry
                .register(identity(3), authorization("fd00::2/128"), 4, recipient_ipv6)
                .unwrap();
            let handle = match first.control.recv().await.unwrap() {
                relay_envelope::Body::RouteHandleBinding(binding) => binding.route_handle,
                _ => unreachable!(),
            };
            let _ = second.control.recv().await;
            let mut frame = Vec::new();
            let mut source = [0_u8; 16];
            source[0] = 0xfd;
            source[15] = 1;
            let mut destination = [0_u8; 16];
            destination[0] = 0xfd;
            destination[15] = 2;
            encode_packet(
                PacketHeader {
                    version: 1,
                    flags: 0,
                    route_handle: handle,
                },
                &ipv6(source, destination),
                &mut frame,
            )
            .unwrap();
            assert!(
                registry
                    .forward(&first.session, Bytes::from(frame))
                    .is_err()
            );
            assert_eq!(metrics.snapshot().dropped_capability, 1);
            assert!(second.outbound.try_recv().is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwarding_remains_available_while_control_state_mutex_is_held() {
        let metrics = Arc::new(Metrics::default());
        let registry = Arc::new(Registry::new(2, 4, 4, Arc::clone(&metrics)));
        let mut first = registry
            .register(identity(2), authorization("100.96.0.1/32"), 4, true)
            .unwrap();
        let mut second = registry
            .register(identity(3), authorization("100.96.0.2/32"), 4, true)
            .unwrap();
        let handle = next_binding(&mut first).await;
        let _ = next_binding(&mut second).await;
        let frame = framed(handle, [100, 96, 0, 1], [100, 96, 0, 2]);
        let sender = Arc::clone(&first.session);
        let worker_registry = Arc::clone(&registry);
        let (completed, completion) = std_mpsc::channel();

        let state_guard = registry.lock();
        let worker = std::thread::spawn(move || {
            completed
                .send(worker_registry.forward(&sender, frame))
                .unwrap();
        });
        let result = completion.recv_timeout(Duration::from_secs(1));
        drop(state_guard);
        worker.join().unwrap();
        result
            .expect("forwarding blocked on the control-state mutex")
            .unwrap();
        assert!(second.outbound.recv().await.is_some());
    }

    #[tokio::test]
    async fn replacement_snapshot_rejects_stale_carrier_and_targets_new_session() {
        let metrics = Arc::new(Metrics::default());
        let registry = Registry::new(4, 4, 4, Arc::clone(&metrics));
        let mut old_first = registry
            .register(identity(2), authorization("100.96.0.1/32"), 4, true)
            .unwrap();
        let mut second = registry
            .register(identity(3), authorization("100.96.0.2/32"), 4, true)
            .unwrap();
        let old_handle = next_binding(&mut old_first).await;
        let _ = next_binding(&mut second).await;

        let mut new_first = registry
            .register(identity(2), authorization("100.96.0.1/32"), 4, true)
            .unwrap();
        let new_handle = next_binding(&mut new_first).await;
        let _ = next_binding(&mut second).await;
        assert!(
            registry
                .forward(
                    &old_first.session,
                    framed(old_handle, [100, 96, 0, 1], [100, 96, 0, 2]),
                )
                .is_err()
        );
        registry
            .forward(
                &new_first.session,
                framed(new_handle, [100, 96, 0, 1], [100, 96, 0, 2]),
            )
            .unwrap();
        assert!(second.outbound.recv().await.is_some());
        assert_eq!(metrics.snapshot().sessions_replaced, 1);

        let mut new_second = registry
            .register(identity(3), authorization("100.96.0.2/32"), 4, true)
            .unwrap();
        let replacement_handle = next_binding(&mut new_first).await;
        let _ = next_binding(&mut new_second).await;
        registry
            .forward(
                &new_first.session,
                framed(replacement_handle, [100, 96, 0, 1], [100, 96, 0, 2]),
            )
            .unwrap();
        assert!(new_second.outbound.recv().await.is_some());
        assert!(second.outbound.try_recv().is_err());
    }

    #[tokio::test]
    async fn directional_release_atomically_disables_both_forwarding_directions() {
        let metrics = Arc::new(Metrics::default());
        let registry = Registry::new(4, 4, 4, Arc::clone(&metrics));
        let mut first = registry
            .register(identity(2), authorization("100.96.0.1/32"), 4, true)
            .unwrap();
        let mut second = registry
            .register(identity(3), authorization("100.96.0.2/32"), 4, true)
            .unwrap();
        let first_handle = next_binding(&mut first).await;
        let second_handle = next_binding(&mut second).await;
        registry.release(&first.session, first_handle).unwrap();

        assert!(
            registry
                .forward(
                    &first.session,
                    framed(first_handle, [100, 96, 0, 1], [100, 96, 0, 2]),
                )
                .is_err()
        );
        assert!(
            registry
                .forward(
                    &second.session,
                    framed(second_handle, [100, 96, 0, 2], [100, 96, 0, 1]),
                )
                .is_err()
        );
        assert_eq!(metrics.snapshot().dropped_unknown_handle, 2);
    }

    #[tokio::test]
    async fn pairs_published_observed_quic_candidates() {
        let registry = Registry::new(2, 4, 4, Arc::new(Metrics::default()));
        let first_endpoint: SocketAddr = "198.51.100.10:41001".parse().unwrap();
        let second_endpoint: SocketAddr = "[2001:db8::20]:41002".parse().unwrap();
        let mut first = registry
            .register_credential(
                identity(2),
                Vec::new(),
                authorization("100.96.0.1/32"),
                4,
                true,
                Some(first_endpoint),
            )
            .unwrap();
        let mut second = registry
            .register_credential(
                identity(3),
                Vec::new(),
                authorization("100.96.0.2/32"),
                4,
                true,
                Some(second_endpoint),
            )
            .unwrap();
        assert!(matches!(
            first.control.recv().await,
            Some(relay_envelope::Body::RouteHandleBinding(_))
        ));
        assert!(matches!(
            second.control.recv().await,
            Some(relay_envelope::Body::RouteHandleBinding(_))
        ));

        let publication = || EndpointCandidate {
            node_id: vec![0xff; 16],
            ip_address: vec![203, 0, 113, 99],
            port: 65_535,
            transport: EndpointTransport::TlsTcp as i32,
            priority: 0,
            rendezvous_token: vec![0xff; 16],
            probe_start_unix_nano: 1,
        };
        registry
            .publish_candidate(&first.session, &publication())
            .unwrap();
        assert!(first.control.try_recv().is_err());
        assert!(second.control.try_recv().is_err());
        registry
            .publish_candidate(&second.session, &publication())
            .unwrap();
        assert!(
            registry
                .publish_candidate(&first.session, &publication())
                .is_err()
        );

        let first_candidate = match first.control.recv().await.unwrap() {
            relay_envelope::Body::EndpointCandidate(candidate) => candidate,
            _ => panic!("wrong control body"),
        };
        let second_candidate = match second.control.recv().await.unwrap() {
            relay_envelope::Body::EndpointCandidate(candidate) => candidate,
            _ => panic!("wrong control body"),
        };
        assert_eq!(first_candidate.node_id, identity(3).subject_id.as_bytes());
        assert_eq!(
            first_candidate.ip_address,
            match second_endpoint.ip() {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            }
        );
        assert_eq!(first_candidate.port, u32::from(second_endpoint.port()));
        assert_eq!(second_candidate.node_id, identity(2).subject_id.as_bytes());
        assert_eq!(
            second_candidate.ip_address,
            match first_endpoint.ip() {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            }
        );
        assert_eq!(second_candidate.port, u32::from(first_endpoint.port()));
        assert_eq!(first_candidate.rendezvous_token.len(), 16);
        assert_ne!(first_candidate.rendezvous_token, vec![0; 16]);
        assert_eq!(
            first_candidate.rendezvous_token,
            second_candidate.rendezvous_token
        );
        assert_eq!(
            first_candidate.probe_start_unix_nano,
            second_candidate.probe_start_unix_nano
        );
        assert!(first_candidate.probe_start_unix_nano > 0);

        tokio::time::sleep(Duration::from_millis(110)).await;
        registry
            .publish_candidate(&first.session, &publication())
            .unwrap();
        let refreshed_first = match first.control.recv().await.unwrap() {
            relay_envelope::Body::EndpointCandidate(candidate) => candidate,
            _ => panic!("wrong refreshed control body"),
        };
        let refreshed_second = match second.control.recv().await.unwrap() {
            relay_envelope::Body::EndpointCandidate(candidate) => candidate,
            _ => panic!("wrong refreshed control body"),
        };
        assert_eq!(
            refreshed_first.rendezvous_token,
            refreshed_second.rendezvous_token
        );
        assert_ne!(
            refreshed_first.rendezvous_token,
            first_candidate.rendezvous_token
        );
        registry
            .publish_candidate(&second.session, &publication())
            .unwrap();
        assert!(first.control.try_recv().is_err());
        assert!(second.control.try_recv().is_err());

        registry.unregister(&second.session);
        assert!(matches!(
            first.control.recv().await,
            Some(relay_envelope::Body::RouteHandleRelease(_))
        ));
        let replacement_endpoint: SocketAddr = "198.51.100.30:41003".parse().unwrap();
        let mut replacement = registry
            .register_credential(
                identity(3),
                Vec::new(),
                authorization("100.96.0.2/32"),
                4,
                true,
                Some(replacement_endpoint),
            )
            .unwrap();
        assert!(matches!(
            first.control.recv().await,
            Some(relay_envelope::Body::RouteHandleBinding(_))
        ));
        assert!(matches!(
            replacement.control.recv().await,
            Some(relay_envelope::Body::RouteHandleBinding(_))
        ));
        registry
            .publish_candidate(&replacement.session, &publication())
            .unwrap();
        let replacement_for_first = match first.control.recv().await.unwrap() {
            relay_envelope::Body::EndpointCandidate(candidate) => candidate,
            _ => panic!("wrong replacement control body"),
        };
        assert_eq!(
            replacement_for_first.port,
            u32::from(replacement_endpoint.port())
        );
        assert!(matches!(
            replacement.control.recv().await,
            Some(relay_envelope::Body::EndpointCandidate(_))
        ));
    }
}
