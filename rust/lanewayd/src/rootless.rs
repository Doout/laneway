//! Portable controller and relay transport for unprivileged Laneway endpoints.

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use ipnet::IpNet;
use laneway_protocol::{
    Id,
    v1::{Capability, RenewalRequest, RenewalResponse, RouteAdvertisementMode},
};
use quinn::Endpoint;
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};

pub use crate::controller_tls::controller_client_tls;

use crate::{
    authority::{Authority, Runner, SnapshotApplier},
    config::{
        Config, ControllerConfig, DiagnosticsConfig, DirectConfig, ForwardingConfig,
        IdentityConfig, RelayConfig, RouteConfig, RouteKind, TcpFallbackConfig, TlsConfig,
        TunConfig,
    },
    controller::{ClientOptions, PollResult, QuicControl, Snapshot, split_host_port},
    metrics::{Metrics, MetricsSnapshot},
    packet_pool::PacketPool,
    relay::{OutboundPacket, PacketInjection, RelayClient},
    routing::{PacketMeta, RoutingTable, packet_meta},
    state::State,
    tls,
};

/// Maximum complete IP datagram accepted from the userspace network stack.
pub const MTU: usize = 1280;

const QUEUE_DEPTH: usize = 256;
const IPV6: u64 = Capability::LanewayIpv6V1 as u64;
const SUBNET: u64 = Capability::LanewaySubnetRouterV1 as u64;

/// Enrolled endpoint identity and pinned controller and relay bootstrap material.
#[derive(Clone, Debug)]
pub struct TransportOptions {
    /// Network named in the local node certificate.
    pub network: Id,
    /// Node named in the local node certificate.
    pub node: Id,
    /// Paths to the current private TLS identity and network trust anchor.
    pub tls: TlsConfig,
    /// Pinned controller endpoint and lease polling cadence.
    pub controller: ControllerConfig,
    /// Bootstrap relay endpoint in host:port form, also naming the TLS fallback server.
    pub relay_endpoint: String,
    /// Bootstrap relay service authorized to operate the optional TCP endpoint.
    pub relay_service: Id,
    /// Optional configured TLS/TCP fallback address for the bootstrap relay.
    pub tcp_fallback: Option<SocketAddr>,
}

#[cfg(feature = "native")]
impl TransportOptions {
    /// Builds the native client configuration for an enrolled identity. The
    /// controller supplies the interface addresses, routes, and QUIC targets.
    pub fn system_config(self, state: &std::path::Path) -> Result<Config> {
        let mut config = relay_config(self)?;
        config.socket_path = crate::config::default_socket_path();
        config.exit_intent_path = state.join("exit-intent-v1.json");
        config.tun.name = "lane0".to_owned();
        config.tun.configure = true;
        Ok(config)
    }
}

/// Renews a node certificate over the authenticated controller QUIC service.
pub async fn renew_certificate(
    controller: &ControllerConfig,
    network: Id,
    tls: &TlsConfig,
    request: RenewalRequest,
) -> Result<RenewalResponse> {
    controller_client(controller, network, tls)
        .await?
        .renew(request)
        .await
}

/// Fetches a complete configuration over the pinned controller QUIC service.
pub async fn get_configuration(
    controller: &ControllerConfig,
    network: Id,
    node: Id,
    tls: &TlsConfig,
) -> Result<laneway_protocol::v1::NodeConfiguration> {
    let options = controller_options(controller, network, tls)?;
    let (client, certificate) = QuicControl::for_node(&options, node).await?;
    match client.poll(0).await? {
        PollResult::Modified(configuration) => {
            let snapshot =
                Snapshot::compile((*configuration).clone(), network, node, &certificate)?;
            ensure!(
                !snapshot.local_certificate_revoked,
                "local node certificate is revoked"
            );
            Ok(*configuration)
        }
        PollResult::NotModified { .. } => {
            anyhow::bail!("controller returned 304 without a previous configuration")
        }
    }
}

async fn controller_client(
    controller: &ControllerConfig,
    network: Id,
    tls: &TlsConfig,
) -> Result<QuicControl> {
    QuicControl::new(&controller_options(controller, network, tls)?).await
}

fn controller_options(
    controller: &ControllerConfig,
    network: Id,
    tls: &TlsConfig,
) -> Result<ClientOptions> {
    Ok(ClientOptions {
        #[cfg(feature = "native")]
        endpoint: controller.endpoint.clone(),
        quic_endpoint: controller.quic_endpoint.clone(),
        server_name: controller.server_name.clone(),
        network,
        service: controller.service_id.parse()?,
        certificate: tls.certificate.clone(),
        private_key: tls.private_key.clone(),
        ca: tls.ca.clone(),
        timeout: controller.timeout,
    })
}

/// Running outbound-only relay carrier and controller authority monitor.
pub struct Transport {
    /// Bounded packet ingress and current authority checks for the stack.
    outbound: PacketSender,
    /// Authenticated, authorized packets destined to this endpoint.
    inbound: PacketReceiver,
    tasks: TransportTasks,
}

impl Transport {
    /// Fetches and validates the first controller lease, then starts relay
    /// reconnection and policy polling. Dropping the transport aborts its tasks.
    pub async fn connect(options: TransportOptions) -> Result<Self> {
        let network = options.network;
        let node = options.node;
        tls::validate_local(&options.tls, network, node)?;
        let local_certificate = tls::local_certificate_health(&options.tls)?;
        let client = controller_client(&options.controller, network, &options.tls).await?;
        let PollResult::Modified(configuration) = client.poll(0).await? else {
            anyhow::bail!("controller returned an unchanged lease before the initial snapshot");
        };
        let snapshot = Arc::new(
            Snapshot::compile(*configuration, network, node, &local_certificate)?
                .resolve_relays()
                .await?,
        );
        let authority = Authority::new();
        let metrics = Arc::new(Metrics::default());
        let state = Arc::new(State::controller(RoutingTable::compile(&[])?, node));
        let (changes, _) = watch::channel(None);
        let applier = Arc::new(PacketApplier {
            node,
            state: Arc::clone(&state),
            changes,
            metrics: Arc::clone(&metrics),
            stopped: Mutex::new(false),
        });
        applier.apply(Arc::clone(&snapshot)).await?;
        authority.seed(snapshot)?;
        let poll_interval = options.controller.poll_interval;
        let config = Arc::new(relay_config(options)?);
        let endpoint = Endpoint::client("[::]:0".parse()?)
            .or_else(|_| Endpoint::client("0.0.0.0:0".parse().expect("constant IPv4 bind")))
            .context("bind unprivileged outbound relay UDP socket")?;
        let boot = loop {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).context("generate relay boot ID")?;
            if let Ok(id) = Id::new(random) {
                break id;
            }
        };
        let (send, to_relay) = mpsc::channel(QUEUE_DEPTH);
        let (from_relay, receive) = mpsc::channel(QUEUE_DEPTH);
        let poller = Runner::new(
            client,
            authority,
            Arc::clone(&applier),
            network,
            node,
            local_certificate,
            poll_interval,
        )?;
        let relay = RelayClient::new(
            endpoint,
            config,
            Arc::clone(&state),
            Arc::clone(&metrics),
            network,
            node,
            boot,
            PacketInjection::Rootless(from_relay),
            None,
        );
        let outbound = PacketSender {
            node,
            state: Arc::clone(&state),
            send,
            pool: Arc::new(PacketPool::prewarmed(QUEUE_DEPTH, MTU + 5)),
            changes: applier.changes.subscribe(),
            scope: None,
        };
        let inbound = PacketReceiver {
            node,
            state,
            receive,
        };
        let mut tasks = JoinSet::new();
        tasks.spawn(relay.run(to_relay));
        let task_applier = Arc::clone(&applier);
        tasks.spawn(async move {
            let result = poller.run().await;
            task_applier.fail_close().await?;
            result
        });
        Ok(Self {
            outbound,
            inbound,
            tasks: TransportTasks {
                tasks,
                metrics,
                applier,
            },
        })
    }

    /// Separates the packet endpoints from the lifetime of the managed tasks.
    pub fn split(self) -> (PacketSender, PacketReceiver, TransportTasks) {
        (self.outbound, self.inbound, self.tasks)
    }
}

/// Lifetime guard for the relay and controller tasks.
pub struct TransportTasks {
    tasks: JoinSet<Result<()>>,
    metrics: Arc<Metrics>,
    applier: Arc<PacketApplier>,
}

impl TransportTasks {
    /// Returns current carrier state and transport counters.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Waits for a managed task to stop and fails the transport closed.
    pub async fn stopped(&mut self) -> Result<()> {
        let result = self
            .tasks
            .join_next()
            .await
            .context("relay transport tasks stopped")?;
        self.tasks.abort_all();
        self.applier.stop();
        result?
    }
}

impl Drop for TransportTasks {
    fn drop(&mut self) {
        self.tasks.abort_all();
        self.applier.stop();
    }
}

/// Sending endpoint for bounded userspace IP packets.
#[derive(Clone)]
pub struct PacketSender {
    node: Id,
    state: Arc<State>,
    send: mpsc::Sender<OutboundPacket>,
    pool: Arc<PacketPool>,
    changes: watch::Receiver<Option<u64>>,
    scope: Option<Arc<()>>,
}

impl PacketSender {
    /// Pins a packet endpoint to the current generation. It stops authorizing
    /// traffic and new flows when the configuration is replaced or expires.
    pub fn scoped(&self) -> Option<Self> {
        let view = self.authority_view()?;
        Some(Self {
            scope: Some(Arc::clone(&view.generation)),
            ..self.clone()
        })
    }

    fn authority_view(&self) -> Option<Arc<PacketAuthority>> {
        self.state.rootless_authority().filter(|view| {
            self.scope
                .as_ref()
                .is_none_or(|scope| Arc::ptr_eq(scope, &view.generation))
        })
    }

    /// Enqueues only packets authorized by the current routing and ACL lease.
    pub fn try_send(&self, packet: &[u8]) -> bool {
        let Some(view) = self.authority_view() else {
            return false;
        };
        let Some(meta) = rootless_packet_meta(packet) else {
            return false;
        };
        let Some(peer) = view.outbound_peer(self.node, meta, packet, IPV6 | SUBNET) else {
            return false;
        };
        let (outbound, _) = OutboundPacket::pooled(peer, packet, &self.pool);
        self.send
            .try_send(outbound.with_generation(Arc::clone(&view.generation)))
            .is_ok()
    }

    /// Checks whether a new TCP (6) or UDP (17) flow from an assigned overlay
    /// address is allowed by the current route and destination-port ACL.
    pub fn allows_flow(&self, source: IpAddr, destination: SocketAddr, protocol: u8) -> bool {
        let Some(view) = self.authority_view() else {
            return false;
        };
        if !view
            .snapshot
            .overlays
            .iter()
            .any(|prefix| prefix.addr() == source)
            || !matches!(protocol, 6 | 17)
            || destination.port() == 0
        {
            return false;
        }
        let mut packet = [0_u8; 48];
        let transport = match (source, destination.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
                packet[9] = protocol;
                packet[12..16].copy_from_slice(&source.octets());
                packet[16..20].copy_from_slice(&destination.octets());
                20
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
                packet[6] = protocol;
                packet[8..24].copy_from_slice(&source.octets());
                packet[24..40].copy_from_slice(&destination.octets());
                40
            }
            _ => return false,
        };
        packet[transport + 2..transport + 4].copy_from_slice(&destination.port().to_be_bytes());
        let packet = &packet[..transport + 8];
        rootless_packet_meta(packet).is_some_and(|meta| {
            view.outbound_peer(self.node, meta, packet, IPV6 | SUBNET)
                .is_some()
        })
    }

    /// Checks whether an authenticated inbound packet may open a host
    /// connection to a locally assigned NAT subnet destination.
    pub fn may_open_destination(&self, destination: IpAddr) -> bool {
        self.authority_view()
            .is_some_and(|view| view.may_open_destination(destination))
    }

    /// Returns live controller-assigned overlay addresses.
    pub fn overlays(&self) -> Vec<IpNet> {
        self.authority_view()
            .map_or_else(Vec::new, |view| view.snapshot.overlays.clone())
    }

    /// Watches the active controller epoch. A missing value indicates expired
    /// or withdrawn authority. Same-epoch lease extensions preserve flows.
    pub fn authority_changes(&self) -> watch::Receiver<Option<u64>> {
        self.changes.clone()
    }
}

/// Receiving endpoint which discards stale queued packets across lease changes.
pub struct PacketReceiver {
    node: Id,
    state: Arc<State>,
    receive: mpsc::Receiver<AuthorizedPacket>,
}

impl PacketReceiver {
    /// Returns the next packet still authorized at the point of delivery.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.recv_for_scope(None).await
    }

    /// Returns the next currently authorized packet for a generation-scoped
    /// stack. While that generation is inactive, waits for the caller to
    /// cancel this receive and build its replacement.
    pub async fn recv_scoped(&mut self, sender: &PacketSender) -> Option<Bytes> {
        self.recv_for_scope(sender.scope.as_ref()).await
    }

    async fn recv_for_scope(&mut self, scope: Option<&Arc<()>>) -> Option<Bytes> {
        loop {
            if scope.is_some_and(|scope| {
                !self
                    .state
                    .rootless_authority()
                    .is_some_and(|view| Arc::ptr_eq(scope, &view.generation))
            }) {
                return std::future::pending().await;
            }
            let packet = self.receive.recv().await?;
            let Some(view) = self.state.rootless_authority() else {
                continue;
            };
            if Arc::ptr_eq(&view.generation, &packet.generation)
                && scope.is_none_or(|scope| Arc::ptr_eq(scope, &view.generation))
                && rootless_packet_meta(&packet.bytes).is_some_and(|meta| {
                    view.allows_inbound(
                        packet.peer,
                        self.node,
                        meta,
                        &packet.bytes,
                        packet.capabilities,
                    )
                })
            {
                return Some(packet.bytes);
            }
        }
    }
}

pub(crate) struct AuthorizedPacket {
    pub(crate) bytes: Bytes,
    pub(crate) generation: Arc<()>,
    pub(crate) peer: Id,
    pub(crate) capabilities: u64,
}

pub(crate) struct PacketAuthority {
    pub(crate) snapshot: Arc<Snapshot>,
    pub(crate) generation: Arc<()>,
    routes: Arc<RoutingTable>,
    served: Arc<Vec<IpNet>>,
    overlay_owners: Arc<HashMap<IpAddr, Id>>,
    source_subnets: Arc<HashMap<Id, Vec<IpNet>>>,
}

impl PacketAuthority {
    fn compile(snapshot: Arc<Snapshot>, node: Id) -> Result<Self> {
        ensure!(!snapshot.expired(), "controller authorization has expired");
        ensure!(
            !snapshot.local_certificate_revoked,
            "local node certificate is revoked"
        );
        ensure!(
            snapshot
                .relays
                .values()
                .any(|relay| !relay.resolved.is_empty()),
            "controller has no resolved relay targets"
        );
        let mut served = Vec::new();
        let mut source_subnets = HashMap::<Id, Vec<IpNet>>::new();
        let overlay_owners = snapshot
            .peers
            .values()
            .flat_map(|peer| {
                peer.overlays
                    .iter()
                    .copied()
                    .map(move |address| (address, peer.node))
            })
            .collect();
        let routes = snapshot
            .routes
            .iter()
            .filter_map(|route| {
                let kind = match route.kind {
                    laneway_protocol::v1::RouteKind::Overlay => RouteKind::Overlay,
                    laneway_protocol::v1::RouteKind::Subnet => {
                        if route.via == node
                            && route.mode == RouteAdvertisementMode::Nat
                            && route.destination.prefix_len() > 0
                            && snapshot.enabled_capabilities & SUBNET != 0
                        {
                            served.push(route.destination);
                        }
                        source_subnets
                            .entry(route.via)
                            .or_default()
                            .push(route.destination);
                        RouteKind::Subnet
                    }
                    _ => return None,
                };
                Some(RouteConfig {
                    prefix: route.destination,
                    via_node: route.via.to_string(),
                    metric: route.metric,
                    kind,
                })
            })
            .collect::<Vec<_>>();
        Ok(Self {
            snapshot,
            generation: Arc::new(()),
            routes: Arc::new(RoutingTable::compile(&routes)?),
            served: Arc::new(served),
            overlay_owners: Arc::new(overlay_owners),
            source_subnets: Arc::new(source_subnets),
        })
    }

    fn may_open_destination(&self, address: IpAddr) -> bool {
        !self.overlay_owners.contains_key(&address)
            && self.served.iter().any(|prefix| prefix.contains(&address))
    }

    fn owns(&self, node: Id, address: IpAddr, capabilities: u64) -> bool {
        self.overlay_owners.get(&address) == Some(&node)
            || (capabilities & SUBNET != 0 && self.may_open_destination(address))
    }

    fn peer_owns_source(&self, peer: Id, address: IpAddr, capabilities: u64) -> bool {
        if let Some(owner) = self.overlay_owners.get(&address) {
            return *owner == peer;
        }
        capabilities & SUBNET != 0
            && self
                .source_subnets
                .get(&peer)
                .is_some_and(|prefixes| prefixes.iter().any(|prefix| prefix.contains(&address)))
    }

    pub(crate) fn outbound_peer(
        &self,
        node: Id,
        meta: PacketMeta,
        packet: &[u8],
        capabilities: u64,
    ) -> Option<Id> {
        if (meta.source.is_ipv6() && capabilities & IPV6 == 0)
            || !self.owns(node, meta.source, capabilities)
        {
            return None;
        }
        self.routes.routes().iter().find_map(|route| {
            (route.via != node
                && route.prefix.contains(&meta.destination)
                && (route.kind != RouteKind::Subnet || capabilities & SUBNET != 0)
                && self.snapshot.policy.allows(node, route.via, packet))
            .then_some(route.via)
        })
    }

    pub(crate) fn allows_inbound(
        &self,
        peer: Id,
        node: Id,
        meta: PacketMeta,
        packet: &[u8],
        capabilities: u64,
    ) -> bool {
        (meta.source.is_ipv4() || capabilities & IPV6 != 0)
            && self.owns(node, meta.destination, capabilities)
            && self.peer_owns_source(peer, meta.source, capabilities)
            && self.snapshot.policy.allows(peer, node, packet)
    }
}

pub(crate) fn rootless_packet_meta(packet: &[u8]) -> Option<PacketMeta> {
    if packet.len() > MTU {
        return None;
    }
    let meta = packet_meta(packet).ok()?;
    if meta.source.is_ipv4() {
        // Reject fragments before evaluating port selectors.
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        (fragment & 0x3fff == 0 && matches!(packet[9], 6 | 17)).then_some(meta)
    } else {
        // Extension headers cannot be classified by the stable-v1 ACL parser.
        (matches!(packet[6], 6 | 17)
            && !matches!(meta.source, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
            && !matches!(meta.destination, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()))
        .then_some(meta)
    }
}

struct PacketApplier {
    node: Id,
    state: Arc<State>,
    changes: watch::Sender<Option<u64>>,
    metrics: Arc<Metrics>,
    stopped: Mutex<bool>,
}

impl PacketApplier {
    fn stop(&self) {
        let mut stopped = self.stopped.lock().unwrap_or_else(|err| err.into_inner());
        *stopped = true;
        self.fail_close_now();
    }

    fn activate(&self, view: Arc<PacketAuthority>, notify: bool) -> Result<()> {
        let stopped = self.stopped.lock().unwrap_or_else(|err| err.into_inner());
        ensure!(!*stopped, "relay transport was stopped");
        ensure!(
            !view.snapshot.expired(),
            "controller authorization has expired"
        );
        let epoch = view.snapshot.epoch;
        self.metrics
            .controller_certificate_renew_after_seconds
            .store(
                view.snapshot.certificate_renew_after,
                std::sync::atomic::Ordering::Relaxed,
            );
        self.metrics.controller_certificate_not_after_seconds.store(
            view.snapshot.certificate_not_after,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.state.publish_rootless(view);
        if notify {
            self.changes.send_replace(Some(epoch));
        }
        Ok(())
    }

    fn fail_close_now(&self) {
        self.state.fail_close();
        self.changes
            .send_if_modified(|epoch| epoch.take().is_some());
    }
}

impl SnapshotApplier for PacketApplier {
    fn apply<'a>(
        &'a self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let view = match PacketAuthority::compile(snapshot, self.node) {
                Ok(view) => view,
                Err(error) => {
                    self.fail_close().await?;
                    return Err(error);
                }
            };
            self.activate(Arc::new(view), true)
        })
    }

    fn fail_close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async {
            self.fail_close_now();
            Ok(())
        })
    }

    fn renew<'a>(
        &'a self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let Some(previous) = self.state.rootless_authority() else {
                return self.apply(snapshot).await;
            };
            self.activate(
                Arc::new(PacketAuthority {
                    snapshot,
                    generation: Arc::clone(&previous.generation),
                    routes: Arc::clone(&previous.routes),
                    served: Arc::clone(&previous.served),
                    overlay_owners: Arc::clone(&previous.overlay_owners),
                    source_subnets: Arc::clone(&previous.source_subnets),
                }),
                false,
            )
        })
    }
}

fn relay_config(options: TransportOptions) -> Result<Config> {
    let (server_name, _) = split_host_port(&options.relay_endpoint)?;
    let handshake_timeout = Duration::from_secs(3);
    let idle_timeout = Duration::from_secs(45);
    let keepalive = Duration::from_secs(15);
    Ok(Config {
        mode: "node".to_owned(),
        socket_path: Default::default(),
        exit_intent_path: Default::default(),
        identity: IdentityConfig {
            name: None,
            product_version: None,
            network_id: options.network.to_string(),
            node_id: options.node.to_string(),
        },
        tls: options.tls,
        controller: Some(options.controller),
        tun: TunConfig {
            name: String::new(),
            mtu: MTU as u16,
            addresses: Vec::new(),
            configure: false,
        },
        relay: RelayConfig {
            address: None,
            display_address: None,
            server_name,
            service_id: options.relay_service.to_string(),
            queue_depth: QUEUE_DEPTH,
            max_routes: 4096,
            handshake_timeout,
            idle_timeout,
            keepalive,
            reconnect_min: Duration::from_millis(250),
            reconnect_max: Duration::from_secs(15),
            quic_recovery_interval: Duration::from_secs(5),
        },
        tcp_fallback: options.tcp_fallback.map(|address| TcpFallbackConfig {
            address,
            handshake_timeout,
            write_timeout: Duration::from_secs(3),
            idle_timeout,
            keepalive_period: keepalive,
            queue_depth: QUEUE_DEPTH,
        }),
        direct: DirectConfig::default(),
        routes: Vec::new(),
        direct_peers: Vec::new(),
        forwarding: ForwardingConfig::default(),
        diagnostics: DiagnosticsConfig::default(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use laneway_protocol::{
        policy::CompiledPolicy,
        v1::{IpProtocol, PolicyAction, PolicyRule, PolicySnapshot, PortRange, TrafficSelector},
    };

    use super::*;
    use crate::controller::{CandidateExchangeAuthority, Peer, RelayAuthority, Route};

    fn id(value: u8) -> Id {
        Id::new([value; 16]).unwrap()
    }

    fn snapshot() -> Snapshot {
        let network = id(1);
        let node = id(2);
        let allowed = id(3);
        let more_specific = id(4);
        let make_peer = |node, address: &str| {
            (
                node,
                Peer {
                    node,
                    name: node.to_string(),
                    overlays: vec![address.parse().unwrap()],
                },
            )
        };
        let route = |route_id, prefix: &str, via, kind, mode| Route {
            id: id(route_id),
            destination: prefix.parse().unwrap(),
            via,
            kind,
            mode,
            metric: 100,
        };
        let overlay = |route_id, prefix, via| {
            route(
                route_id,
                prefix,
                via,
                laneway_protocol::v1::RouteKind::Overlay,
                RouteAdvertisementMode::Unspecified,
            )
        };
        let subnet = |route_id, prefix, via, mode| {
            route(
                route_id,
                prefix,
                via,
                laneway_protocol::v1::RouteKind::Subnet,
                mode,
            )
        };
        let allow = |rule, source: Id, destination: Id, port: u32| PolicyRule {
            rule_id: id(rule).as_bytes().to_vec(),
            priority: 1,
            action: PolicyAction::Accept as i32,
            selector: Some(TrafficSelector {
                source_node_ids: vec![source.as_bytes().to_vec()],
                destination_node_ids: vec![destination.as_bytes().to_vec()],
                ip_protocol: IpProtocol::Udp as i32,
                destination_ports: vec![PortRange {
                    first: port,
                    last: port,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let policy = CompiledPolicy::compile(
            PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: 1,
                default_action: PolicyAction::Deny as i32,
                rules: vec![
                    allow(11, node, allowed, 443),
                    allow(12, allowed, node, 40000),
                ],
            },
            network,
            1,
        )
        .unwrap();
        Snapshot {
            epoch: 1,
            valid_until: u64::MAX,
            identity_lease_expires_at: 0,
            overlays: vec!["100.96.0.1/32".parse().unwrap()],
            peers: HashMap::from([
                make_peer(node, "100.96.0.1"),
                make_peer(allowed, "100.96.0.2"),
                make_peer(more_specific, "100.96.0.3"),
            ]),
            routes: vec![
                overlay(5, "100.96.0.1/32", node),
                overlay(6, "100.96.0.2/32", allowed),
                overlay(7, "100.96.0.3/32", more_specific),
                subnet(8, "10.0.0.0/8", allowed, RouteAdvertisementMode::Nat),
                subnet(9, "10.1.0.0/16", more_specific, RouteAdvertisementMode::Nat),
                subnet(10, "192.168.0.0/16", node, RouteAdvertisementMode::Nat),
                subnet(13, "172.16.0.0/12", node, RouteAdvertisementMode::Routed),
            ],
            policy,
            enabled_capabilities: SUBNET,
            revoked_serials: HashSet::new(),
            local_certificate_revoked: false,
            relays: HashMap::from([(
                id(11),
                RelayAuthority {
                    endpoint: "127.0.0.1:4433".into(),
                    resolved: vec!["127.0.0.1:4433".parse().unwrap()],
                },
            )]),
            candidate_exchange: CandidateExchangeAuthority {
                enabled: false,
                #[cfg(feature = "native")]
                max_candidates: 0,
                #[cfg(feature = "native")]
                ttl: Duration::ZERO,
            },
            #[cfg(feature = "native")]
            authorized_exits: HashSet::new(),
            certificate_renew_after: u64::MAX - 1,
            certificate_not_after: u64::MAX,
        }
    }

    fn udp(source: [u8; 4], destination: [u8; 4], port: u16) -> [u8; 28] {
        let mut bytes = [0_u8; 28];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&28_u16.to_be_bytes());
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&source);
        bytes[16..20].copy_from_slice(&destination);
        bytes[22..24].copy_from_slice(&port.to_be_bytes());
        bytes[24..26].copy_from_slice(&8_u16.to_be_bytes());
        bytes
    }

    #[test]
    fn route_selection_and_source_ownership_are_independent() {
        let node = id(2);
        let authorized_peer = id(3);
        let denied_peer = id(4);
        let authority = PacketAuthority::compile(Arc::new(snapshot()), node).unwrap();
        let request = udp([100, 96, 0, 1], [10, 1, 1, 1], 443);
        let meta = rootless_packet_meta(&request).unwrap();
        assert_eq!(
            authority.outbound_peer(node, meta, &request, SUBNET),
            Some(authorized_peer)
        );
        assert_eq!(authority.outbound_peer(node, meta, &request, 0), None);
        let denied = udp([100, 96, 0, 1], [10, 1, 1, 1], 80);
        assert_eq!(authority.outbound_peer(node, meta, &denied, SUBNET), None);

        let reply = udp([10, 1, 1, 1], [100, 96, 0, 1], 40000);
        let meta = rootless_packet_meta(&reply).unwrap();
        assert!(authority.allows_inbound(authorized_peer, node, meta, &reply, SUBNET));
        assert!(!authority.allows_inbound(denied_peer, node, meta, &reply, SUBNET));
        assert!(!authority.allows_inbound(authorized_peer, node, meta, &reply, 0));
        let spoof = udp([100, 96, 0, 3], [100, 96, 0, 1], 40000);
        assert!(!authority.allows_inbound(
            authorized_peer,
            node,
            rootless_packet_meta(&spoof).unwrap(),
            &spoof,
            SUBNET
        ));

        assert!(authority.may_open_destination("192.168.1.1".parse().unwrap()));
        assert!(!authority.may_open_destination("172.16.1.1".parse().unwrap()));
        assert!(!authority.may_open_destination("100.96.0.1".parse().unwrap()));
        assert!(!authority.may_open_destination("1.1.1.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn expired_or_replaced_generation_retires_scoped_flows_and_queued_input() {
        let node = id(2);
        let state = Arc::new(State::controller(RoutingTable::compile(&[]).unwrap(), node));
        let (changes, watch) = watch::channel(None);
        let (send, _) = mpsc::channel(4);
        let (incoming, receive) = mpsc::channel(4);
        let applier = PacketApplier {
            node,
            state: Arc::clone(&state),
            changes,
            metrics: Arc::new(Metrics::default()),
            stopped: Mutex::new(false),
        };
        let sender = PacketSender {
            node,
            state: Arc::clone(&state),
            send,
            pool: Arc::new(PacketPool::prewarmed(4, MTU)),
            changes: watch,
            scope: None,
        };
        let mut receiver = PacketReceiver {
            node,
            state: Arc::clone(&state),
            receive,
        };
        let original = Arc::new(snapshot());
        applier.apply(Arc::clone(&original)).await.unwrap();
        let scoped = sender.scoped().unwrap();
        let source = "100.96.0.1".parse().unwrap();
        let destination = "10.1.1.1:443".parse().unwrap();
        assert!(scoped.allows_flow(source, destination, 17));
        assert!(!scoped.allows_flow(source, destination, 6));
        let old_generation = Arc::clone(&state.rootless_authority().unwrap().generation);
        applier.renew(Arc::clone(&original)).await.unwrap();
        assert!(scoped.allows_flow(source, destination, 17));
        applier.fail_close().await.unwrap();
        assert!(!scoped.allows_flow(source, destination, 17));
        applier.apply(original).await.unwrap();
        assert!(!scoped.allows_flow(source, destination, 17));
        assert!(
            sender
                .scoped()
                .unwrap()
                .allows_flow(source, destination, 17)
        );

        let packet = udp([10, 1, 1, 1], [100, 96, 0, 1], 40000);
        incoming
            .send(AuthorizedPacket {
                bytes: Bytes::copy_from_slice(&packet),
                generation: old_generation,
                peer: id(3),
                capabilities: SUBNET,
            })
            .await
            .unwrap();
        incoming
            .send(AuthorizedPacket {
                bytes: Bytes::copy_from_slice(&packet),
                generation: Arc::clone(&state.rootless_authority().unwrap().generation),
                peer: id(3),
                capabilities: SUBNET,
            })
            .await
            .unwrap();
        drop(incoming);
        assert_eq!(receiver.recv().await.unwrap().as_ref(), &packet);
        assert!(receiver.recv().await.is_none());
    }
}
