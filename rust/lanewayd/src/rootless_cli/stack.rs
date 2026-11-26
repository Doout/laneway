//! Userspace TCP and UDP over the relay's IP packets.
use std::collections::{HashMap, HashSet, hash_map::RandomState};
use std::future::{Future, pending};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as NetworkDuration, Instant as NetworkTime};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket,
    TcpRepr, UdpPacket,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};

const MTU: usize = 1280;
const TCP_BUFFER: usize = 16 * 1024;
const MAX_TCP: usize = 256;
const MAX_TCP_ADMISSIONS: usize = 32;
pub(crate) const MAX_UDP: usize = 256;
const UDP_QUEUE: usize = 16;
const TCP_HANDSHAKE: Duration = Duration::from_secs(15);
const TCP_IDLE: NetworkDuration = NetworkDuration::from_secs(300);
const UDP_IDLE: Duration = Duration::from_secs(60);
const EPHEMERAL_BASE: u16 = 49152;
const EPHEMERAL_COUNT: usize = 16384;

#[derive(Clone)]
pub struct Stack {
    commands: mpsc::Sender<Command>,
    local4: Option<IpAddr>,
    local6: Option<IpAddr>,
}

pub enum Inbound {
    Tcp {
        source: SocketAddr,
        destination: SocketAddr,
        accept: TcpAccept,
    },
    Udp {
        source: SocketAddr,
        destination: SocketAddr,
        flow: UdpFlow,
    },
}

type TcpReady = oneshot::Sender<io::Result<(DuplexStream, SocketAddr)>>;

/// Authorizes the pending TCP handshake after the destination connection opens.
/// Dropping the handle refuses the handshake.
pub struct TcpAccept(oneshot::Sender<TcpReady>);

impl TcpAccept {
    pub async fn accept(self) -> io::Result<DuplexStream> {
        let (tx, rx) = oneshot::channel();
        self.0.send(tx).map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?.map(|(stream, _)| stream)
    }
}

pub struct UdpFlow {
    sender: UdpSender,
    inbound: mpsc::Receiver<Vec<u8>>,
}

#[derive(Clone)]
pub struct UdpSender {
    destination: SocketAddr,
    outbound: mpsc::Sender<Vec<u8>>,
}

pub fn udp_max_payload(destination: SocketAddr) -> usize {
    if destination.is_ipv4() {
        MTU - 28
    } else {
        MTU - 48
    }
}

impl UdpSender {
    pub fn max_payload(&self) -> usize {
        udp_max_payload(self.destination)
    }

    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > self.max_payload() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram exceeds overlay MTU",
            ));
        }
        self.outbound
            .send(payload.to_vec())
            .await
            .map_err(|_| closed())
    }
}

impl UdpFlow {
    pub fn sender(&self) -> UdpSender {
        self.sender.clone()
    }

    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.sender.send(payload).await
    }

    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.inbound.recv().await.ok_or_else(closed)
    }
}

enum Command {
    Ingress { packet: Vec<u8>, allow_new: bool },
    Tcp(SocketAddr, TcpReady),
    Udp(SocketAddr, oneshot::Sender<io::Result<UdpFlow>>),
    Shutdown(oneshot::Sender<()>),
}

impl Stack {
    /// `local_ips` supplies the assigned overlay source address for each family.
    /// The caller must authorize incoming traffic before passing it to the stack.
    pub fn spawn(
        local_ips: Vec<IpAddr>,
        packets_out: mpsc::Sender<Vec<u8>>,
    ) -> (Self, mpsc::Receiver<Inbound>) {
        let (commands, receiver) = mpsc::channel(256);
        let (accepted, inbound) = mpsc::channel(64);
        let mut unicast = local_ips
            .iter()
            .copied()
            .filter(|ip| IpAddress::from(*ip).is_unicast());
        let local4 = unicast.clone().find(IpAddr::is_ipv4);
        let local6 = unicast.find(IpAddr::is_ipv6);
        let engine = Engine::new(local4, local6, packets_out, accepted);
        tokio::spawn(engine.run(receiver));
        (
            Self {
                commands,
                local4,
                local6,
            },
            inbound,
        )
    }

    pub fn source_ip(&self, destination: IpAddr) -> Option<IpAddr> {
        if destination.is_ipv4() {
            self.local4
        } else {
            self.local6
        }
    }

    pub async fn shutdown(&self) {
        let (done, shutdown) = oneshot::channel();
        let _ = self.commands.send(Command::Shutdown(done)).await;
        let _ = shutdown.await;
    }

    /// Allows an authorized packet to open a new inbound flow.
    pub async fn ingress(&self, packet: Vec<u8>) -> io::Result<()> {
        self.receive_packet(packet, true).await
    }

    /// Accepts packets matching an existing flow, without opening an inbound flow.
    pub async fn ingress_reply(&self, packet: Vec<u8>) -> io::Result<()> {
        self.receive_packet(packet, false).await
    }

    async fn receive_packet(&self, packet: Vec<u8>, allow_new: bool) -> io::Result<()> {
        if packet.len() > MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IP packet exceeds MTU",
            ));
        }
        self.commands
            .send(Command::Ingress { packet, allow_new })
            .await
            .map_err(|_| closed())
    }

    #[cfg(test)]
    pub async fn connect_tcp(&self, dst: SocketAddr) -> io::Result<DuplexStream> {
        self.connect_tcp_with_local(dst)
            .await
            .map(|(stream, _)| stream)
    }

    pub async fn connect_tcp_with_local(
        &self,
        dst: SocketAddr,
    ) -> io::Result<(DuplexStream, SocketAddr)> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Tcp(dst, tx))
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    pub async fn bind_udp(&self, dst: SocketAddr) -> io::Result<UdpFlow> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Udp(dst, tx))
            .await
            .map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "overlay flow closed")
}

fn capacity_error() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "overlay flow capacity exhausted")
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    local: SocketAddr,
    remote: SocketAddr,
}

struct TcpAdmission {
    packet: Vec<u8>,
    decision: oneshot::Receiver<TcpReady>,
    deadline: Instant,
}

struct TcpFlow {
    handle: SocketHandle,
    state: TcpBridge,
}

enum TcpBridge {
    Connecting {
        started: Instant,
        response: Option<TcpReady>,
    },
    Open {
        stream: DuplexStream,
        app_eof: bool,
        peer_eof: bool,
    },
}

struct UdpBridge {
    outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
    last_activity: Instant,
}

struct Engine {
    local4: Option<IpAddr>,
    local6: Option<IpAddr>,
    device: PacketDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: HashMap<FlowKey, TcpFlow>,
    tcp_admissions: HashMap<FlowKey, TcpAdmission>,
    udp: HashMap<FlowKey, UdpBridge>,
    udp_sockets: HashMap<SocketAddr, SocketHandle>,
    active_udp_locals: HashSet<SocketAddr>,
    accepted: mpsc::Sender<Inbound>,
    start: Instant,
    next_port: u16,
}

impl Engine {
    fn new(
        local4: Option<IpAddr>,
        local6: Option<IpAddr>,
        outgoing: mpsc::Sender<Vec<u8>>,
        accepted: mpsc::Sender<Inbound>,
    ) -> Self {
        let seed = RandomState::new().build_hasher().finish();
        let mut device = PacketDevice {
            incoming: None,
            outgoing,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = seed;
        let mut iface = Interface::new(config, &mut device, NetworkTime::ZERO);
        iface.update_ip_addrs(|addresses| {
            for ip in [local4, local6].into_iter().flatten() {
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                addresses
                    .push(IpCidr::new(IpAddress::from(ip), prefix))
                    .expect("two interface addresses fit in smoltcp");
            }
        });
        iface.set_any_ip(true);
        if let Some(IpAddr::V4(ip)) = local4 {
            iface
                .routes_mut()
                .add_default_ipv4_route(ip)
                .expect("default IPv4 route fits");
        }
        if let Some(IpAddr::V6(ip)) = local6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(ip)
                .expect("default IPv6 route fits");
        }

        Self {
            local4,
            local6,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            tcp: HashMap::new(),
            tcp_admissions: HashMap::new(),
            udp: HashMap::new(),
            udp_sockets: HashMap::new(),
            active_udp_locals: HashSet::new(),
            accepted,
            start: Instant::now(),
            next_port: EPHEMERAL_BASE + (seed as u16 % EPHEMERAL_COUNT as u16),
        }
    }

    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        let wake = Arc::new(EngineWake(Notify::new()));
        let waker = Waker::from(wake.clone());
        let outgoing = self.device.outgoing.clone();
        loop {
            self.service(&waker);
            let blocked = outgoing.capacity() == 0;
            let deadline = self.deadline(blocked);
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::Ingress { packet, allow_new }) => self.receive(packet, allow_new),
                    Some(Command::Tcp(dst, response)) => self.open_tcp(dst, response),
                    Some(Command::Udp(dst, response)) => {
                        if !response.is_closed() {
                            let result = self.allocate(dst, true).and_then(|key| self.add_udp(key));
                            let _ = response.send(result);
                        }
                    }
                    Some(Command::Shutdown(done)) => {
                        drop(commands);
                        drop(self);
                        let _ = done.send(());
                        return;
                    }
                    None => break,
                },
                _ = wake.0.notified() => {},
                _ = wait_deadline(deadline) => {},
                _ = outgoing.reserve(), if blocked => {},
                _ = outgoing.closed() => break,
            }
        }
    }

    fn deadline(&mut self, blocked: bool) -> Option<Instant> {
        let time = self.now();
        let network = if blocked {
            None
        } else {
            self.iface
                .poll_at(time, &self.sockets)
                .map(|time| self.start + Duration::from_millis(time.total_millis().max(0) as u64))
        };
        let admissions = self.tcp_admissions.values().map(|flow| flow.deadline);
        let handshakes = self.tcp.values().filter_map(|flow| match flow.state {
            TcpBridge::Connecting { started, .. } => Some(started + TCP_HANDSHAKE),
            TcpBridge::Open { .. } => None,
        });
        let datagrams = self.udp.values().map(|flow| flow.last_activity + UDP_IDLE);
        network
            .into_iter()
            .chain(admissions)
            .chain(handshakes)
            .chain(datagrams)
            .min()
    }

    fn now(&self) -> NetworkTime {
        NetworkTime::from_millis(self.start.elapsed().as_millis() as i64)
    }

    fn allocate(&mut self, remote: SocketAddr, udp: bool) -> io::Result<FlowKey> {
        if remote.port() == 0 || !IpAddress::from(remote.ip()).is_unicast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid overlay endpoint",
            ));
        }
        let local_ip = if remote.is_ipv4() {
            self.local4
        } else {
            self.local6
        };
        let local_ip = local_ip.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no overlay address for this IP family",
            )
        })?;
        for _ in 0..EPHEMERAL_COUNT {
            let port = self.next_port;
            self.next_port = self.next_port.checked_add(1).unwrap_or(EPHEMERAL_BASE);
            let local = SocketAddr::new(local_ip, port);
            let key = FlowKey { local, remote };
            let in_use = if udp {
                self.udp_sockets.contains_key(&local)
            } else {
                self.tcp
                    .keys()
                    .chain(self.tcp_admissions.keys())
                    .any(|flow| flow.local == local)
            };
            if !in_use {
                return Ok(key);
            }
        }
        Err(capacity_error())
    }

    fn open_tcp(&mut self, dst: SocketAddr, response: TcpReady) {
        if response.is_closed() {
            return;
        }
        if self.tcp.len() + self.tcp_admissions.len() >= MAX_TCP {
            let _ = response.send(Err(capacity_error()));
            return;
        }
        let mut socket = tcp_socket();
        let key = match self.allocate(dst, false).and_then(|key| {
            socket
                .connect(
                    self.iface.context(),
                    IpEndpoint::from(key.remote),
                    key.local,
                )
                .map_err(io::Error::other)?;
            Ok(key)
        }) {
            Ok(key) => key,
            Err(err) => {
                let _ = response.send(Err(err));
                return;
            }
        };
        self.tcp.insert(
            key,
            TcpFlow {
                handle: self.sockets.add(socket),
                state: TcpBridge::Connecting {
                    started: Instant::now(),
                    response: Some(response),
                },
            },
        );
    }

    fn udp_socket(&mut self, local: SocketAddr) -> io::Result<SocketHandle> {
        if let Some(&handle) = self.udp_sockets.get(&local) {
            return Ok(handle);
        }
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_QUEUE],
                vec![0; MTU * UDP_QUEUE],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(local).map_err(io::Error::other)?;
        let handle = self.sockets.add(socket);
        self.udp_sockets.insert(local, handle);
        Ok(handle)
    }

    fn add_udp(&mut self, key: FlowKey) -> io::Result<UdpFlow> {
        if self.udp.len() >= MAX_UDP {
            return Err(capacity_error());
        }
        self.udp_socket(key.local)?;
        let (outbound, sends) = mpsc::channel(UDP_QUEUE);
        let (receives, inbound) = mpsc::channel(UDP_QUEUE);
        self.udp.insert(
            key,
            UdpBridge {
                outbound: sends,
                inbound: receives,
                last_activity: Instant::now(),
            },
        );
        Ok(UdpFlow {
            sender: UdpSender {
                destination: key.remote,
                outbound,
            },
            inbound,
        })
    }

    fn receive(&mut self, packet: Vec<u8>, allow_new: bool) {
        let Some((key, protocol)) = flow_headers(&packet) else {
            return;
        };
        match protocol {
            PacketProtocol::Tcp { syn } => {
                if !self.tcp.contains_key(&key) {
                    if allow_new && syn && !self.tcp_admissions.contains_key(&key) {
                        self.request_tcp(key, packet);
                    }
                    return;
                }
            }
            PacketProtocol::Udp => {
                if !self.udp.contains_key(&key)
                    && (!allow_new
                        || self.udp.len() >= MAX_UDP
                        || self.udp_socket(key.local).is_err())
                {
                    return;
                }
            }
        }
        self.deliver_packet(key.local.ip(), packet);
        if matches!(protocol, PacketProtocol::Udp) {
            let handle = self.udp_sockets[&key.local];
            if let Ok((payload, _)) = self.sockets.get_mut::<udp::Socket>(handle).recv() {
                let payload = payload.to_vec();
                if !self.udp.contains_key(&key) {
                    let Ok(flow) = self.add_udp(key) else { return };
                    if self
                        .accepted
                        .try_send(Inbound::Udp {
                            source: key.remote,
                            destination: key.local,
                            flow,
                        })
                        .is_err()
                    {
                        self.udp.remove(&key);
                        return;
                    }
                }
                let bridge = self.udp.get_mut(&key).expect("UDP flow installed");
                let _ = bridge.inbound.try_send(payload);
                bridge.last_activity = Instant::now();
            }
        }
    }

    fn deliver_packet(&mut self, destination: IpAddr, packet: Vec<u8>) {
        // Subnet forwarding has an explicit source on egress and can serve a
        // family for which this connector has no overlay source address.
        let temporary = if destination.is_ipv4() {
            self.local4.is_none()
        } else {
            self.local6.is_none()
        };
        if temporary {
            let prefix = if destination.is_ipv4() { 32 } else { 128 };
            self.iface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new(destination.into(), prefix))
                    .expect("temporary address fits the unassigned family");
            });
        }
        self.device.incoming = Some(packet);
        self.iface
            .poll_ingress_single(self.now(), &mut self.device, &mut self.sockets);
        if temporary {
            self.iface.update_ip_addrs(|addresses| {
                addresses.pop();
            });
        }
    }

    fn request_tcp(&mut self, key: FlowKey, packet: Vec<u8>) {
        if self.tcp.len() + self.tcp_admissions.len() >= MAX_TCP
            || self.tcp_admissions.len() >= MAX_TCP_ADMISSIONS
        {
            self.deliver_packet(key.local.ip(), packet);
            return;
        }
        let (decision, reply) = oneshot::channel();
        let inbound = Inbound::Tcp {
            source: key.remote,
            destination: key.local,
            accept: TcpAccept(decision),
        };
        if self.accepted.try_send(inbound).is_err() {
            self.deliver_packet(key.local.ip(), packet);
            return;
        }
        self.tcp_admissions.insert(
            key,
            TcpAdmission {
                packet,
                decision: reply,
                deadline: Instant::now() + TCP_HANDSHAKE,
            },
        );
    }

    fn service_admissions(&mut self, now: Instant, cx: &mut Context<'_>) {
        let mut completed = Vec::new();
        self.tcp_admissions.retain(|key, request| {
            let decision = Pin::new(&mut request.decision).poll(cx);
            match decision {
                Poll::Pending if now < request.deadline => true,
                Poll::Ready(Ok(response)) if now < request.deadline => {
                    completed.push((*key, std::mem::take(&mut request.packet), Some(response)));
                    false
                }
                _ => {
                    completed.push((*key, std::mem::take(&mut request.packet), None));
                    false
                }
            }
        });
        for (key, packet, response) in completed {
            if let Some(response) = response.filter(|response| !response.is_closed()) {
                let mut socket = tcp_socket();
                if let Err(err) = socket.listen(key.local) {
                    let _ = response.send(Err(io::Error::other(err)));
                } else {
                    self.tcp.insert(
                        key,
                        TcpFlow {
                            handle: self.sockets.add(socket),
                            state: TcpBridge::Connecting {
                                started: now,
                                response: Some(response),
                            },
                        },
                    );
                }
            }
            self.deliver_packet(key.local.ip(), packet);
        }
    }

    fn service(&mut self, waker: &Waker) {
        let now = Instant::now();
        let time = self.now();
        let mut cx = Context::from_waker(waker);
        self.service_admissions(now, &mut cx);
        self.tcp.retain(|key, flow| {
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            let keep = service_tcp(socket, flow, *key, now, &mut cx);
            if !keep {
                self.sockets.remove(flow.handle);
            }
            keep
        });
        self.active_udp_locals.clear();
        self.udp.retain(|key, flow| {
            if flow.inbound.is_closed() || now.duration_since(flow.last_activity) >= UDP_IDLE {
                return false;
            }
            let handle = self.udp_sockets[&key.local];
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            while socket.can_send() {
                let Poll::Ready(Some(datagram)) = flow.outbound.poll_recv(&mut cx) else {
                    break;
                };
                if socket
                    .send_slice(&datagram, IpEndpoint::from(key.remote))
                    .is_ok()
                {
                    flow.last_activity = now;
                }
            }
            self.active_udp_locals.insert(key.local);
            true
        });
        self.iface
            .poll_egress(time, &mut self.device, &mut self.sockets);
        // Dispatch may retire a timed-out or aborted socket without scheduling
        // another smoltcp poll. Drop its bridge and free the flow slot now.
        self.tcp.retain(|_, flow| {
            let socket = self.sockets.get::<tcp::Socket>(flow.handle);
            if socket.remote_endpoint().is_some() {
                return true;
            }
            self.sockets.remove(flow.handle);
            false
        });
        self.udp_sockets.retain(|local, handle| {
            if self.active_udp_locals.contains(local) {
                return true;
            }
            self.sockets.remove(*handle);
            false
        });
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let buffer = || tcp::SocketBuffer::new(vec![0; TCP_BUFFER]);
    let mut socket = tcp::Socket::new(buffer(), buffer());
    socket.set_timeout(Some(TCP_IDLE));
    socket.set_keep_alive(Some(NetworkDuration::from_secs(30)));
    socket
}

fn service_tcp(
    socket: &mut tcp::Socket<'_>,
    flow: &mut TcpFlow,
    key: FlowKey,
    now: Instant,
    cx: &mut Context<'_>,
) -> bool {
    if let TcpBridge::Connecting { started, response } = &mut flow.state {
        let failure = match socket.state() {
            tcp::State::Closed | tcp::State::Listen => Some(io::ErrorKind::ConnectionRefused),
            _ if now.duration_since(*started) >= TCP_HANDSHAKE => Some(io::ErrorKind::TimedOut),
            _ => None,
        };
        if let Some(kind) = failure {
            if let Some(response) = response.take() {
                let _ = response.send(Err(io::Error::new(kind, "overlay TCP handshake failed")));
            }
            socket.abort();
            return socket.remote_endpoint().is_some();
        }
        if response
            .as_mut()
            .is_none_or(|response| response.poll_closed(cx).is_ready())
        {
            socket.abort();
            return true;
        }
        if !matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        ) {
            return true;
        }
        let (app, stream) = tokio::io::duplex(TCP_BUFFER);
        let delivered = response
            .take()
            .is_some_and(|response| response.send(Ok((app, key.local))).is_ok());
        if !delivered {
            socket.abort();
            return true;
        }
        flow.state = TcpBridge::Open {
            stream,
            app_eof: false,
            peer_eof: false,
        };
    }

    let TcpBridge::Open {
        stream,
        app_eof,
        peer_eof,
    } = &mut flow.state
    else {
        unreachable!("established TCP flow has its application stream");
    };
    while socket.can_recv() {
        let written = socket.recv(|bytes| match Pin::new(&mut *stream).poll_write(cx, bytes) {
            Poll::Ready(Ok(written)) => (written, written),
            Poll::Pending => (0, 0),
            Poll::Ready(Err(_)) => {
                *peer_eof = true;
                (0, 0)
            }
        });
        if *peer_eof {
            socket.abort();
            return true;
        }
        if written.unwrap_or(0) == 0 {
            break;
        }
    }
    if !socket.may_recv() && !*peer_eof {
        let _ = Pin::new(&mut *stream).poll_shutdown(cx);
        *peer_eof = true;
    }
    if socket.can_send() && !*app_eof {
        let mut buffer = [0; TCP_BUFFER];
        while socket.can_send() {
            let available = buffer
                .len()
                .min(socket.send_capacity() - socket.send_queue());
            let mut read = ReadBuf::new(&mut buffer[..available]);
            let Poll::Ready(result) = Pin::new(&mut *stream).poll_read(cx, &mut read) else {
                break;
            };
            if result.is_err() || read.filled().is_empty() {
                *app_eof = true;
                socket.close();
                break;
            }
            let _ = socket.send_slice(read.filled());
        }
    }
    socket.remote_endpoint().is_some()
}

struct EngineWake(Notify);

impl Wake for EngineWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

async fn wait_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => pending().await,
    }
}

enum PacketProtocol {
    Tcp { syn: bool },
    Udp,
}

fn flow_headers(packet: &[u8]) -> Option<(FlowKey, PacketProtocol)> {
    let (source, destination, protocol, transport) = match packet.first()? >> 4 {
        4 => {
            let header = Ipv4Packet::new_checked(packet).ok()?;
            if header.header_len() < 20
                || header.more_frags()
                || header.frag_offset() != 0
                || !header.verify_checksum()
            {
                return None;
            }
            (
                IpAddr::from(header.src_addr()),
                IpAddr::from(header.dst_addr()),
                header.next_header(),
                &packet[usize::from(header.header_len())..usize::from(header.total_len())],
            )
        }
        6 => {
            let header = Ipv6Packet::new_checked(packet).ok()?;
            (
                IpAddr::from(header.src_addr()),
                IpAddr::from(header.dst_addr()),
                header.next_header(),
                &packet[40..40 + usize::from(header.payload_len())],
            )
        }
        _ => return None,
    };
    if !IpAddress::from(source).is_unicast() || !IpAddress::from(destination).is_unicast() {
        return None;
    }
    let (src_port, dst_port, kind) = match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(transport).ok()?;
            let syn = tcp.syn() && !tcp.ack() && !tcp.rst() && !tcp.fin();
            if syn {
                TcpRepr::parse(
                    &tcp,
                    &source.into(),
                    &destination.into(),
                    &ChecksumCapabilities::default(),
                )
                .ok()?;
            }
            (tcp.src_port(), tcp.dst_port(), PacketProtocol::Tcp { syn })
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(transport).ok()?;
            (udp.src_port(), udp.dst_port(), PacketProtocol::Udp)
        }
        _ => return None,
    };
    if src_port == 0 || dst_port == 0 {
        return None;
    }
    Some((
        FlowKey {
            local: SocketAddr::new(destination, dst_port),
            remote: SocketAddr::new(source, src_port),
        },
        kind,
    ))
}

struct PacketDevice {
    incoming: Option<Vec<u8>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mpsc::Sender<Vec<u8>>);

impl Device for PacketDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: NetworkTime) -> Option<(Rx, Tx<'_>)> {
        Some((Rx(self.incoming.take()?), Tx(&self.outgoing)))
    }

    fn transmit(&mut self, _: NetworkTime) -> Option<Tx<'_>> {
        (self.outgoing.capacity() > 0 && !self.outgoing.is_closed()).then_some(Tx(&self.outgoing))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }
}

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, size: usize, f: F) -> R {
        let mut packet = vec![0; size];
        let result = f(&mut packet);
        let _ = self.0.try_send(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    fn pair(
        local: IpAddr,
        other: IpAddr,
    ) -> (Stack, mpsc::Receiver<Inbound>, mpsc::Receiver<Inbound>) {
        let (outgoing, mut requests) = mpsc::channel(64);
        let (returning, mut replies) = mpsc::channel(64);
        let (client, reject_unmatched) = Stack::spawn(vec![local], outgoing);
        let (server, inbound) = Stack::spawn(vec![other], returning);
        tokio::spawn({
            let client = client.clone();
            async move {
                while let Some(packet) = replies.recv().await {
                    client.ingress_reply(packet).await.unwrap();
                }
            }
        });
        tokio::spawn(async move {
            while let Some(packet) = requests.recv().await {
                server.ingress(packet).await.unwrap();
            }
        });
        (client, inbound, reject_unmatched)
    }

    #[tokio::test]
    async fn tcp_ipv4_aliased_destination_and_half_close() {
        let (client, mut accepts, _) =
            pair("100.64.0.1".parse().unwrap(), "100.64.0.2".parse().unwrap());
        let requested: SocketAddr = "10.12.0.3:8080".parse().unwrap();
        timeout(Duration::from_secs(3), async {
            let client = tokio::spawn(async move { client.connect_tcp(requested).await.unwrap() });
            let Some(Inbound::Tcp {
                source,
                destination,
                accept,
            }) = accepts.recv().await
            else {
                panic!("expected a TCP admission request");
            };
            assert!(!client.is_finished());
            let mut stream = accept.accept().await.unwrap();
            let mut client = client.await.unwrap();
            assert_eq!(source.ip(), "100.64.0.1".parse::<IpAddr>().unwrap());
            assert_eq!(destination, requested);

            let request_body = vec![0x3a; TCP_BUFFER * 8];
            let mut request = Vec::new();
            tokio::join!(
                async {
                    client.write_all(&request_body).await.unwrap();
                    client.shutdown().await.unwrap();
                },
                async { stream.read_to_end(&mut request).await.unwrap() },
            );
            assert_eq!(request, request_body);

            stream.write_all(b"response").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"response");
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn udp_ipv6_demultiplexes_clients_on_one_destination() {
        let (client, mut accepts, mut unexpected) =
            pair("fd00::1".parse().unwrap(), "100.64.0.2".parse().unwrap());
        let requested: SocketAddr = "[fd12::3]:5353".parse().unwrap();
        timeout(Duration::from_secs(3), async {
            let mut first = client.bind_udp(requested).await.unwrap();
            let mut second = client.bind_udp(requested).await.unwrap();
            first.send(b"first").await.unwrap();
            let Some(Inbound::Udp {
                source,
                destination,
                mut flow,
            }) = accepts.recv().await
            else {
                panic!("expected an accepted UDP flow");
            };
            assert_eq!(source.ip(), "fd00::1".parse::<IpAddr>().unwrap());
            assert_eq!(destination, requested);
            assert_eq!(flow.recv().await.unwrap(), b"first");
            second.send(b"second").await.unwrap();
            let Some(Inbound::Udp {
                source: other_source,
                flow: mut other,
                ..
            }) = accepts.recv().await
            else {
                panic!("expected a second accepted UDP flow");
            };
            assert_ne!(source.port(), other_source.port());
            assert_eq!(other.recv().await.unwrap(), b"second");
            other.send(b"second reply").await.unwrap();
            flow.send(b"first reply").await.unwrap();

            assert_eq!(first.recv().await.unwrap(), b"first reply");
            assert_eq!(second.recv().await.unwrap(), b"second reply");
            assert!(matches!(
                unexpected.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            assert_eq!(
                first
                    .send(&vec![0; udp_max_payload(requested) + 1])
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reply_only_ingress_cannot_open_flows_and_shutdown_closes_them() {
        let (packets_out, mut requests) = mpsc::channel(16);
        let (replies, _replies_in) = mpsc::channel(16);
        let (client, _) = Stack::spawn(vec!["100.64.0.1".parse().unwrap()], packets_out);
        let (server, mut accepts) = Stack::spawn(vec!["100.64.0.2".parse().unwrap()], replies);
        let destination = "100.64.0.2:53".parse().unwrap();
        let flow = client.bind_udp(destination).await.unwrap();

        timeout(Duration::from_secs(3), async {
            flow.send(b"blocked").await.unwrap();
            server
                .ingress_reply(requests.recv().await.unwrap())
                .await
                .unwrap();
            flow.send(b"allowed").await.unwrap();
            server
                .ingress(requests.recv().await.unwrap())
                .await
                .unwrap();
            let Some(Inbound::Udp { mut flow, .. }) = accepts.recv().await else {
                panic!("expected an accepted UDP flow");
            };
            assert_eq!(flow.recv().await.unwrap(), b"allowed");
            server.shutdown().await;
            assert_eq!(
                flow.recv().await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(
                server.bind_udp(destination).await.err().unwrap().kind(),
                io::ErrorKind::BrokenPipe
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn denied_tcp_admission_refuses_the_client_handshake() {
        let (client, mut accepts, _) =
            pair("100.64.0.1".parse().unwrap(), "100.64.0.2".parse().unwrap());
        let dst = "10.12.0.3:8080".parse().unwrap();
        timeout(Duration::from_secs(3), async {
            let client = tokio::spawn(async move { client.connect_tcp(dst).await });
            let Some(Inbound::Tcp { accept, .. }) = accepts.recv().await else {
                panic!("expected TCP admission");
            };
            assert!(!client.is_finished());
            drop(accept);
            assert_eq!(
                client.await.unwrap().unwrap_err().kind(),
                io::ErrorKind::ConnectionRefused
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn expired_and_dropped_udp_flows_free_the_socket_and_timer() {
        let (outgoing, _packets) = mpsc::channel(1);
        let (accepted, _flows) = mpsc::channel(1);
        let mut engine = Engine::new(
            Some("100.64.0.1".parse().unwrap()),
            None,
            outgoing,
            accepted,
        );
        let expired = engine
            .allocate("100.64.0.2:53".parse().unwrap(), true)
            .unwrap();
        let dropped = engine
            .allocate("100.64.0.3:53".parse().unwrap(), true)
            .unwrap();
        let sibling = FlowKey {
            local: expired.local,
            remote: "100.64.0.4:53".parse().unwrap(),
        };
        let _expired = engine.add_udp(expired).unwrap();
        let dropped_flow = engine.add_udp(dropped).unwrap();
        let remaining_flow = engine.add_udp(sibling).unwrap();
        let shared_socket = engine.udp_sockets[&sibling.local];
        assert!(engine.deadline(false).is_some());
        engine.udp.get_mut(&expired).unwrap().last_activity -= UDP_IDLE;
        drop(dropped_flow);
        engine.service(Waker::noop());
        assert_eq!(engine.udp.len(), 1);
        assert_eq!(engine.udp_sockets.len(), 1);
        assert_eq!(engine.udp_sockets[&sibling.local], shared_socket);
        assert!(engine.deadline(false).is_some());

        drop(remaining_flow);
        engine.service(Waker::noop());
        assert!(engine.udp.is_empty());
        assert!(engine.udp_sockets.is_empty());
        assert!(engine.deadline(false).is_none());
    }
}
