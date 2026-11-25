//! A loopback-only SOCKS5 listener for the userspace Laneway dataplane.

use std::{
    collections::{HashMap, hash_map::Entry},
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::{MissedTickBehavior, interval, timeout},
};

use crate::{
    credentials::Verifier,
    runtime::Router,
    stack::{MAX_UDP, Stack, udp_max_payload},
};

const MAX_SESSIONS: usize = 256;
const MAX_UDP_TARGETS: usize = 32;
const UDP_QUEUE: usize = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_IDLE: Duration = Duration::from_secs(60);
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Eq, PartialEq)]
enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Eq, PartialEq)]
struct Address {
    host: Host,
    port: u16,
}

impl Address {
    async fn resolve(&self, router: &Router, protocol: u8) -> io::Result<SocketAddr> {
        if self.port == 0 {
            return Err(ErrorKind::InvalidInput.into());
        }
        match &self.host {
            Host::Ip(ip) => router.resolve(&ip.to_string(), self.port, protocol).await,
            Host::Domain(name) => router.resolve(name, self.port, protocol).await,
        }
    }

    fn udp_client(&self, peer: SocketAddr) -> Option<SocketAddr> {
        let Host::Ip(requested_ip) = self.host else {
            return None;
        };
        // Picking the source port on the first UDP packet would let any local
        // process take over a newly allocated association.
        if self.port == 0 || requested_ip.is_ipv4() != peer.is_ipv4() {
            return None;
        }
        if !requested_ip.is_unspecified() && requested_ip != peer.ip() {
            return None;
        }
        let mut endpoint = peer;
        endpoint.set_port(self.port);
        Some(endpoint)
    }
}

pub async fn serve(
    listener: TcpListener,
    verifier: Verifier,
    stack: Stack,
    router: Router,
) -> io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "SOCKS5 requires a loopback listener",
        ));
    }

    let mut sessions = JoinSet::new();
    // Unbound target workers also consume a slot while awaiting stack admission.
    let udp_slots = Arc::new(Semaphore::new(MAX_UDP));
    loop {
        tokio::select! {
            _ = sessions.join_next(), if !sessions.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                if !peer.ip().is_loopback() || sessions.len() >= MAX_SESSIONS {
                    continue;
                }
                let (verifier, stack, router) = (verifier.clone(), stack.clone(), router.clone());
                let udp_slots = Arc::clone(&udp_slots);
                sessions.spawn(async move {
                    let _ = session(stream, peer, verifier, stack, router, udp_slots).await;
                });
            }
        }
    }
}

async fn session(
    mut stream: TcpStream,
    peer: SocketAddr,
    verifier: Verifier,
    stack: Stack,
    router: Router,
    udp_slots: Arc<Semaphore>,
) -> io::Result<()> {
    let authorization = timeout(HANDSHAKE_TIMEOUT, authenticate(&mut stream, &verifier)).await??;
    tokio::select! {
        biased;
        _ = authorization.cancelled() => Ok(()),
        result = relay(&mut stream, peer, &stack, &router, &udp_slots) => result,
    }
}

async fn authenticate(
    stream: &mut TcpStream,
    verifier: &Verifier,
) -> io::Result<tokio_util::sync::CancellationToken> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        return Err(ErrorKind::InvalidData.into());
    }
    let mut methods = vec![0; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(ErrorKind::PermissionDenied.into());
    }
    stream.write_all(&[5, 2]).await?;

    if stream.read_u8().await? != 1 {
        stream.write_all(&[1, 1]).await?;
        return Err(ErrorKind::InvalidData.into());
    }
    let username = read_field(stream).await?;
    let password = read_field(stream).await?;
    let authorization = match (
        std::str::from_utf8(&username),
        std::str::from_utf8(&password),
    ) {
        (Ok(name), Ok(secret)) if !name.is_empty() && !secret.is_empty() => {
            verifier.verify(name, secret).await
        }
        _ => None,
    };
    let authorization = authorization.filter(|token| !token.is_cancelled());
    stream
        .write_all(&[1, u8::from(authorization.is_none())])
        .await?;
    authorization.ok_or_else(|| ErrorKind::PermissionDenied.into())
}

async fn read_field(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let size = stream.read_u8().await?;
    let mut field = vec![0; usize::from(size)];
    stream.read_exact(&mut field).await?;
    Ok(field)
}

async fn relay(
    stream: &mut TcpStream,
    peer: SocketAddr,
    stack: &Stack,
    router: &Router,
    udp_slots: &Arc<Semaphore>,
) -> io::Result<()> {
    let (command, address) = timeout(HANDSHAKE_TIMEOUT, request(stream)).await??;
    match command {
        1 => {
            let connected = timeout(CONNECT_TIMEOUT, async {
                let target = address.resolve(router, IPPROTO_TCP).await?;
                stack.connect_tcp_with_local(target).await
            })
            .await
            .unwrap_or_else(|_| Err(ErrorKind::TimedOut.into()));
            match connected {
                Ok((mut remote, bound)) => {
                    reply(stream, 0, Some(bound)).await?;
                    tokio::io::copy_bidirectional(stream, &mut remote).await?;
                }
                Err(error) => reply(stream, reply_status(&error), None).await?,
            }
        }
        3 => {
            let Some(client) = address.udp_client(peer) else {
                return reply(stream, 2, None).await;
            };
            let socket = match bind_udp_relay(stream.local_addr()?.ip(), client).await {
                Ok(socket) => socket,
                Err(error) => return reply(stream, reply_status(&error), None).await,
            };
            reply(stream, 0, Some(socket.local_addr()?)).await?;
            udp_associate(stream, socket, stack, router, udp_slots).await?;
        }
        _ => reply(stream, 7, None).await?,
    }
    Ok(())
}

async fn bind_udp_relay(ip: IpAddr, client: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
    socket.connect(client).await?;
    Ok(socket)
}

async fn request(stream: &mut TcpStream) -> io::Result<(u8, Address)> {
    let mut header = [0; 3];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        return Err(ErrorKind::InvalidData.into());
    }
    if let Ok(address) = read_address(stream).await {
        Ok((header[1], address))
    } else {
        reply(stream, 8, None).await?;
        Err(ErrorKind::InvalidData.into())
    }
}

async fn read_address(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Address> {
    let host = match reader.read_u8().await? {
        1 => Host::Ip(IpAddr::V4(reader.read_u32().await?.into())),
        4 => Host::Ip(IpAddr::V6(reader.read_u128().await?.into())),
        3 => {
            let name = read_field(reader).await?;
            if name.is_empty()
                || !name
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
            {
                return Err(ErrorKind::InvalidData.into());
            }
            Host::Domain(String::from_utf8(name).map_err(|_| ErrorKind::InvalidData)?)
        }
        _ => return Err(ErrorKind::InvalidData.into()),
    };
    Ok(Address {
        host,
        port: reader.read_u16().await?,
    })
}

fn append_address(message: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            message.push(1);
            message.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            message.push(4);
            message.extend(ip.octets());
        }
    }
    message.extend(address.port().to_be_bytes());
}

async fn reply(stream: &mut TcpStream, status: u8, bound: Option<SocketAddr>) -> io::Result<()> {
    let mut message = vec![5, status, 0];
    append_address(
        &mut message,
        bound.unwrap_or_else(|| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)),
    );
    stream.write_all(&message).await
}

fn reply_status(error: &io::Error) -> u8 {
    match error.kind() {
        ErrorKind::PermissionDenied | ErrorKind::InvalidInput => 2,
        ErrorKind::NetworkUnreachable => 3,
        ErrorKind::HostUnreachable | ErrorKind::NotFound | ErrorKind::TimedOut => 4,
        ErrorKind::ConnectionRefused => 5,
        _ => 1,
    }
}

struct UdpTarget {
    tx: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
    last_send: Instant,
}

impl Drop for UdpTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn udp_associate(
    control: &mut TcpStream,
    socket: UdpSocket,
    stack: &Stack,
    router: &Router,
    udp_slots: &Arc<Semaphore>,
) -> io::Result<()> {
    tokio::select! {
        biased;
        // Either EOF or extra data closes the association.
        result = control.read_u8() => match result {
            Ok(_) => Err(ErrorKind::InvalidData.into()),
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(()),
            Err(error) => Err(error),
        },
        result = udp_relay(socket, stack, router, udp_slots) => result,
    }
}

async fn udp_relay(
    socket: UdpSocket,
    stack: &Stack,
    router: &Router,
    udp_slots: &Arc<Semaphore>,
) -> io::Result<()> {
    let client = socket.peer_addr()?;
    let mut datagram = vec![0; u16::MAX as usize];
    let mut targets = HashMap::new();
    let (responses_tx, mut responses_rx) = mpsc::channel::<Vec<u8>>(UDP_QUEUE);
    let mut sweep = interval(UDP_IDLE);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = sweep.tick() => {
                targets.retain(|_, flow: &mut UdpTarget| {
                    !flow.task.is_finished() && flow.last_send.elapsed() < UDP_IDLE
                });
            }
            Some(response) = responses_rx.recv() => {
                let _ = socket.send(&response).await;
            }
            received = socket.recv_from(&mut datagram) => {
                // Also reject any packet queued between binding and connecting.
                let size = match received {
                    Ok((size, source)) if source == client => size,
                    Ok(_) => continue,
                    Err(error) if error.kind() == ErrorKind::ConnectionRefused => continue,
                    Err(error) => return Err(error),
                };
                let Some(frame) = datagram[..size].strip_prefix(&[0, 0, 0]) else {
                    continue;
                };
                let mut payload = frame;
                let Ok(address) = read_address(&mut payload).await else {
                    continue;
                };
                let Ok(Ok(target)) = timeout(CONNECT_TIMEOUT, address.resolve(router, IPPROTO_UDP)).await else {
                    continue;
                };
                if payload.len() > udp_max_payload(target) {
                    continue;
                }
                if targets.get(&target).is_some_and(|flow| flow.task.is_finished()) {
                    targets.remove(&target);
                }
                let at_capacity = targets.len() >= MAX_UDP_TARGETS;
                let flow = match targets.entry(target) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) if !at_capacity => {
                        let Some(flow) = spawn_udp_target(stack, target, &responses_tx, udp_slots) else {
                            continue;
                        };
                        entry.insert(flow)
                    }
                    Entry::Vacant(_) => continue,
                };
                if flow.tx.try_send(payload.to_vec()).is_ok() {
                    flow.last_send = Instant::now();
                }
            }
        }
    }
}

fn spawn_udp_target(
    stack: &Stack,
    target: SocketAddr,
    responses: &mpsc::Sender<Vec<u8>>,
    udp_slots: &Arc<Semaphore>,
) -> Option<UdpTarget> {
    let permit = Arc::clone(udp_slots).try_acquire_owned().ok()?;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(UDP_QUEUE);
    let (stack, responses) = (stack.clone(), responses.clone());
    let task = tokio::spawn(async move {
        let _permit = permit;
        let Ok(Ok(mut remote)) = timeout(CONNECT_TIMEOUT, stack.bind_udp(target)).await else {
            return;
        };
        loop {
            tokio::select! {
                request = rx.recv() => {
                    let Some(payload) = request else { return };
                    if remote.send(&payload).await.is_err() {
                        return;
                    }
                }
                response = remote.recv() => {
                    let Ok(payload) = response else { return };
                    let mut frame = vec![0, 0, 0];
                    append_address(&mut frame, target);
                    frame.extend(payload);
                    let _ = responses.try_send(frame);
                }
            }
        }
    });
    Some(UdpTarget {
        tx,
        task,
        last_send: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_target_budget_is_shared_and_reclaimed_on_drop() {
        let (packets, _outgoing) = mpsc::channel(1);
        let (stack, _inbound) = Stack::spawn(vec!["100.64.0.1".parse().unwrap()], packets);
        let slots = Arc::new(Semaphore::new(1));
        let (first_responses, _first_client) = mpsc::channel(1);
        let (second_responses, _second_client) = mpsc::channel(1);
        let first = "100.64.0.2:53".parse().unwrap();
        let second = "100.64.0.3:53".parse().unwrap();

        let flow = spawn_udp_target(&stack, first, &first_responses, &slots).unwrap();
        assert!(spawn_udp_target(&stack, second, &second_responses, &slots).is_none());
        drop(flow);

        let released = timeout(Duration::from_secs(1), slots.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(released);
        assert!(spawn_udp_target(&stack, second, &second_responses, &slots).is_some());
        stack.shutdown().await;
    }

    #[tokio::test]
    async fn socks_listener_requires_username_and_password_method() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        crate::private::ensure_directory(&state).unwrap();
        let verifier = Verifier::open(state.join("credentials.json")).unwrap();

        client.write_all(&[5, 1, 0]).await.unwrap();
        assert_eq!(
            authenticate(&mut server, &verifier)
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(client.read_u16().await.unwrap(), 0x05ff);
    }

    #[tokio::test]
    async fn address_parser_preserves_datagram_boundaries() {
        let mut frame: &[u8] = &[3, 3, b'l', b'a', b'n', 0, 53, 1, 2, 3];
        assert_eq!(
            read_address(&mut frame).await.unwrap(),
            Address {
                host: Host::Domain("lan".into()),
                port: 53
            },
        );
        assert_eq!(frame, &[1, 2, 3]);
        assert!(read_address(&mut &[4, 0, 0][..]).await.is_err());
    }

    #[test]
    fn udp_source_is_bound_to_the_tcp_peer_and_a_declared_port() {
        let peer: SocketAddr = "127.0.0.1:11223".parse().unwrap();
        let signed = Address {
            host: Host::Ip(Ipv4Addr::UNSPECIFIED.into()),
            port: 11224,
        };
        assert_eq!(
            signed.udp_client(peer),
            Some("127.0.0.1:11224".parse().unwrap())
        );
        let other_ip = Address {
            host: Host::Ip(Ipv4Addr::new(127, 0, 0, 2).into()),
            port: 11224,
        };
        assert_eq!(other_ip.udp_client(peer), None);
        let unknown_port = Address { port: 0, ..signed };
        assert_eq!(unknown_port.udp_client(peer), None);
        let other_family = Address {
            host: Host::Ip(std::net::Ipv6Addr::UNSPECIFIED.into()),
            port: 11224,
        };
        assert_eq!(other_family.udp_client(peer), None);
    }

    #[tokio::test]
    async fn udp_relay_socket_accepts_only_the_declared_source() {
        let authorized = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let unauthorized = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = bind_udp_relay(Ipv4Addr::LOCALHOST.into(), authorized.local_addr().unwrap())
            .await
            .unwrap();
        let endpoint = relay.local_addr().unwrap();
        unauthorized.send_to(b"wrong", endpoint).await.unwrap();
        authorized.send_to(b"right", endpoint).await.unwrap();
        let mut packet = [0; 16];
        let size = timeout(Duration::from_secs(1), relay.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&packet[..size], b"right");
    }
}
