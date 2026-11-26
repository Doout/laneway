//! Forward authorized overlay flows through ordinary host sockets.

use crate::rootless_cli::stack::{Inbound, TcpAccept};
use crate::rootless_cli::transport::PacketSender;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout};

const MAX_FLOWS: usize = 256;
const MAX_DIALS: usize = 32;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_IDLE: Duration = Duration::from_secs(300);
const UDP_IDLE: Duration = Duration::from_secs(60);
const UDP_RECEIVE_BUFFER: usize = 1 << 16;

pub async fn serve(mut incoming: mpsc::Receiver<Inbound>, sender: PacketSender) -> io::Result<()> {
    let dials = Arc::new(Semaphore::new(MAX_DIALS));
    let mut flows = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            completed = flows.join_next(), if !flows.is_empty() => {
                if let Some(Err(err)) = completed {
                    return Err(io::Error::other(err));
                }
            }
            inbound = incoming.recv() => {
                let Some(inbound) = inbound else {
                    return Ok(());
                };
                let (source, destination) = match &inbound {
                    Inbound::Tcp { source, destination, .. } | Inbound::Udp { source, destination, .. } => (*source, *destination),
                };
                if flows.len() >= MAX_FLOWS || !allowed(destination, &sender) {
                    continue;
                }
                let Ok(dial) = Arc::clone(&dials).try_acquire_owned() else {
                    continue;
                };
                let sender = sender.clone();
                flows.spawn(async move {
                    if !allowed(destination, &sender) {
                        return;
                    }
                    let result = match inbound {
                        Inbound::Tcp { accept, .. } => {
                            forward_tcp(destination, accept, dial, || allowed(destination, &sender)).await
                        }
                        Inbound::Udp { flow, .. } => {
                            let socket = timeout(DIAL_TIMEOUT, connect_udp(destination)).await;
                            drop(dial);
                            match socket {
                                Ok(Ok(socket)) if allowed(destination, &sender) => relay_udp(flow, socket).await,
                                Ok(Ok(_)) => Err(io::ErrorKind::PermissionDenied.into()),
                                Ok(Err(err)) => Err(err),
                                Err(err) => Err(err.into()),
                            }
                        }
                    };
                    if let Err(err) = result {
                        tracing::debug!(%source, %destination, %err, "rootless forwarding flow ended");
                    }
                });
            }
        }
    }
}

fn allowed(destination: SocketAddr, sender: &PacketSender) -> bool {
    is_unicast_destination(destination) && sender.may_open_destination(destination.ip())
}

fn is_unicast_destination(destination: SocketAddr) -> bool {
    if destination.port() == 0 {
        return false;
    }
    match destination {
        SocketAddr::V4(address) => {
            let ip = address.ip();
            let first = ip.octets()[0];
            first != 0
                && first < 240
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
        }
        SocketAddr::V6(address) => {
            let ip = address.ip();
            address.scope_id() == 0
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && ip.to_ipv4().is_none()
        }
    }
}

async fn forward_tcp(
    destination: SocketAddr,
    accept: TcpAccept,
    dial: OwnedSemaphorePermit,
    still_authorized: impl FnOnce() -> bool,
) -> io::Result<()> {
    let socket = timeout(DIAL_TIMEOUT, TcpStream::connect(destination)).await??;
    drop(dial);
    if !still_authorized() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let stream = accept.accept().await?;
    relay_tcp(stream, socket).await
}

async fn relay_tcp(
    peer: impl AsyncRead + AsyncWrite + Unpin,
    socket: impl AsyncRead + AsyncWrite + Unpin,
) -> io::Result<()> {
    let (mut peer_reader, mut peer_writer) = tokio::io::split(peer);
    let (mut socket_reader, mut socket_writer) = tokio::io::split(socket);
    let (activity, last_activity) = watch::channel(Instant::now());
    tokio::select! {
        result = async {
            tokio::try_join!(
                copy(&mut peer_reader, &mut socket_writer, &activity),
                copy(&mut socket_reader, &mut peer_writer, &activity),
            )?;
            Ok(())
        } => result,
        () = idle(last_activity, TCP_IDLE) => Ok(()),
    }
}

async fn copy(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    activity: &watch::Sender<Instant>,
) -> io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return writer.shutdown().await;
        }
        let mut pending = &buffer[..read];
        while !pending.is_empty() {
            let written = writer.write(pending).await?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            pending = &pending[written..];
            activity.send_replace(Instant::now());
        }
    }
}

async fn idle(mut activity: watch::Receiver<Instant>, limit: Duration) {
    // Only arm a new timer when the current one fires, so busy flows do not
    // repeatedly cancel and re-register the timer.
    loop {
        let deadline = *activity.borrow_and_update() + limit;
        sleep_until(deadline).await;
        if !activity.has_changed().unwrap_or(false) {
            return;
        }
    }
}

async fn connect_udp(destination: SocketAddr) -> io::Result<UdpSocket> {
    let bind_address = match destination.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(destination).await?;
    Ok(socket)
}

async fn relay_udp(
    mut flow: crate::rootless_cli::stack::UdpFlow,
    socket: UdpSocket,
) -> io::Result<()> {
    let sender = flow.sender();
    let max_payload = sender.max_payload();
    let (activity, last_activity) = watch::channel(Instant::now());
    tokio::select! {
        result = async {
            loop {
                let datagram = flow.recv().await?;
                let written = socket.send(&datagram).await?;
                if written != datagram.len() {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                activity.send_replace(Instant::now());
            }
        } => result,
        result = async {
            // Receive the whole datagram so oversized replies can be dropped
            // without truncation or platform-specific socket errors.
            let mut buffer = vec![0; UDP_RECEIVE_BUFFER];
            loop {
                let read = socket.recv(&mut buffer).await?;
                if read <= max_payload {
                    sender.send(&buffer[..read]).await?;
                    activity.send_replace(Instant::now());
                }
            }
        } => result,
        () = idle(last_activity, UDP_IDLE) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn excludes_special_socket_destinations() {
        for destination in [
            "0.1.2.3:80",
            "127.1.2.3:80",
            "169.254.169.254:80",
            "224.0.0.1:80",
            "255.255.255.255:80",
            "10.0.0.2:0",
            "[::]:80",
            "[::1]:80",
            "[::ffff:127.0.0.1]:80",
            "[::ffff:10.0.0.2]:80",
            "[::10.0.0.2]:80",
            "[fe80::1]:80",
            "[ff02::1]:80",
            "[fc00::1%2]:80",
        ] {
            assert!(
                !is_unicast_destination(destination.parse().unwrap()),
                "{destination}"
            );
        }
        for destination in [
            "10.0.0.2:443",
            "192.168.0.2:53",
            "[fc00::1]:443",
            "[2001:db8::1]:53",
        ] {
            assert!(
                is_unicast_destination(destination.parse().unwrap()),
                "{destination}"
            );
        }
    }

    #[tokio::test]
    async fn tcp_relay_preserves_the_reverse_direction_after_a_half_close() {
        let (mut requester, downstream) = duplex(8);
        let (upstream, mut responder) = duplex(8);
        timeout(Duration::from_secs(3), async move {
            tokio::try_join!(
                relay_tcp(downstream, upstream),
                async {
                    requester.write_all(b"request payload").await?;
                    requester.shutdown().await?;
                    let mut reply = Vec::new();
                    requester.read_to_end(&mut reply).await?;
                    assert_eq!(reply, b"response payload");
                    Ok(())
                },
                async {
                    let mut request = Vec::new();
                    responder.read_to_end(&mut request).await?;
                    assert_eq!(request, b"request payload");
                    responder.write_all(b"response payload").await?;
                    responder.shutdown().await
                },
            )
        })
        .await
        .expect("TCP relay stopped making progress")
        .unwrap();
    }

    #[tokio::test]
    async fn tcp_overlay_connect_fails_when_the_host_dial_is_refused() {
        let (client, mut inbound, mut links) = linked_stacks();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_address = listener.local_addr().unwrap();
        drop(listener);

        timeout(Duration::from_secs(3), async {
            let connector = async {
                let Some(Inbound::Tcp { accept, .. }) = inbound.recv().await else {
                    panic!("expected an inbound TCP request");
                };
                let dial = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
                let error = forward_tcp(closed_address, accept, dial, || true)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            };
            let (result, ()) = tokio::join!(
                client.connect_tcp("10.1.1.3:2222".parse().unwrap()),
                connector
            );
            assert!(
                result.is_err(),
                "overlay reported a connection to a closed host port"
            );
        })
        .await
        .expect("overlay did not report the host dial failure");
        links.shutdown().await;
    }

    #[tokio::test]
    async fn tcp_does_not_accept_after_authority_is_withdrawn_during_dial() {
        let (client, mut inbound, mut links) = linked_stacks();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        timeout(Duration::from_secs(3), async {
            let connector = async {
                let Some(Inbound::Tcp { accept, .. }) = inbound.recv().await else {
                    panic!("expected an inbound TCP request");
                };
                let dial = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
                let error = forward_tcp(address, accept, dial, || false)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            };
            let (result, (), host) = tokio::join!(
                client.connect_tcp("10.1.1.3:2222".parse().unwrap()),
                connector,
                listener.accept()
            );
            host.unwrap();
            assert!(
                result.is_err(),
                "overlay reported a connection after authority was withdrawn"
            );
        })
        .await
        .expect("overlay did not report withdrawn authority");
        links.shutdown().await;
    }

    fn linked_stacks() -> (
        crate::rootless_cli::stack::Stack,
        mpsc::Receiver<Inbound>,
        JoinSet<()>,
    ) {
        use crate::rootless_cli::stack::Stack;

        let (outgoing, mut requests) = mpsc::channel(8);
        let (returning, mut replies) = mpsc::channel(8);
        let (client, _client_inbound) = Stack::spawn(vec!["100.64.0.1".parse().unwrap()], outgoing);
        let (connector, connector_inbound) =
            Stack::spawn(vec!["100.64.0.2".parse().unwrap()], returning);
        let mut links = JoinSet::new();
        links.spawn(async move {
            while let Some(packet) = requests.recv().await {
                connector.ingress(packet).await.unwrap();
            }
        });
        links.spawn({
            let client = client.clone();
            async move {
                while let Some(packet) = replies.recv().await {
                    client.ingress_reply(packet).await.unwrap();
                }
            }
        });

        (client, connector_inbound, links)
    }

    #[tokio::test]
    async fn udp_relay_preserves_datagrams_and_discards_invalid_replies() {
        let (client, mut connector_inbound, mut links) = linked_stacks();
        timeout(Duration::from_secs(3), async {
            let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let socket = connect_udp(destination.local_addr().unwrap())
                .await
                .unwrap();
            let wrong_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let host_address = socket.local_addr().unwrap();
            let mut client_flow = client
                .bind_udp("10.1.1.3:2222".parse().unwrap())
                .await
                .unwrap();
            client_flow.send(b"request").await.unwrap();
            let Some(Inbound::Udp { flow, .. }) = connector_inbound.recv().await else {
                panic!("expected an inbound UDP flow");
            };
            let oversized = vec![0; flow.sender().max_payload() + 1];
            links.spawn(async move { relay_udp(flow, socket).await.unwrap() });

            let mut buffer = [0; 32];
            let (read, source) = destination.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], b"request");
            assert_eq!(source, host_address);
            wrong_sender
                .send_to(b"unexpected", host_address)
                .await
                .unwrap();
            destination.send_to(&oversized, host_address).await.unwrap();
            destination.send_to(b"", host_address).await.unwrap();
            destination.send_to(b"reply", host_address).await.unwrap();
            assert!(client_flow.recv().await.unwrap().is_empty());
            assert_eq!(client_flow.recv().await.unwrap(), b"reply");
        })
        .await
        .expect("UDP relay did not complete the exchange");
    }
}
