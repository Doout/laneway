//! Userspace subnet connector. Packets reach this module after carrier
//! authentication. Each host socket is scoped to one authorized overlay flow.
mod tcp;
mod wire;

use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

use anyhow::Result;
use bytes::Bytes;
use laneway_protocol::Id;
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::JoinSet,
    time::{Duration, Instant, sleep},
};

use self::wire::{FlowKey, Kind, Packet};
use crate::{metrics::Metrics, relay::InboundPacket};

const MAX_FLOWS: usize = 1024;
const FLOW_QUEUE: usize = 16;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const AUTHORITY_CHECK: Duration = Duration::from_millis(100);

type Admit = Arc<dyn Fn(&InboundPacket) -> bool + Send + Sync>;

#[cfg(test)]
pub(crate) use wire::udp_packet;

pub(crate) struct Reply {
    pub(crate) trigger: Arc<InboundPacket>,
    pub(crate) bytes: Bytes,
}

struct Flow {
    key: FlowKey,
    peer: Id,
    first: Arc<InboundPacket>,
    mtu: usize,
    admit: Admit,
    output: mpsc::Sender<Reply>,
    input: mpsc::Receiver<InboundPacket>,
    metrics: Arc<Metrics>,
}

impl Flow {
    fn authorized(&self) -> bool {
        self.allows(&self.first)
    }

    fn allows(&self, packet: &InboundPacket) -> bool {
        packet.peer == self.peer && (self.admit)(packet)
    }

    async fn revoked(&self) {
        while self.authorized() {
            sleep(AUTHORITY_CHECK).await;
        }
    }

    fn send(&self, packet: Bytes) {
        if self.authorized()
            && self
                .output
                .try_send(Reply {
                    trigger: Arc::clone(&self.first),
                    bytes: packet,
                })
                .is_err()
        {
            Metrics::increment(&self.metrics.queue_drops);
        }
    }
}

pub(crate) async fn run(
    mtu: usize,
    admit: Admit,
    metrics: Arc<Metrics>,
    mut packets: mpsc::Receiver<InboundPacket>,
    output: mpsc::Sender<Reply>,
) -> Result<()> {
    let mut active = HashMap::<FlowKey, (Id, mpsc::Sender<InboundPacket>)>::new();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            result = tasks.join_next(), if !tasks.is_empty() => {
                let (key, result) = result.expect("connector task present")?;
                active.remove(&key);
                if let Err(error) = result {
                    tracing::debug!(%error, "connector flow closed");
                }
            }
            packet = packets.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                metrics.set_inject_queue_depth(packets.max_capacity().saturating_sub(packets.capacity()));
                if packet.bytes.len() > mtu { continue; }
                let Some(parsed) = Packet::parse(&packet.bytes) else { continue };
                if !admit(&packet) { continue }
                let peer = packet.peer;
                Metrics::increment(&metrics.packets_received_total);
                Metrics::add(&metrics.bytes_received_total, packet.bytes.len());
                let key = parsed.key;
                if let Some((owner, input)) = active.get(&key) {
                    // Never hand the old host socket to a different overlay
                    // node if a source address is reassigned.
                    if *owner == peer && input.try_send(packet).is_err() {
                        Metrics::increment(&metrics.queue_drops);
                    }
                } else if parsed.open && active.len() < MAX_FLOWS {
                    let (input, rx) = mpsc::channel(FLOW_QUEUE);
                    active.insert(key, (peer, input));
                    let mut flow = Flow {
                        key, peer, first: Arc::new(packet), mtu, admit: Arc::clone(&admit),
                        output: output.clone(), input: rx, metrics: Arc::clone(&metrics),
                    };
                    tasks.spawn(async move {
                        let result = match flow.key.kind {
                            Kind::Tcp => tcp::forward(&mut flow).await,
                            Kind::Udp => forward_udp(&mut flow).await,
                        };
                        (key, result)
                    });
                }
            }
        }
    }
}

async fn forward_udp(flow: &mut Flow) -> Result<()> {
    if !flow.authorized() {
        return Ok(());
    }
    let any = if flow.key.destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(any.parse::<SocketAddr>()?).await?;
    socket.connect(flow.key.destination).await?;
    let mut pending = Some(flow.first.as_ref().clone());
    let mut idle = Instant::now() + IDLE_TIMEOUT;
    let limit = flow.mtu - wire::udp_overhead(flow.key.destination);
    // One extra byte lets us drop oversize replies instead of truncating
    // and delivering a different datagram to the requesting application.
    let mut buffer = vec![0; limit + 1];
    loop {
        if !flow.authorized() {
            return Ok(());
        }
        tokio::select! {
            packet = flow.input.recv(), if pending.is_none() => {
                let Some(packet) = packet else { return Ok(()) };
                pending = Some(packet);
            }
            ready = socket.writable(), if pending.is_some() => {
                ready?;
                if !flow.authorized() { return Ok(()) }
                let Some(parsed) = pending.as_ref().filter(|packet| flow.allows(packet))
                    .and_then(|packet| Packet::parse(&packet.bytes)) else {
                    pending = None;
                    continue;
                };
                match socket.try_send(parsed.payload) {
                    Ok(_) => { pending = None; idle = Instant::now() + IDLE_TIMEOUT; }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            ready = socket.readable() => {
                ready?;
                if !flow.authorized() { return Ok(()) }
                match socket.try_recv(&mut buffer) {
                    Ok(size) if size <= limit => {
                        flow.send(wire::udp_packet(flow.key.destination, flow.key.source, &buffer[..size]));
                        idle = Instant::now() + IDLE_TIMEOUT;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            _ = tokio::time::sleep_until(idle) => return Ok(()),
            _ = sleep(AUTHORITY_CHECK) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::{task::JoinHandle, time::timeout};

    use super::*;

    pub(super) fn peer() -> Id {
        Id::from_slice(&[1; 16]).unwrap()
    }

    pub(super) struct TestConnector {
        packets: mpsc::Sender<InboundPacket>,
        pub(super) replies: mpsc::Receiver<Reply>,
        permit: Arc<AtomicBool>,
        task: JoinHandle<Result<()>>,
    }

    impl TestConnector {
        pub(super) fn start() -> Self {
            let (packets, ingress) = mpsc::channel(16);
            let (egress, replies) = mpsc::channel(16);
            let permit = Arc::new(AtomicBool::new(true));
            let decision = Arc::clone(&permit);
            let task = tokio::spawn(run(
                1280,
                Arc::new(move |packet| packet.peer == peer() && decision.load(Ordering::Acquire)),
                Arc::new(Metrics::default()),
                ingress,
                egress,
            ));
            Self {
                packets,
                replies,
                permit,
                task,
            }
        }

        pub(super) async fn packet(&self, peer: Id, bytes: Bytes) -> Result<()> {
            self.packets
                .send(InboundPacket {
                    bytes,
                    peer,
                    direct_serial: None,
                })
                .await?;
            Ok(())
        }
    }

    impl Drop for TestConnector {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn udp_preserves_families_datagrams_and_authority() -> Result<()> {
        for (source, target) in [
            ("100.96.0.2:45080", "127.0.0.1:0"),
            ("[fd7a::2]:45080", "[::1]:0"),
        ] {
            let socket = UdpSocket::bind(target).await?;
            let target = socket.local_addr()?;
            let source: SocketAddr = source.parse()?;
            let mut fixture = TestConnector::start();
            let mut buffer = [0; 128];
            let first = wire::udp_packet(source, target, b"first");
            let wrong_peer = Id::from_slice(&[2; 16])?;
            fixture.packet(wrong_peer, first.clone()).await?;
            let mut corrupt = first.to_vec();
            *corrupt.last_mut().unwrap() ^= 0xff;
            fixture.packet(peer(), corrupt.into()).await?;
            assert!(
                timeout(Duration::from_millis(80), socket.recv_from(&mut buffer))
                    .await
                    .is_err()
            );
            fixture.packet(peer(), first.clone()).await?;
            let (size, host) =
                timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await??;
            assert_eq!(&buffer[..size], b"first");
            socket.send_to(b"reply", host).await?;
            let reply = timeout(Duration::from_secs(2), fixture.replies.recv())
                .await?
                .unwrap();
            let parsed = Packet::parse(&reply.bytes).unwrap();
            assert_eq!(parsed.key.source, target);
            assert_eq!(parsed.key.destination, source);
            assert_eq!(parsed.payload, b"reply");

            fixture.permit.store(false, Ordering::Release);
            fixture.packet(peer(), first).await?;
            let _ = socket.send_to(b"late response", host).await;
            assert!(
                timeout(Duration::from_millis(150), socket.recv_from(&mut buffer))
                    .await
                    .is_err()
            );
            assert!(
                timeout(Duration::from_millis(80), fixture.replies.recv())
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
}
