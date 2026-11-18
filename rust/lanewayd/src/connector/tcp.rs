use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as StackInstant,
    wire::{HardwareAddress, IpCidr},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{Duration, Instant, sleep, timeout},
};

use super::{AUTHORITY_CHECK, DIAL_TIMEOUT, Flow, IDLE_TIMEOUT};

const TCP_WINDOW: usize = 16 * 1024;

pub(super) async fn forward(flow: &mut Flow) -> Result<()> {
    if !flow.authorized() {
        return Ok(());
    }
    let mut upstream = tokio::select! {
        biased;
        _ = flow.revoked() => return Ok(()),
        result = timeout(DIAL_TIMEOUT, TcpStream::connect(flow.key.destination)) => {
            match result {
                Ok(Ok(socket)) => socket,
                _ => {
                    // Let the TCP stack reject the SYN as a closed port. Do
                    // not acknowledge a connection the host cannot open.
                    Stack::new(flow.key.destination.ip(), flow.mtu)?.poll(Some(flow.first.bytes.clone()), flow);
                    return Ok(());
                }
            }
        }
    };
    let mut stack = Stack::new(flow.key.destination.ip(), flow.mtu)?;
    let handle = stack.listen(flow.key.destination)?;
    stack.poll(Some(flow.first.bytes.clone()), flow);
    let mut host_read = true;
    let mut host_write = true;
    let mut idle = Instant::now() + IDLE_TIMEOUT;
    let mut buffer = [0; TCP_WINDOW];
    loop {
        if !flow.authorized() || Instant::now() >= idle {
            return Ok(());
        }
        let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
        let status = socket.state();
        if status == tcp::State::Closed {
            return Ok(());
        }
        if host_write
            && !matches!(status, tcp::State::Listen | tcp::State::SynReceived)
            && !socket.may_recv()
        {
            upstream.shutdown().await?;
            host_write = false;
        }
        let read_ready = host_read && socket.can_send();
        let write_ready = host_write && socket.can_recv();
        let delay = stack.delay().min(AUTHORITY_CHECK);
        let mut packet = None;
        tokio::select! {
            next = flow.input.recv() => {
                let Some(next) = next else { return Ok(()) };
                if flow.allows(&next) { packet = Some(next.bytes); }
            }
            ready = upstream.readable(), if read_ready => {
                ready?;
                if !flow.authorized() { return Ok(()) }
                let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
                let size = (socket.send_capacity() - socket.send_queue()).min(buffer.len());
                match upstream.try_read(&mut buffer[..size]) {
                    Ok(0) => {
                        host_read = false;
                        socket.close();
                    }
                    Ok(bytes) => {
                        ensure!(socket.send_slice(&buffer[..bytes])? == bytes, "short connector TCP write");
                        idle = Instant::now() + IDLE_TIMEOUT;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => {
                        socket.abort();
                        stack.poll(None, flow);
                        return Err(error.into());
                    }
                }
            }
            ready = upstream.writable(), if write_ready => {
                ready?;
                if !flow.authorized() { return Ok(()) }
                let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
                let sent = socket.recv(|data| {
                    let sent = upstream.try_write(data);
                    (sent.as_ref().copied().unwrap_or_default(), sent)
                })?;
                match sent {
                    Ok(0) => return Ok(()),
                    Ok(_) => { idle = Instant::now() + IDLE_TIMEOUT; }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => {
                        socket.abort();
                        stack.poll(None, flow);
                        return Err(error.into());
                    }
                }
            }
            _ = sleep(delay) => {}
        }
        stack.poll(packet, flow);
    }
}

struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: DevicePort,
    start: Instant,
}

impl Stack {
    fn new(local_address: IpAddr, mtu: usize) -> Result<Self> {
        let mut settings = Config::new(HardwareAddress::Ip);
        let mut seed = [0; 8];
        getrandom::fill(&mut seed).context("generate connector TCP sequence seed")?;
        settings.random_seed = u64::from_ne_bytes(seed);
        let mut device = DevicePort {
            mtu,
            input: None,
            output: Vec::with_capacity(4),
        };
        let mut iface = Interface::new(settings, &mut device, StackInstant::from_millis(0));
        // This is an isolated point-to-point stack for a single five-tuple.
        // The CIDR only selects its on-link overlay return path. No route or
        // address is installed in the real host.
        let local = IpCidr::new(local_address.into(), 0);
        iface.update_ip_addrs(|addresses| addresses.push(local).expect("one address fits"));
        Ok(Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            start: Instant::now(),
        })
    }

    fn listen(&mut self, address: SocketAddr) -> Result<SocketHandle> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
            tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
        );
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
            IDLE_TIMEOUT.as_secs(),
        )));
        socket.listen(address)?;
        Ok(self.sockets.add(socket))
    }

    fn timestamp(&self) -> StackInstant {
        StackInstant::from_millis(
            i64::try_from(self.start.elapsed().as_millis()).unwrap_or(i64::MAX),
        )
    }

    fn delay(&mut self) -> Duration {
        self.iface
            .poll_delay(self.timestamp(), &self.sockets)
            .map_or(AUTHORITY_CHECK, |delay| {
                Duration::from_millis(delay.total_millis())
            })
            .max(Duration::from_millis(1))
    }

    fn poll(&mut self, packet: Option<Bytes>, flow: &Flow) {
        if !flow.authorized() {
            return;
        }
        self.step(packet);
        for output in self.device.output.drain(..) {
            flow.send(output);
        }
    }

    fn step(&mut self, packet: Option<Bytes>) {
        self.device.input = packet;
        self.iface
            .poll(self.timestamp(), &mut self.device, &mut self.sockets);
    }
}

#[derive(Debug)]
struct DevicePort {
    mtu: usize,
    input: Option<Bytes>,
    output: Vec<Bytes>,
}

impl Device for DevicePort {
    type RxToken<'a> = Incoming;
    type TxToken<'a> = Outgoing<'a>;

    fn receive(&mut self, _: StackInstant) -> Option<(Incoming, Outgoing<'_>)> {
        Some((Incoming(self.input.take()?), Outgoing(&mut self.output)))
    }

    fn transmit(&mut self, _: StackInstant) -> Option<Outgoing<'_>> {
        (self.output.len() < 32).then_some(Outgoing(&mut self.output))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct Incoming(Bytes);

impl RxToken for Incoming {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, process: F) -> R {
        process(&self.0)
    }
}

struct Outgoing<'a>(&'a mut Vec<Bytes>);

impl TxToken for Outgoing<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, emit: F) -> R {
        let mut packet = vec![0; len];
        let result = emit(&mut packet);
        self.0.push(packet.into());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::tests::{TestConnector, peer};
    use tokio::{io::AsyncReadExt, net::TcpListener};

    #[tokio::test]
    async fn refused_host_connection_returns_reset_not_a_false_accept() -> Result<()> {
        let closed = TcpListener::bind("127.0.0.1:0").await?;
        let target = closed.local_addr()?;
        drop(closed);
        let source: SocketAddr = "100.96.0.2:41114".parse()?;
        let mut fixture = TestConnector::start();
        let mut client = Stack::new(source.ip(), 1280)?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
            tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
        );
        socket.connect(client.iface.context(), target, source)?;
        let handle = client.sockets.add(socket);
        client.step(None);
        for packet in client.device.output.drain(..) {
            fixture.packet(peer(), packet).await?;
        }
        let reply = timeout(Duration::from_secs(2), fixture.replies.recv())
            .await?
            .context("connector did not reject the SYN")?;
        client.step(Some(reply.bytes));
        assert_eq!(
            client.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Closed
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_ipv4_and_ipv6_proxy_through_a_real_host_socket() -> Result<()> {
        for (source, target) in [
            ("100.96.0.2:41114", "127.0.0.1:0"),
            ("[fd7a::2]:41114", "[::1]:0"),
        ] {
            let listener = TcpListener::bind(target).await?;
            let target = listener.local_addr()?;
            let responder = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                let mut request = [0; 8];
                socket.read_exact(&mut request).await?;
                ensure!(&request == b"over TCP", "TCP payload was changed");
                socket.write_all(b"host reply").await?;
                let mut drain = Vec::new();
                socket.read_to_end(&mut drain).await?;
                Ok::<_, anyhow::Error>(())
            });
            let source: SocketAddr = source.parse()?;
            let mut fixture = TestConnector::start();
            let mut client = Stack::new(source.ip(), 1280)?;
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
                tcp::SocketBuffer::new(vec![0; TCP_WINDOW]),
            );
            socket.connect(client.iface.context(), target, source)?;
            let handle = client.sockets.add(socket);
            timeout(Duration::from_secs(5), async {
                let mut sent = false;
                let mut received = Vec::new();
                loop {
                    while let Ok(reply) = fixture.replies.try_recv() {
                        assert_eq!(reply.trigger.peer, peer());
                        client.step(Some(reply.bytes));
                    }
                    let socket = client.sockets.get_mut::<tcp::Socket>(handle);
                    if !sent && socket.can_send() {
                        assert_eq!(socket.send_slice(b"over TCP")?, 8);
                        socket.close();
                        sent = true;
                    }
                    if socket.can_recv() {
                        socket.recv(|data| {
                            received.extend_from_slice(data);
                            (data.len(), ())
                        })?;
                    }
                    client.step(None);
                    for packet in client.device.output.drain(..) {
                        fixture.packet(peer(), packet).await?;
                    }
                    if received.len() >= b"host reply".len() {
                        assert_eq!(received, b"host reply");
                        return Ok::<_, anyhow::Error>(());
                    }
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await??;
            timeout(Duration::from_secs(2), responder).await???;
        }
        Ok(())
    }
}
