use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use tokio::{io::ReadBuf, net::UdpSocket, sync::broadcast};

const PROBE_MAGIC: &[u8; 4] = b"\x0cWHP";
const PROBE_QUEUE: usize = 64;

/// One non-QUIC datagram intercepted from the shared QUIC socket.
#[derive(Clone, Debug)]
pub(crate) struct Datagram {
    pub(crate) source: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

/// A small Quinn socket adapter which diverts the reserved Laneway probe
/// magic while leaving every QUIC datagram on the ordinary endpoint path.
pub(crate) struct ProbeSocket {
    io: UdpSocket,
    probes: broadcast::Sender<Datagram>,
}

impl fmt::Debug for ProbeSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeSocket")
            .field("local_addr", &self.io.local_addr())
            .finish_non_exhaustive()
    }
}

impl ProbeSocket {
    pub(crate) fn bind(
        address: SocketAddr,
        server: ServerConfig,
    ) -> io::Result<(Endpoint, Arc<Self>)> {
        let raw = std::net::UdpSocket::bind(address)?;
        raw.set_nonblocking(true)?;
        let io = UdpSocket::from_std(raw)?;
        let (probes, _) = broadcast::channel(PROBE_QUEUE);
        let socket = Arc::new(Self { io, probes });
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server),
            Arc::clone(&socket) as Arc<dyn AsyncUdpSocket>,
            Arc::new(TokioRuntime),
        )?;
        Ok((endpoint, socket))
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Datagram> {
        self.probes.subscribe()
    }

    pub(crate) async fn send_to(&self, payload: &[u8], destination: SocketAddr) -> io::Result<()> {
        let written = self.io.send_to(payload, destination).await?;
        if written != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short UDP probe write",
            ));
        }
        Ok(())
    }
}

struct Poller(Arc<ProbeSocket>);

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProbePoller").finish()
    }
}

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for ProbeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller(self))
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "segmented UDP transmit is unsupported",
            ));
        }
        match self.io.try_send_to(transmit.contents, transmit.destination) {
            Ok(written) if written == transmit.contents.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short QUIC UDP write",
            )),
            Err(error) => Err(error),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC receive buffers are empty",
            )));
        }
        loop {
            let mut read = ReadBuf::new(&mut bufs[0]);
            let source = ready!(self.io.poll_recv_from(cx, &mut read))?;
            let filled = read.filled();
            if filled.starts_with(PROBE_MAGIC) {
                let _ = self.probes.send(Datagram {
                    source,
                    payload: filled.to_vec(),
                });
                continue;
            }
            meta[0] = RecvMeta {
                addr: source,
                len: filled.len(),
                stride: filled.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}
