use std::{str::FromStr, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use laneway_protocol::{
    Id, TcpRecordKind, decode_packet, decode_tcp_record_prefix, encode_tcp_record_prefix,
};
use rustls::{ProtocolVersion, pki_types::ServerName};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, interval_at, timeout},
};
use tokio_rustls::TlsConnector;

use crate::{config::Config, packet_pool::PacketPool, tls};

const MAX_CONTROL: usize = 1 << 20;
const MAX_PACKET: usize = 5 + 1280;

enum Record {
    Control(Vec<u8>),
    Packet(Bytes),
    Ping,
    Pong,
}

#[derive(Clone)]
pub(crate) struct Writer {
    tx: mpsc::Sender<Record>,
    done: watch::Receiver<Option<Arc<str>>>,
}

impl Writer {
    pub(crate) async fn control(&self, payload: Vec<u8>) -> Result<()> {
        self.send(Record::Control(payload)).await
    }

    pub(crate) async fn packet(&self, payload: Bytes) -> Result<()> {
        self.send(Record::Packet(payload)).await
    }

    async fn send(&self, record: Record) -> Result<()> {
        let mut done = self.done.clone();
        tokio::select! {
            result = self.tx.send(record) => result.context("TCP fallback write queue closed"),
            reason = wait_done(&mut done) => bail!("TCP fallback ended: {reason}"),
        }
    }
}

pub(crate) struct Session {
    pub(crate) control: mpsc::Receiver<Vec<u8>>,
    pub(crate) packets: mpsc::Receiver<Bytes>,
    pub(crate) writer: Writer,
    pub(crate) done: watch::Receiver<Option<Arc<str>>>,
    stop: watch::Sender<Option<Arc<str>>>,
    tasks: JoinSet<()>,
}

impl Session {
    pub(crate) async fn close(mut self) {
        let _ = self.stop.send(Some(Arc::from("session closed")));
        while self.tasks.join_next().await.is_some() {}
    }
}

pub(crate) async fn connect(config: &Config, network: Id) -> Result<Session> {
    let fallback = config
        .tcp_fallback
        .as_ref()
        .context("TCP fallback is disabled")?;
    let raw = timeout(
        fallback.handshake_timeout,
        TcpStream::connect(fallback.address),
    )
    .await
    .context("TCP fallback connect timed out")?
    .context("connect TCP fallback")?;
    raw.set_nodelay(true).context("set TCP_NODELAY")?;
    let server_name = ServerName::try_from(config.relay.server_name.clone())
        .context("invalid relay.server_name")?;
    let stream = timeout(
        fallback.handshake_timeout,
        TlsConnector::from(tls::tcp_client_config(&config.tls)?).connect(server_name, raw),
    )
    .await
    .context("TCP fallback TLS handshake timed out")?
    .context("TCP fallback TLS handshake")?;
    let state = stream.get_ref().1;
    ensure!(
        state.protocol_version() == Some(ProtocolVersion::TLSv1_3)
            && state.alpn_protocol() == Some(tls::TCP_FALLBACK_ALPN),
        "TCP fallback TLS version or ALPN mismatch"
    );
    let leaf = state
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("TCP fallback relay sent no certificate")?;
    tls::validate_relay_certificate(
        leaf.as_ref(),
        network,
        Id::from_str(&config.relay.service_id).context("relay.service_id")?,
    )?;

    let (mut read, mut write) = tokio::io::split(stream);
    let (control_tx, control) = mpsc::channel(fallback.queue_depth);
    let (packet_tx, packets) = mpsc::channel(fallback.queue_depth);
    let (write_tx, mut write_rx) = mpsc::channel(fallback.queue_depth);
    let (stop, done) = watch::channel(None);
    let mut tasks = JoinSet::new();
    let read_stop = stop.clone();
    let mut read_done = done.clone();
    let idle = fallback.idle_timeout;
    let pong = write_tx.clone();
    let read_pool = PacketPool::prewarmed(fallback.queue_depth, MAX_PACKET);
    tasks.spawn(async move {
        let result: Result<()> = async {
            loop {
                let record = tokio::select! {
                    result = timeout(idle, read_record(&mut read, &read_pool)) => result.context("TCP fallback idle timeout")??,
                    reason = wait_done(&mut read_done) => bail!("stopped: {reason}"),
                };
                match record {
                    Record::Control(value) => control_tx.try_send(value).context("control receive queue full")?,
                    Record::Packet(value) => {
                        decode_packet(&value).context("invalid packet record")?;
                        packet_tx.try_send(value).context("packet receive queue full")?;
                    }
                    Record::Ping => pong.try_send(Record::Pong).context("write queue full")?,
                    Record::Pong => {}
                }
            }
        }.await;
        if let Err(error) = result {
            let _ = read_stop.send(Some(Arc::from(error.to_string())));
        }
    });
    let write_stop = stop.clone();
    let mut write_done = done.clone();
    let write_timeout = fallback.write_timeout;
    let keepalive_period = fallback.keepalive_period;
    tasks.spawn(async move {
        let result: Result<()> = async {
            let mut last = Instant::now();
            let mut keepalive = interval_at(last + keepalive_period, keepalive_period);
            loop {
                let record = tokio::select! {
                    value = write_rx.recv() => value.context("write queue closed")?,
                    _ = keepalive.tick() => {
                        if last.elapsed() < keepalive_period { continue; }
                        Record::Ping
                    }
                    reason = wait_done(&mut write_done) => bail!("stopped: {reason}"),
                };
                timeout(write_timeout, write_record(&mut write, &record))
                    .await
                    .context("TCP fallback write timed out")??;
                last = Instant::now();
            }
        }
        .await;
        if let Err(error) = result {
            let _ = write_stop.send(Some(Arc::from(error.to_string())));
        }
    });
    Ok(Session {
        control,
        packets,
        writer: Writer {
            tx: write_tx,
            done: done.clone(),
        },
        done,
        stop,
        tasks,
    })
}

pub(crate) async fn wait_done(done: &mut watch::Receiver<Option<Arc<str>>>) -> Arc<str> {
    loop {
        if let Some(reason) = done.borrow_and_update().clone() {
            return reason;
        }
        if done.changed().await.is_err() {
            return Arc::from("session state closed");
        }
    }
}

async fn read_record<R: AsyncRead + Unpin>(read: &mut R, pool: &PacketPool) -> Result<Record> {
    let mut prefix = [0_u8; 5];
    read.read_exact(&mut prefix)
        .await
        .context("read record prefix")?;
    let header = decode_tcp_record_prefix(&prefix, MAX_CONTROL, MAX_PACKET)
        .context("invalid TCP fallback record prefix")?;
    Ok(match header.kind {
        TcpRecordKind::Control => {
            let mut payload = vec![0; header.payload_length];
            read.read_exact(&mut payload)
                .await
                .context("read control record payload")?;
            Record::Control(payload)
        }
        TcpRecordKind::Packet => {
            let (mut payload, _) = pool.take();
            payload.resize(header.payload_length, 0);
            read.read_exact(&mut payload)
                .await
                .context("read packet record payload")?;
            Record::Packet(Bytes::from_owner(payload))
        }
        TcpRecordKind::Ping => Record::Ping,
        TcpRecordKind::Pong => Record::Pong,
    })
}

async fn write_record<W: AsyncWrite + Unpin>(write: &mut W, record: &Record) -> Result<()> {
    let (kind, payload) = match record {
        Record::Control(value) => (TcpRecordKind::Control, value.as_slice()),
        Record::Packet(value) => (TcpRecordKind::Packet, value.as_ref()),
        Record::Ping => (TcpRecordKind::Ping, &[][..]),
        Record::Pong => (TcpRecordKind::Pong, &[][..]),
    };
    let prefix = encode_tcp_record_prefix(kind, payload.len(), MAX_CONTROL, MAX_PACKET)
        .context("invalid TCP fallback record")?;
    write.write_all(&prefix).await?;
    write.write_all(payload).await?;
    write.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stable_record_layout_and_bounds() {
        let mut wire = Vec::new();
        write_record(&mut wire, &Record::Packet(Bytes::from_static(&[1, 2])))
            .await
            .unwrap();
        assert_eq!(wire, [0, 0, 0, 3, TcpRecordKind::Packet.as_u8(), 1, 2]);
        let oversized_wire = [0, 0, 5, 7, TcpRecordKind::Packet.as_u8()];
        let mut oversized = oversized_wire.as_slice();
        let pool = PacketPool::prewarmed(1, MAX_PACKET);
        assert!(read_record(&mut oversized, &pool).await.is_err());
    }
}
