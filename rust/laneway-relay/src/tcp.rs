use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use laneway_protocol::{
    AuthenticatedIdentity, TcpRecordKind, decode_packet, decode_tcp_record_prefix,
    encode_tcp_record_prefix,
};
use rustls::ProtocolVersion;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, watch},
    task::JoinSet,
    time::{Instant, interval_at, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::{
    Metrics,
    config::TcpFallbackConfig,
    packet_pool::{PacketBuffer, PacketPool},
    tls,
};

const RECORD_CONTROL: u8 = TcpRecordKind::Control as u8;
const RECORD_PACKET: u8 = TcpRecordKind::Packet as u8;
const RECORD_PING: u8 = TcpRecordKind::Ping as u8;
const RECORD_PONG: u8 = TcpRecordKind::Pong as u8;
const MAX_CONTROL_PAYLOAD: usize = 1 << 20;
const MAX_PACKET_FRAME: usize = 5 + 2048;

enum Record {
    Control(Vec<u8>),
    Packet(PacketBuffer),
    Ping,
    Pong,
}

#[derive(Clone)]
pub(crate) struct Writer {
    records: mpsc::Sender<Record>,
    done: watch::Receiver<Option<Arc<str>>>,
}

impl Writer {
    pub(crate) async fn control(&self, payload: Vec<u8>) -> Result<()> {
        self.send(Record::Control(payload)).await
    }

    pub(crate) async fn packet(&self, payload: Bytes) -> Result<()> {
        self.send(Record::Packet(payload.into())).await
    }

    async fn send(&self, record: Record) -> Result<()> {
        let mut done = self.done.clone();
        tokio::select! {
            result = self.records.send(record) => result.context("TCP fallback writer closed"),
            reason = wait_done(&mut done) => bail!("TCP fallback session ended: {reason}"),
        }
    }
}

pub(crate) struct Parts {
    pub(crate) identity: AuthenticatedIdentity,
    pub(crate) certificate_serial: Vec<u8>,
    pub(crate) control: mpsc::Receiver<Vec<u8>>,
    pub(crate) packets: mpsc::Receiver<PacketBuffer>,
    pub(crate) writer: Writer,
    pub(crate) done: watch::Receiver<Option<Arc<str>>>,
    stop: watch::Sender<Option<Arc<str>>>,
    tasks: JoinSet<()>,
}

impl Parts {
    pub(crate) async fn shutdown(mut self, reason: &'static str) {
        let _ = self.stop.send(Some(Arc::from(reason)));
        while self.tasks.join_next().await.is_some() {}
    }
}

pub(crate) async fn accept(
    stream: TcpStream,
    tls_config: Arc<rustls::ServerConfig>,
    config: &TcpFallbackConfig,
    packet_pool: PacketPool,
    metrics: Arc<Metrics>,
) -> Result<Parts> {
    stream.set_nodelay(true).context("set TCP_NODELAY")?;
    let stream = timeout(
        config.handshake_timeout,
        TlsAcceptor::from(tls_config).accept(stream),
    )
    .await
    .context("TCP fallback TLS handshake timed out")?
    .context("TCP fallback TLS handshake failed")?;
    let state = stream.get_ref().1;
    ensure!(
        state.protocol_version() == Some(ProtocolVersion::TLSv1_3),
        "TCP fallback did not negotiate TLS 1.3"
    );
    ensure!(
        state.alpn_protocol() == Some(tls::TCP_FALLBACK_ALPN),
        "TCP fallback ALPN was not negotiated"
    );
    let certificate = state
        .peer_certificates()
        .and_then(|chain| chain.first())
        .context("TCP fallback peer did not present a certificate")?;
    let identity = tls::authenticated_node_identity(certificate.as_ref())?;
    let certificate_serial = tls::certificate_serial(certificate.as_ref())?;

    let (read, write) = tokio::io::split(stream);
    let (control_tx, control) = mpsc::channel(config.queue_depth);
    let (packet_tx, packets) = mpsc::channel(config.queue_depth);
    let (record_tx, record_rx) = mpsc::channel(config.queue_depth);
    let (stop, done) = watch::channel(None);
    let mut tasks = JoinSet::new();
    tasks.spawn(reader_loop(
        read,
        control_tx,
        packet_tx,
        record_tx.clone(),
        stop.clone(),
        done.clone(),
        config.idle_timeout,
        packet_pool,
        metrics,
    ));
    tasks.spawn(writer_loop(
        write,
        record_rx,
        stop.clone(),
        done.clone(),
        config.write_timeout,
        config.keepalive_period,
    ));
    Ok(Parts {
        identity,
        certificate_serial,
        control,
        packets,
        writer: Writer {
            records: record_tx,
            done: done.clone(),
        },
        done,
        stop,
        tasks,
    })
}

#[allow(clippy::too_many_arguments)]
async fn reader_loop(
    mut read: ReadHalf<TlsStream<TcpStream>>,
    control: mpsc::Sender<Vec<u8>>,
    packets: mpsc::Sender<PacketBuffer>,
    writer: mpsc::Sender<Record>,
    stop: watch::Sender<Option<Arc<str>>>,
    mut done: watch::Receiver<Option<Arc<str>>>,
    idle_timeout: Duration,
    packet_pool: PacketPool,
    metrics: Arc<Metrics>,
) {
    let result: Result<()> = async {
        loop {
            let record = tokio::select! {
                result = timeout(idle_timeout, read_record(&mut read, &packet_pool, &metrics)) => {
                    result.context("TCP fallback peer idle timeout")??
                }
                reason = wait_done(&mut done) => bail!("session stopped: {reason}"),
            };
            match record {
                Record::Control(payload) => control
                    .try_send(payload)
                    .context("TCP fallback control receive queue full")?,
                Record::Packet(payload) => {
                    decode_packet(payload.as_ref())
                        .context("invalid TCP fallback packet record")?;
                    packets
                        .try_send(payload)
                        .context("TCP fallback packet receive queue full")?;
                }
                Record::Ping => writer
                    .try_send(Record::Pong)
                    .context("TCP fallback write queue full while answering ping")?,
                Record::Pong => {}
            }
        }
    }
    .await;
    if let Err(error) = result {
        let _ = stop.send(Some(Arc::from(error.to_string())));
    }
}

async fn writer_loop(
    mut write: WriteHalf<TlsStream<TcpStream>>,
    mut records: mpsc::Receiver<Record>,
    stop: watch::Sender<Option<Arc<str>>>,
    mut done: watch::Receiver<Option<Arc<str>>>,
    write_timeout: Duration,
    keepalive_period: Duration,
) {
    let result: Result<()> = async {
        let mut last_send = Instant::now();
        let mut keepalive = interval_at(last_send + keepalive_period, keepalive_period);
        loop {
            let record = tokio::select! {
                record = records.recv() => record.context("TCP fallback write queue closed")?,
                _ = keepalive.tick() => {
                    if last_send.elapsed() < keepalive_period {
                        continue;
                    }
                    Record::Ping
                }
                reason = wait_done(&mut done) => bail!("session stopped: {reason}"),
            };
            timeout(write_timeout, write_record(&mut write, &record))
                .await
                .context("TCP fallback record write timed out")??;
            last_send = Instant::now();
        }
    }
    .await;
    if let Err(error) = result {
        let _ = stop.send(Some(Arc::from(error.to_string())));
    }
}

pub(crate) async fn wait_done(done: &mut watch::Receiver<Option<Arc<str>>>) -> Arc<str> {
    loop {
        if let Some(reason) = done.borrow_and_update().clone() {
            return reason;
        }
        if done.changed().await.is_err() {
            return Arc::from("session state channel closed");
        }
    }
}

async fn read_record<R: AsyncRead + Unpin>(
    read: &mut R,
    packet_pool: &PacketPool,
    metrics: &Metrics,
) -> Result<Record> {
    let mut prefix = [0_u8; 5];
    read.read_exact(&mut prefix)
        .await
        .context("read TCP fallback record prefix")?;
    let header = decode_tcp_record_prefix(&prefix, MAX_CONTROL_PAYLOAD, MAX_PACKET_FRAME)
        .context("invalid TCP fallback record prefix")?;
    Ok(match header.kind {
        TcpRecordKind::Control => {
            let mut payload = vec![0; header.payload_length];
            read.read_exact(&mut payload)
                .await
                .context("read TCP fallback control record payload")?;
            Record::Control(payload)
        }
        TcpRecordKind::Packet => {
            let (mut payload, miss) = packet_pool.take();
            if miss {
                metrics
                    .tcp_packet_pool_misses
                    .fetch_add(1, Ordering::Relaxed);
            }
            payload.resize(header.payload_length, 0);
            read.read_exact(&mut payload)
                .await
                .context("read TCP fallback packet record payload")?;
            Record::Packet(payload.into())
        }
        TcpRecordKind::Ping => Record::Ping,
        TcpRecordKind::Pong => Record::Pong,
    })
}

async fn write_record<W: AsyncWrite + Unpin>(write: &mut W, record: &Record) -> Result<()> {
    let (kind, payload) = match record {
        Record::Control(payload) => (RECORD_CONTROL, payload.as_slice()),
        Record::Packet(payload) => (RECORD_PACKET, payload.as_ref()),
        Record::Ping => (RECORD_PING, &[][..]),
        Record::Pong => (RECORD_PONG, &[][..]),
    };
    let kind = match kind {
        RECORD_CONTROL => TcpRecordKind::Control,
        RECORD_PACKET => TcpRecordKind::Packet,
        RECORD_PING => TcpRecordKind::Ping,
        RECORD_PONG => TcpRecordKind::Pong,
        _ => unreachable!(),
    };
    let prefix =
        encode_tcp_record_prefix(kind, payload.len(), MAX_CONTROL_PAYLOAD, MAX_PACKET_FRAME)
            .context("TCP fallback record exceeds its bound")?;
    write
        .write_all(&prefix)
        .await
        .context("write TCP fallback record prefix")?;
    write
        .write_all(payload)
        .await
        .context("write TCP fallback record payload")?;
    write.flush().await.context("flush TCP fallback record")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_support() -> (PacketPool, Metrics) {
        (
            PacketPool::prewarmed(1, MAX_PACKET_FRAME),
            Metrics::default(),
        )
    }

    #[tokio::test]
    async fn records_match_stable_v1_layout() {
        let mut wire = Vec::new();
        write_record(&mut wire, &Record::Control(vec![0xaa, 0xbb]))
            .await
            .unwrap();
        assert_eq!(wire, [0, 0, 0, 3, RECORD_CONTROL, 0xaa, 0xbb]);
        let mut input = wire.as_slice();
        let (pool, metrics) = read_support();
        assert!(matches!(
            read_record(&mut input, &pool, &metrics).await.unwrap(),
            Record::Control(payload) if payload == [0xaa, 0xbb]
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_types_empty_ping_payloads_and_oversize_before_allocation() {
        for wire in [
            vec![0, 0, 0, 1, 99],
            vec![0, 0, 0, 2, RECORD_PING, 0],
            vec![0, 0, 5, 7, RECORD_PACKET],
        ] {
            let mut input = wire.as_slice();
            let (pool, metrics) = read_support();
            assert!(read_record(&mut input, &pool, &metrics).await.is_err());
        }
    }

    #[tokio::test]
    async fn warmed_packet_records_reuse_storage_without_pool_misses() {
        let pool = PacketPool::prewarmed(1, MAX_PACKET_FRAME);
        let metrics = Metrics::default();
        let mut wire = Vec::new();
        write_record(
            &mut wire,
            &Record::Packet(Bytes::from_static(&[1, 2, 3]).into()),
        )
        .await
        .unwrap();

        let mut first_input = wire.as_slice();
        let first = read_record(&mut first_input, &pool, &metrics)
            .await
            .unwrap();
        let first = match first {
            Record::Packet(packet) => packet,
            _ => panic!("expected packet record"),
        };
        let pointer = first.as_ref().as_ptr();
        assert_eq!(metrics.snapshot().tcp_packet_pool_misses, 0);
        drop(first);

        let mut second_input = wire.as_slice();
        let second = read_record(&mut second_input, &pool, &metrics)
            .await
            .unwrap();
        let second = match second {
            Record::Packet(packet) => packet,
            _ => panic!("expected packet record"),
        };
        assert_eq!(second.as_ref().as_ptr(), pointer);
        assert_eq!(metrics.snapshot().tcp_packet_pool_misses, 0);

        let mut exhausted_input = wire.as_slice();
        let _fallback = read_record(&mut exhausted_input, &pool, &metrics)
            .await
            .unwrap();
        assert_eq!(metrics.snapshot().tcp_packet_pool_misses, 1);
    }
}
