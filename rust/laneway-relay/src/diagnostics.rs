use std::{fmt::Write as _, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use tracing::{debug, warn};

use crate::{Metrics, MetricsSnapshot, allocator};

const MAX_REQUEST_BYTES: usize = 1024;
const MAX_CONNECTIONS: usize = 16;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct Server {
    listener: TcpListener,
    metrics: Arc<Metrics>,
    slots: Arc<Semaphore>,
}

impl Server {
    pub(crate) fn bind(address: SocketAddr, metrics: Arc<Metrics>) -> Result<Self> {
        Self::bind_with_limit(address, metrics, MAX_CONNECTIONS)
    }

    fn bind_with_limit(
        address: SocketAddr,
        metrics: Arc<Metrics>,
        max_connections: usize,
    ) -> Result<Self> {
        ensure!(
            address.ip().is_loopback(),
            "relay diagnostics listener must use a loopback IP address"
        );
        ensure!(max_connections > 0, "diagnostics connection limit is zero");
        let listener = std::net::TcpListener::bind(address)
            .with_context(|| format!("bind relay diagnostics endpoint {address}"))?;
        listener
            .set_nonblocking(true)
            .context("make relay diagnostics listener nonblocking")?;
        Ok(Self {
            listener: TcpListener::from_std(listener)
                .context("create Tokio relay diagnostics listener")?,
            metrics,
            slots: Arc::new(Semaphore::new(max_connections)),
        })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("query relay diagnostics local address")
    }

    pub(crate) async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            while let Some(completed) = tasks.try_join_next() {
                if let Err(error) = completed {
                    warn!(%error, "relay diagnostics task panicked");
                }
            }
            tokio::select! {
                _ = wait_shutdown(&mut shutdown) => break,
                accepted = self.listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(value) => value,
                        Err(error) => {
                            warn!(%error, "relay diagnostics accept failed");
                            continue;
                        }
                    };
                    if !peer.ip().is_loopback() {
                        warn!(%peer, "rejected non-loopback relay diagnostics client");
                        continue;
                    }
                    let permit = match Arc::clone(&self.slots).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            debug!(%peer, "rejected relay diagnostics client: connection limit reached");
                            continue;
                        }
                    };
                    let metrics = Arc::clone(&self.metrics);
                    let connection_shutdown = shutdown.clone();
                    allocator::without_counting(|| {
                        tasks.spawn(async move {
                            let _permit = permit;
                            if let Err(error) = serve_connection(stream, metrics, connection_shutdown).await {
                                debug!(%peer, %error, "relay diagnostics connection ended");
                            }
                        });
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        warn!(%error, "relay diagnostics task panicked");
                    }
                }
            }
        }
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                warn!(%error, "relay diagnostics task panicked during shutdown");
            }
        }
        Ok(())
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let request = tokio::select! {
        result = timeout(READ_TIMEOUT, read_request(&mut stream)) => {
            result.context("relay diagnostics request read timed out")??
        }
        _ = wait_shutdown(&mut shutdown) => return Ok(()),
    };
    let response = allocator::without_counting(|| {
        let (status, content_type, body) = response(&request, metrics.snapshot());
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    });
    tokio::select! {
        result = timeout(WRITE_TIMEOUT, stream.write_all(response.as_bytes())) => {
            result.context("relay diagnostics response write timed out")??;
        }
        _ = wait_shutdown(&mut shutdown) => return Ok(()),
    }
    let _ = stream.shutdown().await;
    Ok(())
}

async fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Allocate the fixed request cap outside allocator accounting so observing
    // the process does not perturb the next external benchmark delta.
    let mut request = allocator::without_counting(|| Vec::with_capacity(MAX_REQUEST_BYTES));
    loop {
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
        ensure!(
            request.len() < MAX_REQUEST_BYTES,
            "relay diagnostics request exceeds {MAX_REQUEST_BYTES} bytes"
        );
        let remaining = MAX_REQUEST_BYTES - request.len();
        let mut buffer = [0_u8; 256];
        let read_length = remaining.min(buffer.len());
        let read = stream
            .read(&mut buffer[..read_length])
            .await
            .context("read relay diagnostics request")?;
        ensure!(read > 0, "relay diagnostics request ended before headers");
        request.extend_from_slice(&buffer[..read]);
    }
}

fn response(request: &[u8], snapshot: MetricsSnapshot) -> (&'static str, &'static str, String) {
    let Ok(request) = std::str::from_utf8(request) else {
        return bad_request();
    };
    let Some(headers_end) = request.find("\r\n\r\n") else {
        return bad_request();
    };
    let mut lines = request[..headers_end].split("\r\n");
    let Some(request_line) = lines.next() else {
        return bad_request();
    };
    let fields: Vec<_> = request_line.split_ascii_whitespace().collect();
    if fields.len() != 3 || !matches!(fields[2], "HTTP/1.0" | "HTTP/1.1") {
        return bad_request();
    }
    if lines.any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return true;
        };
        name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
    }) {
        return bad_request();
    }
    if fields[0] != "GET" {
        return (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n".to_owned(),
        );
    }
    if fields[1] != "/metrics" {
        return (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_owned(),
        );
    }
    (
        "200 OK",
        "text/plain; version=0.0.4; charset=utf-8",
        render(snapshot),
    )
}

fn bad_request() -> (&'static str, &'static str, String) {
    (
        "400 Bad Request",
        "text/plain; charset=utf-8",
        "bad request\n".to_owned(),
    )
}

fn render(snapshot: MetricsSnapshot) -> String {
    let mut output = String::with_capacity(4096);
    counter(
        &mut output,
        "allocator_allocations",
        "Successful instrumented process allocation calls, excluding diagnostics self-observation.",
        snapshot.allocator_allocations,
    );
    counter(
        &mut output,
        "allocator_allocated_bytes",
        "Bytes requested by instrumented process allocations, excluding diagnostics self-observation.",
        snapshot.allocator_allocated_bytes,
    );
    metric(
        &mut output,
        "laneway_relay_sessions",
        "gauge",
        "Live authenticated relay sessions.",
        snapshot.sessions,
    );
    counter(
        &mut output,
        "registrations",
        "Successful registrations.",
        snapshot.registrations,
    );
    counter(
        &mut output,
        "unregistrations",
        "Completed session cleanup operations.",
        snapshot.unregistrations,
    );
    counter(
        &mut output,
        "sessions_replaced",
        "Duplicate authenticated identities replaced.",
        snapshot.sessions_replaced,
    );
    counter(
        &mut output,
        "bindings_created",
        "Directional route handles created.",
        snapshot.bindings_created,
    );
    counter(
        &mut output,
        "bindings_released",
        "Directional route handles released.",
        snapshot.bindings_released,
    );
    counter(
        &mut output,
        "candidate_publications",
        "Accepted endpoint candidate publications.",
        snapshot.candidate_publications,
    );
    counter(
        &mut output,
        "candidate_pairs",
        "Fresh rendezvous candidate pairs distributed.",
        snapshot.candidate_pairs,
    );
    counter(
        &mut output,
        "forwarded_packets",
        "Packets accepted into recipient queues.",
        snapshot.forwarded_packets,
    );
    counter(
        &mut output,
        "forwarded_bytes",
        "Framed packet bytes accepted for forwarding.",
        snapshot.forwarded_bytes,
    );
    counter(
        &mut output,
        "throttled_packets",
        "Packet frames rejected by the aggregate data limiter.",
        snapshot.throttled_packets,
    );
    counter(
        &mut output,
        "throttled_bytes",
        "Framed bytes rejected by the aggregate data limiter.",
        snapshot.throttled_bytes,
    );
    metric(
        &mut output,
        "laneway_relay_limiter_saturated",
        "gauge",
        "One after a recent aggregate data limiter rejection.",
        snapshot.limiter_saturated,
    );
    counter(
        &mut output,
        "dropped_packets",
        "Total packet frames dropped before recipient enqueue.",
        snapshot.dropped_packets,
    );
    counter(
        &mut output,
        "dropped_bytes",
        "Total framed packet bytes dropped before recipient enqueue.",
        snapshot.dropped_bytes,
    );
    counter(
        &mut output,
        "dropped_malformed",
        "Structurally invalid packet drops.",
        snapshot.dropped_malformed,
    );
    counter(
        &mut output,
        "dropped_unknown_handle",
        "Unknown or stale route-handle drops.",
        snapshot.dropped_unknown_handle,
    );
    counter(
        &mut output,
        "dropped_source",
        "Source ownership failure drops.",
        snapshot.dropped_source,
    );
    counter(
        &mut output,
        "dropped_destination",
        "Destination ownership failure drops.",
        snapshot.dropped_destination,
    );
    counter(
        &mut output,
        "dropped_too_large",
        "Payload or path-MTU limit drops.",
        snapshot.dropped_too_large,
    );
    counter(
        &mut output,
        "dropped_capability",
        "Capability or policy failure drops.",
        snapshot.dropped_capability,
    );
    counter(
        &mut output,
        "dropped_queue_full",
        "Full outbound queue drops.",
        snapshot.dropped_queue_full,
    );
    counter(
        &mut output,
        "dropped_closed",
        "Closed or stale session drops.",
        snapshot.dropped_closed,
    );
    counter(
        &mut output,
        "quic_connection_attempts",
        "Accepted QUIC connection attempts.",
        snapshot.quic_connection_attempts,
    );
    counter(
        &mut output,
        "quic_connection_failures",
        "Refused or failed QUIC connection tasks.",
        snapshot.quic_connection_failures,
    );
    counter(
        &mut output,
        "tcp_connection_attempts",
        "Accepted TLS/TCP connection attempts.",
        snapshot.tcp_connection_attempts,
    );
    counter(
        &mut output,
        "tcp_connection_failures",
        "Refused or failed TLS/TCP connection tasks.",
        snapshot.tcp_connection_failures,
    );
    metric(
        &mut output,
        "laneway_relay_queue_depth",
        "gauge",
        "Packets queued or holding a real bounded channel-slot reservation.",
        snapshot.queue_depth,
    );
    metric(
        &mut output,
        "laneway_relay_queue_depth_peak",
        "gauge",
        "Peak aggregate queued-or-channel-reserved count since process start.",
        snapshot.queue_depth_peak,
    );
    metric(
        &mut output,
        "laneway_relay_controller_certificate_renewal_needed",
        "gauge",
        "Whether the controller-accepted relay certificate is due for renewal.",
        snapshot.controller_certificate_renewal_needed,
    );
    metric(
        &mut output,
        "laneway_relay_controller_certificate_renew_after_seconds",
        "gauge",
        "Controller-accepted relay certificate renewal deadline as Unix seconds.",
        snapshot.controller_certificate_renew_after_seconds,
    );
    metric(
        &mut output,
        "laneway_relay_controller_certificate_not_after_seconds",
        "gauge",
        "Controller-accepted relay certificate expiry as Unix seconds.",
        snapshot.controller_certificate_not_after_seconds,
    );
    counter(
        &mut output,
        "tcp_packet_pool_misses",
        "TLS/TCP packet records that could not reuse a prewarmed buffer.",
        snapshot.tcp_packet_pool_misses,
    );
    output
}

fn counter(output: &mut String, suffix: &str, help: &str, value: u64) {
    metric(
        output,
        &format!("laneway_relay_{suffix}_total"),
        "counter",
        help,
        value,
    );
}

fn metric(output: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} {kind}");
    let _ = writeln!(output, "{name} {value}");
}

async fn wait_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use tokio::{io::AsyncReadExt, sync::watch, time::sleep};

    async fn start(
        limit: usize,
    ) -> (
        SocketAddr,
        Arc<Semaphore>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let metrics = Arc::new(Metrics::default());
        metrics.forwarded_packets.store(7, Ordering::Release);
        metrics.queue_depth.store(2, Ordering::Release);
        metrics.queue_depth_peak.store(5, Ordering::Release);
        metrics
            .controller_certificate_renewal_forced
            .store(1, Ordering::Release);
        metrics
            .controller_certificate_renew_after_seconds
            .store(3_000_000_000, Ordering::Release);
        metrics
            .controller_certificate_not_after_seconds
            .store(4_000_000_000, Ordering::Release);
        let server =
            Server::bind_with_limit("127.0.0.1:0".parse().unwrap(), metrics, limit).unwrap();
        let address = server.local_addr().unwrap();
        let slots = Arc::clone(&server.slots);
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(server.run(stopped));
        (address, slots, stop, task)
    }

    async fn request(address: SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = String::new();
        timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        response
    }

    #[tokio::test]
    async fn serves_label_free_prometheus_metrics_and_rejects_other_http_routes() {
        let (address, _, stop, task) = start(4).await;
        let response = request(address, b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("laneway_relay_forwarded_packets_total 7\n"));
        assert!(response.contains("laneway_relay_allocator_allocations_total "));
        assert!(response.contains("laneway_relay_allocator_allocated_bytes_total "));
        assert!(response.contains("laneway_relay_queue_depth 2\n"));
        assert!(response.contains("laneway_relay_queue_depth_peak 5\n"));
        assert!(response.contains("laneway_relay_controller_certificate_renewal_needed 1\n"));
        assert!(
            response
                .contains("laneway_relay_controller_certificate_renew_after_seconds 3000000000\n")
        );
        assert!(
            response
                .contains("laneway_relay_controller_certificate_not_after_seconds 4000000000\n")
        );
        assert!(!response.contains('{'));

        let response = request(address, b"GET /health HTTP/1.0\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        let response = request(address, b"POST /metrics HTTP/1.0\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        let response = request(
            address,
            b"GET /metrics HTTP/1.1\r\nContent-Length: 1\r\n\r\nX",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn caps_requests_and_rejects_connections_when_saturated() {
        let (address, slots, stop, task) = start(1).await;
        let mut held = TcpStream::connect(address).await.unwrap();
        held.write_all(b"GET ").await.unwrap();
        timeout(Duration::from_secs(2), async {
            while slots.available_permits() != 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();

        let mut rejected = TcpStream::connect(address).await.unwrap();
        rejected
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        let read = timeout(Duration::from_secs(2), rejected.read(&mut byte))
            .await
            .unwrap();
        assert!(match read {
            Ok(0) => true,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => true,
            _ => false,
        });

        drop(held);
        timeout(Duration::from_secs(2), async {
            while slots.available_permits() == 0 {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let oversized = vec![b'A'; MAX_REQUEST_BYTES];
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&oversized).await.unwrap();
        let mut response = Vec::new();
        let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await;
        assert!(response.is_empty());

        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn refuses_non_loopback_bindings() {
        let error = Server::bind_with_limit(
            "0.0.0.0:0".parse().unwrap(),
            Arc::new(Metrics::default()),
            1,
        )
        .err()
        .expect("non-loopback listener must fail");
        assert!(error.to_string().contains("loopback"));
    }
}
