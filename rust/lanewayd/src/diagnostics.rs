use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Duration, timeout},
};

use crate::metrics::Metrics;

const MAX_CONNECTIONS: usize = 16;

pub(crate) struct DiagnosticsServer {
    listener: TcpListener,
    metrics: Arc<Metrics>,
    slots: Arc<Semaphore>,
}

impl DiagnosticsServer {
    pub(crate) async fn bind(address: SocketAddr, metrics: Arc<Metrics>) -> Result<Self> {
        ensure!(
            address.ip().is_loopback(),
            "diagnostics listener must use loopback"
        );
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("bind diagnostics {address}"))?;
        Ok(Self {
            listener,
            metrics,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("read diagnostics address")
    }

    pub(crate) async fn run(self) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted.context("accept diagnostics connection")?;
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let metrics = Arc::clone(&self.metrics);
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = serve(stream, metrics).await {
                            tracing::debug!(%error, "diagnostics connection ended");
                        }
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    completed
                        .context("diagnostics connection set stopped")?
                        .context("diagnostics task panicked")?;
                }
            }
        }
    }
}

async fn serve(mut stream: TcpStream, metrics: Arc<Metrics>) -> Result<()> {
    let mut request = [0_u8; 1024];
    let size = timeout(Duration::from_secs(2), stream.read(&mut request))
        .await
        .context("diagnostics request timed out")??;
    let metrics_path = request[..size].starts_with(b"GET /metrics HTTP/1.")
        && request[..size].windows(4).any(|value| value == b"\r\n\r\n");
    let (status, content_type, body) = if metrics_path {
        ("200 OK", "text/plain; version=0.0.4", metrics.prometheus())
    } else {
        ("404 Not Found", "text/plain", "not found\n".to_owned())
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    timeout(Duration::from_secs(2), async {
        stream.write_all(headers.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        stream.shutdown().await
    })
    .await
    .context("diagnostics response timed out")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_metrics_are_prometheus_and_other_paths_are_closed() {
        let metrics = Arc::new(Metrics::default());
        Metrics::increment(&metrics.connections_total);
        let server = DiagnosticsServer::bind("127.0.0.1:0".parse().unwrap(), metrics)
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(server.run());
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("laneway_rust_node_connections_total 1"));
        task.abort();
    }

    #[tokio::test]
    async fn saturated_server_closes_excess_connection() {
        let server =
            DiagnosticsServer::bind("127.0.0.1:0".parse().unwrap(), Arc::new(Metrics::default()))
                .await
                .unwrap();
        let address = server.local_addr().unwrap();
        let slots = Arc::clone(&server.slots);
        let permits = slots
            .acquire_many_owned(MAX_CONNECTIONS as u32)
            .await
            .unwrap();
        let task = tokio::spawn(server.run());
        let mut excess = TcpStream::connect(address).await.unwrap();
        let mut byte = [0_u8; 1];
        let read = timeout(Duration::from_secs(1), excess.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
        drop(permits);
        task.abort();
    }
}
