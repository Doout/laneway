use std::{
    future::Future,
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Duration, timeout},
};

const MAX_HEADER_BYTES: usize = 8 << 10;
const MAX_REQUEST_BYTES: usize = 4 << 10;
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const MAX_CONNECTIONS: usize = 32;

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ApiMetrics {
    pub(crate) connections: u64,
    pub(crate) reconnects: u64,
    pub(crate) packets_sent: u64,
    pub(crate) packets_received: u64,
    pub(crate) packets_dropped: u64,
    pub(crate) tcp_connections: u64,
    pub(crate) quic_failures: u64,
    pub(crate) tcp_failures: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ExitStatus {
    pub(crate) enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) selected_node_id: String,
    pub(crate) authorized: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Status {
    pub(crate) running: bool,
    pub(crate) product_version: String,
    pub(crate) control_version: String,
    pub(crate) packet_version: u8,
    pub(crate) capabilities: String,
    pub(crate) selected_path: String,
    pub(crate) network_id: String,
    pub(crate) node_id: String,
    pub(crate) name: String,
    pub(crate) interface: String,
    pub(crate) relay: String,
    pub(crate) mtu: u16,
    pub(crate) metrics: ApiMetrics,
    pub(crate) exit: ExitStatus,
    pub(crate) controller: ControllerStatus,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct ControllerStatus {
    pub(crate) candidate_exchange_enabled: bool,
    pub(crate) certificate_presented_serial: String,
    pub(crate) certificate_renewal_needed: bool,
    pub(crate) certificate_renew_after_unix_seconds: u64,
    pub(crate) certificate_not_after_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Peer {
    pub(crate) node_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) name: String,
    pub(crate) prefixes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Route {
    pub(crate) prefix: String,
    pub(crate) via_node: String,
    pub(crate) kind: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) status: Status,
    pub(crate) peers: Vec<Peer>,
    pub(crate) routes: Vec<Route>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExitSelection {
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) selected_node_id: String,
}

type SnapshotFn = dyn Fn() -> Snapshot + Send + Sync;
type ExitFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
type ExitFn = dyn Fn(ExitSelection) -> ExitFuture + Send + Sync;

pub(crate) struct Server {
    path: PathBuf,
    snapshot: Arc<SnapshotFn>,
    set_exit: Option<Arc<ExitFn>>,
}

impl Server {
    pub(crate) fn new(
        path: PathBuf,
        snapshot: Arc<SnapshotFn>,
        set_exit: Option<Arc<ExitFn>>,
    ) -> Self {
        Self {
            path,
            snapshot,
            set_exit,
        }
    }

    pub(crate) async fn run(self) -> Result<()> {
        prepare_socket(&self.path).await?;
        let listener = UnixListener::bind(&self.path)
            .with_context(|| format!("listen on local API socket {}", self.path.display()))?;
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
            .context("secure local API socket")?;
        let metadata = std::fs::symlink_metadata(&self.path)?;
        let _owned = OwnedSocket {
            path: self.path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = JoinSet::new();
        loop {
            let (mut stream, _) = listener.accept().await.context("accept local API client")?;
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                let _ = write_response(
                    &mut stream,
                    503,
                    "text/plain; charset=utf-8",
                    b"local API is busy\n",
                )
                .await;
                continue;
            };
            let snapshot = Arc::clone(&self.snapshot);
            let set_exit = self.set_exit.clone();
            tasks.spawn(async move {
                let _permit = permit;
                if timeout(Duration::from_secs(5), handle(stream, snapshot, set_exit))
                    .await
                    .is_err()
                {
                    // Dropping the stream is the bounded timeout response.
                }
            });
            while tasks.len() >= MAX_CONNECTIONS {
                let _ = tasks.join_next().await;
            }
        }
    }
}

async fn prepare_socket(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_socket(),
        "refusing to replace non-socket local API path {:?}",
        path
    );
    if timeout(Duration::from_millis(100), UnixStream::connect(path))
        .await
        .is_ok_and(|result| result.is_ok())
    {
        bail!("lanewayd local API is already running");
    }
    std::fs::remove_file(path).context("remove stale local API socket")?;
    Ok(())
}

struct OwnedSocket {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn handle(mut stream: UnixStream, snapshot: Arc<SnapshotFn>, set_exit: Option<Arc<ExitFn>>) {
    let response = read_request(&mut stream).await.and_then(|request| {
        match (request.method, request.path.as_str()) {
            ("GET", "/v1/status") => json_response(&(snapshot)().status),
            ("GET", "/v1/peers") => json_response(&(snapshot)().peers),
            ("GET", "/v1/routes") => json_response(&(snapshot)().routes),
            ("POST", "/v1/exit") => {
                if set_exit.is_none() {
                    return Ok(Response::Ready(
                        501,
                        "text/plain; charset=utf-8",
                        b"exit selection is not configured\n".to_vec(),
                    ));
                }
                let selection = decode_selection(&request.body)?;
                Ok(Response::Exit(selection))
            }
            (_, "/v1/status" | "/v1/peers" | "/v1/routes" | "/v1/exit") => Ok(Response::Ready(
                405,
                "text/plain; charset=utf-8",
                b"method not allowed\n".to_vec(),
            )),
            _ => Ok(Response::Ready(
                404,
                "text/plain; charset=utf-8",
                b"404 page not found\n".to_vec(),
            )),
        }
    });
    let response = match response {
        Ok(Response::Exit(selection)) => {
            match (set_exit.expect("exit callback checked"))(selection).await {
                Ok(()) => Response::Ready(204, "text/plain; charset=utf-8", Vec::new()),
                Err(error) => Response::Ready(
                    409,
                    "text/plain; charset=utf-8",
                    format!("{error}\n").into_bytes(),
                ),
            }
        }
        Ok(response) => response,
        Err(error) => Response::Ready(
            400,
            "text/plain; charset=utf-8",
            format!("{error}\n").into_bytes(),
        ),
    };
    if let Response::Ready(status, content_type, body) = response {
        let _ = write_response(&mut stream, status, content_type, &body).await;
    }
}

struct Request {
    method: &'static str,
    path: String,
    body: Vec<u8>,
}

enum Response {
    Ready(u16, &'static str, Vec<u8>),
    Exit(ExitSelection),
}

async fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let mut buffer = Vec::with_capacity(1024);
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|value| value == b"\r\n\r\n") {
            break position + 4;
        }
        ensure!(
            buffer.len() < MAX_HEADER_BYTES,
            "request header is too large"
        );
        let mut chunk = [0_u8; 1024];
        let size = stream.read(&mut chunk).await?;
        ensure!(size != 0, "incomplete HTTP request");
        buffer.extend_from_slice(&chunk[..size]);
        ensure!(
            buffer.len() <= MAX_HEADER_BYTES + MAX_REQUEST_BYTES,
            "request is too large"
        );
    };
    ensure!(
        header_end <= MAX_HEADER_BYTES,
        "request header is too large"
    );
    let headers =
        std::str::from_utf8(&buffer[..header_end]).context("request header is not UTF-8")?;
    let mut lines = headers[..headers.len() - 4].split("\r\n");
    let mut request_line = lines.next().context("request line is missing")?.split(' ');
    let method = match request_line.next() {
        Some("GET") => "GET",
        Some("POST") => "POST",
        Some(_) => "OTHER",
        None => bail!("request method is missing"),
    };
    let path = request_line
        .next()
        .context("request path is missing")?
        .to_owned();
    let version = request_line.next().context("HTTP version is missing")?;
    ensure!(
        request_line.next().is_none() && matches!(version, "HTTP/1.0" | "HTTP/1.1"),
        "invalid request line"
    );
    ensure!(
        path.starts_with('/') && !path.contains(['?', '#']),
        "invalid request path"
    );
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').context("invalid HTTP header")?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(content_length.is_none(), "duplicate content-length");
            content_length = Some(value.parse::<usize>().context("invalid content-length")?);
        }
        ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "transfer encoding is not supported"
        );
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_REQUEST_BYTES {
        // Mirror an HTTP max-bytes reader: consume the single detection byte
        // so a just-oversized request receives the 400 response without an
        // unread-body TCP reset, but never drain an attacker-declared body.
        if content_length == MAX_REQUEST_BYTES + 1 {
            let total = header_end + content_length;
            ensure!(buffer.len() <= total, "pipelined or oversized request");
            while buffer.len() < total {
                let mut chunk = [0_u8; 1024];
                let remaining = total - buffer.len();
                let read_length = remaining.min(chunk.len());
                let size = stream.read(&mut chunk[..read_length]).await?;
                ensure!(size != 0, "incomplete request body");
                buffer.extend_from_slice(&chunk[..size]);
            }
        }
        bail!("request body is too large");
    }
    ensure!(
        method == "POST" || content_length == 0,
        "GET request body is not allowed"
    );
    let total = header_end + content_length;
    ensure!(buffer.len() <= total, "pipelined or oversized request");
    while buffer.len() < total {
        let mut chunk = [0_u8; 1024];
        let remaining = total - buffer.len();
        let read_length = remaining.min(chunk.len());
        let size = stream.read(&mut chunk[..read_length]).await?;
        ensure!(size != 0, "incomplete request body");
        buffer.extend_from_slice(&chunk[..size]);
    }
    Ok(Request {
        method,
        path,
        body: buffer[header_end..].to_vec(),
    })
}

fn decode_selection(body: &[u8]) -> Result<ExitSelection> {
    ensure!(!body.is_empty(), "invalid exit selection");
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let selection = ExitSelection::deserialize(&mut decoder).context("invalid exit selection")?;
    decoder.end().context("invalid exit selection")?;
    Ok(selection)
}

fn json_response(value: &impl Serialize) -> Result<Response> {
    let mut body = serde_json::to_vec(value).context("encode response")?;
    body.push(b'\n');
    ensure!(body.len() <= MAX_RESPONSE_BYTES, "response is too large");
    Ok(Response::Ready(200, "application/json", body))
}

async fn write_response(
    stream: &mut UnixStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let cache = if content_type == "application/json" {
        "Cache-Control: no-store\r\n"
    } else {
        ""
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{cache}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, sync::Mutex};

    use tempfile::tempdir;

    use super::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            status: Status {
                running: true,
                product_version: "1.0.0".into(),
                control_version: "1.0".into(),
                packet_version: 1,
                capabilities: "relay-v1".into(),
                selected_path: "relay-quic".into(),
                network_id: "00".repeat(16),
                node_id: "11".repeat(16),
                name: "node".into(),
                interface: "lane0".into(),
                relay: "127.0.0.1:4433".into(),
                mtu: 1280,
                metrics: ApiMetrics::default(),
                exit: ExitStatus::default(),
                controller: ControllerStatus::default(),
            },
            peers: vec![],
            routes: vec![],
        }
    }

    async fn request(path: &Path, request: &str) -> String {
        let mut stream = UnixStream::connect(path).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_go_compatible_bounded_api_and_cleans_up() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("api.sock");
        let selected = Arc::new(Mutex::new(None));
        let selected_callback = Arc::clone(&selected);
        let server = Server::new(
            path.clone(),
            Arc::new(snapshot),
            Some(Arc::new(move |selection| {
                let selected = Arc::clone(&selected_callback);
                Box::pin(async move {
                    *selected.lock().unwrap() = Some(selection.selected_node_id);
                    Ok(())
                })
            })),
        );
        let task = tokio::spawn(server.run());
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let response = request(&path, "GET /v1/status HTTP/1.1\r\nHost: lanewayd\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"packet_version\":1"));
        assert!(response.contains("\"controller\":{"));
        assert!(response.contains("\"certificate_presented_serial\":\"\""));
        assert!(response.contains("\"certificate_renew_after_unix_seconds\":0"));
        assert!(response.contains("\"certificate_not_after_unix_seconds\":0"));
        let body = r#"{"enabled":true,"selected_node_id":"202122232425262728292a2b2c2d2e2f"}"#;
        let response = request(
            &path,
            &format!(
                "POST /v1/exit HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert_eq!(
            selected.lock().unwrap().as_deref(),
            Some("202122232425262728292a2b2c2d2e2f")
        );
        let body = "{}";
        let response = request(
            &path,
            &format!(
                "POST /v1/exit HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert_eq!(selected.lock().unwrap().as_deref(), Some(""));
        let body = r#"{"enabled":false,"unexpected":true}"#;
        let response = request(
            &path,
            &format!(
                "POST /v1/exit HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        let oversized = "x".repeat(MAX_REQUEST_BYTES + 1);
        let response = request(
            &path,
            &format!(
                "POST /v1/exit HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: {}\r\n\r\n{oversized}",
                oversized.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        let second = Server::new(
            path.clone(),
            Arc::new(snapshot),
            Some(Arc::new(|_| Box::pin(async { Ok(()) }))),
        );
        assert!(
            second
                .run()
                .await
                .unwrap_err()
                .to_string()
                .contains("already running")
        );
        task.abort();
        let _ = task.await;
        assert!(!path.exists());

        let unavailable = Server::new(path.clone(), Arc::new(snapshot), None);
        let task = tokio::spawn(unavailable.run());
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let response = request(
            &path,
            "POST /v1/exit HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn refuses_to_replace_regular_file() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("api.sock");
        std::fs::write(&path, b"owned").unwrap();
        let server = Server::new(path.clone(), Arc::new(snapshot), None);
        assert!(
            server
                .run()
                .await
                .unwrap_err()
                .to_string()
                .contains("non-socket")
        );
        assert_eq!(std::fs::read(path).unwrap(), b"owned");
    }

    #[tokio::test]
    async fn removes_only_an_unreachable_stale_socket() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("api.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);
        assert!(path.exists());
        prepare_socket(&path).await.unwrap();
        assert!(!path.exists());
    }
}
