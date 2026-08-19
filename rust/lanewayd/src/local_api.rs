use std::{
    future::Future,
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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
const MAX_ERROR_DETAIL_BYTES: usize = 2 << 10;
const MAX_CONNECTIONS: usize = 32;
const API_REVISION: u32 = 1;
const REQUEST_ID_HEADER: &str = "X-Laneway-Request-ID";

const ERROR_INVALID_REQUEST: &str = "invalid_request";
const ERROR_NOT_FOUND: &str = "not_found";
const ERROR_METHOD_NOT_ALLOWED: &str = "method_not_allowed";
const ERROR_CONFLICT: &str = "conflict";
const ERROR_UNSUPPORTED_OPERATION: &str = "unsupported_operation";
const ERROR_BUSY: &str = "busy";
const ERROR_INTERNAL: &str = "internal";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct ExitStatus {
    pub(crate) enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) selected_node_id: String,
    pub(crate) authorized: bool,
    pub(crate) serving: bool,
    pub(crate) forwarding_ready: bool,
    pub(crate) nat_ready: bool,
    pub(crate) forwarded_packets: u64,
    pub(crate) namespace_cleanup_failures: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Status {
    pub(crate) daemon_instance_id: String,
    pub(crate) api_revision: u32,
    pub(crate) running: bool,
    pub(crate) actor: String,
    pub(crate) product_version: String,
    pub(crate) control_version: String,
    pub(crate) packet_version: u8,
    pub(crate) capabilities: String,
    pub(crate) selected_path: String,
    pub(crate) network_id: String,
    pub(crate) node_id: String,
    pub(crate) name: String,
    pub(crate) overlay_addresses: Vec<String>,
    pub(crate) selected_routes: Vec<String>,
    pub(crate) interface: String,
    pub(crate) relay: String,
    pub(crate) mtu: u16,
    pub(crate) metrics: ApiMetrics,
    pub(crate) exit: ExitStatus,
    pub(crate) controller: ControllerStatus,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct ControllerStatus {
    pub(crate) candidate_exchange_enabled: bool,
    pub(crate) certificate_presented_serial: String,
    pub(crate) certificate_renewal_needed: bool,
    pub(crate) certificate_renew_after_unix_seconds: u64,
    pub(crate) certificate_not_after_unix_seconds: u64,
    pub(crate) identity_lease_expires_at_unix_seconds: u64,
    pub(crate) configuration_lease_valid_until_unix_seconds: u64,
    pub(crate) configuration_lease_expired: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Peer {
    pub(crate) node_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) name: String,
    pub(crate) prefixes: Vec<String>,
    pub(crate) path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

struct RequestIds {
    prefix: String,
    next: AtomicU64,
}

impl RequestIds {
    fn new(instance_id: &str) -> Self {
        Self {
            prefix: instance_id[..16].to_owned(),
            next: AtomicU64::new(0),
        }
    }

    fn next(&self) -> String {
        format!(
            "{}{:016x}",
            self.prefix,
            self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
        )
    }
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
        let mut owned = OwnedSocket {
            path: self.path.clone(),
            identity: None,
        };
        let metadata = std::fs::symlink_metadata(&self.path)
            .context("inspect local API socket path after bind")?;
        owned.identity = Some((metadata.dev(), metadata.ino()));
        let _owned = owned;
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
            .context("secure local API socket")?;
        let instance_id = daemon_instance_id()?;
        let request_ids = Arc::new(RequestIds::new(&instance_id));
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tasks = JoinSet::new();
        loop {
            let (mut stream, _) = listener.accept().await.context("accept local API client")?;
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                let request_id = request_ids.next();
                let response =
                    error_response(503, &request_id, ERROR_BUSY, "local API is busy", true);
                let _ = write_response(
                    &mut stream,
                    response.status,
                    response.content_type,
                    &response.body,
                    &request_id,
                    false,
                )
                .await;
                continue;
            };
            let snapshot = Arc::clone(&self.snapshot);
            let set_exit = self.set_exit.clone();
            let request_id = request_ids.next();
            let instance_id = instance_id.clone();
            tasks.spawn(async move {
                let _permit = permit;
                if timeout(
                    Duration::from_secs(5),
                    handle(stream, snapshot, set_exit, instance_id, request_id),
                )
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

fn daemon_instance_id() -> Result<String> {
    loop {
        let mut value = [0_u8; 16];
        getrandom::fill(&mut value).context("generate local API daemon instance ID")?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(hex::encode(value));
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
        "refusing to replace non-socket local API path {path:?}"
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
    identity: Option<(u64, u64)>,
}

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && self
                .identity
                .is_none_or(|(device, inode)| metadata.dev() == device && metadata.ino() == inode)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn handle(
    mut stream: UnixStream,
    snapshot: Arc<SnapshotFn>,
    set_exit: Option<Arc<ExitFn>>,
    instance_id: String,
    request_id: String,
) {
    let mut suppress_body = false;
    let response = match read_request(&mut stream, &mut suppress_body).await {
        Ok(request) => match (request.method, request.path.as_str()) {
            ("GET", "/v1/status") => {
                let mut status = (snapshot)().status;
                status.daemon_instance_id = instance_id;
                status.api_revision = API_REVISION;
                json_response(&status).unwrap_or_else(|_| {
                    error_response(
                        500,
                        &request_id,
                        ERROR_INTERNAL,
                        "encode local API response",
                        true,
                    )
                })
            }
            ("GET", "/v1/peers") => json_response(&(snapshot)().peers).unwrap_or_else(|_| {
                error_response(
                    500,
                    &request_id,
                    ERROR_INTERNAL,
                    "encode local API response",
                    true,
                )
            }),
            ("GET", "/v1/routes") => json_response(&(snapshot)().routes).unwrap_or_else(|_| {
                error_response(
                    500,
                    &request_id,
                    ERROR_INTERNAL,
                    "encode local API response",
                    true,
                )
            }),
            ("POST", "/v1/exit") => {
                if set_exit.is_none() {
                    error_response(
                        501,
                        &request_id,
                        ERROR_UNSUPPORTED_OPERATION,
                        "exit selection is not configured",
                        false,
                    )
                } else {
                    match decode_selection(&request.body) {
                        Ok(selection) => {
                            match (set_exit.as_ref().expect("exit callback checked"))(selection)
                                .await
                            {
                                Ok(()) => {
                                    ReadyResponse::new(204, "text/plain; charset=utf-8", Vec::new())
                                }
                                Err(error) => error_response(
                                    409,
                                    &request_id,
                                    ERROR_CONFLICT,
                                    &error.to_string(),
                                    false,
                                ),
                            }
                        }
                        Err(_) => error_response(
                            400,
                            &request_id,
                            ERROR_INVALID_REQUEST,
                            "invalid exit selection",
                            false,
                        ),
                    }
                }
            }
            (_, "/v1/status" | "/v1/peers" | "/v1/routes" | "/v1/exit") => error_response(
                405,
                &request_id,
                ERROR_METHOD_NOT_ALLOWED,
                "method not allowed",
                false,
            ),
            _ => error_response(
                404,
                &request_id,
                ERROR_NOT_FOUND,
                "local API route not found",
                false,
            ),
        },
        Err(_) => error_response(
            400,
            &request_id,
            ERROR_INVALID_REQUEST,
            "invalid local API request",
            false,
        ),
    };
    let _ = write_response(
        &mut stream,
        response.status,
        response.content_type,
        &response.body,
        &request_id,
        suppress_body,
    )
    .await;
}

struct Request {
    method: &'static str,
    path: String,
    body: Vec<u8>,
}

struct ReadyResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl ReadyResponse {
    fn new(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }
}

async fn read_request(stream: &mut UnixStream, suppress_body: &mut bool) -> Result<Request> {
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
        Some("HEAD") => "HEAD",
        Some(_) => "OTHER",
        None => bail!("request method is missing"),
    };
    *suppress_body = method == "HEAD";
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
        method != "GET" || content_length == 0,
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
    ensure!(
        body.iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(b'{'),
        "exit selection must be a JSON object"
    );
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let selection = ExitSelection::deserialize(&mut decoder).context("invalid exit selection")?;
    decoder.end().context("invalid exit selection")?;
    ensure!(
        !selection.enabled || canonical_node_id(&selection.selected_node_id),
        "enabled exit selection requires a canonical nonzero node ID"
    );
    ensure!(
        selection.enabled || selection.selected_node_id.is_empty(),
        "disabled exit selection must not select a node"
    );
    Ok(selection)
}

fn canonical_node_id(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn json_response(value: &impl Serialize) -> Result<ReadyResponse> {
    let mut body = serde_json::to_vec(value).context("encode response")?;
    body.push(b'\n');
    ensure!(body.len() <= MAX_RESPONSE_BYTES, "response is too large");
    Ok(ReadyResponse::new(200, "application/json", body))
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    request_id: &'a str,
    code: &'a str,
    detail: &'a str,
    retryable: bool,
}

fn error_response(
    status: u16,
    request_id: &str,
    code: &str,
    detail: &str,
    retryable: bool,
) -> ReadyResponse {
    let detail = if detail.is_empty() {
        "local API request failed"
    } else {
        bounded_detail(detail)
    };
    let mut body = serde_json::to_vec(&ErrorEnvelope {
        request_id,
        code,
        detail,
        retryable,
    })
    .unwrap_or_else(|_| {
        br#"{"request_id":"","code":"internal","detail":"encode local API error","retryable":true}"#
            .to_vec()
    });
    body.push(b'\n');
    ReadyResponse::new(status, "application/json", body)
}

fn bounded_detail(detail: &str) -> &str {
    if detail.len() <= MAX_ERROR_DETAIL_BYTES {
        return detail;
    }
    let mut end = MAX_ERROR_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    &detail[..end]
}

async fn write_response(
    stream: &mut UnixStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    request_id: &str,
    suppress_body: bool,
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
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{REQUEST_ID_HEADER}: {request_id}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if !suppress_body {
        stream.write_all(body).await?;
    }
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, sync::Mutex};

    use tempfile::tempdir;

    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DesktopFixture {
        contract_version: u8,
        platform: String,
        ownership: String,
        capabilities: std::collections::BTreeMap<String, bool>,
        status: Status,
        peers: Vec<Peer>,
        routes: Vec<Route>,
    }

    #[test]
    fn shares_the_desktop_status_contract() {
        let fixture: DesktopFixture = serde_json::from_str(include_str!(
            "../../../testvectors/local-api/desktop-snapshot-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture.contract_version, 1);
        assert_eq!(fixture.platform, "linux");
        assert_eq!(fixture.ownership, "same-user-daemon");
        assert_eq!(fixture.capabilities.get("connection_control"), Some(&false));
        assert_eq!(fixture.capabilities.get("exit_selection"), Some(&false));
        assert_eq!(fixture.capabilities.get("snapshot_coherence"), Some(&true));
        assert_eq!(fixture.status.api_revision, API_REVISION);
        assert!(!fixture.status.daemon_instance_id.is_empty());
        assert_eq!(fixture.status.name, "workstation");
        assert_eq!(fixture.peers[0].name, "office-exit");
        assert_eq!(fixture.routes[0].prefix, "10.20.0.0/16");
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            status: Status {
                daemon_instance_id: "0123456789abcdef0123456789abcdef".into(),
                api_revision: API_REVISION,
                running: true,
                actor: "node".into(),
                product_version: "1.0.0".into(),
                control_version: "1.0".into(),
                packet_version: 1,
                capabilities: "relay-v1".into(),
                selected_path: "relay-quic".into(),
                network_id: "00".repeat(16),
                node_id: "11".repeat(16),
                name: "node".into(),
                overlay_addresses: vec!["100.96.0.1/32".into()],
                selected_routes: vec!["100.96.0.2/32".into()],
                interface: "lane0".into(),
                relay: "127.0.0.1:4433".into(),
                mtu: 1280,
                metrics: ApiMetrics::default(),
                exit: ExitStatus::default(),
                controller: ControllerStatus::default(),
            },
            peers: vec![Peer {
                node_id: "22".repeat(16),
                name: "peer".into(),
                prefixes: vec!["100.96.0.2/32".into()],
                path: "direct".into(),
            }],
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

    fn request_id(response: &str) -> &str {
        response
            .lines()
            .find_map(|line| line.strip_prefix("X-Laneway-Request-ID: "))
            .expect("request ID header")
    }

    fn response_json(response: &str) -> serde_json::Value {
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
    }

    #[test]
    fn matches_shared_v1_golden_documents() {
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testvectors/local-api/status-v1.json"
        ))
        .unwrap();
        let actual = serde_json::to_value(snapshot().status).unwrap();
        assert_eq!(actual, expected);

        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../../testvectors/local-api/error-v1.json"))
                .unwrap();
        let response = error_response(
            400,
            "0123456789abcdef0000000000000001",
            ERROR_INVALID_REQUEST,
            "invalid exit selection",
            false,
        );
        let actual: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(actual, expected);

        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testvectors/local-api/exit-selection-v1.json"
        ))
        .unwrap();
        for case in cases["valid"].as_array().unwrap() {
            let selection = decode_selection(case["json"].as_str().unwrap().as_bytes())
                .unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            assert_eq!(selection.enabled, case["enabled"].as_bool().unwrap());
            assert_eq!(
                selection.selected_node_id,
                case["selected_node_id"].as_str().unwrap()
            );
        }
        for case in cases["invalid"].as_array().unwrap() {
            assert!(
                decode_selection(case["json"].as_str().unwrap().as_bytes()).is_err(),
                "{}",
                case["name"]
            );
        }
        assert!(decode_selection(b"{\"selected_node_id\":\"\xff\"}").is_err());
        let empty_detail = error_response(
            409,
            "0123456789abcdef0000000000000001",
            ERROR_CONFLICT,
            "",
            false,
        );
        assert_ne!(
            serde_json::from_slice::<serde_json::Value>(&empty_detail.body).unwrap()["detail"],
            ""
        );
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
        assert_eq!(request_id(&response).len(), 32);
        assert!(
            request_id(&response)
                .chars()
                .all(|value| value.is_ascii_hexdigit())
        );
        let status = response_json(&response);
        assert_eq!(status["api_revision"], API_REVISION);
        assert_eq!(status["daemon_instance_id"].as_str().unwrap().len(), 32);
        let instance_id = status["daemon_instance_id"].as_str().unwrap().to_owned();
        let first_request_id = request_id(&response).to_owned();
        let response = request(&path, "GET /v1/status HTTP/1.1\r\nHost: lanewayd\r\n\r\n").await;
        let status = response_json(&response);
        assert_eq!(status["daemon_instance_id"], instance_id);
        assert_ne!(request_id(&response), first_request_id);
        assert!(response.contains("\"packet_version\":1"));
        assert!(response.contains("\"actor\":\"node\""));
        assert!(response.contains("\"overlay_addresses\":[\"100.96.0.1/32\"]"));
        assert!(response.contains("\"controller\":{"));
        assert!(response.contains("\"certificate_presented_serial\":\"\""));
        assert!(response.contains("\"certificate_renew_after_unix_seconds\":0"));
        assert!(response.contains("\"certificate_not_after_unix_seconds\":0"));
        assert!(response.contains("\"identity_lease_expires_at_unix_seconds\":0"));
        assert!(response.contains("\"configuration_lease_valid_until_unix_seconds\":0"));
        assert!(response.contains("\"configuration_lease_expired\":false"));
        let response = request(&path, "GET /v1/peers HTTP/1.1\r\nHost: lanewayd\r\n\r\n").await;
        assert!(response.contains("\"path\":\"direct\""));
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
        assert!(response.contains("Content-Type: application/json\r\n"));
        let error = response_json(&response);
        assert_eq!(error["code"], ERROR_INVALID_REQUEST);
        assert_eq!(error["retryable"], false);
        assert_eq!(error["request_id"], request_id(&response));
        assert_eq!(selected.lock().unwrap().as_deref(), Some(""));
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
        assert_eq!(response_json(&response)["code"], ERROR_INVALID_REQUEST);

        let response = request(&path, "GET /missing HTTP/1.1\r\nHost: lanewayd\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_NOT_FOUND);

        let response = request(&path, "POST /v1/status HTTP/1.1\r\nHost: lanewayd\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_METHOD_NOT_ALLOWED);

        let response = request(&path, "HEAD /v1/status HTTP/1.1\r\nHost: lanewayd\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty());
        assert!(!head.contains("Content-Length: 0\r\n"));

        let response = request(
            &path,
            "HEAD /v1/status HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty());
        assert!(!head.contains("Content-Length: 0\r\n"));

        let response = request(
            &path,
            "HEAD /v1/status?fresh=1 HTTP/1.1\r\nHost: lanewayd\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty());
        assert!(!head.contains("Content-Length: 0\r\n"));

        let response = request(
            &path,
            "HEAD /v1/status HTTP/1.1\r\nHost: lanewayd\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(body.is_empty());
        assert!(!head.contains("Content-Length: 0\r\n"));

        let response = request(
            &path,
            "PUT /v1/status HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_METHOD_NOT_ALLOWED);

        let oversized = "x".repeat(MAX_REQUEST_BYTES + 1);
        let response = request(
            &path,
            &format!(
                "PUT /v1/status HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: {}\r\n\r\n{oversized}",
                oversized.len()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_INVALID_REQUEST);

        let response = request(&path, "GET /v1//status HTTP/1.1\r\nHost: lanewayd\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_NOT_FOUND);

        let response = request(
            &path,
            "GET /v1/status?fresh=1 HTTP/1.1\r\nHost: lanewayd\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_INVALID_REQUEST);

        let response = request(
            &path,
            "GET /v1/status HTTP/1.1\r\nHost: lanewayd\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_INVALID_REQUEST);
        let response = request(
            &path,
            "POST /v1/exit HTTP/1.1\r\nHost: lanewayd\r\nTransfer-Encoding: chunked\r\n\r\n11\r\n{\"enabled\":false}\r\n0\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(response_json(&response)["code"], ERROR_INVALID_REQUEST);
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
        assert_eq!(
            response_json(&response)["code"],
            ERROR_UNSUPPORTED_OPERATION
        );
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
        assert_eq!(response_json(&response)["code"], ERROR_INVALID_REQUEST);
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

    #[test]
    fn bound_socket_guard_cleans_up_before_identity_capture() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("api.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let guard = OwnedSocket {
            path: path.clone(),
            identity: None,
        };
        drop(guard);
        assert!(!path.exists());
        drop(listener);
    }
}
