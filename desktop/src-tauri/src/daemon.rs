use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

const DEFAULT_SOCKET: &str = "/run/laneway/lanewayd.sock";
const MAX_HEADER_BYTES: usize = 8 << 10;
const MAX_BODY_BYTES: usize = 1 << 20;
const MAX_WIRE_BYTES: usize = MAX_HEADER_BYTES + MAX_BODY_BYTES;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const SNAPSHOT_ATTEMPTS: usize = 2;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("local daemon access is unavailable on this platform")]
    UnsupportedPlatform,
    #[allow(dead_code)] // Reserved for the unregistered Linux exit adapter.
    #[error("{0} is not supported on this platform")]
    UnsupportedCapability(&'static str),
    #[allow(dead_code)] // Reserved for the unregistered Linux exit adapter.
    #[error("invalid exit selection")]
    InvalidExitSelection,
    #[error("local daemon socket path is invalid")]
    InvalidSocketPath,
    #[error("local daemon socket is not a protected same-user Unix socket")]
    UntrustedSocket,
    #[error("inspect local daemon socket: {0}")]
    Inspect(#[source] std::io::Error),
    #[error("contact local daemon: {0}")]
    Io(#[source] std::io::Error),
    #[error("local daemon request timed out")]
    Timeout,
    #[error("local daemon returned an invalid HTTP response")]
    InvalidResponse,
    #[error("local daemon response is too large")]
    OversizedResponse,
    #[error("local daemon restarted while status was being read")]
    IncoherentSnapshot,
    #[error("local daemon returned {status}: {message}")]
    Rejected { status: u16, message: String },
    #[error("decode local daemon response: {0}")]
    Decode(#[source] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerHealth {
    pub candidate_exchange_enabled: bool,
    pub certificate_presented_serial: String,
    pub certificate_renewal_needed: bool,
    pub certificate_renew_after_unix_seconds: u64,
    pub certificate_not_after_unix_seconds: u64,
    pub identity_lease_expires_at_unix_seconds: u64,
    pub configuration_lease_valid_until_unix_seconds: u64,
    pub configuration_lease_expired: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitStatus {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selected_node_id: String,
    pub authorized: bool,
    pub serving: bool,
    pub forwarding_ready: bool,
    pub nat_ready: bool,
    pub forwarded_packets: u64,
    pub namespace_cleanup_failures: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    #[serde(default)]
    pub daemon_instance_id: String,
    #[serde(default)]
    pub api_revision: u32,
    pub running: bool,
    pub actor: String,
    pub product_version: String,
    pub control_version: String,
    pub packet_version: u8,
    pub capabilities: String,
    pub selected_path: String,
    pub network_id: String,
    pub node_id: String,
    pub name: String,
    pub overlay_addresses: Vec<String>,
    pub selected_routes: Vec<String>,
    pub interface: String,
    pub relay: String,
    pub mtu: u16,
    pub exit: ExitStatus,
    pub controller: ControllerHealth,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub prefixes: Vec<String>,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Route {
    pub prefix: String,
    pub via_node: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DesktopCapabilities {
    pub status: bool,
    pub private_routes: bool,
    pub snapshot_coherence: bool,
    pub exit_selection: bool,
    pub profile_management: bool,
    pub connection_control: bool,
    pub ephemeral_sessions: bool,
    pub updates: bool,
    pub diagnostics: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct DesktopSnapshot {
    pub contract_version: u8,
    pub platform: &'static str,
    pub ownership: &'static str,
    pub capabilities: DesktopCapabilities,
    pub status: DaemonStatus,
    pub peers: Vec<Peer>,
    pub routes: Vec<Route>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Kept native-only until the API exposes capability and candidates.
pub struct ExitSelection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selected_node_id: String,
}

#[derive(Clone, Debug)]
pub struct LocalDaemon {
    socket_path: PathBuf,
}

impl LocalDaemon {
    pub fn from_environment() -> Self {
        Self {
            socket_path: std::env::var_os("LANEWAY_DESKTOP_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET)),
        }
    }

    #[cfg(test)]
    fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub async fn snapshot(&self) -> Result<DesktopSnapshot, DaemonError> {
        let platform = platform_name()?;
        for attempt in 0..SNAPSHOT_ATTEMPTS {
            match self.snapshot_once(platform).await {
                Err(DaemonError::IncoherentSnapshot) if attempt + 1 < SNAPSHOT_ATTEMPTS => {}
                result => return result,
            }
        }
        Err(DaemonError::IncoherentSnapshot)
    }

    async fn snapshot_once(&self, platform: &'static str) -> Result<DesktopSnapshot, DaemonError> {
        let first_status: DaemonStatus = self.get("/v1/status").await?;
        let peers = self.get("/v1/peers").await?;
        let routes = self.get("/v1/routes").await?;
        let status: DaemonStatus = self.get("/v1/status").await?;
        let snapshot_coherence = snapshot_coherence(&first_status, &status)?;
        Ok(DesktopSnapshot {
            contract_version: 1,
            platform,
            ownership: "same-user-daemon",
            capabilities: DesktopCapabilities {
                status: true,
                private_routes: true,
                snapshot_coherence,
                // The current local API does not expose whether exit mutation
                // is configured or which peers are authorized candidates.
                exit_selection: false,
                profile_management: false,
                connection_control: false,
                ephemeral_sessions: false,
                updates: false,
                diagnostics: false,
            },
            status,
            peers,
            routes,
        })
    }

    #[allow(dead_code)] // Intentionally not registered as a Tauri command yet.
    pub async fn set_exit(&self, selection: &ExitSelection) -> Result<(), DaemonError> {
        if platform_name()? != "linux" {
            return Err(DaemonError::UnsupportedCapability("exit selection"));
        }
        validate_exit_selection(selection)?;
        let body = serde_json::to_vec(selection).map_err(DaemonError::Decode)?;
        let response = self.request("POST", "/v1/exit", &body).await?;
        if response.status != 204 {
            return Err(rejected(response));
        }
        if !response.body.is_empty() {
            return Err(DaemonError::InvalidResponse);
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, path: &'static str) -> Result<T, DaemonError> {
        let response = self.request("GET", path, &[]).await?;
        if response.status != 200 {
            return Err(rejected(response));
        }
        serde_json::from_slice(&response.body).map_err(DaemonError::Decode)
    }

    #[cfg(unix)]
    async fn request(
        &self,
        method: &'static str,
        path: &'static str,
        body: &[u8],
    ) -> Result<HttpResponse, DaemonError> {
        let socket_path = validate_socket(&self.socket_path)?;
        tokio::time::timeout(REQUEST_TIMEOUT, exchange(&socket_path, method, path, body))
            .await
            .map_err(|_| DaemonError::Timeout)?
    }

    #[cfg(not(unix))]
    async fn request(
        &self,
        _method: &'static str,
        _path: &'static str,
        _body: &[u8],
    ) -> Result<HttpResponse, DaemonError> {
        Err(DaemonError::UnsupportedPlatform)
    }
}

fn snapshot_coherence(first: &DaemonStatus, second: &DaemonStatus) -> Result<bool, DaemonError> {
    let first_legacy = first.api_revision == 0 && first.daemon_instance_id.is_empty();
    let second_legacy = second.api_revision == 0 && second.daemon_instance_id.is_empty();
    if first_legacy && second_legacy {
        return Ok(false);
    }
    if first.api_revision == 0
        || second.api_revision == 0
        || first.api_revision != second.api_revision
        || !valid_canonical_id(&first.daemon_instance_id)
        || !valid_canonical_id(&second.daemon_instance_id)
        || first.daemon_instance_id != second.daemon_instance_id
    {
        return Err(DaemonError::IncoherentSnapshot);
    }
    Ok(true)
}

#[allow(dead_code)] // Used by the dormant native exit adapter and its Linux gate.
fn validate_exit_selection(selection: &ExitSelection) -> Result<(), DaemonError> {
    let valid_node = valid_canonical_id(&selection.selected_node_id);
    if (selection.enabled && !valid_node)
        || (!selection.enabled && !selection.selected_node_id.is_empty())
    {
        return Err(DaemonError::InvalidExitSelection);
    }
    Ok(())
}

fn valid_canonical_id(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn platform_name() -> Result<&'static str, DaemonError> {
    if cfg!(target_os = "linux") {
        Ok("linux")
    } else if cfg!(target_os = "macos") {
        Ok("macos")
    } else {
        Err(DaemonError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
fn validate_socket(path: &Path) -> Result<PathBuf, DaemonError> {
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
    };

    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() > 103
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(DaemonError::InvalidSocketPath);
    }
    let file_name = path.file_name().ok_or(DaemonError::InvalidSocketPath)?;
    let parent = path.parent().ok_or(DaemonError::InvalidSocketPath)?;
    let physical_parent = std::fs::canonicalize(parent).map_err(DaemonError::Inspect)?;
    let parent_metadata =
        std::fs::symlink_metadata(&physical_parent).map_err(DaemonError::Inspect)?;
    let effective_uid = effective_uid();
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || !protected_owner_mode(
            parent_metadata.uid(),
            parent_metadata.permissions().mode(),
            effective_uid,
        )
    {
        return Err(DaemonError::UntrustedSocket);
    }
    let physical_path = physical_parent.join(file_name);
    if physical_path.as_os_str().as_bytes().len() > 103 {
        return Err(DaemonError::InvalidSocketPath);
    }
    let metadata = std::fs::symlink_metadata(&physical_path).map_err(DaemonError::Inspect)?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || !protected_owner_mode(metadata.uid(), metadata.permissions().mode(), effective_uid)
    {
        return Err(DaemonError::UntrustedSocket);
    }
    Ok(physical_path)
}

#[cfg(unix)]
fn protected_owner_mode(owner_uid: u32, mode: u32, expected_uid: u32) -> bool {
    owner_uid == expected_uid && mode & 0o077 == 0
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no arguments or caller-side preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn verify_peer_uid(peer_uid: u32, expected_uid: u32) -> Result<(), DaemonError> {
    if peer_uid != expected_uid {
        return Err(DaemonError::UntrustedSocket);
    }
    Ok(())
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn rejected(response: HttpResponse) -> DaemonError {
    let message = String::from_utf8_lossy(&response.body)
        .trim()
        .chars()
        .take(512)
        .collect();
    DaemonError::Rejected {
        status: response.status,
        message,
    }
}

#[cfg(unix)]
async fn exchange(
    path: &Path,
    method: &'static str,
    request_path: &'static str,
    body: &[u8],
) -> Result<HttpResponse, DaemonError> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    if !matches!(
        (method, request_path),
        ("GET", "/v1/status" | "/v1/peers" | "/v1/routes") | ("POST", "/v1/exit")
    ) {
        return Err(DaemonError::InvalidResponse);
    }
    if body.len() > 4 << 10 {
        return Err(DaemonError::OversizedResponse);
    }
    let mut stream = UnixStream::connect(path).await.map_err(DaemonError::Io)?;
    let peer = stream.peer_cred().map_err(DaemonError::Io)?;
    verify_peer_uid(peer.uid(), effective_uid())?;
    let mut request = format!(
        "{method} {request_path} HTTP/1.1\r\nHost: lanewayd\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(DaemonError::Io)?;
    stream.write_all(body).await.map_err(DaemonError::Io)?;
    stream.shutdown().await.map_err(DaemonError::Io)?;

    let mut wire = Vec::with_capacity(4096);
    stream
        .take((MAX_WIRE_BYTES + 1) as u64)
        .read_to_end(&mut wire)
        .await
        .map_err(DaemonError::Io)?;
    if wire.len() > MAX_WIRE_BYTES {
        return Err(DaemonError::OversizedResponse);
    }
    parse_response(wire)
}

fn parse_response(wire: Vec<u8>) -> Result<HttpResponse, DaemonError> {
    let header_end = wire
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or(DaemonError::InvalidResponse)?;
    if header_end > MAX_HEADER_BYTES {
        return Err(DaemonError::OversizedResponse);
    }
    let header =
        std::str::from_utf8(&wire[..header_end]).map_err(|_| DaemonError::InvalidResponse)?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    let status_line = lines.next().ok_or(DaemonError::InvalidResponse)?;
    let mut status_fields = status_line.split(' ');
    let version = status_fields.next().ok_or(DaemonError::InvalidResponse)?;
    let status = status_fields
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(DaemonError::InvalidResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || status_fields.next().is_none() {
        return Err(DaemonError::InvalidResponse);
    }
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(DaemonError::InvalidResponse)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(DaemonError::InvalidResponse);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(DaemonError::InvalidResponse);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| DaemonError::InvalidResponse)?,
            );
        }
    }
    let body = wire[header_end..].to_vec();
    match content_length {
        Some(expected) => {
            if expected > MAX_BODY_BYTES {
                return Err(DaemonError::OversizedResponse);
            }
            if body.len() != expected || (status == 204 && expected != 0) {
                return Err(DaemonError::InvalidResponse);
            }
        }
        None if status == 204 && body.is_empty() => {}
        None => return Err(DaemonError::InvalidResponse),
    }
    Ok(HttpResponse { status, body })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::{TempDir, tempdir};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    use super::*;

    const FIXTURE: &str = include_str!("../../../testvectors/local-api/desktop-snapshot-v1.json");

    fn protected_tempdir() -> TempDir {
        let directory = tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    async fn serve_fixture(path: PathBuf, requests: usize, status_instances: Vec<String>) {
        let listener = UnixListener::bind(path).unwrap();
        let mut status_index = 0;
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 8192];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
            let body = if request.starts_with("GET /v1/status ") {
                let mut status = fixture["status"].clone();
                if let Some(instance) = status_instances.get(status_index) {
                    status["daemon_instance_id"] = serde_json::json!(instance);
                    status["api_revision"] = serde_json::json!(1);
                }
                status_index += 1;
                serde_json::to_vec(&status).unwrap()
            } else if request.starts_with("GET /v1/peers ") {
                serde_json::to_vec(&fixture["peers"]).unwrap()
            } else if request.starts_with("GET /v1/routes ") {
                serde_json::to_vec(&fixture["routes"]).unwrap()
            } else {
                Vec::new()
            };
            let status = if request.starts_with("POST /v1/exit ") {
                "204 No Content"
            } else {
                "200 OK"
            };
            let response = if request.starts_with("POST /v1/exit ") {
                // Go's net/http server deliberately omits Content-Length on a
                // successful 204 response.
                format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n")
            } else {
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
            };
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
        }
    }

    #[tokio::test]
    async fn reads_the_shared_contract_from_a_same_user_socket() {
        let directory = protected_tempdir();
        let path = directory.path().join("daemon.sock");
        let task = tokio::spawn(serve_fixture(path.clone(), 4, Vec::new()));
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let snapshot = LocalDaemon::new(path).snapshot().await.unwrap();
        assert_eq!(snapshot.contract_version, 1);
        assert_eq!(snapshot.status.name, "workstation");
        assert_eq!(snapshot.routes[0].prefix, "10.20.0.0/16");
        assert!(!snapshot.capabilities.connection_control);
        assert!(!snapshot.capabilities.snapshot_coherence);
        assert!(!snapshot.capabilities.exit_selection);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn retries_when_the_daemon_restarts_between_snapshot_requests() {
        let directory = protected_tempdir();
        let path = directory.path().join("daemon.sock");
        let first = "1".repeat(32);
        let second = "2".repeat(32);
        let task = tokio::spawn(serve_fixture(
            path.clone(),
            8,
            vec![first, second.clone(), second.clone(), second.clone()],
        ));
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let snapshot = LocalDaemon::new(path).snapshot().await.unwrap();
        assert_eq!(snapshot.status.daemon_instance_id, second);
        assert!(snapshot.capabilities.snapshot_coherence);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn fails_closed_when_the_daemon_keeps_restarting() {
        let directory = protected_tempdir();
        let path = directory.path().join("daemon.sock");
        let task = tokio::spawn(serve_fixture(
            path.clone(),
            8,
            vec![
                "1".repeat(32),
                "2".repeat(32),
                "3".repeat(32),
                "4".repeat(32),
            ],
        ));
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            LocalDaemon::new(path).snapshot().await,
            Err(DaemonError::IncoherentSnapshot)
        ));
        task.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sends_only_the_bounded_exit_intent() {
        let directory = protected_tempdir();
        let path = directory.path().join("daemon.sock");
        let task = tokio::spawn(serve_fixture(path.clone(), 1, Vec::new()));
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        LocalDaemon::new(path)
            .set_exit(&ExitSelection {
                enabled: true,
                selected_node_id: "2".repeat(32),
            })
            .await
            .unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn refuses_regular_symlink_and_broadly_readable_endpoints() {
        let directory = protected_tempdir();
        let regular = directory.path().join("regular.sock");
        std::fs::write(&regular, b"not a socket").unwrap();
        assert!(matches!(
            validate_socket(&regular),
            Err(DaemonError::UntrustedSocket)
        ));

        let path = directory.path().join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(matches!(
            validate_socket(&path),
            Err(DaemonError::UntrustedSocket)
        ));
        drop(listener);

        let broad_parent = directory.path().join("broad");
        std::fs::create_dir(&broad_parent).unwrap();
        std::fs::set_permissions(&broad_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let broad_path = broad_parent.join("daemon.sock");
        let listener = std::os::unix::net::UnixListener::bind(&broad_path).unwrap();
        std::fs::set_permissions(&broad_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            validate_socket(&broad_path),
            Err(DaemonError::UntrustedSocket)
        ));
        drop(listener);

        let target = directory.path().join("target.sock");
        let listener = std::os::unix::net::UnixListener::bind(&target).unwrap();
        let link = directory.path().join("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            validate_socket(&link),
            Err(DaemonError::UntrustedSocket)
        ));
        drop(listener);
    }

    #[test]
    fn rejects_chunked_trailing_and_oversized_responses() {
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()),
            Err(DaemonError::InvalidResponse)
        ));
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}".to_vec()),
            Err(DaemonError::InvalidResponse)
        ));
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        )
        .into_bytes();
        assert!(matches!(
            parse_response(response),
            Err(DaemonError::OversizedResponse)
        ));
    }

    #[test]
    fn accepts_only_an_empty_lengthless_no_content_response() {
        let response = parse_response(
            b"HTTP/1.1 204 No Content\r\nDate: Wed, 19 Aug 2026 18:00:00 GMT\r\n\r\n".to_vec(),
        )
        .unwrap();
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());

        assert!(matches!(
            parse_response(b"HTTP/1.1 204 No Content\r\n\r\nx".to_vec()),
            Err(DaemonError::InvalidResponse)
        ));
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            Err(DaemonError::InvalidResponse)
        ));
        assert!(matches!(
            parse_response(b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx".to_vec()),
            Err(DaemonError::InvalidResponse)
        ));
    }

    #[test]
    fn validates_the_exit_intent_before_contacting_the_daemon() {
        assert!(
            validate_exit_selection(&ExitSelection {
                enabled: true,
                selected_node_id: "2".repeat(32),
            })
            .is_ok()
        );
        assert!(
            validate_exit_selection(&ExitSelection {
                enabled: false,
                selected_node_id: String::new(),
            })
            .is_ok()
        );
        assert!(matches!(
            validate_exit_selection(&ExitSelection {
                enabled: false,
                selected_node_id: "2".repeat(32),
            }),
            Err(DaemonError::InvalidExitSelection)
        ));
        for invalid in [
            "peer".to_owned(),
            "0".repeat(32),
            "2".repeat(33),
            "A".repeat(32),
        ] {
            assert!(matches!(
                validate_exit_selection(&ExitSelection {
                    enabled: true,
                    selected_node_id: invalid,
                }),
                Err(DaemonError::InvalidExitSelection)
            ));
        }
    }

    #[test]
    fn rejects_a_peer_from_another_uid() {
        assert!(verify_peer_uid(1000, 1000).is_ok());
        assert!(matches!(
            verify_peer_uid(1001, 1000),
            Err(DaemonError::UntrustedSocket)
        ));
        assert!(protected_owner_mode(1000, 0o600, 1000));
        assert!(!protected_owner_mode(1001, 0o600, 1000));
        assert!(!protected_owner_mode(1000, 0o660, 1000));
    }
}
