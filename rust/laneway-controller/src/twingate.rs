//! Twingate Admin API verification and controller-local credential storage.

use std::{
    fs::{self, DirBuilder, File},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reqwest::{Client, StatusCode, header::HeaderValue, redirect::Policy};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, IgnoredAny},
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub mod actuator;
pub mod gateway;
pub mod provider;
mod resources;
pub use resources::{list_resources, valid_cursor};

const MAX_INPUT_BYTES: u64 = 32 * 1024;
const MAX_API_BYTES: u64 = 64 * 1024;
const NETWORK_QUERY: &str = "{ remoteNetworks(first: 1) { edges { node { id } } } }";

/// Public connection metadata. Credentials are never part of the reply.
#[derive(Serialize)]
pub struct ConnectionStatus {
    tenant: Option<String>,
    verified_at_unix_seconds: Option<u64>,
}

/// Stable failure codes for the controller's authenticated transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    InvalidTenant,
    InvalidToken,
    Rejected,
    RateLimited,
    Unavailable,
    NotConnected,
    ConnectionChanged,
    GatewayConflict,
    GatewayBusy,
    GatewayChanged,
    GatewayUnsupported,
    GatewayUnavailable,
    GatewayRoute,
    Storage,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    tenant: String,
    #[serde(
        serialize_with = "serialize_token",
        deserialize_with = "deserialize_token"
    )]
    api_token: Zeroizing<String>,
}

fn serialize_token<S: serde::Serializer>(token: &str, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(token)
}

fn deserialize_token<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl Credentials {
    pub fn validated(self) -> Result<Self, Failure> {
        let mut credentials = self;
        credentials.tenant = credentials.tenant.trim().to_ascii_lowercase();
        credentials.api_token = Zeroizing::new(credentials.api_token.trim().to_owned());
        validate_tenant(&credentials.tenant)?;
        token_header(&credentials.api_token)?;
        Ok(credentials)
    }
}

#[derive(Deserialize, Serialize)]
pub struct Connection {
    credentials: Credentials,
    verified_at_unix_seconds: u64,
}

impl Connection {
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    fn status(&self) -> ConnectionStatus {
        ConnectionStatus {
            tenant: Some(self.credentials.tenant.clone()),
            verified_at_unix_seconds: Some(self.verified_at_unix_seconds),
        }
    }
}

/// Each storage operation is scoped to the caller's controller database.
/// Mutations require same-origin CSRF proof established at the HTTP boundary.
pub enum OwnerAccess<'a> {
    Read,
    Write(Option<&'a str>),
}

impl crate::SessionStore {
    pub fn with_twingate_owner<T>(
        &mut self,
        token: &str,
        access: OwnerAccess<'_>,
        action: impl FnOnce() -> T,
    ) -> anyhow::Result<crate::SessionReply<T>> {
        self.with_session(token, true, |tx, principal, session, _, _| {
            match access {
                OwnerAccess::Read => {
                    let owner: bool = tx.query_row(
                        "SELECT role='owner' FROM administrator_principals WHERE id=?1",
                        [principal.as_bytes()],
                        |row| row.get(0),
                    )?;
                    anyhow::ensure!(owner, crate::SessionError::Denied);
                }
                OwnerAccess::Write(csrf) => {
                    crate::management_write::verify_browser_write(tx, session, csrf, false)?;
                }
            }
            Ok(action())
        })
    }
}

fn disconnected() -> ConnectionStatus {
    ConnectionStatus {
        tenant: None,
        verified_at_unix_seconds: None,
    }
}

fn verification_time() -> Result<u64, Failure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Failure::Storage)
}

fn validate_tenant(tenant: &str) -> Result<(), Failure> {
    let valid = (1..=63).contains(&tenant.len())
        && !tenant.starts_with('-')
        && !tenant.ends_with('-')
        && tenant
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    valid.then_some(()).ok_or(Failure::InvalidTenant)
}

fn token_header(token: &str) -> Result<HeaderValue, Failure> {
    if !(1..=4096).contains(&token.len()) || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(Failure::InvalidToken);
    }
    let mut header = HeaderValue::from_str(token).map_err(|_| Failure::InvalidToken)?;
    header.set_sensitive(true);
    Ok(header)
}

pub async fn verify(credentials: &Credentials) -> Result<(), Failure> {
    let bytes = graphql(credentials, NETWORK_QUERY, Value::Null, MAX_API_BYTES).await?;
    check_graphql(&bytes)
}

async fn graphql(
    credentials: &Credentials,
    query: &str,
    variables: Value,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    validate_tenant(&credentials.tenant)?;
    let key = token_header(&credentials.api_token)?;
    let client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| Failure::Unavailable)?;
    let mut payload = json!({ "query": query });
    if !variables.is_null() {
        payload["variables"] = variables;
    }
    let mut reply = client
        .post(format!(
            "https://{}.twingate.com/api/graphql/",
            credentials.tenant
        ))
        .header("x-api-key", key)
        .header("content-type", "application/json")
        .body(payload.to_string())
        .send()
        .await
        .map_err(|_| Failure::Unavailable)?;
    check_http_status(reply.status())?;

    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = reply.chunk().await.map_err(|_| Failure::Unavailable)? {
        if chunk.len() as u64 > max_bytes - bytes.len() as u64 {
            return Err(Failure::Unavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn check_http_status(status: StatusCode) -> Result<(), Failure> {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(Failure::Rejected),
        StatusCode::TOO_MANY_REQUESTS => Err(Failure::RateLimited),
        _ if !status.is_success() => Err(Failure::Unavailable),
        _ => Ok(()),
    }
}

fn graphql_data<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Failure> {
    #[derive(Deserialize)]
    struct GraphQlReply<T> {
        data: Option<T>,
        errors: Option<Vec<IgnoredAny>>,
    }
    let response: GraphQlReply<T> =
        serde_json::from_slice(bytes).map_err(|_| Failure::Unavailable)?;
    if response.errors.is_some_and(|errors| !errors.is_empty()) {
        return Err(Failure::Rejected);
    }
    response.data.ok_or(Failure::Unavailable)
}

fn check_graphql(bytes: &[u8]) -> Result<(), Failure> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct GraphQlData {
        remote_networks: Option<RemoteNetworks>,
    }
    #[derive(Deserialize)]
    struct RemoteNetworks {
        #[serde(rename = "edges")]
        _edges: Vec<IgnoredAny>,
    }
    graphql_data::<GraphQlData>(bytes)?
        .remote_networks
        .map(|_| ())
        .ok_or(Failure::Unavailable)
}

fn read_bounded(reader: impl Read, limit: u64) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("Twingate payload exceeds its limit"));
    }
    Ok(bytes)
}

pub struct Storage(PathBuf);

impl Storage {
    pub fn for_database(database: &Path) -> Self {
        let mut directory = database.as_os_str().to_os_string();
        directory.push(".integrations");
        Self(PathBuf::from(directory))
    }

    pub fn status(&self) -> Result<ConnectionStatus, Failure> {
        self.with_lock(|store| {
            Ok(store
                .read()?
                .as_ref()
                .map_or_else(disconnected, Connection::status))
        })
    }

    pub fn saved(&self) -> Result<Connection, Failure> {
        self.with_lock(|store| store.read()?.ok_or(Failure::NotConnected))
    }

    pub fn save(&self, credentials: Credentials) -> Result<ConnectionStatus, Failure> {
        let saved = Connection {
            credentials,
            verified_at_unix_seconds: verification_time()?,
        };
        self.with_lock(|store| {
            if store.binding()?.is_some()
                && store
                    .read()?
                    .is_none_or(|previous| previous.credentials.tenant != saved.credentials.tenant)
            {
                return Err(Failure::GatewayConflict);
            }
            store.write(&saved)
        })?;
        Ok(saved.status())
    }

    pub fn ensure_current(&self, checked: &Connection) -> Result<(), Failure> {
        self.with_lock(|store| store.current_connection(checked).map(|_| ()))
    }

    fn current_connection(&self, checked: &Connection) -> Result<Connection, Failure> {
        let current = self.read()?.ok_or(Failure::ConnectionChanged)?;
        if current.credentials.tenant != checked.credentials.tenant
            || *current.credentials.api_token != *checked.credentials.api_token
        {
            return Err(Failure::ConnectionChanged);
        }
        Ok(current)
    }

    pub fn confirm(&self, checked: Connection) -> Result<ConnectionStatus, Failure> {
        self.with_lock(|store| {
            let mut current = store.current_connection(&checked)?;
            current.verified_at_unix_seconds =
                current.verified_at_unix_seconds.max(verification_time()?);
            store.write(&current)?;
            Ok(current.status())
        })
    }

    pub fn disconnect(&self) -> Result<ConnectionStatus, Failure> {
        self.with_lock(|store| {
            store.require_gateway_disabled()?;
            store.remove()
        })?;
        Ok(disconnected())
    }

    fn with_lock<T>(&self, action: impl FnOnce(&Self) -> Result<T, Failure>) -> Result<T, Failure> {
        let directory = &self.0;
        match DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => File::open(directory.parent().ok_or(Failure::Storage)?)
                .and_then(|parent| parent.sync_all())
                .map_err(|_| Failure::Storage)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Failure::Storage),
        }
        let metadata = fs::symlink_metadata(directory).map_err(|_| Failure::Storage)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Failure::Storage);
        }
        let lock = open(
            directory.join("twingate.lock"),
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|_| Failure::Storage)?;
        let metadata = lock.metadata().map_err(|_| Failure::Storage)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Failure::Storage);
        }
        flock(&lock, FlockOperation::LockExclusive).map_err(|_| Failure::Storage)?;
        action(self)
    }

    fn path(&self) -> PathBuf {
        self.0.join("twingate.json")
    }

    fn read(&self) -> Result<Option<Connection>, Failure> {
        self.read_json(&self.path())
    }

    fn read_json<T: DeserializeOwned>(&self, path: &Path) -> Result<Option<T>, Failure> {
        let file = match open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(Failure::Storage),
        };
        let metadata = file.metadata().map_err(|_| Failure::Storage)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Failure::Storage);
        }
        let bytes = read_bounded(file, MAX_INPUT_BYTES).map_err(|_| Failure::Storage)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Failure::Storage)
    }

    fn write(&self, connection: &Connection) -> Result<(), Failure> {
        self.write_json(&self.path(), connection)
    }

    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<(), Failure> {
        let mut temp = tempfile::NamedTempFile::new_in(&self.0).map_err(|_| Failure::Storage)?;
        serde_json::to_writer(&mut temp, value).map_err(|_| Failure::Storage)?;
        temp.flush().map_err(|_| Failure::Storage)?;
        temp.as_file().sync_all().map_err(|_| Failure::Storage)?;
        temp.persist(path).map_err(|_| Failure::Storage)?;
        self.sync_directory()
    }

    fn remove(&self) -> Result<(), Failure> {
        match fs::remove_file(self.path()) {
            Ok(()) => self.sync_directory(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Failure::Storage),
        }
    }

    fn sync_directory(&self) -> Result<(), Failure> {
        File::open(&self.0)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Failure::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(tenant: &str, token: &str) -> Credentials {
        Credentials {
            tenant: tenant.into(),
            api_token: Zeroizing::new(token.into()),
        }
        .validated()
        .unwrap()
    }

    #[test]
    fn storage_is_per_database_and_reports_only_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let first = Storage::for_database(&temp.path().join("first.db"));
        let second = Storage::for_database(&temp.path().join("second.db"));
        let first_token = "test-token";
        first.save(credentials("first", first_token)).unwrap();
        let status = serde_json::to_string(&first.status().unwrap()).unwrap();
        assert!(status.contains("first"));
        assert!(!status.contains(first_token));
        assert!(second.status().unwrap().tenant.is_none());
        assert_eq!(
            fs::metadata(first.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let checked = first.saved().unwrap();
        first.disconnect().unwrap();
        assert_eq!(
            first.confirm(checked).err(),
            Some(Failure::ConnectionChanged)
        );
        assert!(first.status().unwrap().tenant.is_none());
    }

    #[test]
    fn guards_the_request_host_and_requires_graphql_data() {
        for tenant in ["twingate.com", "x@host", "x:443", "-x", "x/", ""] {
            assert_eq!(validate_tenant(tenant), Err(Failure::InvalidTenant));
        }
        assert_eq!(token_header("abc\r\ndef"), Err(Failure::InvalidToken));
        assert_eq!(
            check_http_status(StatusCode::FORBIDDEN),
            Err(Failure::Rejected)
        );
        assert_eq!(
            check_http_status(StatusCode::FOUND),
            Err(Failure::Unavailable)
        );
        assert_eq!(
            check_graphql(br#"{"errors":[{"message":"invalid token"}]}"#),
            Err(Failure::Rejected)
        );
        assert_eq!(
            check_graphql(br#"{"data":{"remoteNetworks":{"edges":[]}}}"#),
            Ok(())
        );
        assert_eq!(
            check_graphql(br#"{"data":{"remoteNetworks":null}}"#),
            Err(Failure::Unavailable)
        );
    }
}
