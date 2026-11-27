//! Narrow filesystem protocol for the separately installed host gateway worker.
use std::{
    fs, io,
    net::Ipv4Addr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::Failure;

fn spool() -> PathBuf {
    std::env::var_os("LANEWAY_GATEWAY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/laneway-gateways"))
}

fn tenant(database: &Path) -> Result<String, Failure> {
    let path = database.canonicalize().map_err(|_| Failure::Storage)?;
    Ok(hex::encode(Sha256::digest(path.as_os_str().as_bytes())))
}

fn fresh(timestamp: u64) -> bool {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|now| now.as_secs().checked_sub(timestamp))
        .is_some_and(|elapsed| elapsed < 90)
}

pub fn available(database: &Path) -> bool {
    tenant(database).is_ok()
        && fs::read(spool().join("status/heartbeat"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<u64>(&bytes).ok())
            .is_some_and(fresh)
}

#[derive(Serialize)]
struct Desired<'a> {
    generation: &'a str,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_key: Option<&'a serde_json::value::RawValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment_token: Option<&'a str>,
}

fn write(database: &Path, desired: Desired<'_>) -> Result<(), Failure> {
    let directory = spool().join("requests");
    let target = directory.join(tenant(database)?);
    let mut temporary = NamedTempFile::new_in(&directory).map_err(|_| Failure::Storage)?;
    serde_json::to_writer(&mut temporary, &desired).map_err(|_| Failure::Storage)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| Failure::Storage)?;
    temporary.persist(target).map_err(|_| Failure::Storage)?;
    fs::File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Failure::Storage)
}

pub fn enable(
    database: &Path,
    generation: &str,
    address: Ipv4Addr,
    port: u16,
    service_key: &str,
    enrollment_token: &str,
) -> Result<(), Failure> {
    let key = serde_json::from_str(service_key).map_err(|_| Failure::Storage)?;
    write(
        database,
        Desired {
            generation,
            enabled: true,
            address: Some(address),
            port: Some(port),
            service_key: Some(key),
            enrollment_token: Some(enrollment_token),
        },
    )
}

pub fn disable(database: &Path, generation: &str) -> Result<(), Failure> {
    write(
        database,
        Desired {
            generation,
            enabled: false,
            address: None,
            port: None,
            service_key: None,
            enrollment_token: None,
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeStatus {
    Starting,
    Online,
    Error,
    Disabled,
}

#[derive(Deserialize)]
struct Observed {
    generation: String,
    status: RuntimeStatus,
    updated_at: u64,
}

pub fn status(database: &Path, generation: &str) -> Result<RuntimeStatus, Failure> {
    let filename = spool().join("status").join(tenant(database)?);
    let bytes = match fs::read(filename) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RuntimeStatus::Starting);
        }
        Err(_) => return Err(Failure::Storage),
    };
    let state: Observed = serde_json::from_slice(&bytes).map_err(|_| Failure::Storage)?;
    if state.generation != generation {
        return Ok(RuntimeStatus::Starting);
    }
    if !fresh(state.updated_at) || !available(database) {
        return Ok(RuntimeStatus::Error);
    }
    Ok(state.status)
}
