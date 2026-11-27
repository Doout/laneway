use std::{
    collections::HashSet,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Subcommand;
use laneway_protocol::{
    Id,
    relay_endpoint::{MAX_RELAY_ENDPOINTS, canonical_host_port},
};
use reqwest::{Client, Url, header, redirect::Policy, tls::Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use x509_parser::parse_x509_certificate;

const DISCOVERY_PATH: &str = "/.well-known/laneway/bootstrap.json";
const MAX_DOCUMENT: usize = 256 << 10;
const MAX_ARTIFACT: u64 = 512 << 20;
const KNOWN_V1_CAPABILITIES: u64 = (1 << 8) - 1;

#[derive(Subcommand)]
pub(super) enum Operation {
    /// Inspect public discovery and select this platform's artifact.
    Inspect { domain: String },
    /// Save a verified artifact to a new file.
    Download {
        domain: String,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    schema_version: u32,
    generated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    pub(super) network_id: String,
    pub(super) controller: Controller,
    pub(super) relays: Vec<Relay>,
    pub(super) trust: Trust,
    protocol: Protocol,
    #[serde(default)]
    artifacts: Option<Vec<Artifact>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Controller {
    pub(super) enrollment_endpoint: String,
    pub(super) quic_endpoint: String,
    pub(super) server_name: String,
    pub(super) service_id: String,
}

impl Controller {
    pub(super) fn config(&self) -> lanewayd_rs::ControllerConfig {
        lanewayd_rs::ControllerConfig {
            topology_reporting: false,
            auto_renew_certificate: false,
            disable_status_reporting: false,
            private_dns_listen: None,
            endpoint: self.enrollment_endpoint.clone(),
            quic_endpoint: Some(self.quic_endpoint.clone()),
            server_name: self.server_name.clone(),
            service_id: self.service_id.clone(),
            poll_interval: Duration::from_secs(5),
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Relay {
    name: String,
    pub(super) endpoint: String,
    pub(super) service_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Trust {
    pub(super) ca_pem: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Protocol {
    control_major: u32,
    control_minor: u32,
    packet_versions: Vec<u32>,
    capabilities: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    os: String,
    arch: String,
    url: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Serialize)]
struct Inspection<'a> {
    metadata: &'a Metadata,
    current_platform_artifact: &'a Artifact,
}

pub(super) async fn run(operation: Operation) -> Result<()> {
    let domain = match &operation {
        Operation::Inspect { domain } | Operation::Download { domain, .. } => domain,
    };
    let metadata = fetch(domain).await?;
    let artifact = metadata.current_artifact()?;
    match operation {
        Operation::Inspect { .. } => {
            let mut out = std::io::stdout().lock();
            serde_json::to_writer_pretty(
                &mut out,
                &Inspection {
                    metadata: &metadata,
                    current_platform_artifact: artifact,
                },
            )?;
            writeln!(out)?;
        }
        Operation::Download { out, .. } => {
            download(artifact, &out).await?;
            println!(
                "verified artifact {}/{} sha256={} path={}",
                artifact.os,
                artifact.arch,
                artifact.sha256,
                out.display()
            );
        }
    }
    Ok(())
}

pub(super) async fn discover(domain: &str) -> Result<()> {
    serde_json::to_writer(std::io::stdout().lock(), &fetch(domain).await?)?;
    Ok(())
}

fn client(deadline: Duration, redirects: Policy) -> Result<Client> {
    let roots = rustls_native_certs::load_native_certs();
    ensure!(
        !roots.certs.is_empty(),
        "no native HTTPS trust roots available: {:?}",
        roots.errors
    );
    let mut builder = Client::builder()
        .https_only(true)
        .min_tls_version(Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .connect_timeout(Duration::from_secs(10))
        .timeout(deadline)
        .redirect(redirects);
    for root in roots.certs {
        builder = builder.add_root_certificate(reqwest::Certificate::from_der(root.as_ref())?);
    }
    Ok(builder.build()?)
}

pub(super) fn discovery_url(domain: &str) -> Result<Url> {
    let mut url = origin(&if domain.contains("://") {
        domain.to_owned()
    } else {
        format!("https://{domain}")
    })?;
    let host = url.host_str().context("bootstrap requires a DNS name")?;
    ensure!(
        dns_name(&host.trim_end_matches('.').to_ascii_lowercase()),
        "bootstrap requires a DNS name authenticated by public Web PKI"
    );
    url.set_path(DISCOVERY_PATH);
    Ok(url)
}

pub(super) async fn fetch(domain: &str) -> Result<Metadata> {
    let url = discovery_url(domain)?;
    let mut response = client(Duration::from_secs(15), Policy::none())?
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("fetch bootstrap metadata")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "bootstrap metadata endpoint returned HTTP {}",
        response.status().as_u16()
    );
    ensure!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|kind| {
                kind.to_str().is_ok_and(|kind| {
                    kind.split(';')
                        .next()
                        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
                })
            }),
        "bootstrap metadata response is not application/json"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= MAX_DOCUMENT - bytes.len(),
            "bootstrap metadata exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Metadata::decode(&bytes, now)
}

fn https_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid HTTPS URL")?;
    let authority = value
        .strip_prefix("https://")
        .and_then(|rest| rest.split(['/', '?', '#']).next());
    ensure!(
        authority.is_some_and(|host| !host.is_empty() && host.is_ascii() && !host.contains('@'))
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && !value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\'),
        "expected authenticated HTTPS without credentials or fragment"
    );
    Ok(url)
}

fn origin(value: &str) -> Result<Url> {
    let url = https_url(value)?;
    let rest = value
        .strip_prefix("https://")
        .context("expected HTTPS origin")?;
    ensure!(
        !rest.contains('?')
            && rest
                .split_once('/')
                .is_none_or(|(_, suffix)| suffix.is_empty()),
        "expected an HTTPS origin"
    );
    Ok(url)
}

fn dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

impl Metadata {
    pub(super) fn decode(bytes: &[u8], now: u64) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DOCUMENT,
            "bootstrap metadata exceeds size limit"
        );
        let metadata: Self = serde_json::from_slice(bytes).context("decode bootstrap metadata")?;
        ensure!(
            metadata.schema_version == 1,
            "unsupported bootstrap schema version"
        );
        let generated = metadata.generated_at_unix_seconds;
        let expires = metadata.valid_until_unix_seconds;
        ensure!(
            generated <= now.saturating_add(120)
                && expires > now
                && matches!(expires.checked_sub(generated), Some(1..=600)),
            "bootstrap metadata validity window is invalid or expired"
        );
        metadata
            .network_id
            .parse::<Id>()
            .context("invalid bootstrap network identity")?;
        metadata
            .controller
            .service_id
            .parse::<Id>()
            .context("invalid bootstrap controller identity")?;
        origin(&metadata.controller.enrollment_endpoint)
            .context("invalid bootstrap enrollment endpoint")?;
        ensure!(
            dns_name(&metadata.controller.server_name)
                && canonical_host_port(&metadata.controller.quic_endpoint).is_some(),
            "invalid bootstrap controller server name or QUIC endpoint"
        );
        ensure!(
            (1..=MAX_RELAY_ENDPOINTS).contains(&metadata.relays.len()),
            "invalid bootstrap relay count"
        );
        let mut relays = HashSet::new();
        for relay in &metadata.relays {
            let identity = relay
                .service_id
                .parse::<Id>()
                .context("invalid bootstrap relay identity")?;
            ensure!(
                !relay.name.is_empty()
                    && relay.name.trim() == relay.name
                    && relay.name.len() <= 253
                    && canonical_host_port(&relay.endpoint).as_deref()
                        == Some(relay.endpoint.as_str())
                    && relays.insert((identity, &relay.endpoint)),
                "invalid or duplicate bootstrap relay"
            );
        }
        validate_ca(&metadata.trust.ca_pem)?;
        ensure!(
            metadata.protocol.control_major == 1
                && metadata.protocol.packet_versions.contains(&1)
                && metadata.protocol.capabilities & !KNOWN_V1_CAPABILITIES == 0,
            "unsupported bootstrap protocol declaration"
        );
        let artifacts = metadata.artifacts.as_deref().unwrap_or_default();
        ensure!(artifacts.len() <= 16, "too many bootstrap artifacts");
        let mut platforms = HashSet::new();
        for artifact in artifacts {
            artifact.validate()?;
            ensure!(
                platforms.insert((&artifact.os, &artifact.arch)),
                "duplicate bootstrap artifact platform"
            );
        }
        Ok(metadata)
    }

    pub(super) fn current_artifact(&self) -> Result<&Artifact> {
        let os = if cfg!(target_os = "macos") {
            "darwin"
        } else {
            std::env::consts::OS
        };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        self.artifacts
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|artifact| artifact.os == os && artifact.arch == arch)
            .with_context(|| format!("no verified artifact for {os}/{arch}"))
    }
}

fn validate_ca(mut pem: &str) -> Result<()> {
    ensure!(
        pem.len() <= 128 << 10,
        "bootstrap CA bundle exceeds size limit"
    );
    let mut count = 0;
    while !pem.trim().is_empty() {
        let (body, rest) = pem
            .trim_start()
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .and_then(|certificate| certificate.split_once("-----END CERTIFICATE-----"))
            .context("invalid PEM in bootstrap CA bundle")?;
        let encoded: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let der = STANDARD.decode(encoded).context("decode bootstrap CA")?;
        let (trailing, certificate) = parse_x509_certificate(&der)
            .map_err(|_| anyhow::anyhow!("invalid bootstrap CA certificate"))?;
        ensure!(
            trailing.is_empty()
                && certificate
                    .basic_constraints()?
                    .is_some_and(|ext| ext.value.ca),
            "bootstrap trust bundle contains a non-CA certificate"
        );
        count += 1;
        ensure!(count <= 8, "too many bootstrap trust authorities");
        pem = rest;
    }
    ensure!(count > 0, "bootstrap CA bundle is empty");
    Ok(())
}

impl Artifact {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.os.as_str(), "linux" | "darwin")
                && matches!(self.arch.as_str(), "amd64" | "arm64"),
            "unsupported bootstrap artifact platform"
        );
        https_url(&self.url).context("invalid bootstrap artifact URL")?;
        ensure!(
            self.sha256.len() == 64
                && self
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "bootstrap artifact SHA-256 is not canonical"
        );
        ensure!(
            (1..=MAX_ARTIFACT).contains(&self.size_bytes),
            "invalid bootstrap artifact size"
        );
        Ok(())
    }
}

struct Download<'a> {
    artifact: &'a Artifact,
    file: NamedTempFile,
    hasher: Sha256,
    remaining: u64,
}

impl<'a> Download<'a> {
    fn new(artifact: &'a Artifact, destination: &Path) -> Result<Self> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty());
        let file = NamedTempFile::new_in(parent.unwrap_or_else(|| Path::new(".")))
            .context("create temporary bootstrap artifact")?;
        Ok(Self {
            artifact,
            file,
            hasher: Sha256::new(),
            remaining: artifact.size_bytes,
        })
    }

    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(chunk.len() as u64)
            .context("bootstrap artifact exceeds authenticated size")?;
        self.file
            .write_all(chunk)
            .context("write bootstrap artifact")?;
        self.hasher.update(chunk);
        Ok(())
    }

    fn publish(self, destination: &Path) -> Result<()> {
        ensure!(
            self.remaining == 0,
            "bootstrap artifact is smaller than authenticated size"
        );
        ensure!(
            hex::encode(self.hasher.finalize()) == self.artifact.sha256,
            "bootstrap artifact SHA-256 does not match authenticated metadata"
        );
        self.file
            .as_file()
            .sync_all()
            .context("sync bootstrap artifact")?;
        self.file
            .persist_noclobber(destination)
            .context("publish verified bootstrap artifact without overwrite")?;
        Ok(())
    }
}

async fn download(artifact: &Artifact, destination: &Path) -> Result<()> {
    ensure!(
        destination.file_name().is_some(),
        "bootstrap artifact destination must name a file"
    );
    match destination.symlink_metadata() {
        Ok(_) => anyhow::bail!("bootstrap artifact destination already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect bootstrap artifact destination"),
    }
    let redirects = Policy::custom(|attempt| {
        if attempt.previous().len() < 5 && https_url(attempt.url().as_str()).is_ok() {
            attempt.follow()
        } else {
            attempt.error("unsafe or excessive bootstrap artifact redirect")
        }
    });
    let mut response = client(Duration::from_secs(300), redirects)?
        .get(&artifact.url)
        .header(header::ACCEPT, "application/octet-stream")
        .send()
        .await
        .context("download bootstrap artifact")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "bootstrap artifact download returned HTTP {}",
        response.status().as_u16()
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= artifact.size_bytes),
        "bootstrap artifact response exceeds authenticated size"
    );
    let mut output = Download::new(artifact, destination)?;
    while let Some(chunk) = response.chunk().await? {
        output.write(&chunk)?;
    }
    output.publish(destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use serde_json::json;

    fn discovery() -> serde_json::Value {
        let mut ca = CertificateParams::new(vec![]).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca.self_signed(&KeyPair::generate().unwrap()).unwrap();
        let id = |byte| Id::new([byte; 16]).unwrap().to_string();
        json!({
            "schema_version": 1,
            "generated_at_unix_seconds": 1200,
            "valid_until_unix_seconds": 1500,
            "network_id": id(1),
            "controller": {
                "enrollment_endpoint": "https://control.example.test",
                "quic_endpoint": "control.example.test:443",
                "server_name": "control.example.test",
                "service_id": id(2)
            },
            "relays": [{
                "name": "relay",
                "endpoint": "relay.example.test:443",
                "service_id": id(3)
            }],
            "trust": { "ca_pem": ca.pem() },
            "protocol": {
                "control_major": 1, "control_minor": 0, "packet_versions": [1], "capabilities": 255
            },
            "artifacts": [{
                "os": "linux", "arch": "amd64",
                "url": "https://releases.example.test/laneway_linux_amd64.tar.gz",
                "size_bytes": 3, "sha256": hex::encode(Sha256::digest(b"abc"))
            }]
        })
    }

    #[test]
    fn validates_discovery_before_trusting_credentials_or_artifacts() {
        let valid = discovery();
        let decode =
            |value: &serde_json::Value| Metadata::decode(&serde_json::to_vec(value).unwrap(), 1300);
        assert!(decode(&valid).is_ok());
        for (path, invalid) in [
            ("/valid_until_unix_seconds", json!(1299)),
            (
                "/controller/enrollment_endpoint",
                json!("https://control.example.test/path/.."),
            ),
            ("/controller/server_name", json!("127.0.0.1")),
            ("/relays/0/endpoint", json!("Relay.example.test:443")),
            ("/protocol/capabilities", json!(256)),
            (
                "/trust/ca_pem",
                json!("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----"),
            ),
            (
                "/artifacts/0/url",
                json!("https://user@releases.example.test/archive"),
            ),
            ("/artifacts/0/size_bytes", json!(MAX_ARTIFACT + 1)),
        ] {
            let mut value = valid.clone();
            *value.pointer_mut(path).unwrap() = invalid;
            assert!(decode(&value).is_err(), "{path}");
        }
        let mut duplicate = valid.clone();
        duplicate["artifacts"]
            .as_array_mut()
            .unwrap()
            .push(valid["artifacts"][0].clone());
        assert!(decode(&duplicate).is_err());
    }

    #[test]
    fn verifies_length_and_digest_before_exclusive_publication() -> Result<()> {
        let metadata = Metadata::decode(&serde_json::to_vec(&discovery())?, 1300)?;
        let artifact = &metadata.artifacts.unwrap()[0];
        let directory = tempfile::tempdir()?;
        let destination = directory.path().join("archive");
        for bytes in [b"wrong".as_slice(), b"ab", b"abd"] {
            let mut output = Download::new(artifact, &destination)?;
            assert!(
                output
                    .write(bytes)
                    .and_then(|()| output.publish(&destination))
                    .is_err()
            );
            assert!(!destination.exists());
        }
        let publish = || {
            let mut output = Download::new(artifact, &destination)?;
            output.write(b"a")?;
            output.write(b"bc")?;
            output.publish(&destination)
        };
        publish()?;
        assert!(publish().is_err());
        assert_eq!(std::fs::read(&destination)?, b"abc");
        assert_eq!(directory.path().read_dir()?.count(), 1);
        Ok(())
    }
}
