use std::{
    collections::HashSet,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};
use x509_parser::parse_x509_certificate;

const LIFETIME: i64 = 600;
const CLOCK_SKEW: i64 = 120;
const MAX_RELAYS: usize = 32;
const MAX_ARTIFACTS: usize = 16;
const MAX_CA_BYTES: usize = 128 << 10;
const MAX_CA_CERTIFICATES: usize = 8;
const KNOWN_CAPABILITIES: u64 = 0xff;
pub(super) const MAX_DOCUMENT_BYTES: u64 = 256 << 10;
pub(super) const MAX_ARTIFACT_BYTES: i64 = 512 << 20;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Metadata {
    pub schema_version: u32,
    #[serde(rename = "generated_at_unix_seconds")]
    pub generated_at: i64,
    #[serde(rename = "valid_until_unix_seconds")]
    pub valid_until: i64,
    pub network_id: String,
    pub controller: Controller,
    pub relays: Vec<Relay>,
    pub trust: Trust,
    pub protocol: Protocol,
    #[serde(deserialize_with = "optional_vec")]
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Controller {
    pub enrollment_endpoint: String,
    pub quic_endpoint: String,
    pub server_name: String,
    pub service_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Relay {
    pub name: String,
    pub endpoint: String,
    pub service_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Trust {
    pub ca_pem: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Protocol {
    pub control_major: u32,
    pub control_minor: u32,
    #[serde(rename = "packet_versions")]
    pub packet: Vec<u32>,
    pub capabilities: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Artifact {
    pub os: String,
    pub arch: String,
    pub url: String,
    pub sha256: String,
    pub size_bytes: i64,
}

fn optional_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

impl Metadata {
    pub(crate) fn validate(&self, now_unix: i64) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "bootstrap: unsupported schema version {}",
            self.schema_version
        );
        ensure!(
            self.generated_at <= now_unix.saturating_add(CLOCK_SKEW)
                && self.valid_until > now_unix
                && self
                    .valid_until
                    .checked_sub(self.generated_at)
                    .is_some_and(|seconds| (1..=LIFETIME).contains(&seconds)),
            "bootstrap: metadata validity window is invalid or expired"
        );
        ensure!(
            valid_identity(&self.network_id),
            "bootstrap: invalid network identity"
        );
        https_origin(&self.controller.enrollment_endpoint)
            .context("bootstrap: controller enrollment endpoint")?;
        canonical_host_port(&self.controller.quic_endpoint)
            .context("bootstrap: invalid controller QUIC endpoint")?;
        validate_dns_name(&self.controller.server_name)
            .context("bootstrap: controller server name")?;
        ensure!(
            valid_identity(&self.controller.service_id),
            "bootstrap: invalid controller service identity"
        );
        ensure!(
            (1..=MAX_RELAYS).contains(&self.relays.len()),
            "bootstrap: relay count must be from 1 through {MAX_RELAYS}"
        );
        let mut relays = HashSet::new();
        for relay in &self.relays {
            ensure!(
                !relay.name.is_empty()
                    && relay.name == relay.name.trim()
                    && relay.name.len() <= 253,
                "bootstrap: invalid relay name"
            );
            ensure!(
                canonical_host_port(&relay.endpoint).as_deref().ok()
                    == Some(relay.endpoint.as_str()),
                "bootstrap: invalid or noncanonical relay endpoint"
            );
            ensure!(
                valid_identity(&relay.service_id),
                "bootstrap: invalid relay service identity"
            );
            ensure!(
                relays.insert((&relay.service_id, &relay.endpoint)),
                "bootstrap: duplicate relay identity and endpoint"
            );
        }
        validate_trust(&self.trust.ca_pem)?;
        ensure!(
            self.protocol.control_major == 1
                && self.protocol.packet.contains(&1)
                && self.protocol.capabilities & !KNOWN_CAPABILITIES == 0,
            "bootstrap: unsupported or invalid protocol declaration"
        );
        ensure!(
            self.artifacts.len() <= MAX_ARTIFACTS,
            "bootstrap: artifact set is unbounded"
        );
        let mut platforms = HashSet::new();
        for artifact in &self.artifacts {
            ensure!(
                matches!(artifact.os.as_str(), "linux" | "darwin")
                    && matches!(artifact.arch.as_str(), "amd64" | "arm64"),
                "bootstrap: unsupported artifact platform"
            );
            artifact.url()?;
            artifact.expected_digest()?;
            artifact.expected_size()?;
            ensure!(
                platforms.insert((&artifact.os, &artifact.arch)),
                "bootstrap: duplicate artifact platform"
            );
        }
        Ok(())
    }

    pub(crate) fn artifact_for_current_platform(&self) -> Result<&Artifact> {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        self.artifacts
            .iter()
            .find(|artifact| artifact.os == os && artifact.arch == arch)
            .with_context(|| format!("bootstrap: no verified artifact for {os}/{arch}"))
    }
}

impl Artifact {
    pub(super) fn url(&self) -> Result<Url> {
        let parsed = Url::parse(&self.url).context("bootstrap: invalid artifact URL")?;
        ensure!(
            valid_https_url(&parsed) && parsed.fragment().is_none(),
            "bootstrap: artifact URL must be an HTTPS URL without credentials or fragment"
        );
        let authority = https_authority(&self.url)
            .context("bootstrap: artifact URL must use HTTPS")?
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        ensure!(
            !authority.is_empty() && !authority.contains('@') && !authority.contains('\\'),
            "bootstrap: artifact URL must be an HTTPS URL without credentials or fragment"
        );
        Ok(parsed)
    }

    pub(super) fn expected_size(&self) -> Result<u64> {
        ensure!(
            (1..=MAX_ARTIFACT_BYTES).contains(&self.size_bytes),
            "bootstrap: artifact size is invalid"
        );
        Ok(self.size_bytes as u64)
    }

    pub(super) fn expected_digest(&self) -> Result<[u8; 32]> {
        ensure!(
            self.sha256.bytes().all(lower_hex),
            "bootstrap: artifact SHA-256 is not canonical"
        );
        let mut digest = [0; 32];
        hex::decode_to_slice(&self.sha256, &mut digest)
            .context("bootstrap: artifact SHA-256 is not canonical")?;
        Ok(digest)
    }
}

pub(super) fn decode(reader: impl Read, now_unix: i64) -> Result<Metadata> {
    let mut data = Vec::new();
    reader
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut data)
        .context("bootstrap: read metadata")?;
    ensure!(
        data.len() as u64 <= MAX_DOCUMENT_BYTES,
        "bootstrap: metadata exceeds size limit"
    );
    let metadata: Metadata = serde_json::from_slice(&data).context("bootstrap: decode metadata")?;
    metadata.validate(now_unix)?;
    Ok(metadata)
}

pub(super) fn now_unix() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

pub(super) fn https_origin(value: &str) -> Result<(&str, Url)> {
    // Check the original URL before Url normalizes paths, ports or backslashes.
    let authority = https_authority(value).context("must be an HTTPS origin")?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    ensure!(
        !authority.is_empty()
            && !authority.contains(['/', '\\', '?', '#', '@'])
            && !authority.chars().any(char::is_whitespace),
        "must be an HTTPS origin"
    );
    let parsed = Url::parse(value).context("must be an HTTPS origin")?;
    ensure!(valid_https_url(&parsed), "must be an HTTPS origin");
    Ok((authority, parsed))
}

fn https_authority(value: &str) -> Option<&str> {
    let (scheme, rest) = value.split_once("://")?;
    scheme.eq_ignore_ascii_case("https").then_some(rest)
}

pub(super) fn valid_https_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn valid_identity(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(lower_hex) && value.bytes().any(|b| b != b'0')
}

pub(super) fn validate_dns_name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.parse::<IpAddr>().is_err()
            && value.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')),
        "must be a canonical ASCII DNS name"
    );
    Ok(())
}

fn canonical_host_port(value: &str) -> Result<String> {
    let (host, port) = value.rsplit_once(':').context("missing endpoint port")?;
    ensure!(
        port.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid endpoint port"
    );
    let port = port.parse::<u16>().context("invalid endpoint port")?;
    ensure!(port != 0, "invalid endpoint port");
    let bracketed = host.starts_with('[') && host.ends_with(']');
    let host = if bracketed {
        &host[1..host.len() - 1]
    } else {
        host
    };
    ensure!(
        bracketed || !host.contains(':'),
        "IPv6 endpoints must be bracketed"
    );
    match host.parse::<IpAddr>() {
        Ok(ip) => {
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast(),
                "invalid unicast endpoint"
            );
            match ip {
                IpAddr::V4(ip) => {
                    ensure!(ip != Ipv4Addr::BROADCAST, "invalid broadcast endpoint");
                    Ok(format!("{ip}:{port}"))
                }
                IpAddr::V6(ip) => {
                    ensure!(ip.to_ipv4_mapped().is_none(), "invalid mapped endpoint");
                    Ok(format!("[{ip}]:{port}"))
                }
            }
        }
        Err(_) => {
            let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
            validate_dns_name(&host)?;
            Ok(format!("{host}:{port}"))
        }
    }
}

fn validate_trust(mut pem: &str) -> Result<()> {
    ensure!(
        !pem.is_empty() && pem.len() <= MAX_CA_BYTES,
        "bootstrap: CA bundle is empty or too large"
    );
    let mut count = 0;
    loop {
        pem = pem.trim_start();
        if pem.is_empty() {
            break;
        }
        let (begin, contents) = pem
            .split_once('\n')
            .context("bootstrap: CA bundle contains invalid PEM")?;
        ensure!(
            begin.trim_end_matches('\r') == "-----BEGIN CERTIFICATE-----",
            "bootstrap: CA bundle contains invalid PEM"
        );
        let (body, rest) = contents
            .split_once("\n-----END CERTIFICATE-----")
            .context("bootstrap: CA bundle contains invalid PEM")?;
        pem = if rest.is_empty() {
            rest
        } else if let Some(rest) = rest
            .strip_prefix("\r\n")
            .or_else(|| rest.strip_prefix('\n'))
        {
            rest
        } else {
            bail!("bootstrap: CA bundle contains invalid PEM")
        };
        let encoded = body
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let der = STANDARD
            .decode(encoded)
            .context("bootstrap: CA bundle contains invalid PEM")?;
        let (trailing, certificate) = parse_x509_certificate(&der)
            .map_err(|_| anyhow::anyhow!("bootstrap: CA bundle contains an invalid certificate"))?;
        ensure!(
            trailing.is_empty()
                && certificate
                    .basic_constraints()
                    .map_err(|_| anyhow::anyhow!("bootstrap: invalid CA basic constraints"))?
                    .is_some_and(|constraints| constraints.value.ca),
            "bootstrap: CA bundle contains a non-CA certificate"
        );
        count += 1;
        ensure!(
            count <= MAX_CA_CERTIFICATES,
            "bootstrap: CA bundle has too many certificates"
        );
    }
    ensure!(count > 0, "bootstrap: CA bundle contains no certificate");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    const NOW: i64 = 2_000_000_000;

    fn certificate(is_ca: bool) -> String {
        let mut params = CertificateParams::new(vec!["bootstrap.invalid".to_owned()]).unwrap();
        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
    }

    fn valid_metadata() -> Metadata {
        Metadata {
            schema_version: 1,
            generated_at: NOW,
            valid_until: NOW + 300,
            network_id: "000102030405060708090a0b0c0d0e0f".to_owned(),
            controller: Controller {
                enrollment_endpoint: "https://controller.example.test:8443".to_owned(),
                quic_endpoint: "controller.example.test:8443".to_owned(),
                server_name: "controller.example.test".to_owned(),
                service_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            },
            relays: vec![Relay {
                name: "relay".to_owned(),
                endpoint: "relay.example.test:443".to_owned(),
                service_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            }],
            trust: Trust {
                ca_pem: certificate(true),
            },
            protocol: Protocol {
                control_major: 1,
                control_minor: 0,
                packet: vec![1],
                capabilities: 255,
            },
            artifacts: vec![Artifact {
                os: "darwin".to_owned(),
                arch: "arm64".to_owned(),
                url: "https://download.example.test/laneway.tar.gz".to_owned(),
                sha256: "a".repeat(64),
                size_bytes: 5,
            }],
        }
    }

    #[test]
    fn validates_wire_format_and_rejects_unknown_trailing_and_oversize_data() {
        let metadata = valid_metadata();
        let json = serde_json::to_vec(&metadata).unwrap();
        let decoded = decode(json.as_slice(), NOW).unwrap();
        assert_eq!(decoded.network_id, metadata.network_id);
        let mut encoded = serde_json::to_value(metadata).unwrap();
        assert!(encoded["generated_at_unix_seconds"].is_i64());
        assert_eq!(encoded["protocol"]["packet_versions"][0], 1);
        encoded["controller"]["unexpected"] = 1.into();
        assert!(decode(serde_json::to_vec(&encoded).unwrap().as_slice(), NOW).is_err());
        let mut trailing = json;
        trailing.extend_from_slice(b" {}");
        assert!(decode(trailing.as_slice(), NOW).is_err());
        let oversized = vec![b' '; MAX_DOCUMENT_BYTES as usize + 1];
        assert!(
            decode(oversized.as_slice(), NOW)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
    }

    #[test]
    fn rejects_expired_and_out_of_policy_metadata() {
        let metadata = valid_metadata();
        assert!(metadata.validate(NOW).is_ok());
        type Mutation = fn(&mut Metadata);
        let invalid: [(&str, Mutation); 9] = [
            ("expired", |item| item.valid_until = NOW),
            ("future", |item| item.generated_at = NOW + 121),
            ("identity", |item| {
                item.controller.service_id = "0".repeat(32)
            }),
            ("relay endpoint", |item| {
                item.relays[0].endpoint = "Relay.Example.Test:443".to_owned()
            }),
            ("duplicate relay", |item| {
                item.relays.push(item.relays[0].clone())
            }),
            ("leaf trust", |item| item.trust.ca_pem = certificate(false)),
            ("unknown protocol capability", |item| {
                item.protocol.capabilities |= 1 << 63
            }),
            ("non-canonical digest", |item| {
                item.artifacts[0].sha256 = "A".repeat(64)
            }),
            ("unsafe artifact URL", |item| {
                item.artifacts[0].url = "https:///download.example.test/laneway.tar.gz".to_owned()
            }),
        ];
        for (name, mutate) in invalid {
            let mut candidate = metadata.clone();
            mutate(&mut candidate);
            assert!(candidate.validate(NOW).is_err(), "{name}");
        }
    }

    #[test]
    fn canonical_endpoint_keeps_unicast_and_rejects_invalid_port_or_address() {
        for (input, expected) in [
            ("Relay.Example.:00443", "relay.example:443"),
            ("[2001:0db8::1]:443", "[2001:db8::1]:443"),
            ("127.0.0.1:443", "127.0.0.1:443"),
            ("[fe80::1]:443", "[fe80::1]:443"),
        ] {
            assert_eq!(canonical_host_port(input).unwrap(), expected);
        }
        for invalid in [
            "host:0",
            "host:+443",
            "bad host:443",
            "0.0.0.0:443",
            "[::ffff:127.0.0.1]:443",
            "[ff02::1]:443",
            "[fe80::1%eth0]:443",
            "::1:443",
        ] {
            assert!(canonical_host_port(invalid).is_err(), "{invalid}");
        }
    }
}
