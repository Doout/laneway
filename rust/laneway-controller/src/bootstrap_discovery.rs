//! Bootstrap metadata is opt-in. Advertise only a verified controller
//! identity and explicitly configured artifacts, with fresh relay inventory.
use crate::{check_snapshot, open_existing, read_network};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::Uri;
use laneway_protocol::{
    Id, Role, identity_from_certificate_der,
    relay_endpoint::{MAX_RELAY_ENDPOINTS, canonical_host_port},
};
use rusqlite::OpenFlags;
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io::BufRead, net::IpAddr, path::Path, sync::Arc};
use x509_parser::parse_x509_certificate;

pub const PATH: &str = "/.well-known/laneway/bootstrap.json";
const LIFETIME: i64 = 300;
const MAX_METADATA: usize = 256 * 1024;
// Stable-v1 protocol vocabulary shared with Go's protocol.KnownCapabilities.
// Workload capability negotiation still decides which features a peer uses.
const KNOWN_V1_CAPABILITIES: u64 = (1 << 8) - 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    enrollment_endpoint: String,
    quic_endpoint: String,
    server_name: String,
    #[serde(default)]
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    os: String,
    arch: String,
    url: String,
    sha256: String,
    size_bytes: i64,
}

#[derive(Serialize)]
struct Controller {
    enrollment_endpoint: String,
    quic_endpoint: String,
    server_name: String,
    service_id: String,
}

#[derive(Serialize)]
struct Relay {
    name: String,
    endpoint: String,
    service_id: String,
}

#[derive(Serialize)]
struct Trust<'a> {
    ca_pem: &'a str,
}

#[derive(Serialize)]
struct Protocol {
    control_major: u32,
    control_minor: u32,
    packet_versions: [u32; 1],
    capabilities: u64,
}

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u32,
    generated_at_unix_seconds: i64,
    valid_until_unix_seconds: i64,
    network_id: String,
    controller: &'a Controller,
    relays: Vec<Relay>,
    trust: Trust<'a>,
    protocol: Protocol,
    artifacts: Option<&'a [Artifact]>,
}

pub struct Discovery {
    network: Id,
    controller: Controller,
    trust: String,
    artifacts: Vec<Artifact>,
}

impl Discovery {
    pub fn load(
        database: &Path,
        profile: &[u8],
        chain: &[CertificateDer<'_>],
        trust: &mut dyn BufRead,
    ) -> Result<Self> {
        let profile: Profile =
            serde_json::from_slice(profile).context("invalid bootstrap profile")?;
        ensure!(
            https_uri(&profile.enrollment_endpoint)
                .is_some_and(|uri| uri.path() == "/" && uri.query().is_none()),
            "bootstrap enrollment endpoint must be an HTTPS origin"
        );
        let quic_endpoint = canonical_host_port(&profile.quic_endpoint)
            .context("invalid bootstrap controller QUIC endpoint")?;
        ensure!(
            dns_name(&profile.server_name),
            "invalid bootstrap controller server name"
        );
        validate_artifacts(&profile.artifacts)?;

        let (leaf, intermediates) = chain
            .split_first()
            .context("missing bootstrap controller certificate")?;
        let ident = identity_from_certificate_der(leaf.as_ref())?;
        ensure!(
            ident.role == Role::Controller,
            "bootstrap profile requires a controller identity"
        );
        let (roots, ca_pem) = certificate_authorities(trust)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
        verifier
            .verify_server_cert(
                leaf,
                intermediates,
                &ServerName::try_from(profile.server_name.as_str())?,
                &[],
                UnixTime::now(),
            )
            .context("bootstrap trust and name do not verify the controller certificate")?;

        let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tx = db.transaction()?;
        check_snapshot(&tx)?;
        read_network(&tx, ident.network_id).context("bootstrap network is not provisioned")?;
        tx.commit()?;
        Ok(Self {
            network: ident.network_id,
            controller: Controller {
                enrollment_endpoint: profile.enrollment_endpoint,
                quic_endpoint,
                server_name: profile.server_name,
                service_id: ident.subject_id.to_string(),
            },
            trust: ca_pem,
            artifacts: profile.artifacts,
        })
    }

    pub fn network_id(&self) -> Id {
        self.network
    }

    pub(crate) fn connector_setup(
        &self,
        tx: &rusqlite::Transaction<'_>,
        network: Id,
        name: &str,
        token: &str,
    ) -> Result<zeroize::Zeroizing<String>> {
        ensure!(
            network == self.network,
            "gateway network differs from bootstrap identity"
        );
        let relays = self.relays(tx)?;
        let relay = relays.first().context("no relay configured for gateway")?;
        let contents = zeroize::Zeroizing::new(format!(
            "{name}\n{token}\n{}\n{}\n{}\n{network}\n{}\n{}\n{}\n{}\n",
            self.controller.enrollment_endpoint,
            self.controller.quic_endpoint,
            self.controller.server_name,
            self.controller.service_id,
            relay.endpoint,
            relay.service_id,
            STANDARD.encode(&self.trust),
        ));
        let mut setup = zeroize::Zeroizing::new(String::from("st1."));
        STANDARD.encode_string(contents.as_bytes(), &mut setup);
        Ok(setup)
    }

    pub fn document(&self, database: &Path) -> Result<Vec<u8>> {
        let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tx = db.transaction()?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        ensure!(now > 0, "invalid bootstrap clock");
        let relays = self.relays(&tx)?;
        tx.commit()?;
        let doc = Document {
            schema_version: 1,
            generated_at_unix_seconds: now,
            valid_until_unix_seconds: now + LIFETIME,
            network_id: self.network.to_string(),
            controller: &self.controller,
            relays,
            trust: Trust {
                ca_pem: &self.trust,
            },
            protocol: Protocol {
                control_major: 1,
                control_minor: 0,
                packet_versions: [1],
                capabilities: KNOWN_V1_CAPABILITIES,
            },
            artifacts: (!self.artifacts.is_empty()).then_some(self.artifacts.as_slice()),
        };
        let encoded = serde_json::to_vec(&doc)?;
        ensure!(
            encoded.len() <= MAX_METADATA,
            "bootstrap metadata exceeds declared limit"
        );
        Ok(encoded)
    }

    fn relays(&self, tx: &rusqlite::Transaction<'_>) -> Result<Vec<Relay>> {
        let mut stmt = tx.prepare(
            "SELECT service_id,name,endpoint FROM relays
            WHERE network_id=?1 AND enabled=1 AND service_id IS NOT NULL ORDER BY id LIMIT ?2",
        )?;
        let mut rows = stmt.query((self.network.as_bytes(), MAX_RELAY_ENDPOINTS as i64 + 1))?;
        let mut seen = HashSet::new();
        let mut relays = Vec::new();
        while let Some(row) = rows.next()? {
            let id = Id::new(row.get(0)?)?;
            let name: String = row.get(1)?;
            let endpoint: String = row.get(2)?;
            ensure!(
                !name.is_empty() && name.trim() == name && name.len() <= 253,
                "invalid bootstrap relay name"
            );
            ensure!(
                canonical_host_port(&endpoint).as_deref() == Some(endpoint.as_str()),
                "noncanonical bootstrap relay endpoint"
            );
            ensure!(
                seen.insert((id, endpoint.clone())),
                "duplicate bootstrap relay"
            );
            relays.push(Relay {
                name,
                endpoint,
                service_id: id.to_string(),
            });
        }
        ensure!(
            (1..=MAX_RELAY_ENDPOINTS).contains(&relays.len()),
            "bootstrap relay set is empty or too large"
        );
        Ok(relays)
    }
}

fn https_uri(value: &str) -> Option<Uri> {
    if !value.starts_with("https://")
        || value
            .bytes()
            .any(|b| b <= b' ' || b == 127 || matches!(b, b'\\' | b'#'))
    {
        return None;
    }
    let uri = value.parse::<Uri>().ok()?;
    let authority = uri.authority()?;
    (!authority.host().is_empty() && !authority.as_str().contains(['@', '%', '*'])).then_some(uri)
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn validate_artifacts(items: &[Artifact]) -> Result<()> {
    ensure!(items.len() <= 16, "too many bootstrap artifacts");
    let mut seen = HashSet::new();
    for item in items {
        ensure!(
            matches!(item.os.as_str(), "linux" | "darwin")
                && matches!(item.arch.as_str(), "amd64" | "arm64")
                && seen.insert((item.os.as_str(), item.arch.as_str())),
            "invalid or duplicate bootstrap artifact platform"
        );
        ensure!(
            https_uri(&item.url).is_some(),
            "bootstrap artifact must have an HTTPS URL"
        );
        ensure!(
            item.sha256.len() == 64
                && item
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid bootstrap artifact digest"
        );
        ensure!(
            (1..=512 * 1024 * 1024).contains(&item.size_bytes),
            "invalid bootstrap artifact length"
        );
    }
    Ok(())
}

fn certificate_authorities(reader: &mut dyn BufRead) -> Result<(RootCertStore, String)> {
    let mut roots = RootCertStore::empty();
    let mut public = String::new();
    for item in rustls_pemfile::read_all(reader) {
        let rustls_pemfile::Item::X509Certificate(der) = item? else {
            anyhow::bail!("bootstrap trust file contains a non-certificate object");
        };
        let (_, cert) = parse_x509_certificate(der.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid bootstrap CA"))?;
        ensure!(
            cert.basic_constraints()?
                .is_some_and(|extensions| extensions.value.ca),
            "bootstrap trust file contains a non-CA leaf"
        );
        ensure!(roots.len() < 8, "too many bootstrap trust authorities");
        let encoded = STANDARD.encode(der.as_ref());
        roots.add(der)?;
        public.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            public.push_str(std::str::from_utf8(line)?);
            public.push('\n');
        }
        public.push_str("-----END CERTIFICATE-----\n");
    }
    ensure!(
        !roots.is_empty() && public.len() <= 128 * 1024,
        "bootstrap CA bundle is missing or too large"
    );
    Ok((roots, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_urls_and_names_are_not_inferred_from_request_headers() {
        assert!(https_uri("https://relay.example.test:443").is_some());
        for bad in [
            "http://relay.example.test",
            "https://a@b",
            "https://foo/#frag",
            "https://foo\\bar",
        ] {
            assert!(https_uri(bad).is_none(), "{bad}");
        }
        assert!(dns_name("controller.example.test"));
        for bad in [
            "Controller.example",
            "controller.example.",
            "127.0.0.1",
            "controller..example",
        ] {
            assert!(!dns_name(bad), "{bad}");
        }
    }
}
