use std::{io::Cursor, net::IpAddr, sync::Arc};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_protocol::Id;
use lanewayd_rs::rootless::controller_client_tls;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};

pub(crate) fn https_tls(
    ca_pem: &[u8],
    server_name: &str,
    network: Id,
    service: Id,
    credentials: Option<(&[u8], &[u8])>,
) -> Result<ClientConfig> {
    https_tls_optional(ca_pem, Some(server_name), network, service, credentials)
}

pub(crate) fn https_tls_optional(
    ca_pem: &[u8],
    server_name: Option<&str>,
    network: Id,
    service: Id,
    credentials: Option<(&[u8], &[u8])>,
) -> Result<ClientConfig> {
    let name = server_name
        .map(|name| ServerName::try_from(name.to_owned()))
        .transpose()
        .context("invalid pinned controller server name")?;
    let credential = credentials
        .map(|(chain, key)| Ok::<_, anyhow::Error>((certificates(chain)?, private_key(key)?)))
        .transpose()?;
    let ip_name = matches!(name, Some(ServerName::IpAddress(_)));
    let mut tls = controller_client_tls(roots(ca_pem)?, name, network, service, credential)?;
    if ip_name {
        tls.enable_sni = false;
    }
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

/// Sends the configured TLS DNS name as SNI while dialing the advertised URL.
/// The returned Host header retains the original HTTPS authority.
pub(crate) fn pinned_endpoint(
    builder: reqwest::blocking::ClientBuilder,
    mut url: reqwest::Url,
    name: Option<&str>,
) -> Result<(
    reqwest::blocking::ClientBuilder,
    reqwest::Url,
    Option<String>,
)> {
    let host = url.host_str().context("controller URL has no host")?;
    let Some(name) =
        name.filter(|name| name.parse::<IpAddr>().is_err() && !name.eq_ignore_ascii_case(host))
    else {
        return Ok((builder, url, None));
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let dial_host = host.trim_matches(['[', ']']).to_owned();
    url.set_host(Some(name))
        .context("invalid controller SNI name")?;
    let name = url
        .host_str()
        .context("invalid controller SNI alias")?
        .to_owned();
    let builder = builder.dns_resolver(Arc::new(DialHost { name, dial_host }));
    Ok((builder, url, Some(authority)))
}

struct DialHost {
    name: String,
    dial_host: String,
}

impl reqwest::dns::Resolve for DialHost {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let matches = name.as_str().eq_ignore_ascii_case(&self.name);
        let host = self.dial_host.clone();
        Box::pin(async move {
            if !matches {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unexpected name in pinned controller DNS resolution",
                )
                .into());
            }
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub(super) fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let chain = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse certificate PEM")?;
    ensure!(!chain.is_empty(), "certificate bundle is empty");
    Ok(chain)
}

fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .context("parse node private key")?
        .context("node private key is missing")
}

pub(super) fn roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(pem)? {
        roots
            .add(certificate)
            .context("parse controller CA certificate")?;
    }
    Ok(roots)
}

pub(super) fn verify_key_pair(chain: &[CertificateDer<'static>], pem: &[u8]) -> Result<()> {
    rustls::sign::CertifiedKey::from_der(
        chain.to_vec(),
        private_key(pem)?,
        &rustls::crypto::ring::default_provider(),
    )
    .context("load node certificate and private key")?
    .keys_match()
    .context("node certificate does not match its private key")
}

pub(super) fn encode_chain(chain: &[CertificateDer<'_>]) -> Vec<u8> {
    let mut output = Vec::new();
    for certificate in chain {
        output.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        for line in STANDARD.encode(certificate).as_bytes().chunks(64) {
            output.extend_from_slice(line);
            output.push(b'\n');
        }
        output.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    output
}
