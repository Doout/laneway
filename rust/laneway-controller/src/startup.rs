use anyhow::{Context, Result, bail, ensure};
use laneway_config::{Config, ControllerInitialNetwork};
use laneway_protocol::{AuthenticatedIdentity, Id, Role, identity_from_certificate_der};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{RootCertStore, crypto::CryptoProvider, sign::CertifiedKey};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use x509_parser::{extensions::ParsedExtension, parse_x509_certificate};
use zeroize::Zeroizing;

use crate::store::{InitialNetwork, Store};

fn configured_network(configured: &ControllerInitialNetwork) -> Result<Option<InitialNetwork>> {
    if !configured.configured() {
        return Ok(None);
    }
    let ipv6 = if configured.ipv6_pool.is_empty() {
        None
    } else {
        Some(
            configured
                .ipv6_pool
                .parse()
                .context("parse controller initial IPv6 pool")?,
        )
    };
    Ok(Some(InitialNetwork::new(
        configured
            .network_id
            .parse()
            .context("parse controller initial network ID")?,
        configured.name.clone(),
        configured
            .ipv4_pool
            .parse()
            .context("parse controller initial IPv4 pool")?,
        ipv6,
    )?))
}

pub(crate) fn prepare(path: &Path) -> Result<()> {
    open(&Config::load(path)?)?;
    println!("controller database startup state prepared");
    Ok(())
}

pub(crate) struct Prepared {
    pub store: Store,
    pub certificate: CertifiedKey,
    pub roots: RootCertStore,
    pub identity: AuthenticatedIdentity,
    pub bearer_digest: [u8; 32],
}

pub(crate) fn open(config: &Config) -> Result<Prepared> {
    ensure!(
        config.mode == "controller",
        "configuration mode is {:?}, want \"controller\"",
        config.mode
    );
    let bearer_digest = admin_token_digest(Path::new(&config.controller.admin_token_file))?;
    let (identity, certificate, roots) = validate_pki(config)?;
    let initial = configured_network(&config.controller.initial_network)?;
    if let Some(initial) = &initial {
        ensure!(
            initial.id == identity.network_id,
            "controller initial network does not match the verified controller certificate network identity"
        );
    }
    let bootstrap = if config.bootstrap.network_id.is_empty() {
        None
    } else {
        Some(
            config
                .bootstrap
                .network_id
                .parse::<Id>()
                .context("parse bootstrap network ID")?,
        )
    };
    if let Some(bootstrap) = bootstrap {
        ensure!(
            bootstrap == identity.network_id,
            "bootstrap network does not match the verified controller certificate network identity"
        );
    }

    let mut store = Store::open(Path::new(&config.controller.database))?;
    store.prepare(initial.as_ref(), identity, bootstrap)?;
    Ok(Prepared {
        store,
        certificate,
        roots,
        identity,
        bearer_digest,
    })
}

fn admin_token_digest(path: &Path) -> Result<[u8; 32]> {
    const MAX: u64 = 4096;
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(path)
        .context("open admin token")?
        .take(MAX + 1)
        .read_to_end(&mut bytes)
        .context("read admin token")?;
    ensure!(bytes.len() as u64 <= MAX, "admin token file is too large");
    let token = std::str::from_utf8(&bytes).map(str::trim).unwrap_or("");
    ensure!(
        token.len() >= 32,
        "admin token must contain at least 32 characters"
    );
    let mut digest = Sha256::new();
    digest.update(b"Bearer ");
    digest.update(token.as_bytes());
    Ok(digest.finalize().into())
}

fn validate_pki(config: &Config) -> Result<(AuthenticatedIdentity, CertifiedKey, RootCertStore)> {
    let provider = rustls::crypto::ring::default_provider();
    let roots = certificates(Path::new(&config.tls.ca))?;
    ensure!(
        roots.len() == 1,
        "controller CA file must contain exactly one certificate"
    );
    let issuer_path = if config.controller.issuer_certificate.is_empty() {
        &config.tls.ca
    } else {
        &config.controller.issuer_certificate
    };
    let issuer_chain = certificates(Path::new(issuer_path))?;
    ensure!(
        issuer_chain.last() == roots.first(),
        "controller issuer chain is not anchored by tls.ca"
    );
    let now = UnixTime::now();
    validate_issuer_chain(&issuer_chain, now)?;
    matching_key(
        issuer_chain,
        Path::new(&config.controller.ca_private_key),
        &provider,
        true,
    )
    .context("verify issuing authority key")?;

    let leaf_chain = certificates(Path::new(&config.tls.certificate))?;
    let (leaf, intermediates) = leaf_chain
        .split_first()
        .context("controller certificate chain is empty")?;
    let identity = identity_from_certificate_der(leaf.as_ref())
        .context("read controller certificate identity")?;
    ensure!(
        identity.role == Role::Controller,
        "controller certificate role is not controller"
    );
    let mut trust = RootCertStore::empty();
    trust.add(roots[0].clone())?;
    let parsed = ParsedCertificate::try_from(leaf)?;
    verify_server_cert_signed_by_trust_anchor(
        &parsed,
        &trust,
        intermediates,
        now,
        provider.signature_verification_algorithms.all,
    )
    .context("verify controller certificate chain")?;
    let key = matching_key(
        leaf_chain,
        Path::new(&config.tls.private_key),
        &provider,
        false,
    )
    .context("load controller certificate and key")?;
    Ok((identity, key, trust))
}

pub(crate) fn validate_issuer_chain(chain: &[CertificateDer<'_>], now: UnixTime) -> Result<()> {
    let now = i64::try_from(now.as_secs())?;
    let certificates = chain
        .iter()
        .map(|der| {
            let (remaining, cert) = parse_x509_certificate(der)
                .map_err(|_| anyhow::anyhow!("invalid issuing authority certificate"))?;
            ensure!(
                remaining.is_empty(),
                "invalid trailing data in issuing authority certificate"
            );
            Ok(cert)
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, certificate) in certificates.iter().enumerate() {
        let issuer = certificates.get(index + 1).unwrap_or(certificate);
        ensure!(
            certificate.issuer() == issuer.subject(),
            "issuing authority names do not form an ordered chain"
        );
        certificate
            .verify_signature(Some(issuer.public_key()))
            .context("verify issuing authority signature")?;
        ensure!(
            certificate.validity().not_before.timestamp() <= now
                && now <= certificate.validity().not_after.timestamp(),
            "issuing authority certificate is outside its validity period"
        );
        let constraints = certificate
            .basic_constraints()?
            .context("missing issuing authority CA constraints")?;
        ensure!(
            constraints.value.ca,
            "issuing authority certificate is not a CA"
        );
        if let Some(length) = constraints.value.path_len_constraint {
            ensure!(
                usize::try_from(length)? >= index,
                "issuing authority path exceeds its CA constraint"
            );
        }
        if let Some(usage) = certificate.key_usage()? {
            ensure!(
                usage.value.key_cert_sign(),
                "issuing authority key usage forbids certificate signing"
            );
        }
        for extension in certificate.extensions() {
            if extension.critical
                && !matches!(
                    extension.parsed_extension(),
                    ParsedExtension::BasicConstraints(_) | ParsedExtension::KeyUsage(_)
                )
            {
                bail!(
                    "unsupported critical issuing authority extension {}",
                    extension.oid
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("open certificate file {}", path.display()))?;
    let chain =
        rustls_pemfile::certs(&mut BufReader::new(file)).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        !chain.is_empty(),
        "certificate file is empty: {}",
        path.display()
    );
    Ok(chain)
}

fn matching_key(
    certificates: Vec<CertificateDer<'static>>,
    path: &Path,
    provider: &CryptoProvider,
    pkcs8_only: bool,
) -> Result<CertifiedKey> {
    let file = File::open(path).with_context(|| format!("open private key {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)?.context("private key is missing")?;
    ensure!(
        !pkcs8_only || matches!(key, PrivateKeyDer::Pkcs8(_)),
        "CA private key must be PKCS#8"
    );
    ensure!(
        rustls_pemfile::read_one(&mut reader)?.is_none(),
        "private key file contains extra PEM sections"
    );
    let key = CertifiedKey::from_der(certificates, key, provider)?;
    key.keys_match()?;
    Ok(key)
}
