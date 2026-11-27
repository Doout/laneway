//! Certificate-only rotation. The old credentials stay live while the candidate
//! proves possession and fetches an authorized snapshot on a new TLS connection.
use crate::{
    authority::Authority,
    config::TlsConfig,
    controller::{Client, PollResult, Snapshot},
    tls::{self, LocalCertificateHealth},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_protocol::{
    AuthenticatedIdentity, Id, Role, certificate_serial_from_der, identity_from_certificate_der,
    v1::CertificateChain,
};
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, UnixTime};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::NamedTempFile;
use tracing::{info, warn};
use x509_parser::parse_x509_certificate;

pub(crate) async fn when_due(
    client: Arc<Client>,
    authority: Arc<Authority>,
    config: TlsConfig,
    net: Id,
    node: Id,
    old: LocalCertificateHealth,
) {
    let mut retry = Duration::from_secs(5);
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now < old.renew_after {
            tokio::time::sleep(Duration::from_secs((old.renew_after - now).min(60))).await;
            continue;
        }
        if now >= old.not_after {
            std::future::pending::<()>().await;
            return;
        }
        if let Some(active) = authority.active() {
            let lease = active.identity_lease_expires_at;
            // Renewal cannot prolong an ephemeral session. If the existing
            // certificate already covers its entire lease, there is no work.
            if !active.local_certificate_revoked && (lease == 0 || lease > old.not_after) {
                match replace(&client, &config, net, node, &old, lease).await {
                    Ok(()) => {
                        info!("renewed node certificate; restarting authenticated connections");
                        return;
                    }
                    Err(e) => {
                        warn!(error=%e,"node certificate renewal failed; retaining current identity")
                    }
                }
            }
        }
        tokio::time::sleep(retry.min(Duration::from_secs((old.not_after - now).max(1)))).await;
        retry = (retry * 2).min(Duration::from_secs(60));
    }
}

async fn replace(
    client: &Client,
    config: &TlsConfig,
    net: Id,
    node: Id,
    old: &LocalCertificateHealth,
    lease: u64,
) -> Result<()> {
    let mut staged = Staged::open(&config.certificate, old)?;
    let key = KeyPair::try_from(&tls::load_private_key(&config.private_key)?)
        .context("load renewal signing key")?;
    let csr = CertificateParams::new(Vec::<String>::new())?.serialize_request(&key)?;
    let reply = client.renew_certificate(csr.der().to_vec()).await?;
    let chain = reply
        .certificate_chain
        .context("renewal omitted certificate chain")?;
    let identity = AuthenticatedIdentity {
        network_id: net,
        role: Role::Node,
        subject_id: node,
    };
    let pem = validate(
        &chain,
        &key,
        identity,
        old,
        lease,
        &tls::root_store(&config.ca)?,
    )?;
    staged.write(&pem)?;
    let mut staged_config = config.clone();
    staged_config.certificate = staged.file.path().to_owned();
    let health = tls::local_certificate_health(&staged_config)?;
    let probe = client.with_certificate(staged_config.certificate).await?;
    let PollResult::Modified(snapshot) = probe.poll(0).await? else {
        anyhow::bail!("replacement certificate did not receive an initial snapshot")
    };
    let snapshot = Snapshot::compile(*snapshot, net, node, &health)?;
    ensure!(
        !snapshot.local_certificate_revoked
            && (snapshot.identity_lease_expires_at == 0
                || health.not_after <= snapshot.identity_lease_expires_at),
        "controller rejected replacement certificate authority"
    );
    staged.commit()
}

/// Repair an expired persistent node, with the service stopped, using the
/// operator-delivered approval. Only the certificate file is replaced.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn recover_node_credential(config: &crate::Config, token_file: &Path) -> Result<()> {
    use rcgen::{DistinguishedName, DnType};
    use sha2::{Digest, Sha256};

    let controller = config
        .controller
        .as_ref()
        .context("recovery requires a controller-managed node")?;
    let (network, node) = config.ids()?;
    let identity = AuthenticatedIdentity {
        network_id: network,
        role: Role::Node,
        subject_id: node,
    };
    let tls = &config.tls;
    let old = tls::local_certificate_health(tls)?;
    ensure!(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() >= old.not_after,
        "certificate has not expired; use ordinary renewal"
    );
    let chain = tls::load_certificates(&tls.certificate)?;
    ensure!(
        identity_from_certificate_der(chain[0].as_ref())? == identity,
        "expired certificate does not match configured node identity"
    );
    let key = KeyPair::try_from(&tls::load_private_key(&tls.private_key)?)?;
    let old_leaf = parse_x509_certificate(chain[0].as_ref())
        .map_err(|_| anyhow::anyhow!("invalid expired certificate"))?
        .1;
    ensure!(
        old_leaf.public_key().raw == key.subject_public_key_info(),
        "expired certificate and existing private key do not match"
    );
    // Exercise staging and file permissions before spending the approval.
    let mut staged = Staged::open(&tls.certificate, &old)?;
    let roots = tls::root_store(&tls.ca)?;
    let token = recovery_token(token_file)?;
    let token = token.trim();
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        format!(
            "laneway-recovery:{}",
            hex::encode(Sha256::digest(token.as_bytes()))
        ),
    );
    let csr = params.serialize_request(&key)?;
    let certificates_der =
        crate::controller::recover_certificate(controller, &tls.ca, network, token, csr.der())
            .await?;
    (|| -> Result<()> {
        let (_, leaf) = parse_x509_certificate(&certificates_der[0]).map_err(|_| anyhow::anyhow!("invalid recovered certificate"))?;
        let expiry = leaf.validity().not_after.timestamp().try_into()?;
        let chain = CertificateChain { certificates_der, not_after_unix_seconds: expiry };
        let pem = validate(&chain, &key, identity, &old, 0, &roots)?;
        let still_current = KeyPair::try_from(&tls::load_private_key(&tls.private_key)?)?;
        ensure!(still_current.subject_public_key_info() == key.subject_public_key_info(),
            "existing private key changed during recovery");
        staged.write(&pem)?;
        staged.commit()
    })().context("recovery was approved but the certificate was not installed; request another approval after fixing the problem")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn recovery_token(path: &Path) -> Result<zeroize::Zeroizing<String>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::{
        io::Read,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open private recovery token file")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 128 && metadata.permissions().mode() & 0o077 == 0,
        "recovery token file must be private, regular, and at most 128 bytes"
    );
    let mut token = zeroize::Zeroizing::new(String::new());
    file.take(129).read_to_string(&mut token)?;
    let mut decoded = zeroize::Zeroizing::new([0u8; 32]);
    ensure!(
        token.len() <= 128
            && token.trim().len() == 43
            && URL_SAFE_NO_PAD.decode_slice(token.trim(), &mut *decoded) == Ok(32),
        "invalid recovery token"
    );
    Ok(token)
}

/// Renew the key pair and WireGuard binding of a saved client login.
#[doc(hidden)]
pub async fn renew_saved_login(
    settings: &crate::ControllerConfig,
    tls_config: &TlsConfig,
    network: Id,
    node: Id,
    wireguard_public_key: [u8; 32],
) -> Result<(Vec<u8>, zeroize::Zeroizing<String>)> {
    tls::validate_local(tls_config, network, node)?;
    let old = tls::local_certificate_health(tls_config)?;
    let roots = tls::root_store(&tls_config.ca)?;
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let csr = CertificateParams::new(Vec::new())?.serialize_request(&key)?;
    let reply = crate::rootless::renew_certificate(
        settings,
        network,
        tls_config,
        laneway_protocol::v1::RenewalRequest {
            pkcs10_csr_der: csr.der().to_vec(),
            wireguard_public_key: wireguard_public_key.to_vec(),
        },
    )
    .await?;
    ensure!(
        reply.wireguard_public_key == wireguard_public_key,
        "renewal returned a different WireGuard public key"
    );
    let identity = AuthenticatedIdentity {
        network_id: network,
        role: Role::Node,
        subject_id: node,
    };
    let chain = reply
        .certificate_chain
        .context("renewal omitted certificate chain")?;
    let certificate = validate(&chain, &key, identity, &old, 0, &roots)?;
    Ok((certificate, zeroize::Zeroizing::new(key.serialize_pem())))
}

fn validate(
    chain: &CertificateChain,
    key: &KeyPair,
    identity: AuthenticatedIdentity,
    old: &LocalCertificateHealth,
    lease: u64,
    roots: &rustls::RootCertStore,
) -> Result<Vec<u8>> {
    ensure!(
        (1..=9).contains(&chain.certificates_der.len())
            && chain
                .certificates_der
                .iter()
                .all(|c| !c.is_empty() && c.len() <= 65536),
        "invalid renewal certificate chain size"
    );
    let der: Vec<_> = chain
        .certificates_der
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let (rest, leaf) = parse_x509_certificate(der[0].as_ref())
        .map_err(|_| anyhow::anyhow!("invalid renewal leaf"))?;
    ensure!(
        rest.is_empty()
            && !leaf.is_ca()
            && leaf.public_key().raw == key.subject_public_key_info()
            && identity_from_certificate_der(der[0].as_ref())? == identity,
        "renewed certificate has incorrect identity or key"
    );
    let expiry = u64::try_from(leaf.validity().not_after.timestamp())?;
    let eku = leaf
        .extended_key_usage()?
        .context("renewed certificate lacks explicit peer and client usages")?;
    ensure!(
        eku.value.client_auth && eku.value.server_auth,
        "renewed certificate lacks explicit peer and client usages"
    );
    ensure!(
        expiry == chain.not_after_unix_seconds
            && expiry > old.not_after
            && (lease == 0 || expiry <= lease)
            && certificate_serial_from_der(der[0].as_ref())? != old.serial,
        "renewed certificate does not extend the current identity within its lease"
    );
    let cert = webpki::EndEntityCert::try_from(&der[0])?;
    for usage in [
        webpki::KeyUsage::client_auth(),
        webpki::KeyUsage::server_auth(),
    ] {
        cert.verify_for_usage(
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
            &roots.roots,
            &der[1..],
            UnixTime::now(),
            usage,
            None,
            None,
        )
        .context("verify renewal trust and validity")?;
    }
    let mut pem = Vec::new();
    for cert in der {
        writeln!(pem, "-----BEGIN CERTIFICATE-----")?;
        for chunk in STANDARD.encode(cert.as_ref()).as_bytes().chunks(64) {
            pem.write_all(chunk)?;
            pem.push(b'\n');
        }
        writeln!(pem, "-----END CERTIFICATE-----")?;
    }
    Ok(pem)
}

struct Staged {
    file: NamedTempFile,
    target: PathBuf,
    original: Vec<u8>,
    metadata: fs::Metadata,
}
impl Staged {
    fn open(target: &Path, old: &LocalCertificateHealth) -> Result<Self> {
        let meta = fs::symlink_metadata(target)?;
        ensure!(
            meta.is_file() && meta.len() <= 4 << 20,
            "certificate path must be a bounded regular file, not a symlink"
        );
        let original = fs::read(target)?;
        let mut reader = original.as_slice();
        let mut items = rustls_pemfile::read_all(&mut reader);
        let Some(rustls_pemfile::Item::X509Certificate(first)) = items.next().transpose()? else {
            anyhow::bail!("missing original certificate")
        };
        for item in items {
            ensure!(
                matches!(item?, rustls_pemfile::Item::X509Certificate(_)),
                "renewal requires a certificate-only file"
            );
        }
        ensure!(
            certificate_serial_from_der(first.as_ref())? == old.serial,
            "certificate changed before renewal"
        );
        let dir = parent(target);
        let file = NamedTempFile::new_in(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let temp = file.as_file().metadata()?;
            let directory = fs::symlink_metadata(dir)?;
            ensure!(
                directory.is_dir()
                    && directory.mode() & 0o022 == 0
                    && directory.uid() == temp.uid()
                    && meta.nlink() == 1
                    && meta.mode() & 0o7022 == 0
                    && temp.uid() == meta.uid()
                    && temp.gid() == meta.gid(),
                "renewal requires an owned certificate directory and regular certificate without shared write access"
            );
        }
        Ok(Self {
            file,
            target: target.to_owned(),
            original,
            metadata: meta,
        })
    }
    fn write(&mut self, pem: &[u8]) -> Result<()> {
        self.file.write_all(pem)?;
        self.file
            .as_file()
            .set_permissions(self.metadata.permissions())?;
        self.file.as_file().sync_all()?;
        Ok(())
    }
    fn commit(self) -> Result<()> {
        let current = fs::symlink_metadata(&self.target)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                current.dev() == self.metadata.dev()
                    && current.ino() == self.metadata.ino()
                    && current.nlink() == 1
                    && current.mode() == self.metadata.mode()
                    && current.uid() == self.metadata.uid()
                    && current.gid() == self.metadata.gid(),
                "certificate metadata changed during renewal"
            );
        }
        ensure!(
            current.is_file()
                && current.len() == self.original.len() as u64
                && fs::read(&self.target)? == self.original,
            "certificate changed during renewal"
        );
        self.file
            .persist(&self.target)
            .context("atomically replace node certificate")?;
        // Rename already committed. Reload even if directory sync fails.
        if let Err(e) = fs::File::open(parent(&self.target)).and_then(|f| f.sync_all()) {
            warn!(error=%e,"could not sync renewed certificate directory");
        }
        Ok(())
    }
}
fn parent(p: &Path) -> &Path {
    p.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests;
