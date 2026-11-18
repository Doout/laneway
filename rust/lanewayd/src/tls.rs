use std::{fs, io::Read, path::Path, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::{
    AuthenticatedIdentity, Id, Role, certificate_serial_from_der, identity_from_certificate_der,
};
use quinn::{
    ClientConfig, ServerConfig, TransportConfig, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{
    DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::WebPkiClientVerifier,
};
use x509_parser::parse_x509_certificate;

use crate::config::{RelayConfig, TlsConfig};

pub(crate) const RELAY_ALPN: &[u8] = b"laneway-relay/1";
pub(crate) const TCP_FALLBACK_ALPN: &[u8] = b"laneway-fallback/1";
pub(crate) const DIRECT_ALPN: &[u8] = b"laneway-peer/1";
const MAX_DATAGRAM_FRAME: usize = 5 + 1280;

pub(crate) fn validate_local(config: &TlsConfig, network: Id, node: Id) -> Result<()> {
    let certificates = load_certificates(&config.certificate)?;
    let identity = identity_from_certificate_der(
        certificates
            .first()
            .context("local certificate chain is empty")?
            .as_ref(),
    )
    .context("local certificate SPIFFE identity")?;
    ensure!(
        identity
            == (AuthenticatedIdentity {
                network_id: network,
                role: Role::Node,
                subject_id: node,
            }),
        "local certificate identity differs from configuration"
    );
    let _ = load_private_key(&config.private_key)?;
    let _ = root_store(&config.ca)?;
    Ok(())
}

pub(crate) fn verify_installed_node(config: &TlsConfig) -> Result<AuthenticatedIdentity> {
    let certificates = load_certificates(&config.certificate)?;
    let key = load_private_key(&config.private_key)?;
    let provider = rustls::crypto::ring::default_provider();
    let credential = rustls::sign::CertifiedKey::from_der(certificates, key, &provider)?;
    credential
        .keys_match()
        .context("node certificate and key do not match")?;
    let (leaf, intermediates) = credential
        .cert
        .split_first()
        .context("node certificate is empty")?;
    let parsed = webpki::EndEntityCert::try_from(leaf)
        .map_err(|_| anyhow::anyhow!("invalid node leaf certificate"))?;
    let roots = root_store(&config.ca)?;
    for usage in [
        webpki::KeyUsage::client_auth(),
        webpki::KeyUsage::server_auth(),
    ] {
        parsed
            .verify_for_usage(
                provider.signature_verification_algorithms.all,
                &roots.roots,
                intermediates,
                UnixTime::now(),
                usage,
                None,
                None,
            )
            .map_err(|error| anyhow::anyhow!("certificate is not trusted for node TLS: {error}"))?;
    }
    identity_from_certificate_der(leaf.as_ref()).context("invalid node certificate identity")
}

#[derive(Clone, Debug)]
pub(crate) struct LocalCertificateHealth {
    pub(crate) serial: Vec<u8>,
    pub(crate) not_after: u64,
    pub(crate) renew_after: u64,
}

pub(crate) fn local_certificate_health(config: &TlsConfig) -> Result<LocalCertificateHealth> {
    let certificates = load_certificates(&config.certificate)?;
    let der = certificates
        .first()
        .context("local certificate chain is empty")?
        .as_ref();
    let (_, certificate) = parse_x509_certificate(der)
        .map_err(|_| anyhow::anyhow!("parse local certificate validity"))?;
    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    ensure!(
        not_before > 0 && not_after > not_before,
        "local certificate validity is invalid"
    );
    let lifetime = not_after - not_before;
    Ok(LocalCertificateHealth {
        serial: certificate_serial_from_der(der).context("local certificate serial")?,
        not_after: u64::try_from(not_after).context("local certificate expiry is invalid")?,
        renew_after: u64::try_from(not_before + lifetime * 2 / 3)
            .context("local certificate renewal deadline is invalid")?,
    })
}

pub(crate) fn client_config(
    tls: &TlsConfig,
    relay: &RelayConfig,
    alpn: &[u8],
) -> Result<ClientConfig> {
    let certificates = load_certificates(&tls.certificate)?;
    let key = load_private_key(&tls.private_key)?;
    let roots = root_store(&tls.ca)?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .context("load node certificate and key")?;
    crypto.alpn_protocols = vec![alpn.to_vec()];
    crypto.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(crypto).context("build QUIC client TLS")?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport_config(relay)?);
    Ok(client)
}

pub(crate) fn direct_client_config(
    tls: &TlsConfig,
    relay: &RelayConfig,
    network: Id,
    peer: Id,
) -> Result<ClientConfig> {
    let certificates = load_certificates(&tls.certificate)?;
    let key = load_private_key(&tls.private_key)?;
    let roots = root_store(&tls.ca)?;
    let verifier = Arc::new(DirectServerVerifier {
        roots: Arc::new(roots),
        expected: AuthenticatedIdentity {
            network_id: network,
            role: Role::Node,
            subject_id: peer,
        },
    });
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certificates, key)
        .context("load node direct certificate and key")?;
    crypto.alpn_protocols = vec![DIRECT_ALPN.to_vec()];
    crypto.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(crypto).context("build direct QUIC client TLS")?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport_config(relay)?);
    Ok(client)
}

#[derive(Debug)]
struct DirectServerVerifier {
    roots: Arc<RootCertStore>,
    expected: AuthenticatedIdentity,
}

impl ServerCertVerifier for DirectServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let certificate = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let algorithms = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        certificate
            .verify_for_usage(
                algorithms.all,
                &self.roots.roots,
                intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|_| {
                TlsError::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            })?;
        let identity = identity_from_certificate_der(end_entity.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if identity != self.expected {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn tcp_client_config(tls: &TlsConfig) -> Result<Arc<rustls::ClientConfig>> {
    let certificates = load_certificates(&tls.certificate)?;
    let key = load_private_key(&tls.private_key)?;
    let roots = root_store(&tls.ca)?;
    let mut crypto =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, key)
            .context("load node certificate and key")?;
    crypto.alpn_protocols = vec![TCP_FALLBACK_ALPN.to_vec()];
    crypto.enable_early_data = false;
    Ok(Arc::new(crypto))
}

pub(crate) fn validate_relay_certificate(
    der: &[u8],
    network: Id,
    expected_service: Id,
) -> Result<AuthenticatedIdentity> {
    let identity =
        identity_from_certificate_der(der).context("relay certificate SPIFFE identity")?;
    ensure!(
        identity.network_id == network,
        "relay belongs to another network"
    );
    ensure!(
        identity.role == Role::Relay,
        "relay certificate role is invalid"
    );
    ensure!(
        identity.subject_id == expected_service,
        "unexpected relay service identity"
    );
    Ok(identity)
}

pub(crate) fn direct_server_config(tls: &TlsConfig, relay: &RelayConfig) -> Result<ServerConfig> {
    let certificates = load_certificates(&tls.certificate)?;
    let key = load_private_key(&tls.private_key)?;
    let roots = root_store(&tls.ca)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build direct peer client verifier")?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .context("load direct peer certificate and key")?;
    crypto.alpn_protocols = vec![DIRECT_ALPN.to_vec()];
    crypto.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(crypto).context("build QUIC server TLS")?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(transport_config(relay)?);
    Ok(server)
}

fn transport_config(relay: &RelayConfig) -> Result<Arc<TransportConfig>> {
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .max_idle_timeout(Some(
            relay
                .idle_timeout
                .try_into()
                .context("relay.idle_timeout exceeds QUIC range")?,
        ))
        .keep_alive_interval(Some(relay.keepalive))
        .datagram_receive_buffer_size(Some(
            relay
                .queue_depth
                .saturating_mul(MAX_DATAGRAM_FRAME)
                .max(64 * 1024),
        ))
        .datagram_send_buffer_size(
            relay
                .queue_depth
                .saturating_mul(MAX_DATAGRAM_FRAME)
                .max(64 * 1024),
        );
    Ok(Arc::new(transport))
}

pub(crate) fn peer_identity(connection: &quinn::Connection) -> Result<AuthenticatedIdentity> {
    let identity = connection
        .peer_identity()
        .context("peer did not present a certificate")?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected QUIC peer identity type"))?;
    let leaf = chain.first().context("peer certificate chain is empty")?;
    identity_from_certificate_der(leaf.as_ref()).context("peer certificate SPIFFE identity")
}

pub(crate) fn peer_certificate_serial(connection: &quinn::Connection) -> Result<Vec<u8>> {
    let identity = connection
        .peer_identity()
        .context("peer did not present a certificate")?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected QUIC peer identity type"))?;
    let leaf = chain.first().context("peer certificate chain is empty")?;
    certificate_serial_from_der(leaf.as_ref()).context("peer certificate serial")
}

pub(crate) fn validate_peer(
    connection: &quinn::Connection,
    alpn: &[u8],
    network: Id,
    role: Role,
    expected_subject: Option<Id>,
) -> Result<AuthenticatedIdentity> {
    let handshake = connection
        .handshake_data()
        .context("QUIC handshake data is unavailable")?;
    let handshake = handshake
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| anyhow::anyhow!("unexpected QUIC handshake data"))?;
    ensure!(
        handshake.protocol.as_deref() == Some(alpn),
        "Laneway ALPN was not negotiated"
    );
    ensure!(
        connection.max_datagram_size().is_some(),
        "QUIC DATAGRAM was not negotiated"
    );
    let identity = peer_identity(connection)?;
    ensure!(
        identity.network_id == network,
        "peer belongs to another network"
    );
    ensure!(identity.role == role, "peer certificate role is invalid");
    if let Some(subject) = expected_subject {
        ensure!(
            identity.subject_id == subject,
            "unexpected peer node identity"
        );
    }
    Ok(identity)
}

pub(crate) fn root_store(path: &std::path::Path) -> Result<RootCertStore> {
    let roots = load_certificates(path)?;
    let mut store = RootCertStore::empty();
    let (accepted, rejected) = store.add_parsable_certificates(roots);
    ensure!(
        accepted > 0 && rejected == 0,
        "CA bundle contains invalid certificates"
    );
    Ok(store)
}

pub(crate) fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = read_credential(path, 4 << 20, false)?;
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut bytes.as_slice()).collect();
    let certificates =
        certificates.with_context(|| format!("parse certificate {}", path.display()))?;
    if certificates.is_empty() {
        bail!("certificate file {} is empty", path.display());
    }
    Ok(certificates)
}

pub(crate) fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = zeroize::Zeroizing::new(read_credential(path, 1 << 20, true)?);
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .with_context(|| format!("parse private key {}", path.display()))?
        .with_context(|| format!("private key file {} is empty", path.display()))
}

fn read_credential(path: &Path, limit: u64, private: bool) -> Result<Vec<u8>> {
    let file =
        fs::File::open(path).with_context(|| format!("open credential {}", path.display()))?;
    let metadata = file.metadata().context("inspect open credential")?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "invalid credential file type or size"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            !private || private_key_mode_allowed(metadata.permissions().mode()),
            "private key may be owner/group-readable but not group-writable/executable or world-accessible"
        );
    }
    #[cfg(target_os = "macos")]
    if path.starts_with("/dev/fd") {
        use std::os::unix::fs::{FileExt, MetadataExt};
        ensure!(
            metadata.nlink() == 0
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "inherited credential must be a private unlinked file"
        );
        // Darwin's /dev/fd shares the incoming open file offset. Read from
        // offset zero because the controller, relay and direct path reuse it.
        let mut bytes = vec![0; metadata.len() as usize];
        file.read_exact_at(&mut bytes, 0)?;
        return Ok(bytes);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "credential exceeds size limit");
    Ok(bytes)
}

#[cfg(target_os = "macos")]
pub(crate) fn protect_inherited_credentials(config: &TlsConfig) -> Result<()> {
    for path in [&config.ca, &config.certificate, &config.private_key] {
        if let Ok(relative) = path.strip_prefix("/dev/fd") {
            let descriptor = relative
                .to_str()
                .and_then(|raw| {
                    raw.parse::<libc::c_int>()
                        .ok()
                        .filter(|fd| raw == fd.to_string())
                })
                .filter(|&fd| fd >= 3)
                .context("invalid inherited credential descriptor")?;
            // SAFETY: fcntl only changes inheritance of an existing descriptor.
            if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("protect credential descriptor");
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn private_key_mode_allowed(mode: u32) -> bool {
    mode & 0o027 == 0
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn darwin_inherited_credential_reads_do_not_consume_the_offset_or_leak_on_exec() {
    use std::{
        io::{Seek, SeekFrom, Write},
        os::fd::AsRawFd,
        path::PathBuf,
    };

    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"credential").unwrap();
    let fd = file.as_raw_fd();
    let path = PathBuf::from(format!("/dev/fd/{fd}"));
    let config = TlsConfig {
        certificate: path.clone(),
        private_key: path.clone(),
        ca: path.clone(),
    };
    protect_inherited_credentials(&config).unwrap();
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    assert_eq!(read_credential(&path, 32, true).unwrap(), b"credential");
    assert_eq!(read_credential(&path, 32, true).unwrap(), b"credential");
    assert_eq!(file.stream_position().unwrap(), 10);
    file.seek(SeekFrom::Start(0)).unwrap();
    assert!(read_credential(&path, 9, true).is_err());
}

#[cfg(all(test, unix))]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use laneway_protocol::{AuthenticatedIdentity, Id, Role};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType, date_time_ymd,
    };
    use rustls::{
        RootCertStore,
        client::danger::ServerCertVerifier,
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    use super::{DirectServerVerifier, private_key_mode_allowed};

    #[test]
    fn private_key_permissions_match_service_deployment() {
        assert!(private_key_mode_allowed(0o100600));
        assert!(private_key_mode_allowed(0o100640));
        assert!(!private_key_mode_allowed(0o100660));
        assert!(!private_key_mode_allowed(0o100644));
    }

    #[test]
    fn direct_server_requires_server_auth_eku_without_dns_san() {
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        let network = Id::from_str("000102030405060708090a0b0c0d0e0f").unwrap();
        let peer = Id::from_str("101112131415161718191a1b1c1d1e1f").unwrap();
        let verifier = DirectServerVerifier {
            roots: Arc::new(roots),
            expected: AuthenticatedIdentity {
                network_id: network,
                role: Role::Node,
                subject_id: peer,
            },
        };
        let issue = |usages: Vec<ExtendedKeyUsagePurpose>| {
            let mut params = CertificateParams::new(Vec::new()).unwrap();
            params.subject_alt_names.push(SanType::URI(
                format!("spiffe://laneway/network/{network}/node/{peer}")
                    .try_into()
                    .unwrap(),
            ));
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = usages;
            let key = KeyPair::generate().unwrap();
            CertificateDer::from(params.signed_by(&key, &issuer).unwrap().der().to_vec())
        };
        let client_only = issue(vec![ExtendedKeyUsagePurpose::ClientAuth]);
        let server_only = issue(vec![ExtendedKeyUsagePurpose::ServerAuth]);
        let both = issue(vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ]);
        let name = ServerName::try_from("peer-id.invalid").unwrap();
        let verify = |certificate: &CertificateDer<'_>| {
            verifier.verify_server_cert(certificate, &[], &name, &[], UnixTime::now())
        };
        assert!(verify(&client_only).is_err());
        assert!(verify(&server_only).is_ok());
        assert!(verify(&both).is_ok());

        let mut expired_params = CertificateParams::new(Vec::new()).unwrap();
        expired_params.subject_alt_names.push(SanType::URI(
            format!("spiffe://laneway/network/{network}/node/{peer}")
                .try_into()
                .unwrap(),
        ));
        expired_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        expired_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        expired_params.not_before = date_time_ymd(2020, 1, 1);
        expired_params.not_after = date_time_ymd(2021, 1, 1);
        let expired_key = KeyPair::generate().unwrap();
        let expired = CertificateDer::from(
            expired_params
                .signed_by(&expired_key, &issuer)
                .unwrap()
                .der()
                .to_vec(),
        );
        assert!(verify(&expired).is_err());
    }
}
