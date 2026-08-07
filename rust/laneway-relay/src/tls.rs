use std::{fs, io::Cursor, sync::Arc};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::{
    AuthenticatedIdentity, Role, certificate_serial_from_der, identity_from_certificate_der,
};
use quinn::{ServerConfig, TransportConfig, VarInt, crypto::rustls::QuicServerConfig};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};

use crate::Config;

pub(crate) const ALPN: &[u8] = b"laneway-relay/1";
pub(crate) const TCP_FALLBACK_ALPN: &[u8] = b"laneway-fallback/1";
const MAX_CREDENTIAL_BYTES: usize = 1 << 20;
const MAX_DATAGRAM_FRAME: usize = 5 + 1280;

pub(crate) fn server_config(config: &Config) -> Result<ServerConfig> {
    let certificates = load_certificates(&config.tls.certificate_file)?;
    let leaf = certificates
        .first()
        .context("relay certificate chain is empty")?;
    let local_identity =
        identity_from_certificate_der(leaf.as_ref()).context("relay certificate identity")?;
    ensure!(
        local_identity.role == Role::Relay,
        "local certificate role is not relay"
    );
    let key = load_private_key(&config.tls.private_key_file)?;

    let roots = load_certificates(&config.tls.ca_file)?;
    let mut root_store = RootCertStore::empty();
    let (accepted, rejected) = root_store.add_parsable_certificates(roots);
    ensure!(
        accepted > 0 && rejected == 0,
        "CA file contains an invalid certificate"
    );
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .context("build mTLS client verifier")?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key)
        .context("load relay certificate and key")?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    // rustls defaults to zero bytes of TLS early data for servers. Keep it
    // explicit because authenticated control messages are never replay-safe.
    crypto.max_early_data_size = 0;

    let crypto = QuicServerConfig::try_from(crypto).context("build QUIC TLS config")?;
    let mut server = ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .max_idle_timeout(Some(
            config
                .relay
                .idle_timeout
                .try_into()
                .context("relay.idle_timeout exceeds QUIC range")?,
        ))
        .keep_alive_interval(Some(config.relay.idle_timeout / 3))
        .datagram_receive_buffer_size(Some(
            config
                .relay
                .queue_depth
                .saturating_mul(MAX_DATAGRAM_FRAME)
                .max(64 * 1024),
        ))
        .datagram_send_buffer_size(
            config
                .relay
                .queue_depth
                .saturating_mul(MAX_DATAGRAM_FRAME)
                .max(64 * 1024),
        );
    server.transport_config(Arc::new(transport));
    Ok(server)
}

pub(crate) fn tcp_server_config(config: &Config) -> Result<Arc<rustls::ServerConfig>> {
    let certificates = load_certificates(&config.tls.certificate_file)?;
    let leaf = certificates
        .first()
        .context("relay certificate chain is empty")?;
    let local_identity =
        identity_from_certificate_der(leaf.as_ref()).context("relay certificate identity")?;
    ensure!(
        local_identity.role == Role::Relay,
        "local certificate role is not relay"
    );
    let key = load_private_key(&config.tls.private_key_file)?;

    let roots = load_certificates(&config.tls.ca_file)?;
    let mut root_store = RootCertStore::empty();
    let (accepted, rejected) = root_store.add_parsable_certificates(roots);
    ensure!(
        accepted > 0 && rejected == 0,
        "CA file contains an invalid certificate"
    );
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .context("build mTLS client verifier")?;
    let mut crypto =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .context("load relay certificate and key")?;
    crypto.alpn_protocols = vec![TCP_FALLBACK_ALPN.to_vec()];
    crypto.max_early_data_size = 0;
    Ok(Arc::new(crypto))
}

pub(crate) fn local_identity(config: &Config) -> Result<AuthenticatedIdentity> {
    let certificates = load_certificates(&config.tls.certificate_file)?;
    let leaf = certificates
        .first()
        .context("relay certificate chain is empty")?;
    let identity =
        identity_from_certificate_der(leaf.as_ref()).context("relay certificate identity")?;
    ensure!(
        identity.role == Role::Relay,
        "local certificate role is not relay"
    );
    Ok(identity)
}

pub(crate) fn peer_identity(connection: &quinn::Connection) -> Result<AuthenticatedIdentity> {
    let identity = connection
        .peer_identity()
        .context("peer did not present a certificate")?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected QUIC peer identity type"))?;
    let leaf = chain.first().context("peer certificate chain is empty")?;
    authenticated_node_identity(leaf.as_ref())
}

pub(crate) fn peer_certificate_serial(connection: &quinn::Connection) -> Result<Vec<u8>> {
    let identity = connection
        .peer_identity()
        .context("peer did not present a certificate")?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected QUIC peer identity type"))?;
    let leaf = chain.first().context("peer certificate chain is empty")?;
    certificate_serial(leaf.as_ref())
}

pub(crate) fn certificate_serial(der: &[u8]) -> Result<Vec<u8>> {
    certificate_serial_from_der(der).context("parse peer certificate serial")
}

pub(crate) fn authenticated_node_identity(der: &[u8]) -> Result<AuthenticatedIdentity> {
    let identity = identity_from_certificate_der(der).context("peer certificate identity")?;
    ensure!(
        identity.role == Role::Node,
        "peer certificate role is not node"
    );
    Ok(identity)
}

pub(crate) fn validate_negotiation(connection: &quinn::Connection) -> Result<()> {
    let data = connection
        .handshake_data()
        .context("QUIC handshake data is unavailable")?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| anyhow::anyhow!("unexpected QUIC handshake data type"))?;
    ensure!(
        data.protocol.as_deref() == Some(ALPN),
        "Laneway ALPN was not negotiated"
    );
    ensure!(
        connection.max_datagram_size().is_some(),
        "QUIC DATAGRAM was not negotiated"
    );
    Ok(())
}

fn load_certificates(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    let contents = bounded_read(path, "certificate")?;
    let mut reader = Cursor::new(contents);
    let certificates: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certificates =
        certificates.with_context(|| format!("parse certificate {}", path.display()))?;
    if certificates.is_empty() {
        bail!("certificate file {} is empty", path.display());
    }
    Ok(certificates)
}

fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    let contents = bounded_read(path, "private key")?;
    let mut reader = Cursor::new(contents);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parse private key {}", path.display()))?
        .with_context(|| format!("private key file {} is empty", path.display()))
}

fn bounded_read(path: &std::path::Path, kind: &str) -> Result<Vec<u8>> {
    use std::io::Read;

    let file = fs::File::open(path).with_context(|| format!("open {kind} {}", path.display()))?;
    let mut contents = Vec::new();
    file.take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .with_context(|| format!("read {kind} {}", path.display()))?;
    ensure!(
        contents.len() <= MAX_CREDENTIAL_BYTES,
        "{kind} file {} exceeds {MAX_CREDENTIAL_BYTES} bytes",
        path.display()
    );
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, SerialNumber};

    use super::certificate_serial;

    #[test]
    fn high_bit_serial_matches_controller_canonical_encoding() {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.serial_number = Some(SerialNumber::from_slice(&[0x80, 0x01, 0x02]));
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        assert_eq!(
            certificate_serial(certificate.der().as_ref()).unwrap(),
            [0x80, 0x01, 0x02]
        );
    }
}
