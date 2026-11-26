use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use laneway_protocol::{AuthenticatedIdentity, Id, Role, identity_from_certificate_der};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::ParsedCertificate,
};

/// Builds TLS 1.3 for the exact controller authority. The peer's chain and
/// Laneway identity are checked before TLS may send a client credential.
pub fn controller_client_tls(
    roots: RootCertStore,
    name: Option<ServerName<'static>>,
    network: Id,
    service: Id,
    client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig> {
    pinned_service_tls(
        roots,
        name,
        AuthenticatedIdentity {
            network_id: network,
            role: Role::Controller,
            subject_id: service,
        },
        client,
    )
}

pub(crate) fn pinned_service_tls(
    roots: RootCertStore,
    name: Option<ServerName<'static>>,
    expected: AuthenticatedIdentity,
    client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<ClientConfig> {
    ensure!(!roots.is_empty(), "service CA bundle is empty");
    let roots = Arc::new(roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(ServiceVerifier {
        webpki: WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
            .build()
            .context("build service trust verifier")?,
        name,
        roots,
        provider: provider.clone(),
        expected,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    match client {
        Some((chain, key)) => config
            .with_client_auth_cert(chain, key)
            .context("load node TLS identity"),
        None => Ok(config.with_no_client_auth()),
    }
}

#[derive(Debug)]
struct ServiceVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    name: Option<ServerName<'static>>,
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    expected: AuthenticatedIdentity,
}

impl ServerCertVerifier for ServiceVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _request_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if let Some(name) = &self.name {
            self.webpki
                .verify_server_cert(leaf, intermediates, name, ocsp_response, now)?;
        } else {
            verify_server_cert_signed_by_trust_anchor(
                &ParsedCertificate::try_from(leaf)?,
                &self.roots,
                intermediates,
                now,
                self.provider.signature_verification_algorithms.all,
            )?;
        }

        let identity = identity_from_certificate_der(leaf.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if identity != self.expected {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, sync::Arc};

    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, SanType};
    use rustls::{ClientConnection, ServerConfig, ServerConnection, pki_types::PrivatePkcs8KeyDer};

    #[test]
    fn tls_authentication_pins_identity_and_optional_name() {
        let mut root = CertificateParams::default();
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(root, KeyPair::generate().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let network = Id::new([3; 16]).unwrap();
        let service = Id::new([4; 16]).unwrap();

        let wrong = Id::new([5; 16]).unwrap();
        for (role, name, leaf_network, leaf_service, expected) in [
            (
                "controller",
                Some("laneway.example"),
                network,
                service,
                true,
            ),
            (
                "controller",
                Some("unrelated.example"),
                network,
                service,
                false,
            ),
            ("controller", None, network, service, true),
            ("controller", None, wrong, service, false),
            ("controller", None, network, wrong, false),
            ("relay", Some("laneway.example"), network, service, false),
            ("relay", None, network, service, false),
        ] {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["laneway.example".to_owned()]).unwrap();
            params.subject_alt_names.push(SanType::URI(
                format!("spiffe://laneway/network/{leaf_network}/{role}/{leaf_service}")
                    .try_into()
                    .unwrap(),
            ));
            let cert = params.signed_by(&key, &ca).unwrap();
            let server_config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
            let client_config = controller_client_tls(
                roots.clone(),
                name.map(|name| ServerName::try_from(name.to_owned()).unwrap()),
                network,
                service,
                None,
            )
            .unwrap();
            let mut client = ClientConnection::new(
                Arc::new(client_config),
                ServerName::try_from("dial.example").unwrap(),
            )
            .unwrap();
            let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut request = Vec::new();
            client.write_tls(&mut request).unwrap();
            server.read_tls(&mut Cursor::new(request)).unwrap();
            server.process_new_packets().unwrap();
            let mut reply = Vec::new();
            server.write_tls(&mut reply).unwrap();
            client.read_tls(&mut Cursor::new(reply)).unwrap();
            assert_eq!(
                client.process_new_packets().is_ok(),
                expected,
                "{role:?} {name:?} {leaf_network:?} {leaf_service:?}"
            );
        }
    }
}
