use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_protocol::{
    AuthenticatedIdentity, Id, Role, identity_from_certificate_der,
    v1::{
        CertificateChain, EnrollmentClass, EnrollmentRequest, EnrollmentResponse, RenewalRequest,
        RenewalResponse,
    },
};
use lanewayd_rs::{ControllerConfig, TlsConfig, rootless::renew_certificate};
use prost::Message;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use x509_parser::parse_x509_certificate;

use crate::private;

pub(crate) const MAX_SETUP_TOKEN: usize = 64 << 10;
const MAX_RESPONSE: usize = 1 << 20;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const IDENTITY_FILE: &str = "identity.json";
const IDENTITY_LOCK: &str = "identity.lock";
const TLS_STAGE_PREFIX: &str = ".tls-";

struct Setup {
    name: String,
    code: String,
    controller_endpoint: String,
    controller_quic: String,
    server_name: String,
    network_id: Id,
    controller_service_id: Id,
    relay_endpoint: String,
    relay_service_id: Id,
    ca_pem: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    #[serde(skip)]
    state_dir: PathBuf,
    pub(crate) name: String,
    #[serde(with = "stored_id")]
    pub(crate) network_id: Id,
    #[serde(with = "stored_id")]
    pub(crate) node_id: Id,
    controller_endpoint: String,
    controller_quic: String,
    pub(crate) server_name: String,
    #[serde(with = "stored_id")]
    controller_service_id: Id,
    pub(crate) relay_endpoint: String,
    #[serde(with = "stored_id")]
    pub(crate) relay_service_id: Id,
    #[serde(with = "stored_pem")]
    ca_pem: Vec<u8>,
    #[serde(with = "stored_pem")]
    certificate_pem: Vec<u8>,
    #[serde(with = "stored_pem")]
    private_key_pem: Vec<u8>,
    wireguard_private_key: [u8; 32],
}

pub(crate) struct TlsFiles {
    directory: PathBuf,
    ca: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl TlsFiles {
    pub(crate) fn config(&self) -> TlsConfig {
        TlsConfig {
            ca: self.ca.clone(),
            certificate: self.certificate.clone(),
            private_key: self.private_key.clone(),
        }
    }
}

impl Drop for TlsFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Setup {
    fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        ensure!(
            raw.len() <= MAX_SETUP_TOKEN,
            "connector setup token exceeds 64 KiB"
        );
        let encoded = raw
            .strip_prefix("st1.")
            .context("expected a st1 connector setup token")?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| anyhow::anyhow!("invalid connector setup token encoding"))?;
        let payload = std::str::from_utf8(&bytes).context("connector setup payload is invalid")?;
        ensure!(
            !payload.contains('\r'),
            "connector setup payload contains carriage returns"
        );
        let fields: Vec<&str> = payload
            .strip_suffix('\n')
            .unwrap_or(payload)
            .split('\n')
            .collect();
        let [
            name,
            code,
            endpoint,
            quic,
            server_name,
            network,
            service,
            relay,
            relay_service,
            ca,
        ] = fields.as_slice()
        else {
            anyhow::bail!("invalid connector setup field count");
        };
        ensure!(
            fields[..9].iter().all(|field| !field.is_empty()
                && !field.chars().any(|c| c.is_whitespace() || c.is_control())),
            "connector setup contains an empty or invalid field"
        );
        let controller_endpoint = https_origin(endpoint)?.to_string();
        ServerName::try_from(*server_name).context("invalid controller server name")?;
        validate_host_port(quic).context("invalid controller QUIC endpoint")?;
        validate_host_port(relay).context("invalid relay endpoint")?;
        let ca_pem = STANDARD
            .decode(ca)
            .context("invalid connector setup CA encoding")?;
        roots(&ca_pem)?;
        Ok(Self {
            name: (*name).into(),
            code: (*code).into(),
            controller_endpoint,
            controller_quic: (*quic).into(),
            server_name: (*server_name).into(),
            network_id: network.parse().context("invalid setup network ID")?,
            controller_service_id: service
                .parse()
                .context("invalid setup controller service ID")?,
            relay_endpoint: (*relay).into(),
            relay_service_id: relay_service
                .parse()
                .context("invalid setup relay service ID")?,
            ca_pem,
        })
    }
}

/// Called at startup while holding the exclusive node lock.
pub(crate) fn clean_staged_tls(state_dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(state_dir).context("inspect private connector state")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(suffix) = name
            .to_str()
            .and_then(|name| name.strip_prefix(TLS_STAGE_PREFIX))
        else {
            continue;
        };
        if suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && entry.file_type()?.is_dir()
        {
            let path = entry.path();
            private::ensure_directory(&path)
                .context("check stale private TLS staging directory")?;
            std::fs::remove_dir_all(path).context("remove stale private TLS staging directory")?;
        }
    }
    Ok(())
}

pub(crate) async fn activate(state_dir: &Path, setup_token: &str) -> Result<Identity> {
    let mut setup = Setup::parse(setup_token)?;
    private::ensure_directory(state_dir).context("prepare private connector state")?;
    let _guard = private::try_lock(&state_dir.join(IDENTITY_LOCK))
        .context("lock connector identity for activation")?;
    let path = state_dir.join(IDENTITY_FILE);
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect connector identity"),
        Ok(_) => anyhow::bail!("connector identity already exists"),
    }
    let mut wireguard_private_key = [0; 32];
    getrandom::fill(&mut wireguard_private_key).context("generate WireGuard private key")?;
    let wireguard_public_key = wireguard_public_key(wireguard_private_key);
    let (key, csr) = new_csr(&setup.name)?;
    let enrollment_token = std::mem::take(&mut setup.code);
    let response = enroll_request(
        &setup,
        EnrollmentRequest {
            enrollment_token,
            pkcs10_csr_der: csr,
            requested_name: setup.name.clone(),
            expected_network_id: setup.network_id.as_bytes().to_vec(),
            expected_enrollment_class: EnrollmentClass::DurableNode as i32,
            wireguard_public_key: wireguard_public_key.to_vec(),
        },
    )
    .await?;
    ensure!(
        Id::from_slice(&response.network_id)? == setup.network_id
            && response.enrollment_class == EnrollmentClass::DurableNode as i32
            && response.lease_expires_at_unix_seconds == 0
            && response.wireguard_public_key == wireguard_public_key,
        "controller enrollment binding differs from the connector request"
    );
    ensure!(
        !response.overlay_addresses.is_empty()
            && response
                .overlay_addresses
                .iter()
                .all(|raw| valid_overlay(raw)),
        "controller enrollment contains invalid overlay addresses"
    );
    let node_id =
        Id::from_slice(&response.node_id).context("controller did not return a valid node ID")?;
    let identity = Identity {
        state_dir: state_dir.to_path_buf(),
        name: setup.name,
        network_id: setup.network_id,
        node_id,
        controller_endpoint: setup.controller_endpoint,
        controller_quic: setup.controller_quic,
        server_name: setup.server_name,
        controller_service_id: setup.controller_service_id,
        relay_endpoint: setup.relay_endpoint,
        relay_service_id: setup.relay_service_id,
        ca_pem: setup.ca_pem,
        certificate_pem: chain_pem(response.certificate_chain)?,
        private_key_pem: key.serialize_pem().into_bytes(),
        wireguard_private_key,
    };
    identity.validate()?;
    private::create(&path, &identity.encode()?).context("publish connector identity")?;
    Ok(identity)
}

impl Identity {
    pub(crate) fn load(state_dir: &Path) -> Result<Self> {
        let bytes =
            private::read(&state_dir.join(IDENTITY_FILE)).context("read connector identity")?;
        let mut identity: Self =
            serde_json::from_slice(&bytes).context("parse private connector identity")?;
        identity.state_dir = state_dir.to_path_buf();
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn controller_config(&self) -> ControllerConfig {
        ControllerConfig {
            endpoint: self.controller_endpoint.clone(),
            quic_endpoint: Some(self.controller_quic.clone()),
            server_name: self.server_name.clone(),
            service_id: self.controller_service_id.to_string(),
            poll_interval: Duration::from_secs(30),
            timeout: REQUEST_TIMEOUT,
        }
    }

    pub(crate) fn tls_files(&self) -> Result<TlsFiles> {
        let mut suffix = [0; 16];
        getrandom::fill(&mut suffix).context("generate TLS staging directory name")?;
        let directory = self
            .state_dir
            .join(format!("{TLS_STAGE_PREFIX}{}", hex::encode(suffix)));
        private::ensure_directory(&directory).context("create private TLS staging directory")?;
        let files = TlsFiles {
            ca: directory.join("ca.crt"),
            certificate: directory.join("node.crt"),
            private_key: directory.join("node.key"),
            directory,
        };
        private::create(&files.ca, &self.ca_pem).context("stage connector CA")?;
        private::create(&files.certificate, &self.certificate_pem)
            .context("stage connector certificate")?;
        private::create(&files.private_key, &self.private_key_pem)
            .context("stage connector private key")?;
        Ok(files)
    }

    pub(crate) async fn renew_if_due(&mut self) -> Result<bool> {
        if !self.next_renewal_check()?.is_zero() {
            return Ok(false);
        }
        let _guard = private::try_lock(&self.state_dir.join(IDENTITY_LOCK))
            .context("lock connector identity for renewal")?;
        let mut current = Self::load(&self.state_dir)?;
        if !current.next_renewal_check()?.is_zero() {
            let changed = self.certificate_pem != current.certificate_pem;
            *self = current;
            return Ok(changed);
        }
        let (key, csr) = new_csr(&current.name)?;
        // Preserve the controller's WireGuard binding across TLS renewal and
        // retries so a lost response cannot strand the existing identity.
        let wireguard_public_key = wireguard_public_key(current.wireguard_private_key);
        let tls_files = current.tls_files()?;
        let response: RenewalResponse = renew_certificate(
            &current.controller_config(),
            current.network_id,
            &tls_files.config(),
            RenewalRequest {
                pkcs10_csr_der: csr,
                wireguard_public_key: wireguard_public_key.to_vec(),
            },
        )
        .await?;
        ensure!(
            response.wireguard_public_key == wireguard_public_key,
            "controller renewal changed the WireGuard binding"
        );
        let old_expiry = current.certificate_times()?.1;
        current.certificate_pem = chain_pem(response.certificate_chain)?;
        current.private_key_pem = key.serialize_pem().into_bytes();
        current.validate()?;
        ensure!(
            current.certificate_times()?.1 > old_expiry,
            "renewal did not extend the certificate validity"
        );
        private::write(&current.state_dir.join(IDENTITY_FILE), &current.encode()?)
            .context("publish renewed connector identity")?;
        *self = current;
        Ok(true)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).context("encode connector identity")?;
        // The state reader accepts one MiB, including PEM and JSON encoding.
        ensure!(bytes.len() <= 1 << 20, "connector identity exceeds 1 MiB");
        Ok(bytes)
    }

    pub(crate) fn next_renewal_check(&self) -> Result<Duration> {
        let (start, end) = self.certificate_times()?;
        let renew_after = start + (end - start) * 2 / 3;
        Ok(Duration::from_secs(
            renew_after.saturating_sub(UnixTime::now().as_secs()),
        ))
    }

    fn certificate_times(&self) -> Result<(u64, u64)> {
        let chain = certificates(&self.certificate_pem)?;
        let (_, leaf) = parse_x509_certificate(chain[0].as_ref())
            .map_err(|_| anyhow::anyhow!("invalid connector certificate"))?;
        let start = u64::try_from(leaf.validity().not_before.timestamp())?;
        let end = u64::try_from(leaf.validity().not_after.timestamp())?;
        ensure!(end > start, "invalid connector certificate lifetime");
        Ok((start, end))
    }

    fn validate(&self) -> Result<()> {
        https_origin(&self.controller_endpoint)?;
        ServerName::try_from(self.server_name.as_str())
            .context("invalid controller server name")?;
        validate_host_port(&self.controller_quic).context("invalid controller QUIC endpoint")?;
        validate_host_port(&self.relay_endpoint).context("invalid relay endpoint")?;
        let chain = certificates(&self.certificate_pem)?;
        let leaf = &chain[0];
        ensure!(
            identity_from_certificate_der(leaf.as_ref())
                .context("parse connector certificate identity")?
                == (AuthenticatedIdentity {
                    network_id: self.network_id,
                    role: Role::Node,
                    subject_id: self.node_id,
                }),
            "connector certificate does not match the stored network and node identity"
        );
        let roots = roots(&self.ca_pem)?;
        let verifier =
            webpki::EndEntityCert::try_from(leaf).context("parse connector certificate")?;
        let provider = rustls::crypto::ring::default_provider();
        verifier
            .verify_for_usage(
                provider.signature_verification_algorithms.all,
                &roots.roots,
                &chain[1..],
                UnixTime::now(),
                webpki::KeyUsage::client_auth(),
                None,
                None,
            )
            .context("verify connector certificate chain")?;
        let key = private_key(&self.private_key_pem)?;
        let certified = rustls::sign::CertifiedKey::from_der(chain, key, &provider)
            .context("load connector certificate and private key")?;
        certified
            .keys_match()
            .context("connector certificate does not match its private key")?;
        self.certificate_times()?;
        Ok(())
    }
}

fn https_origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("invalid controller HTTPS origin")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "controller endpoint must be an HTTPS origin"
    );
    Ok(url)
}

fn validate_host_port(value: &str) -> Result<()> {
    let (host, port) = value.rsplit_once(':').context("missing port")?;
    ensure!(
        port.parse::<u16>().is_ok_and(|port| port != 0),
        "invalid port"
    );
    if let Some(ip) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        ip.parse::<std::net::Ipv6Addr>()
            .context("invalid IPv6 host")?;
    } else {
        ensure!(!host.contains(':'), "IPv6 host must be bracketed");
        ServerName::try_from(host).context("invalid host")?;
    }
    Ok(())
}

fn valid_overlay(raw: &[u8]) -> bool {
    let address = match raw.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(raw).expect("validated IPv4 length")),
        16 => {
            let address =
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(raw).expect("validated IPv6 length"));
            if address.to_ipv4_mapped().is_some() {
                return false;
            }
            IpAddr::V6(address)
        }
        _ => return false,
    };
    !address.is_unspecified() && !address.is_multicast()
}

fn new_csr(name: &str) -> Result<(KeyPair, Vec<u8>)> {
    let key = KeyPair::generate_for(&PKCS_ED25519).context("generate connector certificate key")?;
    let mut parameters = CertificateParams::default();
    parameters.distinguished_name.push(DnType::CommonName, name);
    let csr = parameters
        .serialize_request(&key)
        .context("create connector PKCS#10 CSR")?;
    Ok((key, csr.der().to_vec()))
}

fn wireguard_public_key(private: [u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let chain = rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse certificate PEM")?;
    ensure!(!chain.is_empty(), "certificate bundle is empty");
    Ok(chain)
}

fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem))
        .context("parse connector private key")?
        .context("connector private key is missing")
}

fn roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(pem)? {
        roots
            .add(certificate)
            .context("parse controller CA certificate")?;
    }
    Ok(roots)
}

fn chain_pem(chain: Option<CertificateChain>) -> Result<Vec<u8>> {
    let chain = chain.context("controller omitted the connector certificate chain")?;
    ensure!(
        !chain.certificates_der.is_empty(),
        "controller certificate chain is empty"
    );
    let mut output = Vec::new();
    for certificate in chain.certificates_der {
        let (trailing, _) = parse_x509_certificate(&certificate)
            .map_err(|_| anyhow::anyhow!("invalid issued connector certificate"))?;
        ensure!(
            trailing.is_empty(),
            "issued connector certificate contains trailing data"
        );
        output.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        for line in STANDARD.encode(certificate).as_bytes().chunks(64) {
            output.extend_from_slice(line);
            output.push(b'\n');
        }
        output.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    Ok(output)
}

async fn enroll_request(setup: &Setup, request: EnrollmentRequest) -> Result<EnrollmentResponse> {
    let url = https_origin(&setup.controller_endpoint)?
        .join("/v1/enroll")
        .context("construct connector enrollment URL")?;
    let verifier = PinnedController::new(
        &setup.ca_pem,
        &setup.server_name,
        setup.network_id,
        setup.controller_service_id,
    )?;
    // Authenticate the pinned controller before the TLS connection carries the
    // one-time enrollment token.
    let tls = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("initialize connector enrollment client")?;
    let mut response = http
        .post(url)
        .header("content-type", "application/x-protobuf")
        .header("accept", "application/x-protobuf")
        .body(request.encode_to_vec())
        .send()
        .await
        .context("request connector enrollment")?;
    ensure!(
        response.status() == reqwest::StatusCode::CREATED,
        "controller enrollment returned HTTP {}",
        response.status()
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|len| len <= MAX_RESPONSE as u64),
        "controller enrollment response exceeds 1 MiB"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read connector enrollment response")?
    {
        ensure!(
            chunk.len() <= MAX_RESPONSE - body.len(),
            "controller enrollment response exceeds 1 MiB"
        );
        body.extend_from_slice(&chunk);
    }
    EnrollmentResponse::decode(body.as_slice()).context("decode connector enrollment response")
}

#[derive(Debug)]
struct PinnedController {
    verifier: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
    expected: AuthenticatedIdentity,
}

impl PinnedController {
    fn new(ca: &[u8], server_name: &str, network_id: Id, service_id: Id) -> Result<Self> {
        Ok(Self {
            verifier: WebPkiServerVerifier::builder(Arc::new(roots(ca)?))
                .build()
                .context("build controller CA verifier")?,
            name: ServerName::try_from(server_name.to_owned())
                .context("invalid controller server name")?,
            expected: AuthenticatedIdentity {
                network_id,
                role: Role::Controller,
                subject_id: service_id,
            },
        })
    }
}

impl ServerCertVerifier for PinnedController {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let verified = self.verifier.verify_server_cert(
            leaf,
            intermediates,
            &self.name,
            ocsp_response,
            now,
        )?;
        let identity = identity_from_certificate_der(leaf.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if identity != self.expected {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

mod stored_id {
    use laneway_protocol::Id;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &Id, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Id, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

mod stored_pem {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(std::str::from_utf8(value).map_err(serde::ser::Error::custom)?)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        Ok(String::deserialize(deserializer)?.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, ExtendedKeyUsagePurpose, IsCa, Issuer, SanType};

    use super::*;

    const NETWORK: &str = "000102030405060708090a0b0c0d0e0f";
    const CONTROLLER: &str = "101112131415161718191a1b1c1d1e1f";
    const NODE: &str = "202122232425262728292a2b2c2d2e2f";

    fn ca() -> (String, Issuer<'static, KeyPair>) {
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let pem = parameters.self_signed(&key).unwrap().pem();
        (pem, Issuer::new(parameters, key))
    }

    #[test]
    fn cleans_only_staged_tls_directories() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("private");
        private::ensure_directory(&state).unwrap();
        let stale = state.join(format!("{TLS_STAGE_PREFIX}{}", "ab".repeat(16)));
        private::ensure_directory(&stale).unwrap();
        private::create(&stale.join("node.key"), b"old key").unwrap();
        let unrelated = state.join(format!("{TLS_STAGE_PREFIX}backup"));
        private::ensure_directory(&unrelated).unwrap();
        let unrelated_file = state.join(format!("{TLS_STAGE_PREFIX}{}", "bc".repeat(16)));
        private::create(&unrelated_file, b"other file").unwrap();

        clean_staged_tls(&state).unwrap();

        assert!(!stale.exists());
        assert!(unrelated.is_dir());
        assert!(unrelated_file.is_file());
    }

    #[test]
    fn parses_go_connector_setup_token() {
        let (pem, _) = ca();
        let payload = format!(
            "edge-01\ncode\nhttps://control.example.test:4443\ncontrol.example.test:4443\ncontrol.example.test\n{NETWORK}\n{CONTROLLER}\nrelay.example.test:443\n{NODE}\n{}\n",
            STANDARD.encode(pem.as_bytes()),
        );
        let setup = Setup::parse(&format!("st1.{}\n", STANDARD.encode(&payload))).unwrap();
        assert_eq!(setup.name, "edge-01");
        assert_eq!(
            setup.controller_endpoint,
            "https://control.example.test:4443/"
        );
        assert_eq!(setup.ca_pem, pem.as_bytes());
        assert!(
            Setup::parse(&format!(
                "st1.{}",
                STANDARD.encode(payload.replace("https:", "http:"))
            ))
            .is_err()
        );
        assert!(
            Setup::parse(&format!(
                "st1.{}",
                STANDARD.encode(payload.replace(CONTROLLER, ""))
            ))
            .is_err()
        );
    }

    #[test]
    fn controller_verifier_checks_service_role_before_http() {
        let (pem, issuer) = ca();
        let network = NETWORK.parse().unwrap();
        let controller = CONTROLLER.parse().unwrap();
        let trust =
            PinnedController::new(pem.as_bytes(), "control.example.test", network, controller)
                .unwrap();
        let server_name = ServerName::try_from("control.example.test").unwrap();
        let key = KeyPair::generate().unwrap();
        for (role, service_id, expected) in [
            ("controller", CONTROLLER, true),
            ("controller", NODE, false),
            ("relay", CONTROLLER, false),
        ] {
            let mut parameters =
                CertificateParams::new(vec!["control.example.test".into()]).unwrap();
            parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            parameters.subject_alt_names.push(SanType::URI(
                format!("spiffe://laneway/network/{NETWORK}/{role}/{service_id}")
                    .try_into()
                    .unwrap(),
            ));
            let leaf = parameters.signed_by(&key, &issuer).unwrap();
            assert_eq!(
                trust
                    .verify_server_cert(leaf.der(), &[], &server_name, &[], UnixTime::now())
                    .is_ok(),
                expected,
            );
        }
    }

    fn test_identity() -> Identity {
        let (ca, issuer) = ca();
        let (key, _) = new_csr("edge-01").unwrap();
        let mut parameters = CertificateParams::default();
        parameters.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        parameters.subject_alt_names.push(SanType::URI(
            format!("spiffe://laneway/network/{NETWORK}/node/{NODE}")
                .try_into()
                .unwrap(),
        ));
        let leaf = parameters.signed_by(&key, &issuer).unwrap();
        Identity {
            state_dir: PathBuf::new(),
            name: "edge-01".into(),
            network_id: NETWORK.parse().unwrap(),
            node_id: NODE.parse().unwrap(),
            controller_endpoint: "https://control.example.test".into(),
            controller_quic: "control.example.test:443".into(),
            server_name: "control.example.test".into(),
            controller_service_id: CONTROLLER.parse().unwrap(),
            relay_endpoint: "relay.example.test:443".into(),
            relay_service_id: CONTROLLER.parse().unwrap(),
            ca_pem: ca.into_bytes(),
            certificate_pem: leaf.pem().into_bytes(),
            private_key_pem: key.serialize_pem().into_bytes(),
            wireguard_private_key: [1; 32],
        }
    }

    #[test]
    fn stored_identity_rejects_nonmatching_private_key() {
        let mut identity = test_identity();
        assert!(identity.validate().is_ok());
        identity.private_key_pem = new_csr("other").unwrap().0.serialize_pem().into_bytes();
        assert!(identity.validate().is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn system_config_uses_enrolled_identity_and_controller_routes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("system");
        private::ensure_directory(&state).unwrap();
        let file = state.join(IDENTITY_FILE);
        private::create(&file, &test_identity().encode().unwrap()).unwrap();

        let identity = Identity::load(&state).unwrap();
        {
            let tls = identity.tls_files().unwrap();
            let config = crate::system::managed_config(&state, &identity, &tls).unwrap();
            assert_eq!(
                config.ids().unwrap(),
                (identity.network_id, identity.node_id)
            );
            assert_eq!(config.exit_intent_path, state.join("exit-intent-v1.json"));
            assert_eq!(config.tun.name, "lane0");
            assert!(config.tun.configure);
            assert!(config.tun.addresses.is_empty());
            assert!(config.routes.is_empty());
            assert!(config.controller.is_some());
            assert!(!config.forwarding.subnet_router);
            assert!(!config.forwarding.exit_gateway);
            assert!(!config.forwarding.exit_client.enabled);
            let wrong_key = state.join("wrong.key");
            private::create(
                &wrong_key,
                new_csr("wrong").unwrap().0.serialize_pem().as_bytes(),
            )
            .unwrap();
            let mut invalid = config.clone();
            invalid.tls.private_key = wrong_key;
            assert!(lanewayd_rs::Agent::new(invalid).is_err());
            let mut invalid = config;
            invalid.controller.as_mut().unwrap().quic_endpoint = Some("127.0.0.1:0".into());
            assert!(lanewayd_rs::Agent::new(invalid).is_err());
        }
        crate::system::run_enrolled(&state, true).await.unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o077,
            0
        );
        assert!(std::fs::read_dir(&state).unwrap().flatten().all(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(TLS_STAGE_PREFIX)
        }));
    }
}
