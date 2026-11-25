//! Verified enrollment and renewal for remembered logins and ephemeral users.

use std::{
    fs::File,
    io::Read,
    net::IpAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::{
    AuthenticatedIdentity, Id, Role,
    v1::{
        EnrollmentRequest, EnrollmentResponse, ErrorCode, ProtocolError, RenewalRequest,
        RenewalResponse,
    },
};
use lanewayd_rs::{ControllerConfig, TlsConfig, rootless::renew_certificate};
use prost::Message;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, UnixTime},
};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "linux")]
mod legacy;
mod tls;
#[cfg(target_os = "linux")]
pub(crate) use legacy::run as legacy_command;

pub(crate) use laneway_protocol::v1::EnrollmentClass;
#[cfg(target_os = "linux")]
pub(crate) use tls::https_tls_optional;
pub(crate) use tls::{https_tls, pinned_endpoint};

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const MAX_PROFILE_FILE_BYTES: u64 = 256 << 10;

pub(crate) struct Controller<'a> {
    pub(crate) endpoint: &'a str,
    pub(crate) quic_endpoint: &'a str,
    pub(crate) server_name: &'a str,
    pub(crate) network_id: Id,
    pub(crate) service_id: Id,
    pub(crate) ca_pem: &'a [u8],
}

pub(crate) struct Credentials {
    pub(crate) node_id: Id,
    pub(crate) certificate_pem: Vec<u8>,
    pub(crate) private_key_pem: Zeroizing<Vec<u8>>,
    pub(crate) wireguard_private_key: Zeroizing<[u8; 32]>,
    pub(crate) overlays: Vec<IpAddr>,
    pub(crate) lease_expires_at: Option<SystemTime>,
}

pub(crate) fn enroll(
    controller: &Controller<'_>,
    code: &str,
    class: EnrollmentClass,
) -> Result<Credentials> {
    ensure!(
        matches!(
            class,
            EnrollmentClass::RememberedUser | EnrollmentClass::EphemeralUser
        ),
        "enrollment class must be remembered or ephemeral"
    );
    enroll_as(controller, code, class, "", "laneway-temporary-user")
}

#[cfg(target_os = "linux")]
pub(crate) fn enroll_durable(
    controller: &Controller<'_>,
    code: &str,
    requested_name: &str,
) -> Result<Credentials> {
    enroll_as(
        controller,
        code,
        EnrollmentClass::DurableNode,
        requested_name,
        "laneway-persistent-node",
    )
}

fn enroll_as(
    controller: &Controller<'_>,
    code: &str,
    class: EnrollmentClass,
    requested_name: &str,
    csr_name: &str,
) -> Result<Credentials> {
    let keys = Keys::generate(Some(csr_name))?;
    let mut request = EnrollmentRequest {
        enrollment_token: code.to_owned(),
        pkcs10_csr_der: keys.csr.clone(),
        requested_name: requested_name.to_owned(),
        expected_network_id: controller.network_id.as_bytes().to_vec(),
        expected_enrollment_class: class as i32,
        wireguard_public_key: keys.wg_public.to_vec(),
    };
    let payload = request.encode_to_vec();
    request.enrollment_token.zeroize();
    let response = post(controller, "/v1/enroll", payload, None)?;
    verify_enrollment(controller, &keys, class, response)
}

fn enrollment_url(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("invalid controller HTTPS origin")?;
    let (_, authority) = value
        .split_once("://")
        .context("controller endpoint must use HTTPS")?;
    ensure!(
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && !authority.contains(['?', '#', '@', '\\'])
            && authority
                .split_once('/')
                .is_none_or(|(_, path)| path.is_empty()),
        "controller endpoint must be an HTTPS origin"
    );
    Ok(url)
}

fn post<M: Message + Default>(
    controller: &Controller<'_>,
    path: &str,
    payload: Vec<u8>,
    credentials: Option<(&[u8], &[u8])>,
) -> Result<M> {
    let mut endpoint = enrollment_url(controller.endpoint)?;
    endpoint.set_path(path);
    let server_name = (!controller.server_name.is_empty()).then_some(controller.server_name);
    let tls = match server_name {
        Some(name) => https_tls(
            controller.ca_pem,
            name,
            controller.network_id,
            controller.service_id,
            credentials,
        ),
        None => tls::https_tls_optional(
            controller.ca_pem,
            None,
            controller.network_id,
            controller.service_id,
            credentials,
        ),
    }?;
    let builder = reqwest::blocking::Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(TIMEOUT);
    let (builder, endpoint, authority) = pinned_endpoint(builder, endpoint, server_name)?;
    let client = builder
        .build()
        .context("initialize controller credential client")?;
    let mut request = client.post(endpoint);
    if let Some(authority) = authority {
        request = request.header(reqwest::header::HOST, authority);
    }
    let response = request
        .header("content-type", "application/x-protobuf")
        .header("accept", "application/x-protobuf")
        .body(payload)
        .send()
        .context("request controller credentials")?;
    let status = response.status();
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .context("read controller credential response")?;
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "controller credential response exceeds 1 MiB"
    );
    if !status.is_success() {
        if let Ok(error) = ProtocolError::decode(body.as_slice())
            && error.code() != ErrorCode::Unspecified
        {
            bail!(
                "controller returned HTTP {status} ({})",
                error.code().as_str_name()
            );
        }
        bail!("controller returned HTTP {status}");
    }
    M::decode(body.as_slice()).context("decode controller credential response")
}

fn verify_enrollment(
    controller: &Controller<'_>,
    keys: &Keys,
    class: EnrollmentClass,
    response: EnrollmentResponse,
) -> Result<Credentials> {
    ensure!(
        response.network_id == controller.network_id.as_bytes()
            && response.enrollment_class == class as i32
            && !response.overlay_addresses.is_empty(),
        "controller returned an incomplete or class-mismatched enrollment response"
    );
    let node_id = Id::from_slice(&response.node_id).context("invalid enrolled node ID")?;
    ensure!(
        response.wireguard_public_key == keys.wg_public,
        "controller returned a different WireGuard key"
    );
    let wire_chain = response
        .certificate_chain
        .context("controller omitted the enrollment certificate chain")?;
    let chain = wire_chain
        .certificates_der
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let leaf = verify_node_chain(&chain, controller.ca_pem, controller.network_id, node_id)?;
    let mut credentials = keys.credentials(node_id, &chain, &leaf)?;
    credentials.overlays = response
        .overlay_addresses
        .iter()
        .enumerate()
        .map(|(index, address)| {
            overlay(address).with_context(|| format!("invalid enrolled overlay address {index}"))
        })
        .collect::<Result<_>>()?;
    credentials.lease_expires_at = if class == EnrollmentClass::EphemeralUser {
        let seconds = response.lease_expires_at_unix_seconds;
        ensure!(
            seconds > 0 && seconds <= i64::MAX as u64,
            "ephemeral enrollment response has no bounded lease"
        );
        let lease = UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .context("ephemeral session lease is out of range")?;
        ensure!(
            lease > SystemTime::now()
                && system_time(leaf.validity().not_after.timestamp())? <= lease,
            "ephemeral certificate exceeds or outlives its session lease"
        );
        Some(lease)
    } else {
        ensure!(
            response.lease_expires_at_unix_seconds == 0,
            "non-ephemeral enrollment response unexpectedly contains an ephemeral lease"
        );
        None
    };
    Ok(credentials)
}

/// Verifies the saved node identity and current key before opening a renewal stream.
pub(crate) fn renew(
    controller: &Controller<'_>,
    expected_node: Id,
    ca_path: &Path,
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<Credentials> {
    ensure!(
        !controller.quic_endpoint.is_empty(),
        "controller QUIC endpoint is required to refresh a saved login"
    );
    renew_current(
        controller,
        Some(expected_node),
        ca_path,
        certificate_path,
        private_key_path,
    )
}

fn renew_current(
    controller: &Controller<'_>,
    expected_node: Option<Id>,
    ca_path: &Path,
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<Credentials> {
    enrollment_url(controller.endpoint)?;
    let ca_pem = read_profile_file(ca_path)?;
    ensure!(
        ca_pem.trim_ascii() == controller.ca_pem.trim_ascii(),
        "controller CA changed; refusing to refresh saved credentials"
    );
    let certificate_pem = read_profile_file(certificate_path)?;
    let private_key_pem = Zeroizing::new(read_profile_file(private_key_path)?);
    let chain = tls::certificates(&certificate_pem)?;
    let node_id = expected_node
        .unwrap_or(laneway_protocol::identity_from_certificate_der(&chain[0])?.subject_id);
    let current = verify_node_chain(&chain, &ca_pem, controller.network_id, node_id)?;
    tls::verify_key_pair(&chain, &private_key_pem).context("validate saved node credential")?;
    let name = current
        .subject()
        .iter_common_name()
        .next()
        .map(|name| name.as_str())
        .transpose()
        .context("invalid saved certificate common name")?;
    let keys = Keys::generate(name)?;

    let request = RenewalRequest {
        pkcs10_csr_der: keys.csr.clone(),
        wireguard_public_key: keys.wg_public.to_vec(),
    };
    let response: RenewalResponse = if controller.quic_endpoint.is_empty() {
        post(
            controller,
            "/v1/renew",
            request.encode_to_vec(),
            Some((&certificate_pem, &private_key_pem)),
        )?
    } else {
        let options = ControllerConfig {
            endpoint: controller.endpoint.to_owned(),
            quic_endpoint: Some(controller.quic_endpoint.to_owned()),
            server_name: controller.server_name.to_owned(),
            service_id: controller.service_id.to_string(),
            poll_interval: Duration::from_secs(5),
            timeout: TIMEOUT,
        };
        let tls = TlsConfig {
            ca: ca_path.to_path_buf(),
            certificate: certificate_path.to_path_buf(),
            private_key: private_key_path.to_path_buf(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("create controller renewal runtime")?;
        runtime
            .block_on(async {
                tokio::time::timeout(
                    TIMEOUT,
                    renew_certificate(&options, controller.network_id, &tls, request),
                )
                .await
                .context("controller renewal timed out")?
            })
            .context("refresh node credential")?
    };
    ensure!(
        response.wireguard_public_key == keys.wg_public,
        "refreshed login changed the locally generated WireGuard key"
    );
    let wire_chain = response
        .certificate_chain
        .context("controller returned an incomplete login refresh")?;
    let chain = wire_chain
        .certificates_der
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let leaf = verify_node_chain(&chain, &ca_pem, controller.network_id, node_id)?;
    keys.credentials(node_id, &chain, &leaf)
}

fn read_profile_file(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open saved key material {}", path.display()))?
        .take(MAX_PROFILE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_PROFILE_FILE_BYTES,
        "saved key material is empty or too large"
    );
    Ok(bytes)
}

pub(crate) fn certificate_times(pem: &[u8]) -> Result<(SystemTime, SystemTime)> {
    let certificates = tls::certificates(pem)?;
    let leaf = parse_der(&certificates[0])?;
    Ok((
        system_time(leaf.validity().not_before.timestamp())?,
        system_time(leaf.validity().not_after.timestamp())?,
    ))
}

fn system_time(seconds: i64) -> Result<SystemTime> {
    let duration = Duration::from_secs(seconds.unsigned_abs());
    if seconds < 0 {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
    .context("certificate timestamp is out of range")
}

fn parse_der(der: &[u8]) -> Result<X509Certificate<'_>> {
    let (remaining, certificate) =
        parse_x509_certificate(der).map_err(|_| anyhow::anyhow!("invalid node certificate DER"))?;
    ensure!(
        remaining.is_empty(),
        "node certificate contains trailing DER data"
    );
    Ok(certificate)
}

fn verify_node_chain<'a>(
    chain: &'a [CertificateDer<'_>],
    ca_pem: &[u8],
    network_id: Id,
    node_id: Id,
) -> Result<X509Certificate<'a>> {
    let (leaf, intermediates) = chain
        .split_first()
        .context("controller returned an empty node certificate chain")?;
    for certificate in intermediates {
        parse_der(certificate)?;
    }
    let parsed = parse_der(leaf)?;
    ensure!(
        laneway_protocol::identity_from_certificate_der(leaf.as_ref())?
            == (AuthenticatedIdentity {
                network_id,
                role: Role::Node,
                subject_id: node_id
            }),
        "node certificate identity does not match the authenticated network and node"
    );
    let trust: RootCertStore = tls::roots(ca_pem)?;
    webpki::EndEntityCert::try_from(leaf)
        .context("parse node certificate for verification")?
        .verify_for_usage(
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
            &trust.roots,
            intermediates,
            UnixTime::now(),
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .context("verify node certificate issuer and validity")?;
    Ok(parsed)
}

fn overlay(bytes: &[u8]) -> Result<IpAddr> {
    let address = match bytes.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(bytes)?),
        16 => {
            let address = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes)?);
            ensure!(
                address.to_ipv4_mapped().is_none(),
                "IPv4-mapped IPv6 overlay address"
            );
            IpAddr::V6(address)
        }
        _ => bail!("overlay IP has an invalid length"),
    };
    ensure!(
        !address.is_unspecified() && !address.is_multicast(),
        "overlay IP is unspecified or multicast"
    );
    Ok(address)
}

struct Keys {
    tls: KeyPair,
    csr: Vec<u8>,
    wg_private: Zeroizing<[u8; 32]>,
    wg_public: [u8; 32],
}

impl Keys {
    fn generate(common_name: Option<&str>) -> Result<Self> {
        let tls =
            KeyPair::generate_for(&PKCS_ED25519).context("generate enrollment certificate key")?;
        let mut parameters = CertificateParams::default();
        parameters.distinguished_name = rcgen::DistinguishedName::new();
        if let Some(name) = common_name {
            parameters.distinguished_name.push(DnType::CommonName, name);
        }
        let csr = parameters
            .serialize_request(&tls)
            .context("create enrollment CSR")?
            .der()
            .to_vec();
        let mut wg_private = Zeroizing::new([0u8; 32]);
        getrandom::fill(wg_private.as_mut())
            .map_err(|error| anyhow::anyhow!("generate WireGuard private key: {error}"))?;
        let wg_public = x25519_dalek::x25519(*wg_private, x25519_dalek::X25519_BASEPOINT_BYTES);
        Ok(Self {
            tls,
            csr,
            wg_private,
            wg_public,
        })
    }

    fn credentials(
        &self,
        node_id: Id,
        chain: &[CertificateDer<'_>],
        leaf: &X509Certificate<'_>,
    ) -> Result<Credentials> {
        use rcgen::PublicKeyData;
        ensure!(
            leaf.public_key().raw == self.tls.subject_public_key_info(),
            "issued certificate does not contain the locally generated public key"
        );
        Ok(Credentials {
            node_id,
            certificate_pem: tls::encode_chain(chain),
            private_key_pem: Zeroizing::new(self.tls.serialize_pem().into_bytes()),
            wireguard_private_key: self.wg_private.clone(),
            overlays: Vec::new(),
            lease_expires_at: None,
        })
    }
}

#[cfg(test)]
mod tests;
