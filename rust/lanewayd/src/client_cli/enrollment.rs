use std::io::{self, Read, Write};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_protocol::{
    Id,
    v1::{EnrollmentClass, EnrollmentRequest},
};
use prost::Message;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input<'a> {
    endpoint: &'a str,
    ca_pem: String,
    server_name: &'a str,
    service_id: &'a str,
    request: &'a str,
}

pub(super) async fn run() -> Result<()> {
    const MAX_INPUT: u64 = 256 << 10;
    let mut input = Zeroizing::new(Vec::new());
    io::stdin().take(MAX_INPUT + 1).read_to_end(&mut input)?;
    ensure!(
        input.len() as u64 <= MAX_INPUT,
        "enrollment input exceeds 256 KiB"
    );
    let input: Input<'_> =
        serde_json::from_slice(&input).context("decode native enrollment input")?;
    let body = Zeroizing::new(
        STANDARD
            .decode(input.request)
            .context("decode enrollment frame")?,
    );
    let request = EnrollmentRequest::decode(body.as_slice()).context("parse enrollment request")?;
    ensure!(
        matches!(
            EnrollmentClass::try_from(request.expected_enrollment_class),
            Ok(EnrollmentClass::RememberedUser
                | EnrollmentClass::EphemeralUser
                | EnrollmentClass::DurableNode)
        ),
        "a supported enrollment class is required"
    );
    let service = input
        .service_id
        .parse::<Id>()
        .context("invalid controller identity")?;
    let response = crate::rootless_cli::enroll::submit_enrollment(
        input.endpoint,
        input.ca_pem.as_bytes(),
        input.server_name,
        service,
        request,
    )
    .await?;
    io::stdout().lock().write_all(&response.encode_to_vec())?;
    Ok(())
}

pub(super) struct Enrolled {
    pub(super) node: Id,
    pub(super) certificate: Vec<u8>,
    pub(super) key: Zeroizing<String>,
    pub(super) wireguard: Zeroizing<[u8; 32]>,
    pub(super) lease_expires: u64,
    #[cfg(unix)]
    pub(super) overlay: Vec<Vec<u8>>,
}

pub(super) async fn login(domain: &str, token_file: Option<&std::path::Path>) -> Result<()> {
    use super::{
        bootstrap,
        profiles::{Credentials, Profile, Store},
    };
    let store = Store::from_environment();
    let _lock = store.lock(domain)?;
    ensure!(
        !store.exists(domain)?,
        "already logged in to {domain}; use 'laneway logout {domain}' before replacing this identity"
    );
    let metadata = bootstrap::fetch(domain).await?;
    metadata.current_artifact()?;
    let network = metadata.network_id.parse::<Id>()?;
    let service = metadata.controller.service_id.parse::<Id>()?;
    let enrollment = redeem(&metadata, token_file, EnrollmentClass::RememberedUser).await?;
    let node = enrollment.node;
    store.save(
        Profile::new(domain, network, service, node)?,
        Credentials {
            ca: metadata.trust.ca_pem.as_bytes(),
            certificate: &enrollment.certificate,
            private_key: enrollment.key.as_bytes(),
            wireguard_key: enrollment.wireguard.as_ref(),
        },
    )?;
    println!(
        "logged in network={network} node={node} profile={}",
        store.path(domain).display()
    );
    println!("Connect with: laneway connect");
    Ok(())
}

pub(super) async fn redeem(
    metadata: &super::bootstrap::Metadata,
    token_file: Option<&std::path::Path>,
    class: EnrollmentClass,
) -> Result<Enrolled> {
    let code = super::profiles::enrollment_code(token_file)?;
    RedeemTarget {
        endpoint: &metadata.controller.enrollment_endpoint,
        ca: metadata.trust.ca_pem.as_bytes(),
        server_name: &metadata.controller.server_name,
        network: metadata.network_id.parse()?,
        service: metadata.controller.service_id.parse()?,
    }
    .redeem(&code, "", class)
    .await
}

pub(super) struct RedeemTarget<'a> {
    pub(super) endpoint: &'a str,
    pub(super) ca: &'a [u8],
    pub(super) server_name: &'a str,
    pub(super) network: Id,
    pub(super) service: Id,
}

impl RedeemTarget<'_> {
    pub(super) async fn redeem(
        &self,
        code: &str,
        name: &str,
        class: EnrollmentClass,
    ) -> Result<Enrolled> {
        use crate::rootless_cli::enroll::{
            chain_pem, new_csr, submit_enrollment, valid_overlay, wireguard_public_key,
        };
        use laneway_protocol::{AuthenticatedIdentity, Role, identity_from_certificate_der};
        use rcgen::PublicKeyData;
        let network = self.network;
        let csr_name = if name.is_empty() {
            "laneway-temporary-user"
        } else {
            name
        };
        let (key, csr) = new_csr(csr_name)?;
        let mut wireguard = Zeroizing::new([0; 32]);
        getrandom::fill(wireguard.as_mut()).context("generate WireGuard key")?;
        let public = wireguard_public_key(*wireguard);
        let response = submit_enrollment(
            self.endpoint,
            self.ca,
            self.server_name,
            self.service,
            EnrollmentRequest {
                enrollment_token: code.to_owned(),
                requested_name: name.to_owned(),
                pkcs10_csr_der: csr,
                expected_network_id: network.as_bytes().to_vec(),
                expected_enrollment_class: class as i32,
                wireguard_public_key: public.to_vec(),
            },
        )
        .await?;
        let node = Id::from_slice(&response.node_id)?;
        ensure!(
            Id::from_slice(&response.network_id)? == network
                && response.enrollment_class == class as i32
                && response.wireguard_public_key == public
                && !response.overlay_addresses.is_empty()
                && response
                    .overlay_addresses
                    .iter()
                    .all(|address| valid_overlay(address)),
            "controller returned a mismatched or incomplete enrollment"
        );
        let leaf = response
            .certificate_chain
            .as_ref()
            .and_then(|chain| chain.certificates_der.first())
            .context("controller omitted the node certificate")?;
        ensure!(
            identity_from_certificate_der(leaf)?
                == AuthenticatedIdentity {
                    network_id: network,
                    role: Role::Node,
                    subject_id: node
                },
            "issued certificate does not match authenticated bootstrap and enrollment response"
        );
        let (_, certificate) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|_| anyhow::anyhow!("invalid issued node certificate"))?;
        ensure!(
            certificate.public_key().raw == key.subject_public_key_info(),
            "issued certificate does not contain the locally generated public key"
        );
        let lease_expires = response.lease_expires_at_unix_seconds;
        if class == EnrollmentClass::EphemeralUser {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let expiry: u64 = certificate.validity().not_after.timestamp().try_into()?;
            ensure!(
                lease_expires > now && expiry <= lease_expires,
                "ephemeral certificate exceeds or outlives its session lease"
            );
        } else {
            ensure!(
                lease_expires == 0,
                "non-ephemeral enrollment unexpectedly contains an ephemeral lease"
            );
        }
        Ok(Enrolled {
            node,
            certificate: chain_pem(response.certificate_chain)?,
            key: Zeroizing::new(key.serialize_pem()),
            wireguard,
            lease_expires,
            #[cfg(unix)]
            overlay: response.overlay_addresses,
        })
    }
}
