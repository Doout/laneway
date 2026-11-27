use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use clap::Args;
use laneway_protocol::{
    Id, Role, identity_from_certificate_der,
    v1::{RenewalRequest, RenewalResponse},
};
use lanewayd_rs::{ControllerConfig, TlsConfig};
use rcgen::PublicKeyData;
use zeroize::Zeroizing;

use super::{
    admin::{self, Auth, Client, Connection, NodeIdentity},
    pki::stage,
};
use crate::rootless_cli::enroll::{
    certificates, chain_pem, https_origin, new_csr, wireguard_public_key,
};

#[derive(Args)]
pub(super) struct Options {
    #[arg(long)]
    controller: String,
    #[arg(long, required_unless_present = "allow_legacy_controller_https")]
    controller_quic: Option<String>,
    #[arg(long)]
    allow_legacy_controller_https: bool,
    #[arg(long, default_value = "/etc/laneway/ca.crt")]
    ca: PathBuf,
    #[arg(long)]
    server_name: Option<String>,
    #[arg(long)]
    controller_network_id: Id,
    #[arg(long)]
    controller_service_id: Id,
    #[arg(long, default_value = "/etc/laneway/node.crt")]
    cert: PathBuf,
    #[arg(long, default_value = "/etc/laneway/node.key")]
    key: PathBuf,
    #[arg(long, default_value = "/etc/laneway/node.next.crt")]
    out_cert: PathBuf,
    #[arg(long, default_value = "/etc/laneway/node.next.key")]
    out_key: PathBuf,
    #[arg(long, default_value = "/etc/laneway/wireguard.next.key")]
    out_wireguard_key: PathBuf,
}

pub(super) async fn run(options: Options) -> Result<()> {
    let paths = [
        &options.out_wireguard_key,
        &options.out_key,
        &options.out_cert,
    ];
    ensure!(
        paths[0] != paths[1] && paths[1] != paths[2] && paths[0] != paths[2],
        "renewal output paths must be distinct"
    );
    for path in paths {
        match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect renewal output {}", path.display()));
            }
            Ok(_) => anyhow::bail!("renewal output already exists: {}", path.display()),
        }
    }
    let network = options.controller_network_id;
    let leaf = certificates(&admin::read_file(&options.cert, 1 << 20)?)?.remove(0);
    let identity = identity_from_certificate_der(&leaf)?;
    ensure!(
        identity.role == Role::Node && identity.network_id == network,
        "active certificate has a different controller network or role"
    );
    let endpoint = https_origin(&options.controller)?;
    let server_name = options.server_name.unwrap_or_else(|| {
        endpoint
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
            .to_owned()
    });
    let (key, csr) = new_csr("laneway-node-renewal")?;
    let mut wireguard = Zeroizing::new([0; 32]);
    getrandom::fill(wireguard.as_mut()).context("generate replacement WireGuard key")?;
    let public = wireguard_public_key(*wireguard);
    let request = RenewalRequest {
        pkcs10_csr_der: csr,
        wireguard_public_key: public.to_vec(),
    };
    let response = if let Some(quic) = options.controller_quic {
        lanewayd_rs::rootless::renew_certificate(
            &ControllerConfig {
                topology_reporting: false,
                auto_renew_certificate: false,
                disable_status_reporting: false,
                private_dns_listen: None,
                endpoint: options.controller,
                quic_endpoint: Some(quic),
                server_name,
                service_id: options.controller_service_id.to_string(),
                poll_interval: Duration::from_secs(30),
                timeout: Duration::from_secs(30),
            },
            network,
            &TlsConfig {
                ca: options.ca,
                certificate: options.cert,
                private_key: options.key,
            },
            request,
        )
        .await?
    } else {
        ensure!(
            options.allow_legacy_controller_https,
            "controller QUIC is required"
        );
        Client::new(
            Connection {
                controller: Some(options.controller),
                ca: options.ca,
                server_name: Some(server_name),
                controller_network_id: Some(network),
                controller_service_id: Some(options.controller_service_id),
            },
            Auth::Node(NodeIdentity {
                cert: options.cert,
                key: options.key,
            }),
        )?
        .renew_legacy(request)
        .await?
    };
    ensure!(
        response.wireguard_public_key == public,
        "renewal returned a different WireGuard key"
    );
    let chain = response
        .certificate_chain
        .context("renewal omitted certificate chain")?;
    let leaf = chain
        .certificates_der
        .first()
        .context("renewal omitted leaf certificate")?;
    let (_, decoded) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|_| anyhow::anyhow!("invalid renewed certificate"))?;
    ensure!(
        identity_from_certificate_der(leaf)? == identity
            && decoded.public_key().raw == key.subject_public_key_info(),
        "renewed certificate has incorrect identity or key"
    );
    let certificate = chain_pem(Some(chain))?;
    let private = Zeroizing::new(key.serialize_pem());
    let staged = [
        stage(paths[0], wireguard.as_ref(), 0o600, 0o700)?,
        stage(paths[1], private.as_bytes(), 0o600, 0o700)?,
        stage(paths[2], &certificate, 0o644, 0o755)?,
    ];
    for (index, (file, path)) in staged.into_iter().zip(paths).enumerate() {
        if let Err(error) = file.persist_noclobber(path) {
            for published in &paths[..index] {
                let _ = fs::remove_file(published);
            }
            return Err(error)
                .with_context(|| format!("publish renewed credential {}", path.display()));
        }
    }
    println!(
        "renewed network={network} node={} certificate={}",
        identity.subject_id,
        options.out_cert.display()
    );
    Ok(())
}

impl Client {
    pub(super) async fn renew_legacy(&self, request: RenewalRequest) -> Result<RenewalResponse> {
        use prost::Message;
        let response = self
            .http
            .post(self.origin.join("/v1/renew")?)
            .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
            .header(reqwest::header::ACCEPT, "application/x-protobuf")
            .body(request.encode_to_vec())
            .send()
            .await?
            .error_for_status()?;
        Ok(RenewalResponse::decode(
            admin::response_body(response).await?.as_slice(),
        )?)
    }
}
