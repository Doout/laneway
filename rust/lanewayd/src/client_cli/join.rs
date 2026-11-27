use std::{fs, io, net::IpAddr, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use laneway_protocol::{Id, v1::EnrollmentClass};
use zeroize::Zeroizing;

use super::{
    admin::read_file, bootstrap, enrollment::RedeemTarget, pki::stage, profiles::enrollment_code,
};
use crate::rootless_cli::enroll::https_origin;

#[derive(Args)]
pub(super) struct Options {
    #[arg(value_name = "TOKEN")]
    token: Option<String>,
    #[arg(long)]
    token_file: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["controller", "ca", "server_name", "controller_network_id", "controller_service_id"])]
    bootstrap: Option<String>,
    #[arg(long)]
    controller: Option<String>,
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(long)]
    server_name: Option<String>,
    #[arg(long)]
    controller_network_id: Option<Id>,
    #[arg(long)]
    controller_service_id: Option<Id>,
    #[arg(long, default_value = "")]
    name: String,
    #[arg(long, default_value = "/etc/laneway/node.crt")]
    out_cert: PathBuf,
    #[arg(long, default_value = "/etc/laneway/node.key")]
    out_key: PathBuf,
    #[arg(long, default_value = "/etc/laneway/wireguard.key")]
    out_wireguard_key: PathBuf,
}

pub(super) async fn run(mut options: Options, class: EnrollmentClass) -> Result<()> {
    let paths = [
        &options.out_wireguard_key,
        &options.out_key,
        &options.out_cert,
    ];
    ensure!(
        paths[0] != paths[1] && paths[0] != paths[2] && paths[1] != paths[2],
        "credential output paths must be distinct"
    );
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => bail!(
                "refusing to replace existing credential output {}",
                path.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        }
    }

    let mut domain = options.bootstrap.take();
    if domain.is_none()
        && options.controller.is_none()
        && options
            .token
            .as_ref()
            .is_some_and(|token| token.contains('.'))
    {
        domain = options.token.take();
    }
    let (ca, endpoint, server_name, network, service) = if let Some(domain) = domain {
        ensure!(
            options.token.is_none(),
            "bootstrap enrollment requires --token-file or an interactive prompt"
        );
        ensure!(
            options.ca.is_none()
                && options.server_name.is_none()
                && options.controller_network_id.is_none()
                && options.controller_service_id.is_none(),
            "controller options cannot override authenticated bootstrap metadata"
        );
        let metadata = bootstrap::fetch(&domain).await?;
        metadata.current_artifact()?;
        (
            metadata.trust.ca_pem.into_bytes(),
            metadata.controller.enrollment_endpoint,
            metadata.controller.server_name,
            metadata.network_id.parse()?,
            metadata.controller.service_id.parse()?,
        )
    } else {
        ensure!(!options.name.is_empty(), "join requires --name");
        ensure!(
            options.token.is_some() || options.token_file.is_some(),
            "join requires a token or --token-file"
        );
        ensure!(
            options.token.is_none() || options.token_file.is_none(),
            "join accepts either TOKEN or --token-file"
        );
        let endpoint = options.controller.context("--controller is required")?;
        let url = https_origin(&endpoint)?;
        let name = options
            .server_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                url.host_str()
                    .unwrap_or_default()
                    .trim_matches(['[', ']'])
                    .to_owned()
            });
        let network = options
            .controller_network_id
            .context("--controller-network-id is required")?;
        let service = options
            .controller_service_id
            .context("--controller-service-id is required")?;
        let ca = read_file(
            &options.ca.unwrap_or_else(|| "/etc/laneway/ca.crt".into()),
            1 << 20,
        )?;
        (ca, endpoint, name, network, service)
    };

    let code = if let Some(token) = options.token {
        Zeroizing::new(token)
    } else {
        enrollment_code(options.token_file.as_deref())?
    };
    let enrolled = RedeemTarget {
        endpoint: &endpoint,
        ca: &ca,
        server_name: &server_name,
        network,
        service,
    }
    .redeem(&code, &options.name, class)
    .await?;
    #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
    let generation = if class == EnrollmentClass::EphemeralUser {
        Some(
            enrolled
                .exit_generation
                .context("missing test Exit generation")?,
        )
    } else {
        None
    };
    let files = [
        stage(paths[0], enrolled.wireguard.as_ref(), 0o600, 0o700)?,
        stage(paths[1], enrolled.key.as_bytes(), 0o600, 0o700)?,
        stage(paths[2], &enrolled.certificate, 0o644, 0o755)?,
    ];
    for (index, (file, path)) in files.into_iter().zip(paths).enumerate() {
        if let Err(error) = file.persist_noclobber(path) {
            for path in &paths[..index] {
                let _ = fs::remove_file(path);
            }
            return Err(error).with_context(|| format!("publish {}", path.display()));
        }
    }

    let overlays = enrolled
        .overlay
        .iter()
        .map(|bytes| match bytes.as_slice() {
            &[a, b, c, d] => Ok(format!("{}/32", IpAddr::from([a, b, c, d]))),
            bytes => Ok(format!(
                "{}/128",
                IpAddr::from(<[u8; 16]>::try_from(bytes)?)
            )),
        })
        .collect::<Result<Vec<_>>>()?
        .join(",");
    #[cfg(all(target_os = "linux", feature = "network-fixtures"))]
    if let Some(generation) = generation {
        println!(
            "enrolled network={network} node={} overlay={overlays} generation={generation}",
            enrolled.node
        );
        return Ok(());
    }
    println!(
        "enrolled network={network} node={} overlay={overlays} certificate={}",
        enrolled.node,
        options.out_cert.display()
    );
    Ok(())
}
