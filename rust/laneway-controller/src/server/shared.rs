use super::{Serving, pem, prepare, runtime, serve, stop};
use anyhow::{Context, Result, ensure};
use laneway_protocol::{
    identity_from_certificate_der,
    tenants::{Deployment, Manifest},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, ffi::OsString, fs::File, io::Read, path::Path};
use tokio::{sync::watch, task::JoinSet};
use x509_parser::prelude::*;

pub fn start(mut args: impl Iterator<Item = OsString>) -> Result<()> {
    const USAGE: &str = "usage: laneway-controller serve-tenants MANIFEST.json";
    let path = args.next().context(USAGE)?;
    ensure!(args.next().is_none(), "{USAGE}");
    let mut bytes = Vec::new();
    File::open(path)?.take(262_145).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 262_144, "tenant manifest exceeds 256 KiB");
    let manifest: Manifest = serde_json::from_slice(&bytes).context("decode tenant manifest")?;
    let cells = validated_entries(&manifest)?
        .into_iter()
        .map(|(host, cell)| {
            prepare(arguments(cell).into_iter(), Some(&host))
                .with_context(|| format!("prepare controller for {host}"))
                .map(|serving| (host, serving))
        })
        .collect::<Result<Vec<_>>>()?;
    runtime()?.block_on(run(cells))
}

pub(crate) fn validated_entries(manifest: &Manifest) -> Result<Vec<(String, &Deployment)>> {
    let entries = manifest.entries().map_err(anyhow::Error::msg)?;
    let mut databases = BTreeSet::new();
    let mut renewals = BTreeSet::new();
    let mut networks = BTreeSet::new();
    let mut services = BTreeSet::new();
    let mut signers = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    for (host, cell) in &entries {
        let database = std::fs::symlink_metadata(&cell.database)?;
        ensure!(database.is_file(), "{host}: expected a regular database");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                database.nlink() == 1,
                "{host}: database must not be hard-linked"
            );
        }
        ensure!(
            databases.insert(std::fs::canonicalize(&cell.database)?),
            "{host}: duplicate tenant database"
        );
        if let Some(dir) = &cell.controller_renewal_dir {
            ensure!(
                renewals.insert(std::fs::canonicalize(dir)?),
                "{host}: duplicate controller renewal directory"
            );
        }
        let cert = rustls_pemfile::certs(&mut pem(&cell.controller_certificate, false)?)
            .next()
            .context("missing tenant controller certificate")??;
        let identity = identity_from_certificate_der(cert.as_ref())?;
        ensure!(
            networks.insert(*identity.network_id.as_bytes())
                && services.insert(*identity.subject_id.as_bytes()),
            "{host}: duplicate tenant network or controller identity"
        );
        let roots = certificates(&cell.client_ca)?;
        let issuer = certificates(&cell.issuer_chain)?;
        ensure!(
            roots.len() == 1 && issuer.last() == roots.first(),
            "{host}: tenant issuer chain must end at its only trust anchor"
        );
        let keys = issuer
            .iter()
            .map(public_key)
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            signers.is_disjoint(&keys),
            "{host}: tenant authorities and issuers must be independent"
        );
        signers.extend(keys);
        let token = pem(&cell.root_token, true)?.into_inner();
        let fingerprint: [u8; 32] = Sha256::digest(token.trim_ascii()).into();
        ensure!(
            credentials.insert(fingerprint),
            "{host}: duplicate root credential"
        );
    }
    Ok(entries)
}

#[cfg(unix)]
pub(crate) fn validate_staged_tenant(host: &str, deployment: &Deployment) -> Result<()> {
    prepare(arguments(deployment).into_iter(), Some(host))?;
    Ok(())
}

fn certificates(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut bytes = pem(path, false)?;
    Ok(rustls_pemfile::certs(&mut bytes).collect::<std::io::Result<_>>()?)
}

fn public_key(der: &rustls::pki_types::CertificateDer<'_>) -> Result<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(der.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid tenant authority certificate"))?;
    Ok(cert.public_key().raw.to_vec())
}

fn arguments(c: &Deployment) -> Vec<OsString> {
    let mut args = vec![
        c.database.clone().into_os_string(),
        c.controller_https.to_string().into(),
        c.controller_certificate.clone().into_os_string(),
        c.controller_key.clone().into_os_string(),
        "--listen-on-network".into(),
        "--root-token-file".into(),
        c.root_token.clone().into_os_string(),
        "--node-issuer".into(),
        c.issuer_chain.clone().into_os_string(),
        c.issuer_key.clone().into_os_string(),
        "2592000".into(),
        "--node-client-ca".into(),
        c.client_ca.clone().into_os_string(),
        "--node-quic".into(),
        "--quic-listen".into(),
        c.controller_quic.to_string().into(),
    ];
    if let Some(profile) = &c.bootstrap_profile {
        args.extend([
            "--bootstrap-profile".into(),
            profile.clone().into_os_string(),
        ]);
    }
    if let Some(dir) = &c.controller_renewal_dir {
        args.extend([
            "--renew-controller-tls".into(),
            dir.clone().into_os_string(),
        ]);
    }
    args
}

async fn run(cells: Vec<(String, Serving)>) -> Result<()> {
    let (shutdown, stopped) = watch::channel(false);
    let mut running = JoinSet::new();
    for (host, cell) in cells {
        let mut stopped = stopped.clone();
        running.spawn(async move {
            serve(cell, async move {
                let _ = stopped.wait_for(|stop| *stop).await;
                Ok(())
            })
            .await
            .with_context(|| format!("controller for {host} stopped"))
        });
    }
    let result = tokio::select! {
        signal = stop() => signal.context("wait for controller shutdown"),
        ended = running.join_next() => {
            ended.context("no tenant controllers are running")?.context("tenant controller task panicked")?
                .and_then(|()| anyhow::bail!("tenant controller exited before shutdown"))
        },
    };
    let _ = shutdown.send(true);
    while let Some(task) = running.join_next().await {
        if result.is_ok() {
            task.context("tenant controller task panicked during shutdown")??;
        }
    }
    result
}
