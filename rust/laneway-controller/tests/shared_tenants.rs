#![cfg(unix)]

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_controller::{RootCredential, SessionStore, access_admin::Request, backup};
use laneway_protocol::{
    Id,
    tenants::{Deployment, Manifest, Tenant},
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519, SanType,
};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::{SocketAddr, TcpListener, UdpSocket},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Child, Command},
    time::Duration,
};

const DOMAIN: &str = "lane.test";
const INVENTORY: &str = "/v1/admin/networks";

struct Controller(Child);

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut text = format!("-----BEGIN {label}-----\n");
    for begin in (0..encoded.len()).step_by(64) {
        text.push_str(&encoded[begin..(begin + 64).min(encoded.len())]);
        text.push('\n');
    }
    text.push_str(&format!("-----END {label}-----\n"));
    text
}

fn private_file(path: &Path, contents: &str) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(contents.as_bytes())?;
    Ok(())
}

fn create_tenant(
    root: &Path,
    slug: &str,
    identity: u8,
    https: SocketAddr,
    quic: SocketAddr,
) -> Result<(Tenant, Id, String, reqwest::Certificate)> {
    let directory = root.join(slug);
    fs::create_dir(&directory)?;
    let host = format!("{slug}.{DOMAIN}");
    let network = Id::new([identity; 16])?;
    let service = Id::new([identity + 1; 16])?;
    let token = format!("{identity:064x}");

    let mut authority = CertificateParams::new(vec![])?;
    authority.distinguished_name.push(DnType::CommonName, &host);
    authority.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    authority.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    let ca = pem("CERTIFICATE", authority.self_signed(&key)?.der());
    let client_ca = directory.join("authority.crt");
    let issuer_key = directory.join("authority.key");
    fs::write(&client_ca, &ca)?;
    private_file(&issuer_key, &pem("PRIVATE KEY", &key.serialize_der()))?;
    let issuer = Issuer::new(authority, key);

    let mut params = CertificateParams::new(vec![host.clone()])?;
    params.subject_alt_names.push(SanType::URI(
        format!("spiffe://laneway/network/{network}/controller/{service}").try_into()?,
    ));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    let controller_certificate = directory.join("controller.crt");
    let controller_key = directory.join("controller.key");
    fs::write(
        &controller_certificate,
        pem("CERTIFICATE", params.signed_by(&key, &issuer)?.der()),
    )?;
    private_file(&controller_key, &pem("PRIVATE KEY", &key.serialize_der()))?;
    let root_token = directory.join("root.token");
    private_file(&root_token, &token)?;

    let database = directory.join("controller.db");
    backup::initialize(
        &database,
        network,
        service,
        slug,
        &format!("100.96.{identity}.0/24"),
    )?;
    let root_credential = RootCredential::load(&root_token, &database)?;
    SessionStore::open(&database)?.bearer_access(
        &format!("Bearer {token}"),
        Some(&root_credential),
        Ok(Request::RegisterRelay {
            net: network,
            service: Id::new([identity + 5; 16])?,
            node: None,
            name: "Tenant relay".into(),
            endpoint: format!("{host}:4433"),
        }),
    )?;
    let bootstrap_profile = directory.join("bootstrap.json");
    fs::write(
        &bootstrap_profile,
        serde_json::to_vec(&json!({
            "enrollment_endpoint": format!("https://{host}:{}", https.port()),
            "quic_endpoint": format!("{host}:{}", quic.port()),
            "server_name": host,
        }))?,
    )?;
    let tenant = Tenant {
        slug: slug.into(),
        deployment: Deployment {
            database,
            controller_https: https,
            controller_quic: quic,
            controller_certificate,
            controller_key,
            root_token,
            issuer_chain: client_ca.clone(),
            issuer_key,
            client_ca,
            bootstrap_profile: Some(bootstrap_profile),
            controller_renewal_dir: None,
            relay_config: directory.join("relay.toml"),
        },
    };
    Ok((
        tenant,
        network,
        token,
        reqwest::Certificate::from_pem(ca.as_bytes())?,
    ))
}

async fn wait_for_inventory(
    controller: &mut Controller,
    http: &Client,
    url: &str,
    token: &str,
) -> Result<Value> {
    for _ in 0..40 {
        ensure!(
            controller.0.try_wait()?.is_none(),
            "shared controller exited during startup"
        );
        match http.get(url).bearer_auth(token).send().await {
            Ok(response) => {
                let body = response.error_for_status()?.bytes().await?;
                return Ok(serde_json::from_slice(&body)?);
            }
            Err(error) if error.is_connect() => {
                tokio::time::sleep(Duration::from_millis(100)).await
            }
            Err(error) => return Err(error).context("request tenant inventory"),
        }
    }
    anyhow::bail!("timed out waiting for tenant inventory")
}

#[tokio::test]
async fn shared_controller_serves_distinct_tenants_and_rejects_cross_tenant_credentials()
-> Result<()> {
    let workspace = tempfile::tempdir()?;
    let root = workspace.path().canonicalize()?;
    let tcp_a = TcpListener::bind("127.0.0.1:0")?;
    let tcp_b = TcpListener::bind("127.0.0.1:0")?;
    let udp_a = UdpSocket::bind("127.0.0.1:0")?;
    let udp_b = UdpSocket::bind("127.0.0.1:0")?;
    let public = TcpListener::bind("127.0.0.1:0")?;

    let (alpha, alpha_network, alpha_token, alpha_ca) =
        create_tenant(&root, "alpha", 1, tcp_a.local_addr()?, udp_a.local_addr()?)?;
    let (beta, beta_network, beta_token, beta_ca) =
        create_tenant(&root, "beta", 3, tcp_b.local_addr()?, udp_b.local_addr()?)?;
    let alpha_address = alpha.deployment.controller_https;
    let beta_address = beta.deployment.controller_https;
    let mut manifest = Manifest {
        domain: DOMAIN.into(),
        public_listen: public.local_addr()?,
        platform: None,
        tenants: vec![alpha, beta],
    };
    let manifest_path = root.join("tenants.json");
    let controller_binary = env!("CARGO_BIN_EXE_laneway-controller");
    let beta_database = manifest.tenants[1].deployment.database.clone();
    manifest.tenants[1].deployment.database = manifest.tenants[0].deployment.database.clone();
    serde_json::to_writer(File::create(&manifest_path)?, &manifest)?;
    let rejected = Command::new(controller_binary)
        .arg("serve-tenants")
        .arg(&manifest_path)
        .output()?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("duplicate tenant database"));

    manifest.tenants[1].deployment.database = beta_database;
    serde_json::to_writer(File::create(&manifest_path)?, &manifest)?;
    drop((tcp_a, tcp_b, udp_a, udp_b));
    let mut controller = Controller(
        Command::new(controller_binary)
            .arg("serve-tenants")
            .arg(manifest_path)
            .spawn()?,
    );
    let alpha_host = format!("alpha.{DOMAIN}");
    let beta_host = format!("beta.{DOMAIN}");
    let http = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .add_root_certificate(alpha_ca)
        .add_root_certificate(beta_ca)
        .resolve(&alpha_host, alpha_address)
        .resolve(&beta_host, beta_address)
        .build()?;
    let alpha_url = format!("https://{alpha_host}:{}", alpha_address.port());
    let beta_url = format!("https://{beta_host}:{}", beta_address.port());

    for (url, network, own, other) in [
        (alpha_url, alpha_network, &alpha_token, &beta_token),
        (beta_url, beta_network, &beta_token, &alpha_token),
    ] {
        let endpoint = format!("{url}{INVENTORY}");
        let inventory = wait_for_inventory(&mut controller, &http, &endpoint, own).await?;
        assert_eq!(inventory["networks"].as_array().unwrap().len(), 1);
        assert_eq!(inventory["networks"][0]["network_id"], network.to_string());
        assert_eq!(
            http.get(&endpoint)
                .bearer_auth(other)
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let discovery = http
            .get(format!("{url}/.well-known/laneway/bootstrap.json"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        assert_eq!(
            serde_json::from_slice::<Value>(&discovery)?["network_id"],
            network.to_string()
        );
    }
    Ok(())
}
