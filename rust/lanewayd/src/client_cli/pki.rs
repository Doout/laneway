use std::{
    fs,
    io::Write,
    net::IpAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use laneway_protocol::Id;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519, PublicKeyData, SanType, SerialNumber,
};
use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use super::admin::{parse_duration, read_file};
use crate::rootless_cli::enroll::{certificates, private_key};

const PEM_LIMIT: usize = 1 << 20;

#[derive(Args)]
pub(super) struct SigningAuthority {
    #[arg(long, default_value = "ca.crt")]
    ca_cert: PathBuf,
    #[arg(long, default_value = "ca.key")]
    ca_key: PathBuf,
}

#[derive(Args)]
pub(super) struct Output {
    #[arg(long)]
    out_cert: Option<PathBuf>,
    #[arg(long)]
    out_key: Option<PathBuf>,
}

#[derive(Args)]
pub(super) struct Leaf {
    #[command(flatten)]
    authority: SigningAuthority,
    #[command(flatten)]
    output: Output,
    #[arg(long)]
    network_id: Id,
    #[arg(long, value_parser = parse_duration, default_value = "720h")]
    validity: Duration,
}

#[derive(Args)]
pub(super) struct Service {
    #[command(flatten)]
    leaf: Leaf,
    #[arg(long)]
    service_id: Id,
    #[arg(long, value_delimiter = ',')]
    dns: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    ip: Vec<String>,
}

#[derive(Subcommand)]
pub(super) enum Operation {
    Init {
        #[arg(long, default_value = ".")]
        out_dir: PathBuf,
        #[arg(long, default_value = "Laneway Development CA")]
        name: String,
        #[arg(long, value_parser = parse_duration, default_value = "87600h")]
        validity: Duration,
    },
    Intermediate {
        #[command(flatten)]
        authority: SigningAuthority,
        #[command(flatten)]
        output: Output,
        #[arg(long, default_value = "Laneway Intermediate CA")]
        name: String,
        #[arg(long, value_parser = parse_duration, default_value = "43800h")]
        validity: Duration,
    },
    VerifyAuthority {
        #[arg(long, default_value = "ca.crt")]
        root: PathBuf,
        #[arg(long, default_value = "intermediate-chain.crt")]
        issuer: PathBuf,
        #[arg(long, default_value = "intermediate.key")]
        key: PathBuf,
    },
    Node {
        #[command(flatten)]
        leaf: Leaf,
        #[arg(long)]
        node_id: Id,
    },
    Relay(Service),
    Controller(Service),
}

pub(super) fn run(operation: Operation) -> Result<()> {
    match operation {
        Operation::Init {
            out_dir,
            name,
            validity,
        } => {
            let params = ca_params(&name, validity, BasicConstraints::Unconstrained)?;
            let key = KeyPair::generate_for(&PKCS_ED25519)?;
            let ca = params.self_signed(&key)?;
            let (certificate, secret) = (out_dir.join("ca.crt"), out_dir.join("ca.key"));
            write_pair(&certificate, &secret, &ca.pem(), &key)?;
            println!(
                "created CA certificate {} and private key {}",
                certificate.display(),
                secret.display()
            );
        }
        Operation::Intermediate {
            authority,
            output,
            name,
            validity,
        } => {
            let chain = authority.chain()?;
            let parsed = parse_chain(&chain)?;
            let signer = authority.signer(&parsed[0])?;
            let params = ca_params(&name, validity, BasicConstraints::Constrained(0))?;
            check_validity(&params, &parsed)?;
            ensure!(
                parsed[0]
                    .basic_constraints()?
                    .is_some_and(|constraints| constraints.value.path_len_constraint != Some(0)),
                "CA cannot issue another CA"
            );
            let key = KeyPair::generate_for(&PKCS_ED25519)?;
            let mut certificate = params.signed_by(&key, &signer)?.pem();
            append_chain(&mut certificate, &chain);
            let (certificate_path, key_path) = output.paths("intermediate");
            write_pair(&certificate_path, &key_path, &certificate, &key)?;
            println!(
                "created intermediate certificate bundle {} and private key {}",
                certificate_path.display(),
                key_path.display()
            );
        }
        Operation::VerifyAuthority { root, issuer, key } => {
            let expected_root = certificates(&read_file(&root, PEM_LIMIT)?)?;
            let authority = SigningAuthority {
                ca_cert: issuer,
                ca_key: key,
            };
            let chain = authority.chain()?;
            let parsed = parse_chain(&chain)?;
            ensure!(
                expected_root.len() == 1
                    && chain.len() >= 2
                    && chain.last() == expected_root.first(),
                "online issuer chain is not anchored by the supplied offline root"
            );
            ensure!(
                parsed
                    .last()
                    .is_some_and(|root| root.issuer() == root.subject()),
                "offline root certificate is not a self-signed CA"
            );
            ensure!(
                parsed.iter().all(|cert| cert.validity().is_valid()),
                "CA certificate chain is outside its validity interval"
            );
            authority.signer(&parsed[0])?;
            println!("online issuer key and chain are valid for the offline root");
        }
        Operation::Node { leaf, node_id } => issue_leaf(leaf, "node", node_id, Vec::new())?,
        Operation::Relay(service) => issue_service(service, "relay")?,
        Operation::Controller(service) => issue_service(service, "controller")?,
    }
    Ok(())
}

fn issue_service(service: Service, role: &str) -> Result<()> {
    let mut names = Vec::new();
    for name in service
        .dns
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
    {
        names.push(SanType::DnsName(name.try_into()?));
    }
    for ip in service
        .ip
        .iter()
        .map(|ip| ip.trim())
        .filter(|ip| !ip.is_empty())
    {
        let ip = ip
            .parse::<IpAddr>()
            .with_context(|| format!("invalid IP address {ip:?}"))?;
        names.push(SanType::IpAddress(ip));
    }
    ensure!(
        !names.is_empty(),
        "at least one --dns or --ip identity is required"
    );
    issue_leaf(service.leaf, role, service.service_id, names)
}

fn issue_leaf(leaf: Leaf, role: &str, id: Id, mut names: Vec<SanType>) -> Result<()> {
    let chain = leaf.authority.chain()?;
    let parsed = parse_chain(&chain)?;
    let signer = leaf.authority.signer(&parsed[0])?;
    let mut params = params(&format!("laneway-{role}-{id}"), leaf.validity)?;
    check_validity(&params, &parsed)?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    if role != "controller" {
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
    }
    let uri = format!("spiffe://laneway/network/{}/{role}/{id}", leaf.network_id);
    names.insert(0, SanType::URI(uri.try_into()?));
    params.subject_alt_names = names;
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    let mut certificate = params.signed_by(&key, &signer)?.pem();
    let include = parsed
        .last()
        .is_some_and(|last| last.issuer() == last.subject());
    append_chain(
        &mut certificate,
        &chain[..chain.len() - usize::from(include)],
    );
    let (cert_path, key_path) = leaf.output.paths(role);
    write_pair(&cert_path, &key_path, &certificate, &key)?;
    println!(
        "created certificate {} and private key {}",
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}

fn params(name: &str, validity: Duration) -> Result<CertificateParams> {
    ensure!(
        !name.is_empty() && !validity.is_zero(),
        "common name and positive validity are required"
    );
    let now = OffsetDateTime::now_utc();
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).context("generate certificate serial")?;
    serial[0] |= 0x01;
    let mut params = CertificateParams::default();
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now
        .checked_add(validity.try_into()?)
        .context("certificate validity exceeds supported range")?;
    params.distinguished_name.push(DnType::CommonName, name);
    Ok(params)
}

fn ca_params(
    name: &str,
    validity: Duration,
    constraints: BasicConstraints,
) -> Result<CertificateParams> {
    let mut params = params(name, validity)?;
    params.is_ca = IsCa::Ca(constraints);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    Ok(params)
}

fn check_validity(params: &CertificateParams, chain: &[X509Certificate<'_>]) -> Result<()> {
    ensure!(
        chain.iter().all(|issuer| issuer.validity().is_valid()
            && params.not_after.unix_timestamp() <= issuer.validity().not_after.timestamp()),
        "certificate validity exceeds CA validity"
    );
    Ok(())
}

impl SigningAuthority {
    fn chain(&self) -> Result<Vec<CertificateDer<'static>>> {
        certificates(&read_file(&self.ca_cert, PEM_LIMIT)?)
    }

    fn signer(&self, certificate: &X509Certificate<'_>) -> Result<Issuer<'static, KeyPair>> {
        let key = Zeroizing::new(read_file(&self.ca_key, PEM_LIMIT)?);
        let key = KeyPair::try_from(&private_key(&key)?)?;
        ensure!(
            key.subject_public_key_info() == certificate.public_key().raw,
            "CA certificate and private key do not match"
        );
        Ok(Issuer::from_ca_cert_der(
            &CertificateDer::from(certificate.as_raw()),
            key,
        )?)
    }
}

fn parse_chain<'a>(chain: &'a [CertificateDer<'_>]) -> Result<Vec<X509Certificate<'a>>> {
    ensure!(
        !chain.is_empty() && chain.len() <= 8,
        "invalid CA certificate chain length"
    );
    let parsed = chain
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let (rest, cert) = X509Certificate::from_der(entry)
                .map_err(|_| anyhow::anyhow!("invalid CA certificate"))?;
            let constraints = cert
                .basic_constraints()?
                .context("missing CA basic constraints")?
                .value;
            ensure!(
                rest.is_empty()
                    && constraints.ca
                    && constraints
                        .path_len_constraint
                        .is_none_or(|limit| index <= limit as usize)
                    && cert
                        .key_usage()?
                        .is_none_or(|usage| usage.value.key_cert_sign())
                    && cert.signature_algorithm == cert.tbs_certificate.signature,
                "invalid CA certificate or path constraints"
            );
            Ok(cert)
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, cert) in parsed.iter().enumerate() {
        if let Some(parent) = parsed.get(index + 1) {
            ensure!(
                cert.issuer() == parent.subject(),
                "CA certificate bundle is not an ordered issuer chain"
            );
            cert.verify_signature(Some(parent.public_key()))?;
        } else if cert.issuer() == cert.subject() {
            cert.verify_signature(None)?;
        }
    }
    Ok(parsed)
}

fn append_chain(pem_text: &mut String, chain: &[CertificateDer<'_>]) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    for der in chain {
        pem_text.push_str("-----BEGIN CERTIFICATE-----\n");
        let line = STANDARD.encode(der);
        for start in (0..line.len()).step_by(64) {
            pem_text.push_str(&line[start..(start + 64).min(line.len())]);
            pem_text.push('\n');
        }
        pem_text.push_str("-----END CERTIFICATE-----\n");
    }
}

impl Output {
    fn paths(self, role: &str) -> (PathBuf, PathBuf) {
        (
            self.out_cert
                .unwrap_or_else(|| format!("{role}.crt").into()),
            self.out_key.unwrap_or_else(|| format!("{role}.key").into()),
        )
    }
}

pub(super) fn stage(
    path: &Path,
    contents: &[u8],
    mode: u32,
    parent_mode: u32,
) -> Result<tempfile::NamedTempFile> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(parent_mode)
        .create(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(contents)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn write_pair(certificate: &Path, secret: &Path, pem: &str, key: &KeyPair) -> Result<()> {
    ensure!(
        certificate != secret,
        "certificate and key paths must differ"
    );
    let certificate_temp = stage(certificate, pem.as_bytes(), 0o644, 0o755)?;
    let private = Zeroizing::new(key.serialize_pem());
    let secret_temp = stage(secret, private.as_bytes(), 0o600, 0o700)?;
    secret_temp
        .persist_noclobber(secret)
        .context("write private key")?;
    if let Err(error) = certificate_temp.persist_noclobber(certificate) {
        let _ = fs::remove_file(secret);
        return Err(error).context("write certificate");
    }
    Ok(())
}
