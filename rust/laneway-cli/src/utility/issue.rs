//! Issue node, service, and intermediate certificates from an existing Laneway CA.
use super::pki::{parse_duration, write_exclusive};
use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::Id;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, SanType,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};
use x509_parser::{extensions::ParsedExtension, parse_x509_certificate, pem::parse_x509_pem};

pub(super) fn run(args: &[OsString]) -> Result<()> {
    let role = args[1].to_str().context("invalid PKI action")?;
    let intermediate = role == "intermediate";
    let service = matches!(role, "relay" | "controller");
    let mut fields = HashMap::new();
    let mut iter = args[2..].iter();
    while let Some(arg) = iter.next() {
        let (flag, inline) = crate::node::split_flag(arg);
        if flag == "--" || flag == "-" || !flag.starts_with('-') {
            break;
        }
        let flag = flag
            .strip_prefix("--")
            .or_else(|| flag.strip_prefix('-'))
            .unwrap();
        if matches!(flag, "help" | "h") {
            println!(
                "Usage: laneway pki {role} [--ca-cert FILE] [--ca-key FILE] [--out-cert FILE] [--out-key FILE] [--validity DURATION]"
            );
            if intermediate {
                println!("  --name NAME");
            } else if service {
                println!("  --network-id ID --service-id ID [--dns NAMES] [--ip ADDRESSES]");
            } else {
                println!("  --network-id ID --node-id ID");
            }
            return Ok(());
        }
        ensure!(
            matches!(
                flag,
                "ca-cert" | "ca-key" | "out-cert" | "out-key" | "validity"
            ) || (intermediate && flag == "name")
                || (!intermediate && flag == "network-id")
                || (role == "node" && flag == "node-id")
                || (service && matches!(flag, "service-id" | "ip" | "dns")),
            "flag provided but not defined: -{flag}"
        );
        let value = inline
            .or_else(|| iter.next().cloned())
            .with_context(|| format!("flag needs an argument: -{flag}"))?;
        fields.insert(flag.to_owned(), value);
    }
    let string = |key: &str, default: &str| -> Result<String> {
        fields.get(key).map_or(Ok(default.to_owned()), |v| {
            v.to_str()
                .map(str::to_owned)
                .with_context(|| format!("invalid {key} option"))
        })
    };
    let path = |key: &str, default: &str| -> PathBuf {
        fields
            .get(key)
            .map(OsString::as_os_str)
            .unwrap_or(OsStr::new(default))
            .into()
    };
    let validity = parse_duration(&string(
        "validity",
        if intermediate { "43800h" } else { "720h" },
    )?)?;
    ensure!(validity.is_positive(), "positive validity required");
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.not_before = now - Duration::minutes(1);
    params.not_after = now
        .checked_add(validity)
        .context("certificate validity exceeds date range")?;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let common_name = if intermediate {
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params
            .key_usages
            .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
        string("name", "Laneway Intermediate CA")?
    } else {
        let network: Id = string("network-id", "")?.parse().context("network ID")?;
        let id: Id = string(if service { "service-id" } else { "node-id" }, "")?
            .parse()
            .context("invalid subject ID")?;
        params.is_ca = IsCa::ExplicitNoCa;
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        if role != "controller" {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
        }
        params.subject_alt_names.push(SanType::URI(
            format!("spiffe://laneway/network/{network}/{role}/{id}").try_into()?,
        ));
        if service {
            for name in string("dns", "")?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                params
                    .subject_alt_names
                    .push(SanType::DnsName(name.try_into()?));
            }
            for value in string("ip", "")?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                params.subject_alt_names.push(SanType::IpAddress(
                    value
                        .parse()
                        .with_context(|| format!("invalid IP address {value:?}"))?,
                ));
            }
            ensure!(
                params.subject_alt_names.len() > 1,
                "at least one --dns or --ip identity is required"
            );
        }
        format!("laneway-{role}-{id}")
    };
    ensure!(!common_name.is_empty(), "CA common name required");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let ca_bytes = fs::read(path("ca-cert", "ca.crt")).context("read CA certificate")?;
    let chain = pem_blocks(&ca_bytes, "CERTIFICATE")?;
    let parsed = chain
        .iter()
        .map(|der| {
            parse_x509_certificate(der)
                .map_err(|_| anyhow::anyhow!("invalid CA certificate"))
                .and_then(|(rest, cert)| {
                    ensure!(rest.is_empty(), "invalid CA certificate");
                    Ok(cert)
                })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        parsed.iter().all(|cert| cert.is_ca()),
        "invalid CA certificate bundle"
    );
    // rcgen and ring cover Laneway's Ed25519 issuer. Other PKCS#8 signer types
    // continue through the existing implementation, before generating any key.
    if parsed
        .iter()
        .any(|cert| cert.public_key().algorithm.algorithm.to_id_string() != "1.3.101.112")
    {
        return crate::compat::run(args);
    }
    for pair in parsed.windows(2) {
        let parent = &pair[1];
        ensure!(
            parent
                .key_usage()?
                .is_none_or(|usage| usage.value.key_cert_sign()),
            "parent CA cannot sign certificates"
        );
        pair[0]
            .verify_signature(Some(parent.public_key()))
            .context("CA bundle is not an ordered issuer chain")?;
    }
    ensure!(
        params.not_after.unix_timestamp_nanos()
            <= i128::from(parsed[0].validity().not_after.timestamp()) * 1_000_000_000,
        "certificate validity exceeds CA validity"
    );
    let key_bytes = fs::read(path("ca-key", "ca.key")).context("read CA private key")?;
    let keys = pem_blocks(&key_bytes, "PRIVATE KEY")?;
    ensure!(keys.len() == 1, "expected one PKCS#8 private key");
    let signer = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(keys[0].as_slice()),
        &rcgen::PKCS_ED25519,
    )?;
    ensure!(
        signer.subject_public_key_info() == parsed[0].public_key().raw,
        "CA certificate and private key do not match"
    );
    let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(chain[0].as_slice()), signer)?;
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = params.signed_by(&key, &issuer)?;
    let mut bundle = cert.pem();
    for (der, cert) in chain.iter().zip(parsed) {
        if intermediate || cert.verify_signature(None).is_err() {
            use base64::{Engine, engine::general_purpose::STANDARD};
            bundle.push_str("-----BEGIN CERTIFICATE-----\n");
            for line in STANDARD.encode(der).as_bytes().chunks(64) {
                bundle.push_str(std::str::from_utf8(line)?);
                bundle.push('\n');
            }
            bundle.push_str("-----END CERTIFICATE-----\n");
        }
    }
    let cert_path = path("out-cert", &format!("{role}.crt"));
    let key_path = path("out-key", &format!("{role}.key"));
    ensure!(
        cert_path != key_path,
        "certificate and key paths must differ"
    );
    for (file, mode) in [(&cert_path, 0o755), (&key_path, 0o700)] {
        let dir = file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(dir)?;
    }
    write_exclusive(&key_path, key.serialize_pem().as_bytes(), 0o600)?;
    if let Err(e) = write_exclusive(&cert_path, bundle.as_bytes(), 0o644) {
        let _ = fs::remove_file(&key_path);
        return Err(e);
    }
    let what = if intermediate {
        "intermediate certificate bundle"
    } else {
        "certificate"
    };
    println!(
        "created {what} {} and private key {}",
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}

fn pem_blocks(mut data: &[u8], kind: &str) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    while !data.is_empty() {
        let (rest, pem) =
            parse_x509_pem(data).map_err(|_| anyhow::anyhow!("invalid {kind} PEM"))?;
        ensure!(pem.label == kind, "expected {kind} PEM");
        result.push(pem.contents);
        data = rest;
    }
    if result.is_empty() {
        bail!("missing {kind} PEM");
    }
    Ok(result)
}

/// Verify the authority format generated by Laneway. External issuer profiles
/// can carry name constraints, policies and other extensions handled by the
/// full general-purpose verifier in the compatibility executable.
pub(super) fn verify(args: &[OsString]) -> Result<()> {
    let mut root = PathBuf::from("ca.crt");
    let mut issuer = PathBuf::from("intermediate-chain.crt");
    let mut key = PathBuf::from("intermediate.key");
    let mut flags = args[2..].iter();
    while let Some(arg) = flags.next() {
        let (flag, inline) = crate::node::split_flag(arg);
        if flag == "--" && flags.len() == 0 {
            break;
        }
        let target = match flag {
            "-h" | "--help" | "-help" => {
                println!(
                    "Usage: laneway pki verify-authority --root ca.crt --issuer intermediate-chain.crt --key intermediate.key"
                );
                return Ok(());
            }
            "-root" | "--root" => &mut root,
            "-issuer" | "--issuer" => &mut issuer,
            "-key" | "--key" => &mut key,
            _ => bail!("unknown argument for pki verify-authority: {arg:?}"),
        };
        *target = inline
            .or_else(|| flags.next().cloned())
            .with_context(|| format!("{flag} requires a file"))?
            .into();
    }
    let roots = pem_blocks(
        &fs::read(root).context("read offline root certificate")?,
        "CERTIFICATE",
    )?;
    ensure!(
        roots.len() == 1,
        "offline root file must contain exactly one certificate"
    );
    let chain = pem_blocks(
        &fs::read(issuer).context("read online issuer chain")?,
        "CERTIFICATE",
    )?;
    ensure!(
        chain.len() >= 2 && chain.last() == roots.first(),
        "online issuer chain is not anchored by the supplied offline root"
    );
    let parsed = chain
        .iter()
        .map(|der| {
            let (rest, cert) = parse_x509_certificate(der)
                .map_err(|_| anyhow::anyhow!("invalid CA certificate"))?;
            ensure!(rest.is_empty(), "invalid CA certificate");
            Ok(cert)
        })
        .collect::<Result<Vec<_>>>()?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    for (index, cert) in parsed.iter().enumerate() {
        ensure!(
            cert.signature_algorithm == cert.tbs_certificate.signature,
            "certificate signature algorithm mismatch"
        );
        let public_key = &cert.public_key().algorithm;
        if public_key.algorithm.to_id_string() != "1.3.101.112"
            || public_key.parameters.is_some()
            || cert.signature_algorithm != *public_key
            || cert
                .raw_serial()
                .first()
                .is_none_or(|first| first & 0x80 != 0)
            || cert.extensions().iter().any(|ext| {
                !matches!(
                    ext.parsed_extension(),
                    ParsedExtension::SubjectKeyIdentifier(_)
                        | ParsedExtension::AuthorityKeyIdentifier(_)
                        | ParsedExtension::KeyUsage(_)
                        | ParsedExtension::BasicConstraints(_)
                )
            })
        {
            return crate::compat::run(args);
        }
        ensure!(cert.extensions_map().is_ok(), "duplicate CA extensions");
        let parent = parsed.get(index + 1).unwrap_or(cert);
        ensure!(
            cert.issuer().as_raw() == parent.subject().as_raw(),
            "issuer names do not match"
        );
        cert.verify_signature(Some(parent.public_key()))
            .context("verify issuer signature")?;
        ensure!(
            cert.validity().not_before.timestamp() <= now
                && now <= cert.validity().not_after.timestamp(),
            "issuer is outside its validity period"
        );
        let bc = cert
            .basic_constraints()?
            .context("issuer needs CA basic constraints")?;
        ensure!(bc.value.ca, "issuer certificate is not a CA");
        if let Some(max) = bc.value.path_len_constraint {
            ensure!(
                index.saturating_sub(1) <= max as usize,
                "issuer exceeds CA path length"
            );
        }
        if index > 0 {
            ensure!(
                cert.key_usage()?
                    .is_none_or(|value| value.value.key_cert_sign()),
                "issuer cannot sign certificates"
            );
        }
        ensure!(
            !chain[..index].contains(&chain[index]),
            "duplicate certificate in issuer chain"
        );
    }
    let keys = pem_blocks(
        &fs::read(key).context("read online issuer key")?,
        "PRIVATE KEY",
    )?;
    ensure!(keys.len() == 1, "expected one PKCS#8 private key");
    let signer = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(keys[0].as_slice()),
        &rcgen::PKCS_ED25519,
    )?;
    ensure!(
        signer.subject_public_key_info() == parsed[0].public_key().raw,
        "CA certificate and private key do not match"
    );
    println!("online issuer key and chain are valid for the offline root");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn command(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn intermediate_issues_a_relay_with_its_chain_and_refuses_key_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
        super::super::pki::init(
            &command(&["--out-dir", dir.path().to_str().unwrap()]),
            Vec::new(),
        )
        .unwrap();
        run(&command(&[
            "pki",
            "intermediate",
            "--ca-cert",
            &path("ca.crt"),
            "--ca-key",
            &path("ca.key"),
            "--out-cert",
            &path("issuer.crt"),
            "--out-key",
            &path("issuer.key"),
        ]))
        .unwrap();
        let mut verify_args = command(&[
            "pki",
            "verify-authority",
            "--root",
            &path("ca.crt"),
            "--issuer",
            &path("issuer.crt"),
            "--key",
            &path("issuer.key"),
        ]);
        verify(&verify_args).unwrap();
        *verify_args.last_mut().unwrap() = path("ca.key").into();
        assert!(verify(&verify_args).is_err());
        let mut args = command(&[
            "pki",
            "relay",
            "--network-id",
            "11111111111111111111111111111111",
            "--service-id",
            "22222222222222222222222222222222",
            "--dns",
            "relay.example",
            "--ca-cert",
            &path("issuer.crt"),
            "--out-cert",
            &path("leaf.crt"),
            "--out-key",
            &path("leaf.key"),
            "--ca-key",
            &path("ca.key"),
        ]);
        assert!(run(&args).is_err());
        assert!(!dir.path().join("leaf.key").exists());
        *args.last_mut().unwrap() = path("issuer.key").into();
        run(&args).unwrap();
        let leaf_bundle = fs::read(path("leaf.crt")).unwrap();
        let certificates = pem_blocks(&leaf_bundle, "CERTIFICATE").unwrap();
        assert_eq!(certificates.len(), 2);
        let identity = laneway_protocol::identity_from_certificate_der(&certificates[0]).unwrap();
        assert_eq!(identity.role, laneway_protocol::Role::Relay);
        let (_, leaf) = parse_x509_certificate(&certificates[0]).unwrap();
        let (_, ca) = parse_x509_certificate(&certificates[1]).unwrap();
        leaf.verify_signature(Some(ca.public_key())).unwrap();
        let usage = leaf.extended_key_usage().unwrap().unwrap().value;
        assert!(usage.server_auth && usage.client_auth);
        assert!(run(&args).is_err());
        assert_eq!(leaf_bundle, fs::read(path("leaf.crt")).unwrap());
    }
}
