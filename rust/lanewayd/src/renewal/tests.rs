use super::*;
use rcgen::{BasicConstraints, ExtendedKeyUsagePurpose as Usage, IsCa, Issuer, SanType};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn recovery_token_requires_a_private_regular_file() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = tempfile::tempdir()?;
    let path = dir.path().join("approval");
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
    fs::write(&path, format!("{token}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(recovery_token(&path)?.trim() == token);
    let alias = dir.path().join("alias");
    symlink(&path, &alias)?;
    assert!(recovery_token(&alias).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
    assert!(recovery_token(&path).is_err());
    Ok(())
}

struct Fixture {
    key: KeyPair,
    identity: AuthenticatedIdentity,
    issuer: Issuer<'static, KeyPair>,
    roots: rustls::RootCertStore,
    old: LocalCertificateHealth,
}
impl Fixture {
    fn new() -> Self {
        let mut ca = CertificateParams::new(Vec::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.self_signed(&ca_key).unwrap().der().clone())
            .unwrap();
        Self {
            key: KeyPair::generate().unwrap(),
            identity: AuthenticatedIdentity {
                network_id: "000102030405060708090a0b0c0d0e0f".parse().unwrap(),
                subject_id: "101112131415161718191a1b1c1d1e1f".parse().unwrap(),
                role: Role::Node,
            },
            issuer: Issuer::new(ca, ca_key),
            roots,
            old: LocalCertificateHealth {
                serial: vec![1],
                not_after: 1,
                renew_after: 0,
            },
        }
    }
    fn issue(&self, usages: Vec<Usage>) -> CertificateChain {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(
            format!(
                "spiffe://laneway/network/{}/node/{}",
                self.identity.network_id, self.identity.subject_id
            )
            .try_into()
            .unwrap(),
        )];
        params.serial_number = Some(2u64.into());
        params.extended_key_usages = usages;
        let leaf = params.signed_by(&self.key, &self.issuer).unwrap();
        let expiry = parse_x509_certificate(leaf.der())
            .unwrap()
            .1
            .validity()
            .not_after
            .timestamp() as u64;
        CertificateChain {
            certificates_der: vec![leaf.der().to_vec()],
            not_after_unix_seconds: expiry,
        }
    }
    fn check(&self, chain: &CertificateChain) -> Result<Vec<u8>> {
        validate(chain, &self.key, self.identity, &self.old, 0, &self.roots)
    }
}
#[test]
fn candidate_must_extend_same_trusted_identity_with_both_usages() {
    let mut f = Fixture::new();
    let mut c = f.issue(vec![Usage::ClientAuth, Usage::ServerAuth]);
    assert!(f.check(&c).is_ok());
    for usages in [vec![], vec![Usage::ClientAuth], vec![Usage::ServerAuth]] {
        assert!(f.check(&f.issue(usages)).is_err());
    }
    assert!(
        validate(
            &c,
            &KeyPair::generate().unwrap(),
            f.identity,
            &f.old,
            0,
            &f.roots
        )
        .is_err()
    );
    for other in [
        AuthenticatedIdentity {
            subject_id: f.identity.network_id,
            ..f.identity
        },
        AuthenticatedIdentity {
            network_id: f.identity.subject_id,
            ..f.identity
        },
        AuthenticatedIdentity {
            role: Role::Relay,
            ..f.identity
        },
    ] {
        assert!(validate(&c, &f.key, other, &f.old, 0, &f.roots).is_err());
    }
    assert!(validate(&c, &f.key, f.identity, &f.old, 0, &Fixture::new().roots).is_err());
    assert!(
        validate(
            &c,
            &f.key,
            f.identity,
            &f.old,
            c.not_after_unix_seconds - 1,
            &f.roots
        )
        .is_err()
    );
    c.not_after_unix_seconds -= 1;
    assert!(f.check(&c).is_err());
    c.not_after_unix_seconds += 1;
    f.old.not_after = c.not_after_unix_seconds;
    assert!(f.check(&c).is_err());
    f.old.not_after = 1;
    f.old.serial = vec![2];
    assert!(f.check(&c).is_err());
}

#[test]
fn staged_replacement_preserves_old_file_on_failure_or_external_change() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let mut f = Fixture::new();
    let chain = f.issue(vec![Usage::ClientAuth, Usage::ServerAuth]);
    let pem = f.check(&chain).unwrap();
    f.old.serial = vec![2];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.pem");
    fs::write(&path, &pem).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let alias = dir.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(Staged::open(&alias, &f.old).is_err());
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&path, &alias).unwrap();
    assert!(Staged::open(&path, &f.old).is_err());
    fs::remove_file(&alias).unwrap();
    let mut stage = Staged::open(&path, &f.old).unwrap();
    stage.write(b"candidate").unwrap();
    drop(stage); // Validation or authenticated poll failed.
    assert_eq!(fs::read(&path).unwrap(), pem);
    let mut stage = Staged::open(&path, &f.old).unwrap();
    stage.write(b"candidate").unwrap();
    fs::write(&path, b"operator replacement").unwrap();
    assert!(stage.commit().is_err());
    assert_eq!(fs::read(&path).unwrap(), b"operator replacement");
    fs::write(
        &path,
        [pem.as_slice(), f.key.serialize_pem().as_bytes()].concat(),
    )
    .unwrap();
    assert!(Staged::open(&path, &f.old).is_err());
    fs::write(&path, &pem).unwrap();
    let mut stage = Staged::open(&path, &f.old).unwrap();
    stage.write(b"verified").unwrap();
    stage.commit().unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"verified");
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}
