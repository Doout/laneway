use anyhow::{Result, ensure};
use laneway_controller::node_pki::{NodeIssuer, VerifiedCsr};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const NOW: i64 = 1_800_000_000;
const LIFETIME: i64 = 48 * 3600;

#[test]
#[ignore = "requires Go; run make rust-controller-interop"]
fn go_checks_native_enrollment_certificates() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path();
    let go = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../go");
    let fixture = path.join("issuer-fixture");
    ensure!(
        Command::new("go")
            .args(["test", "-tags=rustinterop", "-c", "-o"])
            .arg(&fixture)
            .arg("./internal/controllerservice")
            .current_dir(go)
            .status()?
            .success(),
        "build Go certificate fixture"
    );
    let run_go = |step: &str| -> Result<()> {
        ensure!(
            Command::new(&fixture)
                .arg("-test.run=^TestRustNodeIssuerFixture$")
                .env("LANEWAY_PKI_FIXTURE", path)
                .env("LANEWAY_PKI_STEP", step)
                .status()?
                .success(),
            "Go fixture step failed: {step}"
        );
        Ok(())
    };
    run_go("prepare")?;
    let read = |file: &str| fs::read(path.join(file));
    let cert = |file: &str| -> Result<CertificateDer<'static>> { Ok(read(file)?.into()) };
    let key = |file: &str| -> Result<PrivateKeyDer<'static>> {
        Ok(PrivatePkcs8KeyDer::from(read(file)?).into())
    };
    let root = cert("root.crt")?;
    let inter = cert("inter.crt")?;
    let online_key = key("inter.key")?;
    let root_key = key("root.key")?;
    let root_chain = std::slice::from_ref(&root);
    let full_chain = &[inter.clone(), root.clone()];
    let direct = NodeIssuer::new(root_chain, &root_key, LIFETIME)?;
    let online = NodeIssuer::new(full_chain, &online_key, LIFETIME)?;
    let only_intermediate = NodeIssuer::new(std::slice::from_ref(&inter), &online_key, LIFETIME)?;
    assert_eq!(only_intermediate.intermediates(), online.intermediates());
    assert!(NodeIssuer::new(root_chain, &online_key, LIFETIME).is_err());
    assert!(NodeIssuer::new(&[root.clone(), inter.clone()], &root_key, LIFETIME).is_err());
    assert!(NodeIssuer::new(&[inter.clone(), inter.clone()], &online_key, LIFETIME).is_err());
    assert!(NodeIssuer::new(root_chain, &root_key, 0).is_err());
    let net = "11111111111111111111111111111111".parse()?;
    let node = "33333333333333333333333333333333".parse()?;
    for variant in ["ed25519", "ecdsa-p256", "ecdsa-p384", "rsa", "rsa-pss"] {
        let request = read(&format!("{variant}.csr"))?;
        let verified = VerifiedCsr::parse(&request)?;
        for (profile, issuer, lease) in [
            ("root", &direct, None),
            ("inter", &online, None),
            ("lease", &online, Some(NOW + 300)),
        ] {
            let leaf = issuer.issue(&verified, net, node, NOW, lease)?;
            assert_eq!(leaf.not_before, NOW - 60);
            assert_eq!(
                leaf.not_after,
                match profile {
                    "root" => NOW + LIFETIME,
                    "inter" => NOW - 60 + 86400,
                    _ => NOW + 300,
                }
            );
            let output =
                |suffix: &str| -> PathBuf { path.join(format!("{profile}-{variant}.{suffix}")) };
            fs::write(output("crt"), leaf.der)?;
            fs::write(output("serial"), leaf.serial)?;
            fs::write(output("chain"), issuer.intermediates().concat())?;
        }
        assert!(online.issue(&verified, net, node, NOW, Some(NOW)).is_err());
        assert!(
            online
                .issue(&verified, net, node, NOW + 86400, None)
                .is_err()
        );
        assert!(
            online
                .issue(&verified, net, node, NOW - 7000, None)
                .is_err()
        );
        let mut trailing = request.clone();
        trailing.push(0);
        assert!(VerifiedCsr::parse(&trailing).is_err());
        let mut damaged = request;
        *damaged.last_mut().unwrap() ^= 1;
        assert!(VerifiedCsr::parse(&damaged).is_err());
    }
    assert!(VerifiedCsr::parse(&[]).is_err());
    assert!(VerifiedCsr::parse(&vec![0; 65537]).is_err());
    let leaf = cert("root-ed25519.crt")?;
    assert!(NodeIssuer::new(&[leaf, root], &root_key, LIFETIME).is_err());
    run_go("verify")
}
