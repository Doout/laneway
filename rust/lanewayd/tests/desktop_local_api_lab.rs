#![cfg(target_os = "macos")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command},
    time::Duration,
};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};

#[allow(dead_code)]
#[path = "../../../desktop/src-tauri/src/daemon.rs"]
mod desktop;

const NETWORK: &str = "000102030405060708090a0b0c0d0e0f";
const NODE: &str = "101112131415161718191a1b1c1d1e1f";
const PEER: &str = "202122232425262728292a2b2c2d2e2f";
const ROUTE: &str = "100.96.0.2/32";

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_identity(path: &Path) {
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate().unwrap();
    fs::write(path.join("ca.crt"), ca.self_signed(&key).unwrap().pem()).unwrap();
    let issuer = Issuer::new(ca, key);
    let mut node = CertificateParams::default();
    node.subject_alt_names = vec![SanType::URI(
        format!("spiffe://laneway/network/{NETWORK}/node/{NODE}")
            .try_into()
            .unwrap(),
    )];
    node.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    node.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    fs::write(
        path.join("node.crt"),
        node.signed_by(&key, &issuer).unwrap().pem(),
    )
    .unwrap();
    let private = path.join("node.key");
    fs::write(&private, key.serialize_pem()).unwrap();
    fs::set_permissions(private, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
#[ignore = "requires a Rust daemon extracted from a macOS package"]
async fn packaged_daemon_serves_the_desktop_socket() {
    let runtime = std::env::var_os("LANEWAY_MACOS_PACKAGE_DAEMON").expect("packaged Rust daemon");
    let version = std::env::var("LANEWAY_MACOS_PACKAGE_VERSION").expect("expected package version");
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let path = directory.path();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    write_identity(path);

    // Static userspace mode exercises the shipped local API without utun,
    // route changes, or traffic outside this machine. No relay is necessary.
    let socket = path.join("api.sock");
    fs::write(
        path.join("lab.toml"),
        format!(
            r#"mode = "node"
socket_path = "{socket}"
[identity]
network_id = "{NETWORK}"
node_id = "{NODE}"
[tls]
certificate = "{base}/node.crt"
private_key = "{base}/node.key"
ca = "{base}/ca.crt"
[connector]
userspace = true
[tun]
name = "userspace"
addresses = ["100.96.0.1/32"]
[relay]
address = "127.0.0.1:1"
server_name = "relay.localhost"
service_id = "303132333435363738393a3b3c3d3e3f"
[forwarding]
owned_prefixes = ["192.0.2.0/24"]
[[routes]]
prefix = "{ROUTE}"
via_node = "{PEER}"
"#,
            socket = socket.display(),
            base = path.display(),
        ),
    )
    .unwrap();

    let log = path.join("daemon.log");
    let output = fs::File::create(&log).unwrap();
    let mut daemon = Process(
        Command::new(runtime)
            .current_dir(path)
            .args(["--config", "lab.toml"])
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .expect("start packaged Rust daemon"),
    );
    let snapshot = tokio::time::timeout(Duration::from_secs(10), async {
        while !socket
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
        {
            if let Some(status) = daemon.0.try_wait().unwrap() {
                panic!(
                    "packaged Rust daemon exited with {status}: {}",
                    fs::read_to_string(&log).unwrap_or_default()
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        desktop::LocalDaemon::new(socket).snapshot().await
    })
    .await
    .expect("wait for the packaged socket")
    .expect("read a desktop snapshot from the actual Rust daemon");
    assert_eq!(snapshot.platform, "macos");
    assert_eq!(snapshot.ownership, "same-user-daemon");
    assert!(snapshot.capabilities.snapshot_coherence);
    assert_eq!(snapshot.status.api_revision, 1);
    assert!(snapshot.status.running);
    assert_eq!(snapshot.status.product_version, version);
    assert_eq!(snapshot.status.node_id, NODE);
    assert_eq!(snapshot.status.interface, "userspace");
    assert_eq!(snapshot.peers.len(), 1);
    assert_eq!(snapshot.peers[0].node_id, PEER);
    assert_eq!(snapshot.routes.len(), 1);
    assert_eq!(snapshot.routes[0].prefix, ROUTE);
    assert_eq!(snapshot.routes[0].via_node, PEER);
}
