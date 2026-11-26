use super::*;
use serde_json::json;
use std::cell::{Cell, RefCell};

const NAME: &str = "laneway-connector-lab";
const VOLUME: &str = "laneway-connector-lab-state";
const OLD: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const TAG: &str = "v1.2.4";
const PREVIOUS: &str = "v1.2.3";
const IMAGE: &str = "ghcr.io/doout/lane-edge-rust@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn inspect_fixture() -> Value {
    json!({
        "Id":OLD, "Name":format!("/{NAME}"), "State":{"Running":true},
        "Config":{
            "Image":IMAGE, "Hostname":"connector-lab", "User":"65532:65532",
            "Entrypoint":["/usr/local/bin/laneway"], "Cmd":["connector","run"],
            "Env":["PATH=/usr/bin"], "Labels":{"org.opencontainers.image.version":"1.2.3"},
        },
        "HostConfig":{
            "NetworkMode":"bridge", "ReadonlyRootfs":true, "Privileged":false,
            "CapDrop":["ALL"], "SecurityOpt":["no-new-privileges:true"],
            "RestartPolicy":{"Name":"unless-stopped"}, "PublishAllPorts":false,
            "Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532",
                     "/run/laneway":"rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532"},
        },
        "Mounts":[{"Type":"volume","Name":VOLUME,"Destination":STATE_MOUNT,"RW":true}],
        "NetworkSettings":{"Networks":{"bridge":{}}},
    })
}

#[test]
fn inspection_rejects_a_different_runtime_and_unsupported_profiles() {
    let fixture = inspect_fixture();
    let accepted = profile(&fixture, OLD, NAME).unwrap();
    assert!(is_standard_running(&fixture, NAME));
    assert_eq!(accepted.volume, VOLUME);
    assert_eq!(accepted.hostname, "connector-lab");
    for (pointer, input) in [
        ("/Config/Image", json!("ghcr.io/doout/lane-edge:1.2.3")),
        ("/Mounts/0/Name", json!("another-connector-state")),
        ("/HostConfig/Privileged", json!(true)),
        ("/Config/Env", json!(["SETUP_TOKEN=unexpected"])),
        (
            "/Config/Labels",
            json!({"com.docker.compose.project":"keep"}),
        ),
        ("/HostConfig/NetworkMode", json!("host")),
    ] {
        let mut changed = fixture.clone();
        *changed.pointer_mut(pointer).unwrap() = input;
        assert!(profile(&changed, OLD, NAME).is_err(), "{pointer}");
        assert!(!is_standard_running(&changed, NAME), "{pointer}");
    }
    assert!(profile(&fixture, NEW, NAME).is_err());
    assert!(!valid_name("laneway-connector-x/state"));
    assert!(!valid_name("laneway-connector-.x"));
}

fn runtime(version: &str, mode: &str, instance: u8, same_node: bool) -> Vec<u8> {
    let id = |byte| laneway_protocol::Id::new([byte; 16]).unwrap().to_string();
    serde_json::to_vec(&json!({
        "network_id":id(1), "node_id":id(if same_node {2} else {3}),
        "daemon_instance_id":id(instance), "running":true, "actor":"node",
        "interface":mode, "product_version":version,
        "controller":{
            "certificate_presented_serial":"a1",
            "certificate_not_after_unix_seconds":u64::MAX,
            "configuration_lease_valid_until_unix_seconds":u64::MAX,
            "identity_lease_expires_at_unix_seconds":0, "configuration_lease_expired":false,
        }
    }))
    .unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Healthy,
    WrongIdentity,
    UncertainStart,
    RejectedRename,
}

struct Fixture {
    mode: Mode,
    name: Cell<Option<&'static str>>,
    original_restarted: Cell<bool>,
    calls: RefCell<Vec<Vec<String>>>,
}

impl Fixture {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            name: Cell::new(Some(OLD)),
            original_restarted: Cell::new(false),
            calls: RefCell::default(),
        }
    }
}

impl Docker for Fixture {
    async fn run(&self, args: &[&str], _deadline: Duration) -> Result<Zeroizing<Vec<u8>>> {
        self.calls
            .borrow_mut()
            .push(args.iter().map(|x| (*x).into()).collect());
        let reply = match args {
            ["exec", OLD, ..] => runtime(
                PREVIOUS,
                "userspace",
                if self.original_restarted.get() {
                    12
                } else {
                    10
                },
                true,
            ),
            ["exec", NEW, ..] => runtime(TAG, "userspace", 11, self.mode == Mode::Healthy),
            ["pull" | "run" | "stop", ..] => Vec::new(),
            ["rename", OLD, _] if self.mode == Mode::RejectedRename => return Err(Exit.into()),
            ["rename", OLD, dest] => {
                self.name.set(if *dest == NAME { Some(OLD) } else { None });
                Vec::new()
            }
            ["create", ..] => {
                self.name.set(Some(NEW));
                NEW.as_bytes().to_vec()
            }
            ["container", "ls", ..] => self.name.get().unwrap_or_default().as_bytes().to_vec(),
            ["start", NEW] if self.mode == Mode::UncertainStart => {
                anyhow::bail!("connection closed while starting")
            }
            ["start", NEW] => Vec::new(),
            ["rm", "--force", NEW] => {
                self.name.set(None);
                Vec::new()
            }
            ["start", OLD] => {
                self.original_restarted.set(true);
                Vec::new()
            }
            ["rm", OLD] => Vec::new(),
            _ => anyhow::bail!("unexpected Docker operation: {args:?}"),
        };
        Ok(Zeroizing::new(reply))
    }
    async fn settle(&self) {}
}

#[tokio::test]
async fn preserves_the_volume_and_rolls_back_the_exact_container() {
    for mode in [Mode::Healthy, Mode::WrongIdentity, Mode::UncertainStart] {
        let docker = Fixture::new(mode);
        let prior: LiveStatus =
            serde_json::from_slice(&runtime(PREVIOUS, "userspace", 10, true)).unwrap();
        let existing = profile(&inspect_fixture(), OLD, NAME).unwrap();
        pull(&docker, IMAGE, VOLUME).await.unwrap();
        let outcome = apply(
            &docker,
            NAME,
            existing,
            IMAGE,
            &prior,
            TAG,
            laneway_protocol::Id::new([4; 16]).unwrap(),
        )
        .await;
        let calls = docker.calls.borrow();
        assert_eq!(calls[0], ["pull", IMAGE]);
        assert!(calls[1].windows(2).any(|arg| arg == ["--network", "none"]));
        assert!(calls[1].windows(2).any(|arg| arg
            == [
                "--volume",
                "laneway-connector-lab-state:/var/lib/laneway:ro"
            ]));
        let create = calls.iter().find(|v| v[0] == "create").unwrap();
        assert!(
            create
                .windows(2)
                .any(|arg| arg == ["--volume", "laneway-connector-lab-state:/var/lib/laneway"])
        );
        assert_eq!(create.last().map(String::as_str), Some(IMAGE));
        assert!(
            calls
                .iter()
                .all(|call| !call.iter().any(|arg| arg == "--volumes" || arg == "-v"))
        );
        match mode {
            Mode::Healthy => {
                assert_eq!(outcome.unwrap(), Activated::Healthy);
                assert_eq!(calls.last().unwrap(), &["rm", OLD]);
            }
            Mode::WrongIdentity => {
                assert_eq!(outcome.unwrap(), Activated::RolledBack);
                assert!(calls.iter().any(|v| v == &["rm", "--force", NEW]));
                assert_eq!(docker.name.get(), Some(OLD));
                assert!(docker.original_restarted.get());
            }
            Mode::UncertainStart => {
                assert!(outcome.is_err());
                assert!(!calls.iter().any(|v| v[0] == "rm"));
                assert!(!docker.original_restarted.get());
            }
            Mode::RejectedRename => unreachable!("exercised separately before candidate creation"),
        }
    }
}

#[tokio::test]
async fn failed_rename_restarts_only_the_still_named_original() {
    let docker = Fixture::new(Mode::RejectedRename);
    let prior: LiveStatus =
        serde_json::from_slice(&runtime(PREVIOUS, "userspace", 10, true)).unwrap();
    let existing = profile(&inspect_fixture(), OLD, NAME).unwrap();
    let outcome = apply(
        &docker,
        NAME,
        existing,
        IMAGE,
        &prior,
        TAG,
        laneway_protocol::Id::new([4; 16]).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, Activated::RolledBack);
    assert_eq!(docker.name.get(), Some(OLD));
    assert!(docker.original_restarted.get());
    assert!(
        docker
            .calls
            .borrow()
            .iter()
            .all(|v| v[0] != "create" && v[0] != "rm")
    );
}

fn credential_tar(kind: tar::EntryType, name: &str) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o600);
    header.set_entry_type(kind);
    let bytes: &[u8] = if kind.is_file() { b"fixture pem" } else { b"" };
    if kind.is_symlink() {
        header.set_link_name("/etc/other").unwrap();
    }
    header.set_size(bytes.len() as u64);
    tar.append_data(&mut header, name, bytes).unwrap();
    tar.into_inner().unwrap()
}

#[test]
fn credential_copy_extracts_no_paths_and_accepts_only_the_named_regular_file() {
    assert_eq!(
        &*single_file(
            &credential_tar(tar::EntryType::Regular, "node.key"),
            "node.key"
        )
        .unwrap(),
        b"fixture pem"
    );
    assert!(
        single_file(
            &credential_tar(tar::EntryType::Symlink, "node.key"),
            "node.key"
        )
        .is_err()
    );
    assert!(
        single_file(
            &credential_tar(tar::EntryType::Regular, "node.crt"),
            "node.key"
        )
        .is_err()
    );
}

struct LabDocker;
impl Docker for LabDocker {
    async fn run(&self, args: &[&str], deadline: Duration) -> Result<Zeroizing<Vec<u8>>> {
        LocalDocker.run(args, deadline).await
    }
    async fn settle(&self) {
        sleep(Duration::from_millis(300)).await;
    }
}

#[tokio::test]
#[ignore = "run the isolated connector-managed-updater.sh Docker gate"]
async fn live_named_volume_update_and_rollback() -> Result<()> {
    let name = std::env::var("LANEWAY_MANAGED_CONNECTOR_LAB_NAME")?;
    let image = std::env::var("LANEWAY_MANAGED_CONNECTOR_LAB_IMAGE")?;
    ensure!(
        Path::new("/.dockerenv").exists()
            && name.starts_with("laneway-connector-update-lab-")
            && valid_name(&name)
            && image.starts_with("ghcr.io/doout/lane-edge-rust:managed-lab-"),
        "requires the disposable Connector lab"
    );
    let docker = LabDocker;
    let old = lookup(&docker, &name)
        .await?
        .context("fixture container is missing")?;
    let profile = inspect(&docker, &old, &name).await?;
    ensure!(
        profile.network.starts_with("container:"),
        "fixture must share a private namespace"
    );
    let before = status(&docker, &old).await?;
    let tag = before.version()?;
    let dir = tempfile::tempdir()?;
    let tls = TlsConfig {
        certificate: copy_credential(&docker, &old, "node.crt", dir.path()).await?,
        private_key: copy_credential(&docker, &old, "node.key", dir.path()).await?,
        ca: copy_credential(&docker, &old, "ca.crt", dir.path()).await?,
    };
    let (network, node) = before.identity.checked()?;
    crate::tls::validate_local(&tls, network, node)?;
    validate_candidate(&docker, &image, &profile.volume).await?;
    assert_eq!(
        apply(
            &docker,
            &name,
            profile,
            &image,
            &before,
            &tag,
            laneway_protocol::Id::new([4; 16])?
        )
        .await?,
        Activated::Healthy,
    );
    let current = lookup(&docker, &name)
        .await?
        .context("replacement missing")?;
    assert_ne!(old, current);
    let before = status(&docker, &current).await?;
    let profile = inspect(&docker, &current, &name).await?;
    validate_candidate(&docker, &image, &profile.volume).await?;
    // Deliberately require a different version so the replacement cannot
    // pass the rollout health gate. The existing image and volume are real.
    let failed = if tag == "v9.99.999" {
        "v9.99.998"
    } else {
        "v9.99.999"
    };
    assert_eq!(
        apply(
            &docker,
            &name,
            profile,
            &image,
            &before,
            failed,
            laneway_protocol::Id::new([5; 16])?
        )
        .await?,
        Activated::RolledBack,
    );
    assert_eq!(lookup(&docker, &name).await?, Some(current.clone()));
    assert!(lookup(&docker, &previous_name(&name)).await?.is_none());
    let after = status(&docker, &current).await?;
    assert_ne!(after.daemon_instance_id, before.daemon_instance_id);
    assert!(after.healthy(&before.identity, &tag)?);
    Ok(())
}
