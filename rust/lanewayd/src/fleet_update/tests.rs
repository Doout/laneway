use super::*;
use std::{cell::Cell, fs, path::PathBuf};

const V1: &str = "v1.2.3";
const V2: &str = "v1.2.4";

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn status() -> LiveStatus {
    LiveStatus {
        identity: RuntimeIdentity {
            network: id(1).to_string(),
            node: id(2).to_string(),
        },
        daemon_instance_id: id(10).to_string(),
        product_version: V1.into(),
        running: true,
        actor: "node".into(),
        interface: "lane0".into(),
        controller: ControlHealth {
            certificate_presented_serial: "caf0".into(),
            certificate_not_after_unix_seconds: u64::MAX,
            identity_lease_expires_at_unix_seconds: 0,
            configuration_lease_valid_until_unix_seconds: u64::MAX,
            configuration_lease_expired: false,
        },
    }
}

#[derive(Default)]
struct Upstream {
    lose_claim: bool,
    requested: Option<Component>,
    assigned: Option<Component>,
    reject_ack: Cell<bool>,
    polls: Cell<usize>,
    acknowledgements: Cell<usize>,
}

impl Control for Upstream {
    async fn poll(&self, request: &Poll) -> Result<Option<Assignment>> {
        self.polls.set(self.polls.get() + 1);
        assert_eq!(request.current_version, V1);
        assert_eq!(request.runtime_node_id, id(2).to_string());
        assert_eq!(
            request.component,
            self.requested.clone().unwrap_or(Component::Node)
        );
        if self.lose_claim {
            bail!("controller committed the claim but the connection was lost");
        }
        Ok(Some(Assignment {
            id: id(3).to_string(),
            version: V2.into(),
            component: self.assigned.clone().unwrap_or(Component::Node),
            channel: Channel::Manual,
        }))
    }

    async fn ack(&self, update: Id, report: &Report) -> Result<()> {
        assert_eq!(update, id(3));
        assert_eq!(report.runtime_node_id, id(2).to_string());
        self.acknowledgements.set(self.acknowledgements.get() + 1);
        ensure!(!self.reject_ack.get(), "ACK connection lost");
        Ok(())
    }
}

#[tokio::test]
async fn connector_uses_its_own_claim_lane_and_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    let name = "laneway-connector-lab";
    let before = status();
    let connector = Journal::open_named(&path, Some(name)).unwrap();
    let wrong = Upstream {
        requested: Some(Component::Connector),
        ..Upstream::default()
    };
    assert!(
        claim(
            &connector,
            &wrong,
            &before.identity,
            V1,
            Component::Connector,
            Channel::Manual
        )
        .await
        .is_err()
    );
    assert!(matches!(
        connector.read().unwrap(),
        Some(Entry::Intent { .. })
    ));
    assert_eq!(wrong.acknowledgements.get(), 0);
    drop(connector);
    assert!(Journal::open(&path).unwrap().read().unwrap().is_none());

    let connector = Journal::open_named(&path, Some(name)).unwrap();
    assert!(connector.read().unwrap().is_some());
    // Independently model a fresh operator-configured Connector.
    let other = Journal::open_named(&dir.path().join("other"), Some(name)).unwrap();
    let correct = Upstream {
        requested: Some(Component::Connector),
        assigned: Some(Component::Connector),
        ..Upstream::default()
    };
    assert_eq!(
        claim(
            &other,
            &correct,
            &before.identity,
            V1,
            Component::Connector,
            Channel::Manual
        )
        .await
        .unwrap()
        .map(|x| x.0),
        Some(id(3))
    );
}

#[tokio::test]
async fn a_lost_claim_response_survives_a_new_timer_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    let first = Journal::open(&path).unwrap();
    assert!(Journal::open(&path).is_err());
    let original = status();
    let upstream = Upstream {
        lose_claim: true,
        ..Upstream::default()
    };
    assert!(
        claim(
            &first,
            &upstream,
            &original.identity,
            V1,
            Component::Node,
            Channel::Manual
        )
        .await
        .is_err()
    );
    drop(first);
    let journal = Journal::open(&path).unwrap();
    let pending = journal.read().unwrap().unwrap();
    assert!(matches!(pending, Entry::Intent { .. }));
    assert!(
        retry_terminal(&journal, &upstream, pending, &original)
            .await
            .is_err()
    );
    assert_eq!(upstream.polls.get(), 1);
    assert_eq!(upstream.acknowledgements.get(), 0);
    let (report, bound) =
        reconcile_report(journal.read().unwrap(), &original, id(3), V2, V1).unwrap();
    assert!(!bound);
    assert_eq!(report.state, Outcome::RolledBack);
}

#[tokio::test]
async fn terminal_retry_requires_the_same_live_runtime_and_never_reclaims() {
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(&dir.path().join("private")).unwrap();
    let upstream = Upstream::default();
    let before = status();
    let (assigned, version) = claim(
        &journal,
        &upstream,
        &before.identity,
        V1,
        Component::Node,
        Channel::Manual,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((assigned, version.as_str()), (id(3), V2));
    assert!(matches!(
        journal.read().unwrap(),
        Some(Entry::Claimed { .. })
    ));
    assert!(reconcile_report(journal.read().unwrap(), &before, id(4), V2, V1).is_err());
    let result = evidence(&before.identity, Outcome::Healthy, V2, "checked");
    journal
        .save(&terminal(&before.identity, assigned, result))
        .unwrap();
    let mut current = status();
    current.product_version = V2.into();
    current.identity.node = id(5).to_string();
    assert!(
        retry_terminal(
            &journal,
            &upstream,
            journal.read().unwrap().unwrap(),
            &current
        )
        .await
        .is_err()
    );
    current.identity = before.identity;
    current.controller.configuration_lease_expired = true;
    assert!(
        retry_terminal(
            &journal,
            &upstream,
            journal.read().unwrap().unwrap(),
            &current
        )
        .await
        .is_err()
    );
    assert_eq!(upstream.acknowledgements.get(), 0);
    current.controller.configuration_lease_expired = false;
    upstream.reject_ack.set(true);
    assert!(
        retry_terminal(
            &journal,
            &upstream,
            journal.read().unwrap().unwrap(),
            &current
        )
        .await
        .is_err()
    );
    upstream.reject_ack.set(false);
    assert!(
        retry_terminal(
            &journal,
            &upstream,
            journal.read().unwrap().unwrap(),
            &current
        )
        .await
        .unwrap()
    );
    assert!(journal.read().unwrap().is_none());
    assert_eq!(upstream.acknowledgements.get(), 2);
    assert_eq!(upstream.polls.get(), 1);
}

struct FixtureService {
    installed: PathBuf,
    launches: Cell<u8>,
    reject_target: bool,
    reject_rollback: bool,
}

impl Runtime for FixtureService {
    async fn status(&self) -> Result<LiveStatus> {
        let mut current = status();
        current.product_version = fs::read_to_string(&self.installed)?;
        let n = self.launches.get();
        current.daemon_instance_id = id(10 + n).to_string();
        current.controller.configuration_lease_expired =
            (n == 1 && self.reject_target) || (n == 2 && self.reject_rollback);
        Ok(current)
    }

    async fn restart(&self) -> Result<()> {
        self.launches.set(self.launches.get() + 1);
        Ok(())
    }

    async fn await_rollback(
        &self,
        before: &LiveStatus,
        version: &str,
        rejected: Option<&str>,
    ) -> bool {
        let value = self.status().await.unwrap();
        value.daemon_instance_id != before.daemon_instance_id
            && rejected != Some(&value.daemon_instance_id)
            && value.healthy(&before.identity, version).unwrap()
    }
}

#[tokio::test]
async fn activation_replaces_only_the_daemon_and_requires_new_healthy_authority() {
    use std::os::unix::fs::PermissionsExt;

    for (reject_target, reject_rollback) in [(false, false), (true, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("lanewayd-rs");
        let staged = dir.path().join("asset");
        let other = dir.path().join("node.toml");
        fs::write(&installed, V1).unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&staged, V2).unwrap();
        fs::write(&other, "operator-owned config").unwrap();
        let service = FixtureService {
            installed: installed.clone(),
            launches: 0.into(),
            reject_target,
            reject_rollback,
        };
        let prior = service.status().await.unwrap();
        let install = Install::new(&installed);
        let result = install.apply(&staged, &service, &prior, V2).await;
        assert_eq!(fs::read_to_string(other).unwrap(), "operator-owned config");
        if reject_target {
            assert_eq!(service.launches.get(), 2);
            assert_eq!(fs::read_to_string(&installed).unwrap(), V1);
            if reject_rollback {
                assert!(result.is_err());
                assert!(
                    install.ready().is_err(),
                    "unconfirmed restarts must retain recovery markers"
                );
            } else {
                assert_eq!(result.unwrap(), Activated::RolledBack);
                install.ready().unwrap();
            }
        } else {
            assert_eq!(service.launches.get(), 1);
            assert_eq!(fs::read_to_string(&installed).unwrap(), V2);
            assert_eq!(result.unwrap(), Activated::Healthy);
            install.ready().unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires the disposable systemd VM and an enrolled durable Rust node"]
async fn activation_on_live_systemd_node() -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let marker = fs::symlink_metadata("/run/.laneway-isolated-systemd-lab")?;
    ensure!(
        marker.is_file()
            && marker.uid() == 0
            && marker.mode() & 0o777 == 0o600
            && fs::read_to_string("/proc/1/comm")?.trim() == "systemd",
        "test requires the marked disposable systemd VM"
    );
    // SAFETY: reads process metadata without mutating state.
    ensure!(unsafe { libc::geteuid() } == 0, "test must run as root");
    let unit = clean_command("/usr/bin/systemctl")
        .args([
            "show",
            "--property=Description",
            "--value",
            "lanewayd-rs.service",
        ])
        .output()
        .await?;
    ensure!(
        unit.status.success()
            && std::str::from_utf8(&unit.stdout)?.trim()
                == "Laneway isolated updater activation fixture",
        "refusing to replace a non-fixture service"
    );

    let candidate = PathBuf::from(
        std::env::var_os("LANEWAY_LAB_NODE_CANDIDATE")
            .context("set LANEWAY_LAB_NODE_CANDIDATE to the new native node binary")?,
    );
    let socket = PathBuf::from(
        std::env::var_os("LANEWAY_LAB_NODE_SOCKET")
            .context("set LANEWAY_LAB_NODE_SOCKET to the fixture socket")?,
    );
    let runtime = SystemNode::new(&socket)?;
    let installed = Path::new(BINARY);
    let before = runtime.status().await?;
    let target = installed_version(&candidate).await?;
    assert_ne!(
        before.version()?,
        target,
        "exercise an actual version change"
    );
    let install = Install::new(installed);
    let old_inode = fs::metadata(installed)?.ino();
    assert_eq!(
        install
            .apply(&candidate, &runtime, &before, &target)
            .await?,
        Activated::Healthy
    );
    assert_ne!(old_inode, fs::metadata(installed)?.ino());
    let upgraded = runtime.status().await?;
    assert!(upgraded.healthy(&before.identity, &target)?);
    assert_ne!(before.daemon_instance_id, upgraded.daemon_instance_id);
    assert_eq!(
        before.controller.certificate_presented_serial,
        upgraded.controller.certificate_presented_serial
    );
    println!("systemd activated {target} and the same node regained its controller lease");

    // This executable launches and exits without publishing a health socket.
    // The worker must time out waiting for health, restore the same good inode,
    // restart it, and confirm its controller lease before removing recovery markers.
    let healthy_inode = fs::metadata(installed)?.ino();
    assert_eq!(
        install
            .apply(
                Path::new("/usr/bin/false"),
                &runtime,
                &upgraded,
                "v0.0.9102"
            )
            .await?,
        Activated::RolledBack
    );
    let restored = runtime.status().await?;
    assert_eq!(healthy_inode, fs::metadata(installed)?.ino());
    assert!(restored.healthy(&before.identity, &target)?);
    assert_ne!(upgraded.daemon_instance_id, restored.daemon_instance_id);
    assert_eq!(
        before.controller.certificate_presented_serial,
        restored.controller.certificate_presented_serial
    );
    install.ready()?;
    println!("systemd restored {target}, the same credential, and a fresh controller lease");
    Ok(())
}
