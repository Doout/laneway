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
    reject_ack: Cell<bool>,
    polls: Cell<usize>,
    acknowledgements: Cell<usize>,
}

impl Control for Upstream {
    async fn poll(&self, request: &Poll) -> Result<Option<Assignment>> {
        self.polls.set(self.polls.get() + 1);
        assert_eq!(request.current_version, V1);
        assert_eq!(request.runtime_node_id, id(2).to_string());
        if self.lose_claim {
            bail!("controller committed the claim but the connection was lost");
        }
        Ok(Some(Assignment {
            id: id(3).to_string(),
            version: V2.into(),
            component: Component::Node,
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
        claim(&first, &upstream, &original.identity, V1, Channel::Manual)
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
    let (assigned, version) = claim(&journal, &upstream, &before.identity, V1, Channel::Manual)
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
    for (reject_target, reject_rollback) in [(false, false), (true, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let installed = dir.path().join("lanewayd-rs");
        let staged = dir.path().join("asset");
        let other = dir.path().join("node.toml");
        fs::write(&installed, V1).unwrap();
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
