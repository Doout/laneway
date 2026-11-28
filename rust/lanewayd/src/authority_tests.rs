use super::*;
use crate::controller::tests::{
    EXIT_TEST_GENERATION, ephemeral_configuration, id, local_certificate,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::time::timeout;

#[derive(Default)]
struct ObservedRuntime {
    applied: AtomicUsize,
    suspended: AtomicUsize,
    renewed: AtomicUsize,
}

impl SnapshotApplier for ObservedRuntime {
    fn apply<'a>(
        &'a self,
        _: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.applied.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn fail_close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async {
            self.suspended.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn renew<'a>(
        &'a self,
        _: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.renewed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

struct StalledPoll(Arc<AtomicBool>);

impl ConfigurationSource for StalledPoll {
    fn exit_generation(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(EXIT_TEST_GENERATION)
    }

    fn poll(&self, _: u64) -> Pin<Box<dyn Future<Output = Result<PollResult>> + Send + '_>> {
        Box::pin(async {
            self.0.store(true, Ordering::SeqCst);
            pending().await
        })
    }
}

#[tokio::test]
async fn terminal_exit_deadline_interrupts_poll_and_retires_the_snapshot() -> Result<()> {
    let mut wire = ephemeral_configuration();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    wire.valid_until_unix_seconds = now + 2;
    wire.identity_lease_expires_at_unix_seconds = now + 3;
    let cert = local_certificate();
    let initial = Arc::new(Snapshot::compile_for(
        wire,
        id(1),
        id(2),
        &cert,
        NonZeroU64::new(EXIT_TEST_GENERATION),
    )?);
    let authority = Authority::new();
    authority.seed(Arc::clone(&initial))?;
    let observed = Arc::new(ObservedRuntime::default());
    let request_started = Arc::new(AtomicBool::new(false));
    let runner = Runner::new(
        StalledPoll(Arc::clone(&request_started)),
        Arc::clone(&authority),
        Arc::clone(&observed),
        id(1),
        id(2),
        cert,
        Duration::from_millis(20),
    )?;
    let error = timeout(Duration::from_secs(5), runner.run())
        .await?
        .unwrap_err();
    assert!(error.to_string().contains("terminal"));
    assert!(request_started.load(Ordering::SeqCst));
    assert_eq!(observed.suspended.load(Ordering::SeqCst), 2);
    assert_eq!(observed.applied.load(Ordering::SeqCst), 0);
    assert_eq!(observed.renewed.load(Ordering::SeqCst), 0);
    assert!(authority.active().is_none());
    assert!(authority.seed(initial).is_err());
    Ok(())
}

#[tokio::test]
async fn same_epoch_exit_heartbeat_extends_authority_without_reapplying_policy() -> Result<()> {
    let mut heartbeat = ephemeral_configuration();
    let cert = local_certificate();
    let initial = Arc::new(Snapshot::compile_for(
        heartbeat.clone(),
        id(1),
        id(2),
        &cert,
        NonZeroU64::new(EXIT_TEST_GENERATION),
    )?);
    let authority = Authority::new();
    authority.seed(Arc::clone(&initial))?;
    let observed = Arc::new(ObservedRuntime::default());
    let runner = Runner::new(
        StalledPoll(Arc::new(AtomicBool::new(false))),
        Arc::clone(&authority),
        Arc::clone(&observed),
        id(1),
        id(2),
        cert,
        Duration::from_millis(20),
    )?;

    heartbeat.valid_until_unix_seconds += 5;
    heartbeat.ephemeral_exit_suspect_at_unix_seconds += 5;
    heartbeat.ephemeral_exit_revoke_at_unix_seconds += 5;
    let prepared = runner
        .prepare_poll(PollResult::Modified(Box::new(heartbeat)))
        .await?;
    assert!(runner.apply_poll(prepared, false).await?);
    let renewed = authority.active().context("heartbeat retired authority")?;
    assert_eq!(renewed.epoch, initial.epoch);
    assert_eq!(renewed.valid_until, initial.valid_until + 5);
    assert_eq!(observed.renewed.load(Ordering::SeqCst), 1);
    assert_eq!(observed.applied.load(Ordering::SeqCst), 0);
    assert_eq!(observed.suspended.load(Ordering::SeqCst), 0);
    Ok(())
}
