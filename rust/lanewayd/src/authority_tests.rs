use super::*;
use crate::{
    config::TlsConfig,
    controller::{
        ClientOptions,
        tests::{EXIT_TEST_GENERATION, ephemeral_configuration, id, local_certificate},
    },
    tls::local_certificate_health,
};
use std::{
    env,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
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
    assert!(authority.active().is_none());
    assert!(authority.seed(initial).is_err());
    Ok(())
}

// Invoked by the disposable Go and Rust controller interoperability fixture.
// Only snapshots and auth are tested; this does not create a packet device.
#[tokio::test]
#[ignore = "requires local Go/Rust controller; run integration/rust-lab/exit-lease.sh"]
async fn live_ephemeral_exit_lease() -> Result<()> {
    let tls = TlsConfig {
        ca: env::var("LANEWAY_EXIT_LEASE_CA")?.into(),
        certificate: env::var("LANEWAY_EXIT_LEASE_CERT")?.into(),
        private_key: env::var("LANEWAY_EXIT_LEASE_KEY")?.into(),
    };
    let cert = local_certificate_health(&tls)?;
    let network = env::var("LANEWAY_EXIT_LEASE_NETWORK")?.parse()?;
    let node = env::var("LANEWAY_EXIT_LEASE_NODE")?.parse()?;
    let generation: NonZeroU64 = env::var("LANEWAY_EXIT_LEASE_GENERATION")?.parse()?;
    let client = Arc::new(
        Client::new(ClientOptions {
            endpoint: "https://127.0.0.1:1".to_owned(), // Control is QUIC-only.
            quic_endpoint: Some(env::var("LANEWAY_EXIT_LEASE_QUIC")?),
            server_name: "127.0.0.1".to_owned(),
            network,
            service: env::var("LANEWAY_EXIT_LEASE_SERVICE")?.parse()?,
            certificate: tls.certificate,
            private_key: tls.private_key,
            ca: tls.ca,
            timeout: Duration::from_secs(2),
            exit_generation: Some(generation),
        })
        .await?,
    );
    let PollResult::Modified(wire) = client.poll(0).await? else {
        bail!("controller did not send an initial full snapshot");
    };
    let initial = Arc::new(
        Snapshot::compile_for(*wire, network, node, &cert, Some(generation))?
            .resolve_relays()
            .await?,
    );
    let authority = Authority::new();
    authority.seed(Arc::clone(&initial))?;
    let observed = Arc::new(ObservedRuntime::default());
    let runner = Runner::new(
        client,
        Arc::clone(&authority),
        Arc::clone(&observed),
        network,
        node,
        cert,
        Duration::from_millis(150),
    )?;
    let running = tokio::spawn(async move { runner.run().await });
    timeout(Duration::from_secs(5), async {
        loop {
            if authority
                .active()
                .is_some_and(|current| current.valid_until > initial.valid_until)
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("controller did not extend the same-epoch lease")?;
    assert!(observed.renewed.load(Ordering::SeqCst) > 0);
    assert_eq!(observed.applied.load(Ordering::SeqCst), 0);
    println!("rust ephemeral exit heartbeat verified");

    // The fixture revokes the identity after reading the marker above.
    let error = timeout(Duration::from_secs(5), running)
        .await??
        .unwrap_err();
    assert!(error.is::<AuthorityRejected>(), "{error:#}");
    assert_eq!(observed.suspended.load(Ordering::SeqCst), 1);
    assert!(authority.active().is_none());
    assert!(authority.seed(initial).is_err());
    Ok(())
}
