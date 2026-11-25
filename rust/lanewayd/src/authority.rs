use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use laneway_protocol::Id;
use tokio::time::{Instant, sleep, sleep_until};
use tracing::warn;

use crate::{
    controller::{PollResult, QuicControl, Snapshot},
    tls::LocalCertificateHealth,
};

pub(crate) trait ConfigurationSource: Send + Sync {
    fn poll<'a>(
        &'a self,
        known_epoch: u64,
    ) -> Pin<Box<dyn Future<Output = Result<PollResult>> + Send + 'a>>;
}

#[cfg(feature = "native")]
impl ConfigurationSource for crate::controller::Client {
    fn poll<'a>(
        &'a self,
        known_epoch: u64,
    ) -> Pin<Box<dyn Future<Output = Result<PollResult>> + Send + 'a>> {
        Box::pin(async move { self.poll(known_epoch).await })
    }
}

impl ConfigurationSource for QuicControl {
    fn poll<'a>(
        &'a self,
        known_epoch: u64,
    ) -> Pin<Box<dyn Future<Output = Result<PollResult>> + Send + 'a>> {
        Box::pin(async move { self.poll(known_epoch).await })
    }
}

/// Runtime transaction boundary for controller authority. Implementations must
/// finish or roll back every native mutation before returning an error.
pub(crate) trait SnapshotApplier: Send + Sync {
    fn apply<'a>(
        &'a self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    fn fail_close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

    fn renew<'a>(
        &'a self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

/// Monotonic controller state. The last expired snapshot is retained only so a
/// valid 304 can renew it; `active()` never returns expired authority.
pub(crate) struct Authority {
    current: RwLock<Option<Arc<Snapshot>>>,
}

impl Authority {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(None),
        })
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.current
            .read()
            .ok()
            .and_then(|value| value.as_ref().map(|snapshot| snapshot.epoch))
            .unwrap_or(0)
    }

    pub(crate) fn retained(&self) -> Option<Arc<Snapshot>> {
        self.current.read().ok()?.clone()
    }

    pub(crate) fn active(&self) -> Option<Arc<Snapshot>> {
        self.retained().filter(|snapshot| !snapshot.expired())
    }

    pub(crate) fn seed(&self, snapshot: Arc<Snapshot>) -> Result<()> {
        ensure!(
            self.retained().is_none(),
            "controller authority already seeded"
        );
        self.publish_modified(snapshot)
    }

    fn publish_modified(&self, next: Arc<Snapshot>) -> Result<()> {
        let mut current = self
            .current
            .write()
            .map_err(|_| anyhow::anyhow!("controller authority lock poisoned"))?;
        if let Some(previous) = current.as_ref() {
            ensure!(
                next.epoch > previous.epoch,
                "controller configuration epoch did not advance"
            );
        }
        *current = Some(next);
        Ok(())
    }

    fn publish_renewal(&self, renewed: Arc<Snapshot>) -> Result<()> {
        let mut current = self
            .current
            .write()
            .map_err(|_| anyhow::anyhow!("controller authority lock poisoned"))?;
        let previous = current
            .as_ref()
            .context("controller renewed authority before initial snapshot")?;
        ensure!(
            renewed.epoch == previous.epoch && renewed.valid_until >= previous.valid_until,
            "controller lease renewal did not preserve epoch and a monotonic deadline"
        );
        *current = Some(renewed);
        Ok(())
    }
}

/// Polls the Go controller while independently enforcing the last lease
/// deadline. Startup cannot return until a complete snapshot has been applied.
pub(crate) struct Runner<S, A> {
    client: S,
    authority: Arc<Authority>,
    applier: Arc<A>,
    network: Id,
    node: Id,
    local_certificate: LocalCertificateHealth,
    poll_interval: Duration,
    #[cfg(feature = "native")]
    filter: Option<crate::ConfigurationFilter>,
}

impl<S: ConfigurationSource + 'static, A: SnapshotApplier + 'static> Runner<S, A> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        client: S,
        authority: Arc<Authority>,
        applier: Arc<A>,
        network: Id,
        node: Id,
        local_certificate: LocalCertificateHealth,
        poll_interval: Duration,
    ) -> Result<Self> {
        ensure!(
            !poll_interval.is_zero() && poll_interval <= Duration::from_secs(300),
            "controller poll interval must be in (0,5m]"
        );
        Ok(Self {
            client,
            authority,
            applier,
            network,
            node,
            local_certificate,
            poll_interval,
            #[cfg(feature = "native")]
            filter: None,
        })
    }

    #[cfg(feature = "native")]
    pub(crate) fn with_filter(mut self, filter: Option<crate::ConfigurationFilter>) -> Self {
        self.filter = filter;
        self
    }

    pub(crate) async fn run(&self) -> Result<()> {
        ensure!(
            self.authority.active().is_some(),
            "controller runner was not initialized"
        );
        let mut delay = self.poll_interval;
        let mut failed_closed = false;
        loop {
            let retained = self
                .authority
                .retained()
                .context("controller authority disappeared")?;
            let lease = deadline(retained.effective_deadline());
            tokio::select! {
                _ = sleep(delay) => {
                    let poll = async {
                        let result = self.client.poll(self.authority.epoch()).await?;
                        self.prepare_poll(result).await
                    };
                    let prepared = if failed_closed {
                        poll.await
                    } else {
                        tokio::select! {
                            result = poll => result,
                            _ = sleep_until(lease) => {
                                self.applier.fail_close().await.context("fail close expired controller authority")?;
                                failed_closed = true;
                                delay = Duration::from_millis(250).min(self.poll_interval);
                                warn!(epoch = retained.epoch, "controller node authority expired during poll; dataplane failed closed");
                                continue;
                            }
                        }
                    };
                    match prepared {
                        #[cfg(feature = "native")]
                        Ok(PreparedPoll::SessionRejected(error)) => {
                            self.applier.fail_close().await.context("fail close session route selection")?;
                            return Err(error.context("controller withdrew session route selection"));
                        }
                        Ok(prepared) => match self.apply_poll(prepared, failed_closed).await {
                            Ok(now_active) => {
                                failed_closed = !now_active;
                                delay = self.poll_interval;
                            }
                            Err(error) => {
                                warn!(%error, "controller node snapshot poll failed");
                                delay = self.poll_interval;
                            }
                        },
                        Err(error) => {
                            warn!(%error, "controller node snapshot poll failed");
                            delay = self.poll_interval;
                        }
                    }
                }
                _ = sleep_until(lease), if !failed_closed => {
                    self.applier.fail_close().await.context("fail close expired controller authority")?;
                    failed_closed = true;
                    delay = Duration::from_millis(250).min(self.poll_interval);
                    warn!(epoch = retained.epoch, "controller node authority expired; dataplane failed closed");
                }
            }
        }
    }

    async fn prepare_poll(&self, result: PollResult) -> Result<PreparedPoll> {
        match result {
            PollResult::Modified(configuration) => {
                #[cfg(feature = "native")]
                let original = self.filter.as_ref().map(|_| (*configuration).clone());
                let snapshot = Snapshot::compile(
                    *configuration,
                    self.network,
                    self.node,
                    &self.local_certificate,
                )?;
                ensure!(
                    snapshot.epoch > self.authority.epoch(),
                    "controller configuration epoch did not advance"
                );
                #[cfg(feature = "native")]
                let snapshot = if !snapshot.local_certificate_revoked
                    && let (Some(filter), Some(original)) = (&self.filter, original)
                {
                    let mut snapshot = snapshot;
                    if let Err(error) = filter(&original)
                        .and_then(|routes| snapshot.filter_session(routes, self.node))
                    {
                        return Ok(PreparedPoll::SessionRejected(error));
                    }
                    snapshot
                } else {
                    snapshot
                };
                Ok(PreparedPoll::Modified(Arc::new(
                    snapshot.resolve_relays().await?,
                )))
            }
            PollResult::NotModified { valid_until } => {
                let retained = self
                    .authority
                    .retained()
                    .context("controller returned 304 before initial snapshot")?;
                Ok(PreparedPoll::Renewed(Arc::new(
                    retained.renew(valid_until)?,
                )))
            }
        }
    }

    async fn apply_poll(&self, prepared: PreparedPoll, failed_closed: bool) -> Result<bool> {
        match prepared {
            #[cfg(feature = "native")]
            PreparedPoll::SessionRejected(error) => Err(error),
            PreparedPoll::Modified(snapshot) => {
                if snapshot.local_certificate_revoked {
                    self.applier
                        .fail_close()
                        .await
                        .context("fail close revoked local certificate")?;
                    warn!("local node certificate is revoked; dataplane failed closed");
                    return Ok(false);
                }
                self.applier.apply(Arc::clone(&snapshot)).await?;
                if let Err(error) = self.authority.publish_modified(snapshot) {
                    let _ = self.applier.fail_close().await;
                    return Err(error);
                }
                Ok(true)
            }
            PreparedPoll::Renewed(renewed) => {
                if failed_closed {
                    ensure!(
                        !renewed.local_certificate_revoked,
                        "local node certificate is revoked"
                    );
                    self.applier.apply(Arc::clone(&renewed)).await?;
                } else {
                    self.applier.renew(Arc::clone(&renewed)).await?;
                }
                if let Err(error) = self.authority.publish_renewal(renewed) {
                    let _ = self.applier.fail_close().await;
                    return Err(error);
                }
                Ok(true)
            }
        }
    }
}

enum PreparedPoll {
    Modified(Arc<Snapshot>),
    Renewed(Arc<Snapshot>),
    #[cfg(feature = "native")]
    SessionRejected(anyhow::Error),
}

fn deadline(unix_seconds: u64) -> Instant {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Instant::now() + Duration::from_secs(unix_seconds).saturating_sub(now_unix)
}
