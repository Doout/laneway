use std::{
    future::{Future, pending},
    num::NonZeroU64,
    pin::Pin,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::Id;
use tokio::time::{Instant, sleep, sleep_until};
use tracing::warn;

use crate::{
    controller::{AuthorityRejected, Client, PollResult, Snapshot},
    tls::LocalCertificateHealth,
};

pub(crate) trait ConfigurationSource: Send + Sync {
    fn exit_generation(&self) -> Option<NonZeroU64> {
        None
    }

    fn poll<'a>(
        &'a self,
        known_epoch: u64,
    ) -> Pin<Box<dyn Future<Output = Result<PollResult>> + Send + 'a>>;

    fn reconnect_after_expiry(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

impl ConfigurationSource for Arc<Client> {
    fn exit_generation(&self) -> Option<NonZeroU64> {
        self.as_ref().exit_generation()
    }

    fn poll<'a>(
        &'a self,
        known_epoch: u64,
    ) -> Pin<Box<dyn Future<Output = Result<PollResult>> + Send + 'a>> {
        Box::pin(async move { self.as_ref().poll(known_epoch).await })
    }

    fn reconnect_after_expiry(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(self.as_ref().reconnect_quic())
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

    /// Normal snapshot expiry, not revocation. A runtime may retain only
    /// bounded, explicitly eligible drain authority instead of tearing down.
    fn expire<'a>(
        &'a self,
        _snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        self.fail_close()
    }

    fn renew<'a>(
        &'a self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

/// Monotonic controller state. The last expired snapshot is retained only so a
/// valid 304 can renew it; `active()` never returns expired authority.
pub(crate) struct Authority {
    state: RwLock<AuthorityState>,
}

#[derive(Default)]
struct AuthorityState {
    current: Option<Arc<Snapshot>>,
    retired: bool,
}

impl Authority {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(AuthorityState::default()),
        })
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.retained().map_or(0, |snapshot| snapshot.epoch)
    }

    pub(crate) fn retained(&self) -> Option<Arc<Snapshot>> {
        self.state.read().ok()?.current.clone()
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
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("controller authority lock poisoned"))?;
        ensure!(!state.retired, "controller authority is retired");
        if let Some(previous) = state.current.as_ref() {
            previous.validate_exit_successor(&next)?;
            ensure!(
                next.epoch > previous.epoch,
                "controller configuration epoch did not advance"
            );
        }
        state.current = Some(next);
        Ok(())
    }

    fn publish_renewal(&self, renewed: Arc<Snapshot>) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("controller authority lock poisoned"))?;
        ensure!(!state.retired, "controller authority is retired");
        let previous = state
            .current
            .as_ref()
            .context("controller renewed authority before initial snapshot")?;
        previous.validate_exit_successor(&renewed)?;
        ensure!(
            renewed.epoch == previous.epoch && renewed.valid_until >= previous.valid_until,
            "controller lease renewal did not preserve epoch and a monotonic deadline"
        );
        state.current = Some(renewed);
        Ok(())
    }

    fn retire(&self) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("controller authority lock poisoned"))?;
        state.retired = true;
        state.current = None;
        Ok(())
    }
}

/// Polls the controller while independently enforcing the last lease
/// deadline. Startup cannot return until a complete snapshot has been applied.
pub(crate) struct Runner<S, A> {
    client: S,
    authority: Arc<Authority>,
    applier: Arc<A>,
    network: Id,
    node: Id,
    local_certificate: LocalCertificateHealth,
    poll_interval: Duration,
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
        })
    }

    pub(crate) async fn run(&self) -> Result<()> {
        let initial = self
            .authority
            .active()
            .context("controller runner was not initialized")?;
        ensure!(
            initial.exit_generation() == self.client.exit_generation(),
            "controller runner lease generation differs from the initial snapshot"
        );
        drop(initial);
        let mut delay = self.poll_interval;
        let mut failed_closed = false;
        loop {
            let retained = self
                .authority
                .retained()
                .context("controller authority disappeared")?;
            let terminal = retained.exit_terminal_at();
            if terminal.is_some() && !failed_closed {
                // Poll early enough even when the controller clamps validity
                // to the nearest revocation or route-expiry deadline.
                delay = delay.min((until(retained.valid_until) / 2).max(Duration::from_millis(50)));
            }
            let result = tokio::select! {
                biased;
                _ = wait_deadline(terminal) => {
                    self.retire_exit().await.context("fail close terminal ephemeral Exit")?;
                    bail!("ephemeral Exit lease is terminal");
                }
                _ = wait_deadline((!failed_closed).then_some(retained.valid_until)) => {
                    self.applier.expire(Arc::clone(&retained)).await.context("expire controller authority")?;
                    if terminal.is_some() && retained.wireguard_drain_eligible() {
                        self.client.reconnect_after_expiry().await;
                    }
                    failed_closed = true;
                    delay = Duration::from_millis(250).min(self.poll_interval);
                    warn!(epoch = retained.epoch, "controller node authority expired");
                    continue;
                }
                result = async {
                    sleep(delay).await;
                    let result = self.client.poll(retained.epoch).await?;
                    self.prepare_poll(result).await
                } => result,
            };
            let prepared = match result {
                Ok(prepared) => prepared,
                Err(error) => {
                    if terminal.is_some() && error.is::<AuthorityRejected>() {
                        self.retire_exit()
                            .await
                            .context("fail close rejected ephemeral Exit")?;
                        return Err(error);
                    }
                    warn!(%error, "controller node snapshot poll failed");
                    delay = self.poll_interval;
                    continue;
                }
            };
            if terminal.is_some() && prepared.local_certificate_revoked() {
                self.retire_exit()
                    .await
                    .context("fail close revoked ephemeral Exit certificate")?;
                bail!("ephemeral Exit certificate is revoked");
            }
            match self.apply_poll(prepared, failed_closed).await {
                Ok(now_active) => failed_closed = !now_active,
                Err(error) => warn!(%error, "controller node snapshot apply failed"),
            }
            delay = self.poll_interval;
        }
    }

    async fn retire_exit(&self) -> Result<()> {
        let retire = self.authority.retire();
        // Cut the dataplane even if marking the local lease retired fails.
        self.applier.fail_close().await?;
        retire
    }

    async fn prepare_poll(&self, result: PollResult) -> Result<PreparedPoll> {
        match result {
            PollResult::Modified(configuration) => {
                let snapshot = Snapshot::compile_for(
                    *configuration,
                    self.network,
                    self.node,
                    &self.local_certificate,
                    self.client.exit_generation(),
                )?;
                if let Some(previous) = self.authority.retained() {
                    previous.validate_exit_successor(&snapshot)?;
                    if snapshot.epoch == previous.epoch && previous.ephemeral_exit.is_some() {
                        return Ok(PreparedPoll::Renewed(Arc::new(
                            previous.renew_exit(snapshot)?,
                        )));
                    }
                }
                ensure!(
                    snapshot.epoch > self.authority.epoch(),
                    "controller configuration epoch did not advance"
                );
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
}

impl PreparedPoll {
    fn local_certificate_revoked(&self) -> bool {
        match self {
            Self::Modified(snapshot) | Self::Renewed(snapshot) => {
                snapshot.local_certificate_revoked
            }
        }
    }
}

async fn wait_deadline(unix_seconds: Option<u64>) {
    if let Some(unix_seconds) = unix_seconds {
        let remaining = until(unix_seconds).min(Duration::from_secs(31_536_000));
        sleep_until(Instant::now() + remaining).await;
    } else {
        pending().await
    }
}

fn until(unix_seconds: u64) -> Duration {
    Duration::from_secs(unix_seconds).saturating_sub(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default(),
    )
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
