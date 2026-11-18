//! Publish only bounded runtime health from a controller-managed node.
use crate::{
    config::Config, controller::Client, metrics::Metrics, state::State, tls::LocalCertificateHealth,
};
use anyhow::Result;
use arc_swap::ArcSwap;
use laneway_protocol::{
    Id,
    endpoint_status::{
        Carrier, Certificate, Configuration, MAX_CLEANUP_FAILURES, Platform, Report, Route,
        SelectedExit,
    },
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::Mutex,
    time::{Duration, MissedTickBehavior, interval},
};

pub(crate) struct Reporter {
    pub(crate) client: Arc<Client>,
    pub(crate) state: Arc<State>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) base: Arc<ArcSwap<Config>>,
    pub(crate) control_lock: Arc<Mutex<()>>,
    pub(crate) certificate: LocalCertificateHealth,
}

impl Reporter {
    pub(crate) async fn run(self) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut epoch = 0;
        loop {
            ticker.tick().await;
            let report = {
                let _guard = self.control_lock.lock().await;
                self.snapshot(&mut epoch)
            };
            if let Err(error) = self.client.report_status(&report).await {
                // A report is diagnostic. Failure does not change live traffic
                // authority or cause the node to restart.
                tracing::debug!(%error, "endpoint health report not delivered");
            }
        }
    }

    fn snapshot(&self, epoch: &mut u64) -> Report {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let authority = self.state.authority_snapshot();
        if let Some(snapshot) = &authority {
            *epoch = snapshot.epoch;
        }
        let live = authority.as_ref().filter(|snapshot| !snapshot.expired());
        let config = self.base.load();
        let metrics = self.metrics.snapshot();
        let selected = &config.forwarding.exit_client;
        let exit = if !selected.enabled {
            SelectedExit::NotSelected
        } else if live.is_some_and(|snapshot| {
            selected.authorized
                && selected
                    .selected_node
                    .as_deref()
                    .and_then(|id| id.parse::<Id>().ok())
                    .is_some_and(|id| {
                        snapshot.authorized_exits.contains(&id) && self.state.has_path(id)
                    })
        }) {
            SelectedExit::Ready
        } else {
            SelectedExit::Unavailable
        };
        Report {
            valid_for_seconds: 30,
            product_version: env!("CARGO_PKG_VERSION").to_owned(),
            platform: Platform::Linux,
            certificate_state: if authority
                .as_ref()
                .is_some_and(|s| s.local_certificate_revoked)
            {
                Certificate::Revoked
            } else if now >= self.certificate.not_after {
                Certificate::Expired
            } else if now >= self.certificate.renew_after
                || metrics.controller_certificate_renewal_needed != 0
            {
                Certificate::RenewalDue
            } else {
                Certificate::Healthy
            },
            configuration_state: if live.is_some() {
                Configuration::Current
            } else if *epoch != 0 {
                Configuration::Expired
            } else {
                Configuration::Unknown
            },
            carrier_state: if live.is_none() {
                Carrier::Disconnected
            } else if metrics.direct_active_paths != 0 {
                Carrier::Direct
            } else if metrics.quic_active != 0 {
                Carrier::RelayQuic
            } else if metrics.tcp_active != 0 {
                Carrier::RelayTcp
            } else {
                Carrier::Disconnected
            },
            route_state: if live.is_none() {
                Route::Unavailable
            } else if config.tun.configure {
                Route::Ready
            } else {
                Route::Unknown
            },
            selected_exit_state: exit,
            cleanup_failure_count: metrics
                .exit_namespace_cleanup_failures_total
                .min(u64::from(MAX_CLEANUP_FAILURES)) as u32,
            configuration_epoch: *epoch,
        }
    }
}
