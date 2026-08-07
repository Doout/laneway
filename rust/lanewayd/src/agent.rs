use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use laneway_protocol::{Id, v1};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::{Duration, MissedTickBehavior, interval},
};
use tracing::info;

use crate::{
    authority::{Authority, Runner, SnapshotApplier},
    config::Config,
    controller::{Client as ControllerClient, ClientOptions, PollResult, Snapshot},
    diagnostics::DiagnosticsServer,
    direct::{DirectManager, try_send_direct},
    exit_intent::Store as ExitIntentStore,
    kernel::KernelManager,
    local_api,
    metrics::Metrics,
    packet_pool::PacketPool,
    probe::ProbeSocket,
    relay::{OutboundPacket, RelayClient},
    routing::{RoutingTable, packet_meta},
    state::State,
    tls,
    tun::TunDevice,
};

/// Native Linux node agent owning TUN, routing, and all packet carriers.
pub struct Agent {
    config: Arc<Config>,
    network: Id,
    node: Id,
    boot: Id,
    state: Arc<State>,
    metrics: Arc<Metrics>,
}

impl Agent {
    /// Validates immutable state and local certificate identity without opening
    /// a network device or socket.
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let (network, node) = config.ids()?;
        tls::validate_local(&config.tls, network, node)?;
        let routes = RoutingTable::compile(&config.routes)?;
        let boot = random_id()?;
        let controller_managed = config.controller.is_some();
        Ok(Self {
            config: Arc::new(config),
            network,
            node,
            boot,
            state: Arc::new(if controller_managed {
                State::controller(routes, node)
            } else {
                State::new(routes)
            }),
            metrics: Arc::new(Metrics::default()),
        })
    }

    /// Returns the lock-free metric registry.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Runs until the supplied shutdown future resolves, then restores routes
    /// installed by this process and closes all QUIC paths.
    pub async fn run_until<F>(mut self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()>,
    {
        let mut authority_base = (*self.config).clone();
        let certificate_presented_serial =
            hex::encode(tls::local_certificate_health(&authority_base.tls)?.serial);
        let exit_intent = Arc::new(ExitIntentStore::new(
            authority_base.exit_intent_path.clone(),
        ));
        let intent_persisted = if authority_base.controller.is_some() {
            let loaded = exit_intent
                .load(&mut authority_base)
                .context("load explicit exit selection")?;
            authority_base
                .validate()
                .context("validate persisted exit selection")?;
            loaded
        } else {
            false
        };
        let bootstrap = self.controller_bootstrap().await?;
        if let Some((client, snapshot, _, _)) = &bootstrap {
            authority_base
                .forwarding
                .exit_client
                .controller_bypass
                .extend(client.resolved_ips());
            authority_base
                .forwarding
                .exit_client
                .controller_bypass
                .sort_unstable();
            authority_base
                .forwarding
                .exit_client
                .controller_bypass
                .dedup();
            let effective = controller_effective_config(&authority_base, snapshot, self.node);
            self.config = Arc::new(effective);
        }
        let mut owned = self.config.tun.addresses.clone();
        owned.extend(self.config.forwarding.owned_prefixes.iter().copied());
        let owned = Arc::new(owned);
        let server = tls::direct_server_config(&self.config.tls, &self.config.relay)?;
        let (endpoint, probe) = ProbeSocket::bind(self.config.direct.listen, server)
            .context("bind shared direct/relay UDP endpoint")?;
        let direct_address = endpoint.local_addr()?;
        let diagnostics = if let Some(address) = self.config.diagnostics.listen {
            let server = DiagnosticsServer::bind(address, Arc::clone(&self.metrics)).await?;
            info!(address = %server.local_addr()?, "Rust node diagnostics listening");
            Some(server)
        } else {
            None
        };
        let (relay_tx, relay_rx) = mpsc::channel(self.config.relay.queue_depth);
        let (inject_tx, mut inject_rx) = mpsc::channel(self.config.relay.queue_depth);
        let (candidate_tx, candidate_rx) = mpsc::channel(32);
        let packet_pool = PacketPool::prewarmed(
            self.config.relay.queue_depth,
            usize::from(self.config.tun.mtu) + 5,
        );
        let kernel = Arc::new(StdMutex::new(None));
        let dynamic_bypasses = Arc::new(StdMutex::new(BTreeMap::new()));
        let relay_client = RelayClient::new(
            endpoint.clone(),
            Arc::clone(&self.config),
            Arc::clone(&self.state),
            Arc::clone(&self.metrics),
            self.network,
            self.node,
            self.boot,
            Arc::clone(&owned),
            inject_tx.clone(),
            candidate_tx,
        );
        let direct_manager = DirectManager::new(
            endpoint.clone(),
            Arc::clone(&self.config),
            Arc::clone(&self.state),
            Arc::clone(&self.metrics),
            self.network,
            self.node,
            Arc::clone(&owned),
            inject_tx,
            candidate_rx,
            probe,
            Arc::clone(&kernel),
            Arc::clone(&dynamic_bypasses),
        )?;
        let tun = TunDevice::open(&self.config.tun, &self.config.routes).await?;
        let tun = Arc::new(Mutex::new(tun));
        let needs_kernel = self.config.forwarding.subnet_router
            || self.config.forwarding.exit_gateway
            || self.config.forwarding.exit_client.enabled;
        let initial_kernel = if needs_kernel {
            match KernelManager::apply(Arc::clone(&self.config)) {
                Ok(kernel) => Some(kernel),
                Err(error) => {
                    let tun_restore = tun.lock().await.restore().await;
                    return aggregate_results([
                        ("install owned Linux forwarding state", Err(error)),
                        ("restore TUN after kernel activation failure", tun_restore),
                    ]);
                }
            }
        } else {
            None
        };
        match kernel.lock() {
            Ok(mut slot) => *slot = initial_kernel,
            Err(poisoned) => {
                let kernel_restore = {
                    let mut slot = poisoned.into_inner();
                    *slot = initial_kernel;
                    slot.as_mut().map_or(Ok(()), KernelManager::restore)
                };
                let tun_restore = tun.lock().await.restore().await;
                return aggregate_results([
                    (
                        "publish initial kernel manager",
                        Err(anyhow::anyhow!("kernel manager lock poisoned")),
                    ),
                    (
                        "restore kernel after kernel publication failure",
                        kernel_restore,
                    ),
                    ("restore TUN after kernel publication failure", tun_restore),
                ]);
            }
        }
        let runtime_base = Arc::new(ArcSwap::from_pointee(authority_base.clone()));
        let control_lock = Arc::new(Mutex::new(()));
        let intent_persisted = Arc::new(StdMutex::new(intent_persisted));
        let device = tun.lock().await.device();
        let mut tasks = JoinSet::new();

        if let Some((client, snapshot, authority, local_certificate)) = bootstrap {
            let applier = Arc::new(RuntimeApplier {
                state: Arc::clone(&self.state),
                metrics: Arc::clone(&self.metrics),
                tun: Arc::clone(&tun),
                configure_tun: self.config.tun.configure,
                node: self.node,
                base_config: Arc::clone(&runtime_base),
                kernel: Arc::clone(&kernel),
                dynamic_bypasses: Arc::clone(&dynamic_bypasses),
                control_lock: Arc::clone(&control_lock),
            });
            if let Err(error) = applier.apply(Arc::clone(&snapshot)).await {
                let kernel_restore = restore_kernel(&kernel);
                let tun_restore = tun.lock().await.restore().await;
                return aggregate_results([
                    ("apply initial controller snapshot", Err(error)),
                    (
                        "restore kernel after controller apply failure",
                        kernel_restore,
                    ),
                    ("restore TUN after controller apply failure", tun_restore),
                ]);
            }
            if let Err(error) = authority.seed(snapshot) {
                let fail_close = applier.fail_close().await;
                let kernel_restore = restore_kernel(&kernel);
                let tun_restore = tun.lock().await.restore().await;
                return aggregate_results([
                    ("publish initial controller authority", Err(error)),
                    (
                        "fail close after controller publication failure",
                        fail_close,
                    ),
                    (
                        "restore kernel after controller publication failure",
                        kernel_restore,
                    ),
                    (
                        "restore TUN after controller publication failure",
                        tun_restore,
                    ),
                ]);
            }
            let Some(settings) = self.config.controller.as_ref() else {
                let kernel_restore = restore_kernel(&kernel);
                let tun_restore = tun.lock().await.restore().await;
                return aggregate_results([
                    (
                        "build controller runner",
                        Err(anyhow::anyhow!("controller settings disappeared")),
                    ),
                    (
                        "restore kernel after controller runner failure",
                        kernel_restore,
                    ),
                    ("restore TUN after controller runner failure", tun_restore),
                ]);
            };
            let runner = match Runner::new(
                client,
                authority,
                applier,
                self.network,
                self.node,
                local_certificate,
                settings.poll_interval,
            ) {
                Ok(runner) => runner,
                Err(error) => {
                    let kernel_restore = restore_kernel(&kernel);
                    let tun_restore = tun.lock().await.restore().await;
                    return aggregate_results([
                        ("build controller runner", Err(error)),
                        (
                            "restore kernel after controller runner failure",
                            kernel_restore,
                        ),
                        ("restore TUN after controller runner failure", tun_restore),
                    ]);
                }
            };
            tasks.spawn(async move { runner.run().await });
        }

        let local_control = Arc::new(RuntimeControl {
            state: Arc::clone(&self.state),
            metrics: Arc::clone(&self.metrics),
            tun: Arc::clone(&tun),
            configure_tun: self.config.tun.configure,
            network: self.network,
            node: self.node,
            base_config: Arc::clone(&runtime_base),
            kernel: Arc::clone(&kernel),
            dynamic_bypasses: Arc::clone(&dynamic_bypasses),
            control_lock: Arc::clone(&control_lock),
            exit_intent,
            intent_persisted,
            certificate_presented_serial,
        });
        let snapshot_control = Arc::clone(&local_control);
        let exit_control = Arc::clone(&local_control);
        let api = local_api::Server::new(
            self.config.socket_path.clone(),
            Arc::new(move || snapshot_control.snapshot()),
            self.config.controller.as_ref().map(|_| {
                Arc::new(move |selection| {
                    let control = Arc::clone(&exit_control);
                    Box::pin(async move { control.set_exit(selection).await })
                        as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                }) as Arc<_>
            }),
        );
        tasks.spawn(async move { api.run().await });

        if let Some(diagnostics) = diagnostics {
            tasks.spawn(async move { diagnostics.run().await });
        }

        info!(
            node = %self.node,
            network = %self.network,
            tun = %self.config.tun.name,
            direct = %direct_address,
            "native Rust Laneway agent started"
        );

        {
            tasks.spawn(async move { relay_client.run(relay_rx).await });
        }
        {
            tasks.spawn(async move { direct_manager.run().await });
        }
        {
            let device = Arc::clone(&device);
            let state = Arc::clone(&self.state);
            let metrics = Arc::clone(&self.metrics);
            let owned = Arc::clone(&owned);
            let mtu = usize::from(self.config.tun.mtu);
            let exit_gateway = self.config.forwarding.exit_gateway;
            let local_node = self.node;
            let packet_pool = packet_pool.clone();
            tasks.spawn(async move {
                let mut buffer = vec![0_u8; mtu];
                loop {
                    let size = device.recv(&mut buffer).await.context("read TUN packet")?;
                    let packet = &buffer[..size];
                    let Ok(meta) = packet_meta(packet) else {
                        Metrics::increment(&metrics.invalid_drops);
                        Metrics::increment(&metrics.malformed_drops);
                        continue;
                    };
                    if !state.owns(&owned, meta.source) && !exit_gateway {
                        Metrics::increment(&metrics.invalid_drops);
                        Metrics::increment(&metrics.auth_drops);
                        continue;
                    }
                    let routes = state.routes.load();
                    let Some(route) = routes.lookup(meta.destination) else {
                        Metrics::increment(&metrics.no_path_drops);
                        continue;
                    };
                    let peer = route.via;
                    Metrics::increment(&metrics.tun_packets);
                    Metrics::increment(&metrics.packets_sent_total);
                    Metrics::add(&metrics.bytes_sent_total, packet.len());
                    if try_send_direct(&state, &metrics, local_node, peer, packet, &packet_pool) {
                        continue;
                    }
                    let (outbound, pool_miss) = OutboundPacket::pooled(peer, packet, &packet_pool);
                    if pool_miss {
                        Metrics::increment(&metrics.packet_pool_misses);
                    }
                    let sent = relay_tx.try_send(outbound);
                    let depth = relay_tx.max_capacity().saturating_sub(relay_tx.capacity());
                    metrics.set_outbound_queue_depth(depth);
                    if sent.is_err() {
                        Metrics::increment(&metrics.queue_drops);
                    }
                }
                #[allow(unreachable_code)]
                Result::<()>::Ok(())
            });
        }
        {
            let state = Arc::clone(&self.state);
            let kernel = Arc::clone(&kernel);
            let metrics = Arc::clone(&self.metrics);
            tasks.spawn(async move { monitor_selected_exit(state, kernel, metrics).await });
        }
        {
            let device = Arc::clone(&device);
            let metrics = Arc::clone(&self.metrics);
            tasks.spawn(async move {
                while let Some(packet) = inject_rx.recv().await {
                    metrics.set_inject_queue_depth(
                        inject_rx
                            .max_capacity()
                            .saturating_sub(inject_rx.capacity()),
                    );
                    device
                        .send_all(&packet)
                        .await
                        .context("inject TUN packet")?;
                    Metrics::increment(&metrics.injected_packets);
                    Metrics::increment(&metrics.packets_received_total);
                    Metrics::add(&metrics.bytes_received_total, packet.len());
                }
                anyhow::bail!("TUN injection queue closed")
            });
        }

        tokio::pin!(shutdown);
        let run_result = tokio::select! {
            _ = &mut shutdown => Ok(()),
            completed = tasks.join_next() => match completed {
                Some(Ok(result)) => result,
                Some(Err(error)) => Err(error.into()),
                None => anyhow::bail!("all agent tasks stopped"),
            },
        };
        endpoint.close(0_u32.into(), b"shutdown");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let kernel_restore = restore_kernel(&kernel);
        let tun_restore = tun.lock().await.restore().await;
        info!(metrics = ?self.metrics.snapshot(), "native Rust Laneway agent stopped");
        aggregate_results([
            ("node runtime", run_result),
            ("restore kernel during shutdown", kernel_restore),
            ("restore TUN during shutdown", tun_restore),
        ])
    }

    async fn controller_bootstrap(
        &self,
    ) -> Result<
        Option<(
            ControllerClient,
            Arc<Snapshot>,
            Arc<Authority>,
            tls::LocalCertificateHealth,
        )>,
    > {
        let Some(settings) = &self.config.controller else {
            return Ok(None);
        };
        let local_certificate = tls::local_certificate_health(&self.config.tls)?;
        let client = ControllerClient::new(ClientOptions {
            endpoint: settings.endpoint.clone(),
            quic_endpoint: settings.quic_endpoint.clone(),
            server_name: settings.server_name.clone(),
            network: self.network,
            service: settings.service_id.parse()?,
            certificate: self.config.tls.certificate.clone(),
            private_key: self.config.tls.private_key.clone(),
            ca: self.config.tls.ca.clone(),
            timeout: settings.timeout,
        })
        .await?;
        let PollResult::Modified(configuration) = client.poll(0).await? else {
            anyhow::bail!("controller returned 304 before initial node snapshot");
        };
        let snapshot = Arc::new(
            Snapshot::compile(*configuration, self.network, self.node, &local_certificate)?
                .resolve_relays()
                .await?,
        );
        ensure!(
            !snapshot.local_certificate_revoked,
            "local node certificate is revoked"
        );
        validate_controller_relay(&self.config, &snapshot)?;
        Ok(Some((
            client,
            snapshot,
            Authority::new(),
            local_certificate,
        )))
    }
}

async fn monitor_selected_exit(
    state: Arc<State>,
    kernel: Arc<StdMutex<Option<KernelManager>>>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let mut ticker = interval(Duration::from_millis(250));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut hysteresis = PathHysteresis::default();
    loop {
        ticker.tick().await;
        let selected = kernel
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel manager lock poisoned"))?
            .as_ref()
            .and_then(KernelManager::selected_exit_node);
        let Some(selected) = selected else {
            Metrics::set(&metrics.exit_path_available, false);
            hysteresis = PathHysteresis::default();
            continue;
        };
        let healthy = state.has_path(selected);
        Metrics::set(&metrics.exit_path_available, healthy);
        let Some(desired) = hysteresis.observe(healthy) else {
            continue;
        };
        let result = kernel
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel manager lock poisoned"))?
            .as_mut()
            .map_or(Ok(()), |manager| manager.set_exit_path_available(desired));
        match result {
            Ok(()) => {
                hysteresis.commit(desired);
                info!(%selected, available = desired, "selected exit path state changed");
            }
            Err(error) => {
                tracing::warn!(%error, %selected, available = desired, "apply selected exit failure mode")
            }
        }
    }
}

struct PathHysteresis {
    up: u8,
    down: u8,
    published: bool,
}

impl Default for PathHysteresis {
    fn default() -> Self {
        Self {
            up: 0,
            down: 0,
            published: true,
        }
    }
}

impl PathHysteresis {
    const DOWN_THRESHOLD: u8 = 4;
    const UP_THRESHOLD: u8 = 2;

    fn observe(&mut self, healthy: bool) -> Option<bool> {
        if healthy {
            self.up = self.up.saturating_add(1);
            self.down = 0;
            (self.up >= Self::UP_THRESHOLD && !self.published).then_some(true)
        } else {
            self.down = self.down.saturating_add(1);
            self.up = 0;
            (self.down >= Self::DOWN_THRESHOLD && self.published).then_some(false)
        }
    }

    fn commit(&mut self, available: bool) {
        self.published = available;
        self.up = 0;
        self.down = 0;
    }
}

struct RuntimeControl {
    state: Arc<State>,
    metrics: Arc<Metrics>,
    tun: Arc<Mutex<TunDevice>>,
    configure_tun: bool,
    network: Id,
    node: Id,
    base_config: Arc<ArcSwap<Config>>,
    kernel: Arc<StdMutex<Option<KernelManager>>>,
    dynamic_bypasses: Arc<StdMutex<BTreeMap<std::net::IpAddr, usize>>>,
    control_lock: Arc<Mutex<()>>,
    exit_intent: Arc<ExitIntentStore>,
    intent_persisted: Arc<StdMutex<bool>>,
    certificate_presented_serial: String,
}

impl RuntimeControl {
    fn snapshot(&self) -> local_api::Snapshot {
        let base = self.base_config.load_full();
        let authority = self.state.authority_snapshot();
        let effective = authority
            .as_ref()
            .map(|snapshot| controller_effective_config(&base, snapshot, self.node))
            .unwrap_or_else(|| {
                if base.controller.is_some() {
                    controller_disabled_config(&base)
                } else {
                    (*base).clone()
                }
            });
        let values = self.metrics.snapshot();
        let selected_path = if values.direct_active_paths != 0 {
            "direct"
        } else if values.quic_active != 0 {
            "relay-quic"
        } else if values.tcp_active != 0 {
            "tcp-fallback"
        } else {
            "disconnected"
        };
        let authorized_exit = base.forwarding.exit_client.authorized
            && if base.controller.is_some() {
                authority.as_ref().is_some_and(|snapshot| {
                    !snapshot.expired()
                        && snapshot
                            .authorized_exits
                            .iter()
                            .any(|node| *node != self.node)
                })
            } else {
                true
            };
        let local_name = authority
            .as_ref()
            .and_then(|snapshot| snapshot.peers.get(&self.node))
            .map_or_else(String::new, |peer| peer.name.clone());
        let selected_node_id = effective
            .forwarding
            .exit_client
            .selected_node
            .clone()
            .unwrap_or_default();
        let status = local_api::Status {
            running: true,
            product_version: "1.0.0".to_owned(),
            control_version: "1.0".to_owned(),
            packet_version: 1,
            capabilities: capability_names(advertised_capabilities(&effective)),
            selected_path: selected_path.to_owned(),
            network_id: self.network.to_string(),
            node_id: self.node.to_string(),
            name: local_name,
            interface: effective.tun.name.clone(),
            relay: effective
                .relay
                .address
                .map_or_else(String::new, |address| address.to_string()),
            mtu: effective.tun.mtu,
            metrics: local_api::ApiMetrics {
                connections: values.connections_total,
                reconnects: values.reconnects_total,
                packets_sent: values.packets_sent_total,
                packets_received: values.packets_received_total,
                packets_dropped: values
                    .invalid_drops
                    .saturating_add(values.queue_drops)
                    .saturating_add(values.no_path_drops),
                tcp_connections: values.tcp_connections_total,
                quic_failures: values.quic_failures,
                tcp_failures: values.tcp_failures,
            },
            exit: local_api::ExitStatus {
                enabled: effective.forwarding.exit_client.enabled,
                selected_node_id,
                authorized: authorized_exit,
            },
            controller: local_api::ControllerStatus {
                candidate_exchange_enabled: values.controller_candidate_exchange_enabled != 0,
                certificate_presented_serial: self.certificate_presented_serial.clone(),
                certificate_renewal_needed: values.controller_certificate_renewal_needed != 0,
                certificate_renew_after_unix_seconds: values
                    .controller_certificate_renew_after_seconds,
                certificate_not_after_unix_seconds: values.controller_certificate_not_after_seconds,
            },
        };

        let mut peers = Vec::new();
        if let Some(authority) = &authority {
            for peer in authority
                .peers
                .values()
                .filter(|peer| peer.node != self.node)
            {
                peers.push(local_api::Peer {
                    node_id: peer.node.to_string(),
                    name: peer.name.clone(),
                    prefixes: peer
                        .overlays
                        .iter()
                        .map(|address| {
                            ipnet::IpNet::new(*address, if address.is_ipv4() { 32 } else { 128 })
                                .expect("host prefix length")
                                .to_string()
                        })
                        .collect(),
                });
            }
        } else {
            let mut by_peer = BTreeMap::<Id, Vec<String>>::new();
            for route in self.state.routes.load().routes() {
                by_peer
                    .entry(route.via)
                    .or_default()
                    .push(route.prefix.to_string());
            }
            for (node, prefixes) in by_peer {
                peers.push(local_api::Peer {
                    node_id: node.to_string(),
                    name: String::new(),
                    prefixes,
                });
            }
        }
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        for peer in &mut peers {
            peer.prefixes.sort();
        }

        let routes_snapshot = self.state.routes.load();
        let mut routes: Vec<_> = routes_snapshot
            .routes()
            .iter()
            .map(|route| local_api::Route {
                prefix: route.prefix.to_string(),
                via_node: route.via.to_string(),
                // The stable local API calls every installed forwarding-table
                // entry a peer route; detailed route classes remain internal.
                kind: "peer".to_owned(),
            })
            .collect();
        routes.sort_by(|left, right| {
            left.prefix
                .cmp(&right.prefix)
                .then_with(|| left.via_node.cmp(&right.via_node))
        });
        local_api::Snapshot {
            status,
            peers,
            routes,
        }
    }

    async fn set_exit(&self, selection: local_api::ExitSelection) -> Result<()> {
        let _guard = self.control_lock.lock().await;
        let snapshot = self
            .state
            .authority_snapshot()
            .context("exit selection requires active controller authority")?;
        ensure!(!snapshot.expired(), "controller authority is expired");
        let previous = self.base_config.load_full();
        let next = prepare_exit_base(&previous, &snapshot, self.node, &selection)?;
        let effective = Arc::new(controller_effective_config(&next, &snapshot, self.node));
        ensure!(
            !selection.enabled || effective.forwarding.exit_client.enabled,
            "selected exit has no usable controller route"
        );
        let previous_effective =
            Arc::new(controller_effective_config(&previous, &snapshot, self.node));
        let was_persisted = *self
            .intent_persisted
            .lock()
            .map_err(|_| anyhow::anyhow!("exit intent lock poisoned"))?;
        self.exit_intent
            .save(&next)
            .context("persist exit selection")?;
        if let Err(error) = self
            .apply_effective(
                Arc::clone(&effective),
                Arc::clone(&previous_effective),
                &snapshot,
            )
            .await
        {
            let persistence_rollback = if was_persisted {
                self.exit_intent.save(&previous)
            } else {
                self.exit_intent.remove()
            };
            return Err(match persistence_rollback {
                Ok(()) => error,
                Err(rollback) => error.context(format!(
                    "restore persisted exit selection failed: {rollback:#}"
                )),
            });
        }
        self.base_config.store(Arc::new(next));
        *self
            .intent_persisted
            .lock()
            .map_err(|_| anyhow::anyhow!("exit intent lock poisoned"))? = true;
        let selected = effective
            .forwarding
            .exit_client
            .selected_node
            .as_deref()
            .and_then(|value| value.parse::<Id>().ok());
        Metrics::set(
            &self.metrics.exit_path_available,
            selected.is_some_and(|node| self.state.has_path(node)),
        );
        Ok(())
    }

    async fn apply_effective(
        &self,
        next: Arc<Config>,
        rollback: Arc<Config>,
        snapshot: &Snapshot,
    ) -> Result<()> {
        let compiled = RoutingTable::compile(&next.routes)?;
        reconcile_kernel(&self.kernel, &self.dynamic_bypasses, Arc::clone(&next))?;
        if self.configure_tun
            && let Err(error) = self
                .tun
                .lock()
                .await
                .apply_controller(&snapshot.overlays, &next.routes)
                .await
        {
            let rollback_result = reconcile_kernel(&self.kernel, &self.dynamic_bypasses, rollback);
            return Err(match rollback_result {
                Ok(()) => error,
                Err(rollback) => error.context(format!("kernel rollback failed: {rollback:#}")),
            });
        }
        self.state.routes.store(Arc::new(compiled));
        Ok(())
    }
}

fn prepare_exit_base(
    base: &Config,
    snapshot: &Snapshot,
    local: Id,
    selection: &local_api::ExitSelection,
) -> Result<Config> {
    ensure!(
        base.controller.is_some(),
        "exit selection requires controller authority"
    );
    let mut next = base.clone();
    if selection.enabled {
        let selected: Id = selection
            .selected_node_id
            .parse()
            .context("selected exit node is invalid")?;
        ensure!(selected != local, "selected exit node is local");
        ensure!(
            next.forwarding.exit_client.authorized,
            "exit client is not configuration-authorized"
        );
        ensure!(
            matches!(
                next.forwarding.exit_client.failure_mode,
                crate::config::ExitFailureMode::Open | crate::config::ExitFailureMode::Closed
            ),
            "exit failure_mode is not configured"
        );
        ensure!(
            snapshot.authorized_exits.contains(&selected)
                && snapshot
                    .routes
                    .iter()
                    .any(|route| route.kind == v1::RouteKind::Exit && route.via == selected),
            "selected node is not a controller-authorized exit"
        );
        next.forwarding.exit_client.enabled = true;
        next.forwarding.exit_client.selected_node = Some(selected.to_string());
    } else {
        next.forwarding.exit_client.enabled = false;
        next.forwarding.exit_client.selected_node = None;
    }
    next.validate().context("validate exit selection")?;
    Ok(next)
}

fn advertised_capabilities(config: &Config) -> u64 {
    let mut capabilities =
        v1::Capability::LanewayRelayV1 as u64 | v1::Capability::LanewayQuicDatagramV1 as u64;
    if config.controller.is_some() || !config.direct_peers.is_empty() {
        capabilities |= v1::Capability::LanewayDirectPeerV1 as u64;
    }
    if config.controller.is_some()
        || config.forwarding.subnet_router
        || config
            .routes
            .iter()
            .any(|route| route.kind == crate::config::RouteKind::Subnet)
    {
        capabilities |= v1::Capability::LanewaySubnetRouterV1 as u64;
    }
    if config.controller.is_some()
        || config.forwarding.exit_gateway
        || config
            .routes
            .iter()
            .any(|route| route.kind == crate::config::RouteKind::Exit)
    {
        capabilities |= v1::Capability::LanewayExitNodeV1 as u64;
    }
    if config.tcp_fallback.is_some() {
        capabilities |= v1::Capability::LanewayTcpFallbackV1 as u64;
    }
    if config.controller.is_some()
        || config
            .tun
            .addresses
            .iter()
            .chain(config.routes.iter().map(|route| &route.prefix))
            .any(|prefix| matches!(prefix, ipnet::IpNet::V6(_)))
    {
        capabilities |= v1::Capability::LanewayIpv6V1 as u64;
    }
    capabilities
}

fn capability_names(value: u64) -> String {
    let values = [
        (v1::Capability::LanewayRelayV1 as u64, "relay-v1"),
        (
            v1::Capability::LanewayQuicDatagramV1 as u64,
            "quic-datagram-v1",
        ),
        (v1::Capability::LanewayDirectPeerV1 as u64, "direct-peer-v1"),
        (
            v1::Capability::LanewaySubnetRouterV1 as u64,
            "subnet-router-v1",
        ),
        (v1::Capability::LanewayExitNodeV1 as u64, "exit-node-v1"),
        (
            v1::Capability::LanewayTcpFallbackV1 as u64,
            "tcp-fallback-v1",
        ),
        (v1::Capability::LanewayIpv6V1 as u64, "ipv6-v1"),
        (v1::Capability::LanewayE2ePacketV1 as u64, "e2e-packet-v1"),
    ];
    let names: Vec<_> = values
        .into_iter()
        .filter_map(|(bit, name)| (value & bit != 0).then_some(name))
        .collect();
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(",")
    }
}

struct RuntimeApplier {
    state: Arc<State>,
    metrics: Arc<Metrics>,
    tun: Arc<Mutex<TunDevice>>,
    configure_tun: bool,
    node: Id,
    base_config: Arc<ArcSwap<Config>>,
    kernel: Arc<StdMutex<Option<KernelManager>>>,
    dynamic_bypasses: Arc<StdMutex<BTreeMap<std::net::IpAddr, usize>>>,
    control_lock: Arc<Mutex<()>>,
}

impl SnapshotApplier for RuntimeApplier {
    fn apply<'a>(
        &'a self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let _guard = self.control_lock.lock().await;
            ensure!(
                !snapshot.expired(),
                "controller snapshot expired during application"
            );
            let base = self.base_config.load_full();
            if let Err(error) = validate_controller_relay(&base, &snapshot) {
                self.state.fail_close();
                Metrics::set(&self.metrics.controller_candidate_exchange_enabled, false);
                Metrics::set(&self.metrics.controller_certificate_renewal_forced, true);
                reconcile_kernel(
                    &self.kernel,
                    &self.dynamic_bypasses,
                    Arc::new(controller_disabled_config(&base)),
                )?;
                if self.configure_tun {
                    self.tun.lock().await.apply_controller(&[], &[]).await?;
                }
                return Err(error.context("controller withdrew configured relay authority"));
            }
            let effective = Arc::new(controller_effective_config(&base, &snapshot, self.node));
            let rollback_config = self
                .state
                .authority_snapshot()
                .map(|previous| Arc::new(controller_effective_config(&base, &previous, self.node)))
                .unwrap_or_else(|| Arc::new(controller_disabled_config(&base)));
            let routes = effective.routes.clone();
            let compiled = RoutingTable::compile(&routes)?;
            reconcile_kernel(&self.kernel, &self.dynamic_bypasses, Arc::clone(&effective))?;
            if self.configure_tun
                && let Err(error) = self
                    .tun
                    .lock()
                    .await
                    .apply_controller(&snapshot.overlays, &routes)
                    .await
            {
                let rollback =
                    reconcile_kernel(&self.kernel, &self.dynamic_bypasses, rollback_config);
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback) => error.context(format!("kernel rollback failed: {rollback:#}")),
                });
            }
            self.state.routes.store(Arc::new(compiled));
            publish_controller_metrics(&self.metrics, &snapshot);
            self.state.publish_authority(snapshot);
            Ok(())
        })
    }

    fn fail_close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let _guard = self.control_lock.lock().await;
            self.state.fail_close();
            Metrics::set(&self.metrics.controller_candidate_exchange_enabled, false);
            Metrics::set(&self.metrics.controller_certificate_renewal_forced, true);
            let base = self.base_config.load_full();
            reconcile_kernel(
                &self.kernel,
                &self.dynamic_bypasses,
                Arc::new(controller_disabled_config(&base)),
            )?;
            if self.configure_tun {
                self.tun.lock().await.apply_controller(&[], &[]).await?;
            }
            Ok(())
        })
    }

    fn renew<'a>(
        &'a self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let _guard = self.control_lock.lock().await;
            ensure!(
                !snapshot.expired(),
                "controller renewed an expired snapshot"
            );
            publish_controller_metrics(&self.metrics, &snapshot);
            self.state.publish_authority(snapshot);
            Ok(())
        })
    }
}

fn reconcile_kernel(
    slot: &StdMutex<Option<KernelManager>>,
    dynamic_bypasses: &StdMutex<BTreeMap<std::net::IpAddr, usize>>,
    next: Arc<Config>,
) -> Result<()> {
    let dynamic_bypasses = dynamic_bypasses
        .lock()
        .map_err(|_| anyhow::anyhow!("dynamic bypass lock poisoned"))?
        .clone();
    let mut slot = slot
        .lock()
        .map_err(|_| anyhow::anyhow!("kernel manager lock poisoned"))?;
    let previous_config = slot.as_ref().map(KernelManager::configuration);
    if let Some(previous) = slot.as_mut() {
        previous.restore()?;
    }
    *slot = None;
    let needs_kernel = next.forwarding.subnet_router
        || next.forwarding.exit_gateway
        || next.forwarding.exit_client.enabled;
    if !needs_kernel {
        return Ok(());
    }
    let activate = |config: Arc<Config>| -> Result<KernelManager> {
        let mut manager = KernelManager::apply(config)?;
        if let Err(error) = manager.adopt_dynamic_bypasses(dynamic_bypasses.clone()) {
            let restore = manager.restore();
            return aggregate_results([
                ("adopt dynamic transport bypasses", Err(error)),
                ("restore kernel after bypass adoption failure", restore),
            ])
            .map(|()| manager);
        }
        Ok(manager)
    };
    match activate(next) {
        Ok(manager) => {
            *slot = Some(manager);
            Ok(())
        }
        Err(error) => {
            if let Some(previous) = previous_config {
                match activate(previous) {
                    Ok(manager) => *slot = Some(manager),
                    Err(rollback) => {
                        return Err(error.context(format!(
                            "new kernel activation failed and prior activation could not be restored: {rollback:#}"
                        )));
                    }
                }
            }
            Err(error)
        }
    }
}

fn restore_kernel(slot: &StdMutex<Option<KernelManager>>) -> Result<()> {
    let (lock_result, mut slot) = match slot.lock() {
        Ok(slot) => (Ok(()), slot),
        Err(poisoned) => (
            Err(anyhow::anyhow!("kernel manager lock poisoned")),
            poisoned.into_inner(),
        ),
    };
    let restore_result = slot.as_mut().map_or(Ok(()), KernelManager::restore);
    if restore_result.is_ok() {
        *slot = None;
    }
    drop(slot);
    aggregate_results([
        ("access kernel manager", lock_result),
        ("restore kernel manager", restore_result),
    ])
}

fn aggregate_results<const N: usize>(results: [(&str, Result<()>); N]) -> Result<()> {
    let failures: Vec<String> = results
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error:#}")))
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(failures.join("; ")))
    }
}

fn controller_disabled_config(base: &Config) -> Config {
    let mut disabled = base.clone();
    disabled.routes.clear();
    disabled.tun.addresses.clear();
    disabled.forwarding.subnet_router = false;
    disabled.forwarding.subnet_routes.clear();
    disabled.forwarding.exit_gateway = false;
    disabled.forwarding.exit_gateway_sources.clear();
    disabled.forwarding.exit_client.enabled = false;
    disabled
}

fn validate_controller_relay(_config: &Config, snapshot: &Snapshot) -> Result<()> {
    ensure!(
        snapshot
            .relays
            .values()
            .any(|relay| !relay.resolved.is_empty()),
        "controller authorized no relay service endpoints"
    );
    Ok(())
}

fn publish_controller_metrics(metrics: &Metrics, snapshot: &Snapshot) {
    Metrics::set(
        &metrics.controller_candidate_exchange_enabled,
        snapshot.candidate_exchange.enabled,
    );
    metrics.controller_certificate_renew_after_seconds.store(
        snapshot.certificate_renew_after,
        std::sync::atomic::Ordering::Relaxed,
    );
    metrics.controller_certificate_not_after_seconds.store(
        snapshot.certificate_not_after,
        std::sync::atomic::Ordering::Relaxed,
    );
    Metrics::set(&metrics.controller_certificate_renewal_forced, false);
}

fn controller_effective_config(base: &Config, snapshot: &Snapshot, local: Id) -> Config {
    let mut effective = base.clone();
    effective.tun.addresses = snapshot.overlays.clone();
    effective.routes = route_configs(snapshot, local);
    effective.forwarding.exit_client.controller_bypass.extend(
        snapshot
            .relays
            .values()
            .flat_map(|relay| relay.resolved.iter().map(std::net::SocketAddr::ip)),
    );
    effective
        .forwarding
        .exit_client
        .controller_bypass
        .sort_unstable();
    effective.forwarding.exit_client.controller_bypass.dedup();

    let subnet_capability =
        snapshot.enabled_capabilities & v1::Capability::LanewaySubnetRouterV1 as u64 != 0;
    effective.forwarding.subnet_routes.retain(|configured| {
        subnet_capability
            && snapshot.routes.iter().any(|route| {
                route.via == local
                    && route.kind == v1::RouteKind::Subnet
                    && route.destination == configured.prefix
                    && matches!(
                        (route.mode, configured.mode),
                        (
                            v1::RouteAdvertisementMode::Nat,
                            crate::config::ForwardMode::Nat
                        ) | (
                            v1::RouteAdvertisementMode::Routed,
                            crate::config::ForwardMode::Routed
                        )
                    )
            })
    });
    effective.forwarding.subnet_router =
        base.forwarding.subnet_router && !effective.forwarding.subnet_routes.is_empty();

    let exit_capability =
        snapshot.enabled_capabilities & v1::Capability::LanewayExitNodeV1 as u64 != 0;
    let exit_advertised = snapshot
        .routes
        .iter()
        .any(|route| route.via == local && route.kind == v1::RouteKind::Exit);
    effective.forwarding.exit_gateway =
        base.forwarding.exit_gateway && exit_capability && exit_advertised;
    if !effective.forwarding.exit_gateway {
        effective.forwarding.exit_gateway_sources.clear();
    }

    if effective.forwarding.exit_client.enabled {
        let selected = effective
            .forwarding
            .exit_client
            .selected_node
            .as_deref()
            .and_then(|value| value.parse::<Id>().ok());
        effective.routes.retain(|route| {
            route.kind != crate::config::RouteKind::Exit
                || selected.is_some_and(|selected| {
                    snapshot.authorized_exits.contains(&selected)
                        && route.via_node == selected.to_string()
                })
        });
        if !effective
            .routes
            .iter()
            .any(|route| route.kind == crate::config::RouteKind::Exit)
        {
            effective.forwarding.exit_client.enabled = false;
        }
    } else {
        effective
            .routes
            .retain(|route| route.kind != crate::config::RouteKind::Exit);
    }
    effective
}

fn route_configs(snapshot: &Snapshot, local: Id) -> Vec<crate::config::RouteConfig> {
    snapshot
        .routes
        .iter()
        .filter(|route| route.via != local)
        .map(|route| crate::config::RouteConfig {
            prefix: route.destination,
            via_node: route.via.to_string(),
            metric: route.metric,
            kind: match route.kind {
                v1::RouteKind::Overlay => crate::config::RouteKind::Overlay,
                v1::RouteKind::Subnet => crate::config::RouteKind::Subnet,
                v1::RouteKind::Exit => crate::config::RouteKind::Exit,
                v1::RouteKind::Unspecified => unreachable!("snapshot compilation rejects kind"),
            },
        })
        .collect()
}

fn random_id() -> Result<Id> {
    loop {
        let mut value = [0_u8; 16];
        getrandom::fill(&mut value).context("generate boot ID")?;
        if let Ok(id) = Id::new(value) {
            return Ok(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use ipnet::IpNet;
    use laneway_protocol::{
        policy::CompiledPolicy,
        v1::{PolicyAction, PolicySnapshot},
    };

    use super::*;
    use crate::{
        config::{ForwardMode, SubnetForwardConfig},
        controller::{Peer, Route},
    };

    #[test]
    fn cleanup_aggregation_reports_primary_and_every_restore_failure() {
        let error = aggregate_results([
            ("runtime", Err(anyhow::anyhow!("carrier stopped"))),
            ("kernel", Err(anyhow::anyhow!("rule cleanup failed"))),
            ("tun", Err(anyhow::anyhow!("address cleanup failed"))),
        ])
        .unwrap_err()
        .to_string();

        assert!(error.contains("runtime: carrier stopped"));
        assert!(error.contains("kernel: rule cleanup failed"));
        assert!(error.contains("tun: address cleanup failed"));
    }

    #[test]
    fn cleanup_aggregation_fails_when_only_restore_fails() {
        let error = aggregate_results([
            ("runtime", Ok(())),
            ("kernel", Ok(())),
            ("tun", Err(anyhow::anyhow!("device restore failed"))),
        ])
        .unwrap_err()
        .to_string();

        assert_eq!(error, "tun: device restore failed");
        assert!(aggregate_results([("runtime", Ok(())), ("kernel", Ok(()))]).is_ok());
    }

    #[test]
    fn selected_exit_hysteresis_ignores_transient_loss_and_requires_recovery() {
        let mut state = PathHysteresis::default();
        for _ in 0..PathHysteresis::DOWN_THRESHOLD - 1 {
            assert_eq!(state.observe(false), None);
        }
        assert_eq!(state.observe(false), Some(false));
        state.commit(false);
        assert_eq!(state.observe(true), None);
        assert_eq!(state.observe(false), None);
        assert_eq!(state.observe(true), None);
        assert_eq!(state.observe(true), Some(true));
        state.commit(true);
        assert_eq!(state.observe(true), None);
    }

    #[test]
    fn controller_withdrawal_disables_native_roles_and_filters_exit_selection() {
        let mut base: Config = toml::from_str(include_str!(
            "../../../deploy/examples/node-rust-controller.toml"
        ))
        .unwrap();
        let network = Id::from_str(&base.identity.network_id).unwrap();
        let local = Id::from_str(&base.identity.node_id).unwrap();
        let selected = Id::from_str("202122232425262728292a2b2c2d2e2f").unwrap();
        let other = Id::from_str("303132333435363738393a3b3c3d3e3f").unwrap();
        base.forwarding.subnet_router = true;
        base.forwarding.subnet_routes = vec![SubnetForwardConfig {
            prefix: "192.168.50.0/24".parse().unwrap(),
            mode: ForwardMode::Nat,
            output_interface: "lan0".into(),
        }];
        base.forwarding.owned_prefixes = vec!["192.168.50.0/24".parse().unwrap()];
        base.forwarding.exit_gateway = true;
        base.forwarding.exit_gateway_sources = vec!["100.96.0.0/24".parse().unwrap()];
        base.forwarding.exit_output_interface = Some("eth0".into());
        base.forwarding.exit_client.enabled = true;
        base.forwarding.exit_client.authorized = true;
        base.forwarding.exit_client.selected_node = Some(selected.to_string());
        base.forwarding.exit_client.failure_mode = crate::config::ExitFailureMode::Closed;
        let epoch = 11;
        let policy = CompiledPolicy::compile(
            PolicySnapshot {
                network_id: network.as_bytes().to_vec(),
                configuration_epoch: epoch,
                rules: Vec::new(),
                default_action: PolicyAction::Deny as i32,
            },
            network,
            epoch,
        )
        .unwrap();
        let route = |value: u8, destination: IpNet, via: Id, kind, mode| Route {
            id: Id::new([value; 16]).unwrap(),
            destination,
            via,
            kind,
            mode,
            metric: 100,
        };
        let snapshot = Snapshot {
            epoch,
            valid_until: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            overlays: vec!["100.96.0.1/32".parse().unwrap()],
            peers: HashMap::from([
                (
                    local,
                    Peer {
                        node: local,
                        name: "local".into(),
                        overlays: vec!["100.96.0.1".parse().unwrap()],
                    },
                ),
                (
                    selected,
                    Peer {
                        node: selected,
                        name: "selected".into(),
                        overlays: vec!["100.96.0.2".parse().unwrap()],
                    },
                ),
                (
                    other,
                    Peer {
                        node: other,
                        name: "other".into(),
                        overlays: vec!["100.96.0.3".parse().unwrap()],
                    },
                ),
            ]),
            routes: vec![
                route(
                    1,
                    "192.168.50.0/24".parse().unwrap(),
                    local,
                    v1::RouteKind::Subnet,
                    v1::RouteAdvertisementMode::Nat,
                ),
                route(
                    2,
                    "0.0.0.0/0".parse().unwrap(),
                    local,
                    v1::RouteKind::Exit,
                    v1::RouteAdvertisementMode::Nat,
                ),
                route(
                    3,
                    "0.0.0.0/0".parse().unwrap(),
                    selected,
                    v1::RouteKind::Exit,
                    v1::RouteAdvertisementMode::Nat,
                ),
                route(
                    4,
                    "::/0".parse().unwrap(),
                    other,
                    v1::RouteKind::Exit,
                    v1::RouteAdvertisementMode::Nat,
                ),
            ],
            policy,
            enabled_capabilities: v1::Capability::LanewaySubnetRouterV1 as u64
                | v1::Capability::LanewayExitNodeV1 as u64,
            revoked_serials: HashSet::new(),
            local_certificate_revoked: false,
            relays: HashMap::new(),
            candidate_exchange: crate::controller::CandidateExchangeAuthority {
                enabled: true,
                max_candidates: 8,
                ttl: Duration::from_secs(120),
            },
            authorized_exits: HashSet::from([local, selected, other]),
            certificate_renew_after: u64::MAX - 1,
            certificate_not_after: u64::MAX,
        };
        let effective = controller_effective_config(&base, &snapshot, local);
        assert!(effective.forwarding.subnet_router);
        assert!(effective.forwarding.exit_gateway);
        assert!(
            effective
                .routes
                .iter()
                .any(|route| route.kind == crate::config::RouteKind::Exit
                    && route.via_node == selected.to_string())
        );
        assert!(
            !effective
                .routes
                .iter()
                .any(|route| route.kind == crate::config::RouteKind::Exit
                    && route.via_node == other.to_string())
        );

        let switched = prepare_exit_base(
            &base,
            &snapshot,
            local,
            &local_api::ExitSelection {
                enabled: true,
                selected_node_id: other.to_string(),
            },
        )
        .unwrap();
        let other_string = other.to_string();
        assert_eq!(
            switched.forwarding.exit_client.selected_node.as_deref(),
            Some(other_string.as_str())
        );
        assert!(
            prepare_exit_base(
                &base,
                &snapshot,
                local,
                &local_api::ExitSelection {
                    enabled: true,
                    selected_node_id: Id::new([9; 16]).unwrap().to_string(),
                },
            )
            .unwrap_err()
            .to_string()
            .contains("controller-authorized")
        );
        let disabled = prepare_exit_base(
            &base,
            &snapshot,
            local,
            &local_api::ExitSelection {
                enabled: false,
                selected_node_id: String::new(),
            },
        )
        .unwrap();
        assert!(!disabled.forwarding.exit_client.enabled);
        assert!(disabled.forwarding.exit_client.selected_node.is_none());

        let mut withdrawn = snapshot;
        withdrawn.enabled_capabilities = 0;
        withdrawn.routes.clear();
        let effective = controller_effective_config(&base, &withdrawn, local);
        assert!(!effective.forwarding.subnet_router);
        assert!(effective.forwarding.subnet_routes.is_empty());
        assert!(!effective.forwarding.exit_gateway);
        assert!(effective.forwarding.exit_gateway_sources.is_empty());
        assert!(!effective.forwarding.exit_client.enabled);
        assert!(
            !effective
                .routes
                .iter()
                .any(|route| route.kind == crate::config::RouteKind::Exit)
        );
    }
}
