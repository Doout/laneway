//! Encrypted relay transport. The kernel/device caller owns keys and applies
//! cryptographic peer routes and the decrypted firewall before joining.

use std::{
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use laneway_protocol::{Id, validate_wireguard_packet};
use tokio::sync::mpsc;

use crate::{
    agent::random_id,
    authority::{Authority, Runner, SnapshotApplier},
    config::Config,
    controller::{Client, ClientOptions, PollResult, Snapshot},
    metrics::Metrics,
    packet_pool::PacketPool,
    relay::{OutboundPacket, RelayClient},
    routing::RoutingTable,
    state::State,
    tls,
};

#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
mod plan;
#[cfg(target_os = "linux")]
pub use native::WireGuardNode;

pub(crate) const MAX_WIREGUARD_DATAGRAM: usize = 2048;

/// Opaque WireGuard UDP data and the exact controller-bound peer key.
pub struct WireGuardDatagram {
    peer: Id,
    key: [u8; 32],
    payload: Bytes,
}

impl std::fmt::Debug for WireGuardDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardDatagram")
            .field("peer", &self.peer)
            .field("len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl WireGuardDatagram {
    /// Wrap a kernel-produced WireGuard message with the configured peer key.
    pub fn new(peer: Id, key: [u8; 32], payload: Bytes) -> Result<Self> {
        ensure!(
            payload.len() <= MAX_WIREGUARD_DATAGRAM,
            "WireGuard datagram exceeds the relay limit"
        );
        validate_wireguard_packet(&payload)?;
        Ok(Self::checked(peer, key, payload))
    }

    pub(crate) fn checked(peer: Id, key: [u8; 32], payload: Bytes) -> Self {
        Self { peer, key, payload }
    }

    /// Authenticated overlay identity of the remote peer.
    pub fn peer(&self) -> Id {
        self.peer
    }

    /// Controller-bound public key; check it again before injecting a queued
    /// datagram into a device whose peer configuration may have changed.
    pub fn peer_key(&self) -> [u8; 32] {
        self.key
    }

    /// Byte-for-byte WireGuard UDP message, never decrypted by this transport.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// An authenticated relay transport for a WireGuard device managed by its caller.
///
/// This component does not configure addresses, device keys, forwarding, or
/// decrypted traffic policy. It never starts the raw-IP node path.
pub struct WireGuardRelay {
    config: Arc<Config>,
    generation: Option<NonZeroU64>,
    local_key: [u8; 32],
}

impl WireGuardRelay {
    /// Validate the carrier configuration and bind it to the caller's actual
    /// local WireGuard public key. Ephemeral exits must supply their enrollment
    /// generation; ordinary nodes must not.
    pub fn new(
        config: Config,
        local_key: [u8; 32],
        generation: Option<NonZeroU64>,
    ) -> Result<Self> {
        config.validate()?;
        ensure!(
            config.controller.is_some() && !config.connector.userspace,
            "WireGuard relay requires controller node authority"
        );
        ensure!(local_key != [0; 32], "missing local WireGuard public key");
        let (network, node) = config.ids()?;
        tls::validate_local(&config.tls, network, node)?;
        Ok(Self {
            config: Arc::new(config),
            generation,
            local_key,
        })
    }

    /// Run QUIC with optional TLS/TCP fallback. Both carriers require WireGuard
    /// negotiation and live controller ownership for the datagram's peer key.
    pub async fn run_until(
        self,
        from_device: mpsc::Receiver<WireGuardDatagram>,
        to_device: mpsc::Sender<WireGuardDatagram>,
        shutdown: impl Future<Output = ()>,
    ) -> Result<()> {
        self.run(
            from_device,
            to_device,
            #[cfg(target_os = "linux")]
            None,
            shutdown,
        )
        .await
    }

    async fn run(
        self,
        mut from_device: mpsc::Receiver<WireGuardDatagram>,
        to_device: mpsc::Sender<WireGuardDatagram>,
        #[cfg(target_os = "linux")] native: Option<Arc<native::NativeKernel>>,
        shutdown: impl Future<Output = ()>,
    ) -> Result<()> {
        let (network, node) = self.config.ids()?;
        let control = self
            .config
            .controller
            .as_ref()
            .context("missing WireGuard controller")?;
        let cert = tls::local_certificate_health(&self.config.tls)?;
        let cert_deadline = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(cert.not_after))
            .context("invalid WireGuard certificate deadline")?;
        let client = Arc::new(
            Client::new(ClientOptions {
                endpoint: control.endpoint.clone(),
                quic_endpoint: control.quic_endpoint.clone(),
                server_name: control.server_name.clone(),
                network,
                service: control.service_id.parse()?,
                certificate: self.config.tls.certificate.clone(),
                private_key: self.config.tls.private_key.clone(),
                ca: self.config.tls.ca.clone(),
                timeout: control.timeout,
                exit_generation: self.generation,
            })
            .await?,
        );
        let _control_guard = ControlGuard(Arc::clone(&client));
        tokio::pin!(shutdown);
        let initial = tokio::select! {
            biased;
            _ = &mut shutdown => {
                client.close_quic().await;
                return Ok(());
            }
            initial = client.poll(0) => initial?,
        };
        let PollResult::Modified(initial) = initial else {
            bail!("missing initial WireGuard authority snapshot");
        };
        let initial = Arc::new(
            Snapshot::compile_for(*initial, network, node, &cert, self.generation)?
                .resolve_relays()
                .await?,
        );
        let authority = Authority::new();
        let state = Arc::new(State::controller(RoutingTable::compile(&[])?, node));
        let applier = Arc::new(CarrierAuthority {
            state: Arc::clone(&state),
            node,
            local_key: self.local_key,
            #[cfg(target_os = "linux")]
            native,
        });
        applier.apply(Arc::clone(&initial)).await?;
        authority.seed(initial)?;
        let runner = Runner::new(
            Arc::clone(&client),
            authority,
            Arc::clone(&applier),
            network,
            node,
            cert,
            control.poll_interval,
        )?;

        let endpoint = quinn::Endpoint::client(self.config.direct.listen)?;
        let metrics = Arc::new(Metrics::default());
        let (outbound, from_kernel) = mpsc::channel(self.config.relay.queue_depth);
        // These queues have no consumers in encrypted transport mode; the
        // relay cannot publish plaintext packets or direct candidates to them.
        let (raw, _raw) = mpsc::channel(1);
        let (candidates, _candidates) = mpsc::channel(1);
        let carrier = RelayClient::new(
            endpoint.clone(),
            Arc::clone(&self.config),
            Arc::clone(&state),
            Arc::clone(&metrics),
            network,
            node,
            random_id()?,
            Arc::new(Vec::new()),
            raw,
            candidates,
        )
        .require_wireguard(self.local_key, to_device);
        let pool = PacketPool::prewarmed(self.config.relay.queue_depth, MAX_WIREGUARD_DATAGRAM + 5);
        let pump = async {
            while let Some(datagram) = from_device.recv().await {
                let (packet, miss) = OutboundPacket::wireguard(datagram, &pool);
                if miss {
                    Metrics::increment(&metrics.packet_pool_misses);
                }
                if outbound.try_send(packet).is_err() {
                    Metrics::increment(&metrics.queue_drops);
                }
            }
            bail!("WireGuard device queue closed")
        };
        let result = tokio::select! {
            biased;
            _ = shutdown => Ok(()),
            _ = tokio::time::sleep(cert_deadline.duration_since(SystemTime::now()).unwrap_or_default()) =>
                Err(anyhow::anyhow!("WireGuard node certificate expired")),
            result = runner.run() => result,
            result = carrier.run(from_kernel) => result,
            result = pump => result,
        };
        state.fail_close();
        endpoint.close(0_u32.into(), b"WireGuard relay ended");
        let cleanup = applier.fail_close().await;
        client.close_quic().await;
        match (result, cleanup) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(error), Err(cleanup)) => {
                Err(error.context(format!("WireGuard shutdown failed: {cleanup:#}")))
            }
        }
    }
}

struct ControlGuard(Arc<Client>);

impl Drop for ControlGuard {
    fn drop(&mut self) {
        self.0.begin_quic_shutdown();
    }
}

struct CarrierAuthority {
    state: Arc<State>,
    node: Id,
    local_key: [u8; 32],
    #[cfg(target_os = "linux")]
    native: Option<Arc<native::NativeKernel>>,
}

impl CarrierAuthority {
    async fn publish(&self, snapshot: Arc<Snapshot>, _renewed: bool) -> Result<()> {
        if snapshot.wireguard_authority_expired()
            || snapshot.local_certificate_revoked
            || snapshot.peers.get(&self.node).and_then(|p| p.wireguard_key) != Some(self.local_key)
        {
            self.fail_close().await?;
            bail!("live controller does not bind the local WireGuard key");
        }
        #[cfg(target_os = "linux")]
        if let Some(native) = &self.native {
            if !_renewed {
                self.state.suspend_wireguard_authority();
            }
            if let Err(error) = native.apply(Arc::clone(&snapshot), _renewed).await {
                self.state.fail_close();
                return Err(error);
            }
        }
        self.state.publish_authority(snapshot);
        Ok(())
    }
}

impl SnapshotApplier for CarrierAuthority {
    fn apply(
        &self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(self.publish(snapshot, false))
    }

    fn fail_close(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async {
            self.state.fail_close();
            #[cfg(target_os = "linux")]
            if let Some(native) = &self.native {
                native.fail_close().await?;
            }
            Ok(())
        })
    }

    fn renew(
        &self,
        snapshot: Arc<Snapshot>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(self.publish(snapshot, true))
    }
}
