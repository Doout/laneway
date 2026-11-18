//! Kernel packet fixture for the production encrypted relay component.
#![cfg(target_os = "linux")]

use std::{env, future::pending, num::NonZeroU64};

use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use lanewayd_rs::{Config, WireGuardDatagram, WireGuardRelay};
use tokio::{
    net::UdpSocket,
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};
use tracing_subscriber::EnvFilter;

fn key(variable: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(env::var(variable)?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid lab public key"))
}

#[tokio::test]
#[ignore = "requires Linux network namespace and kernel WireGuard"]
async fn kernel_relay_bridge() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()
        .ok();
    let config = Config::load(env::var("LANEWAY_WG_CONFIG")?)?;
    let local_key = key("LANEWAY_WG_LOCAL_PUBLIC")?;
    let peer_key = key("LANEWAY_WG_PEER_PUBLIC")?;
    let peer = env::var("LANEWAY_WG_PEER_ID")?.parse()?;
    let generation = env::var("LANEWAY_WG_EXIT_GENERATION")
        .ok()
        .map(|g| g.parse::<NonZeroU64>())
        .transpose()?;
    let socket = UdpSocket::bind(("127.0.0.1", 57002)).await?;
    socket.connect(("127.0.0.1", 57001)).await?;
    let relay = WireGuardRelay::new(config, local_key, generation)?;
    let (outbound, relay_input) = mpsc::channel(32);
    let (relay_output, mut inbound) = mpsc::channel::<WireGuardDatagram>(32);
    let adapter = async {
        let mut buffer = [0_u8; 2049];
        loop {
            tokio::select! {
                read = socket.recv(&mut buffer) => {
                    let size = read?;
                    let datagram = WireGuardDatagram::new(peer, peer_key, Bytes::copy_from_slice(&buffer[..size]))?;
                    if outbound.send(datagram).await.is_err() {
                        return pending().await;
                    }
                }
                received = inbound.recv() => {
                    // Packet channels close before the control session. Let
                    // the relay finish cleanup and return its own result.
                    let Some(datagram) = received else { return pending().await };
                    if datagram.peer() != peer || datagram.peer_key() != peer_key {
                        bail!("relay delivered ciphertext from an unconfigured kernel peer");
                    }
                    socket.send(datagram.payload()).await?;
                }
            }
        }
    };
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        result = relay.run_until(relay_input, relay_output, async { term.recv().await; }) => result,
        result = adapter => result,
    }
}
