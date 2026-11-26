use std::{
    io,
    net::{IpAddr, SocketAddr, TcpListener as StdListener},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{
    net::{TcpListener, lookup_host},
    sync::{mpsc, watch},
    time::{MissedTickBehavior, interval, sleep, timeout},
};

use crate::rootless_cli::{
    credentials::Verifier,
    enroll::Identity,
    forward, proxy,
    stack::Stack,
    transport::{PacketReceiver, PacketSender, Transport, TransportOptions},
};

#[derive(Clone)]
pub struct Router {
    stack: Stack,
    sender: PacketSender,
}

impl Router {
    pub async fn resolve(&self, host: &str, port: u16, protocol: u8) -> io::Result<SocketAddr> {
        let allowed = |dst: &SocketAddr| {
            self.stack
                .source_ip(dst.ip())
                .is_some_and(|source| self.sender.allows_flow(source, *dst, protocol))
        };
        let destination = if let Ok(ip) = host.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, port)).filter(allowed)
        } else {
            timeout(Duration::from_secs(5), lookup_host((host, port)))
                .await??
                .find(allowed)
        };
        destination.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no permitted Laneway route",
            )
        })
    }
}

struct LocalProxy {
    listener: StdListener,
    verifier: Verifier,
}

struct Services {
    proxy: Option<LocalProxy>,
    serve_routes: bool,
}

impl LocalProxy {
    fn bind(address: SocketAddr, credentials: PathBuf) -> Result<Self> {
        let listener =
            StdListener::bind(address).with_context(|| format!("binding proxy at {address}"))?;
        listener.set_nonblocking(true)?;
        let verifier = Verifier::open(credentials)?;
        eprintln!("SOCKS5 listening on {}", listener.local_addr()?);
        Ok(Self { listener, verifier })
    }

    async fn refresh_credentials(&self) -> Result<()> {
        // Run one refresh at a time across transport reconnects.
        let mut reload = interval(Duration::from_secs(1));
        reload.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            reload.tick().await;
            let verifier = self.verifier.clone();
            let result = tokio::task::spawn_blocking(move || verifier.reload())
                .await
                .context("reload local proxy credentials")?;
            if let Err(error) = result {
                tracing::warn!(%error, "local proxy credential file unavailable");
            }
        }
    }
}

pub async fn run(
    identity: Identity,
    database: PathBuf,
    listen: Option<SocketAddr>,
    serve_routes: bool,
) -> Result<()> {
    let services = Services {
        proxy: match listen {
            Some(address) => Some(
                tokio::task::spawn_blocking(move || LocalProxy::bind(address, database))
                    .await
                    .context("open local proxy")??,
            ),
            None => None,
        },
        serve_routes,
    };
    let Some(proxy) = &services.proxy else {
        return run_transport(identity, &services).await;
    };
    tokio::select! {
        biased;
        result = proxy.refresh_credentials() => result,
        result = run_transport(identity, &services) => result,
    }
}

async fn run_transport(mut identity: Identity, services: &Services) -> Result<()> {
    loop {
        let files = identity.tls_files()?;
        // The connector invitation uses the controller DNS name for the public
        // TCP relay on 443, just as the existing connector configuration does.
        let fallback = timeout(
            Duration::from_secs(5),
            lookup_host((identity.server_name.as_str(), 443)),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .and_then(|mut addresses| addresses.next());
        let options = TransportOptions {
            network: identity.network_id,
            node: identity.node_id,
            tls: files.config(),
            controller: identity.controller_config(),
            relay_endpoint: identity.relay_endpoint.clone(),
            relay_service: identity.relay_service_id,
            tcp_fallback: fallback,
        };
        tokio::select! {
            () = maintain_transport(options, services) => unreachable!(),
            result = wait_for_renewal(&mut identity) => {
                result?;
                tracing::info!("using renewed node certificate");
            },
        }
    }
}

async fn maintain_transport(options: TransportOptions, services: &Services) {
    let mut retry = Duration::from_secs(1);
    loop {
        let result = match Transport::connect(options.clone()).await {
            Ok(transport) => {
                retry = Duration::from_secs(1);
                process_packets(transport, services).await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            tracing::warn!(%error, "Laneway session interrupted");
        }
        sleep(retry).await;
        retry = (retry * 2).min(Duration::from_secs(30));
    }
}

pub(crate) async fn wait_for_renewal(identity: &mut Identity) -> Result<()> {
    loop {
        sleep(identity.next_renewal_check()?).await;
        match identity.renew_if_due().await {
            Ok(true) => return Ok(()),
            Err(error) => {
                tracing::warn!(%error, "certificate renewal will be retried");
                sleep(Duration::from_secs(5)).await;
            }
            Ok(false) => (),
        }
    }
}

async fn process_packets(transport: Transport, services: &Services) -> Result<()> {
    let (sender, mut incoming, mut tasks) = transport.split();
    let mut authority = sender.authority_changes();
    tokio::select! {
        result = tasks.stopped() => result,
        result = async {
            loop {
                let active = authority.borrow_and_update().is_some();
                if active && let Some(scoped) = sender.scoped() {
                    serve_epoch(&scoped, &mut incoming, &mut authority, services).await?;
                } else {
                    authority.changed().await?;
                }
            }
        } => result,
    }
}

async fn serve_epoch(
    sender: &PacketSender,
    incoming: &mut PacketReceiver,
    authority: &mut watch::Receiver<Option<u64>>,
    services: &Services,
) -> Result<()> {
    let addresses = sender
        .overlays()
        .into_iter()
        .map(|net| net.addr())
        .collect();
    let (tx, mut outgoing) = mpsc::channel(128);
    let (stack, accepted) = Stack::spawn(addresses, tx);
    let listen = async {
        let Some(proxy) = services.proxy.as_ref() else {
            return std::future::pending().await;
        };
        let socket = TcpListener::from_std(proxy.listener.try_clone()?)?;
        let router = Router {
            sender: sender.clone(),
            stack: stack.clone(),
        };
        proxy::serve(socket, proxy.verifier.clone(), stack.clone(), router).await
    };
    let packets = async {
        loop {
            tokio::select! {
                packet = incoming.recv_scoped(sender) => {
                    let packet = packet.context("relay input closed")?;
                    let Ok(meta) = lanewayd_rs::packet_meta(&packet) else { continue };
                    if services.serve_routes && sender.may_open_destination(meta.destination) {
                        stack.ingress(packet.to_vec()).await?;
                    } else {
                        stack.ingress_reply(packet.to_vec()).await?;
                    }
                }
                packet = outgoing.recv() => {
                    sender.try_send(&packet.context("userspace packet stack stopped")?);
                }
            }
        }
    };
    // A changed policy retires the entire generation, including already-open
    // destination sockets and proxy sessions. Renewing an unchanged lease is cheap.
    let result: Result<()> = tokio::select! {
        biased;
        change = authority.changed() => change.context("authority updates stopped"),
        result = forward::serve(accepted, sender.clone()) => result.context("serving assigned subnet"),
        result = listen => result.context("serving local proxy"),
        result = packets => result,
    };
    stack.shutdown().await;
    result
}
