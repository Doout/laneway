use super::{Inner, Server, serve_shared_tls, wait_shutdown};
use anyhow::{Context, Result, ensure};
use laneway_protocol::{Role, identity_from_certificate_der, tenants::Manifest};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
    time::Instant,
};
use tokio_rustls::LazyConfigAcceptor;
use tracing::debug;

struct Route {
    inner: Arc<Inner>,
    slots: Arc<Semaphore>,
}

pub(super) async fn run(path: &Path, shutdown: impl Future<Output = ()>) -> Result<()> {
    let mut bytes = Vec::new();
    File::open(path)?.take(262_145).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 262_144, "tenant manifest exceeds 256 KiB");
    let manifest: Manifest = serde_json::from_slice(&bytes).context("decode tenant manifest")?;
    let entries = manifest.entries().map_err(anyhow::Error::msg)?;
    let mut routes = BTreeMap::new();
    let mut udp = BTreeSet::new();
    let mut certificate_caches = BTreeSet::new();
    let mut workloads = BTreeSet::new();
    let mut servers = Vec::new();
    for (host, cell) in entries {
        let config = crate::Config::load(&cell.relay_config)?;
        let public = config
            .public_https
            .as_ref()
            .context("each tenant relay requires public HTTPS")?;
        let controller = config
            .controller
            .as_ref()
            .context("each tenant relay requires a controller")?;
        let expected = crate::tls::load_certificates(&cell.controller_certificate)?;
        let expected = identity_from_certificate_der(
            expected.first().context("empty controller chain")?.as_ref(),
        )?;
        ensure!(
            expected.role == Role::Controller
                && public.server_name == host
                && controller.server_name == host
                && controller
                    .dial_address
                    .is_some_and(|addr| addr.port() == cell.controller_https.port())
                && controller.network_id == expected.network_id.to_string()
                && controller.service_id == expected.subject_id.to_string(),
            "{host}: relay does not match the hostname and controller in the tenant manifest"
        );
        let relay_leaf = crate::tls::load_certificates(&config.tls.certificate_file)?;
        let relay = identity_from_certificate_der(
            relay_leaf.first().context("empty relay chain")?.as_ref(),
        )?;
        ensure!(
            relay.role == Role::Relay
                && relay.network_id == expected.network_id
                && workloads.insert(*relay.network_id.as_bytes())
                && crate::tls::load_certificates(&config.tls.ca_file)?
                    == crate::tls::load_certificates(&cell.client_ca)?,
            "{host}: relay workload identity or trust roots do not match the tenant"
        );
        ensure!(
            config.tcp_fallback_addr()? == Some(manifest.public_listen),
            "{host}: relay TCP fallback must match the shared public listener"
        );
        let quic = config.listen_addr()?;
        ensure!(
            quic.port() != 0 && udp.insert(quic),
            "{host}: duplicate or ephemeral relay QUIC listener"
        );
        if let Some(cache) = &public.cache_dir {
            ensure!(
                certificate_caches.insert(std::fs::canonicalize(cache)?),
                "{host}: public TLS caches must be independent"
            );
        }
        if let Some(renewal) = &config.tls.renewal_dir {
            ensure!(
                certificate_caches.insert(std::fs::canonicalize(renewal)?),
                "{host}: workload renewal directories must be independent"
            );
        }
        let server = Server::bind_with_tcp(config, false)
            .with_context(|| format!("bind relay for {host}"))?;
        routes.insert(
            host.clone(),
            Route {
                inner: server.inner.clone(),
                slots: server.slots.clone(),
            },
        );
        servers.push((host, server));
    }
    let listener = TcpListener::bind(manifest.public_listen)
        .await
        .context("bind shared public TCP listener")?;
    let budget = Arc::new(Semaphore::new(128));
    let routes = Arc::new(routes);
    let (stop, stopped) = watch::channel(false);
    let mut workers = JoinSet::new();
    for (host, server) in servers {
        let mut stopped = stopped.clone();
        workers.spawn(async move {
            server
                .serve_until(wait_shutdown(&mut stopped))
                .await
                .with_context(|| format!("relay for {host} stopped"))
        });
    }
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            worker = workers.join_next() => {
                break match worker {
                    Some(Ok(Err(error))) => Err(error),
                    Some(Err(error)) => Err(error).context("tenant relay panicked"),
                    _ => Err(anyhow::anyhow!("tenant relay exited before shutdown")),
                };
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(socket) => socket,
                    Err(error) => break Err(error).context("accept tenant TLS connection"),
                };
                let Ok(permit) = budget.clone().try_acquire_owned() else { continue };
                let routes = routes.clone();
                let mut stopped = stopped.clone();
                connections.spawn(async move {
                    let result = async {
                        stream.set_nodelay(true)?;
                        let start = Instant::now();
                        let hello = tokio::select! {
                            result = tokio::time::timeout_at(start + Duration::from_secs(5),
                                LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)) => result??,
                            _ = wait_shutdown(&mut stopped) => return Ok(()),
                        };
                        // Only the exact TLS SNI selects a cell, never a user-controlled
                        // HTTP header. PublicHttps independently checks the Host header.
                        let route = hello.client_hello().server_name()
                            .and_then(|name| routes.get(name))
                            .context("unknown tenant hostname")?;
                        let deadline = start + route.inner.tcp_config.as_ref()
                            .context("missing tenant TCP configuration")?.handshake_timeout;
                        serve_shared_tls(route.inner.clone(), hello, peer.ip(), permit,
                            route.slots.clone(), stopped, deadline).await
                    }.await;
                    if let Err(error) = result {
                        debug!(%error, "tenant TLS connection ended");
                    }
                });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    let _ = stop.send(true);
    while connections.join_next().await.is_some() {}
    while let Some(worker) = workers.join_next().await {
        if result.is_ok() {
            worker.context("tenant relay panicked during shutdown")??;
        }
    }
    result
}
