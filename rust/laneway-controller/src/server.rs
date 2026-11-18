use anyhow::{Context, Result, ensure};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ServerConfig;
use std::{
    convert::Infallible,
    ffi::OsString,
    fs::File,
    io::{Cursor, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_rustls::TlsAcceptor;
mod service_tls;

const DEFAULT_RENEW_BEFORE: i64 = 7 * 24 * 60 * 60;
const USAGE: &str = "usage: laneway-controller serve DATABASE LOOPBACK_IP:PORT CERT_PEM KEY_PEM [--root-token-file PATH] [--node-issuer CHAIN_PEM KEY_PEM LIFETIME_SECONDS] [--node-client-ca ROOTS_PEM] [--node-quic [--quic-listen IP:PORT]] [--snapshot-validity SECONDS] [--location-database CITY_MMDB] [--allow-insecure-application-callbacks] [--bootstrap-profile PROFILE_JSON] [--console-dir ABSOLUTE_DIST_DIR] [--renew-controller-tls ABSOLUTE_STATE_DIR [--controller-renew-before SECONDS]]";

struct QuicListener {
    config: quinn::ServerConfig,
    network: laneway_protocol::Id,
    address: Option<SocketAddr>,
}

pub fn start(mut args: impl Iterator<Item = OsString>) -> Result<()> {
    let database = PathBuf::from(args.next().context(USAGE)?);
    let address: SocketAddr = args
        .next()
        .context(USAGE)?
        .to_str()
        .context(USAGE)?
        .parse()?;
    ensure!(
        address.ip().is_loopback(),
        "controller inventory listener requires a loopback address"
    );
    let cert = PathBuf::from(args.next().context(USAGE)?);
    let key = PathBuf::from(args.next().context(USAGE)?);
    ensure!(
        std::fs::symlink_metadata(&database)?.is_file(),
        "expected a regular controller database file, not a symlink"
    );
    #[cfg(unix)]
    let _lifecycle_lock = laneway_controller::database_lock::acquire(&database)?;
    let mut root = None;
    let mut issuer = None;
    let mut client_ca = None;
    let mut node_quic = false;
    let mut quic_listen = None;
    let mut snapshot_validity = None;
    let mut location_database = None;
    let mut allow_loopback_callbacks = false;
    let mut bootstrap_profile = None;
    let mut console_dir = None;
    let mut renewal_dir = None;
    let mut renew_before = None;
    while let Some(flag) = args.next() {
        if flag == "--root-token-file" && root.is_none() {
            root = Some(laneway_controller::RootCredential::load(
                &PathBuf::from(args.next().context(USAGE)?),
                &database,
            )?);
        } else if flag == "--node-issuer" && issuer.is_none() {
            let chain = PathBuf::from(args.next().context(USAGE)?);
            let signer = PathBuf::from(args.next().context(USAGE)?);
            let lifetime = args
                .next()
                .context(USAGE)?
                .to_str()
                .context(USAGE)?
                .parse()?;
            let certificates = rustls_pemfile::certs(&mut pem(&chain, false)?)
                .collect::<std::io::Result<Vec<_>>>()?;
            let key = rustls_pemfile::private_key(&mut pem(&signer, true)?)?
                .context("missing node CA key")?;
            issuer = Some(laneway_controller::node_pki::NodeIssuer::new(
                &certificates,
                &key,
                lifetime,
            )?);
        } else if flag == "--node-client-ca" && client_ca.is_none() {
            client_ca = Some(PathBuf::from(args.next().context(USAGE)?));
        } else if flag == "--node-quic" && !node_quic {
            node_quic = true;
        } else if flag == "--location-database" && location_database.is_none() {
            location_database = Some(PathBuf::from(args.next().context(USAGE)?));
        } else if flag == "--allow-insecure-application-callbacks" && !allow_loopback_callbacks {
            allow_loopback_callbacks = true;
        } else if flag == "--bootstrap-profile" && bootstrap_profile.is_none() {
            bootstrap_profile = Some(PathBuf::from(args.next().context(USAGE)?));
        } else if flag == "--console-dir" && console_dir.is_none() {
            console_dir = Some(PathBuf::from(args.next().context(USAGE)?));
        } else if flag == "--renew-controller-tls" && renewal_dir.is_none() {
            renewal_dir = Some(PathBuf::from(args.next().context(USAGE)?));
        } else if flag == "--controller-renew-before" && renew_before.is_none() {
            let seconds = args
                .next()
                .context(USAGE)?
                .to_str()
                .context(USAGE)?
                .parse()?;
            ensure!(
                (1..=DEFAULT_RENEW_BEFORE).contains(&seconds),
                "controller renewal window must be between 1 second and 7 days"
            );
            renew_before = Some(seconds);
        } else if flag == "--quic-listen" && quic_listen.is_none() {
            quic_listen = Some(
                args.next()
                    .context(USAGE)?
                    .to_str()
                    .context(USAGE)?
                    .parse()?,
            );
        } else if flag == "--snapshot-validity" && snapshot_validity.is_none() {
            let seconds = args
                .next()
                .context(USAGE)?
                .to_str()
                .context(USAGE)?
                .parse()?;
            ensure!(
                (1..=86400).contains(&seconds),
                "snapshot validity must be in [1,86400] seconds"
            );
            snapshot_validity = Some(seconds);
        } else {
            anyhow::bail!(USAGE)
        }
    }
    ensure!(
        client_ca.is_none() || issuer.is_some(),
        "node renewal requires --node-issuer"
    );
    ensure!(
        quic_listen.is_none() || node_quic,
        "--quic-listen requires --node-quic"
    );
    ensure!(
        renew_before.is_none() || renewal_dir.is_some(),
        "--controller-renew-before requires --renew-controller-tls"
    );
    let identity = Arc::new(service_tls::Identity::load(&cert, &key)?);
    let roots = client_ca.as_deref().map(tls_roots).transpose()?;
    laneway_controller::SessionStore::check_database(&database)?;
    let location_database =
        location_database.and_then(
            |path| match laneway_controller::node_location::Database::open(&path) {
                Ok(db) => Some(Arc::new(db)),
                Err(_) => {
                    eprintln!("Node location lookup disabled: could not open local City database");
                    None
                }
            },
        );
    let mut state = super::http::State::new(
        database.clone(),
        root,
        issuer,
        client_ca.is_some(),
        snapshot_validity.unwrap_or(300),
        location_database,
        allow_loopback_callbacks,
    )?;
    let renewal = renewal_dir
        .as_deref()
        .map(|directory| {
            service_tls::Renewal::prepare(
                directory,
                [&cert, &key],
                Arc::clone(&identity),
                roots
                    .clone()
                    .context("--renew-controller-tls requires --node-client-ca")?,
                state
                    .issuer
                    .clone()
                    .context("--renew-controller-tls requires --node-issuer")?,
                renew_before.unwrap_or(DEFAULT_RENEW_BEFORE),
            )
        })
        .transpose()?;
    let active = identity.active();
    state.bootstrap_discovery = if let Some(profile) = bootstrap_profile {
        let ca = client_ca
            .as_ref()
            .context("--bootstrap-profile requires --node-client-ca")?;
        let profile = pem(&profile, false)
            .context("read bootstrap profile")?
            .into_inner();
        Some(Arc::new(
            laneway_controller::bootstrap_discovery::Discovery::load(
                &database,
                &profile,
                &active.cert,
                &mut pem(ca, false)?,
            )?,
        ))
    } else {
        None
    };
    let quic = if node_quic {
        ensure!(roots.is_some(), "node QUIC requires --node-client-ca");
        let id =
            laneway_protocol::identity_from_certificate_der(active.end_entity_cert()?.as_ref())?;
        ensure!(
            id.role == laneway_protocol::Role::Controller,
            "node QUIC requires a controller service certificate"
        );
        Some(QuicListener {
            config: crate::quic::config(tls(Arc::clone(&identity), roots.as_ref(), true)?)?,
            network: id.network_id,
            address: quic_listen,
        })
    } else {
        None
    };
    let config = tls(identity, roots.as_ref(), false)?;
    let console_dir =
        console_dir.or_else(|| std::env::var_os("LANEWAY_CONSOLE_DIR").map(PathBuf::from));
    state.console = console_dir
        .as_deref()
        .map(super::http::console::Console::load)
        .transpose()
        .context("load live console build")?
        .map(Arc::new);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(state, address, config, quic, renewal))
}

fn pem(path: &Path, private: bool) -> Result<Cursor<zeroize::Zeroizing<Vec<u8>>>> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    ensure!(meta.is_file(), "TLS material must be a regular file");
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o037 == 0,
            "private TLS key must not be group-writable or world-accessible"
        );
    }
    let mut data = zeroize::Zeroizing::new(Vec::new());
    file.take(65537).read_to_end(&mut data)?;
    ensure!(data.len() <= 65536, "oversized TLS material");
    Ok(Cursor::new(data))
}

fn tls_roots(path: &Path) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pem(path, false)?) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "node client trust store is empty");
    Ok(roots)
}

fn tls(
    identity: Arc<service_tls::Identity>,
    roots: Option<&rustls::RootCertStore>,
    quic: bool,
) -> Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let builder = if let Some(roots) = roots {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            provider,
        );
        let verifier = if quic {
            verifier
        } else {
            verifier.allow_unauthenticated()
        }
        .build()?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_cert_resolver(identity);
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![if quic {
        b"laneway-control/1".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Ok(config)
}

async fn stop() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = term.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

async fn serve(
    state: super::http::State,
    address: SocketAddr,
    config: ServerConfig,
    quic: Option<QuicListener>,
    renewal: Option<service_tls::Renewal>,
) -> Result<()> {
    let listener = TcpListener::bind(address).await?;
    // Bind both sockets before announcing readiness. By default UDP shares the
    // actual TCP address even when the lab requests an ephemeral port.
    let endpoint = quic
        .map(|cfg| {
            Ok::<_, anyhow::Error>((
                quinn::Endpoint::server(cfg.config, cfg.address.unwrap_or(listener.local_addr()?))?,
                cfg.network,
            ))
        })
        .transpose()?;
    let control = async {
        match &endpoint {
            Some((ep, network)) => crate::quic::serve(ep, *network, state.clone()).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(control);
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let connections = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    println!("listening https://{}", listener.local_addr()?);
    if let Some((ep, _)) = &endpoint {
        println!("listening quic://{}", ep.local_addr()?);
    }
    let renewal = renewal.map(|worker| tokio::spawn(worker.run()));
    let topology_expiry = prune_topology(state.clone());
    tokio::pin!(topology_expiry);
    let stop = stop();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            result=&mut control => return result,
            _=&mut topology_expiry => unreachable!("topology expiry loop never returns"),
            result=&mut stop => { result?; break; }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            socket=listener.accept() => {
                let (socket, peer)=socket?;
                let Ok(permit)=Arc::clone(&connections).try_acquire_owned() else {continue};
                let state=state.clone();
                let acceptor=acceptor.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let Ok(Ok(tls))=timeout(Duration::from_secs(5),acceptor.accept(socket)).await else {return};
                    // Incoming HTTP headers never supply an identity. rustls has
                    // verified both the client chain and proof of key possession.
                    let leaf=tls.get_ref().1.peer_certificates().and_then(|c|c.first()).map(|c|c.clone().into_owned());
                    let handler=service_fn(move |mut req:hyper::Request<hyper::body::Incoming>| {
                        if let Some(cert)=&leaf{req.extensions_mut().insert(cert.clone());}
                        let state=state.clone();
                        async move {Ok::<_,Infallible>(super::http::handle(req,state,peer.ip()).await)}
                    });
                    let mut builder=http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5))
                        .keep_alive(false).max_headers(64).max_buf_size(32*1024);
                    let _=timeout(Duration::from_secs(15),builder.serve_connection(TokioIo::new(tls),handler)).await;
                });
            }
        }
    }
    // No new sockets. Requests already admitted may finish within their deadline.
    if let Some((ep, _)) = &endpoint {
        ep.close(0u32.into(), b"controller shutdown");
    }
    if let Some(worker) = renewal {
        worker.abort();
        let _ = worker.await;
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn prune_topology(state: super::http::State) {
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let Ok(permit) = Arc::clone(&state.queries).try_acquire_owned() else {
            continue;
        };
        let database = state.database.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            laneway_controller::SessionStore::open(&database)?.prune_topology()
        })
        .await;
    }
}
