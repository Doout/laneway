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

const USAGE: &str = "usage: laneway-controller serve DATABASE LOOPBACK_IP:PORT CERT_PEM KEY_PEM [--root-token-file PATH] [--node-issuer CHAIN_PEM KEY_PEM LIFETIME_SECONDS] [--node-client-ca ROOTS_PEM] [--node-quic] [--snapshot-validity SECONDS]";

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
    let mut root = None;
    let mut issuer = None;
    let mut client_ca = None;
    let mut node_quic = false;
    let mut snapshot_validity = None;
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
    let (config, _) = tls(&cert, &key, client_ca.as_deref(), false)?;
    let quic = if node_quic {
        ensure!(client_ca.is_some(), "node QUIC requires --node-client-ca");
        let (config, id) = tls(&cert, &key, client_ca.as_deref(), true)?;
        Some((
            crate::quic::config(config)?,
            id.context("missing controller identity")?.network_id,
        ))
    } else {
        None
    };
    laneway_controller::SessionStore::check_database(&database)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(
            super::http::State::new(
                database,
                root,
                issuer,
                client_ca.is_some(),
                snapshot_validity.unwrap_or(300),
            )?,
            address,
            config,
            quic,
        ))
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

fn tls(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
    quic: bool,
) -> Result<(
    ServerConfig,
    Option<laneway_protocol::AuthenticatedIdentity>,
)> {
    let chain =
        rustls_pemfile::certs(&mut pem(cert, false)?).collect::<std::io::Result<Vec<_>>>()?;
    let key =
        rustls_pemfile::private_key(&mut pem(key, true)?)?.context("missing TLS private key")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let builder = if let Some(path) = client_ca {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut pem(path, false)?) {
            roots.add(cert?)?;
        }
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
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
    let identity = if quic {
        let id = laneway_protocol::identity_from_certificate_der(
            chain.first().context("empty service certificate")?.as_ref(),
        )?;
        ensure!(
            id.role == laneway_protocol::Role::Controller,
            "node QUIC requires a controller service certificate"
        );
        Some(id)
    } else {
        None
    };
    let mut config = builder.with_single_cert(chain, key)?;
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![if quic {
        b"laneway-control/1".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Ok((config, identity))
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
    quic: Option<(quinn::ServerConfig, laneway_protocol::Id)>,
) -> Result<()> {
    let listener = TcpListener::bind(address).await?;
    // Bind both sockets before announcing readiness. UDP uses the actual TCP
    // port even when the lab requests an ephemeral port.
    let endpoint = quic
        .map(|(cfg, network)| {
            Ok::<_, anyhow::Error>((
                quinn::Endpoint::server(cfg, listener.local_addr()?)?,
                network,
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
    let stop = stop();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            result=&mut control => return result,
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
    while tasks.join_next().await.is_some() {}
    Ok(())
}
