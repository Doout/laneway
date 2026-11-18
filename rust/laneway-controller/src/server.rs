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

const USAGE: &str = "usage: laneway-controller serve DATABASE LOOPBACK_IP:PORT CERT_PEM KEY_PEM [--root-token-file PATH] [--node-issuer CHAIN_PEM KEY_PEM LIFETIME_SECONDS]";

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
        } else {
            anyhow::bail!(USAGE)
        }
    }
    let config = tls(&cert, &key)?;
    laneway_controller::SessionStore::check_database(&database)?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve(
            super::http::State::new(database, root, issuer)?,
            address,
            config,
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

fn tls(cert: &Path, key: &Path) -> Result<ServerConfig> {
    let chain =
        rustls_pemfile::certs(&mut pem(cert, false)?).collect::<std::io::Result<Vec<_>>>()?;
    let key =
        rustls_pemfile::private_key(&mut pem(key, true)?)?.context("missing TLS private key")?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
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

async fn serve(state: super::http::State, address: SocketAddr, config: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(address).await?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let connections = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    println!("listening https://{}", listener.local_addr()?);
    let stop = stop();
    tokio::pin!(stop);
    loop {
        tokio::select! {
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
                    let handler=service_fn(move |req| {
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
    while tasks.join_next().await.is_some() {}
    Ok(())
}
