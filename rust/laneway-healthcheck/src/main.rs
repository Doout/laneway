use std::{
    env, io,
    net::{Ipv4Addr, SocketAddrV4},
    process::ExitCode,
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};

enum Target {
    Tcp(SocketAddrV4),
    Tls(SocketAddrV4, String, rustls::pki_types::ServerName<'static>),
    #[cfg(unix)]
    Unix(String),
}

fn target(mut args: impl Iterator<Item = String>) -> Option<Target> {
    let flag = args.next()?;
    let value = args.next()?;
    match flag.as_str() {
        "-tcp" => {
            let address: SocketAddrV4 = value.parse().ok()?;
            if address.ip() != &Ipv4Addr::LOCALHOST || address.port() == 0 {
                return None;
            }
            match args.next().as_deref() {
                None => Some(Target::Tcp(address)),
                Some("-tls-ca") => {
                    let ca = args.next()?;
                    if ca.is_empty() || args.next().as_deref() != Some("-tls-server-name") {
                        return None;
                    }
                    let name = rustls::pki_types::ServerName::try_from(args.next()?).ok()?;
                    args.next()
                        .is_none()
                        .then_some(Target::Tls(address, ca, name))
                }
                _ => None,
            }
        }
        #[cfg(unix)]
        "-unix"
            if args.next().is_none()
                && value.starts_with('/')
                && value.len() <= 4096
                && !value.contains('\0')
                && value[1..]
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | "..")) =>
        {
            Some(Target::Unix(value))
        }
        _ => None,
    }
}

#[cfg(unix)]
async fn status(path: &str) -> io::Result<()> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    let mut stream = UnixStream::connect(path).await?;
    stream
        .write_all(b"GET /v1/status HTTP/1.1\r\nHost: lanewayd\r\nConnection: close\r\n\r\n")
        .await?;
    let expected = b"HTTP/1.1 200 OK\r\n";
    let mut received = [0; b"HTTP/1.1 200 OK\r\n".len()];
    stream.read_exact(&mut received).await?;
    if &received != expected {
        return Err(io::Error::other("local status API did not return HTTP 200"));
    }
    Ok(())
}

async fn probe(target: Target, deadline: Duration) -> io::Result<()> {
    timeout(deadline, async {
        match target {
            Target::Tcp(address) => TcpStream::connect(address).await.map(drop),
            Target::Tls(address, ca, name) => tls_probe(address, &ca, name).await,
            #[cfg(unix)]
            Target::Unix(path) => status(&path).await,
        }
    })
    .await?
}

async fn tls_probe(
    address: SocketAddrV4,
    ca: &str,
    name: rustls::pki_types::ServerName<'static>,
) -> io::Result<()> {
    use std::{io::Read, sync::Arc};
    let file = std::fs::File::open(ca)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("CA bundle must be a regular file"));
    }
    let mut data = Vec::new();
    file.take(65537).read_to_end(&mut data)?;
    if data.len() > 65536 {
        return Err(io::Error::other("CA bundle too large"));
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(cert?).map_err(io::Error::other)?;
    }
    if roots.is_empty() {
        return Err(io::Error::other("no trust anchors in CA bundle"));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let stream = TcpStream::connect(address).await?;
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .map(drop)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if matches!(
        env::args_os().nth(1).as_deref().and_then(|s| s.to_str()),
        Some("--version" | "-version")
    ) && env::args_os().nth(2).is_none()
    {
        println!(
            "{}",
            option_env!("LANEWAY_PRODUCT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        );
        return ExitCode::SUCCESS;
    }
    let Some(target) = target(env::args().skip(1)) else {
        eprintln!(
            "usage: laneway-healthcheck (-tcp 127.0.0.1:PORT [-tls-ca PATH -tls-server-name NAME] | -unix /absolute/socket)"
        );
        return ExitCode::FAILURE;
    };
    match probe(target, Duration::from_secs(2)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("laneway-healthcheck: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detects_listener_shutdown() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let parsed = || target(["-tcp".into(), address.to_string()].into_iter()).unwrap();
        probe(parsed(), Duration::from_secs(1)).await.unwrap();
        drop(listener);
        assert!(probe(parsed(), Duration::from_secs(1)).await.is_err());
    }

    #[test]
    fn rejects_remote_targets_unclean_paths_and_extra_options() {
        for args in [
            vec!["-tcp", "0.0.0.0:443"],
            vec!["-tcp", "example.com:443"],
            vec!["-tcp", "127.0.0.1:0"],
            vec!["-tcp", "127.0.0.1:443", "-tls-ca", "/test"],
            vec!["-unix", "relative"],
            vec!["-unix", "/run/../tmp/a"],
            vec!["-unix", "/run//a"],
            vec!["-unix", "/run/a/"],
        ] {
            assert!(target(args.into_iter().map(String::from)).is_none());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn checks_http_status_and_times_out_on_a_stalled_socket() {
        use tokio::{
            io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
            net::UnixListener,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let parsed = || target(["-unix".into(), path.display().to_string()].into_iter()).unwrap();
        for (response, ready) in [
            ("HTTP/1.1 200 OK\r\n", true),
            ("HTTP/1.1 503 Busy\r\n", false),
            ("HTTP/1.1 200 OKAY\r\n", false),
        ] {
            let (result, ()) = tokio::join!(probe(parsed(), Duration::from_secs(1)), async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut line = String::new();
                BufReader::new(&mut stream)
                    .read_line(&mut line)
                    .await
                    .unwrap();
                assert_eq!(line, "GET /v1/status HTTP/1.1\r\n");
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            assert_eq!(result.is_ok(), ready);
        }
        assert_eq!(
            probe(parsed(), Duration::from_millis(50))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
