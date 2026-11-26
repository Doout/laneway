use std::{
    future::Future,
    io,
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
            Target::Tls(address, ca, name) => tls_probe(address, ca, name).await,
            #[cfg(unix)]
            Target::Unix(path) => status(&path).await,
        }
    })
    .await?
}

fn load_ca(ca: &str) -> io::Result<rustls::RootCertStore> {
    use std::{fs::OpenOptions, io::Read};

    const MAX_CA_BYTES: usize = 65536;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // Check the opened descriptor without getting stuck opening a FIFO.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(ca)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("CA bundle must be a regular file"));
    }
    let mut data = Vec::new();
    file.take(MAX_CA_BYTES as u64 + 1).read_to_end(&mut data)?;
    if data.len() > MAX_CA_BYTES {
        return Err(io::Error::other("CA bundle too large"));
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut data.as_slice()) {
        roots.add(cert?).map_err(io::Error::other)?;
    }
    if roots.is_empty() {
        return Err(io::Error::other("no trust anchors in CA bundle"));
    }
    Ok(roots)
}

async fn tls_probe(
    address: SocketAddrV4,
    ca: String,
    name: rustls::pki_types::ServerName<'static>,
) -> io::Result<()> {
    use std::sync::Arc;

    let roots = tokio::task::spawn_blocking(move || load_ca(&ca))
        .await
        .map_err(io::Error::other)??;
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

fn run_probe(probe: impl Future<Output = io::Result<()>>) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(probe);
    // A filesystem syscall can outlive the probe deadline. The standalone
    // healthcheck must return to main without waiting for the blocking pool.
    runtime.shutdown_background();
    result
}

pub fn run(command: &str, args: impl Iterator<Item = String>) -> ExitCode {
    let Some(target) = target(args) else {
        eprintln!(
            "usage: {command} (-tcp 127.0.0.1:PORT [-tls-ca PATH -tls-server-name NAME] | -unix /absolute/socket)"
        );
        return ExitCode::FAILURE;
    };
    match run_probe(probe(target, Duration::from_secs(2))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{command}: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detects_whether_the_socket_is_listening() {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let address = socket.local_addr().unwrap();
        let parsed = || target(["-tcp".into(), address.to_string()].into_iter()).unwrap();

        // Keep the port reserved throughout the test so another socket cannot
        // take it between the readiness checks.
        assert!(probe(parsed(), Duration::from_millis(100)).await.is_err());
        let _listener = socket.listen(1).unwrap();
        probe(parsed(), Duration::from_secs(1)).await.unwrap();
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

    #[test]
    fn timed_out_probe_does_not_wait_for_a_running_blocking_task() {
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let result = run_probe(async {
            let worker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                // Bound cleanup even if runtime shutdown regresses.
                let _ = blocked.recv_timeout(Duration::from_secs(3));
            });
            running.await.unwrap();
            timeout(Duration::from_millis(25), worker)
                .await?
                .map_err(io::Error::other)
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        release
            .send(())
            .expect("probe waited for its blocking task");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unopened_ca_fifo_without_waiting_for_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("ca.pem");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let parsed = target(
            [
                "-tcp",
                "127.0.0.1:1",
                "-tls-ca",
                fifo.to_str().unwrap(),
                "-tls-server-name",
                "localhost",
            ]
            .into_iter()
            .map(String::from),
        )
        .unwrap();
        let error = run_probe(probe(parsed, Duration::from_secs(2))).unwrap_err();
        assert_eq!(error.to_string(), "CA bundle must be a regular file");
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
