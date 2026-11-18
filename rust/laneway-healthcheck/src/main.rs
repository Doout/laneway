use std::{
    env, io,
    net::{Ipv4Addr, SocketAddrV4},
    process::ExitCode,
    time::Duration,
};
use tokio::{net::TcpStream, time::timeout};

enum Target {
    Tcp(SocketAddrV4),
    #[cfg(unix)]
    Unix(String),
}

fn target(mut args: impl Iterator<Item = String>) -> Option<Target> {
    let flag = args.next()?;
    let value = args.next()?;
    if args.next().is_some() {
        return None;
    }
    match flag.as_str() {
        "-tcp" => {
            let address: SocketAddrV4 = value.parse().ok()?;
            (address.ip() == &Ipv4Addr::LOCALHOST && address.port() != 0)
                .then_some(Target::Tcp(address))
        }
        #[cfg(unix)]
        "-unix"
            if value.starts_with('/')
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
            #[cfg(unix)]
            Target::Unix(path) => status(&path).await,
        }
    })
    .await?
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let Some(target) = target(env::args().skip(1)) else {
        eprintln!("usage: laneway-healthcheck (-tcp 127.0.0.1:PORT | -unix /absolute/socket)");
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
