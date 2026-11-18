use std::{
    convert::Infallible,
    fs::{self, Permissions},
    future::Future,
    io::{self, ErrorKind},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

use crate::{Backend, Driver, Error, Reply, Result, conflict};

/// Reserve the socket before mutating host state. Serve requests only after
/// the driver has reconciled all recorded networks.
pub async fn serve_until<B: Backend + 'static>(
    path: &Path,
    driver: Arc<Driver<B>>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let listener = open_socket(path).await?;
    let info = fs::symlink_metadata(path)?;
    let _socket = SocketGuard {
        path: path.into(),
        device: info.dev(),
        inode: info.ino(),
    };
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    let reconcile = Arc::clone(&driver);
    tokio::task::spawn_blocking(move || reconcile.reconcile())
        .await
        .map_err(worker_error)??;
    fs::set_permissions(path, Permissions::from_mode(0o660))?;
    let permits = Arc::new(Semaphore::new(32));
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {},
            next = listener.accept() => {
                let (stream, _) = next?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue; };
                let driver = Arc::clone(&driver);
                connections.spawn(async move {
                    let _permit = permit;
                    let service = service_fn(move |request| http_request(Arc::clone(&driver), request));
                    let connection = http1::Builder::new()
                        .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5))
                        .max_headers(32).max_buf_size(32 << 10)
                        .serve_connection(TokioIo::new(stream), service);
                    let _ = timeout(Duration::from_secs(30), connection).await;
                });
            }
        }
    }
    drop(listener);
    if timeout(Duration::from_secs(10), async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
    }
    Ok(())
}

async fn http_request<B: Backend + 'static>(
    driver: Arc<Driver<B>>,
    request: Request<Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let reply = match timeout(
        Duration::from_secs(10),
        Limited::new(body, 1 << 20).collect(),
    )
    .await
    {
        Ok(Ok(body)) => match tokio::task::spawn_blocking(move || {
            driver.handle(parts.method.as_str(), parts.uri.path(), &body.to_bytes())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Reply {
                status: 500,
                body: json!({"Err":"Docker driver worker failed"}),
            },
        },
        Ok(Err(_)) => Reply {
            status: 400,
            body: json!({"Err":"invalid or oversized Docker request body"}),
        },
        Err(_) => Reply {
            status: 408,
            body: json!({"Err":"timed out reading Docker request body"}),
        },
    };
    let mut body = serde_json::to_vec(&reply.body).expect("JSON value is serializable");
    body.push(b'\n');
    Ok(Response::builder()
        .status(reply.status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("valid Docker HTTP response"))
}

fn worker_error(error: tokio::task::JoinError) -> Error {
    Error::Backend(format!("Docker worker failed: {error}"))
}

async fn open_socket(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(parent)?;
    let directory = fs::symlink_metadata(parent)?;
    let owner = unsafe { libc::geteuid() };
    if !directory.is_dir() || directory.uid() != owner || directory.mode() & 0o022 != 0 {
        return Err(conflict(
            "Docker socket directory must be protected and owned by the plugin",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(prior) if prior.file_type().is_socket() && prior.uid() == owner => {
            match timeout(Duration::from_secs(1), UnixStream::connect(path)).await {
                Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => (),
                _ => {
                    return Err(conflict(
                        "Docker plugin socket is live or cannot be inspected",
                    ));
                }
            }
            let current = fs::symlink_metadata(path)?;
            if prior.dev() != current.dev() || prior.ino() != current.ino() {
                return Err(conflict("Docker socket changed during restart"));
            }
            fs::remove_file(path)?;
        }
        Ok(_) => return Err(conflict("refusing to replace an unowned socket path")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(UnixListener::bind(path)?)
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|info| {
            info.file_type().is_socket() && info.dev() == self.device && info.ino() == self.inode
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
