use std::{
    ffi::OsString,
    fs::{self, File},
    future::Future,
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    net::IpAddr,
    os::{
        fd::OwnedFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::PathBuf,
    pin::Pin,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use lanewayd_rs::{
    RouteConfig, RouteKind, SessionExitPlan, SessionNetwork, SessionNetworkOpener, SessionRoutes,
    TunConfig,
};
use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendFlags, SocketFlags, SocketType, recvmsg, send, socketpair,
    },
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::unix::AsyncFd,
    process::{Child, Command},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};

const VERSION: u8 = 1;
const MAX_MESSAGE: usize = 64 << 10;
const OPERATION: Duration = Duration::from_secs(10);

pub(super) struct Helper {
    executable: PathBuf,
    sudo: String,
}

impl Helper {
    pub(super) fn locate() -> Result<Self> {
        let executable: PathBuf = crate::compat::command(&[OsString::from("_network-helper")])?
            .get_program()
            .into();
        ensure!(
            crate::compat::trusted_executable(&executable),
            "install a protected root-owned Laneway package before starting the Linux network helper"
        );
        crate::compat::verify_linux_network_helper_bridge(&executable)?;
        Ok(Self {
            executable,
            sudo: super::system_tool("sudo")?,
        })
    }
}

impl SessionNetworkOpener for Helper {
    fn open<'a>(
        &'a self,
        config: &'a TunConfig,
        routes: &'a [RouteConfig],
        bypasses: &'a [IpAddr],
    ) -> Pin<Box<dyn Future<Output = Result<SessionNetwork>> + Send + 'a>> {
        Box::pin(self.open_session(config, routes, bypasses))
    }
}

impl Helper {
    async fn open_session(
        &self,
        config: &TunConfig,
        routes: &[RouteConfig],
        bypasses: &[IpAddr],
    ) -> Result<SessionNetwork> {
        ensure!(
            config.addresses.len() <= 8,
            "interface addresses exceed the helper limit"
        );
        let setup = Setup {
            name: &config.name,
            mtu: config.mtu,
            addresses: config.addresses.iter().map(ToString::to_string).collect(),
            routes: RoutePlan::new(routes, bypasses)?,
        };
        let (parent, child) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        fcntl_setfl(&parent, fcntl_getfl(&parent)? | OFlags::NONBLOCK)?;
        let socket = AsyncFd::new(parent)?;
        let child_socket = File::from(child);
        let mut child = Command::new(&self.sudo)
            .arg("--")
            .arg(&self.executable)
            .args(["_network-helper", "--control-fd=0"])
            .stdin(Stdio::from(child_socket.try_clone()?))
            .stdout(Stdio::from(child_socket))
            .stderr(Stdio::inherit())
            .spawn()
            .context("start the installed Linux network helper through sudo")?;
        let exchange = async {
            let (reply, mut rights) =
                exchange(&socket, 1, Operation::Setup(SetupOperation { setup })).await?;
            reply.accepted()?;
            ensure!(
                reply.helper_pid.is_some_and(|pid| pid > 0)
                    && reply.interface_name.as_deref() == Some(config.name.as_str()),
                "network helper returned an unexpected interface or process identity"
            );
            ensure!(
                rights.len() == 1,
                "network helper must return exactly one TUN descriptor"
            );
            let packet = File::from(rights.pop().expect("length checked"));
            let source = fs::metadata("/dev/net/tun")?;
            let returned = packet.metadata()?;
            ensure!(
                returned.file_type().is_char_device() && returned.rdev() == source.rdev(),
                "network helper did not return a Linux TUN device"
            );
            fcntl_setfl(&packet, fcntl_getfl(&packet)? | OFlags::NONBLOCK)?;
            Ok::<_, anyhow::Error>(packet)
        }
        .await;
        let packet = match exchange {
            Ok(packet) => packet,
            Err(error) => {
                drop(socket);
                wait_failed_setup(&mut child).await;
                return Err(error.context("network helper setup"));
            }
        };
        let (stopped, receiver) = watch::channel(false);
        let waiter = tokio::spawn(async move {
            let exit = child.wait().await;
            stopped.send_replace(true);
            exit
        });
        Ok(SessionNetwork {
            packet,
            routes: Box::new(Session {
                socket: Some(socket),
                next: 1,
                stopped: receiver,
                waiter,
                exit: None,
            }),
        })
    }
}

async fn wait_failed_setup(child: &mut Child) {
    if timeout(OPERATION, child.wait()).await.is_err() {
        let _ = child.start_kill();
    }
}

struct Session {
    socket: Option<AsyncFd<OwnedFd>>,
    next: u64,
    stopped: watch::Receiver<bool>,
    waiter: JoinHandle<io::Result<ExitStatus>>,
    exit: Option<SessionExitPlan>,
}

impl Session {
    async fn request(&mut self, operation: Operation<'_>) -> Result<()> {
        self.next = self
            .next
            .checked_add(1)
            .context("network helper request ID exhausted")?;
        let socket = self.socket.as_ref().context("network helper is closed")?;
        let result = exchange(socket, self.next, operation)
            .await
            .and_then(|(reply, rights)| {
                ensure!(
                    rights.is_empty(),
                    "network helper returned unexpected descriptors"
                );
                Ok(reply)
            });
        if result.is_err() {
            drop(self.socket.take());
        }
        result?.accepted()
    }

    async fn reconcile_exit(&mut self, plan: Option<&SessionExitPlan>) -> Result<()> {
        if self.exit.as_ref() == plan {
            return Ok(());
        }
        if let Some(plan) = plan {
            validate_exit_plan(plan)?;
        }
        let previous = self.exit.clone();
        let has_dns = [previous.as_ref(), plan]
            .into_iter()
            .flatten()
            .any(|plan| !plan.dns_servers.is_empty());
        if let Err(error) = self.write_exit(plan, has_dns).await {
            if self.socket.is_none() {
                return Err(error);
            }
            if let Err(rollback) = self.write_exit(previous.as_ref(), has_dns).await {
                drop(self.socket.take());
                return Err(error.context(format!("roll back helper exit policy: {rollback:#}")));
            }
            return Err(error);
        }
        self.exit = plan.cloned();
        Ok(())
    }

    async fn write_exit(&mut self, plan: Option<&SessionExitPlan>, has_dns: bool) -> Result<()> {
        if let Some(plan) = plan {
            self.request(Operation::ApplyExitRoutes(ApplyExitOperation {
                exit_routes: ExitRoutePlan {
                    tunnel_prefixes: &plan.tunnel_prefixes,
                    transport_bypasses: &plan.transport_bypasses,
                    local_lan_bypasses: &plan.local_lan_bypasses,
                },
            }))
            .await?;
            if !plan.dns_servers.is_empty() {
                self.request(Operation::ApplyDns(ApplyDnsOperation {
                    dns: DnsPlan {
                        servers: &plan.dns_servers,
                    },
                }))
                .await?;
            } else if has_dns {
                self.request(Operation::RestoreDns).await?;
            }
        } else {
            // Restore native DNS while tunnel routes still protect the old DNS servers.
            if has_dns {
                self.request(Operation::RestoreDns).await?;
            }
            self.request(Operation::RestoreExitRoutes).await?;
        }
        Ok(())
    }
}

fn validate_exit_plan(plan: &SessionExitPlan) -> Result<()> {
    ensure!(
        !plan.tunnel_prefixes.is_empty()
            && plan.tunnel_prefixes.len() <= 4
            && !plan.transport_bypasses.is_empty()
            && plan.transport_bypasses.len() <= 64
            && plan.local_lan_bypasses.len() <= 64
            && plan.dns_servers.len() <= 8,
        "exit plan exceeds network helper bounds"
    );
    Ok(())
}

impl SessionRoutes for Session {
    fn apply<'a>(
        &'a mut self,
        routes: &'a [RouteConfig],
        bypasses: &'a [IpAddr],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.request(Operation::Apply(ApplyOperation {
                routes: RoutePlan::new(routes, bypasses)?,
            }))
            .await
        })
    }

    fn apply_exit<'a>(
        &'a mut self,
        plan: Option<&'a SessionExitPlan>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(self.reconcile_exit(plan))
    }

    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async {
            let restore = self.reconcile_exit(None).await;
            let acknowledgement = if self.socket.is_some() {
                self.request(Operation::Close).await
            } else {
                Ok(())
            };
            drop(self.socket.take());
            let status = timeout(OPERATION, &mut self.waiter)
                .await
                .context("wait for network helper cleanup")???;
            restore?;
            acknowledgement?;
            ensure!(status.success(), "network helper exited with {status}");
            Ok(())
        })
    }

    fn stopped(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        let mut stopped = self.stopped.clone();
        Box::pin(async move {
            let _ = stopped.wait_for(|stopped| *stopped).await;
            anyhow::bail!("network helper stopped during the session")
        })
    }
}

#[derive(Serialize)]
struct Request<'a> {
    version: u8,
    id: u64,
    #[serde(flatten)]
    operation: Operation<'a>,
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Operation<'a> {
    Setup(SetupOperation<'a>),
    #[serde(rename = "apply-routes")]
    Apply(ApplyOperation),
    ApplyExitRoutes(ApplyExitOperation<'a>),
    RestoreExitRoutes,
    ApplyDns(ApplyDnsOperation<'a>),
    RestoreDns,
    Close,
}

#[derive(Serialize)]
struct ApplyExitOperation<'a> {
    exit_routes: ExitRoutePlan<'a>,
}

#[derive(Serialize)]
struct ExitRoutePlan<'a> {
    tunnel_prefixes: &'a [ipnet::IpNet],
    transport_bypasses: &'a [IpAddr],
    local_lan_bypasses: &'a [ipnet::IpNet],
}

#[derive(Serialize)]
struct ApplyDnsOperation<'a> {
    dns: DnsPlan<'a>,
}

#[derive(Serialize)]
struct DnsPlan<'a> {
    servers: &'a [IpAddr],
}

#[derive(Serialize)]
struct SetupOperation<'a> {
    setup: Setup<'a>,
}

#[derive(Serialize)]
struct ApplyOperation {
    routes: RoutePlan,
}

#[derive(Serialize)]
struct Setup<'a> {
    name: &'a str,
    mtu: u16,
    addresses: Vec<String>,
    routes: RoutePlan,
}

#[derive(Serialize)]
struct RoutePlan {
    routes: Vec<Route>,
    bypasses: Vec<IpAddr>,
}

#[derive(Serialize)]
struct Route {
    prefix: String,
    metric: u32,
}

impl RoutePlan {
    fn new(routes: &[RouteConfig], bypasses: &[IpAddr]) -> Result<Self> {
        ensure!(
            routes.len() <= 1024 && bypasses.len() <= 64,
            "split routes exceed the network helper limit"
        );
        ensure!(
            routes.iter().all(|route| route.kind != RouteKind::Exit),
            "the helper-backed Rust dataplane supports split routes only"
        );
        Ok(Self {
            routes: routes
                .iter()
                .map(|route| Route {
                    prefix: route.prefix.to_string(),
                    metric: route.metric,
                })
                .collect(),
            bypasses: bypasses.to_vec(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u8,
    id: u64,
    ok: bool,
    error: Option<String>,
    helper_pid: Option<u32>,
    interface_name: Option<String>,
}

impl Reply {
    fn accepted(&self) -> Result<()> {
        ensure!(
            self.ok,
            "network helper rejected the request: {}",
            self.error.as_deref().unwrap_or("unknown error")
        );
        Ok(())
    }
}

async fn exchange(
    socket: &AsyncFd<OwnedFd>,
    id: u64,
    operation: Operation<'_>,
) -> Result<(Reply, Vec<OwnedFd>)> {
    timeout(OPERATION, async {
        let payload = serde_json::to_vec(&Request {
            version: VERSION,
            id,
            operation,
        })?;
        ensure!(
            payload.len() <= MAX_MESSAGE,
            "network helper request exceeds the message limit"
        );
        loop {
            let mut ready = socket.writable().await?;
            if let Ok(result) = ready.try_io(|fd| {
                send(fd.get_ref(), &payload, SendFlags::NOSIGNAL).map_err(io::Error::from)
            }) {
                ensure!(
                    result? == payload.len(),
                    "network helper accepted a partial request"
                );
                break;
            }
        }
        let mut bytes = vec![0; MAX_MESSAGE];
        let (size, rights) = loop {
            let mut ready = socket.readable().await?;
            if let Ok(result) = ready.try_io(|fd| receive(fd.get_ref(), &mut bytes)) {
                break result?;
            }
        };
        let reply: Reply =
            serde_json::from_slice(&bytes[..size]).context("decode network helper reply")?;
        ensure!(
            reply.version == VERSION && reply.id == id,
            "network helper returned a mismatched response"
        );
        Ok((reply, rights))
    })
    .await
    .context("network helper operation timed out")?
}

fn receive(socket: &OwnedFd, bytes: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let response = recvmsg(
        socket,
        &mut [IoSliceMut::new(bytes)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    if response.bytes == 0
        || response
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty or truncated network helper reply",
        ));
    }
    let mut rights = Vec::new();
    for item in control.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(descriptors) => rights.extend(descriptors),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected network helper ancillary data",
                ));
            }
        }
    }
    Ok((response.bytes, rights))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::{
        io::{FdFlags, fcntl_getfd},
        net::{SendAncillaryBuffer, SendAncillaryMessage, sendmsg},
    };
    use std::{io::IoSlice, os::fd::AsFd};

    #[test]
    fn request_shapes_match_helper_v1() {
        let plan = RoutePlan {
            routes: vec![Route {
                prefix: "192.0.2.0/24".into(),
                metric: 20,
            }],
            bypasses: Vec::new(),
        };
        let value = serde_json::to_value(Request {
            version: VERSION,
            id: 1,
            operation: Operation::Setup(SetupOperation {
                setup: Setup {
                    name: "lane0",
                    mtu: 1280,
                    addresses: vec!["100.64.0.2/32".into()],
                    routes: plan,
                },
            }),
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "version": 1, "id": 1, "op": "setup", "setup": {
                    "name": "lane0", "mtu": 1280, "addresses": ["100.64.0.2/32"],
                    "routes": {"routes": [{"prefix": "192.0.2.0/24", "metric": 20}], "bypasses": []}
                }
            })
        );
        assert_eq!(
            serde_json::to_value(Request {
                version: VERSION,
                id: 2,
                operation: Operation::Close
            })
            .unwrap(),
            serde_json::json!({"version": 1, "id": 2, "op": "close"})
        );
    }

    #[tokio::test]
    async fn exit_dns_failure_replays_previous_routes_before_previous_dns() {
        let (client, server) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        let (stopped, receiver) = watch::channel(false);
        let mut session = Session {
            socket: Some(AsyncFd::new(client).unwrap()),
            next: 1,
            stopped: receiver,
            waiter: tokio::spawn(std::future::pending()),
            exit: None,
        };
        let server = AsyncFd::new(server).unwrap();
        let operations = [
            ("apply-exit-routes", "transport_bypasses", "192.0.2.1", true),
            ("apply-dns", "servers", "10.23.0.4", true),
            ("apply-exit-routes", "transport_bypasses", "192.0.2.2", true),
            ("apply-dns", "servers", "10.23.0.5", false),
            ("apply-exit-routes", "transport_bypasses", "192.0.2.1", true),
            ("apply-dns", "servers", "10.23.0.4", true),
            ("restore-dns", "", "", true),
            ("restore-exit-routes", "", "", true),
        ];
        let helper = tokio::spawn(async move {
            let _stopped = stopped;
            for (index, (name, field, address, ok)) in operations.into_iter().enumerate() {
                let mut payload = [0; 4096];
                let n = loop {
                    let mut ready = server.readable().await.unwrap();
                    if let Ok(result) = ready.try_io(|fd| receive(fd.get_ref(), &mut payload)) {
                        let (n, rights) = result.unwrap();
                        assert!(rights.is_empty());
                        break n;
                    }
                };
                let message: serde_json::Value = serde_json::from_slice(&payload[..n]).unwrap();
                let id = index + 2;
                assert_eq!(message["id"], id);
                assert_eq!(message["op"], name);
                if !field.is_empty() {
                    let container = if name == "apply-dns" {
                        "dns"
                    } else {
                        "exit_routes"
                    };
                    assert_eq!(message[container][field], serde_json::json!([address]));
                }
                let reply =
                    serde_json::to_vec(&serde_json::json!({"id": id, "version": 1, "ok": ok}))
                        .unwrap();
                send(server.get_ref(), &reply, SendFlags::NOSIGNAL).unwrap();
            }
        });
        let initial = SessionExitPlan {
            tunnel_prefixes: vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()],
            transport_bypasses: vec!["192.0.2.1".parse().unwrap()],
            local_lan_bypasses: Vec::new(),
            dns_servers: vec!["10.23.0.4".parse().unwrap()],
        };
        let mut next = initial.clone();
        next.transport_bypasses = vec!["192.0.2.2".parse().unwrap()];
        next.dns_servers = vec!["10.23.0.5".parse().unwrap()];
        session.reconcile_exit(Some(&initial)).await.unwrap();
        assert!(session.reconcile_exit(Some(&next)).await.is_err());
        assert_eq!(session.exit.as_ref(), Some(&initial));
        session.reconcile_exit(None).await.unwrap();
        assert!(session.exit.is_none());
        helper.await.unwrap();
        session.waiter.abort();
    }

    #[tokio::test]
    #[ignore = "requires an ordinary user, protected sudo helper, TUN and fixture links in an isolated Linux network namespace"]
    async fn exit_route_helper_applies_refreshes_and_restores_kernel_state() {
        fn ip(args: &[&str]) -> String {
            let output = std::process::Command::new("/usr/sbin/ip")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        }

        assert!(!nix::unistd::geteuid().is_root());
        assert!(ip(&["-4", "route", "show", "dev", "lane-fixture"]).contains("192.0.2.0/24"));
        let rule = ["-4", "rule", "show"];
        let before_rules = ip(&rule);
        let before_routes = ip(&["-4", "route", "show", "table", "main"]);
        let helper = Helper::locate().unwrap();
        let mut network = helper
            .open(
                &TunConfig {
                    name: "lane0".into(),
                    mtu: 1280,
                    addresses: vec!["100.64.0.2/32".parse().unwrap()],
                    configure: true,
                },
                &[],
                &[],
            )
            .await
            .unwrap();
        let mut plan = SessionExitPlan {
            tunnel_prefixes: vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()],
            transport_bypasses: vec!["192.0.2.1".parse().unwrap()],
            local_lan_bypasses: Vec::new(),
            dns_servers: Vec::new(),
        };
        network.routes.apply_exit(Some(&plan)).await.unwrap();
        assert!(ip(&rule).contains("lookup 51820"));
        assert!(ip(&["-4", "route", "get", "203.0.113.1"]).contains("dev lane0"));
        assert!(ip(&["-4", "route", "get", "192.0.2.1"]).contains("dev lane-fixture"));
        plan.transport_bypasses = vec!["192.0.2.2".parse().unwrap()];
        network.routes.apply_exit(Some(&plan)).await.unwrap();
        assert!(ip(&["-4", "route", "get", "192.0.2.2"]).contains("dev lane-fixture"));
        network.routes.apply_exit(None).await.unwrap();
        assert_eq!(ip(&rule), before_rules);
        network.routes.apply_exit(Some(&plan)).await.unwrap();
        network.routes.close().await.unwrap();
        drop(network);
        assert_eq!(ip(&rule), before_rules);
        assert_eq!(ip(&["-4", "route", "show", "table", "main"]), before_routes);
        assert!(!std::path::Path::new("/sys/class/net/lane0").exists());
    }

    #[test]
    fn seqpacket_delivers_cloexec_descriptors_and_rejects_truncation() {
        let (sender, receiver) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let file = File::open("/dev/null").unwrap();
        let fds = [file.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        sendmsg(
            &sender,
            &[IoSlice::new(b"reply")],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        let mut data = [0; 16];
        let (size, rights) = receive(&receiver, &mut data).unwrap();
        assert_eq!(&data[..size], b"reply");
        assert_eq!(rights.len(), 1);
        assert!(fcntl_getfd(&rights[0]).unwrap().contains(FdFlags::CLOEXEC));
        send(&sender, &[0; 17], SendFlags::NOSIGNAL).unwrap();
        assert!(receive(&receiver, &mut data).is_err());
    }
}
