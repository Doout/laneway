//! Root-side service. Only typed interface and split-route operations are exposed.
mod routes;

use std::{
    collections::BTreeSet,
    mem,
    net::IpAddr,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;

use super::{Frame, Reply, RoutePlan, Setup, TIMEOUT, read_frame, send_reply};
use crate::tun::darwin::{
    control_id, cvt, darwin_control_socket, numbered_utun, utun_name, verify_utun,
};
use routes::{Routes, run};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    id: u64,
    op: String,
    setup: Option<Setup>,
    routes: Option<RoutePlan>,
}

struct NetworkSetup {
    unit: u32,
    mtu: u16,
    addresses: BTreeSet<IpNet>,
    routes: BTreeSet<IpNet>,
}

impl NetworkSetup {
    fn validate(setup: Setup) -> Result<Self> {
        let unit = if setup.name == "utun" {
            0
        } else {
            ensure!(numbered_utun(&setup.name), "invalid utun name");
            let index = setup.name[4..].parse::<u32>()?;
            ensure!(
                setup.name == format!("utun{index}") && index < 1024,
                "invalid utun unit"
            );
            index + 1
        };
        ensure!((576..=1280).contains(&setup.mtu), "invalid tunnel MTU");
        ensure!(
            (1..=8).contains(&setup.addresses.len()),
            "invalid tunnel address count"
        );
        let mut addresses = BTreeSet::new();
        for raw in setup.addresses {
            let address = raw.parse::<IpNet>()?;
            ensure!(
                IpNet::from(address.addr()) == address && routes::routable(address),
                "invalid tunnel host address"
            );
            ensure!(
                address.addr().is_ipv4() || setup.mtu >= 1280,
                "IPv6 requires a 1280 MTU"
            );
            ensure!(addresses.insert(address), "duplicate tunnel host address");
        }
        Ok(Self {
            unit,
            mtu: setup.mtu,
            addresses,
            routes: routes::validate(setup.routes)?,
        })
    }
}

pub(crate) fn serve_inherited() -> Result<()> {
    let socket = inherited_socket()?;
    serve(socket, NativeNetwork::open)
}

fn inherited_socket() -> Result<UnixStream> {
    let original = libc::STDIN_FILENO;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "macOS network helper requires root"
    );
    inspect_socket(original)?;
    // SAFETY: each call uses an exact libc scalar or a correctly sized OS
    // structure. Only descriptors in this process are queried or modified.
    unsafe {
        if libc::setpgid(0, 0) != 0 {
            let error = std::io::Error::last_os_error();
            ensure!(
                libc::getpgrp() == libc::getpid(),
                "isolate privileged helper process: {error}"
            );
        }
        let fd = cvt(libc::fcntl(original, libc::F_DUPFD_CLOEXEC, 3))?;
        Ok(UnixStream::from(OwnedFd::from_raw_fd(fd)))
    }
}

fn inspect_socket(fd: libc::c_int) -> Result<()> {
    // SAFETY: live output buffer is exactly the length passed to getpeername.
    let mut peer: libc::sockaddr_un = unsafe { mem::zeroed() };
    let mut size = mem::size_of_val(&peer) as libc::socklen_t;
    cvt(unsafe { libc::getpeername(fd, (&mut peer as *mut libc::sockaddr_un).cast(), &mut size) })
        .context("inspect inherited network helper socket")?;
    ensure!(
        i32::from(peer.sun_family) == libc::AF_UNIX,
        "helper requires an inherited Unix socket"
    );
    ensure!(
        socket_value(fd, libc::SOL_SOCKET, libc::SO_TYPE)? == libc::SOCK_STREAM,
        "helper requires an inherited stream socket"
    );
    ensure!(
        socket_value(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID)? > 0,
        "network helper peer lacks a process identity"
    );
    Ok(())
}

fn socket_value(fd: libc::c_int, level: libc::c_int, option: libc::c_int) -> Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut size = mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: the kernel writes only the declared integer buffer size.
    cvt(unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut size,
        )
    })?;
    ensure!(
        size as usize == mem::size_of_val(&value),
        "unexpected network helper socket option length"
    );
    Ok(value)
}

fn receive(socket: &mut UnixStream, last: u64) -> Result<Option<Request>> {
    let Some(Frame(bytes, rights)) = read_frame(socket)? else {
        return Ok(None);
    };
    ensure!(
        rights.is_empty(),
        "the network helper never accepts file descriptors"
    );
    let request: Request =
        serde_json::from_slice(&bytes).context("decode network helper request")?;
    ensure!(
        request.version == 1 && request.id > last,
        "invalid or replayed network helper request"
    );
    Ok(Some(request))
}

fn send(
    socket: &mut UnixStream,
    id: u64,
    result: Result<()>,
    network: Option<(&str, &OwnedFd)>,
) -> Result<()> {
    send_reply(
        socket,
        &Reply {
            version: 1,
            id,
            ok: result.is_ok(),
            error: result.err().map(|error| error.to_string()),
            helper_pid: network.map(|_| std::process::id() as i32),
            interface_name: network.map(|(name, _)| name.to_owned()),
        },
        network.map(|(_, fd)| fd),
    )
}

trait Network {
    fn device(&self) -> (&str, &OwnedFd);
    fn replace(&mut self, routes: BTreeSet<IpNet>) -> Result<()>;
    fn clear(&mut self) -> Result<()>;
}

fn serve<N: Network>(
    mut socket: UnixStream,
    open: impl FnOnce(NetworkSetup) -> Result<N>,
) -> Result<()> {
    socket.set_write_timeout(Some(TIMEOUT))?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    let first = receive(&mut socket, 0)?.context("helper setup was not received")?;
    let setup = match (first.op.as_str(), first.setup, first.routes) {
        ("setup", Some(setup), None) => NetworkSetup::validate(setup),
        _ => Err(anyhow::anyhow!("first helper operation must be setup")),
    };
    let mut network = match setup.and_then(open) {
        Ok(network) => network,
        Err(error) => {
            send(
                &mut socket,
                first.id,
                Err(anyhow::anyhow!("{error:#}")),
                None,
            )?;
            return Err(error);
        }
    };
    let result = (|| {
        send(&mut socket, first.id, Ok(()), Some(network.device()))?;
        socket.set_read_timeout(None)?;
        let mut last = first.id;
        while let Some(request) = receive(&mut socket, last)? {
            last = request.id;
            let result = match (request.op.as_str(), request.setup, request.routes) {
                ("apply-routes", None, Some(routes)) => {
                    routes::validate(routes).and_then(|routes| network.replace(routes))
                }
                ("close", None, None) => return Ok(Some(last)),
                _ => Err(anyhow::anyhow!(
                    "unsupported or malformed network helper operation"
                )),
            };
            if let Err(error) = result {
                send(&mut socket, last, Err(anyhow::anyhow!("{error:#}")), None)?;
                return Err(error);
            }
            send(&mut socket, last, Ok(()), None)?;
        }
        Ok(None)
    })();
    match (result, network.clear()) {
        (Ok(Some(id)), Ok(())) => send(&mut socket, id, Ok(()), None),
        (Ok(Some(id)), Err(error)) => {
            send(&mut socket, id, Err(anyhow::anyhow!("{error:#}")), None)?;
            Err(error)
        }
        (Ok(None), cleanup) => cleanup,
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("could not restore owned macOS routes: {cleanup:#}")))
        }
    }
}

struct NativeNetwork {
    routes: Routes,
    fd: OwnedFd,
}

impl NativeNetwork {
    fn open(setup: NetworkSetup) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(8);
        let fd = darwin_control_socket(libc::AF_SYSTEM, libc::SYSPROTO_CONTROL)?;
        let id = control_id(&fd)?;
        let address = libc::sockaddr_ctl {
            sc_len: mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: id,
            sc_unit: setup.unit,
            sc_reserved: [0; 5],
        };
        // SAFETY: the fixed Darwin control address lives for the call.
        cvt(unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ctl).cast(),
                mem::size_of_val(&address) as _,
            )
        })
        .context("open kernel utun interface")?;
        let name = utun_name(&fd)?;
        let mtu = setup.mtu.to_string();
        run("/sbin/ifconfig", &[&name, "mtu", &mtu, "up"], deadline)?
            .success("configure utun MTU")?;
        for address in setup.addresses {
            let ip = address.addr().to_string();
            let args = match address.addr() {
                IpAddr::V4(_) => vec![
                    name.as_str(),
                    "inet",
                    &ip,
                    &ip,
                    "netmask",
                    "255.255.255.255",
                    "alias",
                ],
                IpAddr::V6(_) => vec![name.as_str(), "inet6", &ip, "prefixlen", "128", "alias"],
            };
            run("/sbin/ifconfig", &args, deadline)?.success("assign utun address")?;
        }
        verify_utun(&fd, &name, setup.mtu)?;
        let mut network = Self {
            routes: Routes::new(name),
            fd,
        };
        let result = network.routes.replace(setup.routes, deadline);
        if let Err(error) = result {
            return Err(match network.clear() {
                Ok(()) => error,
                Err(cleanup) => error.context(format!("failed to restore routes: {cleanup:#}")),
            });
        }
        Ok(network)
    }
}

impl Network for NativeNetwork {
    fn device(&self) -> (&str, &OwnedFd) {
        (self.routes.name(), &self.fd)
    }
    fn replace(&mut self, routes: BTreeSet<IpNet>) -> Result<()> {
        self.routes
            .replace(routes, Instant::now() + Duration::from_secs(8))
    }
    fn clear(&mut self) -> Result<()> {
        self.routes.clear(Instant::now() + Duration::from_secs(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::darwin::helper::{Route, Session};
    use std::{
        os::unix::net::UnixDatagram,
        sync::{Arc, Mutex},
    };

    struct FakeNetwork {
        fd: OwnedFd,
        active: Arc<Mutex<BTreeSet<IpNet>>>,
    }

    impl Network for FakeNetwork {
        fn device(&self) -> (&str, &OwnedFd) {
            ("utun123", &self.fd)
        }
        fn replace(&mut self, routes: BTreeSet<IpNet>) -> Result<()> {
            *self.active.lock().unwrap() = routes;
            Ok(())
        }
        fn clear(&mut self) -> Result<()> {
            self.active.lock().unwrap().clear();
            Ok(())
        }
    }

    fn plan(prefix: &str) -> RoutePlan {
        RoutePlan {
            routes: vec![Route {
                prefix: prefix.into(),
                metric: 100,
            }],
            bypasses: vec![],
        }
    }

    fn setup() -> Setup {
        Setup {
            name: "utun".into(),
            mtu: 1280,
            addresses: vec!["100.96.0.1/32".into()],
            routes: plan("10.1.0.0/16"),
        }
    }

    #[test]
    fn authenticated_peer_check_accepts_real_socketpairs_only() -> Result<()> {
        let (ancillary, _) = UnixDatagram::pair()?;
        assert!(inspect_socket(ancillary.as_raw_fd()).is_err());
        let (socket, _peer) = UnixStream::pair()?;
        inspect_socket(socket.as_raw_fd())?;
        let unrelated = tempfile::tempfile()?;
        assert!(inspect_socket(unrelated.as_raw_fd()).is_err());
        Ok(())
    }

    #[test]
    fn service_transfers_descriptor_and_restores_on_close_or_eof() -> Result<()> {
        for clean_close in [true, false] {
            let (client, helper) = UnixStream::pair()?;
            client.set_read_timeout(Some(Duration::from_secs(2)))?;
            let (packet, peer) = UnixDatagram::pair()?;
            let active = Arc::new(Mutex::new(BTreeSet::new()));
            let routes = Arc::clone(&active);
            let handle = std::thread::spawn(move || {
                serve(helper, |setup| {
                    *routes.lock().unwrap() = setup.routes;
                    Ok(FakeNetwork {
                        fd: packet.into(),
                        active: routes,
                    })
                })
            });
            let mut session = Session {
                socket: client,
                child: None,
                last_id: 0,
            };
            let (name, descriptor) = session.setup(&setup())?;
            assert_eq!(name, "utun123");
            let datagram = UnixDatagram::from(descriptor);
            datagram.set_read_timeout(Some(Duration::from_secs(2)))?;
            peer.send(b"descriptor transfer")?;
            let mut bytes = [0; 32];
            let n = datagram.recv(&mut bytes)?;
            assert_eq!(&bytes[..n], b"descriptor transfer");
            assert!(active.lock().unwrap().contains(&"10.1.0.0/16".parse()?));
            session.replace_routes(&plan("10.2.0.0/16"))?;
            assert_eq!(
                *active.lock().unwrap(),
                BTreeSet::from(["10.2.0.0/16".parse()?])
            );
            if clean_close {
                session.close()?;
                assert!(active.lock().unwrap().is_empty());
            } else {
                drop(session);
            }
            handle.join().unwrap()?;
            assert!(active.lock().unwrap().is_empty());
        }
        Ok(())
    }

    #[test]
    fn invalid_operation_closes_session_and_withdraws_routes() -> Result<()> {
        let (client, helper) = UnixStream::pair()?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let (packet, _peer) = UnixDatagram::pair()?;
        let active = Arc::new(Mutex::new(BTreeSet::new()));
        let routes = Arc::clone(&active);
        let handle = std::thread::spawn(move || {
            serve(helper, |setup| {
                *routes.lock().unwrap() = setup.routes;
                Ok(FakeNetwork {
                    fd: packet.into(),
                    active: routes,
                })
            })
        });
        let mut session = Session {
            socket: client,
            child: None,
            last_id: 0,
        };
        let _ = session.setup(&setup())?;
        assert!(session.replace_routes(&plan("0.0.0.0/0")).is_err());
        assert!(handle.join().unwrap().is_err());
        assert!(active.lock().unwrap().is_empty());
        Ok(())
    }
}
