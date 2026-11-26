use std::{
    collections::BTreeSet,
    ffi::CStr,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    net::IpAddr,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use rustix::io::{FdFlags, fcntl_setfd};

use super::{Backend, Change, RoutePlan, Session, Setup, security::syscall};

/// Runs the Darwin helper using an inherited private Unix stream.
pub fn serve_darwin(control: OwnedFd) -> Result<()> {
    ensure!(crate::is_root(), "network helper requires root");
    super::serve_inherited(control, Darwin)
}

struct Darwin;

impl Backend for Darwin {
    type Session = DarwinSession;

    fn setup(self, request: Setup, deadline: Instant) -> Result<Self::Session> {
        let (packet, name) = open_utun(&request.name)?;
        let mut session: DarwinSession = DarwinSession {
            packet,
            routes: Routes {
                name,
                owned: BTreeSet::new(),
                command: run_command,
            },
        };
        let name = &session.routes.name;
        checked_command(
            "/sbin/ifconfig",
            &[name, "mtu", &request.mtu.to_string()],
            deadline,
        )?;
        for address in request.addresses {
            let ip = address.addr().to_string();
            let args = if address.addr().is_ipv4() {
                vec![
                    name.as_str(),
                    "inet",
                    &ip,
                    &ip,
                    "netmask",
                    "255.255.255.255",
                    "up",
                ]
            } else {
                vec![name.as_str(), "inet6", &ip, "prefixlen", "128", "up"]
            };
            checked_command("/sbin/ifconfig", &args, deadline)?;
        }
        if let Err(error) = session.routes.apply(request.routes, deadline) {
            let cleanup = session.restore(super::operation_deadline());
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => error.context(format!("restore partial setup: {cleanup:#}")),
            });
        }
        Ok(session)
    }
}

type HostCommand = fn(&str, &[&str], Instant) -> Result<CommandOutput>;

struct DarwinSession {
    packet: OwnedFd,
    routes: Routes<HostCommand>,
}

impl Session for DarwinSession {
    fn packet(&self) -> BorrowedFd<'_> {
        self.packet.as_fd()
    }

    fn interface(&self) -> &str {
        &self.routes.name
    }

    fn apply(&mut self, change: Change, deadline: Instant) -> Result<()> {
        match change {
            Change::Routes(plan) => self.routes.apply(plan, deadline),
            Change::Exit(_) | Change::Dns(_) => bail!("macOS exit routes and DNS are unsupported"),
            Change::RestoreExit | Change::RestoreDns => Ok(()),
        }
    }

    fn restore(mut self, deadline: Instant) -> Result<()> {
        // Route commands require the interface to stay alive. Dropping the
        // final utun fd also removes its kernel-owned interface and routes.
        self.routes.restore(deadline)
    }
}

fn utun_unit(name: &str) -> Option<u32> {
    let unit = name.strip_prefix("utun")?.parse::<u32>().ok()?;
    (format!("utun{unit}") == name).then_some(unit)
}

fn open_utun(requested: &str) -> Result<(OwnedFd, String)> {
    let unit = match requested {
        "lane0" | "utun" => 0,
        name => utun_unit(name)
            .and_then(|unit| unit.checked_add(1))
            .context("macOS helper requires a utun interface name")?,
    };
    // SAFETY: socket takes only value arguments. Ownership transfers to
    // OwnedFd after verifying the result.
    let raw = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    syscall(raw).context("open utun system control socket")?;
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
    // SAFETY: ctl_info is a C struct of integer fields and accepts zeroes.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (field, byte) in info
        .ctl_name
        .iter_mut()
        .zip(c"com.apple.net.utun_control".to_bytes_with_nul())
    {
        *field = *byte as libc::c_char;
    }
    // SAFETY: CTLIOCGINFO reads the C name and fills ctl_id.
    syscall(unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) })
        .context("look up utun system control")?;
    let address = libc::sockaddr_ctl {
        sc_len: size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: info.ctl_id,
        sc_unit: unit,
        sc_reserved: [0; 5],
    };
    // SAFETY: connect receives a valid sockaddr_ctl and its exact length.
    syscall(unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            address.sc_len.into(),
        )
    })
    .context("create utun interface")?;

    const UTUN_OPT_IFNAME: libc::c_int = 2;
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    // SAFETY: getsockopt receives a writable ifname buffer of the given length.
    syscall(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    })
    .context("read assigned utun interface name")?;
    let name =
        CStr::from_bytes_until_nul(name.get(..length as usize).context("oversized utun name")?)?
            .to_str()?
            .to_owned();
    let assigned = utun_unit(&name).context("kernel returned an invalid utun interface name")?;
    ensure!(
        unit == 0 || assigned.checked_add(1) == Some(unit),
        "kernel assigned a different utun interface"
    );
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    rustix::fs::fcntl_setfl(&fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    Ok((fd, name))
}

struct Routes<R> {
    name: String,
    owned: BTreeSet<IpNet>,
    command: R,
}

impl<R: FnMut(&str, &[&str], Instant) -> Result<CommandOutput>> Routes<R> {
    fn apply(&mut self, plan: RoutePlan, deadline: Instant) -> Result<()> {
        let previous = self.owned.clone();
        let desired = plan.routes.into_iter().map(|route| route.prefix).collect();
        match self.reconcile(&desired, deadline) {
            Ok(()) => Ok(()),
            Err(error) => super::combine(
                Err(error),
                self.rollback(&previous, super::operation_deadline()),
            ),
        }
    }

    fn route(&mut self, verb: &str, prefix: IpNet, deadline: Instant) -> Result<CommandOutput> {
        let family = if prefix.addr().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        let address = prefix.to_string();
        let mut args = vec!["-n", verb, family, "-net", &address];
        if verb != "get" {
            args.extend(["-interface", &self.name]);
        }
        (self.command)("/sbin/route", &args, deadline)
    }

    fn lookup(&mut self, prefix: IpNet, deadline: Instant) -> Result<Option<String>> {
        let output = self.route("get", prefix, deadline)?;
        if !output.success && output.text.to_ascii_lowercase().contains("not in table") {
            return Ok(None);
        }
        let output = output.checked("look up macOS route")?;
        if !route_matches(&output, prefix) {
            return Ok(None);
        }
        route_field(&output, "interface:")
            .map(str::to_owned)
            .context("exact route has no interface")
            .map(Some)
    }

    fn remove(&mut self, prefix: IpNet, deadline: Instant) -> Result<()> {
        if let Some(interface) = self.lookup(prefix, deadline)? {
            ensure!(
                interface == self.name,
                "route {prefix} no longer belongs to {}",
                self.name
            );
            self.route("delete", prefix, deadline)?
                .checked("delete owned macOS route")?;
        }
        self.owned.remove(&prefix);
        Ok(())
    }

    fn add(&mut self, prefix: IpNet, deadline: Instant) -> Result<()> {
        ensure!(
            self.lookup(prefix, deadline)?.is_none(),
            "route {prefix} already exists"
        );
        self.route("add", prefix, deadline)?
            .checked("add macOS route")?;
        self.owned.insert(prefix);
        Ok(())
    }

    fn restore(&mut self, deadline: Instant) -> Result<()> {
        self.rollback(&BTreeSet::new(), deadline)
    }

    fn rollback(&mut self, previous: &BTreeSet<IpNet>, deadline: Instant) -> Result<()> {
        let mut result = Ok(());
        for prefix in self.owned.difference(previous).copied().collect::<Vec<_>>() {
            result = super::combine(result, self.remove(prefix, deadline));
        }
        for prefix in previous
            .difference(&self.owned)
            .copied()
            .collect::<Vec<_>>()
        {
            result = super::combine(result, self.add(prefix, deadline));
        }
        result
    }

    fn reconcile(&mut self, desired: &BTreeSet<IpNet>, deadline: Instant) -> Result<()> {
        for prefix in self.owned.difference(desired).copied().collect::<Vec<_>>() {
            self.remove(prefix, deadline)?;
        }
        for prefix in desired.difference(&self.owned).copied().collect::<Vec<_>>() {
            self.add(prefix, deadline)?;
        }
        Ok(())
    }
}

fn route_field<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix(key))
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn route_matches(output: &str, prefix: IpNet) -> bool {
    let Some(destination) = route_field(output, "destination:") else {
        return false;
    };
    if let Ok(network) = destination.parse::<IpNet>() {
        return network.trunc() == prefix;
    }
    if destination.parse::<IpAddr>() != Ok(prefix.addr()) {
        return false;
    }
    let mask = route_field(output, "mask:").or_else(|| route_field(output, "netmask:"));
    match (prefix, mask) {
        (IpNet::V4(net), Some(mask)) => mask.parse().ok() == Some(net.netmask()),
        (IpNet::V6(net), Some(mask)) => mask.parse().ok() == Some(net.netmask()),
        (prefix, None) => prefix.prefix_len() == prefix.max_prefix_len(),
    }
}

struct CommandOutput {
    success: bool,
    text: String,
}

impl CommandOutput {
    fn checked(self, operation: &str) -> Result<String> {
        ensure!(self.success, "{operation}: {}", self.text.trim());
        Ok(self.text)
    }
}

fn checked_command(program: &str, args: &[&str], deadline: Instant) -> Result<()> {
    run_command(program, args, deadline)?.checked(program)?;
    Ok(())
}

fn run_command(program: &str, args: &[&str], deadline: Instant) -> Result<CommandOutput> {
    ensure!(
        Instant::now() < deadline,
        "macOS network operation timed out"
    );
    let mut output = tempfile::tempfile_in("/private/tmp")?;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?)
        .spawn()
        .with_context(|| format!("start {program}"))?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                result?;
                bail!("macOS network operation timed out");
            }
        }
    };
    output.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    output.take(8193).read_to_end(&mut data)?;
    ensure!(
        data.len() <= 8192,
        "macOS network command output exceeds limit"
    );
    Ok(CommandOutput {
        success: status.success(),
        text: String::from_utf8_lossy(&data).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        io::{IoSliceMut, Read, Write},
        mem::MaybeUninit,
        os::unix::net::{UnixDatagram, UnixStream},
        sync::{Arc, Mutex},
    };

    #[test]
    fn rollback_and_cleanup_preserve_foreign_routes() {
        let first: IpNet = "198.18.1.0/24".parse().unwrap();
        let next: IpNet = "198.18.2.0/24".parse().unwrap();
        let foreign: IpNet = "198.18.3.0/24".parse().unwrap();
        let table = RefCell::new(BTreeMap::from([(foreign, "en0".to_string())]));
        let mut routes = Routes {
            name: "utun19".into(),
            owned: BTreeSet::new(),
            command: |program: &str, args: &[&str], _: Instant| {
                assert_eq!(program, "/sbin/route");
                assert_eq!(&args[2..4], &["-inet", "-net"]);
                let prefix = args[4].parse::<IpNet>()?;
                let mut table = table.borrow_mut();
                let mut result = CommandOutput {
                    success: true,
                    text: String::new(),
                };
                match args[1] {
                    "get" => {
                        if let Some(interface) = table.get(&prefix) {
                            result.text =
                                format!("destination: {prefix}\ninterface: {interface}\n");
                        } else {
                            result.success = false;
                            result.text = "route: writing to routing socket: not in table".into();
                        }
                    }
                    "add" => {
                        assert_eq!(table.insert(prefix, args[6].into()), None);
                    }
                    "delete" => {
                        assert_eq!(table.remove(&prefix).as_deref(), Some(args[6]));
                    }
                    other => panic!("unexpected route operation {other}"),
                }
                Ok(result)
            },
        };
        let plan = |prefixes: &[IpNet]| RoutePlan {
            routes: prefixes
                .iter()
                .map(|&prefix| super::super::wire::Route { prefix, metric: 0 })
                .collect(),
            transport_bypasses: vec![],
        };
        let deadline = super::super::operation_deadline();
        routes.apply(plan(&[first]), deadline).unwrap();
        assert!(routes.apply(plan(&[next, foreign]), deadline).is_err());
        assert_eq!(
            *table.borrow(),
            BTreeMap::from([(first, "utun19".into()), (foreign, "en0".into())])
        );
        routes.apply(plan(&[first, next]), deadline).unwrap();

        table.borrow_mut().insert(first, "en1".into());
        assert!(routes.restore(deadline).is_err());
        assert_eq!(
            *table.borrow(),
            BTreeMap::from([(first, "en1".into()), (foreign, "en0".into())])
        );
    }

    #[test]
    fn exact_route_parsing_checks_ipv4_and_ipv6_masks() {
        assert!(route_matches(
            "destination: 198.18.1.0\nmask: 255.255.255.0",
            "198.18.1.0/24".parse().unwrap()
        ));
        assert!(!route_matches(
            "destination: 198.18.1.0\nmask: 255.255.0.0",
            "198.18.1.0/24".parse().unwrap()
        ));
        assert!(route_matches(
            "destination: fd42::\nmask: ffff:ffff:ffff:ffff::",
            "fd42::/64".parse().unwrap()
        ));
        assert!(route_matches(
            "destination: 198.18.1.12",
            "198.18.1.12/32".parse().unwrap()
        ));
        assert!(!route_matches(
            "destination: default\nmask: default",
            "198.18.1.0/24".parse().unwrap()
        ));
    }

    struct Fake(UnixDatagram, Arc<Mutex<Vec<&'static str>>>);

    impl Backend for Fake {
        type Session = Self;
        fn setup(self, request: Setup, _: Instant) -> Result<Self> {
            assert_eq!(request.addresses, vec!["100.64.7.9/32".parse().unwrap()]);
            self.1.lock().unwrap().push("setup");
            Ok(self)
        }
    }

    impl Session for Fake {
        fn packet(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
        fn interface(&self) -> &str {
            "utun19"
        }
        fn apply(&mut self, change: Change, _: Instant) -> Result<()> {
            assert!(matches!(change, Change::Routes(_)));
            self.1.lock().unwrap().push("routes");
            Ok(())
        }
        fn restore(self, _: Instant) -> Result<()> {
            self.1.lock().unwrap().push("restore");
            Ok(())
        }
    }

    #[test]
    fn private_stream_transfers_packet_fd_and_restores_on_close_or_eof() {
        for close in [true, false] {
            let (control, inherited) = UnixStream::pair().unwrap();
            let (packet, opposite) = UnixDatagram::pair().unwrap();
            opposite
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let actions = Arc::new(Mutex::new(Vec::new()));
            let fake = Fake(packet, actions.clone());
            let channel = super::super::socket::Channel::open(inherited.into()).unwrap();
            let server = thread::spawn(move || super::super::serve(channel, fake, || Ok(())));
            let mut client = control;
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            send(
                &mut client,
                serde_json::json!({
                    "version": 1, "id": 1, "op": "setup", "setup": {
                        "name": "utun", "mtu": 1280, "addresses": ["100.64.7.9/32"],
                        "routes": {"routes": [], "bypasses": []}
                    }
                }),
            );
            let (reply, descriptors) = receive(&mut client);
            assert_eq!(reply["interface_name"], "utun19");
            assert_eq!(reply["ok"], true);
            assert_eq!(descriptors.len(), 1);
            let packet = UnixDatagram::from(descriptors.into_iter().next().unwrap());
            packet.send(b"packet").unwrap();
            let mut received = [0; 16];
            let n = opposite.recv(&mut received).unwrap();
            assert_eq!(&received[..n], b"packet");
            send(
                &mut client,
                serde_json::json!({
                    "version": 1, "id": 2, "op": "apply-routes", "routes": {}
                }),
            );
            let (reply, descriptors) = receive(&mut client);
            assert_eq!(reply["ok"], true);
            assert!(descriptors.is_empty());
            if close {
                send(
                    &mut client,
                    serde_json::json!({"version": 1, "id": 3, "op": "close"}),
                );
                let (reply, descriptors) = receive(&mut client);
                assert_eq!(reply["ok"], true);
                assert!(descriptors.is_empty());
                assert_eq!(*actions.lock().unwrap(), ["setup", "routes", "restore"]);
            } else {
                drop(client);
            }
            server.join().unwrap().unwrap();
            assert_eq!(*actions.lock().unwrap(), ["setup", "routes", "restore"]);
        }
    }
    fn send(stream: &mut UnixStream, request: serde_json::Value) {
        let bytes = serde_json::to_vec(&request).unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&bytes).unwrap();
    }

    fn receive(stream: &mut UnixStream) -> (serde_json::Value, Vec<OwnedFd>) {
        use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

        let mut header = [0; 4];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let read = recvmsg(
            &*stream,
            &mut [IoSliceMut::new(&mut header)],
            &mut control,
            RecvFlags::empty(),
        )
        .unwrap();
        assert_ne!(read.bytes, 0);
        let mut descriptors = Vec::new();
        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = ancillary {
                descriptors.extend(rights);
            } else {
                panic!("unexpected ancillary data");
            }
        }
        stream.read_exact(&mut header[read.bytes..]).unwrap();
        let length = u32::from_be_bytes(header) as usize;
        assert!((1..=super::super::MAX_MESSAGE).contains(&length));
        let mut message = vec![0; length];
        stream.read_exact(&mut message).unwrap();
        (serde_json::from_slice(&message).unwrap(), descriptors)
    }
}
