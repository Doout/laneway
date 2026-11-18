//! The same installed Rust binary has separate packet and privileged helper modes.
mod helper;
pub(crate) use helper::serve_inherited;

use std::{
    collections::BTreeMap,
    ffi::CStr,
    io::{self, ErrorKind, IoSlice, IoSliceMut},
    mem,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use tokio::io::unix::AsyncFd;

use crate::config::{RouteConfig, RouteKind, TunConfig};
use helper::{Route, RoutePlan, Session, Setup};

const PACKET_HEADER: usize = 4;
const SIOCGIFMTU: libc::c_ulong = 0xc000_0000
    | ((mem::size_of::<libc::ifreq>() as libc::c_ulong) << 16)
    | ((b'i' as libc::c_ulong) << 8)
    | 51;

pub(crate) struct TunDevice {
    interface: String,
    addresses: Vec<IpNet>,
    session: Arc<Mutex<Option<Session>>>,
    device: Arc<PacketDevice>,
}

impl TunDevice {
    pub async fn open(
        config: &TunConfig,
        routes: &[RouteConfig],
        bypasses: &[IpAddr],
    ) -> Result<Self> {
        ensure!(
            config.configure,
            "macOS tun.configure must enable the installed helper"
        );
        let name = match config.name.as_str() {
            "lane0" | "utun" => "utun",
            candidate if numbered_utun(candidate) => candidate,
            _ => bail!("macOS tun.name must be utun or a numbered utun interface"),
        };
        let setup = Setup {
            name: name.to_owned(),
            mtu: config.mtu,
            addresses: config.addresses.iter().map(ToString::to_string).collect(),
            routes: route_plan(routes, bypasses),
        };
        let (session, interface, fd) = tokio::task::spawn_blocking(move || {
            let (session, interface, fd) = Session::open(&setup)?;
            ensure!(
                numbered_utun(&interface) && (setup.name == "utun" || setup.name == interface),
                "macOS helper returned an unexpected tunnel name"
            );
            verify_utun(&fd, &interface, setup.mtu)?;
            Ok::<_, anyhow::Error>((session, interface, fd))
        })
        .await
        .context("macOS TUN setup task failed")??;
        Ok(Self {
            interface,
            addresses: config.addresses.clone(),
            session: Arc::new(Mutex::new(Some(session))),
            device: Arc::new(PacketDevice::new(fd)?),
        })
    }

    pub fn device(&self) -> Arc<PacketDevice> {
        Arc::clone(&self.device)
    }

    pub fn interface_name(&self) -> &str {
        &self.interface
    }

    pub fn ensure_helper_running(&self) -> Result<()> {
        self.session
            .lock()
            .map_err(|_| anyhow::anyhow!("macOS helper lock poisoned"))?
            .as_mut()
            .context("macOS network helper session is closed")?
            .ensure_running()
    }

    pub async fn apply_controller(
        &mut self,
        addresses: &[IpNet],
        routes: &[RouteConfig],
        bypasses: &[IpAddr],
    ) -> Result<()> {
        // The installed helper cannot change addresses mid-session. An empty
        // lease withdraws routes immediately. A new nonempty address set
        // requires a fresh helper session rather than keeping stale routes.
        if !addresses.is_empty()
            && (addresses.len() != self.addresses.len()
                || addresses
                    .iter()
                    .any(|address| !self.addresses.contains(address)))
        {
            self.restore().await?;
            bail!("macOS overlay addresses changed; reconnect to open a fresh tunnel");
        }
        let plan = if addresses.is_empty() {
            RoutePlan::default()
        } else {
            route_plan(routes, bypasses)
        };
        let session = Arc::clone(&self.session);
        tokio::task::spawn_blocking(move || {
            session
                .lock()
                .map_err(|_| anyhow::anyhow!("macOS helper lock poisoned"))?
                .as_mut()
                .context("macOS network helper session is closed")?
                .replace_routes(&plan)
        })
        .await
        .context("macOS route update task failed")?
    }

    pub async fn restore(&mut self) -> Result<()> {
        let session = Arc::clone(&self.session);
        tokio::task::spawn_blocking(move || {
            let mut session = session
                .lock()
                .map_err(|_| anyhow::anyhow!("macOS helper lock poisoned"))?;
            session.take().map_or(Ok(()), Session::close)
        })
        .await
        .context("macOS route cleanup task failed")?
    }
}

fn numbered_utun(name: &str) -> bool {
    name.len() < libc::IFNAMSIZ
        && name.strip_prefix("utun").is_some_and(|index| {
            !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn route_plan(routes: &[RouteConfig], bypasses: &[IpAddr]) -> RoutePlan {
    let mut metrics = BTreeMap::<IpNet, u32>::new();
    for route in routes
        .iter()
        .filter(|route| route.kind != RouteKind::Exit && route.prefix.prefix_len() != 0)
    {
        metrics
            .entry(route.prefix)
            .and_modify(|metric| *metric = (*metric).min(route.metric))
            .or_insert(route.metric);
    }
    RoutePlan {
        routes: metrics
            .into_iter()
            .map(|(prefix, metric)| Route {
                prefix: prefix.to_string(),
                metric,
            })
            .collect(),
        bypasses: bypasses.iter().map(ToString::to_string).collect(),
    }
}

fn darwin_control_socket(family: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: these are socket constants and a successful result is uniquely
    // owned until wrapped in OwnedFd.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
    Ok(fd)
}

fn control_id(control: &OwnedFd) -> Result<u32> {
    // SAFETY: these C structures allow zero initialization. Each operation
    // receives a live descriptor and the appropriately sized output buffer.
    unsafe {
        let mut info: libc::ctl_info = mem::zeroed();
        for (dst, src) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
            *dst = *src as libc::c_char;
        }
        cvt(libc::ioctl(
            control.as_raw_fd(),
            libc::CTLIOCGINFO,
            &mut info,
        ))
        .context("look up utun control")?;
        Ok(info.ctl_id)
    }
}

fn utun_name(fd: &OwnedFd) -> Result<String> {
    let mut actual = [0u8; libc::IFNAMSIZ];
    let mut length = actual.len() as libc::socklen_t;
    // SAFETY: getsockopt receives a live descriptor and sized output buffer.
    cvt(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            actual.as_mut_ptr().cast(),
            &mut length,
        )
    })
    .context("read kernel utun name")?;
    let name = actual
        .get(..length as usize)
        .and_then(|raw| CStr::from_bytes_until_nul(raw).ok())
        .context("unterminated utun name")?
        .to_str()?;
    ensure!(numbered_utun(name), "kernel returned an invalid utun name");
    Ok(name.to_owned())
}

fn verify_utun(fd: &OwnedFd, name: &str, mtu: u16) -> Result<()> {
    let control = darwin_control_socket(libc::AF_SYSTEM, libc::SYSPROTO_CONTROL)?;
    let id = control_id(&control)?;
    ensure!(
        utun_name(fd)? == name,
        "helper tunnel name differs from the kernel"
    );
    // SAFETY: these C structures allow zero initialization and all kernel
    // calls use live FDs with appropriately sized pointers.
    unsafe {
        let mut peer: libc::sockaddr_ctl = mem::zeroed();
        let mut length = mem::size_of_val(&peer) as libc::socklen_t;
        cvt(libc::getpeername(
            fd.as_raw_fd(),
            (&mut peer as *mut libc::sockaddr_ctl).cast(),
            &mut length,
        ))
        .context("inspect helper tunnel descriptor")?;
        ensure!(
            length as usize == mem::size_of_val(&peer)
                && i32::from(peer.sc_family) == libc::AF_SYSTEM
                && i32::from(peer.ss_sysaddr) == libc::AF_SYS_CONTROL
                && peer.sc_id == id
                && peer.sc_unit != 0,
            "transferred descriptor is not a connected utun controller socket"
        );

        let query = darwin_control_socket(libc::AF_INET, 0)?;
        let mut request: libc::ifreq = mem::zeroed();
        for (dst, src) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        cvt(libc::ioctl(query.as_raw_fd(), SIOCGIFMTU, &mut request))
            .context("read kernel utun MTU")?;
        ensure!(
            request.ifr_ifru.ifru_mtu == i32::from(mtu),
            "helper tunnel MTU differs from the kernel"
        );
    }
    Ok(())
}

fn cvt(status: libc::c_int) -> io::Result<libc::c_int> {
    if status < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(status)
    }
}

pub(crate) struct PacketDevice(AsyncFd<OwnedFd>);

impl PacketDevice {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: these fcntl operations change only the owned descriptor's
        // status flags. AsyncFd requires a nonblocking descriptor.
        unsafe {
            let flags = cvt(libc::fcntl(fd.as_raw_fd(), libc::F_GETFL))?;
            cvt(libc::fcntl(
                fd.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            ))?;
        }
        Ok(Self(AsyncFd::new(fd)?))
    }

    pub async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.0.readable().await?;
            if let Ok(result) = ready.try_io(|fd| receive_packet(fd.as_raw_fd(), packet)) {
                match result {
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    result => return result,
                }
            }
        }
    }

    pub async fn send_all(&self, packet: &[u8]) -> io::Result<()> {
        let header = ip_family(packet)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "invalid utun packet family"))?
            .to_be_bytes();
        loop {
            let mut ready = self.0.writable().await?;
            if let Ok(result) = ready.try_io(|fd| {
                let vectors = [IoSlice::new(&header), IoSlice::new(packet)];
                // SAFETY: Darwin IoSlice has the iovec layout and both
                // slices live for the duration of this synchronous call.
                let written = unsafe { libc::writev(fd.as_raw_fd(), vectors.as_ptr().cast(), 2) };
                if written < 0 {
                    return Err(io::Error::last_os_error());
                }
                if written as usize != PACKET_HEADER + packet.len() {
                    return Err(io::Error::new(ErrorKind::WriteZero, "short utun write"));
                }
                Ok(())
            }) {
                match result {
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    result => return result,
                }
            }
        }
    }
}

fn ip_family(packet: &[u8]) -> Option<u32> {
    match packet.first()? >> 4 {
        4 => Some(libc::AF_INET as u32),
        6 => Some(libc::AF_INET6 as u32),
        _ => None,
    }
}

fn receive_packet(fd: libc::c_int, packet: &mut [u8]) -> io::Result<usize> {
    let mut header = [0u8; PACKET_HEADER];
    let mut vectors = [IoSliceMut::new(&mut header), IoSliceMut::new(packet)];
    // SAFETY: zero represents an empty msghdr; the iovecs refer to valid
    // mutable buffers and Darwin IoSliceMut has the iovec layout.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = vectors.as_mut_ptr().cast();
    msg.msg_iovlen = 2;
    let received = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if received == 0 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "utun disconnected",
        ));
    }
    if received as usize <= PACKET_HEADER
        || received as usize > PACKET_HEADER + packet.len()
        || msg.msg_flags & libc::MSG_TRUNC != 0
        || ip_family(packet) != Some(u32::from_be_bytes(header))
    {
        // The common packet parser treats an empty packet as malformed.
        return Ok(0);
    }
    Ok(received as usize - PACKET_HEADER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    #[tokio::test]
    async fn darwin_frames_ip_without_copying_header_into_payload() -> Result<()> {
        let (input, peer) = UnixDatagram::pair()?;
        peer.set_read_timeout(Some(Duration::from_secs(1)))?;
        let device = PacketDevice::new(input.into())?;
        let ipv4 = [0x45, 1, 2, 3];
        let mut frame = (libc::AF_INET as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&ipv4);
        peer.send(&frame)?;
        let mut buffer = [0u8; 40];
        let count =
            tokio::time::timeout(Duration::from_secs(1), device.recv(&mut buffer)).await??;
        assert_eq!(&buffer[..count], ipv4);

        let ipv6 = [0x60, 4, 5, 6];
        device.send_all(&ipv6).await?;
        let count = peer.recv(&mut buffer)?;
        assert_eq!(count, 8);
        assert_eq!(&buffer[..4], (libc::AF_INET6 as u32).to_be_bytes());
        assert_eq!(&buffer[4..count], ipv6);

        // A mismatched AF prefix, a short frame and a truncated datagram
        // must never deliver partial bytes to the IP parser.
        frame[4] = 0x60;
        for malformed in [&frame[..], &[0, 0][..], &[0; 64][..]] {
            peer.send(malformed)?;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), device.recv(&mut buffer)).await??,
                0
            );
        }
        assert!(device.send_all(&[0x70]).await.is_err());
        Ok(())
    }

    #[test]
    fn non_tunnel_descriptor_is_not_a_mac_interface() -> Result<()> {
        let (regular_socket, _peer) = UnixDatagram::pair()?;
        assert!(verify_utun(&regular_socket.into(), "utun0", 1280).is_err());
        Ok(())
    }

    #[test]
    fn helper_routes_keep_transport_bypasses_and_collapse_duplicate_prefixes() -> Result<()> {
        let route = |prefix: &str, metric, kind| -> Result<RouteConfig> {
            Ok(RouteConfig {
                prefix: prefix.parse()?,
                via_node: String::new(),
                metric,
                kind,
            })
        };
        let plan = route_plan(
            &[
                route("100.96.0.3/32", 200, RouteKind::Overlay)?,
                route("100.96.0.3/32", 100, RouteKind::Overlay)?,
                route("0.0.0.0/0", 100, RouteKind::Exit)?,
            ],
            &["192.0.2.20".parse()?],
        );
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.routes[0].metric, 100);
        assert_eq!(plan.bypasses, ["192.0.2.20"]);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires the installed helper and a disposable macOS lab"]
    async fn darwin_installed_helper_routes_and_restores_real_utun() -> Result<()> {
        use std::{
            ffi::CString,
            net::{IpAddr, Ipv4Addr},
            process::Command,
        };
        use tokio::net::UdpSocket;

        ensure!(
            std::env::var("LANEWAY_MACOS_UTUN_TEST").as_deref() == Ok("1"),
            "only run on a disposable macOS lab VM"
        );
        let local = Ipv4Addr::new(198, 18, 78, 1);
        let first = Ipv4Addr::new(198, 18, 78, 2);
        let second = Ipv4Addr::new(198, 18, 78, 3);
        let config = TunConfig {
            name: "utun".into(),
            mtu: 1280,
            addresses: vec![IpNet::from(IpAddr::V4(local))],
            configure: true,
        };
        let route = |address| RouteConfig {
            prefix: IpNet::from(IpAddr::V4(address)),
            via_node: "00000000000000000000000000000001".into(),
            metric: 100,
            kind: RouteKind::Overlay,
        };
        let mut tunnel = TunDevice::open(&config, &[route(first)], &[]).await?;
        let name = tunnel.interface_name().to_owned();
        let name_c = CString::new(name.as_str())?;
        let routes_via_tunnel = |address: Ipv4Addr| -> Result<bool> {
            let output = Command::new("/sbin/route")
                .args(["-n", "get", &address.to_string()])
                .output()?;
            Ok(output.status.success()
                && String::from_utf8(output.stdout)?
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .any(|(key, value)| key.trim() == "interface" && value.trim() == name))
        };
        let socket = UdpSocket::bind((local, 0)).await?;
        assert!(routes_via_tunnel(first)?);
        let mut competing = config.clone();
        competing.addresses = vec![IpNet::from(IpAddr::V4(Ipv4Addr::new(198, 18, 78, 15)))];
        assert!(
            TunDevice::open(&competing, &[route(first)], &[])
                .await
                .is_err()
        );
        assert!(routes_via_tunnel(first)?);
        tunnel
            .apply_controller(&config.addresses, &[route(second)], &[])
            .await?;
        assert!(!routes_via_tunnel(first)?);
        assert!(routes_via_tunnel(second)?);

        let device = tunnel.device();
        let payload = b"macos-rust-utun-lab";
        socket.send_to(payload, (second, 9784)).await?;
        let mut buffer = [0u8; 1280];
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let size = device.recv(&mut buffer).await?;
                if crate::routing::packet_meta(&buffer[..size])
                    .is_ok_and(|meta| meta.destination == second)
                    && buffer[..size].ends_with(payload)
                {
                    return Ok::<_, io::Error>(());
                }
            }
        })
        .await??;

        tunnel
            .apply_controller(&config.addresses, &[route(second)], &[IpAddr::V4(second)])
            .await?;
        assert!(!routes_via_tunnel(second)?);
        tunnel.apply_controller(&[], &[], &[]).await?;
        assert!(!routes_via_tunnel(second)?);
        tunnel.restore().await?;
        drop(device);
        drop(tunnel);
        tokio::time::timeout(Duration::from_secs(2), async {
            // SAFETY: the interface name is a live NUL-terminated CString.
            while unsafe { libc::if_nametoindex(name_c.as_ptr()) } != 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .context("utun survived helper shutdown")?;
        Ok(())
    }
}
