//! Minimal client for the Linux WireGuard generic-netlink SET interface.
//! No credential is passed to a subprocess or rendered as a command string.

use std::{
    io,
    mem::{size_of, zeroed},
    net::SocketAddrV4,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use zeroize::Zeroizing;

// linux/uapi/{netlink,genetlink,wireguard}.h
const HEADER: usize = 16;
const GENL: usize = HEADER + 4;
const CTRL: u16 = 0x10;
const CTRL_NEW_FAMILY: u8 = 1;
const CTRL_GET_FAMILY: u8 = 3;
const CTRL_FAMILY_ID: u16 = 1;
const CTRL_FAMILY_NAME: u16 = 2;
const WG_SET_DEVICE: u8 = 1;
const WG_IFINDEX: u16 = 1;
const WG_PRIVATE_KEY: u16 = 3;
const WG_FLAGS: u16 = 5;
const WG_LISTEN_PORT: u16 = 6;
const WG_PEERS: u16 = 8;
const PEER_PUBLIC_KEY: u16 = 1;
const PEER_FLAGS: u16 = 3;
const PEER_ENDPOINT: u16 = 4;
const PEER_PREFIXES: u16 = 9;
const PREFIX_FAMILY: u16 = 1;
const PREFIX_ADDRESS: u16 = 2;
const PREFIX_CIDR: u16 = 3;
const REPLACE_PEERS: u32 = 1;
const REPLACE_PREFIXES: u32 = 2;
const UPDATE_PEER_ONLY: u32 = 4;
const NESTED: u16 = 1 << 15;

struct Message {
    bytes: Zeroizing<[u8; 4096]>,
    len: usize,
}

impl Message {
    fn new(family: u16, command: u8, version: u8, ack: bool) -> Self {
        let mut bytes = Zeroizing::new([0; 4096]);
        bytes[4..6].copy_from_slice(&family.to_ne_bytes());
        let flags = libc::NLM_F_REQUEST | if ack { libc::NLM_F_ACK } else { 0 };
        bytes[6..8].copy_from_slice(&(flags as u16).to_ne_bytes());
        bytes[HEADER..HEADER + 2].copy_from_slice(&[command, version]);
        Self { bytes, len: GENL }
    }

    fn append(&mut self, kind: u16, value: &[u8]) -> Result<()> {
        let start = self.begin(kind)?;
        let end = self
            .len
            .checked_add(value.len())
            .context("netlink length overflow")?;
        let aligned = align(end);
        ensure!(
            aligned <= self.bytes.len(),
            "WireGuard netlink request exceeded its bound"
        );
        self.bytes[self.len..end].copy_from_slice(value);
        self.close(start, end)?;
        self.len = aligned;
        Ok(())
    }

    fn nested(&mut self, kind: u16, fill: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let start = self.begin(kind | NESTED)?;
        fill(self)?;
        self.close(start, self.len)
    }

    fn begin(&mut self, kind: u16) -> Result<usize> {
        let start = self.len;
        ensure!(
            start + 4 <= self.bytes.len(),
            "WireGuard attribute header would overflow"
        );
        self.bytes[start + 2..start + 4].copy_from_slice(&kind.to_ne_bytes());
        self.len += 4;
        Ok(start)
    }

    fn close(&mut self, start: usize, end: usize) -> Result<()> {
        self.bytes[start..start + 2].copy_from_slice(&u16::try_from(end - start)?.to_ne_bytes());
        Ok(())
    }
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}

pub(super) struct WireGuardControl {
    socket: OwnedFd,
    family: u16,
    sequence: u32,
}

impl WireGuardControl {
    pub(super) fn open() -> Result<Self> {
        let socket = unsafe {
            // SAFETY: no pointers; the resulting fd is owned only here.
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_GENERIC,
            );
            checked(fd as isize).context("open WireGuard netlink")?;
            OwnedFd::from_raw_fd(fd)
        };
        let mut control = Self {
            socket,
            family: 0,
            sequence: 0,
        };
        control.connect()?;
        let mut query = Message::new(CTRL, CTRL_GET_FAMILY, 1, false);
        query.append(CTRL_FAMILY_NAME, b"wireguard\0")?;
        control.family = control.exchange(query, Reply::Family)?;
        Ok(control)
    }

    fn connect(&self) -> Result<()> {
        // SAFETY: sockaddr_nl is a plain C structure. A zero netlink port and
        // group designate the kernel, never a userspace multicast receiver.
        let mut address: libc::sockaddr_nl = unsafe { zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let socket = self.socket.as_raw_fd();
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let cap_ack: libc::c_int = 1;
        unsafe {
            // SAFETY: all inputs and lengths refer to initialized C values.
            checked(libc::connect(
                socket,
                (&raw const address).cast(),
                size_of::<libc::sockaddr_nl>() as _,
            ) as isize)?;
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                checked(libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    option,
                    (&raw const timeout).cast(),
                    size_of::<libc::timeval>() as _,
                ) as isize)?;
            }
            // Do not let the kernel echo a private-key-bearing request back as
            // part of an ACK; do not include netlink payloads in diagnostics.
            checked(libc::setsockopt(
                socket,
                libc::SOL_NETLINK,
                libc::NETLINK_CAP_ACK,
                (&raw const cap_ack).cast(),
                size_of::<libc::c_int>() as _,
            ) as isize)?;
        }
        Ok(())
    }

    pub(super) fn configure_device(&mut self, index: u32, key: &[u8; 32], port: u16) -> Result<()> {
        let mut request = self.set_device(index)?;
        request.append(WG_PRIVATE_KEY, key)?;
        request.append(WG_LISTEN_PORT, &port.to_ne_bytes())?;
        request.append(WG_FLAGS, &REPLACE_PEERS.to_ne_bytes())?;
        self.exchange(request, Reply::Ack)
            .context("configure WireGuard link identity")?;
        Ok(())
    }

    pub(super) fn configure_peer(
        &mut self,
        index: u32,
        key: &[u8; 32],
        endpoint: SocketAddrV4,
        prefixes: &[IpNet],
    ) -> Result<()> {
        ensure!(
            !prefixes.is_empty(),
            "WireGuard peer has no ownership prefixes"
        );
        // Configure bounded fragments while the device is still down. Only
        // the first fragment replaces ownership or can create the peer.
        for (i, prefixes) in prefixes.chunks(64).enumerate() {
            let mut request = self.set_device(index)?;
            request.nested(WG_PEERS, |peers| {
                peers.nested(0, |peer| {
                    peer.append(PEER_PUBLIC_KEY, key)?;
                    let flags = if i == 0 {
                        REPLACE_PREFIXES
                    } else {
                        UPDATE_PEER_ONLY
                    };
                    peer.append(PEER_FLAGS, &flags.to_ne_bytes())?;
                    if i == 0 {
                        let mut socket = [0u8; 16];
                        socket[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
                        socket[2..4].copy_from_slice(&endpoint.port().to_be_bytes());
                        socket[4..8].copy_from_slice(&endpoint.ip().octets());
                        peer.append(PEER_ENDPOINT, &socket)?;
                    }
                    peer.nested(PEER_PREFIXES, |allowed| {
                        for prefix in prefixes {
                            allowed.nested(0, |attrs| {
                                match prefix {
                                    IpNet::V4(ip) => {
                                        attrs.append(
                                            PREFIX_FAMILY,
                                            &(libc::AF_INET as u16).to_ne_bytes(),
                                        )?;
                                        attrs.append(PREFIX_ADDRESS, &ip.addr().octets())?;
                                    }
                                    IpNet::V6(ip) => {
                                        attrs.append(
                                            PREFIX_FAMILY,
                                            &(libc::AF_INET6 as u16).to_ne_bytes(),
                                        )?;
                                        attrs.append(PREFIX_ADDRESS, &ip.addr().octets())?;
                                    }
                                }
                                attrs.append(PREFIX_CIDR, &[prefix.prefix_len()])
                            })?;
                        }
                        Ok(())
                    })
                })
            })?;
            self.exchange(request, Reply::Ack)
                .context("configure WireGuard peer ownership")?;
        }
        Ok(())
    }

    fn set_device(&self, index: u32) -> Result<Message> {
        let mut request = Message::new(self.family, WG_SET_DEVICE, 1, true);
        request.append(WG_IFINDEX, &index.to_ne_bytes())?;
        Ok(request)
    }

    fn exchange(&mut self, mut request: Message, expected: Reply) -> Result<u16> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("netlink sequence exhausted")?;
        request.bytes[..4].copy_from_slice(&(request.len as u32).to_ne_bytes());
        request.bytes[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        let socket = self.socket.as_raw_fd();
        // SAFETY: send reads only the initialized request from a connected fd.
        let sent = unsafe { libc::send(socket, request.bytes.as_ptr().cast(), request.len, 0) };
        ensure!(
            checked(sent)? == request.len,
            "short WireGuard netlink send"
        );
        drop(request);

        let mut reply = Zeroizing::new([0_u8; 8192]);
        let mut sender: libc::sockaddr_nl = unsafe { zeroed() };
        let mut sender_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: buffers are live and sized. MSG_TRUNC makes an oversized
        // datagram distinguishable instead of letting us parse its prefix.
        let received = unsafe {
            libc::recvfrom(
                socket,
                reply.as_mut_ptr().cast(),
                reply.len(),
                libc::MSG_TRUNC,
                (&raw mut sender).cast(),
                &mut sender_len,
            )
        };
        let length = checked(received)?;
        ensure!(
            sender_len as usize == size_of::<libc::sockaddr_nl>()
                && sender.nl_family == libc::AF_NETLINK as u16
                && sender.nl_pid == 0
                && (GENL..=reply.len()).contains(&length),
            "invalid WireGuard netlink sender or datagram length"
        );
        parse_reply(&reply[..length], self.sequence, expected)
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Ack,
    Family,
}

fn parse_reply(reply: &[u8], sequence: u32, expected: Reply) -> Result<u16> {
    ensure!(reply.len() >= GENL, "truncated WireGuard netlink reply");
    let size = ne_u32(&reply[..4]) as usize;
    ensure!(
        (GENL..=reply.len()).contains(&size)
            && align(size) == reply.len()
            && ne_u32(&reply[8..12]) == sequence,
        "invalid WireGuard netlink reply"
    );
    let kind = ne_u16(&reply[4..6]);
    if kind == libc::NLMSG_ERROR as u16 {
        let code = i32::from_ne_bytes(reply[HEADER..GENL].try_into()?);
        if code < 0 {
            return Err(io::Error::from_raw_os_error(code.saturating_neg()).into());
        }
        ensure!(
            code == 0 && matches!(expected, Reply::Ack),
            "unexpected WireGuard netlink ACK"
        );
        return Ok(0);
    }
    ensure!(
        matches!(expected, Reply::Family) && kind == CTRL && reply[HEADER] == CTRL_NEW_FAMILY,
        "unexpected WireGuard netlink family response"
    );
    let mut attrs = &reply[GENL..size];
    let mut id = None;
    let mut name = None;
    while !attrs.is_empty() {
        ensure!(attrs.len() >= 4, "truncated WireGuard family attribute");
        let len = usize::from(ne_u16(&attrs[..2]));
        let kind = ne_u16(&attrs[2..4]);
        ensure!(
            len >= 4 && align(len) <= attrs.len(),
            "invalid WireGuard family attribute length"
        );
        match kind {
            CTRL_FAMILY_ID if len == 6 && id.is_none() => id = Some(ne_u16(&attrs[4..6])),
            CTRL_FAMILY_NAME if name.is_none() => name = Some(&attrs[4..len]),
            CTRL_FAMILY_ID | CTRL_FAMILY_NAME => {
                bail!("invalid or duplicate WireGuard family identity")
            }
            _ => (),
        }
        attrs = &attrs[align(len)..];
    }
    ensure!(
        name == Some(b"wireguard\0"),
        "netlink returned a different family"
    );
    id.filter(|id| *id > CTRL)
        .context("missing WireGuard family ID")
}

fn checked(ret: isize) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

fn ne_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes.try_into().expect("sized netlink field"))
}

fn ne_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes.try_into().expect("sized netlink field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_parser_rejects_wrong_sequence_or_truncated_attributes() -> Result<()> {
        let mut message = Message::new(CTRL, CTRL_NEW_FAMILY, 1, false);
        message.append(CTRL_FAMILY_ID, &54_u16.to_ne_bytes())?;
        message.append(CTRL_FAMILY_NAME, b"wireguard\0")?;
        message.bytes[..4].copy_from_slice(&(message.len as u32).to_ne_bytes());
        message.bytes[8..12].copy_from_slice(&2_u32.to_ne_bytes());
        let reply = &message.bytes[..message.len];
        assert_eq!(parse_reply(reply, 2, Reply::Family)?, 54);
        assert!(parse_reply(reply, 1, Reply::Family).is_err());
        assert!(parse_reply(&reply[..reply.len() - 1], 2, Reply::Family).is_err());
        assert!(parse_reply(reply, 2, Reply::Ack).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires a dedicated network namespace and CAP_NET_ADMIN"]
    fn wireguard_kernel_accepts_batched_peer_prefixes() -> Result<()> {
        // The fixture creates only this fresh device, in a disconnected lab.
        use std::process::Command;
        let interface = "lwwg_batchtest";
        let run = |tool: &str, args: &[&str]| -> Result<Vec<u8>> {
            let output = Command::new(tool).args(args).output()?;
            ensure!(
                output.status.success(),
                "{tool} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(output.stdout)
        };
        run(
            "ip",
            &["link", "add", "dev", interface, "type", "wireguard"],
        )?;
        let result = (|| -> Result<()> {
            let mut kernel = WireGuardControl::open()?;
            let info = run("ip", &["-j", "link", "show", "dev", interface])?;
            let info: serde_json::Value = serde_json::from_slice(&info)?;
            let index = u32::try_from(
                info[0]["ifindex"]
                    .as_u64()
                    .context("test link has no ifindex")?,
            )?;
            kernel.configure_device(index, &[34; 32], 12345)?;
            let prefixes = (1..=70)
                .map(|i| format!("198.18.0.{i}/32").parse::<IpNet>())
                .collect::<Result<Vec<_>, _>>()?;
            let peer = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([57; 32]));
            kernel.configure_peer(
                index,
                peer.as_bytes(),
                "127.0.0.1:12346".parse()?,
                &prefixes,
            )?;
            let actual = run("wg", &["show", interface, "allowed-ips"])?;
            let actual = std::str::from_utf8(&actual)?;
            assert_eq!(actual.split_whitespace().skip(1).count(), 70);
            Ok(())
        })();
        let cleanup = run("ip", &["link", "delete", "dev", interface]);
        result.and(cleanup.map(|_| ()))
    }
}
