//! Darwin utun packet framing and the Go helper's inherited socket protocol.
//!
//! The client requires an already authenticated helper channel. It never
//! starts sudo, opens an interface, or changes host networking by itself.

use std::{
    io::{IoSliceMut, Write},
    mem::MaybeUninit,
    net::IpAddr,
    os::{fd::OwnedFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::{FdFlags, fcntl_setfd},
    net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg, sockopt},
};
use serde::{Deserialize, Serialize};

const V1: u8 = 1;
const MESSAGE_LIMIT: usize = 64 << 10;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);

pub use lanewayd_rs::UtunPackets;

/// A controller-selected split route to install through the helper.
#[derive(Serialize)]
pub struct Route {
    /// Destination prefix.
    pub prefix: IpNet,
    /// Route metric.
    pub metric: u32,
}

/// Routes and transport bypasses to replace as one helper transaction.
#[derive(Serialize)]
pub struct RoutePlan<'a> {
    /// Signed routes selected by the caller.
    pub routes: &'a [Route],
    /// Numeric addresses of the authenticated transport endpoints.
    pub bypasses: &'a [IpAddr],
}

#[derive(Serialize)]
struct Setup<'a> {
    name: &'static str,
    mtu: u16,
    addresses: &'a [IpNet],
    routes: RoutePlan<'a>,
}

#[derive(Serialize)]
struct Request<T> {
    version: u8,
    id: u64,
    op: &'static str,
    #[serde(flatten)]
    contents: T,
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

/// Version-one control client for the installed Darwin helper.
pub struct HelperClient {
    stream: UnixStream,
    next_id: u64,
    active: bool,
}

impl HelperClient {
    /// Takes the parent socket of an already authenticated helper. EOF makes
    /// the Go helper restore its routes even when setup or the client fails.
    pub fn new(stream: UnixStream) -> Result<Self> {
        stream.set_read_timeout(Some(PROCESS_TIMEOUT))?;
        stream.set_write_timeout(Some(PROCESS_TIMEOUT))?;
        sockopt::set_socket_nosigpipe(&stream, true)?;
        Ok(Self {
            stream,
            next_id: 1,
            active: false,
        })
    }

    /// Creates a helper-managed utun interface and applies the initial routes.
    pub fn setup(
        &mut self,
        mtu: u16,
        addresses: &[IpNet],
        routes: RoutePlan<'_>,
    ) -> Result<(String, OwnedFd)> {
        ensure!(
            !self.active && self.next_id == 1,
            "network helper setup already attempted"
        );
        ensure!(
            addresses.len() <= 8,
            "interface addresses exceed the helper limit"
        );
        validate_plan(&routes)?;
        let mut reply = self.operation(
            "setup",
            &serde_json::json!({
                "setup": Setup { name: "utun", mtu, addresses, routes }
            }),
        )?;
        let name = reply
            .0
            .interface_name
            .take()
            .context("network helper did not return an interface name")?;
        ensure!(
            reply.0.helper_pid.is_some_and(|pid| pid != 0) && valid_interface(&name),
            "network helper returned an invalid interface or process identity"
        );
        ensure!(
            reply.1.len() == 1,
            "network helper setup must transfer exactly one descriptor"
        );
        self.active = true;
        Ok((name, reply.1.pop().expect("descriptor count checked")))
    }

    /// Replaces the currently owned routes using a fresh authorized plan.
    pub fn apply_routes(&mut self, plan: RoutePlan<'_>) -> Result<()> {
        ensure!(self.active, "network helper setup is incomplete");
        validate_plan(&plan)?;
        self.acknowledge("apply-routes", &serde_json::json!({ "routes": plan }))
    }

    /// Requests route restoration and closes the inherited socket.
    pub fn close(mut self) -> Result<()> {
        if self.active {
            self.acknowledge("close", &serde_json::json!({}))?;
        }
        Ok(())
    }

    fn acknowledge(&mut self, op: &'static str, contents: &serde_json::Value) -> Result<()> {
        let (reply, rights) = self.operation(op, contents)?;
        ensure!(
            rights.is_empty() && reply.interface_name.is_none() && reply.helper_pid.is_none(),
            "unexpected helper response metadata"
        );
        Ok(())
    }

    fn operation(
        &mut self,
        op: &'static str,
        contents: &serde_json::Value,
    ) -> Result<(Reply, Vec<OwnedFd>)> {
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .context("network helper request ID exhausted")?;
        let data = serde_json::to_vec(&Request {
            version: V1,
            id,
            op,
            contents,
        })?;
        ensure!(
            data.len() <= MESSAGE_LIMIT,
            "network helper request exceeds the frame limit"
        );
        self.stream.write_all(&(data.len() as u32).to_be_bytes())?;
        self.stream.write_all(&data)?;
        let (reply, rights) = read_reply(&self.stream)?;
        ensure!(
            reply.version == V1 && reply.id == id,
            "mismatched network helper reply"
        );
        ensure!(
            reply.ok,
            "network helper rejected {op}: {}",
            reply.error.as_deref().unwrap_or("unknown error")
        );
        ensure!(
            reply.error.is_none(),
            "network helper sent both success and an error"
        );
        Ok((reply, rights))
    }
}

fn validate_plan(plan: &RoutePlan<'_>) -> Result<()> {
    ensure!(
        plan.routes.len() <= 1024 && plan.bypasses.len() <= 64,
        "split routes exceed the helper limit"
    );
    ensure!(
        plan.routes
            .iter()
            .all(|route| route.prefix.prefix_len() != 0 && route.prefix == route.prefix.trunc()),
        "split routes require canonical non-default prefixes"
    );
    Ok(())
}

fn valid_interface(name: &str) -> bool {
    name.strip_prefix("utun").is_some_and(|unit| {
        !unit.is_empty() && unit.len() <= 10 && unit.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn read_reply(stream: &UnixStream) -> Result<(Reply, Vec<OwnedFd>)> {
    let mut header = [0; 4];
    let mut rights = Vec::new();
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    receive_exact(stream, &mut header, &mut rights, true, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        (1..=MESSAGE_LIMIT).contains(&length),
        "invalid network helper frame size"
    );
    let mut payload = vec![0; length];
    receive_exact(stream, &mut payload, &mut rights, false, deadline)?;
    let reply = serde_json::from_slice(&payload).context("decode network helper reply")?;
    Ok((reply, rights))
}

fn receive_exact(
    stream: &UnixStream,
    mut bytes: &mut [u8],
    rights: &mut Vec<OwnedFd>,
    accept_first_rights: bool,
    deadline: Instant,
) -> Result<()> {
    let mut first = true;
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "network helper response timed out");
        let wait = Timespec {
            tv_sec: remaining.as_secs() as _,
            tv_nsec: remaining.subsec_nanos() as _,
        };
        ensure!(
            poll(&mut [PollFd::new(stream, PollFlags::IN)], Some(&wait))? > 0,
            "network helper response timed out"
        );
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let message = recvmsg(
            stream,
            &mut [IoSliceMut::new(bytes)],
            &mut ancillary,
            RecvFlags::empty(),
        )?;
        ensure!(
            message.bytes > 0
                && !message
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC),
            "empty or truncated network helper response"
        );
        for message in ancillary.drain() {
            let RecvAncillaryMessage::ScmRights(descriptors) = message else {
                anyhow::bail!("unexpected network helper ancillary message");
            };
            ensure!(
                accept_first_rights && first,
                "descriptors appeared outside the first frame segment"
            );
            for descriptor in descriptors {
                // Darwin does not implement MSG_CMSG_CLOEXEC.
                fcntl_setfd(&descriptor, FdFlags::CLOEXEC)?;
                rights.push(descriptor);
            }
            ensure!(
                rights.len() <= 1,
                "network helper returned extra descriptors"
            );
        }
        bytes = &mut bytes[message.bytes..];
        first = false;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, IoSlice, Read},
        os::unix::net::UnixDatagram,
        thread,
    };

    use rustix::{
        io::fcntl_getfd,
        net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg},
    };
    use serde_json::{Value, json};

    use super::*;

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 30;

    fn read_request(stream: &mut UnixStream) -> Value {
        let mut header = [0; 4];
        stream.read_exact(&mut header).unwrap();
        let mut contents = vec![0; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut contents).unwrap();
        serde_json::from_slice(&contents).unwrap()
    }

    fn write_reply(stream: &mut UnixStream, reply: Value, descriptor: Option<&UnixDatagram>) {
        use std::os::fd::AsFd;
        let payload = serde_json::to_vec(&reply).unwrap();
        let header = (payload.len() as u32).to_be_bytes();
        if let Some(descriptor) = descriptor {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            let descriptors = [descriptor.as_fd()];
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
            // The descriptor accompanies the first two header bytes. The
            // receiver must keep it while finishing the fragmented header.
            let count = sendmsg(
                &*stream,
                &[IoSlice::new(&header[..2])],
                &mut ancillary,
                SendFlags::empty(),
            )
            .unwrap();
            assert_eq!(count, 2);
            stream.write_all(&header[2..]).unwrap();
        } else {
            stream.write_all(&header).unwrap();
        }
        stream.write_all(&payload[..1]).unwrap();
        stream.write_all(&payload[1..]).unwrap();
    }

    #[tokio::test]
    async fn receives_rights_and_pumps_darwin_ipv4_and_ipv6_packets() {
        let (client, mut helper) = UnixStream::pair().unwrap();
        let (device, kernel) = UnixDatagram::pair().unwrap();
        let fake = thread::spawn(move || {
            let request = read_request(&mut helper);
            assert_eq!(request["op"], "setup");
            assert_eq!(request["id"], 1);
            assert_eq!(request["setup"]["name"], "utun");
            assert_eq!(request["setup"]["addresses"], json!(["100.64.0.2/32"]));
            write_reply(
                &mut helper,
                json!({"version":1,"id":1,"ok":true,"helper_pid":1,"interface_name":"utun9"}),
                Some(&device),
            );
            let revised = read_request(&mut helper);
            assert_eq!(revised["op"], "apply-routes");
            assert_eq!(revised["id"], 2);
            assert_eq!(
                revised["routes"],
                json!({"routes":[{"prefix":"192.0.2.0/24","metric":3}],"bypasses":["198.51.100.2"]})
            );
            write_reply(&mut helper, json!({"version":1,"id":2,"ok":true}), None);
            let close = read_request(&mut helper);
            assert_eq!(close["op"], "close");
            assert_eq!(close["id"], 3);
            write_reply(&mut helper, json!({"version":1,"id":3,"ok":true}), None);
        });
        let mut client = HelperClient::new(client).unwrap();
        let empty = RoutePlan {
            routes: &[],
            bypasses: &[],
        };
        let (interface, fd) = client
            .setup(1280, &["100.64.0.2/32".parse().unwrap()], empty)
            .unwrap();
        assert_eq!(interface, "utun9");
        assert!(fcntl_getfd(&fd).unwrap().contains(FdFlags::CLOEXEC));
        let packets = UtunPackets::adopt(fd).unwrap();
        let mut v4 = [0; 20];
        v4[0] = 0x45;
        v4[9] = 1; // ICMP is an IP payload, not TCP/UDP-only userspace framing.
        let mut ipv4_frame = AF_INET.to_be_bytes().to_vec();
        ipv4_frame.extend_from_slice(&v4);
        kernel.send(&ipv4_frame).unwrap();
        let mut buffer = [0; 1280];
        let length = packets.recv(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], &v4);

        let mut v6 = [0; 40];
        v6[0] = 0x60;
        v6[6] = 58;
        packets.send(&v6).await.unwrap();
        let length = kernel.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..4], &AF_INET6.to_be_bytes());
        assert_eq!(&buffer[4..length], &v6);

        client
            .apply_routes(RoutePlan {
                routes: &[Route {
                    prefix: "192.0.2.0/24".parse().unwrap(),
                    metric: 3,
                }],
                bypasses: &["198.51.100.2".parse().unwrap()],
            })
            .unwrap();
        client.close().unwrap();
        fake.join().unwrap();
    }

    #[tokio::test]
    async fn utun_rejects_family_mismatch_and_truncation() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert!(matches!(
            UtunPackets::adopt(stream.into()),
            Err(err) if err.kind() == io::ErrorKind::InvalidInput
        ));
        let (device, kernel) = UnixDatagram::pair().unwrap();
        let packets = UtunPackets::adopt(device.into()).unwrap();
        let mut frame = AF_INET6.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0x45; 20]);
        kernel.send(&frame).unwrap();
        assert_eq!(
            packets.recv(&mut [0; 20]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        frame[..4].copy_from_slice(&AF_INET.to_be_bytes());
        frame.push(1);
        kernel.send(&frame).unwrap();
        assert_eq!(
            packets.recv(&mut [0; 20]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn refuses_oversized_helper_reply_and_ancillary_data_after_header() {
        use std::os::fd::AsFd;
        let (client, mut helper) = UnixStream::pair().unwrap();
        helper
            .write_all(&((MESSAGE_LIMIT + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(read_reply(&client).is_err());

        let (client, mut helper) = UnixStream::pair().unwrap();
        let (device, _) = UnixDatagram::pair().unwrap();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let descriptors = [device.as_fd()];
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)));
        helper.write_all(&2_u32.to_be_bytes()).unwrap();
        sendmsg(
            &helper,
            &[IoSlice::new(b"{}")],
            &mut ancillary,
            SendFlags::empty(),
        )
        .unwrap();
        assert!(read_reply(&client).is_err());
    }
}
