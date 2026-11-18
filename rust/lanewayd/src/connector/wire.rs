use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr,
        UdpPacket, UdpRepr,
    },
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Kind {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct FlowKey {
    pub(super) kind: Kind,
    pub(super) source: SocketAddr,
    pub(super) destination: SocketAddr,
}

pub(super) struct Packet<'a> {
    pub(super) key: FlowKey,
    pub(super) open: bool,
    pub(super) payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub(super) fn parse(raw: &'a [u8]) -> Option<Self> {
        let meta = crate::routing::packet_meta(raw).ok()?;
        let caps = ChecksumCapabilities::default();
        let (protocol, body) = if meta.source.is_ipv4() {
            let packet = Ipv4Packet::new_checked(raw).ok()?;
            let ip = Ipv4Repr::parse(&packet, &caps).ok()?;
            (ip.next_header, packet.payload())
        } else {
            let packet = Ipv6Packet::new_checked(raw).ok()?;
            (packet.next_header(), packet.payload())
        };
        if !usable(meta.source) || !usable(meta.destination) {
            return None;
        }
        let (kind, from, to, open, payload) = match protocol {
            IpProtocol::Tcp => {
                let tcp = TcpPacket::new_checked(body).ok()?;
                let tcp =
                    TcpRepr::parse(&tcp, &meta.source.into(), &meta.destination.into(), &caps)
                        .ok()?;
                (
                    Kind::Tcp,
                    tcp.src_port,
                    tcp.dst_port,
                    tcp.control == TcpControl::Syn && tcp.ack_number.is_none(),
                    tcp.payload,
                )
            }
            IpProtocol::Udp => {
                let udp = UdpPacket::new_checked(body).ok()?;
                if usize::from(udp.len()) != body.len()
                    || (meta.source.is_ipv6() && udp.checksum() == 0)
                {
                    return None;
                }
                let repr =
                    UdpRepr::parse(&udp, &meta.source.into(), &meta.destination.into(), &caps)
                        .ok()?;
                (Kind::Udp, repr.src_port, repr.dst_port, true, udp.payload())
            }
            // Fragments and IPv6 extension headers are not forwarded. Handle
            // transport parsing and ACL classification the same way.
            _ => return None,
        };
        (from != 0 && to != 0).then_some(Self {
            key: FlowKey {
                kind,
                source: SocketAddr::new(meta.source, from),
                destination: SocketAddr::new(meta.destination, to),
            },
            open,
            payload,
        })
    }
}

fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => !ip.is_broadcast(),
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none() && !ip.is_unicast_link_local(),
        }
}

pub(super) fn udp_overhead(address: SocketAddr) -> usize {
    if address.is_ipv4() { 28 } else { 48 }
}

pub(crate) fn udp_packet(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Bytes {
    let caps = ChecksumCapabilities::default();
    let ip_length = udp_overhead(from) - 8;
    let payload_len = 8 + payload.len();
    let mut raw = vec![0; ip_length + payload_len];
    match (from.ip(), to.ip()) {
        (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len,
            hop_limit: 64,
        }
        .emit(&mut Ipv4Packet::new_unchecked(&mut raw), &caps),
        (IpAddr::V6(src_addr), IpAddr::V6(dst_addr)) => Ipv6Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len,
            hop_limit: 64,
        }
        .emit(&mut Ipv6Packet::new_unchecked(&mut raw)),
        _ => unreachable!("flow keys have matching address families"),
    }
    UdpRepr {
        src_port: from.port(),
        dst_port: to.port(),
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut raw[ip_length..]),
        &from.ip().into(),
        &to.ip().into(),
        payload.len(),
        |out| out.copy_from_slice(payload),
        &caps,
    );
    raw.into()
}
