use std::{
    fs::File,
    io::{self, IoSlice, IoSliceMut, Read, Write},
    os::fd::OwnedFd,
};

use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    io::{FdFlags, fcntl_setfd},
    net::{SocketType, sockopt},
};
use tokio::io::unix::AsyncFd;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;

/// Raw packet endpoint over a Darwin utun descriptor.
pub struct UtunPackets(AsyncFd<File>);

impl UtunPackets {
    /// Adopt a descriptor delivered by the authenticated helper.
    pub fn adopt(descriptor: OwnedFd) -> io::Result<Self> {
        fcntl_setfd(&descriptor, FdFlags::CLOEXEC)?;
        if sockopt::socket_type(&descriptor)? != SocketType::DGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "utun requires a datagram descriptor",
            ));
        }
        fcntl_setfl(&descriptor, fcntl_getfl(&descriptor)? | OFlags::NONBLOCK)?;
        Ok(Self(AsyncFd::new(File::from(descriptor))?))
    }

    /// Reads one IP datagram after removing the four-byte utun family field.
    pub async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut readiness = self.0.readable().await?;
            if let Ok(result) = readiness.try_io(|fd| read_packet(fd.get_ref(), packet)) {
                return result;
            }
        }
    }

    /// Writes one complete IP datagram with a network-byte-order family field.
    pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
        let format = packet_family(packet)?.to_be_bytes();
        loop {
            let mut readiness = self.0.writable().await?;
            if let Ok(result) = readiness.try_io(|fd| {
                let written = fd
                    .get_ref()
                    .write_vectored(&[IoSlice::new(&format), IoSlice::new(packet)])?;
                if written == format.len() + packet.len() {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial utun datagram",
                    ))
                }
            }) {
                return result;
            }
        }
    }
}

fn read_packet(mut input: &File, packet: &mut [u8]) -> io::Result<usize> {
    let mut header = [0; 4];
    let mut excess = [0; 1];
    let count = input.read_vectored(&mut [
        IoSliceMut::new(&mut header),
        IoSliceMut::new(packet),
        IoSliceMut::new(&mut excess),
    ])?;
    if count <= header.len() || count > header.len() + packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated or oversized utun datagram",
        ));
    }
    let length = count - header.len();
    if u32::from_be_bytes(header) != packet_family(&packet[..length])? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "utun family differs from IP version",
        ));
    }
    Ok(length)
}

fn packet_family(packet: &[u8]) -> io::Result<u32> {
    match packet.first().map(|first| first >> 4) {
        Some(4) if packet.len() >= 20 => Ok(AF_INET),
        Some(6) if packet.len() >= 40 => Ok(AF_INET6),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IP datagram for utun",
        )),
    }
}
