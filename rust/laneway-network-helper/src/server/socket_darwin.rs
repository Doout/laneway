use std::{
    io::{IoSlice, IoSliceMut},
    mem::{MaybeUninit, size_of},
    os::{
        fd::{AsRawFd, BorrowedFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::{Errno, FdFlags, fcntl_setfd},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, SocketType, recvmsg, sendmsg, sockopt,
    },
};

use super::{
    security::{stopping, syscall},
    wire::MAX_MESSAGE,
};

const TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct Channel(UnixStream);

impl Channel {
    pub(super) fn open(socket: OwnedFd) -> Result<Self> {
        let stream = UnixStream::from(socket);
        ensure!(
            sockopt::socket_type(&stream)? == SocketType::STREAM
                && stream.local_addr()?.is_unnamed()
                && stream.peer_addr()?.is_unnamed(),
            "helper requires a connected unnamed Unix stream socket"
        );
        let mut peer_pid = 0 as libc::pid_t;
        let mut length = size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: the socket fd remains borrowed; LOCAL_PEERPID writes one
        // pid_t into this initialized object, and length is checked below.
        syscall(unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                std::ptr::from_mut(&mut peer_pid).cast(),
                &mut length,
            )
        })
        .context("authenticate Darwin network helper peer")?;
        ensure!(
            length as usize == size_of::<libc::pid_t>() && peer_pid > 0,
            "network helper peer has no process identity"
        );
        sockopt::set_socket_nosigpipe(&stream, true)?;
        Ok(Self(stream))
    }

    pub(super) fn read(&self, buffer: &mut [u8; MAX_MESSAGE]) -> Result<Option<usize>> {
        let mut header = [0; 4];
        let mut read = self.receive(&mut header, None)?;
        if read == 0 {
            return Ok(None);
        }
        let deadline = Instant::now() + TIMEOUT;
        while read < header.len() {
            let amount = self.receive(&mut header[read..], Some(deadline))?;
            ensure!(amount != 0, "truncated helper frame header");
            read += amount;
        }
        let length = u32::from_be_bytes(header) as usize;
        ensure!(
            (1..=buffer.len()).contains(&length),
            "invalid helper frame size"
        );
        let mut read = 0;
        while read < length {
            let amount = self.receive(&mut buffer[read..length], Some(deadline))?;
            ensure!(amount != 0, "truncated helper frame");
            read += amount;
        }
        Ok(Some(length))
    }

    fn receive(&self, bytes: &mut [u8], deadline: Option<Instant>) -> Result<usize> {
        loop {
            if stopping() {
                return Ok(0);
            }
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            match recvmsg(
                &self.0,
                &mut [IoSliceMut::new(bytes)],
                &mut control,
                RecvFlags::DONTWAIT,
            ) {
                Ok(message) => {
                    let mut unexpected = false;
                    for entry in control.drain() {
                        unexpected = true;
                        if let RecvAncillaryMessage::ScmRights(descriptors) = entry {
                            for fd in descriptors {
                                // Darwin lacks MSG_CMSG_CLOEXEC. No other
                                // thread can spawn during this synchronous call.
                                fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
                            }
                        }
                    }
                    ensure!(
                        !unexpected
                            && !message
                                .flags
                                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC),
                        "invalid or truncated helper ancillary data"
                    );
                    return Ok(message.bytes);
                }
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => self.wait(PollFlags::IN, deadline)?,
                Err(err) => return Err(err).context("read network helper request"),
            }
        }
    }

    pub(super) fn write(&self, bytes: &[u8], descriptor: Option<BorrowedFd<'_>>) -> Result<()> {
        ensure!(
            (1..=MAX_MESSAGE).contains(&bytes.len()),
            "invalid helper response size"
        );
        let mut frame = Vec::with_capacity(4 + bytes.len());
        frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(bytes);
        let deadline = Instant::now() + TIMEOUT;
        let mut written = 0;
        while written < frame.len() {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let rights;
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            if let Some(fd) = descriptor.filter(|_| written == 0) {
                rights = [fd];
                ensure!(
                    ancillary.push(SendAncillaryMessage::ScmRights(&rights)),
                    "prepare helper descriptor transfer"
                );
            }
            match sendmsg(
                &self.0,
                &[IoSlice::new(&frame[written..])],
                &mut ancillary,
                SendFlags::DONTWAIT,
            ) {
                Ok(0) => bail!("short network helper response"),
                Ok(count) => written += count,
                Err(Errno::INTR) => continue,
                Err(Errno::AGAIN) => self.wait(PollFlags::OUT, Some(deadline))?,
                Err(err) => return Err(err).context("send network helper response"),
            }
        }
        Ok(())
    }

    fn wait(&self, interest: PollFlags, deadline: Option<Instant>) -> Result<()> {
        loop {
            if stopping() && interest == PollFlags::IN {
                return Ok(());
            }
            let wake = Duration::from_millis(250);
            let timeout = {
                let remaining = deadline.map_or(wake, |deadline| {
                    deadline.saturating_duration_since(Instant::now()).min(wake)
                });
                Timespec {
                    tv_sec: remaining.as_secs() as _,
                    tv_nsec: remaining.subsec_nanos() as _,
                }
            };
            match poll(&mut [PollFd::new(&self.0, interest)], Some(&timeout)) {
                Ok(0) if deadline.is_none_or(|deadline| Instant::now() < deadline) => continue,
                Ok(0) => bail!("network helper operation timed out"),
                Ok(_) => return Ok(()),
                Err(Errno::INTR) => continue,
                Err(err) => return Err(err).context("wait for network helper socket"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::fd::AsFd, os::unix::net::UnixListener};

    #[test]
    fn rejects_named_or_unconnected_stream() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let socket = temporary.path().join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(Channel::open(listener.try_clone().unwrap().into()).is_err());
        let client = UnixStream::connect(&socket).unwrap();
        let (server, _) = listener.accept().unwrap();
        assert!(Channel::open(client.into()).is_err());
        assert!(Channel::open(server.into()).is_err());
    }

    #[test]
    fn rejects_oversized_partial_and_descriptor_requests() {
        let (mut peer, inherited) = UnixStream::pair().unwrap();
        let channel = Channel::open(inherited.into()).unwrap();
        let mut bytes = Box::new([0; MAX_MESSAGE]);
        peer.write_all(&((MAX_MESSAGE + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(
            channel
                .read(&mut bytes)
                .unwrap_err()
                .to_string()
                .contains("frame size")
        );

        let (mut peer, inherited) = UnixStream::pair().unwrap();
        let channel = Channel::open(inherited.into()).unwrap();
        peer.write_all(&[0, 0]).unwrap();
        drop(peer);
        assert!(
            channel
                .read(&mut bytes)
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );

        let (peer, inherited) = UnixStream::pair().unwrap();
        let channel = Channel::open(inherited.into()).unwrap();
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let rights = [peer.as_fd()];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
        assert_eq!(
            sendmsg(
                &peer,
                &[IoSlice::new(&[0, 0, 0, 1, 0])],
                &mut ancillary,
                SendFlags::empty()
            )
            .unwrap(),
            5
        );
        assert!(
            channel
                .read(&mut bytes)
                .unwrap_err()
                .to_string()
                .contains("ancillary data")
        );
    }
}
