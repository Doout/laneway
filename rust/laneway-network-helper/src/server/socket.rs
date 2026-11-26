// Each syscall uses either a borrowed open descriptor or initialized buffers
// whose full size is passed to the kernel. SCM_RIGHTS replies send one fd.

use std::{
    io, mem,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    ptr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::wire::MAX_MESSAGE;

const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct Channel {
    socket: OwnedFd,
    shutdown: Option<OwnedFd>,
}

impl Channel {
    pub(super) fn open(socket: OwnedFd) -> Result<Self> {
        let channel = Self {
            socket,
            shutdown: None,
        };
        let kind: libc::c_int = channel.socket_option(libc::SO_TYPE)?;
        ensure!(
            kind == libc::SOCK_SEQPACKET,
            "helper requires a Unix seqpacket socket"
        );
        channel.check_unnamed_endpoint(false)?;
        channel.check_unnamed_endpoint(true)?;
        let peer: libc::ucred = channel.socket_option(libc::SO_PEERCRED)?;
        ensure!(peer.pid > 0, "helper peer has no process identity");
        Ok(channel)
    }

    // The dedicated helper stays single-threaded. Keep SIGTERM blocked
    // throughout setup and cleanup so a pending signal cannot interrupt either.
    pub(super) fn watch_shutdown(&mut self) -> Result<()> {
        let mut signals = mem::MaybeUninit::<libc::sigset_t>::uninit();
        let fd = unsafe {
            syscall(libc::sigemptyset(signals.as_mut_ptr()))?;
            syscall(libc::sigaddset(signals.as_mut_ptr(), libc::SIGTERM))?;
            syscall(libc::sigprocmask(
                libc::SIG_BLOCK,
                signals.as_ptr(),
                ptr::null_mut(),
            ))?;
            syscall(libc::signalfd(
                -1,
                signals.as_ptr(),
                libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
            ))?
        };
        self.shutdown = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(())
    }

    fn shutdown_descriptor(&self) -> libc::pollfd {
        libc::pollfd {
            fd: self.shutdown.as_ref().map_or(-1, AsRawFd::as_raw_fd),
            events: libc::POLLIN,
            revents: 0,
        }
    }

    fn shutdown_requested(&self) -> Result<bool> {
        if self.shutdown.is_none() {
            return Ok(false);
        }
        let mut signal = self.shutdown_descriptor();
        loop {
            match syscall(unsafe { libc::poll(&mut signal, 1, 0) }) {
                Ok(_) => return Ok(signal.revents != 0),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error).context("poll helper shutdown signal"),
            }
        }
    }

    fn socket_option<T: Copy>(&self, option: libc::c_int) -> io::Result<T> {
        let mut value = mem::MaybeUninit::<T>::uninit();
        let expected = mem::size_of::<T>() as libc::socklen_t;
        let mut length = expected;
        syscall(unsafe {
            libc::getsockopt(
                self.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                value.as_mut_ptr().cast(),
                &mut length,
            )
        })?;
        if length != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "wrong socket option size",
            ));
        }
        Ok(unsafe { value.assume_init() })
    }

    fn check_unnamed_endpoint(&self, peer: bool) -> Result<()> {
        let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
        let mut length = mem::size_of_val(&address) as libc::socklen_t;
        let function = if peer {
            libc::getpeername
        } else {
            libc::getsockname
        };
        syscall(unsafe {
            function(
                self.socket.as_raw_fd(),
                ptr::from_mut(&mut address).cast(),
                &mut length,
            )
        })
        .context("inspect helper socket endpoint")?;
        ensure!(
            address.sun_family == libc::AF_UNIX as libc::sa_family_t
                && length as usize == mem::offset_of!(libc::sockaddr_un, sun_path),
            "helper only accepts connected unnamed Unix socket pairs"
        );
        Ok(())
    }

    pub(super) fn read(&self, buffer: &mut [u8; MAX_MESSAGE]) -> Result<Option<usize>> {
        let mut vector = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        loop {
            if self.shutdown_requested()? {
                return Ok(None);
            }
            // There is deliberately no control buffer. Linux discards any received
            // descriptors and reports MSG_CTRUNC, which fails the connection.
            let mut message: libc::msghdr = unsafe { mem::zeroed() };
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            let length =
                unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
            if length >= 0 {
                ensure!(
                    message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0,
                    "invalid or truncated helper request"
                );
                return Ok((length != 0).then_some(length as usize));
            }
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => (),
                io::ErrorKind::WouldBlock => self.wait(libc::POLLIN, None)?,
                _ => return Err(io::Error::last_os_error()).context("read helper request"),
            }
        }
    }

    pub(super) fn write(&self, bytes: &[u8], fd: Option<BorrowedFd<'_>>) -> Result<()> {
        let mut vector = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        // usize alignment meets Linux cmsghdr alignment.
        let mut control = [0usize; 8];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        if let Some(fd) = fd {
            unsafe {
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen =
                    libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) as _;
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as _;
                ptr::write_unaligned(libc::CMSG_DATA(header).cast(), fd.as_raw_fd());
            }
        }
        let deadline = Instant::now() + WRITE_TIMEOUT;
        loop {
            if self.shutdown_requested()? {
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "helper reply timed out");
            let length = unsafe {
                libc::sendmsg(
                    self.socket.as_raw_fd(),
                    &message,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if length >= 0 {
                ensure!(
                    length as usize == bytes.len(),
                    "partial helper packet write"
                );
                return Ok(());
            }
            match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => (),
                io::ErrorKind::WouldBlock => self.wait(libc::POLLOUT, Some(deadline))?,
                _ => return Err(io::Error::last_os_error()).context("send helper response"),
            }
        }
    }

    fn wait(&self, events: libc::c_short, deadline: Option<Instant>) -> Result<()> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events,
                revents: 0,
            },
            self.shutdown_descriptor(),
        ];
        loop {
            let millis = match deadline {
                None => -1,
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    ensure!(!remaining.is_zero(), "helper reply timed out");
                    i32::try_from(remaining.as_millis())
                        .unwrap_or(i32::MAX)
                        .max(1)
                }
            };
            match syscall(unsafe {
                libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, millis)
            }) {
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error).context("poll helper channel"),
            }
        }
    }
}

pub(super) fn syscall(value: libc::c_int) -> io::Result<libc::c_int> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
