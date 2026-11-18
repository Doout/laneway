//! Client for the installed, credential-free macOS network helper.
use std::{
    fs,
    io::{self, ErrorKind, Read, Write},
    mem,
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt;

const HELPER: &str = "/Library/PrivilegedHelperTools/laneway-network-helper";
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FRAME: usize = 64 << 10;

#[derive(Serialize)]
pub(super) struct Setup {
    pub name: String,
    pub mtu: u16,
    pub addresses: Vec<String>,
    pub routes: RoutePlan,
}

#[derive(Serialize, Default)]
pub(super) struct RoutePlan {
    pub routes: Vec<Route>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bypasses: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct Route {
    pub prefix: String,
    pub metric: u32,
}

#[derive(Serialize)]
struct Request<'a> {
    version: u8,
    id: u64,
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    setup: Option<&'a Setup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    routes: Option<&'a RoutePlan>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u8,
    id: u64,
    ok: bool,
    error: Option<String>,
    helper_pid: Option<i32>,
    interface_name: Option<String>,
}

pub(super) struct Session {
    socket: UnixStream,
    child: Option<Child>,
    last_id: u64,
}

impl Session {
    pub fn open(setup: &Setup) -> Result<(Self, String, OwnedFd)> {
        let helper = trusted_executable(Path::new(HELPER))
            .context("macOS network helper is not installed or trusted")?;
        let (socket, inherited) = UnixStream::pair()?;
        let mut command = if unsafe { libc::geteuid() } == 0 {
            Command::new(helper)
        } else {
            let mut sudo = Command::new(trusted_executable(Path::new("/usr/bin/sudo"))?);
            sudo.arg("--").arg(helper);
            sudo
        };
        let keep: OwnedFd = inherited.try_clone()?.into();
        let transfer: OwnedFd = inherited.into();
        command
            .args(["_network-helper", "--control-fd=0"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(transfer)
            .stdout(keep)
            .stderr(Stdio::inherit());
        // Dropping Command closes the parent copies of the helper's end.
        let child = command.spawn().context("start macOS network helper")?;
        drop(command);
        let mut session = Self {
            socket,
            child: Some(child),
            last_id: 0,
        };
        session.socket.set_read_timeout(Some(TIMEOUT))?;
        session.socket.set_write_timeout(Some(TIMEOUT))?;
        let (name, fd) = session.setup(setup)?;
        Ok((session, name, fd))
    }

    fn setup(&mut self, setup: &Setup) -> Result<(String, OwnedFd)> {
        let (reply, mut rights) = self.call("setup", Some(setup), None)?;
        ensure!(
            reply.helper_pid.is_some_and(|pid| pid > 0) && rights.len() == 1,
            "helper omitted its process identity or did not send one tunnel descriptor"
        );
        let name = reply
            .interface_name
            .context("helper omitted tunnel interface name")?;
        Ok((name, rights.pop().expect("one right verified")))
    }

    fn call(
        &mut self,
        op: &str,
        setup: Option<&Setup>,
        routes: Option<&RoutePlan>,
    ) -> Result<(Reply, Vec<OwnedFd>)> {
        self.last_id = self
            .last_id
            .checked_add(1)
            .context("network helper request ID exhausted")?;
        let id = self.last_id;
        let bytes = serde_json::to_vec(&Request {
            version: 1,
            id,
            op,
            setup,
            routes,
        })?;
        ensure!(
            (1..=MAX_FRAME).contains(&bytes.len()),
            "network helper request is too large"
        );
        let result = (|| {
            self.socket.write_all(&(bytes.len() as u32).to_be_bytes())?;
            self.socket.write_all(&bytes)?;
            let (reply, rights) = read_reply(&mut self.socket)?;
            ensure!(
                reply.version == 1 && reply.id == id,
                "mismatched network helper response"
            );
            ensure!(
                op == "setup" || rights.is_empty(),
                "unexpected network helper descriptor"
            );
            ensure!(
                reply.ok,
                "network helper rejected {op}: {}",
                reply.error.as_deref().unwrap_or("no reason given")
            );
            Ok((reply, rights))
        })();
        // An interrupted frame must not be reused. EOF is also the helper's
        // authoritative rollback signal when it never receives a close request.
        if result.is_err() {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
        result
    }

    pub fn replace_routes(&mut self, routes: &RoutePlan) -> Result<()> {
        self.call("apply-routes", None, Some(routes)).map(|_| ())
    }

    pub fn close(mut self) -> Result<()> {
        let reply = self.call("close", None, None).map(|_| ());
        let _ = self.socket.shutdown(Shutdown::Both);
        if let Some(child) = &mut self.child {
            let status = child
                .wait_timeout(TIMEOUT)?
                .context("macOS helper did not finish route cleanup")?;
            self.child = None;
            ensure!(
                status.success(),
                "macOS helper did not exit cleanly: {status}"
            );
        }
        reply
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        if let Some(mut child) = self.child.take() {
            // Let the helper restore routes before reaping, even if setup was
            // interrupted. A detached wait never needs access to node keys.
            let _ = std::thread::Builder::new()
                .name("laneway-helper-reap".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

fn trusted_executable(path: &Path) -> Result<PathBuf> {
    let resolved = fs::canonicalize(path)?;
    for (index, item) in resolved.ancestors().enumerate() {
        let meta = fs::symlink_metadata(item)?;
        ensure!(
            meta.uid() == 0
                && meta.mode() & 0o022 == 0
                && if index == 0 {
                    meta.is_file()
                } else {
                    meta.is_dir()
                },
            "unsafe network-helper executable or parent: {}",
            item.display()
        );
    }
    Ok(resolved)
}

// macOS uses stream framing but transmits the descriptor alongside the first
// bytes of the 4-byte length. recvmsg must run before any ordinary read.
fn read_reply(socket: &mut UnixStream) -> Result<(Reply, Vec<OwnedFd>)> {
    #[repr(align(8))]
    struct Aligned([u8; 128]);
    let mut control = Aligned([0; 128]);
    let mut length = [0u8; 4];
    let mut iov = libc::iovec {
        iov_base: length.as_mut_ptr().cast(),
        iov_len: length.len(),
    };
    // SAFETY: zero is a valid empty msghdr. The only output pointers refer
    // to live, suitably aligned buffers for the duration of recvmsg.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = control.0.len() as _;
    let n = loop {
        // SAFETY: all buffers described by msg are valid and writable.
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
        if n >= 0 {
            break n as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error.into());
        }
    };
    let mut rights = Vec::new();
    let mut unsupported = false;
    // SAFETY: kernel-supplied ancillary data is bounded by msg_controllen.
    // Each SCM_RIGHTS integer transfers one newly owned descriptor.
    unsafe {
        let mut hdr = libc::CMSG_FIRSTHDR(&msg);
        let end = control.0.as_ptr() as usize + msg.msg_controllen as usize;
        while !hdr.is_null() {
            let payload = libc::CMSG_DATA(hdr);
            let bytes = (*hdr).cmsg_len as usize;
            let overhead = payload as usize - hdr as usize;
            if bytes < overhead || bytes > end - hdr as usize {
                unsupported = true;
                break;
            }
            if (*hdr).cmsg_level == libc::SOL_SOCKET && (*hdr).cmsg_type == libc::SCM_RIGHTS {
                let size = mem::size_of::<libc::c_int>();
                unsupported |= !(bytes - overhead).is_multiple_of(size);
                for index in 0..(bytes - overhead) / size {
                    let fd = payload.cast::<libc::c_int>().add(index).read_unaligned();
                    rights.push(OwnedFd::from_raw_fd(fd));
                }
            } else {
                unsupported = true;
            }
            hdr = libc::CMSG_NXTHDR(&msg, hdr);
        }
        for fd in &rights {
            ensure!(
                libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) == 0,
                "protect network helper descriptor from inheritance"
            );
        }
    }
    ensure!(
        !unsupported
            && msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0
            && n != 0
            && n <= 4,
        "invalid or truncated network helper response"
    );
    socket.read_exact(&mut length[n..])?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        (1..=MAX_FRAME).contains(&length),
        "invalid network helper frame length"
    );
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes)?;
    Ok((serde_json::from_slice(&bytes)?, rights))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::os::unix::net::UnixDatagram;

    fn read_request(socket: &mut UnixStream) -> Result<Value> {
        let mut length = [0; 4];
        socket.read_exact(&mut length)?;
        let mut body = vec![0; u32::from_be_bytes(length) as usize];
        socket.read_exact(&mut body)?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn reply(socket: &mut UnixStream, payload: Value, fds: &[libc::c_int]) -> Result<()> {
        let bytes = serde_json::to_vec(&payload)?;
        let length = (bytes.len() as u32).to_be_bytes();
        if fds.is_empty() {
            socket.write_all(&length)?;
        } else {
            // Attach SCM_RIGHTS to only one byte to exercise partial reads
            // of the stream length field.
            #[repr(align(8))]
            struct Aligned([u8; 128]);
            let mut ancillary = Aligned([0; 128]);
            let mut iov = libc::iovec {
                iov_base: length.as_ptr().cast_mut().cast(),
                iov_len: 1,
            };
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = ancillary.0.as_mut_ptr().cast();
            let width = mem::size_of_val(fds);
            // SAFETY: the fixed aligned buffer is larger than this bounded
            // test's control header and descriptor payload, and all fields
            // remain live while sendmsg copies them.
            unsafe {
                assert!(libc::CMSG_SPACE(width as _) as usize <= ancillary.0.len());
                msg.msg_controllen = libc::CMSG_SPACE(width as _);
                let header = libc::CMSG_FIRSTHDR(&msg);
                (*header).cmsg_len = libc::CMSG_LEN(width as _);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(header),
                    width,
                );
                assert_eq!(libc::sendmsg(socket.as_raw_fd(), &msg, 0), 1);
            }
            socket.write_all(&length[1..])?;
        }
        socket.write_all(&bytes)?;
        Ok(())
    }

    fn setup_request() -> Setup {
        Setup {
            name: "utun".into(),
            mtu: 1280,
            addresses: vec!["100.96.0.7/32".into()],
            routes: RoutePlan::default(),
        }
    }

    #[test]
    fn helper_stream_adopts_one_right_and_updates_routes_until_close() -> Result<()> {
        let (client, mut helper) = UnixStream::pair()?;
        for stream in [&client, &helper] {
            stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        }
        let (tun, peer) = UnixDatagram::pair()?;
        let server = std::thread::spawn(move || -> Result<()> {
            let message = read_request(&mut helper)?;
            assert_eq!(message["op"], "setup");
            assert_eq!(message["setup"]["addresses"], json!(["100.96.0.7/32"]));
            reply(
                &mut helper,
                json!({"version":1,"id":1,"ok":true,"helper_pid":123,"interface_name":"utun7"}),
                &[tun.as_raw_fd()],
            )?;
            for (id, op) in [(2, "apply-routes"), (3, "close")] {
                let message = read_request(&mut helper)?;
                assert_eq!(message["id"], id);
                assert_eq!(message["op"], op);
                if id == 2 {
                    assert_eq!(message["routes"]["routes"][0]["prefix"], "100.96.0.9/32");
                    assert_eq!(message["routes"]["bypasses"], json!(["192.0.2.20"]));
                }
                reply(&mut helper, json!({"version":1,"id":id,"ok":true}), &[])?;
            }
            Ok(())
        });
        let mut client = Session {
            socket: client,
            child: None,
            last_id: 0,
        };
        let (name, fd) = client.setup(&setup_request())?;
        assert_eq!(name, "utun7");
        // SAFETY: F_GETFD accepts this still-owned descriptor.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        UnixDatagram::from(fd).send(b"packet")?;
        peer.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut bytes = [0; 10];
        let size = peer.recv(&mut bytes)?;
        assert_eq!(&bytes[..size], b"packet");
        client.replace_routes(&RoutePlan {
            routes: vec![Route {
                prefix: "100.96.0.9/32".into(),
                metric: 100,
            }],
            bypasses: vec!["192.0.2.20".into()],
        })?;
        client.close()?;
        server.join().expect("test server panicked")?;
        Ok(())
    }

    #[test]
    fn reply_rejects_extra_descriptors_and_invalid_lengths() -> Result<()> {
        let (client, mut helper) = UnixStream::pair()?;
        let (one, two) = UnixDatagram::pair()?;
        reply(
            &mut helper,
            json!({"version":1,"id":1,"ok":true,"helper_pid":123,"interface_name":"utun7"}),
            &[one.as_raw_fd(), two.as_raw_fd()],
        )?;
        let mut client = Session {
            socket: client,
            child: None,
            last_id: 0,
        };
        assert!(client.setup(&setup_request()).is_err());

        let (mut client, mut helper) = UnixStream::pair()?;
        helper.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())?;
        assert!(read_reply(&mut client).is_err());
        Ok(())
    }
}
