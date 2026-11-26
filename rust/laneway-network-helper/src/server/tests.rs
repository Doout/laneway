use std::{
    fs::File,
    mem,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
    thread,
};

use serde_json::Value;

use super::*;

fn pair(kind: libc::c_int) -> (OwnedFd, OwnedFd) {
    let mut files = [-1; 2];
    socket::syscall(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            kind | libc::SOCK_CLOEXEC,
            0,
            files.as_mut_ptr(),
        )
    })
    .unwrap();
    let [client, server] = files.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    (client, server)
}

#[test]
fn sets_close_on_exec_for_inherited_control_descriptor() {
    let (_client, server) = pair(libc::SOCK_SEQPACKET);
    let inherited =
        socket::syscall(unsafe { libc::fcntl(server.as_raw_fd(), libc::F_DUPFD, 10) }).unwrap();
    let inherited = unsafe { OwnedFd::from_raw_fd(inherited) };
    let flags =
        || socket::syscall(unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_GETFD) }).unwrap();
    assert_eq!(flags() & libc::FD_CLOEXEC, 0);
    let channel = socket::Channel::open(inherited.as_fd()).unwrap();
    drop(channel);
    assert_ne!(flags() & libc::FD_CLOEXEC, 0);
}

fn reply(channel: &OwnedFd) -> (Value, Option<OwnedFd>) {
    let mut bytes = [0u8; 8192];
    let mut control = [0usize; 8];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&control) as _;
    let count = unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    assert!(count > 0);
    assert_eq!(message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
    let fd = unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            None
        } else {
            assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!(
                (*header).cmsg_len as usize,
                libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as usize,
            );
            assert!(libc::CMSG_NXTHDR(&message, header).is_null());
            let fd = libc::CMSG_DATA(header)
                .cast::<libc::c_int>()
                .read_unaligned();
            assert_ne!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
            Some(OwnedFd::from_raw_fd(fd))
        }
    };
    (
        serde_json::from_slice(&bytes[..count as usize]).unwrap(),
        fd,
    )
}

struct Fixture(Arc<Mutex<Vec<&'static str>>>);

struct Active {
    events: Arc<Mutex<Vec<&'static str>>>,
    packet: File,
}

impl Backend for Fixture {
    type Session = Active;

    fn setup(self, request: Setup, deadline: Instant) -> Result<Active> {
        assert!(deadline > Instant::now());
        assert_eq!(request.name, "lane0");
        assert_eq!(request.mtu, 1200);
        assert_eq!(
            request.addresses,
            ["100.96.0.1/32".parse::<ipnet::IpNet>().unwrap()]
        );
        self.0.lock().unwrap().push("setup");
        Ok(Active {
            events: self.0,
            packet: File::open("/dev/null")?,
        })
    }
}

impl Session for Active {
    fn packet(&self) -> BorrowedFd<'_> {
        self.packet.as_fd()
    }
    fn interface(&self) -> &str {
        "lane0"
    }

    fn apply(&mut self, change: Change, deadline: Instant) -> Result<()> {
        assert!(deadline > Instant::now());
        self.events.lock().unwrap().push(match change {
            Change::Routes(routes) => {
                assert!(routes.routes.is_empty());
                "routes"
            }
            Change::Exit(_) => "exit",
            Change::RestoreExit => "restore-exit",
            Change::Dns(_) => "dns",
            Change::RestoreDns => "restore-dns",
        });
        Ok(())
    }

    fn restore(self, deadline: Instant) -> Result<()> {
        assert!(deadline > Instant::now());
        self.events.lock().unwrap().push("restore");
        Ok(())
    }
}

const SETUP: &[u8] = br#"{"version":1,"id":1,"op":"setup","setup":{"name":"lane0","mtu":1200,"addresses":["100.96.0.1/32"],"routes":{}}}"#;

#[test]
fn go_wire_setup_routes_restore_and_descriptor_handoff() {
    let (client, server) = pair(libc::SOCK_SEQPACKET);
    let sender = socket::Channel::open(client.as_fd()).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let backend = Fixture(Arc::clone(&events));
    let harden_events = Arc::clone(&events);
    let handle = thread::spawn(move || {
        serve(
            socket::Channel::open(server.as_fd()).unwrap(),
            backend,
            || {
                harden_events.lock().unwrap().push("harden");
                Ok(())
            },
        )
    });

    sender.write(SETUP, None).unwrap();
    let (setup, packet) = reply(&client);
    assert!(packet.is_some());
    assert_eq!(setup["version"], 1);
    assert_eq!(setup["id"], 1);
    assert_eq!(setup["ok"], true);
    assert_eq!(setup["interface_name"], "lane0");
    assert_eq!(setup["helper_pid"], std::process::id());
    assert_eq!(events.lock().unwrap().as_slice(), ["setup", "harden"]);

    for (request, expected) in [
        (&br#"{"version":1,"id":1,"op":"restore-dns"}"#[..], false),
        (&br#"{"version":1,"id":2,"op":"apply-routes","routes":{"routes":[{"prefix":"100.64.0.0/10"}],"bypasses":["100.96.0.5"]}}"#[..], true),
        (&br#"{"version":1,"id":3,"op":"apply-exit-routes","exit_routes":{"tunnel_prefixes":["0.0.0.0/1","128.0.0.0/1"],"transport_bypasses":["192.0.2.1"]}}"#[..], true),
        (&br#"{"version":1,"id":4,"op":"apply-dns","dns":{"servers":["192.0.2.53"]}}"#[..], true),
        (&br#"{"version":1,"id":5,"op":"restore-exit-routes"}"#[..], true),
        (&br#"{"version":1,"id":6,"op":"restore-dns"}"#[..], true),
        (&br#"{"version":1,"id":7,"op":"close"}"#[..], true),
    ] {
        sender.write(request, None).unwrap();
        let (response, descriptor) = reply(&client);
        assert_eq!(response["ok"], expected);
        assert!(response.get("interface_name").is_none());
        assert!(descriptor.is_none());
    }
    handle.join().unwrap().unwrap();
    assert_eq!(
        events.lock().unwrap().as_slice(),
        [
            "setup",
            "harden",
            "routes",
            "exit",
            "dns",
            "restore-exit",
            "restore-dns",
            "restore"
        ]
    );
}

#[test]
fn rejects_stream_peer_and_requests_with_rights_or_truncation() {
    let (_client, server) = pair(libc::SOCK_STREAM);
    assert!(socket::Channel::open(server.as_fd()).is_err());

    for (bytes, rights) in [(SETUP.to_vec(), true), (vec![b'x'; MAX_MESSAGE + 1], false)] {
        let (client, server) = pair(libc::SOCK_SEQPACKET);
        let sender = socket::Channel::open(client.as_fd()).unwrap();
        let reader = socket::Channel::open(server.as_fd()).unwrap();
        let file = File::open("/dev/null").unwrap();
        sender.write(&bytes, rights.then(|| file.as_fd())).unwrap();
        assert!(reader.read(&mut [0; MAX_MESSAGE]).is_err());
    }
}

#[test]
fn peer_death_or_hardening_failure_restores_session() {
    for hardening_fails in [false, true] {
        let (client, server) = pair(libc::SOCK_SEQPACKET);
        let sender = socket::Channel::open(client.as_fd()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let backend = Fixture(Arc::clone(&events));
        let handle = thread::spawn(move || {
            serve(
                socket::Channel::open(server.as_fd()).unwrap(),
                backend,
                || {
                    ensure!(!hardening_fails, "fixture hardening failed");
                    Ok(())
                },
            )
        });
        sender.write(SETUP, None).unwrap();
        let (response, descriptor) = reply(&client);
        assert_eq!(response["ok"], !hardening_fails);
        assert_eq!(descriptor.is_some(), !hardening_fails);
        drop(sender);
        drop(client);
        assert_eq!(handle.join().unwrap().is_err(), hardening_fails);
        assert_eq!(events.lock().unwrap().as_slice(), ["setup", "restore"]);
    }
}

#[test]
fn rejects_invalid_operation_json_without_backend_mutation() {
    for input in [
        &br#"{"version":1,"id":1,"op":"apply-dns","dns":{"servers":["224.0.0.1"]}}"#[..],
        &br#"{"version":1,"id":1,"op":"apply-routes","routes":{"routes":[{"prefix":"10.1.1.1/8"}]}}"#[..],
        &br#"{"version":1,"id":1,"op":"apply-routes","routes":{"routes":[{"prefix":"0.0.0.0/0"}]}}"#[..],
        &br#"{"version":1,"id":1,"op":"close","routes":{}}"#[..],
        &br#"{"version":1,"id":1,"op":"close","unknown":true}"#[..],
        &br#"{"version":1,"id":1,"id":2,"op":"close"}"#[..],
        &br#"{"version":1,"id":1,"op":"close"} {}"#[..],
    ] {
        assert!(Request::decode(input).and_then(Request::operation).is_err(), "{input:?}");
    }
}

#[test]
fn malformed_close_is_terminal_and_acknowledges_after_restore() {
    let (client, server) = pair(libc::SOCK_SEQPACKET);
    let sender = socket::Channel::open(client.as_fd()).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let backend = Fixture(Arc::clone(&events));
    let handle = thread::spawn(move || {
        serve(
            socket::Channel::open(server.as_fd()).unwrap(),
            backend,
            || Ok(()),
        )
    });
    sender.write(SETUP, None).unwrap();
    assert_eq!(reply(&client).0["ok"], true);
    sender
        .write(br#"{"version":1,"id":2,"op":"close","routes":{}}"#, None)
        .unwrap();
    assert_eq!(reply(&client).0["ok"], false);
    assert_eq!(events.lock().unwrap().as_slice(), ["setup", "restore"]);
    assert!(handle.join().unwrap().is_err());
}

#[test]
fn rejects_even_connected_seqpacket_sockets_with_a_named_endpoint() {
    let create = || {
        let fd = socket::syscall(unsafe {
            libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0)
        })
        .unwrap();
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    let listener = create();
    let client = create();
    assert!(socket::Channel::open(client.as_fd()).is_err());
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // A Linux abstract name creates no filesystem entry.
    let name = format!("laneway-helper-test-{}", std::process::id());
    for (destination, byte) in address.sun_path[1..].iter_mut().zip(name.bytes()) {
        *destination = byte as libc::c_char;
    }
    let length = (mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len()) as libc::socklen_t;
    let pointer = (&raw const address).cast();
    socket::syscall(unsafe { libc::bind(listener.as_raw_fd(), pointer, length) }).unwrap();
    socket::syscall(unsafe { libc::listen(listener.as_raw_fd(), 1) }).unwrap();
    socket::syscall(unsafe { libc::connect(client.as_raw_fd(), pointer, length) }).unwrap();
    let server = socket::syscall(unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    })
    .unwrap();
    let server = unsafe { OwnedFd::from_raw_fd(server) };
    assert!(socket::Channel::open(client.as_fd()).is_err());
    assert!(socket::Channel::open(server.as_fd()).is_err());
}
