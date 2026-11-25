#![cfg(target_os = "linux")]

use std::{
    ffi::{OsStr, OsString},
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixListener,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

const CLI: &str = env!("CARGO_BIN_EXE_laneway");

fn request(args: &[&str], endpoint: &str, status: &str, body: Vec<u8>) -> Output {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("d.sock");
    let listener = UnixListener::bind(&path).unwrap();
    request_on_socket(listener, path.as_os_str(), args, endpoint, status, body)
}

fn request_on_socket(
    listener: UnixListener,
    socket: &OsStr,
    args: &[&str],
    endpoint: &str,
    status: &str,
    body: Vec<u8>,
) -> Output {
    listener.set_nonblocking(true).unwrap();
    let expected = format!("GET /v1/{endpoint} HTTP/1.1\r\n");
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("CLI failed to connect to fixture socket: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 4096);
            let mut byte = [0_u8];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(expected.as_bytes()), "{request:?}");
        stream.write_all(headers.as_bytes()).unwrap();
        let _ = stream.write_all(&body);
    });

    let mut socket_option = OsString::from("-socket=");
    socket_option.push(socket);
    let output = Command::new(CLI)
        .args(args.iter().map(OsStr::new))
        .arg(socket_option)
        .output()
        .unwrap();
    server.join().unwrap();
    output
}

fn stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn socket_status_and_up_share_the_status_endpoint() {
    let body = br#"{"name":"fixture<&>","network_id":"net","running":true,"selected_routes":["10.0.0.0/8"],"mtu":1420}"#;
    let output = request(
        &["node", "status", "-config", "/no/such/config"],
        "status",
        "200 OK",
        body.to_vec(),
    );
    assert_eq!(
        stdout(output),
        "actor=node node= name=fixture<&> network=net overlay= interface= mtu=1420 relay= running=true\n\
         version= control= packet=0 capabilities= path=\n\
         selected_routes=10.0.0.0/8\n\
         connections=0 reconnects=0 sent=0 received=0 dropped=0\n\
         tcp_connections=0 quic_failures=0 tcp_failures=0\n"
    );
    let json = stdout(request(
        &["up", "--json"],
        "status",
        "200 OK",
        body.to_vec(),
    ));
    assert!(
        json.contains(r#""name": "fixture\u003c\u0026\u003e""#),
        "{json}"
    );
    let decoded: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded["running"], true);
    assert_eq!(decoded["actor"], "");
    assert_eq!(decoded["overlay_addresses"], serde_json::Value::Null);
    assert_eq!(decoded["metrics"]["quic_failures"], 0);
}

#[test]
fn socket_list_commands_preserve_text_columns_and_null_json() {
    let peers = br#"[{"node_id":"one","name":"named","path":"direct","prefixes":["10.0.0.1/32"]},{"node_id":"two","path":"relay","prefixes":null}]"#;
    assert_eq!(
        stdout(request(
            &["node", "peers"],
            "peers",
            "200 OK",
            peers.to_vec()
        )),
        "named\tone\tdirect\t10.0.0.1/32\ntwo\trelay\t\n"
    );
    let routes = br#"[{"prefix":"10.0.0.2/32","via_node":"two","kind":"overlay"}]"#;
    assert_eq!(
        stdout(request(&["routes"], "routes", "200 OK", routes.to_vec())),
        "10.0.0.2/32\tvia two\toverlay\n"
    );
    assert_eq!(
        stdout(request(
            &["node", "routes", "--json=1"],
            "routes",
            "200 OK",
            b"null".to_vec()
        )),
        "null\n"
    );
}

#[test]
fn socket_commands_reject_bad_status_oversized_and_invalid_json() {
    for (status, body, expected) in [
        (
            "503 Service Unavailable",
            b"{}".to_vec(),
            "returned 503 Service Unavailable",
        ),
        ("200 OK", br#"{"unknown":42}"#.to_vec(), "unknown field"),
        ("200 OK", b"{} {}".to_vec(), "trailing characters"),
        ("200 OK", vec![b' '; (1 << 20) + 1], "response is oversized"),
    ] {
        let output = request(&["status"], "status", status, body);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(expected), "{stderr}");
    }
}

#[test]
fn node_flags_can_precede_help() {
    for (args, usage) in [
        (&["start", "--system", "--help"][..], "Usage: laneway start"),
        (
            &["configure", "--check", "-h"][..],
            "Usage: laneway configure",
        ),
        (
            &["node", "status", "-json", "-h"][..],
            "Usage: laneway node status",
        ),
    ] {
        assert!(stdout(Command::new(CLI).args(args).output().unwrap()).contains(usage));
    }
}

#[test]
fn config_file_selects_local_socket_without_a_helper() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("status.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let config = directory.path().join("with space.toml");
    std::fs::write(
        &config,
        include_str!("../../../deploy/examples/relay.toml")
            .replace("\"/run/laneway/relay.sock\"", &format!("{socket:?}")),
    )
    .unwrap();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("CLI did not use configured socket: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut head = [0; 2048];
        let n = stream.read(&mut head).unwrap();
        assert!(head[..n].starts_with(b"GET /v1/peers "));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]")
            .unwrap();
    });
    let output = Command::new(CLI)
        .args(["node", "peers", "--json", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert_eq!(stdout(output), "[]\n");
    server.join().unwrap();
}

#[test]
fn socket_override_accepts_linux_abstract_address() {
    use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};

    let name = format!("laneway-local-test-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let listener = UnixListener::bind_addr(&address).unwrap();
    let socket = OsString::from(format!("@{name}"));
    let output = request_on_socket(
        listener,
        &socket,
        &["peers", "--json"],
        "peers",
        "200 OK",
        b"[]".to_vec(),
    );
    assert_eq!(stdout(output), "[]\n");
}

#[test]
fn exit_selection_uses_existing_local_api() {
    use std::io::{BufRead, BufReader};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("node.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        for enabled in [true, false] {
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("no exit selection: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut r = BufReader::new(stream);
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            assert_eq!(line, "POST /v1/exit HTTP/1.1\r\n");
            let mut length = 0;
            loop {
                line.clear();
                r.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = n.trim().parse().unwrap();
                }
                assert!(!line.is_empty());
            }
            assert!(length < 1024);
            let mut body = vec![0; length];
            r.read_exact(&mut body).unwrap();
            let selection: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let want = if enabled {
                serde_json::json!({"enabled":true,"selected_node_id":"11111111111111111111111111111111"})
            } else {
                serde_json::json!({"enabled":false})
            };
            assert_eq!(selection, want);
            r.get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
        }
    });
    for cmd in [
        vec!["node", "exit", "use", "11111111111111111111111111111111"],
        vec!["exit", "disable"],
    ] {
        let output = Command::new(CLI)
            .args(cmd)
            .arg("-socket")
            .arg(&socket)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    server.join().unwrap();
}
