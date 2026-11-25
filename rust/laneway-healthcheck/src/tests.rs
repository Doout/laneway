use super::*;
use tokio::{io::AsyncReadExt, net::TcpListener};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn compatible_duration_syntax() {
    for (input, nanos) in [
        ("2s", 2_000_000_000),
        ("+1s500ms", 1_500_000_000),
        (".5s", 500_000_000),
        ("1.s", 1_000_000_000),
        ("0.5µs25ns", 525),
        ("0.01μs", 10),
    ] {
        assert_eq!(parse_duration(input).unwrap(), Duration::from_nanos(nanos));
    }
    for input in ["", "1", "1day", "1..0s", "2s-1s", "18446744073709551616h"] {
        assert!(parse_duration(input).is_err(), "{input}");
    }
}

#[tokio::test]
async fn tcp_probe_sends_no_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let response = async {
        let (mut stream, _) = timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("test probe never connected")
            .unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    };
    let (result, ()) = tokio::join!(run(args(&["--tcp", &address, "-timeout=1s"])), response);
    result.unwrap();
}

#[tokio::test]
async fn rejects_invalid_probe_arguments() {
    for invalid in [
        vec!["-tcp", ""],
        vec!["-tcp", "0.0.0.0:1"],
        vec!["-tcp", "example.com:443"],
        vec!["-tcp", "127.0.0.1"],
        vec!["-tcp", "127.0.0.1:1", "extra"],
        vec!["-tcp", "127.0.0.1:1", "--", "extra"],
        vec!["-tcp", "127.0.0.1:1", "-unix", "/tmp/socket"],
        vec!["-tcp", "127.0.0.1:1", "-tls-ca", "/missing"],
        vec!["-unix", "/tmp/../socket"],
        vec!["-unix", "/tmp//socket"],
        vec!["-unix", "/tmp/socket\0bad"],
        vec!["-unix", "relative.sock"],
        vec!["-unix", "/tmp/socket", "-timeout", "-1s"],
        vec!["-unix", "/tmp/socket", "-timeout", "10s1ns"],
    ] {
        assert!(run(args(&invalid)).await.is_err(), "{invalid:?}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unix_probe_requires_complete_success_status() {
    use tokio::net::UnixListener;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("probe.sock");
    let listener = UnixListener::bind(&path).unwrap();
    for (status, expected) in [
        ("HTTP/1.1 200 OK\r\n", true),
        ("HTTP/1.1 500 Internal Server Error\r\n", false),
        ("HTTP/1.1 200 OK", false),
    ] {
        let response = async {
            const REQUEST: &[u8] =
                b"GET /v1/status HTTP/1.1\r\nHost: lanewayd\r\nConnection: close\r\n\r\n";
            let (mut stream, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("test probe never connected")
                .unwrap();
            let mut request = [0; REQUEST.len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, REQUEST);
            stream.write_all(status.as_bytes()).await.unwrap();
        };
        let (result, ()) = tokio::join!(
            run(args(&["-unix", path.to_str().unwrap(), "-timeout", "1s"])),
            response
        );
        assert_eq!(result.is_ok(), expected, "{status:?}: {result:?}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unix_probe_rejects_oversized_unterminated_status() {
    use tokio::net::UnixListener;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("probe.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let oversized = vec![b'x'; MAX_STATUS_LINE_BYTES as usize + 1];
        stream.write_all(&oversized).await.unwrap();
        // Leave the socket open to verify the limit fires before EOF or timeout.
        std::future::pending::<()>().await;
    });
    let error = run(args(&["-unix", path.to_str().unwrap(), "-timeout", "1s"]))
        .await
        .unwrap_err();
    server.abort();
    assert_eq!(
        error.to_string(),
        format!("Unix status line exceeds {MAX_STATUS_LINE_BYTES} bytes")
    );
}

#[tokio::test]
async fn tls_probe_rejects_oversized_ca_file() {
    let directory = tempfile::tempdir().unwrap();
    let ca_file = directory.path().join("ca.crt");
    fs::File::create(&ca_file)
        .unwrap()
        .set_len(MAX_CA_BYTES + 1)
        .unwrap();

    let error = run(args(&[
        "-tcp",
        "127.0.0.1:1",
        "-tls-ca",
        ca_file.to_str().unwrap(),
        "-tls-server-name",
        "controller.example",
    ]))
    .await
    .unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        format!("read TLS CA: file exceeds {MAX_CA_BYTES} bytes")
    );
}

#[tokio::test]
async fn tls_probe_verifies_identity_with_custom_roots() {
    use rcgen::{CertificateParams, IsCa, KeyPair};
    use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
    use tokio_rustls::TlsAcceptor;

    let ca_key = KeyPair::generate().unwrap();
    let mut parameters = CertificateParams::default();
    parameters.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(parameters, ca_key).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["controller.example".to_owned()])
        .unwrap()
        .signed_by(&server_key, &ca)
        .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let ca_file = directory.path().join("ca.crt");
    fs::write(&ca_file, ca.pem()).unwrap();
    let server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();

    for (identity, expected) in [("controller.example", true), ("wrong.example", false)] {
        let response = async {
            let (stream, _) = timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("test probe never connected")
                .unwrap();
            if let Ok(mut stream) = acceptor.accept(stream).await {
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
            }
        };
        let (result, ()) = tokio::join!(
            run(args(&[
                "-tcp",
                &address,
                "-tls-ca",
                ca_file.to_str().unwrap(),
                "-tls-server-name",
                identity,
                "-timeout",
                "1s",
            ])),
            response
        );
        assert_eq!(result.is_ok(), expected, "{identity}: {result:?}");
    }
}

#[tokio::test]
async fn stalled_tls_handshake_respects_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let certificate =
        rcgen::generate_simple_self_signed(vec!["controller.example".to_owned()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let ca_file = directory.path().join("ca.crt");
    fs::write(&ca_file, certificate.cert.pem()).unwrap();
    let result = run(args(&[
        "-tcp",
        &address,
        "-tls-ca",
        ca_file.to_str().unwrap(),
        "-tls-server-name",
        "controller.example",
        "-timeout",
        "30ms",
    ]))
    .await
    .unwrap_err();
    assert!(
        format!("{result:#}").contains("deadline exceeded"),
        "{result:#}"
    );
}
