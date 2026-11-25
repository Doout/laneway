use std::{
    fs,
    io::{self, Read, Write},
    net::IpAddr,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use reqwest::{
    StatusCode, Url,
    blocking::{Client, ClientBuilder},
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
    tls::Version,
};
use sha2::{Digest, Sha256};

use super::metadata::{
    Artifact, Metadata, decode, https_origin, now_unix, valid_https_url, validate_dns_name,
};

const WELL_KNOWN_PATH: &str = "/.well-known/laneway/bootstrap.json";

fn discovery_url(authority: &str) -> Result<String> {
    let origin = if authority.contains("://") {
        authority.to_owned()
    } else {
        format!("https://{authority}")
    };
    let (raw_authority, parsed) =
        https_origin(&origin).context("bootstrap: discovery authority")?;
    let host = parsed
        .host_str()
        .context("bootstrap: discovery authority has no host")?;
    ensure!(
        !host.starts_with('[') && host.parse::<IpAddr>().is_err(),
        "bootstrap: discovery requires a DNS name authenticated by public Web PKI"
    );
    let raw_host = raw_authority
        .split_once(':')
        .map_or(raw_authority, |(host, _)| host);
    validate_dns_name(
        &raw_host
            .strip_suffix('.')
            .unwrap_or(raw_host)
            .to_ascii_lowercase(),
    )?;
    Ok(format!("https://{raw_authority}{WELL_KNOWN_PATH}"))
}

fn client_builder(timeout: Duration) -> ClientBuilder {
    Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .min_tls_version(Version::TLS_1_3)
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
}

fn discovery_client() -> ClientBuilder {
    client_builder(Duration::from_secs(15)).redirect(Policy::custom(|attempt| {
        attempt.error("bootstrap: redirects are not allowed")
    }))
}

pub(crate) fn fetch(authority: &str) -> Result<Metadata> {
    let url = discovery_url(authority)?;
    fetch_from(&discovery_client().build()?, &url, now_unix()?)
}

fn fetch_from(client: &Client, url: &str, now: i64) -> Result<Metadata> {
    let response = client
        .get(url)
        .header(ACCEPT, "application/json")
        .send()
        .context("bootstrap: fetch metadata")?;
    ensure!(
        response.status() == StatusCode::OK,
        "bootstrap: metadata endpoint returned HTTP {}",
        response.status().as_u16()
    );
    let media_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok());
    ensure!(
        media_type.is_some_and(|value| value.essence_str() == "application/json"),
        "bootstrap: metadata response is not application/json"
    );
    // The TLS client uses public trust roots and authenticates the requested
    // DNS name. A discovery response never crosses to another origin.
    decode(response, now)
}

fn safe_artifact_redirect(url: &Url, previous: usize) -> bool {
    previous < 5 && valid_https_url(url)
}

fn artifact_client() -> Result<Client> {
    Ok(client_builder(Duration::from_secs(5 * 60))
        .redirect(Policy::custom(|attempt| {
            if safe_artifact_redirect(attempt.url(), attempt.previous().len()) {
                attempt.follow()
            } else {
                attempt.error("bootstrap: unsafe or excessive artifact redirect")
            }
        }))
        .build()?)
}

pub(crate) fn download_artifact(artifact: &Artifact, destination: &Path) -> Result<()> {
    let url = artifact.url()?;
    let size = artifact.expected_size()?;
    let digest = artifact.expected_digest()?;
    ensure!(
        destination.file_name().is_some(),
        "bootstrap: artifact destination must name a file"
    );
    match fs::symlink_metadata(destination) {
        Ok(_) => anyhow::bail!("bootstrap: artifact destination already exists"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("bootstrap: inspect artifact destination"),
    }
    let response = artifact_client()?
        .get(url)
        .header(ACCEPT, "application/octet-stream")
        .send()
        .context("bootstrap: download artifact")?;
    ensure!(
        response.status() == StatusCode::OK,
        "bootstrap: artifact download was not a successful Web PKI authenticated response"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= size),
        "bootstrap: artifact response exceeds authenticated size"
    );
    publish_artifact(response, destination, size, digest)
}

fn publish_artifact(
    source: impl Read,
    destination: &Path,
    size: u64,
    digest: [u8; 32],
) -> Result<()> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".laneway-artifact-")
        .tempfile_in(parent)
        .context("bootstrap: create artifact temporary file")?;
    verify_and_copy(source, temporary.as_file_mut(), size, digest)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(destination)
        .map_err(|err| err.error)
        .context("bootstrap: publish artifact without overwrite")?;
    Ok(())
}

fn verify_and_copy(
    source: impl Read,
    mut destination: impl Write,
    expected_size: u64,
    expected_digest: [u8; 32],
) -> Result<()> {
    let mut source = source.take(expected_size + 1);
    let mut hash = Sha256::new();
    let mut bytes = [0; 16 << 10];
    let mut size = 0;
    loop {
        let read = source
            .read(&mut bytes)
            .context("bootstrap: read artifact")?;
        if read == 0 {
            break;
        }
        let data = &bytes[..read];
        hash.update(data);
        size += read as u64;
        destination
            .write_all(data)
            .context("bootstrap: save artifact")?;
    }
    ensure!(
        size == expected_size,
        "bootstrap: artifact size {size} does not match authenticated size {expected_size}"
    );
    ensure!(
        hash.finalize()[..] == expected_digest,
        "bootstrap: artifact SHA-256 does not match authenticated metadata"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_keeps_the_requested_dns_origin_and_rejects_invalid_origins() {
        assert_eq!(
            discovery_url("lane.example.test:443").unwrap(),
            format!("https://lane.example.test:443{WELL_KNOWN_PATH}")
        );
        assert_eq!(
            discovery_url("HTTPS://Lane.Example.Test.:8443/").unwrap(),
            format!("https://Lane.Example.Test.:8443{WELL_KNOWN_PATH}")
        );
        for invalid in [
            "http://lane.example.test",
            "https://127.0.0.1",
            "https://127.1",
            "https://[::1]",
            "https://user@lane.example.test",
            "https://lane.example.test/path",
            "https://lane.example.test/a/..",
            "https://lane.example.test#",
            "https://lane.example.test?x=y",
            "https://lane.example.test\\other",
        ] {
            assert!(discovery_url(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn web_pki_discovery_binds_the_dns_name_and_refuses_a_tls_redirect() {
        use std::{io::BufRead, net::TcpListener, sync::Arc, thread};

        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};

        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let server_cert = CertificateParams::new(vec!["bootstrap.example.test".to_owned()])
            .unwrap()
            .signed_by(&server_key, &ca)
            .unwrap();
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_cert.der().clone()],
                    PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
                )
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let thread = thread::spawn(move || {
            // The bad DNS name must fail its handshake. The subsequent valid
            // connection should reach exactly one request at the known path.
            for _ in 0..2 {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut stream =
                    StreamOwned::new(ServerConnection::new(Arc::clone(&config)).unwrap(), socket);
                let mut reader = io::BufReader::new(&mut stream);
                let mut request = String::new();
                if reader.read_line(&mut request).is_err() || request.is_empty() {
                    continue;
                }
                assert!(request.starts_with(&format!("GET {WELL_KNOWN_PATH} ")));
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap() == 0 || header == "\r\n" {
                        break;
                    }
                }
                stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://other.example.test/bootstrap.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            }
        });
        let client = discovery_client()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap())
            .resolve("bootstrap.example.test", address)
            .resolve("wrong.example.test", address)
            .build()
            .unwrap();
        let wrong = discovery_url(&format!("wrong.example.test:{}", address.port())).unwrap();
        let error = fetch_from(&client, &wrong, 0).unwrap_err();
        assert!(format!("{error:#}").contains("certificate"), "{error:#}");
        let known = discovery_url(&format!("bootstrap.example.test:{}", address.port())).unwrap();
        let error = fetch_from(&client, &known, 0).unwrap_err();
        assert!(
            format!("{error:#}").contains("redirects are not allowed"),
            "{error:#}"
        );
        thread.join().unwrap();
    }

    #[test]
    fn artifact_redirects_allow_https_download_hosts_only_within_budget() {
        assert!(safe_artifact_redirect(
            &Url::parse("https://download.example.test/file").unwrap(),
            4
        ));
        for unsafe_url in [
            "http://download.example.test/file",
            "https://guest@download.example.test/file",
            "https://:secret@download.example.test/file",
        ] {
            assert!(!safe_artifact_redirect(&Url::parse(unsafe_url).unwrap(), 1));
        }
        assert!(!safe_artifact_redirect(
            &Url::parse("https://download.example.test/file").unwrap(),
            5
        ));
    }

    #[test]
    fn publication_preserves_existing_files_and_leaves_no_bad_output() {
        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("existing.tar.gz");
        let missing = directory.path().join("missing.tar.gz");
        fs::write(&existing, b"keep").unwrap();
        let payload = b"verified release";
        let digest: [u8; 32] = Sha256::digest(payload).into();
        assert!(
            publish_artifact(payload.as_slice(), &existing, payload.len() as u64, digest).is_err()
        );
        assert_eq!(fs::read(&existing).unwrap(), b"keep");
        assert!(
            publish_artifact(
                b"modified bytes".as_slice(),
                &missing,
                payload.len() as u64,
                digest
            )
            .is_err()
        );
        assert!(!missing.exists());
        publish_artifact(payload.as_slice(), &missing, payload.len() as u64, digest).unwrap();
        assert_eq!(fs::read(missing).unwrap(), payload);
    }

    #[test]
    fn artifact_stream_requires_authenticated_size_and_digest() {
        let payload = b"verified release";
        let size = payload.len() as u64;
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let mut saved = Vec::new();
        verify_and_copy(payload.as_slice(), &mut saved, size, digest).unwrap();
        assert_eq!(saved, payload);
        for invalid in [
            b"tampered release".as_slice(),
            b"short".as_slice(),
            b"verified release extra".as_slice(),
        ] {
            assert!(verify_and_copy(invalid, io::sink(), size, digest).is_err());
        }
    }
}
