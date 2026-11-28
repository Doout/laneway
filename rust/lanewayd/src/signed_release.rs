//! Fetch only fixed GitHub release assets; never run a server-chosen URL or path.
#[cfg(target_os = "linux")]
use crate::fleet_update::{installed_version, journal};
use anyhow::{Context, Result, bail, ensure};
use flate2::read::MultiGzDecoder;
use laneway_protocol::fleet_updates::valid_version;
use sha2::{Digest, Sha256};
use std::process::Stdio;
use std::{
    cmp::Ordering,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

pub(crate) fn stable_tag(value: &str) -> Result<String> {
    let tag = if value.starts_with('v') {
        value.to_owned()
    } else {
        format!("v{value}")
    };
    ensure!(
        valid_version(&tag),
        "expected an exact stable release version"
    );
    Ok(tag)
}

pub(crate) fn clean_command(path: impl AsRef<Path>) -> Command {
    let mut command = Command::new(path.as_ref());
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

pub(crate) async fn checked_command(mut command: Command, deadline: Duration) -> Result<()> {
    let status = timeout(deadline, command.stdout(Stdio::null()).status()).await??;
    ensure!(status.success(), "local command did not succeed");
    Ok(())
}

fn absent(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn check_verifier(path: &Path) -> Result<()> {
    journal::protect_parents(path)?;
    ensure!(
        path.symlink_metadata()?.is_file(),
        "verifier must not be a symlink"
    );
    journal::verify_file(
        &File::open(path).context("open pinned release verifier")?,
        0o022,
    )
}

#[cfg(target_os = "macos")]
fn check_verifier(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for (index, path) in path.ancestors().enumerate() {
        let data = path.symlink_metadata()?;
        let valid = if index == 0 {
            data.is_file() && data.mode() & 0o100 != 0
        } else {
            data.is_dir()
        };
        ensure!(
            valid && data.uid() == 0 && data.mode() & 0o7022 == 0,
            "unsafe local release verifier path {}",
            path.display()
        );
    }
    Ok(())
}

const RELEASE_ORIGIN: &str = "https://github.com/Doout/laneway/releases/download";
const LATEST_URL: &str = "https://github.com/Doout/laneway/releases/latest";
const WORKFLOW: &str = "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
const COSIGN: &str = "/usr/local/libexec/laneway/cosign-v3.1.3";
const MAX_CHECKSUMS: usize = 1 << 20;
const MAX_BUNDLE: usize = 4 << 20;
const MAX_ARCHIVE: usize = 256 << 20;
const MAX_EXPANDED: u64 = 512 << 20;
const MAX_BINARY: u64 = 128 << 20;
#[cfg(target_os = "linux")]
const MEMBER: &[u8] = b"laneway/sbin/lanewayd-rs";
#[cfg(target_os = "macos")]
const MEMBER: &[u8] = b"laneway/bin/lanewayd-rs";
#[cfg(target_os = "linux")]
pub(crate) const EDGE_IMAGE: &str = "ghcr.io/doout/laneway/edge";
#[cfg(target_os = "linux")]
pub(crate) const CONNECTOR_IMAGE: &str = "ghcr.io/doout/lane-edge";
#[cfg(target_os = "linux")]
pub(crate) const LEGACY_CONNECTOR_IMAGE: &str = "ghcr.io/doout/lane-edge-rust";
#[cfg(target_os = "linux")]
const NODE_IMAGE: &str = "ghcr.io/doout/laneway-node";

/// Compare two canonical stable release versions.
pub fn compare_versions(target: &str, previous: &str) -> Result<Ordering> {
    fn numbers(value: &str) -> Result<Vec<u64>> {
        stable_tag(value)?
            .trim_start_matches('v')
            .split('.')
            .map(|part| {
                part.parse()
                    .context("release version exceeds the numeric bound")
            })
            .collect()
    }
    Ok(numbers(target)?.cmp(&numbers(previous)?))
}

/// Discover the latest stable release from the official repository.
pub async fn latest_tag() -> Result<String> {
    let request_nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let reply = github_client()?
        .get(format!("{LATEST_URL}?laneway_cache_bust={request_nonce}"))
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .header(reqwest::header::PRAGMA, "no-cache")
        .timeout(Duration::from_secs(30))
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        reply.status() == reqwest::StatusCode::OK,
        "latest stable release not found"
    );
    tag_from_url(reply.url())
}

fn tag_from_url(url: &reqwest::Url) -> Result<String> {
    let tag = url
        .as_str()
        .strip_prefix("https://github.com/Doout/laneway/releases/tag/")
        .context("latest release did not resolve to the official Laneway release page")?;
    ensure!(
        stable_tag(tag)? == tag,
        "latest release did not resolve to a stable tag"
    );
    Ok(tag.into())
}

#[cfg(target_os = "linux")]
pub(crate) async fn obtain(tag: &str, directory: &Path) -> Result<PathBuf> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("unsupported managed Linux node architecture"),
    };
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let name = format!("laneway_{os}_{arch}.tar.gz");
    let (client, manifest) = signed_manifest(tag, directory).await?;
    let checksum = checksum_for(&manifest, &name)?;
    let archive = directory.join(&name);
    download(&client, tag, &name, &archive, MAX_ARCHIVE, 180).await?;
    let binary = directory.join("verified-lanewayd-rs");
    let output = binary.clone();
    tokio::task::spawn_blocking(move || verified_extract(File::open(archive)?, &checksum, &output))
        .await??;
    ensure!(
        installed_version(&binary).await? == tag,
        "verified daemon reports the wrong release tag"
    );
    Ok(binary)
}

/// Authenticated client archive and the two staged executables.
pub struct ClientArchive {
    /// Verified release tarball.
    pub archive: PathBuf,
    /// Staged CLI from the signed archive.
    pub cli: PathBuf,
    /// Staged runtime from the signed archive.
    pub daemon: PathBuf,
    /// Signed SHA-256 digest of the archive.
    pub checksum: [u8; 32],
}

/// Download and authenticate the host package before extracting its executables.
pub async fn client_archive(tag: &str, directory: &Path) -> Result<ClientArchive> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("unsupported client architecture"),
    };
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let name = format!("laneway_{os}_{arch}.tar.gz");
    let (client, manifest) = signed_manifest(tag, directory).await?;
    let checksum = checksum_for(&manifest, &name)?;
    let archive = directory.join(&name);
    download(&client, tag, &name, &archive, MAX_ARCHIVE, 180).await?;
    let candidates = directory.join("client-candidates");
    fs::create_dir(&candidates)?;
    let cli = candidates.join("laneway");
    let daemon = candidates.join("lanewayd-rs");
    let paths = (archive.clone(), cli.clone(), daemon.clone());
    tokio::task::spawn_blocking(move || {
        let mut file = File::open(paths.0)?;
        verify_archive(&mut file, &checksum)?;
        extract_members(
            file,
            &[(b"laneway/bin/laneway", &paths.1), (MEMBER, &paths.2)],
        )
    })
    .await??;
    Ok(ClientArchive {
        archive,
        cli,
        daemon,
        checksum,
    })
}

/// The same release must authenticate the manifest and the pinned OCI subject.
#[cfg(target_os = "linux")]
pub(crate) async fn connector_image(tag: &str, directory: &Path) -> Result<String> {
    let (client, manifest) = signed_manifest(tag, directory).await?;
    const ASSET: &str = "image-digests.txt";
    let expected = checksum_for(&manifest, ASSET)?;
    let path = directory.join(ASSET);
    download(&client, tag, ASSET, &path, MAX_CHECKSUMS, 30).await?;
    let bytes = fs::read(path)?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    ensure!(
        actual == expected,
        "connector image manifest checksum mismatch"
    );
    let reference = connector_subject(std::str::from_utf8(&bytes)?)?;
    verify(
        &client,
        tag,
        directory,
        "verify",
        &[],
        Path::new(&reference),
    )
    .await
    .context("Rust connector image signature verification failed")?;
    Ok(reference)
}

#[cfg(target_os = "linux")]
fn image_subject<'a>(manifest: &'a str, repository: &str) -> Result<Option<&'a str>> {
    let mut entries = manifest.lines().filter_map(|line| {
        let (name, digest) = line.split_once('@')?;
        (name == repository).then_some((line, digest))
    });
    let Some((line, digest)) = entries.next() else {
        return Ok(None);
    };
    ensure!(
        entries.next().is_none()
            && digest.strip_prefix("sha256:").is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    && value.bytes().any(|byte| byte != b'0')
            }),
        "release has no unique valid digest for {repository}"
    );
    Ok(Some(line))
}

#[cfg(target_os = "linux")]
fn connector_subject(manifest: &str) -> Result<String> {
    if manifest
        .lines()
        .any(|line| line.starts_with("ghcr.io/doout/laneway/"))
    {
        return Ok(image_subject(manifest, EDGE_IMAGE)?
            .context("release has no Edge image")?
            .to_owned());
    }

    // The older unsuffixed inventory included a standalone node image. Releases
    // that published a Go connector under the same name lacked that entry.
    let repository = if image_subject(manifest, NODE_IMAGE)?.is_some() {
        CONNECTOR_IMAGE
    } else {
        LEGACY_CONNECTOR_IMAGE
    };
    Ok(image_subject(manifest, repository)?
        .context("release has no Rust connector image")?
        .to_owned())
}

fn github_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 6
                && attempt.url().scheme() == "https"
                && attempt.url().username().is_empty()
                && attempt.url().password().is_none()
                && matches!(
                    attempt.url().host_str(),
                    Some(
                        "github.com"
                            | "release-assets.githubusercontent.com"
                            | "objects.githubusercontent.com"
                            | "github-releases.githubusercontent.com"
                    )
                )
            {
                attempt.follow()
            } else {
                attempt.error("release download redirect is not permitted")
            }
        }))
        .build()?)
}

async fn signed_manifest(tag: &str, directory: &Path) -> Result<(reqwest::Client, String)> {
    ensure!(
        stable_tag(tag)? == tag,
        "assignment must pin an exact stable tag"
    );
    let client = github_client()?;
    let manifest = directory.join("checksums.txt");
    let bundle = directory.join("checksums.sigstore.json");
    download(&client, tag, "checksums.txt", &manifest, MAX_CHECKSUMS, 30).await?;
    download(
        &client,
        tag,
        "checksums.sigstore.json",
        &bundle,
        MAX_BUNDLE,
        30,
    )
    .await?;
    verify(
        &client,
        tag,
        directory,
        "verify-blob",
        &["--bundle".as_ref(), &bundle],
        &manifest,
    )
    .await
    .context("release signature verification failed")?;
    Ok((client, fs::read_to_string(manifest)?))
}

async fn verify(
    client: &reqwest::Client,
    tag: &str,
    directory: &Path,
    subcommand: &str,
    args: &[&Path],
    subject: &Path,
) -> Result<()> {
    let verifier = release_verifier(client, directory).await?;
    // Do not inherit trust overrides. With no account home Cosign's TUF
    // client uses a temporary directory; keep it inside root-only staging.
    let mut command = clean_command(verifier);
    command.env("TMPDIR", directory);
    command
        .arg(subcommand)
        .args(args)
        .args([
            "--certificate-identity",
            &format!("{WORKFLOW}/{tag}"),
            "--certificate-oidc-issuer",
            ISSUER,
        ])
        .arg(subject);
    checked_command(command, Duration::from_secs(60)).await
}

async fn release_verifier(client: &reqwest::Client, directory: &Path) -> Result<PathBuf> {
    let installed = Path::new(COSIGN);
    if !absent(installed)? {
        check_verifier(installed)?;
        return Ok(installed.into());
    }
    let (os, arch, digest) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => (
            "linux",
            "amd64",
            "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
        ),
        ("linux", "aarch64") => (
            "linux",
            "arm64",
            "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
        ),
        ("macos", "x86_64") => (
            "darwin",
            "amd64",
            "2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c",
        ),
        ("macos", "aarch64") => (
            "darwin",
            "arm64",
            "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76",
        ),
        _ => bail!("no pinned Cosign verifier for this platform"),
    };
    let local = directory.join("cosign-v3.1.3");
    // Both the checksum bundle and the image can use this temporary verifier.
    if absent(&local)? {
        download_url(
            client,
            &format!(
                "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-{os}-{arch}"
            ),
            &local,
            160 << 20,
            180,
        )
        .await
        .context("download pinned release verifier")?;
        let path = local.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut file = File::open(path)?;
            let mut hash = Sha256::new();
            io::copy(&mut file, &mut hash)?;
            ensure!(
                hex::encode(hash.finalize()) == digest,
                "pinned Cosign checksum verification failed"
            );
            file.set_permissions(fs::Permissions::from_mode(0o700))?;
            Ok(())
        })
        .await??;
    }
    Ok(local)
}

#[cfg(any(test, target_os = "linux"))]
fn verified_extract(
    mut source: impl Read + Seek,
    expected: &[u8; 32],
    output: &Path,
) -> Result<()> {
    verify_archive(&mut source, expected)?;
    extract(source, output)
}

fn verify_archive(source: &mut (impl Read + Seek), expected: &[u8; 32]) -> Result<()> {
    let mut digest = Sha256::new();
    io::copy(source, &mut digest)?;
    let observed: [u8; 32] = digest.finalize().into();
    ensure!(
        &observed == expected,
        "release archive disagrees with the signed checksum"
    );
    source.rewind()?;
    Ok(())
}

async fn download(
    client: &reqwest::Client,
    tag: &str,
    asset: &str,
    output: &Path,
    limit: usize,
    seconds: u64,
) -> Result<()> {
    download_url(
        client,
        &format!("{RELEASE_ORIGIN}/{tag}/{asset}"),
        output,
        limit,
        seconds,
    )
    .await
}

async fn download_url(
    client: &reqwest::Client,
    url: &str,
    output: &Path,
    limit: usize,
    seconds: u64,
) -> Result<()> {
    let mut response = client
        .get(url)
        .timeout(Duration::from_secs(seconds))
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "release download did not return an asset"
    );
    ensure!(
        response.content_length().unwrap_or(0) <= limit as u64,
        "release asset exceeds size limit"
    );
    let mut file = tokio::fs::File::from_std(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)?,
    );
    let mut bytes = 0;
    while let Some(chunk) = response.chunk().await? {
        bytes += chunk.len();
        ensure!(bytes <= limit, "release asset exceeds size limit");
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    ensure!(bytes > 0, "release asset was empty");
    Ok(())
}

fn checksum_for(manifest: &str, asset: &str) -> Result<[u8; 32]> {
    let mut matching = manifest.lines().filter_map(|line| {
        line.split_once("  ")
            .filter(|(_, name)| *name == asset)
            .map(|(digest, _)| digest)
    });
    let raw = matching
        .next()
        .context("release is absent from the signed checksum manifest")?;
    ensure!(
        matching.next().is_none()
            && raw.len() == 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "release lacks an unambiguous signed checksum"
    );
    let mut result = [0_u8; 32];
    hex::decode_to_slice(raw, &mut result)?;
    Ok(result)
}

#[cfg(any(test, target_os = "linux"))]
fn extract(source: impl Read, output: &Path) -> Result<()> {
    extract_members(source, &[(MEMBER, output)])
}

fn extract_members(source: impl Read, members: &[(&[u8], &Path)]) -> Result<()> {
    let mut archive = tar::Archive::new(MultiGzDecoder::new(source).take(MAX_EXPANDED + 1));
    let mut found = vec![false; members.len()];
    // Inspect raw members. GNU/PAX long name and sparse metadata never
    // substitute for the one short canonical regular path we accept.
    for (index, next) in archive.entries()?.raw(true).enumerate() {
        let mut entry = next?;
        ensure!(index < 10_000, "release archive contains too many members");
        let Some(index) = members
            .iter()
            .position(|(path, _)| entry.path_bytes().as_ref() == *path)
        else {
            continue;
        };
        let output = members[index].1;
        ensure!(
            !found[index]
                && entry.header().entry_type().is_file()
                && (1..=MAX_BINARY).contains(&entry.size()),
            "release lacks an unambiguous regular executable at {}",
            String::from_utf8_lossy(members[index].0)
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)?;
        ensure!(
            io::copy(&mut entry, &mut file)? == entry.size(),
            "truncated release executable"
        );
        found[index] = true;
    }
    // Consume/check gzip EOF and reject concatenated tar members after the
    // first terminator instead of silently choosing a duplicate target.
    let mut source = archive.into_inner();
    let mut tail = [0; 8192];
    loop {
        let n = source.read(&mut tail)?;
        if n == 0 {
            break;
        }
        ensure!(
            tail[..n].iter().all(|b| *b == 0),
            "unexpected data after release archive"
        );
    }
    ensure!(source.limit() > 0, "release archive exceeds size limit");
    for ((name, output), found) in members.iter().zip(found) {
        ensure!(
            found,
            "release archive is missing {}",
            String::from_utf8_lossy(name)
        );
        fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    #[test]
    fn latest_release_accepts_only_the_exact_official_stable_tag() {
        let valid =
            reqwest::Url::parse("https://github.com/Doout/laneway/releases/tag/v1.2.3").unwrap();
        assert_eq!(tag_from_url(&valid).unwrap(), "v1.2.3");
        for url in [
            "https://github.com/other/laneway/releases/tag/v1.2.3",
            "https://github.com/Doout/laneway/releases/tag/v1.2.3-rc1",
            "https://github.com/Doout/laneway/releases/tag/v1.2.3?x=1",
            "https://example.org/Doout/laneway/releases/tag/v1.2.3",
        ] {
            assert!(
                tag_from_url(&reqwest::Url::parse(url).unwrap()).is_err(),
                "{url}"
            );
        }
        assert_eq!(
            compare_versions("v1.10.0", "v1.2.0").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("v1.2.0", "v1.10.0").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("1.2.0", "v1.2.0").unwrap(),
            Ordering::Equal
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn connector_manifest_selects_the_image_for_its_release_layout() {
        let edge = format!("{EDGE_IMAGE}@sha256:{}", "d".repeat(64));
        let canonical = format!("{CONNECTOR_IMAGE}@sha256:{}", "a".repeat(64));
        let legacy = format!("{LEGACY_CONNECTOR_IMAGE}@sha256:{}", "b".repeat(64));
        let node = format!("{NODE_IMAGE}@sha256:{}", "c".repeat(64));

        assert_eq!(
            connector_subject(&format!("{canonical}\n{legacy}")).unwrap(),
            legacy
        );
        assert!(connector_subject(&canonical).is_err());
        assert_eq!(connector_subject(&edge).unwrap(), edge);
        assert!(connector_subject(&format!("{edge}\n{EDGE_IMAGE}@invalid")).is_err());
        assert!(
            connector_subject(&format!("ghcr.io/doout/laneway/console@unused\n{legacy}")).is_err()
        );
        assert_eq!(
            connector_subject(&format!("{node}\n{canonical}")).unwrap(),
            canonical
        );
        assert!(
            connector_subject(&format!("{node}\n{canonical}\n{CONNECTOR_IMAGE}@invalid")).is_err()
        );
        assert!(connector_subject(&format!("{node}\n{NODE_IMAGE}@invalid\n{canonical}")).is_err());
    }

    fn archive(entries: &[(tar::EntryType, &[u8])]) -> Vec<u8> {
        let writer = GzEncoder::new(Vec::new(), Compression::fast());
        let mut archive = tar::Builder::new(writer);
        for (kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            if kind.is_symlink() {
                header.set_link_name("/untrusted/path").unwrap();
            }
            archive
                .append_data(&mut header, std::str::from_utf8(MEMBER).unwrap(), *bytes)
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn extracts_only_one_exact_regular_member() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate");
        let regular = tar::EntryType::Regular;
        extract(
            archive(&[(regular, b"verified contents")]).as_slice(),
            &path,
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"verified contents");
        assert!(
            extract(
                archive(&[(regular, b"one"), (regular, b"two")]).as_slice(),
                &directory.path().join("duplicate")
            )
            .is_err()
        );
        assert!(
            extract(
                archive(&[(tar::EntryType::Symlink, b"")]).as_slice(),
                &directory.path().join("link")
            )
            .is_err()
        );
        assert!(extract(archive(&[]).as_slice(), &directory.path().join("missing")).is_err());
    }

    #[test]
    fn signed_digest_must_be_unique_and_canonical() {
        let digest = "a5".repeat(32);
        let line = format!("{digest}  release.tar.gz\n");
        assert_eq!(checksum_for(&line, "release.tar.gz").unwrap(), [0xa5; 32]);
        assert!(checksum_for(&line.repeat(2), "release.tar.gz").is_err());
        assert!(checksum_for(&line.to_uppercase(), "RELEASE.TAR.GZ").is_err());
        assert!(checksum_for(&line, "other.tar.gz").is_err());
    }

    #[test]
    fn wrong_digest_does_not_stage_a_candidate() {
        let input = archive(&[(tar::EntryType::Regular, b"candidate")]);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate");
        assert!(verified_extract(io::Cursor::new(&input), &[0; 32], &path).is_err());
        assert!(absent(&path).unwrap());
        let checksum = Sha256::digest(&input).into();
        verified_extract(io::Cursor::new(&input), &checksum, &path).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"candidate");
    }
}
