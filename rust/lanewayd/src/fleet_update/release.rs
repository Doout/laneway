//! Fetch only fixed GitHub release assets; never run a server-chosen URL or path.
use super::{checked_command, clean_command, journal, stable_tag};
use anyhow::{Context, Result, bail, ensure};
use flate2::read::MultiGzDecoder;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncWriteExt;

const RELEASE_ORIGIN: &str = "https://github.com/Doout/laneway/releases/download";
const WORKFLOW: &str = "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
const COSIGN: &str = "/usr/local/libexec/laneway/cosign-v3.1.3";
const MAX_CHECKSUMS: usize = 1 << 20;
const MAX_BUNDLE: usize = 4 << 20;
const MAX_ARCHIVE: usize = 256 << 20;
const MAX_EXPANDED: u64 = 512 << 20;
const MAX_BINARY: u64 = 128 << 20;
const MEMBER: &[u8] = b"laneway/sbin/lanewayd-rs";

pub(super) async fn obtain(tag: &str, directory: &Path) -> Result<PathBuf> {
    ensure!(
        stable_tag(tag)? == tag,
        "assignment must pin an exact stable tag"
    );
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("unsupported managed Linux node architecture"),
    };
    let name = format!("laneway_linux_{arch}.tar.gz");
    let client = reqwest::Client::builder()
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
        .build()?;
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
    // The installed verifier is selected by the operator, not by the plan.
    journal::protect_parents(Path::new(COSIGN))?;
    let verifier = fs::symlink_metadata(COSIGN)?;
    ensure!(verifier.is_file(), "verifier must not be a symlink");
    journal::verify_file(
        &File::open(COSIGN).context("open pinned release verifier")?,
        0o022,
    )?;
    // Do not inherit trust overrides. With no account home Cosign's TUF
    // client uses a temporary directory; keep it inside root-only staging.
    let mut command = clean_command(COSIGN);
    command.env("TMPDIR", directory);
    command
        .args(["verify-blob", "--bundle"])
        .arg(&bundle)
        .args([
            "--certificate-identity",
            &format!("{WORKFLOW}/{tag}"),
            "--certificate-oidc-issuer",
            ISSUER,
        ])
        .arg(&manifest);
    checked_command(command, Duration::from_secs(60))
        .await
        .context("release signature verification failed")?;
    let checksum = checksum_for(&fs::read_to_string(&manifest)?, &name)?;
    let archive = directory.join(&name);
    download(&client, tag, &name, &archive, MAX_ARCHIVE, 180).await?;
    let binary = directory.join("verified-lanewayd-rs");
    let output = binary.clone();
    tokio::task::spawn_blocking(move || verified_extract(File::open(archive)?, &checksum, &output))
        .await??;
    ensure!(
        super::installed_version(&binary).await? == tag,
        "verified daemon reports the wrong release tag"
    );
    Ok(binary)
}

fn verified_extract(
    mut source: impl Read + Seek,
    expected: &[u8; 32],
    output: &Path,
) -> Result<()> {
    let mut digest = Sha256::new();
    io::copy(&mut source, &mut digest)?;
    let observed: [u8; 32] = digest.finalize().into();
    ensure!(
        &observed == expected,
        "release archive disagrees with the signed checksum"
    );
    source.rewind()?;
    extract(source, output)
}

async fn download(
    client: &reqwest::Client,
    tag: &str,
    asset: &str,
    output: &Path,
    limit: usize,
    seconds: u64,
) -> Result<()> {
    let mut response = client
        .get(format!("{RELEASE_ORIGIN}/{tag}/{asset}"))
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

fn extract(source: impl Read, output: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(MultiGzDecoder::new(source).take(MAX_EXPANDED + 1));
    let mut found = false;
    // Inspect raw members. GNU/PAX long name and sparse metadata never
    // substitute for the one short canonical regular path we accept.
    for (index, next) in archive.entries()?.raw(true).enumerate() {
        let mut entry = next?;
        ensure!(index < 10_000, "release archive contains too many members");
        if entry.path_bytes().as_ref() != MEMBER {
            continue;
        }
        ensure!(
            !found
                && entry.header().entry_type().is_file()
                && (1..=MAX_BINARY).contains(&entry.size()),
            "release lacks an unambiguous regular Rust node executable"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)?;
        ensure!(
            io::copy(&mut entry, &mut file)? == entry.size(),
            "truncated Rust node executable"
        );
        found = true;
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
    ensure!(
        found && source.limit() > 0,
        "release archive exceeds size limit or lacks Rust node executable"
    );
    fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

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
        assert!(journal::absent(&path).unwrap());
        let checksum = Sha256::digest(&input).into();
        verified_extract(io::Cursor::new(&input), &checksum, &path).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"candidate");
    }
}
