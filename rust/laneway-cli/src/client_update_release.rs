use std::{
    env,
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{
    StatusCode, Url,
    blocking::{Client, Response},
    header::{ACCEPT, CACHE_CONTROL, PRAGMA},
    redirect::Policy,
};
use sha2::{Digest, Sha256};

const REPOSITORY: &str = "https://github.com/Doout/laneway";
const MANIFEST_LIMIT: usize = 1 << 20;
const BINARY_LIMIT: u64 = 128 << 20;

pub(super) fn stable_version(version: &str) -> Option<[u64; 3]> {
    let mut parts = version.split('.');
    let mut parsed = [0; 3];
    for part in &mut parsed {
        let value = parts.next()?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        *part = value.parse().ok()?;
    }
    parts.next().is_none().then_some(parsed)
}

pub(super) fn tag_from_url(url: &Url) -> Result<String> {
    let prefix = format!("{REPOSITORY}/releases/tag/");
    let tag = url
        .as_str()
        .strip_prefix(&prefix)
        .context("latest release redirected to an unexpected URL")?;
    ensure!(
        tag.strip_prefix('v').and_then(stable_version).is_some(),
        "latest release is not a stable semantic tag"
    );
    Ok(tag.to_owned())
}

pub(super) struct ReleaseClient(Client);

impl ReleaseClient {
    pub(super) fn new() -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .redirect(Policy::custom(|attempt| {
                let url = attempt.url();
                if attempt.previous().len() >= 5
                    || url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    attempt.error("unsafe or excessive release redirect")
                } else {
                    attempt.follow()
                }
            }))
            .build()?;
        Ok(Self(client))
    }

    fn get(&self, url: &str, accept: &str) -> Result<Response> {
        let response = self
            .0
            .get(url)
            .header(ACCEPT, accept)
            .header(CACHE_CONTROL, "no-cache")
            .header(PRAGMA, "no-cache")
            .send()
            .context("download Laneway release")?;
        ensure!(
            response.status() == StatusCode::OK,
            "release download returned {}",
            response.status()
        );
        Ok(response)
    }

    pub(super) fn latest_tag(&self) -> Result<String> {
        let cache_bust = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let response = self.get(
            &format!("{REPOSITORY}/releases/latest?laneway_cache_bust={cache_bust}"),
            "text/html",
        )?;
        tag_from_url(response.url())
    }

    pub(super) fn metadata(&self, tag: &str, asset: &str) -> Result<Vec<u8>> {
        let response = self.asset(tag, asset)?;
        let mut bytes = Vec::new();
        response
            .take((MANIFEST_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MANIFEST_LIMIT,
            "{asset} exceeds the metadata size limit"
        );
        Ok(bytes)
    }

    pub(super) fn download(
        &self,
        tag: &str,
        asset: &str,
        destination: &Path,
        digest: &str,
    ) -> Result<()> {
        self.download_bounded(tag, asset, destination, digest, BINARY_LIMIT)
    }

    fn download_bounded(
        &self,
        tag: &str,
        asset: &str,
        destination: &Path,
        digest: &str,
        limit: u64,
    ) -> Result<()> {
        let mut response = self.asset(tag, asset)?.take(limit + 1);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut file = options.open(destination)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 16 * 1024];
        let mut total = 0;
        loop {
            let size = response.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            total += size as u64;
            ensure!(total <= limit, "{asset} exceeds the executable size limit");
            hasher.update(&buffer[..size]);
            file.write_all(&buffer[..size])?;
        }
        ensure!(
            total > 0 && format!("{:x}", hasher.finalize()) == digest,
            "{asset} failed checksum verification"
        );
        file.sync_all()?;
        Ok(())
    }

    fn asset(&self, tag: &str, name: &str) -> Result<Response> {
        self.get(
            &format!("{REPOSITORY}/releases/download/{tag}/{name}"),
            "application/octet-stream",
        )
        .with_context(|| format!("download release asset {name}"))
    }
}

pub(super) fn asset_checksum<'a>(manifest: &'a str, asset: &str) -> Result<&'a str> {
    let mut checksum = None;
    for line in manifest.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(value), Some(name), None) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        if name != asset {
            continue;
        }
        ensure!(checksum.is_none(), "duplicate manifest entry for {asset}");
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "no canonical SHA-256 digest for {asset}"
        );
        checksum = Some(value);
    }
    checksum.with_context(|| format!("no checksum manifest entry for {asset}"))
}

pub(crate) fn find_on_path(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    env::split_paths(path?)
        .filter(|directory| directory.is_absolute())
        .find_map(|directory| {
            let candidate = directory.join(name);
            let info = fs::metadata(&candidate).ok()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if info.permissions().mode() & 0o111 == 0 {
                    return None;
                }
            }
            info.is_file().then_some(candidate)
        })
}

pub(super) fn verifier_override(name: &OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_uppercase();
    ["COSIGN_", "SIGSTORE_", "TUF_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

pub(super) fn verify_manifest(
    cosign: &Path,
    stage: &Path,
    tag: &str,
    manifest: &[u8],
    bundle: &[u8],
) -> Result<()> {
    let checksums = stage.join("checksums.txt");
    let signature = stage.join("checksums.sigstore.json");
    fs::write(&checksums, manifest)?;
    fs::write(&signature, bundle)?;
    let mut verifier = Command::new(cosign);
    verifier
        .arg("verify-blob")
        .arg("--bundle")
        .arg(&signature)
        .arg("--certificate-identity")
        .arg(format!(
            "{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}"
        ))
        .args([
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ])
        .arg(&checksums);
    for (name, _) in env::vars_os().filter(|(name, _)| verifier_override(name)) {
        verifier.env_remove(name);
    }
    #[cfg(unix)]
    if nix::unistd::geteuid().is_root() {
        for name in ["HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "TMPDIR"] {
            verifier.env(name, stage);
        }
        verifier.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }
    let status = verifier
        .status()
        .context("launch Cosign release verification")?;
    ensure!(status.success(), "release signature verification failed");
    Ok(())
}

pub(crate) fn prepare_release(
    stage: &Path,
    cosign: &Path,
    assets: &[(&str, &str)],
    extra_asset: Option<&str>,
) -> Result<String> {
    let client = ReleaseClient::new()?;
    let tag = client.latest_tag()?;
    let expected = tag.strip_prefix('v').expect("validated stable tag");
    if let Some(installed) = stable_version(crate::VERSION)
        && let Some(latest) = stable_version(expected)
        && installed > latest
    {
        bail!(
            "latest stable release {tag} would downgrade installed v{}",
            crate::VERSION
        );
    }
    let manifest = client.metadata(&tag, "checksums.txt")?;
    let bundle = client.metadata(&tag, "checksums.sigstore.json")?;
    verify_manifest(cosign, stage, &tag, &manifest, &bundle)?;
    let manifest = std::str::from_utf8(&manifest).context("invalid checksum manifest")?;
    for &(file, asset) in assets {
        client.download(
            &tag,
            asset,
            &stage.join(file),
            asset_checksum(manifest, asset)?,
        )?;
    }
    if let Some(asset) = extra_asset {
        client.download_bounded(
            &tag,
            asset,
            &stage.join(asset),
            asset_checksum(manifest, asset)?,
            MANIFEST_LIMIT as u64,
        )?;
    }
    Ok(tag)
}

pub(crate) fn check_candidate(candidate: &Path, flag: &str, version: &str) -> Result<()> {
    let output = Command::new(candidate)
        .arg(flag)
        .output()
        .with_context(|| format!("check downloaded {} version", candidate.display()))?;
    ensure!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == version,
        "downloaded {} did not report expected version {version}",
        candidate.display()
    );
    Ok(())
}

pub(crate) fn confirm_install(tag: &str, bin: &Path) -> Result<()> {
    eprint!("Install Laneway {tag} at {}? [y/N] ", bin.display());
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    ensure!(answer.trim().eq_ignore_ascii_case("y"), "update cancelled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_only_stable_tags_from_this_repository() {
        let accepted = Url::parse(&format!("{REPOSITORY}/releases/tag/v1.2.3")).unwrap();
        assert_eq!(tag_from_url(&accepted).unwrap(), "v1.2.3");
        for url in [
            "https://github.com/other/laneway/releases/tag/v1.2.3",
            "https://example.test/Doout/laneway/releases/tag/v1.2.3",
            "https://github.com/Doout/laneway/releases/tag/v1.2.3-rc1",
            "https://github.com/Doout/laneway/releases/tag/v01.2.3",
            "https://github.com/Doout/laneway/releases/tag/v1.2.3?release=1",
        ] {
            assert!(tag_from_url(&Url::parse(url).unwrap()).is_err(), "{url}");
        }
        assert!(stable_version("0.8.10") > stable_version("0.8.9"));
    }

    #[test]
    fn requires_an_exact_unique_canonical_digest_for_each_asset() {
        let digest = "ab".repeat(32);
        let daemon = format!("{digest}  lanewayd_linux_amd64\n");
        assert_eq!(
            asset_checksum(&daemon, "lanewayd_linux_amd64").unwrap(),
            digest
        );
        assert!(asset_checksum(&daemon, "laneway-native_linux_amd64").is_err());
        assert!(asset_checksum(&daemon.repeat(2), "lanewayd_linux_amd64").is_err());
        assert!(asset_checksum(&daemon.to_uppercase(), "LANEWAYD_LINUX_AMD64").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn signature_verifier_uses_the_release_workflow_certificate() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::tempdir().unwrap();
        let script = fixture.path().join("cosign");
        fs::write(
            &script,
            r#"#!/bin/sh
set -eu
test "$#" -eq 8
test "$1" = verify-blob
test "$2" = --bundle
test "$(cat "$3")" = bundle-fixture
test "$4" = --certificate-identity
test "$5" = 'https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v1.2.3'
test "$6" = --certificate-oidc-issuer
test "$7" = 'https://token.actions.githubusercontent.com'
test "$(cat "$8")" = checksum-fixture
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        verify_manifest(
            &script,
            fixture.path(),
            "v1.2.3",
            b"checksum-fixture",
            b"bundle-fixture",
        )
        .unwrap();
        assert!(
            verify_manifest(
                &script,
                fixture.path(),
                "v1.2.4",
                b"checksum-fixture",
                b"bundle-fixture",
            )
            .is_err()
        );
        assert!(verifier_override(OsStr::new("Cosign_Unsafe")));
        assert!(verifier_override(OsStr::new("SIGSTORE_ROOT")));
        assert!(verifier_override(OsStr::new("tuf_root")));
        assert!(!verifier_override(OsStr::new("PATH")));
    }
}
