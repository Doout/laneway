use super::{CheckedKey, usable_key};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use rustls::crypto::CryptoProvider;
use rustls_acme::{AccountCache, CertCache};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const MAX_CACHE_FILE: usize = 128 * 1024;

#[derive(Clone)]
pub(super) struct Cache {
    go: PathBuf,
    rust: PathBuf,
    name: String,
    crypto: Arc<CryptoProvider>,
}

impl Cache {
    pub(super) fn new(root: &Path, name: &str, crypto: Arc<CryptoProvider>) -> Result<Self> {
        directory(root, false).context("prepare public HTTPS cache directory")?;
        let rust = root.join("rust-v1");
        directory(&rust, true).context("prepare private native ACME cache")?;
        Ok(Self {
            go: root.to_path_buf(),
            rust,
            name: name.to_owned(),
            crypto,
        })
    }

    pub(super) fn go_seed(&self) -> Option<CheckedKey> {
        // The Go cache puts the ECDSA key first, then the public chain. Never
        // read the +token challenge file or import the Go account credential.
        let names = [self.name.clone(), format!("{}+rsa", self.name)];
        for name in names {
            let result = read(&self.go.join(name)).and_then(|maybe| {
                maybe
                    .map(|pem| {
                        self.certificate(pem.as_slice(), true)
                            .map_err(io::Error::other)
                    })
                    .transpose()
            });
            match result {
                Ok(Some(key)) => return Some(key),
                Ok(None) => {}
                Err(_) => tracing::warn!("ignoring unusable Go public HTTPS cache entry"),
            }
        }
        None
    }

    fn certificate(&self, pem: &[u8], current: bool) -> Result<CheckedKey> {
        let mut private_pem = pem;
        let mut cert_pem = pem;
        let key = rustls_pemfile::private_key(&mut private_pem)?
            .context("private key missing in public HTTPS cache entry")?;
        let chain = rustls_pemfile::certs(&mut cert_pem).collect::<io::Result<Vec<_>>>()?;
        usable_key(chain, key, &self.name, &self.crypto, current)
    }

    fn key(&self, kind: &str, fields: &[String], url: &str) -> PathBuf {
        let mut sha = Sha256::new();
        for field in fields {
            sha.update(field.as_bytes());
            sha.update([0]);
        }
        sha.update(url.as_bytes());
        self.rust.join(format!("{kind}-{:x}", sha.finalize()))
    }
}

#[async_trait]
impl CertCache for Cache {
    type EC = io::Error;

    async fn load_cert(&self, domains: &[String], url: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.key("cert", domains, url);
        let cache = self.clone();
        blocking(move || {
            let Some(mut pcm) = read(&path)? else {
                return Ok(None);
            };
            cache
                .certificate(pcm.as_slice(), false)
                .map_err(io::Error::other)?;
            Ok(Some(std::mem::take(&mut *pcm)))
        })
        .await
    }

    async fn store_cert(&self, domains: &[String], url: &str, data: &[u8]) -> io::Result<()> {
        let path = self.key("cert", domains, url);
        let cache = self.clone();
        let data = Zeroizing::new(data.to_vec());
        blocking(move || {
            cache
                .certificate(data.as_slice(), true)
                .map_err(io::Error::other)?;
            write(&path, data.as_slice())
        })
        .await
    }
}

#[async_trait]
impl AccountCache for Cache {
    type EA = io::Error;

    async fn load_account(&self, contact: &[String], url: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.key("account", contact, url);
        blocking(move || Ok(read(&path)?.map(|mut bytes| std::mem::take(&mut *bytes)))).await
    }

    async fn store_account(&self, contact: &[String], url: &str, data: &[u8]) -> io::Result<()> {
        let path = self.key("account", contact, url);
        let data = Zeroizing::new(data.to_vec());
        blocking(move || write(&path, data.as_slice())).await
    }
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(io::Error::other)?
}

pub(crate) fn directory(path: &Path, owner_only: bool) -> Result<()> {
    let mut options = fs::DirBuilder::new();
    options.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        options.mode(0o700);
    }
    options.create(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(meta.is_dir(), "ACME cache must be a real directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let prohibited = if owner_only { 0o077 } else { 0o022 };
        ensure!(
            meta.permissions().mode() & prohibited == 0,
            "ACME cache directory permissions are too broad"
        );
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    Ok(())
}

pub(crate) fn read(path: &Path) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !meta.is_file() || meta.len() > MAX_CACHE_FILE as u64 {
        return Err(io::Error::other("invalid ACME cache entry"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other("ACME cache file is not private"));
        }
    }
    let mut data = Zeroizing::new(Vec::new());
    File::open(path)?
        .take((MAX_CACHE_FILE + 1) as u64)
        .read_to_end(&mut data)?;
    if data.is_empty() || data.len() > MAX_CACHE_FILE {
        return Err(io::Error::other("invalid ACME cache length"));
    }
    Ok(Some(data))
}

pub(crate) fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    if data.is_empty() || data.len() > MAX_CACHE_FILE {
        return Err(io::Error::other("invalid ACME cache length"));
    }
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("missing ACME cache path"))?;
    let mut candidate = tempfile::NamedTempFile::new_in(directory)?;
    candidate.write_all(data)?;
    candidate.as_file().sync_all()?;
    candidate.persist(path)?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;

    #[tokio::test]
    async fn production_seed_is_read_only_and_native_cache_is_directory_scoped() -> Result<()> {
        let root = tempfile::tempdir()?;
        let name = "relay.example.test";
        let cache = Cache::new(
            root.path(),
            name,
            Arc::new(rustls::crypto::ring::default_provider()),
        )?;
        let issued = generate_simple_self_signed(vec![name.to_owned()])?;
        let pem = format!(
            "{}{}",
            issued.signing_key.serialize_pem(),
            issued.cert.pem()
        );
        write(&root.path().join(format!("{name}+token")), pem.as_bytes())?;
        assert!(cache.go_seed().is_none());
        let legacy = root.path().join(name);
        write(&legacy, pem.as_bytes())?;
        assert!(cache.go_seed().is_some_and(|seed| seed.valid_now()));
        let ids = [name.to_owned()];
        cache
            .store_cert(&ids, "directory-a", pem.as_bytes())
            .await?;
        assert!(cache.load_cert(&ids, "directory-b").await?.is_none());
        assert_eq!(
            cache.load_cert(&ids, "directory-a").await?.as_deref(),
            Some(pem.as_bytes())
        );
        let wrong = generate_simple_self_signed(vec!["other.example.test".into()])?;
        let wrong = format!("{}{}", wrong.signing_key.serialize_pem(), wrong.cert.pem());
        assert!(
            cache
                .store_cert(&ids, "directory-a", wrong.as_bytes())
                .await
                .is_err()
        );
        assert_eq!(
            cache.load_cert(&ids, "directory-a").await?.as_deref(),
            Some(pem.as_bytes())
        );
        assert_eq!(fs::read(&legacy)?, pem.as_bytes());
        Ok(())
    }
}
