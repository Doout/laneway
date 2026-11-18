//! Runtime side of the transient systemd credential contract.

use std::{
    ffi::CStr,
    fs::{self, File, OpenOptions},
    future::Future,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};

use crate::{Config, TlsConfig};

use super::native::WireGuardNode;

const CREDENTIAL_ROOT: &str = "/run/credentials";
const UNIT_PREFIX: &str = "laneway-ephemeral-exit-";
const RAMFS_MAGIC: libc::c_long = 0x858458f6_u32 as libc::c_long;

/// Native service for a private systemd network namespace. Keeps TLS
/// credentials pinned by descriptor for the entire lifetime of the service.
pub struct SharedHostExit {
    node: WireGuardNode,
    _tls_credentials: [File; 3],
}

impl SharedHostExit {
    /// Lock process memory, disable dumping, and reject unexpected inherited
    /// descriptors. Invoke before starting threads or reading any credential.
    pub fn harden_process() -> Result<()> {
        // SAFETY: The kernel operations only change this process. The rlimit
        // argument is initialized and valid throughout the syscall.
        unsafe {
            os_result(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0))
                .context("disable shared-host process dumps")?;
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            os_result(libc::setrlimit(libc::RLIMIT_CORE, &zero))
                .context("disable shared-host core files")?;
            os_result(libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE))
                .context("lock shared-host service memory")?;
        }
        verify_inherited_descriptors()
    }

    /// Read the existing bootstrap's sealed Go TOML and exact credential names.
    /// Does not start the network or write any credentials to disk.
    /// Requires process hardening and the systemd namespace setup beforehand.
    pub fn load(credential_path: &Path) -> Result<Self> {
        let runtime = service_runtime(credential_path)?;
        let credentials = open_ram_directory(credential_path)?;
        let ca = read_credential(&credentials, c"ca.crt", 4 << 20)?;
        let certificate = read_credential(&credentials, c"node.crt", 4 << 20)?;
        let private_key = read_credential(&credentials, c"node.key", 1 << 20)?;
        let wireguard = read_credential(&credentials, c"wireguard.key", 32)?;
        let config = read_credential(&credentials, c"config", 256 << 10)?;
        let (config, generation) = Config::load_shared_host_config(
            config,
            TlsConfig {
                ca: descriptor_path(&ca),
                certificate: descriptor_path(&certificate),
                private_key: descriptor_path(&private_key),
            },
            &runtime,
        )?;
        let node = WireGuardNode::from_credential(config, wireguard, generation)?;
        Ok(Self {
            node,
            _tls_credentials: [ca, certificate, private_key],
        })
    }

    /// Run until the operator shuts down the unit or its controller lease
    /// reaches a terminal state.
    pub async fn run_until(self, shutdown: impl Future<Output = ()>) -> Result<()> {
        let Self {
            node,
            _tls_credentials,
        } = self;
        node.run_until(shutdown).await
    }
}

fn service_runtime(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".service"))
        .context("invalid shared-host credential service name")?;
    let token = name
        .strip_prefix(UNIT_PREFIX)
        .context("invalid shared-host unit prefix")?;
    ensure!(
        token.len() == 16
            && token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && path.as_os_str()
                == Path::new(CREDENTIAL_ROOT)
                    .join(format!("{name}.service"))
                    .as_os_str(),
        "invalid shared-host credential directory"
    );
    Ok(Path::new("/run").join(name))
}

fn open_ram_directory(path: &Path) -> Result<File> {
    // The fixed parent of the production path is system-wide and root owned.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("open shared-host credential directory")?;
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no arguments.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_dir()
            && (metadata.uid() == 0 || metadata.uid() == uid)
            && metadata.mode() & 0o500 == 0o500
            && metadata.mode() & 0o027 == 0,
        "unsafe shared-host credential directory ownership or mode"
    );
    let mut information = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: The live fd and writable statfs storage are valid; the kernel
    // initializes the record on success.
    unsafe {
        os_result(libc::fstatfs(
            directory.as_raw_fd(),
            information.as_mut_ptr(),
        ))?;
        let filesystem = information.assume_init().f_type;
        ensure!(
            matches!(filesystem, libc::TMPFS_MAGIC | RAMFS_MAGIC),
            "shared-host credentials must be on a memory-backed filesystem"
        );
    }
    Ok(directory)
}

fn read_credential(directory: &File, name: &CStr, max_bytes: u64) -> Result<File> {
    // SAFETY: the directory and constant basename live through the call and
    // the returned descriptor (on success) is uniquely owned.
    let file = unsafe {
        let fd = libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        os_result(fd).with_context(|| format!("open shared-host credential {name:?}"))?;
        File::from_raw_fd(fd)
    };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && (metadata.uid() == 0 || metadata.uid() == uid)
            && matches!(metadata.mode() & 0o777, 0o400 | 0o440)
            && (1..=max_bytes).contains(&metadata.len()),
        "unsafe shared-host credential ownership, mode or size: {name:?}"
    );
    Ok(file)
}

fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn os_result(value: libc::c_int) -> io::Result<()> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn verify_inherited_descriptors() -> Result<()> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir("/proc/self/fd").context("inspect shared-host process descriptors")? {
        let name = entry?.file_name();
        if let Some(fd) = name
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
            && fd > 2
        {
            descriptors.push(fd);
        }
    }
    // The read_dir iterator is dropped before checking its own descriptor.
    for fd in descriptors {
        // SAFETY: F_GETFD reads flags and does not claim ownership.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            let error = io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(libc::EBADF),
                "read shared-host descriptor flags: {error}"
            );
        } else {
            ensure!(
                flags & libc::FD_CLOEXEC != 0,
                "unexpected inherited shared-host descriptor {fd}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn runtime_is_derived_from_an_exact_unit_path() -> Result<()> {
        let name = "laneway-ephemeral-exit-112233aabbccddee";
        let path = format!("/run/credentials/{name}.service");
        assert_eq!(
            service_runtime(Path::new(&path))?,
            Path::new("/run").join(name)
        );
        assert!(service_runtime(Path::new(&format!("/tmp/{name}.service"))).is_err());
        assert!(
            service_runtime(Path::new(&format!(
                "/run/credentials/../credentials/{name}.service"
            )))
            .is_err()
        );
        assert!(
            service_runtime(Path::new(
                "/run/credentials/laneway-ephemeral-exit-bad.service"
            ))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn credentials_reject_unsafe_files_and_keep_the_original_descriptor() -> Result<()> {
        let fixture = tempfile::tempdir_in("/dev/shm")?;
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700))?;
        let path = fixture.path().join("node.key");
        let replacement = fixture.path().join("replacement");
        fs::write(&path, b"original fixture")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        let dir = open_ram_directory(fixture.path())?;
        let original = read_credential(&dir, c"node.key", 32)?;
        assert!(read_credential(&dir, c"node.key", 10).is_err());
        fs::hard_link(&path, &replacement)?;
        assert!(read_credential(&dir, c"node.key", 32).is_err());
        fs::remove_file(&path)?;
        symlink(&replacement, &path)?;
        assert!(read_credential(&dir, c"node.key", 32).is_err());
        let mut fixture_bytes = Vec::new();
        File::open(descriptor_path(&original))?.read_to_end(&mut fixture_bytes)?;
        assert_eq!(fixture_bytes, b"original fixture");
        fs::remove_file(&path)?;
        fs::rename(&replacement, &path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
        assert!(read_credential(&dir, c"node.key", 32).is_err());
        Ok(())
    }
}
