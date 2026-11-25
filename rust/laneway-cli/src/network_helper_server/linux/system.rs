use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use nix::libc;

use super::{
    super::{Setup, socket::syscall},
    protected_path,
};

const IP_OUTPUT_LIMIT: u64 = 64 << 10;
const COMMAND_OUTPUT_LIMIT: u64 = 1 << 20;

pub(super) struct Ip {
    executable: PathBuf,
    runner: Runner,
}

impl Ip {
    pub(super) fn new(state: &Path, lock: &File) -> Result<Self> {
        let runner = Runner::new(state, lock)?;
        Ok(Self {
            executable: locate("ip")?,
            runner,
        })
    }

    pub(super) fn command(&self, args: &[&str], deadline: Instant) -> Result<String> {
        let (ok, stdout, stderr) =
            self.runner
                .output_path(&self.executable, args, deadline, IP_OUTPUT_LIMIT)?;
        ensure!(
            ok,
            "ip {args:?}: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
        String::from_utf8(stdout).context("non-UTF-8 iproute2 output")
    }
}

pub(super) struct Runner {
    state: PathBuf,
    lock: File,
}

impl Runner {
    pub(super) fn new(state: &Path, lock: &File) -> Result<Self> {
        Ok(Self {
            state: state.to_owned(),
            lock: lock.try_clone()?,
        })
    }

    pub(super) fn run(&self, tool: &str, args: &[&str], deadline: Instant) -> Result<Vec<u8>> {
        let (ok, stdout, stderr) = self.output(tool, args, deadline)?;
        ensure!(
            ok,
            "{tool} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        );
        Ok(stdout)
    }

    pub(super) fn output(
        &self,
        tool: &str,
        args: &[&str],
        deadline: Instant,
    ) -> Result<(bool, Vec<u8>, Vec<u8>)> {
        self.output_path(&locate(tool)?, args, deadline, COMMAND_OUTPUT_LIMIT)
    }

    fn output_path(
        &self,
        executable: &Path,
        args: &[&str],
        deadline: Instant,
        limit: u64,
    ) -> Result<(bool, Vec<u8>, Vec<u8>)> {
        ensure!(
            deadline > Instant::now(),
            "network helper operation timed out"
        );
        let mut stdout = tempfile::tempfile_in(&self.state)?;
        let mut stderr = tempfile::tempfile_in(&self.state)?;
        let mut command = Command::new(executable);
        command
            .args(args)
            .current_dir("/")
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?);
        let parent = unsafe { libc::getpid() };
        let lock = self.lock.as_raw_fd();
        // Kernel route changes cannot outlive the session. Keep the route lock
        // in the child as well, so recovery cannot race with a dying command.
        // This post-fork closure uses only async-signal-safe Linux syscalls.
        unsafe {
            command.pre_exec(move || {
                syscall(libc::fcntl(lock, libc::F_SETFD, 0))?;
                syscall(libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ))?;
                if libc::getppid() != parent {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                Ok(())
            });
        }
        let mut process = command
            .spawn()
            .with_context(|| format!("execute protected command {}", executable.display()))?;
        let result = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match process.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if !remaining.is_zero() => {
                    thread::sleep(remaining.min(Duration::from_millis(3)))
                }
                Ok(None) => break Err(anyhow::anyhow!("network helper operation timed out")),
                Err(error) => break Err(error.into()),
            }
        };
        let status = match result {
            Ok(status) => status,
            Err(error) => {
                let _ = process.kill();
                let _ = process.wait();
                return Err(error);
            }
        };
        Ok((
            status.success(),
            output(&mut stdout, limit)?,
            output(&mut stderr, limit)?,
        ))
    }
}

fn locate(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && !name.contains('/') && !matches!(name, "." | ".."),
        "invalid network command"
    );
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let command = Path::new(directory).join(name);
        match fs::canonicalize(&command) {
            Ok(executable) => {
                ensure!(
                    protected_path(&executable, false)?,
                    "unsafe network command {name}"
                );
                return Ok(executable);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("resolve protected command {name}"));
            }
        }
    }
    anyhow::bail!("locate protected system command {name}")
}

fn output(file: &mut File, limit: u64) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    file.rewind()?;
    file.take(limit + 1).read_to_end(&mut output)?;
    ensure!(
        output.len() as u64 <= limit,
        "network command output exceeds helper limit"
    );
    Ok(output)
}

pub(super) fn interface_index(name: &str) -> Result<Option<u32>> {
    let name = CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index != 0 {
        return Ok(Some(index));
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENODEV | libc::ENXIO)) {
        Ok(None)
    } else {
        Err(error).context("look up Linux interface index")
    }
}

pub(super) fn open_tun(ip: &Ip, setup: &Setup, deadline: Instant) -> Result<(File, u32)> {
    let packet = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .context("open Linux TUN device")?;
    let metadata = packet.metadata()?;
    ensure!(
        metadata.file_type().is_char_device() && metadata.rdev() == libc::makedev(10, 200),
        "invalid Linux TUN device"
    );
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    for (destination, byte) in request.ifr_name.iter_mut().zip(setup.name.bytes()) {
        *destination = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as _;
    syscall(unsafe { libc::ioctl(packet.as_raw_fd(), libc::TUNSETIFF, &mut request) })
        .context("create exclusive, nonpersistent Linux TUN interface")?;
    let index = interface_index(&setup.name)?.context("new TUN interface has no index")?;
    ip.command(
        &[
            "link",
            "set",
            "dev",
            &setup.name,
            "mtu",
            &setup.mtu.to_string(),
            "up",
        ],
        deadline,
    )?;
    for address in &setup.addresses {
        let family = if address.addr().is_ipv4() { "-4" } else { "-6" };
        ip.command(
            &[
                family,
                "address",
                "add",
                &address.to_string(),
                "dev",
                &setup.name,
            ],
            deadline,
        )?;
    }
    Ok((packet, index))
}

pub(super) fn namespace_cookie() -> Result<u64> {
    const SO_NETNS_COOKIE: libc::c_int = 71;
    let socket =
        syscall(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })?;
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let mut cookie = 0u64;
    let mut length = mem::size_of_val(&cookie) as libc::socklen_t;
    syscall(unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_NETNS_COOKIE,
            (&raw mut cookie).cast(),
            &mut length,
        )
    })
    .context("identify the Linux network namespace for recovery (requires SO_NETNS_COOKIE)")?;
    ensure!(
        length as usize == mem::size_of_val(&cookie) && cookie != 0,
        "invalid network namespace cookie"
    );
    Ok(cookie)
}
