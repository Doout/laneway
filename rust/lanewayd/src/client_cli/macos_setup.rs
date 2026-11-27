use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, Read, Seek, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, chown},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

const CLIENT: &str = "/usr/local/bin/laneway";
const RUNTIME: &str = "/Library/Application Support/Laneway/lanewayd-rs";
const SIZE_LIMIT: u64 = 128 << 20;

#[derive(Parser)]
#[command(name = "laneway configure", disable_version_flag = true)]
struct Options {
    #[arg(long, conflicts_with = "yes")]
    check: bool,
    #[arg(long)]
    yes: bool,
}

pub(crate) fn run(source: PathBuf, args: impl Iterator<Item = OsString>) -> Result<()> {
    let options = Options::try_parse_from(std::iter::once("laneway configure".into()).chain(args))?;
    let source = source.canonicalize()?;
    let companion = if source == Path::new(CLIENT) {
        PathBuf::from(RUNTIME)
    } else {
        source.with_file_name("lanewayd-rs")
    };
    native_executable(&companion)?;
    let existing = verify(&source, &companion);
    if existing.is_err() {
        if options.check || source == Path::new(CLIENT) {
            return existing;
        }
        // SAFETY: geteuid only reads the process credentials.
        if unsafe { libc::geteuid() } != 0 {
            if !options.yes {
                confirm()?;
            }
            let status = Command::new("/usr/bin/sudo")
                .arg("--")
                .arg(env::current_exe()?)
                .arg("_mac-setup")
                .arg(&source)
                .arg("--yes")
                .status()?;
            ensure!(
                status.success(),
                "macOS system configuration failed: {status}"
            );
            return Ok(());
        }
        install(&source, &companion)?;
        verify(&source, &companion)?;
    }
    println!("macOS client configured cli={CLIENT} runtime={RUNTIME}");
    Ok(())
}

fn confirm() -> Result<()> {
    let mut terminal = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context(
            "confirmation requires a terminal; rerun with --yes for unattended installation",
        )?;
    terminal.write_all(b"Install the Laneway CLI and root-owned Rust network runtime? [y/N]: ")?;
    terminal.flush()?;
    let mut response = String::new();
    io::BufReader::new(terminal)
        .take(128)
        .read_line(&mut response)?;
    ensure!(
        matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        "macOS configuration cancelled; no changes were made"
    );
    Ok(())
}

fn native_executable(path: &Path) -> Result<()> {
    let mut file = open_binary(path)?;
    let mut header = [0; 16];
    file.read_exact(&mut header)?;
    let cpu: u32 = if cfg!(target_arch = "aarch64") {
        0x0100_000c
    } else {
        0x0100_0007
    };
    ensure!(
        header[..4] == [0xcf, 0xfa, 0xed, 0xfe]
            && header[4..8] == cpu.to_le_bytes()
            && header[12..16] == 2u32.to_le_bytes(),
        "expected a native macOS executable at {}",
        path.display()
    );
    Ok(())
}

fn open_binary(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && (1..=SIZE_LIMIT).contains(&metadata.len())
            && metadata.mode() & 0o111 != 0,
        "expected a bounded regular executable at {}",
        path.display()
    );
    Ok(file)
}

fn trusted_runtime(directory: &Path) -> Result<()> {
    for parent in directory.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "privileged runtime parent must be protected: {}",
            parent.display()
        );
    }
    Ok(())
}

fn checksum(file: &mut File) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let size = io::copy(&mut file.take(SIZE_LIMIT + 1), &mut digest)?;
    ensure!(
        (1..=SIZE_LIMIT).contains(&size),
        "hash input exceeds size limit"
    );
    file.rewind()?;
    Ok(digest.finalize().into())
}

fn verify(source: &Path, companion: &Path) -> Result<()> {
    let runtime = Path::new(RUNTIME);
    trusted_runtime(runtime.parent().context("missing runtime parent")?)?;
    for (target, expected) in [(Path::new(CLIENT), source), (runtime, companion)] {
        let mut installed = open_binary(target)?;
        let metadata = installed.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.gid() == 0 && metadata.mode() & 0o022 == 0,
            "installed binary must be root:wheel: {}",
            target.display()
        );
        ensure!(
            checksum(&mut installed)? == checksum(&mut open_binary(expected)?)?,
            "installed binary differs from this Laneway archive: {}",
            target.display()
        );
    }
    native_executable(runtime)
}

fn stage(source: &Path, parent: &Path) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new_in(parent)?;
    let read = io::copy(
        &mut open_binary(source)?.take(SIZE_LIMIT + 1),
        file.as_file_mut(),
    )?;
    ensure!(
        (1..=SIZE_LIMIT).contains(&read),
        "copy exceeds allowed binary size"
    );
    // SAFETY: this is the open staging file's own descriptor.
    use std::os::fd::AsRawFd;
    if unsafe { libc::fchown(file.as_file().as_raw_fd(), 0, 0) } != 0 {
        return Err(io::Error::last_os_error()).context("protect staged executable");
    }
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn ensure_directory(path: &Path, privileged: bool) -> Result<()> {
    match fs::DirBuilder::new().mode(0o755).create(path) {
        Ok(()) if privileged => chown(path, Some(0), Some(0))?,
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    }
    let metadata = path.symlink_metadata()?;
    ensure!(
        metadata.is_dir(),
        "installation directory is not a real directory: {}",
        path.display()
    );
    if privileged {
        ensure!(
            metadata.gid() == 0,
            "privileged runtime directory must be root:wheel"
        );
        trusted_runtime(path)?;
    }
    Ok(())
}

fn existing(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "refusing to replace non-regular {}",
                path.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn install(source: &Path, companion: &Path) -> Result<()> {
    let cli = Path::new(CLIENT);
    let runtime = Path::new(RUNTIME);
    let cli_dir = cli.parent().context("missing CLI directory")?;
    let runtime_dir = runtime.parent().context("missing runtime directory")?;
    trusted_runtime(runtime_dir.parent().context("missing runtime parent")?)?;
    ensure_directory(Path::new("/usr/local"), false)?;
    ensure_directory(cli_dir, false)?;
    ensure_directory(runtime_dir, true)?;
    existing(cli)?;
    let backup = existing(runtime)?
        .then(|| stage(runtime, runtime_dir))
        .transpose()?;
    let client = stage(source, cli_dir)?;
    let daemon = stage(companion, runtime_dir)?;
    native_executable(daemon.path())?;
    daemon
        .persist(runtime)
        .context("install the Rust runtime")?;
    if let Err(error) = client.persist(cli) {
        if let Some(backup) = backup {
            backup
                .persist(runtime)
                .context("restore previous Rust runtime")?;
        } else {
            fs::remove_file(runtime).context("remove newly installed runtime")?;
        }
        return Err(error).context("install client");
    }
    Ok(())
}

pub(crate) fn update(source: PathBuf, args: &[OsString], privileged: bool) -> Result<()> {
    use lanewayd_rs::client_package;

    let args = args
        .strip_prefix(&[OsString::from("client")])
        .unwrap_or(args);
    let yes = match args {
        [] => false,
        [arg]
            if matches!(
                arg.to_str(),
                Some("--yes" | "-yes" | "--yes=true" | "-yes=true")
            ) =>
        {
            true
        }
        [arg] if matches!(arg.to_str(), Some("--yes=false" | "-yes=false")) => false,
        [arg] if arg == "--help" || arg == "-h" => {
            println!("usage: laneway update client [--yes]");
            return Ok(());
        }
        _ => anyhow::bail!("usage: laneway update client [--yes]"),
    };
    let source = source.canonicalize()?;
    // SAFETY: geteuid reads the process credentials.
    let uid = unsafe { libc::geteuid() };
    if !privileged && let Some(bin) = client_package::user_bin(&source, uid)? {
        return super::runtime()?.block_on(client_package::update_user(&bin, uid));
    }
    if !privileged && uid == 0 {
        anyhow::bail!(
            "run 'laneway update client' as your normal macOS user; the verified package will request sudo to install"
        );
    }
    ensure!(
        source == Path::new(CLIENT),
        "update from the installed laneway in ~/.local/bin or /usr/local/bin"
    );
    let companion = Path::new(RUNTIME);
    verify(&source, companion)?;
    if !privileged {
        if !yes {
            confirm()?;
        }
        let status = Command::new("/usr/bin/sudo")
            .arg("--")
            .arg(companion)
            .arg("_mac-update-approved")
            .arg(&source)
            .arg("--yes")
            .status()?;
        ensure!(status.success(), "macOS client update failed: {status}");
        return Ok(());
    }
    ensure!(uid == 0 && yes, "system client installation requires root");
    let directory = companion
        .parent()
        .context("missing protected runtime directory")?;
    let _lock = client_package::InstallLock::acquire(directory)?;
    let stage = tempfile::Builder::new()
        .prefix(".client-update-")
        .tempdir_in(directory)?;
    let (tag, archive) = super::runtime()?.block_on(async {
        let previous = client_package::read_version(companion, "--version").await?;
        client_package::prepare(stage.path(), &previous).await
    })?;
    install(&archive.cli, &archive.daemon)?;
    verify(&archive.cli, &archive.daemon)?;
    println!(
        "updated CLI and Rust runtime to {tag} sha256={}",
        hex::encode(archive.checksum)
    );
    Ok(())
}
