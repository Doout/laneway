//! The macOS host-networking installation and its protected helper.
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use tempfile::Builder;

use crate::client_update::{
    release::{check_candidate, confirm_install, find_on_path, prepare_release},
    unix::{install_files, protected_directory, root_cosign},
};

const BIN: &str = "/usr/local/bin";
const CLIENT: &str = "/usr/local/bin/laneway";
const COMPAT: &str = "/usr/local/bin/laneway-compat";
const NODE: &str = "/usr/local/bin/lanewayd";
pub(crate) const HELPER: &str = "/Library/PrivilegedHelperTools/laneway-network-helper";
const LIMIT: u64 = 128 << 20;
const SUDO: &str = "/usr/bin/sudo";

pub(crate) fn configure(check: bool, yes: bool) -> Result<()> {
    ensure!(!(check && yes), "--check and --yes cannot be used together");
    let source = current_executable()?;
    let files = install_sources(&source)?;
    if let Err(err) = verify_files(&files) {
        if check {
            return Err(err);
        }
        if nix::unistd::geteuid().is_root() {
            for (_, destination) in &files {
                ensure_install_directory(destination.parent().context("invalid install path")?)?;
            }
            install_files(Path::new(BIN), &files)?;
            verify_files(&files)?;
        } else {
            ensure!(
                crate::compat::trusted_executable(Path::new(SUDO)),
                "unsafe macOS sudo executable"
            );
            if !yes {
                confirm_helper_install()?;
            }
            let status = Command::new(SUDO)
                .arg(&source)
                .args(["configure", "--system", "--yes"])
                .status()
                .context("install the root-owned macOS network helper")?;
            ensure!(
                status.success(),
                "macOS system configuration exited with {status}"
            );
            return Ok(());
        }
    }
    println!("macOS client configured cli={CLIENT} helper={HELPER}");
    Ok(())
}

pub(crate) fn verify_installation() -> Result<()> {
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "foreground connect requires an ordinary macOS user"
    );
    let source = current_executable()?;
    verify_files(&install_sources(&source)?)
}

pub(crate) fn update(yes: bool) -> Result<()> {
    let root = nix::unistd::geteuid().is_root();
    let executable = if root {
        env::current_exe().context("locate the protected Laneway frontend")?
    } else {
        current_executable()?
    };
    ensure!(
        executable == Path::new(CLIENT) && crate::compat::trusted_executable(&executable),
        "macOS system update requires the protected installation at {CLIENT}"
    );
    let cosign = if root {
        root_cosign()?
    } else {
        find_on_path("cosign", env::var_os("PATH").as_deref())
            .context("cosign is required to authenticate the signed release")?
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        arch => bail!("unsupported macOS update architecture: {arch}"),
    };
    let mut builder = Builder::new();
    builder.prefix(".laneway-macos-update-");
    let stage = if root {
        builder.tempdir_in("/private/tmp")?
    } else {
        builder.tempdir()?
    };
    let binaries = [
        (
            "laneway",
            format!("laneway-native_darwin_{arch}"),
            "version",
        ),
        (
            "laneway-compat",
            format!("laneway-compat_darwin_{arch}"),
            "version",
        ),
        ("lanewayd", format!("lanewayd_darwin_{arch}"), "--version"),
    ];
    let assets = binaries
        .each_ref()
        .map(|(name, asset, _)| (*name, asset.as_str()));
    let tag = prepare_release(stage.path(), &cosign, &assets, None)?;
    let version = &tag[1..];
    for (name, _, flag) in binaries {
        let expected = if name == "lanewayd" {
            format!("lanewayd {version}")
        } else {
            version.to_owned()
        };
        check_candidate(&stage.path().join(name), flag, &expected)?;
    }
    if !yes {
        confirm_install(&tag, Path::new(BIN))?;
    }
    let candidate = stage.path().join("laneway");
    let status = Command::new(&candidate)
        .args(["configure", "--system", "--yes"])
        .status()
        .context("install the verified macOS release")?;
    ensure!(
        status.success(),
        "macOS release configuration exited with {status}"
    );
    verify_files(&install_sources(&candidate)?)?;
    println!("Updated laneway, lanewayd, laneway-compat and the macOS network helper to {tag}");
    println!("Restart any running lanewayd processes to use the new version.");
    Ok(())
}

fn current_executable() -> Result<PathBuf> {
    env::current_exe()
        .context("locate current Laneway frontend")?
        .canonicalize()
        .context("resolve current Laneway frontend")
}

fn install_sources(frontend: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let companion = frontend.with_file_name("laneway-compat");
    let node = frontend.with_file_name("lanewayd");
    let files = [
        (frontend.to_owned(), PathBuf::from(CLIENT)),
        (companion, PathBuf::from(COMPAT)),
        (node, PathBuf::from(NODE)),
        (frontend.to_owned(), PathBuf::from(HELPER)),
    ];
    for (source, _) in &files {
        let metadata = fs::symlink_metadata(source).with_context(|| {
            format!(
                "install the matching Laneway release to restore {}",
                source.display()
            )
        })?;
        ensure!(
            metadata.is_file()
                && metadata.mode() & 0o111 != 0
                && (1..=LIMIT).contains(&metadata.len()),
            "Laneway source {} is not a bounded regular executable",
            source.display()
        );
    }
    Ok(files.into())
}

fn ensure_install_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            ensure_install_directory(path.parent().context("invalid system directory")?)?;
            fs::create_dir(path)?;
        }
        Err(err) => return Err(err).with_context(|| format!("inspect {}", path.display())),
    }
    ensure!(
        protected_directory(path),
        "unsafe macOS installation directory {}",
        path.display()
    );
    Ok(())
}

fn verify_files(files: &[(PathBuf, PathBuf)]) -> Result<()> {
    for (source, destination) in files {
        let guidance = || {
            format!(
                "verify {}; run 'laneway configure --system'",
                destination.display()
            )
        };
        let metadata = fs::symlink_metadata(destination).with_context(guidance)?;
        ensure!(
            metadata.gid() == 0 && crate::compat::trusted_executable(destination),
            "{} must be a protected root:wheel executable",
            destination.display()
        );
        ensure!(
            digest(source)? == digest(destination)?,
            "{} does not match the installed Laneway release; run 'laneway configure --system'",
            destination.display()
        );
    }
    Ok(())
}

fn digest(path: &Path) -> Result<[u8; 32]> {
    let mut reader = File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take(LIMIT + 1);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    let mut total = 0;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(total <= LIMIT, "macOS executable exceeds the size limit");
        hasher.update(&buffer[..count]);
    }
    ensure!(total != 0, "macOS executable is empty");
    Ok(hasher.finalize().into())
}

fn confirm_helper_install() -> Result<()> {
    use std::io::{BufRead, BufReader};
    let mut terminal = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context(
            "confirmation requires a terminal; rerun with --yes for unattended installation",
        )?;
    write!(
        terminal,
        "Install the Laneway system client and its root-owned network helper? [y/N]: "
    )?;
    terminal.flush()?;
    let mut reply = String::new();
    BufReader::new(&terminal).read_line(&mut reply)?;
    ensure!(
        matches!(reply.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        "macOS configuration cancelled"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn the_helper_source_matches_the_packaged_implementation() {
        let package = tempfile::tempdir().unwrap();
        let cli = package.path().join("laneway");
        let compat = package.path().join("laneway-compat");
        let node = package.path().join("lanewayd");
        for path in [&cli, &compat, &node] {
            fs::write(path, path.file_name().unwrap().as_encoded_bytes()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let files = install_sources(&cli).unwrap();
        assert!(files.contains(&(cli.clone(), PathBuf::from(CLIENT))));
        assert!(files.contains(&(cli.clone(), PathBuf::from(HELPER))));
        assert_ne!(digest(&cli).unwrap(), digest(&compat).unwrap());
        fs::remove_file(&compat).unwrap();
        symlink(&cli, &compat).unwrap();
        assert!(install_sources(&cli).is_err());
    }
}
