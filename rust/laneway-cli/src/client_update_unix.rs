use std::{
    env,
    ffi::OsStr,
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::{Builder, TempDir};

use super::release::{check_candidate, confirm_install, find_on_path, prepare_release};

const BINARIES: [(&str, &str, &str); 3] = [
    ("laneway-compat", "laneway-compat", "version"),
    ("lanewayd", "lanewayd", "--version"),
    ("laneway", "laneway-native", "version"),
];

pub(super) fn run(yes: bool) -> Result<()> {
    let executable = env::current_exe().context("locate current Laneway executable")?;
    let root = nix::unistd::geteuid().is_root();
    #[cfg(target_os = "macos")]
    if root || executable == Path::new("/usr/local/bin/laneway") {
        // The macOS system install also updates its privileged network helper.
        return crate::macos::update(yes);
    }
    let (bin, daemon_dir) = if root || executable == Path::new("/usr/local/bin/laneway") {
        ensure!(root, "system installation requires sudo laneway update");
        ensure!(
            executable == Path::new("/usr/local/bin/laneway")
                && crate::compat::trusted_executable(&executable),
            "root may update only the protected system installation in /usr/local/bin"
        );
        let daemon_dir = PathBuf::from("/usr/local/sbin");
        ensure!(
            protected_directory(&daemon_dir),
            "unsafe system update directory {}",
            daemon_dir.display()
        );
        (PathBuf::from("/usr/local/bin"), daemon_dir)
    } else {
        let bin = user_installation(&executable, env::var_os("HOME").as_deref())?
            .context("run the installed client in ~/.local/bin or /usr/local/bin to update")?;
        (bin.clone(), bin)
    };
    let suffix = platform_suffix(env::consts::OS, env::consts::ARCH)?;
    let cosign = if root {
        root_cosign()?
    } else {
        find_on_path("cosign", env::var_os("PATH").as_deref())
            .context("cosign is required to authenticate the signed release")?
    };

    let stage = Builder::new().prefix(".laneway-native-").tempdir_in(&bin)?;
    let names = BINARIES.map(|(file, asset, _)| (file, format!("{asset}{suffix}")));
    let assets = names
        .each_ref()
        .map(|(file, asset)| (*file, asset.as_str()));
    let tag = prepare_release(stage.path(), &cosign, &assets, None)?;
    let expected = &tag[1..];
    for (binary, _, flag) in BINARIES {
        let candidate = stage.path().join(binary);
        let version = if binary == "lanewayd" {
            format!("lanewayd {expected}")
        } else {
            expected.to_owned()
        };
        check_candidate(&candidate, flag, &version)?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))?;
    }

    if !yes {
        confirm_install(&tag, &bin)?;
    }

    install_binaries(stage, &bin, &daemon_dir)?;
    println!("Updated laneway, lanewayd and laneway-compat to {tag}");
    println!("Restart any running lanewayd process to use the new version.");
    Ok(())
}

pub(crate) fn root_cosign() -> Result<PathBuf> {
    [
        "/usr/local/libexec/laneway/cosign-v3.1.3",
        "/usr/local/bin/cosign",
        "/usr/bin/cosign",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| crate::compat::trusted_executable(path))
    .context("root requires a protected Cosign installation")
}

pub(crate) fn protected_directory(path: &Path) -> bool {
    path.is_absolute()
        && path.ancestors().all(|ancestor| {
            fs::symlink_metadata(ancestor)
                .is_ok_and(|info| info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0)
        })
}

fn user_installation(executable: &Path, home: Option<&OsStr>) -> Result<Option<PathBuf>> {
    let Some(home) = home else {
        return Ok(None);
    };
    let bin = Path::new(home).join(".local/bin");
    let bin = match fs::canonicalize(bin) {
        Ok(bin) => bin,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("resolve native installation directory"),
    };
    let executable = fs::canonicalize(executable).context("resolve Laneway executable")?;
    Ok((executable == bin.join("laneway")).then_some(bin))
}

fn platform_suffix(os: &str, arch: &str) -> Result<String> {
    let os = match os {
        "linux" => "linux",
        "macos" => "darwin",
        _ => bail!("unsupported native update operating system: {os}"),
    };
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("unsupported native update architecture: {arch}"),
    };
    Ok(format!("_{os}_{arch}"))
}

struct InstallationLock(PathBuf);

impl Drop for InstallationLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

struct Replacement {
    work: TempDir,
    destination: PathBuf,
    had_previous: bool,
}

fn install_binaries(stage: TempDir, bin: &Path, daemon_dir: &Path) -> Result<()> {
    let files = BINARIES.map(|(binary, _, _)| {
        let directory = if binary == "lanewayd" {
            daemon_dir
        } else {
            bin
        };
        (stage.path().join(binary), directory.join(binary))
    });
    install_files(bin, &files)
}

/// Stage on each destination filesystem and replace or restore the group.
pub(crate) fn install_files(bin: &Path, files: &[(PathBuf, PathBuf)]) -> Result<()> {
    let lock = bin.join(".laneway-update-lock");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&lock)
        .with_context(|| format!("lock Laneway installation at {}", lock.display()))?;
    let _lock = InstallationLock(lock);

    let root = nix::unistd::geteuid().is_root();
    let mut replacements = Vec::with_capacity(files.len());
    for (source, destination) in files {
        let directory = destination
            .parent()
            .context("update destination has no parent")?;
        let work = Builder::new()
            .prefix(".laneway-update-")
            .tempdir_in(directory)?;
        if root {
            std::os::unix::fs::chown(work.path(), Some(0), Some(0))?;
        }
        let previous = work.path().join("previous");
        let had_previous = match fs::symlink_metadata(destination) {
            Ok(info) if info.is_file() => {
                fs::hard_link(destination, previous)?;
                true
            }
            Ok(info)
                if info.file_type().is_symlink()
                    && destination.file_name() == Some(OsStr::new("lanewayd"))
                    && directory != bin
                    && fs::read_link(destination)? == Path::new("../bin/laneway") =>
            {
                symlink("../bin/laneway", previous)?;
                true
            }
            Ok(_) => bail!(
                "refusing to replace non-regular file {}",
                destination.display()
            ),
            Err(err) if err.kind() == io::ErrorKind::NotFound => false,
            Err(err) => {
                return Err(err).with_context(|| format!("inspect {}", destination.display()));
            }
        };
        let candidate = work.path().join("next");
        fs::copy(source, &candidate)?;
        if root {
            std::os::unix::fs::chown(&candidate, Some(0), Some(0))?;
            fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))?;
        }
        fs::OpenOptions::new()
            .write(true)
            .open(&candidate)?
            .sync_all()?;
        replacements.push(Replacement {
            work,
            destination: destination.clone(),
            had_previous,
        });
    }
    replace_binaries(replacements)
}

fn replace_binaries(mut replacements: Vec<Replacement>) -> Result<()> {
    for index in 0..replacements.len() {
        let item = &replacements[index];
        if let Err(error) = fs::rename(item.work.path().join("next"), &item.destination) {
            let mut errors = Vec::new();
            for item in replacements.drain(..index).rev() {
                let restored = if item.had_previous {
                    fs::rename(item.work.path().join("previous"), &item.destination)
                } else {
                    fs::remove_file(&item.destination)
                };
                if let Err(err) = restored {
                    let retained = item.work.keep();
                    errors.push(format!(
                        "{}: {err}; retained recovery files in {}",
                        item.destination.display(),
                        retained.display()
                    ));
                }
            }
            if !errors.is_empty() {
                bail!(
                    "install Laneway update: {error}; rollback failed: {}",
                    errors.join(", ")
                );
            }
            return Err(error).context("install Laneway update");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_native_installation_to_its_existing_user_bin() {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        let cli = bin.join("laneway");
        fs::write(&cli, "old").unwrap();
        let expected = fs::canonicalize(&bin).unwrap();
        assert_eq!(
            user_installation(&cli, Some(home.path().as_os_str())).unwrap(),
            Some(expected)
        );
        let other = home.path().join("laneway");
        fs::write(&other, "external").unwrap();
        assert_eq!(
            user_installation(&other, Some(home.path().as_os_str())).unwrap(),
            None
        );
        assert_eq!(platform_suffix("linux", "x86_64").unwrap(), "_linux_amd64");
        assert_eq!(
            platform_suffix("macos", "aarch64").unwrap(),
            "_darwin_arm64"
        );
    }

    #[test]
    fn installs_missing_compatibility_binary_with_the_pair() {
        let bin = tempfile::tempdir().unwrap();
        fs::write(bin.path().join("laneway"), "previous cli").unwrap();
        fs::write(bin.path().join("lanewayd"), "previous node").unwrap();
        let stage = Builder::new().tempdir_in(bin.path()).unwrap();
        for (file, _, _) in BINARIES {
            fs::write(stage.path().join(file), file).unwrap();
        }
        install_binaries(stage, bin.path(), bin.path()).unwrap();
        for (file, _, _) in BINARIES {
            assert_eq!(fs::read_to_string(bin.path().join(file)).unwrap(), file);
        }
        assert!(!bin.path().join(".laneway-update-lock").exists());
    }

    #[test]
    fn late_install_failure_restores_previous_node_and_removes_new_compatibility_binary() {
        let bin = tempfile::tempdir().unwrap();
        fs::write(bin.path().join("laneway"), "previous cli").unwrap();
        fs::write(bin.path().join("lanewayd"), "previous node").unwrap();
        let replacements = BINARIES
            .into_iter()
            .map(|(name, _, _)| {
                let destination = bin.path().join(name);
                let work = Builder::new().tempdir_in(bin.path()).unwrap();
                let had_previous = destination.is_file();
                if had_previous {
                    fs::hard_link(&destination, work.path().join("previous")).unwrap();
                }
                if name != "laneway" {
                    fs::write(work.path().join("next"), name).unwrap();
                }
                Replacement {
                    work,
                    destination,
                    had_previous,
                }
            })
            .collect();
        assert!(replace_binaries(replacements).is_err());
        assert_eq!(
            fs::read_to_string(bin.path().join("laneway")).unwrap(),
            "previous cli"
        );
        assert_eq!(
            fs::read_to_string(bin.path().join("lanewayd")).unwrap(),
            "previous node"
        );
        assert!(!bin.path().join("laneway-compat").exists());
        assert!(!bin.path().join(".laneway-update-lock").exists());
    }

    #[test]
    fn system_layout_replaces_only_the_known_legacy_daemon_symlink() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let sbin = root.path().join("sbin");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&sbin).unwrap();
        let daemon = sbin.join("lanewayd");

        for (target, succeeds) in [("../bin/other", false), ("../bin/laneway", true)] {
            symlink(target, &daemon).unwrap();
            let stage = Builder::new().tempdir_in(root.path()).unwrap();
            for (binary, _, _) in BINARIES {
                fs::write(stage.path().join(binary), binary).unwrap();
            }
            assert_eq!(install_binaries(stage, &bin, &sbin).is_ok(), succeeds);
            if succeeds {
                assert_eq!(fs::read_to_string(&daemon).unwrap(), "lanewayd");
                assert_eq!(fs::read_to_string(bin.join("laneway")).unwrap(), "laneway");
                assert_eq!(
                    fs::read_to_string(bin.join("laneway-compat")).unwrap(),
                    "laneway-compat"
                );
                assert!(!bin.join("lanewayd").exists());
            } else {
                assert_eq!(fs::read_link(&daemon).unwrap(), Path::new(target));
                assert!(!bin.join("laneway").exists());
                fs::remove_file(&daemon).unwrap();
            }
        }
    }

    #[test]
    fn refuses_to_install_through_symlink_or_concurrent_writer() {
        let bin = tempfile::tempdir().unwrap();
        let cli = bin.path().join("laneway");
        fs::write(&cli, "untouched").unwrap();
        let node = bin.path().join("lanewayd");
        std::os::unix::fs::symlink(&cli, &node).unwrap();
        let stage = Builder::new().tempdir_in(bin.path()).unwrap();
        assert!(install_binaries(stage, bin.path(), bin.path()).is_err());
        assert!(
            fs::symlink_metadata(&node)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let lock = bin.path().join(".laneway-update-lock");
        fs::create_dir(&lock).unwrap();
        let stage = Builder::new().tempdir_in(bin.path()).unwrap();
        assert!(install_binaries(stage, bin.path(), bin.path()).is_err());
        assert!(lock.exists());
        assert_eq!(fs::read_to_string(cli).unwrap(), "untouched");
    }
}
