use std::{
    env, fs,
    os::windows::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
};

use anyhow::{Context, Result, bail, ensure};
use tempfile::Builder;

use super::release::{check_candidate, confirm_install, find_on_path, prepare_release};

const REPARSE_POINT: u32 = 0x400;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RETRY_AFTER_EXIT: i32 = 75;
const INSTALLER: &str = "install-node.ps1";

pub(super) fn run(yes: bool) -> Result<()> {
    let local = env::var_os("LOCALAPPDATA").context("LOCALAPPDATA must be an absolute path")?;
    let executable = env::current_exe().context("locate current Laneway executable")?;
    let bin = installation_directory(Path::new(&local), &executable)?;
    let lookup = env::var_os("PATH");
    let powershell = find_on_path("pwsh.exe", lookup.as_deref())
        .context("laneway update requires PowerShell 7 (pwsh.exe)")?;
    let cosign = find_on_path("cosign.exe", lookup.as_deref())
        .context("cosign is required to authenticate the signed release")?;
    let architecture = native_architecture(&powershell)?;
    let names = [
        format!("laneway-native_windows_{architecture}.exe"),
        format!("laneway-compat_windows_{architecture}.exe"),
        format!("lanewayd_windows_{architecture}.exe"),
    ];
    let assets = names.each_ref().map(|name| (name.as_str(), name.as_str()));
    let stage = Builder::new().prefix(".laneway-stage-").tempdir_in(&bin)?;
    let tag = prepare_release(stage.path(), &cosign, &assets, Some(INSTALLER))?;
    let expected = &tag[1..];
    for (name, flag, version) in [
        (&names[0], "version", expected.to_owned()),
        (&names[1], "version", expected.to_owned()),
        (&names[2], "--version", format!("lanewayd {expected}")),
    ] {
        check_candidate(&stage.path().join(name), flag, &version)?;
    }
    if !yes {
        confirm_install(&tag, &bin)?;
    }
    let mut apply = installer(&powershell, stage.path(), &tag);
    let status = apply.status().context("apply verified Windows update")?;
    if status.success() {
        println!("Restart any running lanewayd process to use the new version.");
        return Ok(());
    }
    ensure!(
        status.code() == Some(RETRY_AFTER_EXIT),
        "install verified Windows update: {status}"
    );

    // The signed installer rolled back before requesting a retry. Keep its
    // recovery logic in one place and wait for this running image to exit.
    let log = Builder::new()
        .prefix("laneway-update-")
        .suffix(".log")
        .tempfile_in(&bin)?;
    let (log_file, log_path) = log.keep()?;
    let diagnostics = format!("start deferred update (log {})", log_path.display());
    installer(&powershell, stage.path(), &tag)
        .arg("-WaitForProcessId")
        .arg(process::id().to_string())
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .spawn()
        .with_context(|| diagnostics)?;
    let _ = stage.keep();
    println!(
        "Verified Laneway {tag} is staged. Installation will finish after this command exits. Status: {}",
        log_path.display()
    );
    Ok(())
}

fn installer(powershell: &Path, stage: &Path, tag: &str) -> Command {
    let mut command = Command::new(powershell);
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(stage.join(INSTALLER))
        .args(["-Version", tag, "-VerifiedStage"])
        .arg(stage);
    command
}

fn native_architecture(powershell: &Path) -> Result<&'static str> {
    let output = Command::new(powershell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()",
        ])
        .output()
        .context("identify Windows system architecture")?;
    ensure!(
        output.status.success(),
        "could not identify Windows architecture"
    );
    match String::from_utf8_lossy(&output.stdout).trim() {
        "X64" => Ok("amd64"),
        "Arm64" => Ok("arm64"),
        other => bail!("unsupported Windows system architecture: {other}"),
    }
}

fn installation_directory(local: &Path, executable: &Path) -> Result<PathBuf> {
    ensure!(local.is_absolute(), "LOCALAPPDATA must be an absolute path");
    let bin = local.join("Laneway").join("bin");
    let expected = bin.join("laneway.exe");
    ensure!(
        same_windows_path(executable, &expected),
        "run the per-user installed client at {} to update",
        expected.display()
    );
    for ancestor in bin.ancestors() {
        let info = fs::symlink_metadata(ancestor)?;
        ensure!(
            info.is_dir() && info.file_attributes() & REPARSE_POINT == 0,
            "the Laneway bin directory must not use a junction or symlink: {}",
            ancestor.display()
        );
    }
    Ok(bin)
}

fn same_windows_path(left: &Path, right: &Path) -> bool {
    fn normal(path: &Path) -> String {
        let text = path.to_string_lossy().replace('/', "\\");
        if let Some(suffix) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{suffix}").to_lowercase();
        }
        text.strip_prefix(r"\\?\").unwrap_or(&text).to_lowercase()
    }
    normal(left) == normal(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_the_installed_executable_across_windows_path_spellings() {
        assert!(same_windows_path(
            Path::new(r"\\?\C:\Users\user\Laneway\bin\Laneway.exe"),
            Path::new("c:/Users/user/Laneway/bin/laneway.exe"),
        ));
        assert!(!same_windows_path(
            Path::new(r"C:\Users\user\Downloads\laneway.exe"),
            Path::new(r"C:\Users\user\Laneway\bin\laneway.exe"),
        ));
    }

    #[test]
    fn invokes_the_installer_from_the_verified_stage() {
        let stage = Path::new(r"C:\Users\user\Laneway\bin\.laneway-stage-test");
        let command = installer(Path::new("pwsh.exe"), stage, "v1.2.3");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(
            &args[..5],
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File"
            ]
        );
        let script = stage.join(INSTALLER);
        assert_eq!(args[5], script.as_os_str());
        assert_eq!(&args[6..9], ["-Version", "v1.2.3", "-VerifiedStage"]);
        assert_eq!(args[9], stage.as_os_str());
    }
}
