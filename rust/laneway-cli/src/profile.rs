use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

mod credentials;
mod store;

#[cfg(target_os = "linux")]
pub(crate) use credentials::read_managed_enrollment_code;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use credentials::{enroll_remembered, read_enrollment_code, validate_platform_artifact};
pub(crate) use credentials::{is_missing, login};
pub(crate) use store::default_authority;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use store::{SavedProfile, load};

const USAGE: &str = "usage: laneway logout DOMAIN";

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    ensure!(args.first().is_some_and(|arg| arg == "logout"), "{USAGE}");
    let Some(authority) = parse_authority(&args[1..])? else {
        println!("{USAGE}");
        return Ok(());
    };
    let root = profile_root(|key| env::var_os(key));
    remove_profile(&root, authority)?;
    println!("logged out of {authority}; the controller identity remains revocable by its NodeID");
    Ok(())
}

fn parse_authority(args: &[OsString]) -> Result<Option<&str>> {
    let args = match args.first().and_then(|arg| arg.to_str()) {
        Some("-h" | "--h" | "-help" | "--help") => return Ok(None),
        Some("--") => &args[1..],
        Some(flag) if flag.starts_with('-') && flag != "-" => {
            bail!("flag provided but not defined: {flag}")
        }
        _ => args,
    };
    let [authority] = args else {
        bail!("{USAGE}");
    };
    authority.to_str().map(Some).context(USAGE)
}

fn profile_root(mut lookup: impl FnMut(&str) -> Option<OsString>) -> PathBuf {
    let mut path = |key| {
        lookup(key)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    if let Some(directory) = path("LANEWAY_PROFILE_DIR") {
        return directory;
    }
    let user_config = if cfg!(windows) {
        path("AppData")
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        path("HOME").map(|home| home.join("Library/Application Support"))
    } else if let Some(xdg) = path("XDG_CONFIG_HOME") {
        xdg.is_absolute().then_some(xdg)
    } else {
        path("HOME").map(|home| home.join(".config"))
    };
    user_config
        .map(|directory| directory.join("laneway").join("profiles"))
        .unwrap_or_else(|| PathBuf::from(".laneway"))
}

fn profile_path(root: &Path, authority: &str) -> PathBuf {
    // Go's strings.ToLower uses the simple Unicode mapping for each rune.
    let authority: String = authority
        .trim()
        .chars()
        .filter_map(|character| character.to_lowercase().next())
        .collect();
    let digest = Sha256::digest(authority.as_bytes());
    root.join(hex::encode(&digest[..16]))
}

fn remove_profile(root: &Path, authority: &str) -> Result<()> {
    let _guard = store::lock_profile(root, authority).context("open saved login")?;
    let directory = profile_path(root, authority);
    let info = fs::symlink_metadata(&directory).context("open saved login")?;
    ensure!(
        info.is_dir() && !info.is_symlink(),
        "saved login path is not a safe directory"
    );
    fs::remove_dir_all(directory).context("remove saved login")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_go_profile_directory_names() {
        let root = Path::new("profiles");
        assert_eq!(
            profile_path(root, "  EXAMPLE.COM\n"),
            root.join("a379a6f6eeafb9a55e378c118034e275")
        );
        assert_eq!(profile_path(root, "İ"), profile_path(root, "i"));
        assert_eq!(profile_path(root, "ΟΣ"), profile_path(root, "οσ"));
    }

    #[test]
    fn discovers_existing_profile_root() {
        let mut entries = [
            ("HOME", Some(OsString::from("/home/alex"))),
            ("XDG_CONFIG_HOME", Some(OsString::from("relative"))),
            (
                "AppData",
                Some(OsString::from(r"C:\Users\alex\AppData\Roaming")),
            ),
            ("LANEWAY_PROFILE_DIR", Some(OsString::from("profiles"))),
        ];
        let lookup = |entries: &[(&str, Option<OsString>)], key: &str| {
            entries
                .iter()
                .find(|(name, _)| *name == key)
                .and_then(|(_, value)| value.clone())
        };
        assert_eq!(
            profile_root(|key| lookup(&entries, key)),
            Path::new("profiles")
        );
        entries[3].1 = None;
        let expected = if cfg!(windows) {
            PathBuf::from(r"C:\Users\alex\AppData\Roaming").join("laneway/profiles")
        } else if cfg!(any(target_os = "macos", target_os = "ios")) {
            PathBuf::from("/home/alex/Library/Application Support/laneway/profiles")
        } else {
            PathBuf::from(".laneway")
        };
        assert_eq!(profile_root(|key| lookup(&entries, key)), expected);
    }

    #[test]
    fn handles_the_go_logout_argument_shape() {
        assert_eq!(
            parse_authority(&["--".into(), "example.com".into()]).unwrap(),
            Some("example.com")
        );
        assert_eq!(parse_authority(&["-h".into()]).unwrap(), None);
        assert!(parse_authority(&["--all".into()]).is_err());
        assert!(parse_authority(&["one".into(), "two".into()]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn removes_only_the_selected_profile_and_refuses_symlink_paths() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let selected = profile_path(root, "one.example");
        let preserved = profile_path(root, "two.example");
        let link = profile_path(root, "link.example");
        fs::create_dir_all(selected.join("credentials-123")).unwrap();
        fs::create_dir(&preserved).unwrap();
        fs::write(preserved.join("profile.json"), b"preserved").unwrap();
        symlink(&preserved, &link).unwrap();
        symlink(&preserved, selected.join("nested-link")).unwrap();

        assert!(remove_profile(root, "link.example").is_err());
        remove_profile(root, "ONE.EXAMPLE").unwrap();
        assert!(!selected.exists());
        assert!(preserved.join("profile.json").exists());
        assert!(link.is_symlink());
        assert!(remove_profile(root, "one.example").is_err());
    }
}
