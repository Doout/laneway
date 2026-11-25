#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use std::time::SystemTime;
use std::{
    ffi::{OsStr, OsString},
    fs,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use laneway_private::open_private_file;
use zeroize::Zeroizing;

use crate::{
    bootstrap::{self, Metadata},
    enrollment::{self, Controller, EnrollmentClass},
    node::split_flag,
};

use super::{
    profile_path,
    store::{
        Manifest, SavedProfile, current_root, ensure_profile_root, load_at, lock_profile, save,
    },
};

const LOGIN_USAGE: &str = "usage: laneway login DOMAIN [--token-file PATH]";
const MAX_TOKEN_BYTES: u64 = 4096;

pub(crate) fn login(args: &[OsString]) -> Result<()> {
    ensure!(
        args.first().is_some_and(|arg| arg == "login"),
        "{LOGIN_USAGE}"
    );
    let Some(options) = parse_login(&args[1..])? else {
        println!("{LOGIN_USAGE}");
        return Ok(());
    };
    let root = current_root();
    require_new_login(&root, options.authority)?;
    let metadata = bootstrap::fetch(options.authority)?;
    let profile = enroll_remembered(options.authority, &metadata, options.token_file.as_deref())?;
    println!(
        "logged in network={} node={} profile={}",
        profile.network_id,
        profile.node_id,
        profile_path(&root, options.authority).display()
    );
    println!("Connect with: laneway connect");
    Ok(())
}

pub(crate) fn enroll_remembered(
    authority: &str,
    metadata: &Metadata,
    token_file: Option<&Path>,
) -> Result<SavedProfile> {
    validate_platform_artifact(metadata)?;
    let root = current_root();
    ensure_profile_root(&root)?;
    let _guard = lock_profile(&root, authority)?;
    require_new_login(&root, authority)?;
    let controller = controller(metadata)?;
    let code = read_enrollment_code(token_file)?;
    let credentials =
        enrollment::enroll(&controller, code.as_str(), EnrollmentClass::RememberedUser)?;
    let manifest = Manifest::new(authority, metadata, credentials.node_id)?;
    save(
        &root,
        manifest,
        metadata.trust.ca_pem.as_bytes(),
        &credentials,
        false,
    )
}

fn require_new_login(root: &Path, authority: &str) -> Result<()> {
    match load_at(root, authority) {
        Ok(_) => bail!(
            "already logged in to {authority}; use 'laneway logout {authority}' before replacing this identity"
        ),
        Err(error) if is_missing(&error) => {
            // A missing credential in an already committed profile is an error.
            // Do not consume a new one-time token when the profile cannot be saved.
            match fs::symlink_metadata(profile_path(root, authority).join("profile.json")) {
                Err(absent) if absent.kind() == ErrorKind::NotFound => Ok(()),
                _ => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|cause| cause.kind() == ErrorKind::NotFound)
}

fn controller(metadata: &Metadata) -> Result<Controller<'_>> {
    Ok(Controller {
        endpoint: &metadata.controller.enrollment_endpoint,
        quic_endpoint: &metadata.controller.quic_endpoint,
        server_name: &metadata.controller.server_name,
        network_id: metadata
            .network_id
            .parse()
            .context("invalid bootstrap network ID")?,
        service_id: metadata
            .controller
            .service_id
            .parse()
            .context("invalid bootstrap controller ID")?,
        ca_pem: metadata.trust.ca_pem.as_bytes(),
    })
}

pub(crate) fn validate_platform_artifact(metadata: &Metadata) -> Result<()> {
    if !cfg!(target_os = "macos") {
        metadata.artifact_for_current_platform()?;
    }
    Ok(())
}

pub(crate) fn read_enrollment_code(token_file: Option<&Path>) -> Result<Zeroizing<String>> {
    read_code(token_file, open_private_file)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_managed_enrollment_code(token_file: Option<&Path>) -> Result<Zeroizing<String>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    read_code(token_file, |path| {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
            return Err(std::io::Error::from(ErrorKind::PermissionDenied));
        }
        Ok(file)
    })
}

fn read_code(
    token_file: Option<&Path>,
    open: impl FnOnce(&Path) -> std::io::Result<fs::File>,
) -> Result<Zeroizing<String>> {
    let code = if let Some(path) = token_file {
        let file = open(path).context(
            "--token-file must be a private, nonempty regular file no larger than 4096 bytes",
        )?;
        let length = file.metadata()?.len();
        ensure!(
            (1..=MAX_TOKEN_BYTES).contains(&length),
            "--token-file must be a private, nonempty regular file no larger than 4096 bytes"
        );
        let mut code = Zeroizing::new(String::new());
        file.take(MAX_TOKEN_BYTES + 1)
            .read_to_string(&mut code)
            .context("read --token-file")?;
        ensure!(
            code.len() as u64 <= MAX_TOKEN_BYTES,
            "--token-file is too large"
        );
        code
    } else {
        Zeroizing::new(
            rpassword::prompt_password("Enrollment code: ")
                .context("read enrollment code on the controlling terminal; use --token-file on non-interactive input")?,
        )
    };
    let trimmed = code.trim();
    ensure!(
        !trimmed.is_empty()
            && trimmed.len() as u64 <= MAX_TOKEN_BYTES
            && !trimmed.contains([' ', '\t', '\r', '\n']),
        "enrollment code is invalid"
    );
    Ok(Zeroizing::new(trimmed.to_owned()))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl SavedProfile {
    pub(crate) fn renewal(&self) -> Result<(bool, SystemTime)> {
        let (not_before, not_after) = enrollment::certificate_times(&self.read_certificate()?)?;
        renewal_window(not_before, not_after, SystemTime::now())
    }

    pub(crate) fn renew(self, metadata: &Metadata) -> Result<Self> {
        let root = current_root();
        let _guard = lock_profile(&root, &self.authority)?;
        let current = load_at(&root, &self.authority)?;
        current.validate_metadata(metadata)?;
        ensure!(
            current.node_id == self.node_id,
            "saved login identity changed during renewal"
        );
        if current.generation() != self.generation() {
            // A concurrent process already rotated these keys while we waited.
            return Ok(current);
        }
        let controller = controller(metadata)?;
        let node = current
            .node_id
            .parse()
            .context("invalid saved login node ID")?;
        let credentials = enrollment::renew(
            &controller,
            node,
            &current.ca,
            &current.certificate,
            &current.private_key,
        )
        .context("refresh saved login")?;
        let ca = current.read_ca()?;
        save(&root, current.manifest, &ca, &credentials, true)
    }
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn renewal_window(
    not_before: SystemTime,
    not_after: SystemTime,
    now: SystemTime,
) -> Result<(bool, SystemTime)> {
    ensure!(
        now < not_after,
        "saved login certificate expired; log in again with a new token"
    );
    let lifetime = not_after
        .duration_since(not_before)
        .context("saved login certificate validity is invalid")?;
    let interval = lifetime
        .checked_mul(2)
        .context("saved login certificate validity is invalid")?
        / 3;
    let renew_at = not_before
        .checked_add(interval)
        .context("saved login certificate renewal date is invalid")?;
    Ok((now >= renew_at, renew_at))
}

#[derive(Debug)]
struct LoginArgs<'a> {
    authority: &'a str,
    token_file: Option<PathBuf>,
}

fn parse_login(args: &[OsString]) -> Result<Option<LoginArgs<'_>>> {
    let mut args = args.iter();
    let mut authority = None;
    let mut token_file = None;
    if let Some(value) = args
        .as_slice()
        .first()
        .and_then(|value| value.to_str())
        .filter(|value| !value.starts_with('-'))
    {
        authority = Some(value);
        args.next();
    }
    while let Some(arg) = args.next() {
        let (flag, attached) = split_flag(arg);
        if arg == "--" {
            for value in args.by_ref() {
                set_authority(&mut authority, value)?;
            }
            break;
        }
        if matches!(flag, "-h" | "--h" | "-help" | "--help") {
            return Ok(None);
        }
        if flag == "-token-file" || flag == "--token-file" {
            token_file = Some(PathBuf::from(
                attached
                    .or_else(|| args.next().cloned())
                    .context("flag needs an argument: --token-file")?,
            ));
        } else if flag.starts_with('-') {
            bail!("flag provided but not defined: {flag}");
        } else {
            set_authority(&mut authority, arg)?;
            ensure!(args.as_slice().is_empty(), "{LOGIN_USAGE}");
            break;
        }
    }
    let authority = authority
        .filter(|value| !value.is_empty())
        .context(LOGIN_USAGE)?;
    let token_file = token_file.filter(|path| !path.as_os_str().is_empty());
    Ok(Some(LoginArgs {
        authority,
        token_file,
    }))
}

fn set_authority<'a>(authority: &mut Option<&'a str>, value: &'a OsStr) -> Result<()> {
    ensure!(authority.is_none(), "{LOGIN_USAGE}");
    *authority = Some(value.to_str().context(LOGIN_USAGE)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_accepts_domain_before_or_after_token_file() {
        for args in [
            ["example.com", "--token-file", "/safe/token"],
            ["-token-file", "/safe/token", "example.com"],
        ] {
            let args = args.map(OsString::from);
            let parsed = parse_login(&args).unwrap().unwrap();
            assert_eq!(parsed.authority, "example.com");
            assert_eq!(parsed.token_file.as_deref(), Some(Path::new("/safe/token")));
        }
        assert!(parse_login(&["one.example".into(), "two.example".into()]).is_err());
        assert!(parse_login(&["--help".into()]).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn accepts_non_unicode_token_path() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let args = [
            OsString::from("example.com"),
            OsString::from_vec(b"--token-file=/secure/\xff".to_vec()),
        ];
        let options = parse_login(&args).unwrap().unwrap();
        assert_eq!(
            options.token_file.unwrap().as_os_str().as_bytes(),
            b"/secure/\xff"
        );
    }

    #[test]
    fn reads_protected_token_and_rejects_whitespace_or_oversize() {
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join("private");
        laneway_private::ensure_directory(&private).unwrap();
        let path = private.join("token");
        laneway_private::create(&path, b" test-code\n").unwrap();
        assert_eq!(
            read_enrollment_code(Some(&path)).unwrap().as_str(),
            "test-code"
        );
        for bad in [
            b"two words".as_slice(),
            &vec![b'x'; MAX_TOKEN_BYTES as usize + 1],
        ] {
            laneway_private::write(&path, bad).unwrap();
            assert!(read_enrollment_code(Some(&path)).is_err());
        }
    }

    #[test]
    fn renews_at_two_thirds_of_the_certificate_lifetime() {
        use std::time::{Duration, UNIX_EPOCH};
        let before = UNIX_EPOCH + Duration::from_secs(100);
        let after = before + Duration::from_secs(42);
        let due = before + Duration::from_secs(28);
        assert_eq!(
            renewal_window(before, after, due - Duration::from_nanos(1)).unwrap(),
            (false, due)
        );
        assert_eq!(renewal_window(before, after, due).unwrap(), (true, due));
        assert!(renewal_window(before, after, after).is_err());
    }
}
