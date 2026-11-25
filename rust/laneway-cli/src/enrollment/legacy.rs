use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, DirBuilder},
    io::{ErrorKind, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

use crate::{bootstrap, profile};

use super::{
    Controller, Credentials, EnrollmentClass, enroll_as, read_profile_file, renew_current,
};

const AUTHORITY_OPTIONS: &[&str] = &[
    "controller",
    "ca",
    "server-name",
    "controller-network-id",
    "controller-service-id",
];
const OUTPUT_OPTIONS: &[&str] = &["out-cert", "out-key", "out-wireguard-key"];
const LEGACY_HTTPS: &str = "allow-legacy-controller-https";
const JOIN_USAGE: &str = "usage: laneway join DOMAIN [--token-file PATH], or laneway join TOKEN --controller https://host:port --name NAME [advanced options]";
const RENEW_USAGE: &str =
    "usage: laneway renew --controller https://host:port --controller-quic host:port [options]";

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    match args {
        [command, rest @ ..] if command == "join" => join(rest),
        [command, rest @ ..] if command == "renew" => renew(rest),
        _ => bail!("unsupported credential command"),
    }
}

fn join(args: &[OsString]) -> Result<()> {
    let mut selector = None;
    let mut args = args;
    if let Some(first) = args.first()
        && !first.as_bytes().starts_with(b"-")
    {
        selector = Some(
            first
                .to_str()
                .context("enrollment selector must be UTF-8")?,
        );
        args = &args[1..];
    }
    let Some((flags, rest)) = Flags::parse(
        args,
        &["token-file", "bootstrap", "name"],
        false,
        JOIN_USAGE,
    )?
    else {
        return Ok(());
    };
    ensure!(
        rest.len() <= 1 && !(rest.len() == 1 && selector.is_some()),
        "{JOIN_USAGE}"
    );
    let selector = match rest.first() {
        Some(value) => Some(
            value
                .to_str()
                .context("enrollment selector must be UTF-8")?,
        ),
        None => selector,
    };
    let endpoint = flags.text("controller")?;
    let mut authority = flags.text("bootstrap")?;
    let mut token = selector.unwrap_or("");
    if authority.is_empty() && endpoint.is_empty() && token.contains('.') {
        authority = token;
        token = "";
    }
    let token_file = flags.path("token-file", "");
    ensure!(
        token.is_empty() || token_file.as_os_str().is_empty(),
        "join accepts either TOKEN or --token-file, not both"
    );
    let name = flags.text("name")?;
    let outputs = Outputs::from_flags(&flags, false);
    let code_from_file = if token_file.as_os_str().is_empty() {
        None
    } else {
        Some(profile::read_enrollment_code(Some(token_file))?)
    };

    let (metadata, explicit_ca) = if authority.is_empty() {
        ensure!(
            (!token.is_empty() || code_from_file.is_some())
                && !endpoint.is_empty()
                && !name.is_empty(),
            "{JOIN_USAGE}"
        );
        outputs.preflight()?;
        (
            None,
            Some(read_profile_file(flags.path("ca", "/etc/laneway/ca.crt"))?),
        )
    } else {
        for flag in AUTHORITY_OPTIONS {
            ensure!(
                !flags.contains(flag),
                "--{flag} cannot override authenticated bootstrap metadata"
            );
        }
        ensure!(
            token.is_empty(),
            "bootstrap enrollment refuses a code in argv; use the prompt or --token-file"
        );
        let metadata = bootstrap::fetch(authority)?;
        profile::validate_platform_artifact(&metadata)?;
        outputs.preflight()?;
        (Some(metadata), None)
    };
    let controller = if let Some(metadata) = &metadata {
        Controller {
            endpoint: &metadata.controller.enrollment_endpoint,
            quic_endpoint: &metadata.controller.quic_endpoint,
            server_name: &metadata.controller.server_name,
            network_id: metadata.network_id.parse()?,
            service_id: metadata.controller.service_id.parse()?,
            ca_pem: metadata.trust.ca_pem.as_bytes(),
        }
    } else {
        flags.controller("", explicit_ca.as_deref().context("missing controller CA")?)?
    };
    let code = match code_from_file {
        Some(code) => code,
        None if !token.is_empty() => Zeroizing::new(token.to_owned()),
        None => profile::read_enrollment_code(None)?,
    };
    let csr_name = if name.is_empty() {
        "laneway-bootstrap-enrollment"
    } else {
        name
    };
    let credential = enroll_as(
        &controller,
        &code,
        EnrollmentClass::DurableNode,
        name,
        csr_name,
    )?;
    outputs.write(&credential)?;
    let overlays = credential
        .overlays
        .iter()
        .map(|address| format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "enrolled network={} node={} overlay={} certificate={}",
        controller.network_id,
        credential.node_id,
        overlays,
        outputs.cert.display(),
    );
    Ok(())
}

fn renew(args: &[OsString]) -> Result<()> {
    let Some((flags, rest)) =
        Flags::parse(args, &["controller-quic", "cert", "key"], true, RENEW_USAGE)?
    else {
        return Ok(());
    };
    let quic = flags.text("controller-quic")?;
    ensure!(
        rest.is_empty()
            && !flags.text("controller")?.is_empty()
            && (!quic.is_empty() || flags.legacy_https),
        "{RENEW_USAGE}"
    );
    let current_cert = flags.path("cert", "/etc/laneway/node.crt");
    let current_key = flags.path("key", "/etc/laneway/node.key");
    let outputs = Outputs::from_flags(&flags, true);
    let active_paths = [clean(current_cert), clean(current_key)];
    ensure!(
        outputs
            .paths()
            .iter()
            .all(|path| !active_paths.contains(&clean(path))),
        "renewal output paths must differ from the active certificate and key paths"
    );
    outputs.preflight()?;
    let ca_path = flags.path("ca", "/etc/laneway/ca.crt");
    let ca = read_profile_file(ca_path)?;
    let controller = flags.controller(quic, &ca)?;
    let credential = renew_current(&controller, None, ca_path, current_cert, current_key)?;
    outputs.write(&credential)?;
    println!(
        "renewed network={} node={} certificate={}",
        controller.network_id,
        credential.node_id,
        outputs.cert.display(),
    );
    Ok(())
}

#[derive(Default)]
struct Flags {
    values: HashMap<String, OsString>,
    legacy_https: bool,
}

impl Flags {
    fn parse<'a>(
        mut args: &'a [OsString],
        extra: &[&str],
        allow_legacy_flag: bool,
        usage: &str,
    ) -> Result<Option<(Self, &'a [OsString])>> {
        let mut parsed = Self::default();
        while let Some((argument, rest)) = args.split_first() {
            let bytes = argument.as_bytes();
            if bytes == b"--" {
                args = rest;
                break;
            }
            if bytes == b"-" || !bytes.starts_with(b"-") {
                break;
            }
            args = rest;
            let bytes = bytes.strip_prefix(b"--").unwrap_or(&bytes[1..]);
            let (name, inline) = if let Some(index) = bytes.iter().position(|&b| b == b'=') {
                (
                    &bytes[..index],
                    Some(OsStr::from_bytes(&bytes[index + 1..])),
                )
            } else {
                (bytes, None)
            };
            let name = std::str::from_utf8(name).context("invalid option name")?;
            if matches!(name, "help" | "h") {
                println!("{usage}");
                return Ok(None);
            }
            if name == LEGACY_HTTPS && allow_legacy_flag {
                parsed.legacy_https = match inline.and_then(OsStr::to_str) {
                    None if inline.is_none() => true,
                    Some("1" | "t" | "T" | "true" | "TRUE" | "True") => true,
                    Some("0" | "f" | "F" | "false" | "FALSE" | "False") => false,
                    _ => bail!("invalid flag -{name}"),
                };
                continue;
            }
            ensure!(
                AUTHORITY_OPTIONS.contains(&name)
                    || OUTPUT_OPTIONS.contains(&name)
                    || extra.contains(&name),
                "flag provided but not defined: -{name}"
            );
            let value = match inline {
                Some(value) => value.to_os_string(),
                None => {
                    let (value, rest) = args
                        .split_first()
                        .with_context(|| format!("flag needs an argument: -{name}"))?;
                    args = rest;
                    value.clone()
                }
            };
            parsed.values.insert(name.to_owned(), value);
        }
        Ok(Some((parsed, args)))
    }

    fn text(&self, key: &str) -> Result<&str> {
        self.values.get(key).map_or(Ok(""), |value| {
            value
                .to_str()
                .with_context(|| format!("--{key} must be UTF-8"))
        })
    }

    fn path<'a>(&'a self, key: &str, default: &'a str) -> &'a Path {
        self.values
            .get(key)
            .map_or_else(|| Path::new(default), Path::new)
    }

    fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    fn controller<'a>(
        &'a self,
        quic_endpoint: &'a str,
        ca_pem: &'a [u8],
    ) -> Result<Controller<'a>> {
        Ok(Controller {
            endpoint: self.text("controller")?,
            quic_endpoint,
            server_name: self.text("server-name")?,
            network_id: self
                .text("controller-network-id")?
                .parse()
                .context("--controller-network-id")?,
            service_id: self
                .text("controller-service-id")?
                .parse()
                .context("--controller-service-id")?,
            ca_pem,
        })
    }
}

struct Outputs<'a> {
    cert: &'a Path,
    key: &'a Path,
    wireguard: &'a Path,
}

impl<'a> Outputs<'a> {
    fn from_flags(flags: &'a Flags, renewal: bool) -> Self {
        let defaults = if renewal {
            [
                "/etc/laneway/node.next.crt",
                "/etc/laneway/node.next.key",
                "/etc/laneway/wireguard.next.key",
            ]
        } else {
            [
                "/etc/laneway/node.crt",
                "/etc/laneway/node.key",
                "/etc/laneway/wireguard.key",
            ]
        };
        Self {
            cert: flags.path("out-cert", defaults[0]),
            key: flags.path("out-key", defaults[1]),
            wireguard: flags.path("out-wireguard-key", defaults[2]),
        }
    }

    fn paths(&self) -> [&Path; 3] {
        [self.cert, self.key, self.wireguard]
    }

    fn preflight(&self) -> Result<()> {
        let mut seen = HashSet::new();
        for path in self.paths() {
            ensure!(
                seen.insert(clean(path)),
                "credential output paths must be distinct"
            );
            match path.symlink_metadata() {
                Ok(_) => bail!(
                    "refusing to replace existing credential output {}",
                    path.display()
                ),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect credential output {}", path.display()));
                }
            }
        }
        Ok(())
    }

    fn write(&self, credential: &Credentials) -> Result<()> {
        let mut staged = Vec::new();
        for (path, bytes, file_mode, directory_mode) in [
            (
                self.wireguard,
                credential.wireguard_private_key.as_slice(),
                0o600,
                0o700,
            ),
            (
                self.cert,
                credential.certificate_pem.as_slice(),
                0o644,
                0o755,
            ),
            (
                self.key,
                credential.private_key_pem.as_slice(),
                0o600,
                0o700,
            ),
        ] {
            let directory = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            DirBuilder::new()
                .recursive(true)
                .mode(directory_mode)
                .create(directory)
                .with_context(|| {
                    format!("create credential output directory {}", directory.display())
                })?;
            let mut file = tempfile::Builder::new()
                .prefix(".laneway-")
                .tempfile_in(directory)?;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(file_mode))?;
            file.write_all(bytes)?;
            file.as_file().sync_all()?;
            let metadata = file.as_file().metadata()?;
            staged.push((path, file, metadata));
        }
        staged.swap(1, 2); // Publish private credentials first, then the certificate.
        let mut published = Vec::new();
        for (path, file, metadata) in staged {
            match file.persist_noclobber(path) {
                Ok(_) => published.push((path, metadata)),
                Err(error) => {
                    for (path, original) in published.into_iter().rev() {
                        if path.symlink_metadata().is_ok_and(|current| {
                            current.dev() == original.dev() && current.ino() == original.ino()
                        }) {
                            let _ = fs::remove_file(path);
                        }
                    }
                    return Err(error.error)
                        .with_context(|| format!("write credential output {}", path.display()));
                }
            }
        }
        Ok(())
    }
}

fn clean(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir
                if result
                    .components()
                    .next_back()
                    .is_some_and(|last| matches!(last, Component::Normal(_))) =>
            {
                result.pop();
            }
            Component::ParentDir if result.has_root() => {}
            Component::CurDir => {}
            component => result.push(component.as_os_str()),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_preflight_rejects_existing_or_aliased_paths() {
        let directory = tempfile::tempdir().unwrap();
        let cert = directory.path().join("node.crt");
        let key = directory.path().join("node.key");
        let wireguard = directory.path().join("wg.key");
        let alias = directory.path().join("sub/../node.crt");
        let output = Outputs {
            cert: &cert,
            key: &key,
            wireguard: &wireguard,
        };
        output.preflight().unwrap();
        assert!(
            Outputs {
                wireguard: &alias,
                ..output
            }
            .preflight()
            .is_err()
        );
        std::os::unix::fs::symlink(directory.path().join("absent"), &cert).unwrap();
        assert!(output.preflight().is_err());
    }

    #[test]
    fn credential_publish_rolls_back_if_destination_appears_after_preflight() {
        let directory = tempfile::tempdir().unwrap();
        let cert = directory.path().join("node.crt");
        let key = directory.path().join("node.key");
        let wireguard = directory.path().join("wg.key");
        let output = Outputs {
            cert: &cert,
            key: &key,
            wireguard: &wireguard,
        };
        output.preflight().unwrap();
        fs::write(&cert, b"concurrent certificate").unwrap();
        let credentials = Credentials {
            node_id: laneway_protocol::Id::new([7; 16]).unwrap(),
            certificate_pem: b"new certificate PEM".to_vec(),
            private_key_pem: Zeroizing::new(b"new private key PEM".to_vec()),
            wireguard_private_key: Zeroizing::new([5; 32]),
            overlays: Vec::new(),
            lease_expires_at: None,
        };
        assert!(output.write(&credentials).is_err());
        assert_eq!(fs::read(&cert).unwrap(), b"concurrent certificate");
        assert!(!key.exists() && !wireguard.exists());
        fs::remove_file(&cert).unwrap();

        output.write(&credentials).unwrap();
        assert_eq!(fs::read(&wireguard).unwrap(), [5; 32]);
        for private in [wireguard, key] {
            assert_eq!(private.metadata().unwrap().mode() & 0o777, 0o600);
        }
        assert_eq!(cert.metadata().unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn needs_explicit_opt_in_for_https_renewal() {
        let args = ["renew", "--controller", "https://controller.example"].map(OsString::from);
        let error = run(&args).unwrap_err();
        assert!(error.to_string().contains(RENEW_USAGE));
    }
}
