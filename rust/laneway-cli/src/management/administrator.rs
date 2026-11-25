use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::{Mode, fchmod},
    unistd::{Gid, Uid, UnlinkatFlags, fchown, unlinkat},
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{args::Flags, transport::Client};

pub(super) fn run(args: &[OsString]) -> Result<()> {
    ensure!(
        Uid::effective().is_root(),
        "controller administrator lifecycle commands must run as root"
    );
    match args {
        [action, rest @ ..] if action == "bootstrap" || action == "recover" => {
            password_lifecycle(action == "bootstrap", rest)
        }
        [action, verb, rest @ ..] if action == "root-token" => {
            root_token(verb.to_str().unwrap_or_default(), rest)
        }
        _ => bail!("usage: laneway controller administrator <bootstrap|recover|root-token> ..."),
    }
}

fn root_token(verb: &str, args: &[OsString]) -> Result<()> {
    let fields = match verb {
        "generate" => &["out-file"][..],
        "authentication-check" => &["expect"],
        "rotation-begin" | "rotation-complete" => &["rotation-id"],
        _ => bail!(
            "usage: laneway controller administrator root-token <generate|authentication-check|rotation-begin|rotation-complete> ..."
        ),
    };
    if verb == "generate" {
        let (flags, rest) = Flags::local(args, fields, &[])?;
        ensure!(
            rest.is_empty(),
            "unexpected administrator positional arguments"
        );
        return generate(flags.path("out-file", ""));
    }
    let flags = parse(args, fields)?;
    match verb {
        "authentication-check" => {
            let want = flags.enum_value("expect", "", &["accepted", "rejected"])? == "accepted";
            let status = root_accepted(&Client::new(&flags, false)?)?;
            ensure!(
                status == want,
                "root administrator credential did not have the required authentication status"
            );
            Ok(())
        }
        _ => {
            let id = flags.id("rotation-id")?;
            let phase = verb
                .strip_prefix("rotation-")
                .context("invalid root rotation command")?;
            let path = format!("/v1/admin/auth/root-token-rotations/{id}/{phase}");
            let (status, _, _) =
                Client::new(&flags, false)?.lifecycle(Method::POST, &path, None)?;
            ensure!(
                status == 204,
                "controller root token rotation {phase} returned unexpected HTTP status {status}"
            );
            Ok(())
        }
    }
}

fn parse<'a>(args: &'a [OsString], fields: &[&str]) -> Result<Flags<'a>> {
    let (flags, rest) = Flags::parse(args, fields, &[], false)?;
    ensure!(
        rest.is_empty(),
        "unexpected administrator positional arguments"
    );
    Ok(flags)
}

fn root_accepted(client: &Client) -> Result<bool> {
    let (status, _, _) = client.lifecycle(Method::GET, "/v1/admin/auth/root", None)?;
    match status {
        204 => Ok(true),
        401 => Ok(false),
        _ => bail!("controller root authentication returned unexpected HTTP status {status}"),
    }
}

fn generate(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "root-token generate requires an absolute --out-file"
    );
    let parent = path
        .parent()
        .context("invalid root token output directory")?;
    let name = path
        .file_name()
        .context("invalid root token output filename")?;
    ensure!(
        parent.canonicalize()? == parent,
        "root token output parent must be a real directory without symbolic links"
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(parent)?;
    let info = dir.metadata()?;
    ensure!(
        info.uid() == 0 && info.mode() & 0o777 == 0o700,
        "root token output parent must be a root-owned protected directory with mode 0700"
    );
    let mut raw = Zeroizing::new([0_u8; 32]);
    getrandom::fill(raw.as_mut()).context("could not generate root administrator credential")?;
    let mut token = Zeroizing::new([0_u8; 65]);
    hex::encode_to_slice(raw.as_slice(), &mut token[..64])?;
    token[64] = b'\n';
    let fd = openat(
        &dir,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .context("could not create protected root token output")?;
    let outcome = (|| -> Result<()> {
        fchown(&fd, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))?;
        fchmod(&fd, Mode::S_IRUSR | Mode::S_IWUSR)?;
        let mut file = File::from(fd);
        file.write_all(token.as_slice())?;
        file.sync_all()?;
        dir.sync_all()?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = unlinkat(&dir, name, UnlinkatFlags::NoRemoveDir);
    }
    outcome.context("could not persist protected root token output")
}

fn password_lifecycle(bootstrap: bool, args: &[OsString]) -> Result<()> {
    let flags = parse(args, &["username"])?;
    let username = flags.required("username")?;
    ensure!(
        valid_username(username),
        "administrator lifecycle requires a valid --username"
    );
    ensure!(
        root_accepted(&Client::new(&flags, false)?)?,
        "root administrator credential was rejected before administrator lifecycle input"
    );
    let password = prompt_password()?;
    let client = Client::new(&flags, false)?;
    let (issue_path, consume_path) = if bootstrap {
        (
            "/v1/admin/auth/bootstrap-grants".to_owned(),
            "/v1/admin/auth/bootstrap",
        )
    } else {
        let owner = recover_owner(&client, username)?;
        (
            format!("/v1/admin/administrators/{owner}/recovery-grants"),
            "/v1/admin/auth/recover",
        )
    };
    let (status, json, response) = client.lifecycle(Method::POST, &issue_path, None)?;
    ensure!(
        status == 201 && json,
        "controller administrator grant issuance returned unexpected HTTP status or content type ({status})"
    );
    let grant: Grant = serde_json::from_slice(&response)
        .map_err(|_| anyhow::anyhow!("controller administrator grant response is malformed"))?;
    let mut decoded = Zeroizing::new([0_u8; 32]);
    ensure!(
        grant.grant.len() == 43
            && grant.expires_at_unix_seconds > 0
            && URL_SAFE_NO_PAD
                .decode_slice(&grant.grant, decoded.as_mut())
                .is_ok_and(|len| len == 32),
        "controller administrator grant response is invalid"
    );
    let mut payload = Zeroizing::new(Vec::with_capacity(8192));
    serde_json::to_writer(
        &mut *payload,
        &Consume {
            grant: &grant.grant,
            username: bootstrap.then_some(username),
            password: &password,
        },
    )?;
    let (status, _, _) = client.lifecycle(Method::POST, consume_path, Some(payload))?;
    ensure!(
        status == 204,
        "controller administrator grant consumption returned unexpected HTTP status {status}"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    grant: String,
    expires_at_unix_seconds: i64,
}

impl Drop for Grant {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.grant.zeroize();
    }
}

#[derive(Serialize)]
struct Consume<'a> {
    grant: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    password: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owners {
    administrators: Vec<Owner>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    principal_id: String,
    username: String,
    role: String,
    #[serde(rename = "enabled")]
    _enabled: bool,
    all_networks: bool,
    network_ids: Vec<String>,
    created_at_unix_seconds: i64,
    updated_at_unix_seconds: i64,
    password_updated_at_unix_seconds: i64,
    #[serde(rename = "disabled_at_unix_seconds")]
    _disabled_at_unix_seconds: Option<i64>,
}

fn recover_owner(client: &Client, username: &str) -> Result<Id> {
    let path = format!("/v1/admin/administrators?username={username}");
    let (status, json, response) = client.lifecycle(Method::GET, &path, None)?;
    ensure!(
        status == 200 && json,
        "controller administrator lookup returned unexpected HTTP status or content type ({status})"
    );
    let owners: Owners = serde_json::from_slice(&response)
        .map_err(|_| anyhow::anyhow!("controller administrator lookup returned malformed JSON"))?;
    let [owner] = owners.administrators.as_slice() else {
        bail!("controller administrator recovery target was not found uniquely");
    };
    ensure!(
        owner.username == username
            && owner.role == "owner"
            && owner.all_networks
            && owner.network_ids.is_empty()
            && owner.created_at_unix_seconds > 0
            && owner.updated_at_unix_seconds > 0
            && owner.password_updated_at_unix_seconds > 0,
        "controller administrator recovery target is not a valid owner"
    );
    owner
        .principal_id
        .parse()
        .context("invalid administrator identity")
}

fn valid_username(name: &str) -> bool {
    (3..=64).contains(&name.len())
        && name.bytes().enumerate().all(|(i, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (i > 0 && i + 1 < name.len() && matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn prompt_password() -> Result<Zeroizing<String>> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("administrator lifecycle requires a controlling terminal")?;
    let first = Zeroizing::new(
        rpassword::prompt_password("New administrator password: ")
            .context("could not read administrator password from controlling terminal")?,
    );
    ensure!(
        (15..=1024).contains(&first.len()),
        "administrator password must be 15..1024 bytes"
    );
    let confirmation = Zeroizing::new(
        rpassword::prompt_password("Confirm administrator password: ")
            .context("could not read administrator password from controlling terminal")?,
    );
    ensure!(
        *first == *confirmation,
        "administrator password confirmation did not match"
    );
    Ok(first)
}
