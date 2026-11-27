use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use clap::{Args, Subcommand};
use laneway_protocol::Id;
use reqwest::{Method, StatusCode, header};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    admin::{Auth, Bearer, Client, Connection},
    pki::stage,
};

#[derive(Subcommand)]
pub(super) enum Operation {
    Bootstrap(Password),
    Recover(Password),
    #[command(subcommand)]
    RootToken(RootToken),
}

#[derive(Args)]
pub(super) struct Password {
    #[arg(long)]
    username: String,
    #[command(flatten)]
    bearer: Bearer,
}

#[derive(Args)]
pub(super) struct Rotation {
    #[arg(long)]
    rotation_id: Id,
    #[command(flatten)]
    bearer: Bearer,
}

#[derive(Subcommand)]
pub(super) enum RootToken {
    Generate {
        #[arg(long)]
        out_file: PathBuf,
    },
    AuthenticationCheck {
        #[arg(long, value_parser = ["accepted", "rejected"])]
        expect: String,
        #[command(flatten)]
        bearer: Bearer,
    },
    RotationBegin(Rotation),
    RotationComplete(Rotation),
}

pub(super) async fn run(connection: Connection, operation: Operation) -> Result<()> {
    // SAFETY: geteuid takes no arguments and returns the current effective UID.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "controller administrator lifecycle commands must run as root"
    );
    match operation {
        Operation::Bootstrap(options) => password_lifecycle(connection, options, false).await,
        Operation::Recover(options) => password_lifecycle(connection, options, true).await,
        Operation::RootToken(RootToken::Generate { out_file }) => generate(out_file),
        Operation::RootToken(RootToken::AuthenticationCheck { expect, bearer }) => {
            let client = Client::new(connection, Auth::Bearer(bearer))?;
            ensure!(
                accepted(&client).await? == (expect == "accepted"),
                "root administrator credential did not have the required authentication status"
            );
            Ok(())
        }
        Operation::RootToken(RootToken::RotationBegin(rotation)) => {
            rotate(connection, rotation, "begin").await
        }
        Operation::RootToken(RootToken::RotationComplete(rotation)) => {
            rotate(connection, rotation, "complete").await
        }
    }
}

async fn accepted(client: &Client) -> Result<bool> {
    let (status, _, _) = client
        .lifecycle(Method::GET, "/v1/admin/auth/root", None)
        .await?;
    match status {
        StatusCode::NO_CONTENT => Ok(true),
        StatusCode::UNAUTHORIZED => Ok(false),
        _ => anyhow::bail!(
            "controller root authentication returned unexpected HTTP status {}",
            status.as_u16()
        ),
    }
}

async fn rotate(connection: Connection, rotation: Rotation, phase: &str) -> Result<()> {
    let client = Client::new(connection, Auth::Bearer(rotation.bearer))?;
    let path = format!(
        "/v1/admin/auth/root-token-rotations/{}/{phase}",
        rotation.rotation_id
    );
    let (status, _, _) = client.lifecycle(Method::POST, &path, None).await?;
    ensure!(
        status == StatusCode::NO_CONTENT,
        "controller root token rotation {phase} returned unexpected HTTP status {}",
        status.as_u16()
    );
    Ok(())
}

fn generate(path: PathBuf) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "root-token generate requires an absolute --out-file"
    );
    let parent = path
        .parent()
        .context("root token output requires a parent")?;
    ensure!(
        parent.canonicalize()? == parent,
        "root token output parent must be a real directory without symbolic links"
    );
    let metadata = parent.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o700 && metadata.uid() == 0,
        "root token output parent must be a protected directory owned by root with mode 0700"
    );
    let mut random = Zeroizing::new([0; 32]);
    getrandom::fill(random.as_mut()).context("generate root administrator credential")?;
    let mut token = Zeroizing::new([b'\n'; 65]);
    hex::encode_to_slice(random.as_ref(), &mut token[..64])?;
    let file = stage(&path, token.as_ref(), 0o600, 0o700)?;
    ensure!(
        file.as_file().metadata()?.gid() == 0,
        "root token output must be owned by root group"
    );
    file.persist_noclobber(&path)
        .context("create protected root token output")?;
    if let Err(error) = fs::File::open(parent).and_then(|directory| directory.sync_all()) {
        let _ = fs::remove_file(&path);
        return Err(error).context("sync root token output directory");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant<'a> {
    grant: &'a str,
    expires_at_unix_seconds: u64,
}

#[derive(Serialize)]
struct Credential<'a> {
    grant: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
}

struct SecretBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

async fn password_lifecycle(
    connection: Connection,
    options: Password,
    recover: bool,
) -> Result<()> {
    let username = options.username.as_str();
    ensure!(
        (3..=64).contains(&username.len())
            && username.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index != 0
                        && index + 1 != username.len()
                        && matches!(byte, b'.' | b'_' | b'-'))
            }),
        "administrator lifecycle requires a valid --username"
    );

    let client = Client::new(connection, Auth::Bearer(options.bearer))?;
    ensure!(
        accepted(&client).await?,
        "root administrator credential was rejected before administrator lifecycle input"
    );
    let password = Zeroizing::new(rpassword::prompt_password("New administrator password: ")?);
    ensure!(
        (15..=1024).contains(&password.len()),
        "administrator password must be 15..1024 bytes"
    );
    let confirmation = Zeroizing::new(rpassword::prompt_password(
        "Confirm administrator password: ",
    )?);
    ensure!(
        *password == *confirmation,
        "administrator password confirmation did not match"
    );
    drop(confirmation);

    let (grant_path, consume_path) = if recover {
        let path = format!("/v1/admin/administrators?username={username}");
        let (status, headers, body) = client.lifecycle(Method::GET, &path, None).await?;
        ensure!(
            status == StatusCode::OK,
            "controller administrator lookup returned unexpected HTTP status {}",
            status.as_u16()
        );
        check_json(&headers)?;
        let principal = recovery_owner(&body, username)?;
        (
            format!("/v1/admin/administrators/{principal}/recovery-grants"),
            "/v1/admin/auth/recover",
        )
    } else {
        (
            "/v1/admin/auth/bootstrap-grants".into(),
            "/v1/admin/auth/bootstrap",
        )
    };
    let (status, headers, body) = client.lifecycle(Method::POST, &grant_path, None).await?;
    ensure!(
        status == StatusCode::CREATED,
        "controller administrator grant issuance returned unexpected HTTP status {}",
        status.as_u16()
    );
    check_json(&headers)?;
    let grant: Grant<'_> = serde_json::from_slice(&body)
        .map_err(|_| anyhow::anyhow!("controller returned an invalid lifecycle grant response"))?;
    let mut decoded = Zeroizing::new([0; 32]);
    ensure!(
        grant.expires_at_unix_seconds > 0
            && grant.grant.len() == 43
            && URL_SAFE_NO_PAD.decode_slice(grant.grant, decoded.as_mut()) == Ok(32),
        "controller returned an invalid lifecycle grant"
    );
    let mut payload = Zeroizing::new(Vec::new());
    serde_json::to_writer(
        &mut *payload,
        &Credential {
            grant: grant.grant,
            password: &password,
            username: (!recover).then_some(username),
        },
    )?;
    drop(body);
    drop(password);
    let (status, _, _) = client
        .lifecycle(
            Method::POST,
            consume_path,
            Some(Bytes::from_owner(SecretBody(payload))),
        )
        .await?;
    ensure!(
        status == StatusCode::NO_CONTENT,
        "controller administrator grant consumption returned unexpected HTTP status {}",
        status.as_u16()
    );
    Ok(())
}

fn check_json(headers: &header::HeaderMap) -> Result<()> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    ensure!(
        values
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
            && values.next().is_none(),
        "controller administrator response must be JSON"
    );
    Ok(())
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
    created_at_unix_seconds: u64,
    updated_at_unix_seconds: u64,
    password_updated_at_unix_seconds: u64,
    #[serde(rename = "disabled_at_unix_seconds")]
    _disabled_at_unix_seconds: Option<u64>,
}

fn recovery_owner(body: &[u8], username: &str) -> Result<Id> {
    let owners: Owners = serde_json::from_slice(body)
        .map_err(|_| anyhow::anyhow!("controller administrator lookup returned malformed JSON"))?;
    let [owner] = owners.administrators.as_slice() else {
        anyhow::bail!("controller administrator recovery target was not found uniquely");
    };
    ensure!(
        owner.username == username
            && owner.role == "owner"
            && owner.all_networks
            && owner.network_ids.is_empty()
            && owner.created_at_unix_seconds > 0
            && owner.updated_at_unix_seconds > 0
            && owner.password_updated_at_unix_seconds > 0,
        "controller administrator recovery target is invalid"
    );
    owner
        .principal_id
        .parse()
        .context("controller returned an invalid administrator identity")
}
