use std::{
    env, fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use clap::{Args, Subcommand};
use laneway_protocol::v1::EnrollmentClass;
use lanewayd_rs::{Agent, Config};
use ring::aead;
use zeroize::Zeroizing;

use super::enrollment::RedeemTarget;

const TOKEN_LIMIT: usize = 64 << 10;
const ENVELOPE_LIMIT: usize = 128 << 10;
const ENVELOPE_VERSION: u8 = 1;
const HEADER_LEN: usize = 9;
const NONCE_LEN: usize = 12;
const IDENTITY: [&str; 5] = [
    "connector.toml",
    "ca.crt",
    "node.crt",
    "node.key",
    "wireguard.key",
];

#[derive(Args)]
pub(super) struct StateDirectory {
    #[arg(long, default_value = "/var/lib/laneway/connector")]
    state_dir: PathBuf,
}

#[derive(Subcommand)]
pub(super) enum Operation {
    Activate {
        #[command(flatten)]
        state: StateDirectory,
        #[arg(long)]
        setup_token: String,
    },
    BootstrapSeal {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        expires_at: u64,
    },
    BootstrapActivate {
        #[command(flatten)]
        state: StateDirectory,
        #[arg(long)]
        envelope_file: PathBuf,
    },
    Configure(StateDirectory),
    Validate(StateDirectory),
    Run {
        #[command(flatten)]
        state: StateDirectory,
        #[arg(long)]
        setup_token_file: Option<PathBuf>,
    },
}

pub(super) async fn run(operation: Operation) -> Result<()> {
    match operation {
        Operation::BootstrapSeal { out, expires_at } => {
            ensure!(out.is_absolute(), "--out must be absolute");
            let token = read_secret(io::stdin().lock(), TOKEN_LIMIT + 1)?;
            let token = token.strip_suffix(b"\n").unwrap_or(&token);
            Setup::parse(token)?;
            let (key, envelope) = seal(token, SystemTime::now(), expires_at)?;
            let result = write_envelope(&out, &envelope);
            result?;
            println!("{}", key.as_str());
        }
        Operation::BootstrapActivate {
            state,
            envelope_file,
        } => {
            ensure!(
                envelope_file.is_absolute(),
                "--envelope-file must be absolute"
            );
            let envelope = read_regular(&envelope_file, ENVELOPE_LIMIT, false)?;
            let key = read_secret(io::stdin().lock(), 255)?;
            let plaintext = open(
                std::str::from_utf8(&key)?.trim(),
                std::str::from_utf8(&envelope)?.trim(),
                SystemTime::now(),
            )?;
            activate(&state.state_dir, Setup::parse(&plaintext)?).await?;
        }
        Operation::Activate { state, setup_token } => {
            let token = Zeroizing::new(setup_token);
            activate(&state.state_dir, Setup::parse(token.as_bytes())?).await?;
        }
        Operation::Configure(state) | Operation::Validate(state) => {
            Agent::new(Config::load_connector_state(state.state_dir)?)?;
            println!("configuration is valid");
        }
        Operation::Run {
            state,
            setup_token_file,
        } => {
            let directory = state.state_dir;
            ensure!(directory.is_absolute(), "--state-dir must be absolute");
            let present = IDENTITY
                .iter()
                .try_fold(0, |count, name| {
                    identity_present(&directory.join(name))
                        .map(|present| count + usize::from(present))
                })
                .context("inspect persistent Connector identity")?;
            if present != IDENTITY.len() {
                ensure!(
                    present == 0,
                    "persistent volume contains an incomplete Connector identity"
                );
                let token = startup_token(setup_token_file)?;
                activate(&directory, Setup::parse(&token)?).await?;
            }
            // The daemon runs as PID 1 in the image and receives signals directly.
            let error = Command::new(env::current_exe()?)
                .arg0("lanewayd-rs")
                .arg("--connector-state")
                .arg(directory)
                .env_remove("SETUP_TOKEN")
                .env_remove("SETUP_TOKEN_FILE")
                .exec();
            return Err(error).context("start Connector daemon");
        }
    }
    Ok(())
}

fn identity_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn startup_token(flag: Option<PathBuf>) -> Result<Zeroizing<Vec<u8>>> {
    let environment = env::var_os("SETUP_TOKEN_FILE").filter(|path| !path.is_empty());
    ensure!(
        flag.is_none() || environment.is_none(),
        "Connector setup token file was specified more than once"
    );
    let file = flag.or_else(|| environment.map(PathBuf::from));
    let token = env::var("SETUP_TOKEN").unwrap_or_default();
    let token = Zeroizing::new(token);
    ensure!(
        file.is_none() || token.is_empty(),
        "Connector accepts either SETUP_TOKEN or a setup token file, not both"
    );
    if let Some(path) = file {
        ensure!(
            path.is_absolute(),
            "Connector setup token file path must be absolute"
        );
        let contents = read_regular(&path, TOKEN_LIMIT, true)?;
        let token = std::str::from_utf8(&contents)?.trim();
        ensure!(
            valid_token(token.as_bytes()),
            "--setup-token-file contains an invalid setup token"
        );
        return Ok(Zeroizing::new(token.as_bytes().to_vec()));
    }
    ensure!(
        !token.is_empty(),
        "SETUP_TOKEN or --setup-token-file is required for first start"
    );
    Ok(Zeroizing::new(token.as_bytes().to_vec()))
}

fn read_secret(reader: impl Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut content = Zeroizing::new(Vec::new());
    reader.take(maximum as u64 + 1).read_to_end(&mut content)?;
    ensure!(
        content.len() <= maximum,
        "secret input exceeds its size limit"
    );
    Ok(content)
}

fn read_regular(path: &Path, limit: usize, protected: bool) -> Result<Zeroizing<Vec<u8>>> {
    let file = fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && (!protected || metadata.permissions().mode() & 0o077 == 0),
        "invalid Connector input file"
    );
    read_secret(file, limit)
}

fn valid_token(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= TOKEN_LIMIT
        && !token
            .iter()
            .any(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

struct Setup {
    name: String,
    token: Zeroizing<String>,
    controller: String,
    quic: String,
    server: String,
    network: String,
    controller_service: String,
    relay: String,
    relay_service: String,
    ca: String,
}

impl Setup {
    fn parse(raw: &[u8]) -> Result<Self> {
        ensure!(valid_token(raw), "SETUP_TOKEN has an unsupported format");
        let raw = raw
            .strip_prefix(b"st1.")
            .context("SETUP_TOKEN has an unsupported format")?;
        let payload = Zeroizing::new(
            STANDARD
                .decode(raw)
                .map_err(|_| anyhow::anyhow!("SETUP_TOKEN payload is invalid"))?,
        );
        let payload = std::str::from_utf8(&payload)
            .map_err(|_| anyhow::anyhow!("SETUP_TOKEN payload is invalid"))?;
        ensure!(!payload.contains('\r'), "SETUP_TOKEN payload is invalid");
        let fields: Vec<_> = payload
            .strip_suffix('\n')
            .unwrap_or(payload)
            .splitn(11, '\n')
            .collect();
        let [
            name,
            token,
            controller,
            quic,
            server,
            network,
            controller_service,
            relay,
            relay_service,
            ca,
        ] = fields.as_slice()
        else {
            bail!("SETUP_TOKEN payload has an invalid field count");
        };
        ensure!(
            !name.is_empty()
                && !token.is_empty()
                && !fields[..9].iter().any(|field| field.contains([' ', '\t'])),
            "SETUP_TOKEN contains an empty or unsafe field"
        );
        let ca = String::from_utf8(
            STANDARD
                .decode(ca)
                .map_err(|_| anyhow::anyhow!("SETUP_TOKEN CA bundle is invalid"))?,
        )?;
        ensure!(!ca.is_empty(), "SETUP_TOKEN CA bundle is invalid");
        Ok(Self {
            name: (*name).to_owned(),
            token: Zeroizing::new((*token).to_owned()),
            controller: (*controller).to_owned(),
            quic: (*quic).to_owned(),
            server: (*server).to_owned(),
            network: (*network).to_owned(),
            controller_service: (*controller_service).to_owned(),
            relay: (*relay).to_owned(),
            relay_service: (*relay_service).to_owned(),
            ca,
        })
    }

    fn config(&self, directory: &Path) -> Result<String> {
        let path = directory.to_str().context("state path must be UTF-8")?;
        let mut config = toml::toml! {
            mode = "node"
            socket_path = "/run/laneway/lanewayd.sock"
            [node]
            reconnect_min = "1s"
            reconnect_max = "30s"
            [controller]
            poll_interval = "30s"
            [direct]
            enabled = true
            listen = ":0"
            [connector]
            userspace = true
        };
        config.insert("state_dir".into(), path.into());
        config.insert(
            "tls".into(),
            toml::Value::Table(toml::Table::from_iter([
                ("certificate".into(), format!("{path}/node.crt").into()),
                ("private_key".into(), format!("{path}/node.key").into()),
                ("ca".into(), format!("{path}/ca.crt").into()),
                ("server_name".into(), self.server.as_str().into()),
            ])),
        );
        let node = config["node"]
            .as_table_mut()
            .context("missing node table")?;
        node.insert("name".into(), self.name.as_str().into());
        node.insert("relay_address".into(), self.relay.as_str().into());
        node.insert("relay_network_id".into(), self.network.as_str().into());
        node.insert(
            "relay_service_id".into(),
            self.relay_service.as_str().into(),
        );
        let controller = config["controller"]
            .as_table_mut()
            .context("missing controller table")?;
        controller.insert("endpoint".into(), self.controller.as_str().into());
        controller.insert("quic_endpoint".into(), self.quic.as_str().into());
        controller.insert("server_name".into(), self.server.as_str().into());
        controller.insert("network_id".into(), self.network.as_str().into());
        controller.insert("service_id".into(), self.controller_service.as_str().into());
        let fallback = if self.server.contains(':') && !self.server.starts_with('[') {
            format!("[{}]:443", self.server)
        } else {
            format!("{}:443", self.server)
        };
        config.insert(
            "tcp_fallback".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "address".into(),
                fallback.into(),
            )])),
        );
        Ok(toml::to_string(&config)?)
    }
}

async fn activate(directory: &Path, setup: Setup) -> Result<()> {
    ensure!(directory.is_absolute(), "--state-dir must be absolute");
    let parent = directory
        .parent()
        .context("Connector state has no parent directory")?;
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(parent)?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) => {
            ensure!(metadata.is_dir(), "Connector state path is not a directory");
            ensure!(
                fs::read_dir(directory)?.next().is_none(),
                "Connector activation refuses to replace existing state"
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error).context("inspect Connector state"),
    }

    let staging = tempfile::Builder::new()
        .prefix(".connector-activation-")
        .tempdir_in(parent)?;
    let final_config = setup.config(directory)?;
    let enrolled = RedeemTarget {
        endpoint: &setup.controller,
        ca: setup.ca.as_bytes(),
        server_name: &setup.server,
        network: setup.network.parse()?,
        service: setup.controller_service.parse()?,
    }
    .redeem(&setup.token, &setup.name, EnrollmentClass::DurableNode)
    .await?;
    let path = staging.path();
    write_exclusive(&path.join("ca.crt"), setup.ca.as_bytes(), 0o444)?;
    write_exclusive(&path.join("node.crt"), &enrolled.certificate, 0o444)?;
    write_exclusive(&path.join("node.key"), enrolled.key.as_bytes(), 0o400)?;
    write_exclusive(
        &path.join("wireguard.key"),
        enrolled.wireguard.as_ref(),
        0o400,
    )?;
    let config_path = path.join("connector.toml");
    write_exclusive(&config_path, setup.config(path)?.as_bytes(), 0o444)?;
    Agent::new(Config::load_connector_state(path)?)?;
    fs::remove_file(&config_path)?;
    write_exclusive(&config_path, final_config.as_bytes(), 0o444)?;
    fs::File::open(path)?.sync_all()?;
    fs::rename(path, directory).context("publish Connector identity")?;
    fs::File::open(parent)?.sync_all()?;
    println!(
        "Connector {} activated; persistent identity: {}",
        setup.name,
        directory.display()
    );
    Ok(())
}

fn write_exclusive(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut file = fs::File::options()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn write_envelope(path: &Path, envelope: &str) -> Result<()> {
    let mut file = fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("create bootstrap envelope")?;
    if let Err(error) = writeln!(file, "{envelope}").and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error).context("write bootstrap envelope");
    }
    Ok(())
}

fn seal(token: &[u8], now: SystemTime, expires_at: u64) -> Result<(Zeroizing<String>, String)> {
    ensure!(
        valid_token(token),
        "bootstrap secret: setup token is invalid"
    );
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(expires_at))
        .context("invalid expiry")?;
    ensure!(
        expiry > now && expiry.duration_since(now)? <= Duration::from_secs(600),
        "bootstrap secret: expiry must be in (0,10m]"
    );
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(key.as_mut()).context("generate bootstrap key")?;
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).context("generate bootstrap nonce")?;
    let aead = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key.as_ref()).map_err(|_| invalid_envelope())?,
    );
    let mut header = [0; HEADER_LEN];
    header[0] = ENVELOPE_VERSION;
    header[1..].copy_from_slice(&expires_at.to_be_bytes());
    let mut payload = Zeroizing::new(token.to_vec());
    let tag = aead
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(header),
            &mut payload,
        )
        .map_err(|_| invalid_envelope())?;
    let envelope = [header.as_slice(), &nonce, &payload, tag.as_ref()].concat();
    Ok((
        Zeroizing::new(URL_SAFE_NO_PAD.encode(key.as_ref())),
        URL_SAFE_NO_PAD.encode(envelope),
    ))
}

fn invalid_envelope() -> anyhow::Error {
    anyhow::anyhow!("bootstrap secret: invalid key or payload")
}

fn open(key: &str, envelope: &str, now: SystemTime) -> Result<Zeroizing<Vec<u8>>> {
    let key = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(key)
            .map_err(|_| invalid_envelope())?,
    );
    let mut envelope = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(envelope)
            .map_err(|_| invalid_envelope())?,
    );
    let (header, rest) = envelope
        .split_at_mut_checked(HEADER_LEN)
        .ok_or_else(invalid_envelope)?;
    let (nonce, payload) = rest
        .split_at_mut_checked(NONCE_LEN)
        .ok_or_else(invalid_envelope)?;
    ensure!(header[0] == ENVELOPE_VERSION, invalid_envelope());
    let aead = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| invalid_envelope())?,
    );
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| invalid_envelope())?;
    let plaintext = aead
        .open_in_place(nonce, aead::Aad::from(&*header), payload)
        .map_err(|_| invalid_envelope())?;
    ensure!(valid_token(plaintext), invalid_envelope());
    let expires_at = u64::from_be_bytes(header[1..].try_into()?);
    ensure!(
        expires_at <= i64::MAX as u64 && expires_at > now.duration_since(UNIX_EPOCH)?.as_secs(),
        "bootstrap secret: payload has expired"
    );
    Ok(Zeroizing::new(plaintext.to_vec()))
}
