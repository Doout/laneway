//! Linux Docker Connector setup and service dispatch.

mod seal;
mod state;

use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, Zeroizing};

use crate::compat;

const DEFAULT_STATE_DIR: &str = "/var/lib/laneway/connector";
const USAGE: &str =
    "Usage: laneway connector <activate|bootstrap-seal|bootstrap-activate|configure|run|validate>";
const MAX_TOKEN: usize = 64 << 10;
const MAX_ENVELOPE: usize = 128 << 10;
const ENV_TOKEN: &str = "SETUP_TOKEN";
const ENV_TOKEN_FILE: &str = "SETUP_TOKEN_FILE";

#[derive(Zeroize)]
#[zeroize(drop)]
struct Setup {
    name: String,
    code: String,
    controller_endpoint: String,
    controller_quic: String,
    server_name: String,
    network_id: String,
    controller_service_id: String,
    relay_endpoint: String,
    relay_service_id: String,
    ca_pem: Vec<u8>,
}

pub(crate) fn run(args: &[OsString]) -> Result<()> {
    let args = if args.first().is_some_and(|arg| arg == "connector") {
        &args[1..]
    } else {
        args
    };
    let command = args.first().and_then(|arg| arg.to_str()).context(USAGE)?;
    let (usage, allowed): (&str, &[&str]) = match command {
        "--help" | "-h" => {
            println!("{USAGE}");
            return Ok(());
        }
        "configure" => (
            "laneway connector configure [--state-dir DIR]",
            &["state-dir"],
        ),
        "validate" => (
            "laneway connector validate [--state-dir DIR]",
            &["state-dir"],
        ),
        "run" => (
            "laneway connector run [--state-dir DIR] [--setup-token-file PATH]",
            &["state-dir", "setup-token-file"],
        ),
        "activate" => (
            "laneway connector activate --setup-token TOKEN [--state-dir DIR]",
            &["setup-token", "state-dir"],
        ),
        "bootstrap-seal" => (
            "laneway connector bootstrap-seal --out FILE --expires-at UNIX < setup-token",
            &["out", "expires-at"],
        ),
        "bootstrap-activate" => (
            "laneway connector bootstrap-activate --envelope-file FILE [--state-dir DIR] < decryption-key",
            &["envelope-file", "state-dir"],
        ),
        _ => bail!("{USAGE}"),
    };
    let Some(options) = parse_options(&args[1..], allowed, usage)? else {
        println!("Usage: {usage}");
        return Ok(());
    };
    let state_dir = options
        .get("state-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    ensure!(state_dir.is_absolute(), "Usage: {usage}");
    match command {
        "configure" => state::configure(&state_dir),
        "validate" => state::validate(&state_dir).map(|_| ()),
        "run" => run_service(
            &state_dir,
            options.get("setup-token-file").map(PathBuf::from),
        ),
        "activate" => {
            let token = options
                .get("setup-token")
                .and_then(|v| v.to_str())
                .context(usage)?;
            state::activate(&state_dir, &parse_setup(token)?)
        }
        "bootstrap-seal" => {
            let output = absolute_path(options.get("out"), usage)?;
            let expires_at = options
                .get("expires-at")
                .and_then(|v| v.to_str())
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| *v > 0)
                .context(usage)?;
            let mut token = Zeroizing::new(Vec::new());
            io::stdin()
                .take(MAX_TOKEN as u64 + 2)
                .read_to_end(&mut token)
                .context("read Connector setup token")?;
            ensure!(
                token.len() <= MAX_TOKEN + 1,
                "Connector setup token exceeds the bootstrap limit"
            );
            let token = token.strip_suffix(b"\n").unwrap_or(&token);
            parse_setup(std::str::from_utf8(token).context("SETUP_TOKEN payload is invalid")?)?;
            let (key, envelope) = seal::seal(token, now()?, expires_at)?;
            let mut file = tempfile::NamedTempFile::new_in(
                output.parent().context("missing envelope parent")?,
            )?;
            writeln!(file, "{envelope}")?;
            file.as_file().sync_all()?;
            file.persist_noclobber(output)
                .map_err(|err| err.error)
                .context("create bootstrap envelope")?;
            println!("{}", key.as_str());
            Ok(())
        }
        "bootstrap-activate" => {
            let path = absolute_path(options.get("envelope-file"), usage)?;
            let envelope = Zeroizing::new(
                state::read_regular(path, MAX_ENVELOPE, false)
                    .context("--envelope-file must be a bounded regular file")?,
            );
            let mut key = Zeroizing::new(String::new());
            io::stdin()
                .take(256)
                .read_to_string(&mut key)
                .context("read bootstrap decryption key")?;
            let setup = seal::open(key.trim(), std::str::from_utf8(&envelope)?.trim(), now()?)?;
            state::activate(&state_dir, &parse_setup(std::str::from_utf8(&setup)?)?)
        }
        _ => unreachable!("checked Connector command"),
    }
}

fn parse_options<'a>(
    args: &'a [OsString],
    allowed: &[&'a str],
    usage: &'static str,
) -> Result<Option<HashMap<&'a str, &'a OsStr>>> {
    let mut options = HashMap::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let option = arg.to_str().context(usage)?;
        if matches!(option, "--help" | "-h") {
            return Ok(None);
        }
        if option == "--" && args.next().is_none() {
            break;
        }
        let option = option
            .strip_prefix("--")
            .or_else(|| option.strip_prefix('-'))
            .context(usage)?;
        let (name, value) = if let Some((name, value)) = option.split_once('=') {
            (name, OsStr::new(value))
        } else {
            (option, args.next().map(OsString::as_os_str).context(usage)?)
        };
        ensure!(allowed.contains(&name), "Usage: {usage}");
        options.insert(name, value);
    }
    Ok(Some(options))
}

fn absolute_path<'a>(value: Option<&&'a OsStr>, usage: &'static str) -> Result<&'a Path> {
    let value = value.copied().context(usage)?;
    let path = Path::new(value);
    ensure!(path.is_absolute(), "Usage: {usage}");
    Ok(path)
}

fn run_service(state_dir: &Path, token_file: Option<PathBuf>) -> Result<()> {
    if let Some(path) = token_file
        .as_deref()
        .filter(|path| !path.as_os_str().is_empty())
    {
        ensure!(
            path.is_absolute(),
            "Connector setup token file path must be absolute"
        );
    }
    let count = state::identity_count(state_dir)?;
    if count != state::IDENTITY_FILES.len() {
        ensure!(
            count == 0,
            "persistent volume contains an incomplete Connector identity"
        );
        let token = service_token(token_file)?;
        state::activate(state_dir, &parse_setup(token.as_str())?)?;
    }
    state::configure(state_dir)?;
    // The legacy Linux runtime still owns the Go userspace Connector dataplane.
    // Preserve the container argv and remove one-time setup material on exec.
    let args = [
        "node".into(),
        "run".into(),
        "-config".into(),
        state_dir.join("connector.toml").into_os_string(),
    ];
    let mut command = compat::command(&args)?;
    command.env_remove(ENV_TOKEN).env_remove(ENV_TOKEN_FILE);
    compat::execute(&mut command)
}

fn service_token(token_file: Option<PathBuf>) -> Result<Zeroizing<String>> {
    let argument = token_file.filter(|path| !path.as_os_str().is_empty());
    let environment = env::var_os(ENV_TOKEN_FILE)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    ensure!(
        argument.is_none() || environment.is_none(),
        "Connector setup token file was specified more than once"
    );
    let token = Zeroizing::new(env::var(ENV_TOKEN).unwrap_or_default());
    if let Some(path) = argument.or(environment) {
        ensure!(
            path.is_absolute(),
            "Connector setup token file path must be absolute"
        );
        ensure!(
            token.is_empty(),
            "Connector accepts either SETUP_TOKEN or a setup token file, not both"
        );
        let token = Zeroizing::new(state::read_regular(&path, MAX_TOKEN, true).context(
            "--setup-token-file must be a protected nonempty regular file no larger than 64 KiB",
        )?);
        let token = std::str::from_utf8(&token)?.trim();
        ensure!(
            !token.is_empty() && !token.contains([' ', '\t', '\r', '\n']),
            "--setup-token-file contains an invalid setup token"
        );
        return Ok(Zeroizing::new(token.to_owned()));
    }
    ensure!(
        !token.is_empty(),
        "SETUP_TOKEN or --setup-token-file is required for first start"
    );
    Ok(token)
}

fn parse_setup(raw: &str) -> Result<Setup> {
    ensure!(
        raw.len() <= MAX_TOKEN,
        "SETUP_TOKEN has an unsupported format"
    );
    let encoded = raw
        .strip_prefix("st1.")
        .context("SETUP_TOKEN has an unsupported format")?;
    let payload = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .context("SETUP_TOKEN payload is invalid")?,
    );
    ensure!(
        !payload.is_empty() && payload.len() <= 48 << 10 && !payload.contains(&b'\r'),
        "SETUP_TOKEN payload is invalid"
    );
    let text = std::str::from_utf8(&payload).context("SETUP_TOKEN payload is invalid")?;
    let fields: Vec<_> = text
        .strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .collect();
    let [
        name,
        code,
        endpoint,
        quic,
        sni,
        network,
        controller,
        relay_endpoint,
        relay_service,
        ca,
    ] = fields.as_slice()
    else {
        bail!("SETUP_TOKEN payload has an invalid field count");
    };
    ensure!(
        !name.is_empty()
            && !code.is_empty()
            && fields[..9].iter().all(|field| !field.contains([' ', '\t'])),
        "SETUP_TOKEN contains an empty or unsafe field"
    );
    let ca_pem = STANDARD
        .decode(ca)
        .context("SETUP_TOKEN CA bundle is invalid")?;
    ensure!(
        !ca_pem.is_empty() && ca_pem.len() <= 128 << 10,
        "SETUP_TOKEN CA bundle is invalid"
    );
    Ok(Setup {
        name: (*name).to_owned(),
        code: (*code).to_owned(),
        controller_endpoint: (*endpoint).to_owned(),
        controller_quic: (*quic).to_owned(),
        server_name: (*sni).to_owned(),
        network_id: (*network).to_owned(),
        controller_service_id: (*controller).to_owned(),
        relay_endpoint: (*relay_endpoint).to_owned(),
        relay_service_id: (*relay_service).to_owned(),
        ca_pem,
    })
}

fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
