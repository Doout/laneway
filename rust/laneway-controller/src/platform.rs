//! Opt-in operator plane. No instance HTTP API is mounted on this listener.
use anyhow::{Context, Result, ensure};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use laneway_protocol::tenants::{Deployment, Manifest, Tenant, valid_slug};
use rusqlite::{Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    ffi::OsString,
    fmt::Write as _,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};

const USAGE: &str = "usage: laneway-controller platform init STATE_DIR | serve STATE_DIR ACTIVE_MANIFEST 127.0.0.1:PORT | stage STATE_DIR ACTIVE_MANIFEST SLUG PROVISION_JSON";
const LIMIT: u64 = 262_144;
const SESSION_AGE: Duration = Duration::from_secs(8 * 60 * 60);
const COOKIE: &str = "__Host-laneway-platform";
const SIGN_IN: &str = "/platform/sign-in";

pub fn command(args: impl Iterator<Item = OsString>) -> Result<()> {
    let args: Vec<_> = args.collect();
    match args.as_slice() {
        [verb, state] if verb == "init" => init(Path::new(state)),
        [verb, state, active, address] if verb == "serve" => {
            let address: SocketAddr = address.to_str().context(USAGE)?.parse()?;
            ensure!(
                address.ip().is_loopback() && address.port() > 0,
                "use a fixed loopback listener"
            );
            let state = State::open(Path::new(state), Path::new(active))?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve(state, address))
        }
        [verb, state, active, slug, deployment] if verb == "stage" => {
            let state = State::open(Path::new(state), Path::new(active))?;
            stage(&state, slug.to_str().context(USAGE)?, Path::new(deployment))
        }
        _ => anyhow::bail!(USAGE),
    }
}

fn init(path: &Path) -> Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    let mut password = [0u8; 32];
    getrandom::fill(&mut password).map_err(|error| anyhow::anyhow!("{error}"))?;
    let mut key = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("operator.password"))?;
    writeln!(key, "{}", hex::encode(password))?;
    Connection::open(path.join("directory.db"))?.execute_batch(
        "CREATE TABLE requests (slug TEXT PRIMARY KEY, candidate_base TEXT) STRICT;",
    )?;
    println!("Platform directory initialized. Read operator.password locally; it is never served.");
    Ok(())
}

struct State {
    directory: PathBuf,
    manifest: PathBuf,
    auth_digest: [u8; 32],
    sessions: Mutex<BTreeMap<[u8; 32], Instant>>,
}

impl State {
    fn open(directory: &Path, manifest: &Path) -> Result<Self> {
        let info = fs::symlink_metadata(directory)?;
        ensure!(
            info.is_dir() && info.permissions().mode() & 0o077 == 0,
            "platform state must be a private directory"
        );
        let directory = directory.canonicalize()?;
        let key = directory.join("operator.password");
        let info = fs::symlink_metadata(&key)?;
        ensure!(
            info.is_file() && info.permissions().mode() & 0o077 == 0,
            "operator password must be a private regular file"
        );
        let password = zeroize::Zeroizing::new(String::from_utf8(read_limited(&key, 128)?)?);
        let password = password.trim_end();
        ensure!(
            password.len() == 64 && password.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid operator password file"
        );
        let credential = zeroize::Zeroizing::new(format!("operator:{password}"));
        let state = Self {
            directory,
            manifest: manifest.canonicalize()?,
            auth_digest: Sha256::digest(credential.as_bytes()).into(),
            sessions: Mutex::default(),
        };
        load_manifest(&state.manifest)?;
        state.db()?;
        Ok(state)
    }

    fn db(&self) -> Result<Connection> {
        let db = Connection::open_with_flags(
            self.directory.join("directory.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        db.busy_timeout(Duration::from_secs(1))?;
        Ok(db)
    }

    fn valid_password(&self, password: &str) -> bool {
        let candidate = zeroize::Zeroizing::new(format!("operator:{password}"));
        let actual: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        bool::from(self.auth_digest.ct_eq(&actual))
    }

    fn session(&self, token: Option<[u8; 32]>, revoke: bool, now: Instant) -> bool {
        let (Some(token), Ok(mut sessions)) = (token, self.sessions.lock()) else {
            return false;
        };
        sessions.retain(|_, expires| *expires > now);
        if revoke {
            sessions.remove(&token).is_some()
        } else {
            sessions.contains_key(&token)
        }
    }

    fn start_session(&self, previous: Option<[u8; 32]>, now: Instant) -> Result<String> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!("{error}"))?;
        let token = hex::encode(random);
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session lock"))?;
        sessions.retain(|key, expires| Some(*key) != previous && *expires > now);
        if sessions.len() >= 64
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, expires)| *expires)
                .map(|(key, _)| *key)
        {
            sessions.remove(&oldest);
        }
        sessions.insert(Sha256::digest(token.as_bytes()).into(), now + SESSION_AGE);
        Ok(token)
    }
}

fn session_key(headers: &hyper::HeaderMap) -> Option<[u8; 32]> {
    let mut values = headers
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == COOKIE).then_some(value)
        });
    let token = values.next()?;
    (values.next().is_none() && token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| Sha256::digest(token.as_bytes()).into())
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= limit,
        "platform input exceeds size limit"
    );
    Ok(data)
}

fn load_manifest(path: &Path) -> Result<(Manifest, String)> {
    let bytes = read_limited(path, LIMIT)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    manifest.directory_entries().map_err(anyhow::Error::msg)?;
    Ok((manifest, hex::encode(Sha256::digest(&bytes))))
}

fn reserve(state: &State, slug: &str) -> Result<bool> {
    if !valid_slug(slug) {
        return Ok(false);
    }
    let mut db = state.db()?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (manifest, _) = load_manifest(&state.manifest)?;
    if manifest.tenants.iter().any(|tenant| tenant.slug == slug) {
        return Ok(false);
    }
    let inserted = tx.execute(
        "INSERT INTO requests (slug) SELECT ?1 WHERE (SELECT count(*) FROM requests) < 128 ON CONFLICT DO NOTHING",
        [slug],
    )?;
    tx.commit()?;
    Ok(inserted != 0)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Provision {
    deployment: Deployment,
    ipv4_pool: String,
    relay_certificate: PathBuf,
    relay_endpoint: String,
}

fn stage(state: &State, slug: &str, input: &Path) -> Result<()> {
    ensure!(valid_slug(slug), "invalid tenant slug");
    let mut db = state.db()?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let staged: Option<String> = tx
        .query_row(
            "SELECT candidate_base FROM requests WHERE slug = ?1",
            [slug],
            |row| row.get(0),
        )
        .context("reserve the tenant in the Platform first")?;
    ensure!(staged.is_none(), "tenant already has a staged candidate");
    let (mut manifest, base) = load_manifest(&state.manifest)?;
    let Provision {
        deployment,
        ipv4_pool,
        relay_certificate,
        relay_endpoint,
    } = serde_json::from_slice(&read_limited(input, LIMIT)?)?;
    let database = deployment.database.clone();
    let candidate = state.directory.join(format!("{slug}.manifest.json"));
    ensure!(
        !candidate.exists(),
        "a candidate file already exists; review it before retrying"
    );
    manifest.tenants.push(Tenant {
        slug: slug.into(),
        deployment,
    });
    manifest.entries().map_err(anyhow::Error::msg)?;
    let deployment = &mut manifest
        .tenants
        .last_mut()
        .context("missing staged tenant")?
        .deployment;
    let host = format!("{slug}.{}", manifest.domain);
    ensure!(!database.exists(), "stage requires a new database path");
    let scratch = tempfile::tempdir_in(
        database
            .parent()
            .context("tenant database needs a parent")?,
    )?;
    deployment.database = scratch.path().join("controller.db");
    let scratch_db = deployment.database.clone();
    crate::server::initialize(
        [
            scratch_db.as_os_str().to_owned(),
            deployment.controller_certificate.as_os_str().to_owned(),
            slug.into(),
            ipv4_pool.into(),
        ]
        .into_iter(),
    )?;
    crate::server::validated_entries(&manifest)?;
    let deployment = &mut manifest
        .tenants
        .last_mut()
        .context("missing staged tenant")?
        .deployment;
    crate::server::validate_staged_tenant(&host, deployment)?;
    register_relay(deployment, &relay_certificate, relay_endpoint)?;
    deployment.database.clone_from(&database);
    let mut file = tempfile::NamedTempFile::new_in(&state.directory)?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    ensure!(
        file.as_file().metadata()?.len() <= LIMIT,
        "candidate manifest exceeds size limit"
    );
    file.as_file().sync_all()?;
    ensure!(
        load_manifest(&state.manifest)?.1 == base,
        "active manifest changed during staging"
    );
    laneway_controller::backup::create(&scratch_db, &database)?;
    file.persist_noclobber(&candidate)?;
    tx.execute(
        "UPDATE requests SET candidate_base = ?1 WHERE slug = ?2",
        [&base, slug],
    )?;
    tx.commit()?;
    println!(
        "Candidate written to {}. Active manifest unchanged. Base SHA-256: {base}",
        candidate.display()
    );
    Ok(())
}

fn register_relay(deployment: &Deployment, certificate: &Path, endpoint: String) -> Result<()> {
    fn identity(path: &Path) -> Result<laneway_protocol::AuthenticatedIdentity> {
        let bytes = read_limited(path, LIMIT)?;
        let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(bytes))
            .next()
            .context("missing workload certificate")??;
        Ok(laneway_protocol::identity_from_certificate_der(
            leaf.as_ref(),
        )?)
    }
    let controller = identity(&deployment.controller_certificate)?;
    let relay = identity(certificate)?;
    ensure!(
        relay.role == laneway_protocol::Role::Relay && relay.network_id == controller.network_id,
        "relay certificate must belong to the new tenant network"
    );
    let root =
        laneway_controller::RootCredential::load(&deployment.root_token, &deployment.database)?;
    let token = zeroize::Zeroizing::new(read_limited(&deployment.root_token, 4096)?);
    let header = zeroize::Zeroizing::new(format!(
        "Bearer {}",
        std::str::from_utf8(token.trim_ascii())?
    ));
    laneway_controller::SessionStore::open(&deployment.database)?.bearer_access(
        &header,
        Some(&root),
        Ok(laneway_controller::access_admin::Request::RegisterRelay {
            net: relay.network_id,
            service: relay.subject_id,
            node: None,
            name: "Tenant relay".into(),
            endpoint,
        }),
    )?;
    Ok(())
}

fn directory(state: &State) -> Result<String> {
    let (manifest, base) = load_manifest(&state.manifest)?;
    let mut entries = BTreeMap::new();
    let db = state.db()?;
    let mut query = db.prepare("SELECT slug, candidate_base FROM requests ORDER BY slug")?;
    for row in query.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })? {
        let (slug, staged) = row?;
        ensure!(valid_slug(&slug), "invalid platform record");
        let status = match staged {
            Some(hash) if hash == base => "Staged · awaiting activation",
            Some(_) => "Staged · active manifest changed",
            None => "Reserved · awaiting staging",
        };
        entries.insert(slug, status);
    }
    for tenant in manifest.tenants {
        entries.insert(tenant.slug, "Configured");
    }
    let mut rows = String::new();
    for (slug, status) in entries {
        let host = format!("{slug}.{}", manifest.domain);
        let name = if status == "Configured" {
            format!("<a href=\"https://{host}/\">{host}</a>")
        } else {
            host
        };
        writeln!(rows, "<tr><td>{name}</td><td>{status}</td></tr>")?;
    }
    Ok(platform_page(include_str!("platform.html")).replace("<!-- tenants -->", &rows))
}

fn platform_page(template: &str) -> String {
    template
        .replace("<!-- platform styles -->", include_str!("platform.css"))
        .replace(
            "<!-- platform brand -->",
            include_str!("platform_brand.html"),
        )
}

async fn serve(state: State, address: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(address).await?;
    let state = Arc::new(state);
    let host: Arc<str> = address.to_string().into();
    let permits = Arc::new(Semaphore::new(16));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let (state, host) = (state.clone(), host.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(|req| response(req, state.clone(), host.clone()));
            let _ = timeout(
                Duration::from_secs(12),
                http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(5))
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(socket), service),
            )
            .await;
        });
    }
}

async fn response(
    req: Request<Incoming>,
    state: Arc<State>,
    host: Arc<str>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let header = |key| req.headers().get(key).and_then(|v| v.to_str().ok());
    let key = session_key(req.headers());
    let now = Instant::now();
    let signed_in = state.session(key, false, now);
    let mut res = if header("host") != Some(host.as_ref()) {
        reply(
            StatusCode::BAD_REQUEST,
            "Use the configured loopback address.",
        )
    } else if req.method() == Method::POST
        && (req.headers().get_all("origin").iter().count() != 1
            || header("origin") != Some(format!("http://{host}").as_str()))
    {
        reply(StatusCode::FORBIDDEN, "Submit from the Platform console.")
    } else {
        match (req.method(), req.uri().path()) {
            (&Method::GET, SIGN_IN) => {
                if signed_in {
                    redirect("/")
                } else {
                    sign_in(false)
                }
            }
            (&Method::POST, SIGN_IN)
                if header("content-type") == Some("application/x-www-form-urlencoded") =>
            {
                let body = timeout(
                    Duration::from_secs(3),
                    Limited::new(req.into_body(), 512).collect(),
                )
                .await;
                let Ok(Ok(body)) = body else {
                    return Ok(reply(StatusCode::BAD_REQUEST, "Invalid request body."));
                };
                let body = body.to_bytes();
                let mut fields = form_urlencoded::parse(&body);
                let valid = matches!((fields.next(), fields.next(), fields.next()),
                    (Some((user, name)), Some((pass, password)), None)
                        if user == "username" && name == "operator" && pass == "password"
                            && state.valid_password(&password));
                if !valid {
                    sign_in(true)
                } else {
                    match state.start_session(key, now) {
                        Ok(token) => with_session_cookie(redirect("/"), &token, SESSION_AGE),
                        Err(_) => reply(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Could not start a session.",
                        ),
                    }
                }
            }
            (&Method::POST, "/platform/sign-out") => {
                state.session(key, true, now);
                with_session_cookie(redirect(SIGN_IN), "", Duration::ZERO)
            }
            (&Method::GET, "/") | (&Method::POST, "/tenants") if !signed_in => redirect(SIGN_IN),
            (&Method::GET, "/") => {
                match tokio::task::spawn_blocking(move || directory(&state)).await {
                    Ok(Ok(html)) => reply(StatusCode::OK, html),
                    _ => reply(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Tenant directory unavailable.",
                    ),
                }
            }
            (&Method::POST, "/tenants")
                if header("content-type") == Some("application/x-www-form-urlencoded") =>
            {
                let Ok(Ok(body)) = timeout(
                    Duration::from_secs(3),
                    Limited::new(req.into_body(), 512).collect(),
                )
                .await
                else {
                    return Ok(reply(StatusCode::BAD_REQUEST, "Invalid request body."));
                };
                let pairs = form_urlencoded::parse(&body.to_bytes())
                    .into_owned()
                    .collect::<Vec<_>>();
                if let [(key, slug)] = pairs.as_slice()
                    && key == "slug"
                {
                    let slug = slug.clone();
                    match tokio::task::spawn_blocking(move || reserve(&state, &slug)).await {
                        Ok(Ok(true)) => {
                            let mut value = reply(StatusCode::SEE_OTHER, "");
                            value
                                .headers_mut()
                                .insert("location", hyper::header::HeaderValue::from_static("/"));
                            value
                        }
                        Ok(Ok(false)) => reply(
                            StatusCode::CONFLICT,
                            "Name is invalid, reserved, already in use, or the queue is full.",
                        ),
                        _ => reply(StatusCode::SERVICE_UNAVAILABLE, "Could not reserve tenant."),
                    }
                } else {
                    reply(StatusCode::BAD_REQUEST, "Provide one tenant slug.")
                }
            }
            (&Method::POST, "/tenants") => {
                reply(StatusCode::FORBIDDEN, "Submit from the Platform console.")
            }
            _ => reply(StatusCode::NOT_FOUND, "Not found."),
        }
    };
    res.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    Ok(res)
}

fn redirect(path: &'static str) -> Response<Full<Bytes>> {
    let mut result = reply(StatusCode::SEE_OTHER, "");
    result
        .headers_mut()
        .insert("location", hyper::header::HeaderValue::from_static(path));
    result
}

fn with_session_cookie(
    mut response: Response<Full<Bytes>>,
    token: &str,
    age: Duration,
) -> Response<Full<Bytes>> {
    let mut value: hyper::header::HeaderValue = format!(
        "{COOKIE}={token}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
        age.as_secs()
    )
    .parse()
    .expect("generated cookie header");
    value.set_sensitive(true);
    response.headers_mut().insert("set-cookie", value);
    response
}

fn sign_in(failed: bool) -> Response<Full<Bytes>> {
    let message = if failed {
        "<p role=\"alert\">Incorrect username or password.</p>"
    } else {
        ""
    };
    reply(
        if failed {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::OK
        },
        platform_page(include_str!("platform_sign_in.html")).replace("<!-- error -->", message),
    )
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder().status(status)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        .body(Full::new(body.into())).expect("static response headers")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire_and_cannot_be_reused_after_revocation() {
        let state = State {
            directory: PathBuf::new(),
            manifest: PathBuf::new(),
            auth_digest: [0; 32],
            sessions: Mutex::default(),
        };
        let now = Instant::now();
        let token = state.start_session(None, now).unwrap();
        let key = Some(Sha256::digest(token.as_bytes()).into());
        assert!(state.session(key, false, now + SESSION_AGE - Duration::from_secs(1)));
        assert!(!state.session(key, false, now + SESSION_AGE));

        let other = state.start_session(None, now).unwrap();
        let key = Some(Sha256::digest(other.as_bytes()).into());
        assert!(state.session(key, true, now));
        assert!(!state.session(key, false, now));
    }
}
