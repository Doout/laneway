use std::{
    fs::File,
    io::Cursor,
    io::Read,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{Method, Url, blocking::Client as Http, redirect::Policy};
use serde_json::Value;
use zeroize::Zeroizing;

use super::args::Flags;

pub(super) const MAX_REQUEST: usize = 128 << 10;
const MAX_RESPONSE: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(15);

struct SecretBytes(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(super) struct Client {
    origin: String,
    public_origin: String,
    authority: Option<String>,
    http: Http,
    token: Option<Zeroizing<String>>,
    deadline: Instant,
}

impl Client {
    pub(super) fn new(flags: &Flags<'_>, node: bool) -> Result<Self> {
        Self::with_dial(flags, node, None)
    }

    pub(super) fn with_dial(flags: &Flags<'_>, node: bool, dial: Option<&str>) -> Result<Self> {
        let mut url = https_origin(flags.required("controller")?)?;
        let public_origin = url.as_str().trim_end_matches('/').to_owned();
        let origin_authority = url
            .as_str()
            .strip_prefix("https://")
            .context("invalid controller origin")?
            .trim_end_matches('/')
            .to_owned();
        if let Some(dial) = dial {
            let dial: SocketAddr = dial
                .parse()
                .context("controller listen address must be IP:port")?;
            let ip = dial.ip();
            ensure!(
                !ip.is_multicast() && !ip.is_unspecified() && dial.port() != 0,
                "controller listen address must be a usable IP:port"
            );
            url.set_ip_host(ip)
                .map_err(|_| anyhow::anyhow!("invalid controller listen IP"))?;
            url.set_port(Some(dial.port()))
                .map_err(|_| anyhow::anyhow!("invalid controller listen port"))?;
        }
        let ca = bounded(flags.path("ca", "/etc/laneway/ca.crt"), MAX_RESPONSE)?;
        let cert = node
            .then(|| bounded(flags.path("cert", "/etc/laneway/node.crt"), MAX_RESPONSE))
            .transpose()?;
        let key = node
            .then(|| bounded(flags.path("key", "/etc/laneway/node.key"), MAX_REQUEST))
            .transpose()?;
        let key = key.map(Zeroizing::new);
        let credentials = cert.as_deref().zip(key.as_ref().map(|key| key.as_slice()));
        let server_name = flags.text("server-name")?;
        let server_name = (!server_name.is_empty()).then_some(server_name);
        let config = crate::enrollment::https_tls_optional(
            &ca,
            server_name,
            flags.id("controller-network-id")?,
            flags.id("controller-service-id")?,
            credentials,
        )?;
        let token = if node {
            None
        } else {
            let file = flags.path("admin-token-file", "/etc/laneway/admin.token");
            let contents =
                Zeroizing::new(bounded(file, 8 << 10).context("read controller admin token")?);
            let secret = std::str::from_utf8(&contents)
                .context("admin token must be valid UTF-8")?
                .trim();
            ensure!(
                !secret.is_empty() && !secret.contains(['\r', '\n']),
                "admin token must be one nonempty line"
            );
            Some(Zeroizing::new(secret.to_owned()))
        };
        let builder = Http::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(TIMEOUT)
            .https_only(true);
        let (builder, url, authority) =
            crate::enrollment::pinned_endpoint(builder, url, server_name)?;
        let http = builder
            .use_preconfigured_tls(config)
            .build()
            .context("initialize pinned controller HTTPS client")?;
        Ok(Self {
            origin: url.as_str().trim_end_matches('/').to_owned(),
            public_origin,
            authority: if dial.is_some() {
                Some(origin_authority)
            } else {
                authority
            },
            http,
            token,
            deadline: Instant::now() + Duration::from_secs(30),
        })
    }

    pub(super) fn lifecycle(
        &self,
        method: Method,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<(u16, bool, Zeroizing<Vec<u8>>)> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "controller administrator command timed out"
        );
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.origin))
            .timeout(remaining.min(TIMEOUT))
            .header("accept", "application/json")
            .header("cache-control", "no-store");
        if let Some(authority) = &self.authority {
            request = request.header("host", authority);
        }
        if let Some(payload) = body {
            let len = payload.len();
            request = request
                .header("origin", &self.public_origin)
                .header("content-type", "application/json")
                .body(reqwest::blocking::Body::sized(
                    Cursor::new(SecretBytes(payload)),
                    len as u64,
                ));
        } else {
            request = request.bearer_auth(
                self.token
                    .as_ref()
                    .map(|secret| secret.as_str())
                    .context("root administrator credential is required")?,
            );
        }
        let response = request
            .send()
            .context("controller administrator request failed")?;
        let headers = response.headers();
        let mut cache = headers.get_all("cache-control").iter();
        ensure!(
            cache
                .next()
                .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"no-store"))
                && cache.next().is_none()
                && !headers.contains_key("set-cookie"),
            "controller administrator response omitted cache protection or tried to set a cookie"
        );
        let mut types = headers.get_all("content-type").iter();
        let json = types
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<mime::Mime>().ok())
            .is_some_and(|value| value.essence_str() == "application/json")
            && types.next().is_none();
        let status = response.status().as_u16();
        ensure!(
            status != 204 || response.content_length().unwrap_or_default() == 0,
            "controller administrator no-content response declared a body"
        );
        const LIMIT: usize = 8 << 10;
        let mut bytes = Zeroizing::new(Vec::with_capacity(LIMIT + 1));
        response
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .context("controller administrator response could not be read")?;
        ensure!(
            bytes.len() <= LIMIT && (status != 204 || bytes.is_empty()),
            "invalid controller administrator response size"
        );
        Ok((status, json, bytes))
    }

    pub(super) fn get(&self, path: &str) -> Result<Value> {
        self.request(Method::GET, path, None)
    }

    pub(super) fn request(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "controller command timed out");
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.origin))
            .timeout(remaining.min(TIMEOUT))
            .header("accept", "application/json");
        if let Some(authority) = &self.authority {
            request = request.header("host", authority);
        }
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.as_str());
        }
        if let Some(body) = body {
            let payload = serde_json::to_vec(&body)?;
            ensure!(
                payload.len() <= MAX_REQUEST,
                "controller request exceeds limit"
            );
            request = request
                .header("content-type", "application/json")
                .body(payload);
        }
        let response = request.send().context("controller request")?;
        let status = response.status();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut bytes)
            .context("read controller response")?;
        ensure!(
            bytes.len() <= MAX_RESPONSE,
            "controller response exceeds limit"
        );
        if !status.is_success() {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                && let Some(detail) = value["detail"].as_str().filter(|value| !value.is_empty())
            {
                bail!(
                    "controller: {}: {detail}",
                    value["code"].as_str().unwrap_or_default()
                );
            }
            bail!("controller returned {status}");
        }
        serde_json::from_slice(&bytes).context("decode controller response")
    }
}

fn https_origin(value: &str) -> Result<Url> {
    let raw = value
        .strip_prefix("https://")
        .context("controller client: endpoint must be an HTTPS origin")?;
    ensure!(
        !raw.is_empty()
            && !raw.chars().any(char::is_whitespace)
            && !raw.contains(['?', '#', '\\'])
            && (!raw.contains('/') || raw.ends_with('/') && !raw[..raw.len() - 1].contains('/')),
        "controller client: endpoint must be an HTTPS origin"
    );
    let parsed =
        Url::parse(value).context("controller client: endpoint must be an HTTPS origin")?;
    ensure!(
        parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && !parsed.cannot_be_a_base()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && !raw.contains('@')
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "controller client: endpoint must be an HTTPS origin"
    );
    Ok(parsed)
}

pub(super) fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        bytes.len() <= limit,
        "{} exceeds the size limit",
        path.display()
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_rejects_redirection_or_path_inputs() {
        for invalid in [
            "http://127.0.0.1",
            "https://user@localhost",
            "https://localhost/a/..",
            "https://localhost?x=1",
            "https://localhost#fragment",
            "https://localhost\\admin",
            "https:///",
        ] {
            assert!(https_origin(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            https_origin("https://127.0.0.1:8000/").unwrap().as_str(),
            "https://127.0.0.1:8000/"
        );
    }
}
