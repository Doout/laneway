use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use clap::{ArgAction, Args, Subcommand, ValueEnum};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use laneway_protocol::Id;
use reqwest::{Method, Url};
use rustls::ClientConfig;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::rootless_cli::enroll::{PinnedController, certificates, https_origin, private_key};

const REQUEST_LIMIT: usize = 128 << 10;
const RESPONSE_LIMIT: usize = 1 << 20;
pub(super) const SUBNET_ROUTER: u64 = 1 << 3;
pub(super) const EXIT_NODE: u64 = 1 << 4;

#[derive(Args)]
pub(super) struct Connection {
    #[arg(long, global = true)]
    pub(super) controller: Option<String>,
    #[arg(long, global = true, default_value = "/etc/laneway/ca.crt")]
    pub(super) ca: PathBuf,
    #[arg(long, global = true)]
    pub(super) server_name: Option<String>,
    #[arg(long, global = true)]
    pub(super) controller_network_id: Option<Id>,
    #[arg(long, global = true)]
    pub(super) controller_service_id: Option<Id>,
}

#[derive(Args)]
pub(super) struct Bearer {
    #[arg(long, default_value = "/etc/laneway/admin.token")]
    pub(super) admin_token_file: PathBuf,
}

#[derive(Args)]
pub(super) struct NodeIdentity {
    #[arg(long, default_value = "/etc/laneway/node.crt")]
    pub(super) cert: PathBuf,
    #[arg(long, default_value = "/etc/laneway/node.key")]
    pub(super) key: PathBuf,
}

#[derive(Args)]
pub(super) struct Limit {
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
    limit: u16,
}

#[derive(Args)]
pub(super) struct NetworkList {
    #[arg(long)]
    network_id: Id,
    #[command(flatten)]
    limit: Limit,
}

#[derive(Subcommand)]
pub(super) enum Operation {
    #[cfg(target_os = "linux")]
    #[command(subcommand)]
    Administrator(super::administrator::Operation),
    #[command(subcommand)]
    Network(Network),
    #[command(subcommand)]
    Node(Node),
    #[command(subcommand)]
    Relay(Relay),
    #[command(subcommand)]
    Certificate(Certificate),
    #[command(subcommand)]
    Acl(Acl),
    #[command(subcommand)]
    EnrollmentToken(EnrollmentToken),
    #[command(subcommand)]
    BootstrapBundle(BootstrapBundle),
    #[command(subcommand)]
    Route(Route),
    Overview {
        #[arg(long)]
        network_id: Id,
        #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
        json: bool,
        #[command(flatten)]
        bearer: Bearer,
    },
    Audit {
        #[command(flatten)]
        list: NetworkList,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Subcommand)]
pub(super) enum Network {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        ipv4_pool: Ipv4Net,
        #[arg(long)]
        ipv6_pool: Option<Ipv6Net>,
        #[arg(long)]
        network_id: Option<Id>,
        #[command(flatten)]
        bearer: Bearer,
    },
    Get {
        #[arg(long)]
        network_id: Id,
        #[command(flatten)]
        bearer: Bearer,
    },
    List {
        #[command(flatten)]
        limit: Limit,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Subcommand)]
pub(super) enum Node {
    List {
        #[command(flatten)]
        list: NetworkList,
        #[command(flatten)]
        bearer: Bearer,
    },
    Revoke {
        #[arg(long)]
        node_id: Id,
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        bearer: Bearer,
    },
    Capabilities {
        #[arg(long)]
        node_id: Id,
        #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
        subnet_router: bool,
        #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
        exit_node: bool,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Subcommand)]
pub(super) enum Relay {
    Register {
        #[arg(long)]
        network_id: Id,
        #[arg(long)]
        service_id: Id,
        #[arg(long)]
        node_id: Option<Id>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        endpoint: String,
        #[command(flatten)]
        bearer: Bearer,
    },
    Update {
        #[arg(long)]
        relay_id: Id,
        #[arg(long)]
        name: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = true)]
        enabled: bool,
        #[command(flatten)]
        bearer: Bearer,
    },
    Disable {
        #[arg(long)]
        relay_id: Id,
        #[command(flatten)]
        bearer: Bearer,
    },
    List {
        #[command(flatten)]
        list: NetworkList,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Subcommand)]
pub(super) enum Certificate {
    List {
        #[command(flatten)]
        list: NetworkList,
        #[command(flatten)]
        bearer: Bearer,
    },
    Revoke {
        #[arg(long)]
        network_id: Id,
        #[arg(long)]
        serial: String,
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub(super) struct Selector {
    #[arg(long)]
    selector: Option<String>,
    #[arg(long)]
    selector_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(super) enum Acl {
    List {
        #[command(flatten)]
        list: NetworkList,
        #[command(flatten)]
        bearer: Bearer,
    },
    Add {
        #[arg(long)]
        network_id: Id,
        #[arg(long, default_value_t = 0)]
        priority: u32,
        #[arg(long, value_parser = ["accept", "deny"])]
        action: String,
        #[command(flatten)]
        selector: Selector,
        #[arg(long, default_value = "")]
        description: String,
        #[command(flatten)]
        bearer: Bearer,
    },
    Delete {
        #[arg(long)]
        rule_id: Id,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum EnrollmentClass {
    Durable,
    Ephemeral,
    Remembered,
}

impl EnrollmentClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Ephemeral => "ephemeral",
            Self::Remembered => "remembered",
        }
    }
}

#[derive(Subcommand)]
pub(super) enum EnrollmentToken {
    Issue {
        #[arg(long)]
        network_id: Id,
        #[arg(long)]
        label: String,
        #[arg(long, value_parser = parse_duration, default_value = "1h")]
        expires_in: Duration,
        #[arg(long, value_enum, default_value = "durable")]
        class: EnrollmentClass,
        #[arg(long, value_parser = parse_duration, default_value = "0")]
        session_lifetime: Duration,
        #[arg(long, default_value = "")]
        requested_name: String,
        #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
        connector: bool,
        #[arg(long, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = false)]
        exit_node: bool,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Subcommand)]
pub(super) enum BootstrapBundle {
    Create {
        #[arg(long)]
        payload_file: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        expires_at: i64,
        #[command(flatten)]
        bearer: Bearer,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub(super) struct AdvertisedPrefix {
    #[arg(value_name = "PREFIX")]
    positional_prefix: Option<IpNet>,
    #[arg(long)]
    prefix: Option<IpNet>,
}

#[derive(Subcommand)]
pub(super) enum Route {
    Assign {
        #[command(flatten)]
        assignment: super::inventory::Assignment,
        #[command(flatten)]
        bearer: Bearer,
    },
    List {
        #[command(flatten)]
        list: NetworkList,
        #[command(flatten)]
        bearer: Bearer,
    },
    Approve {
        #[arg(long)]
        route_id: Id,
        #[command(flatten)]
        bearer: Bearer,
    },
    Advertise {
        #[command(flatten)]
        prefix: AdvertisedPrefix,
        #[arg(long, value_parser = ["subnet", "exit"], default_value = "subnet")]
        kind: String,
        #[arg(long, value_parser = ["nat", "routed"], default_value = "nat")]
        mode: String,
        #[arg(long, default_value_t = 0)]
        metric: u32,
        #[arg(long, value_parser = parse_duration, default_value = "0")]
        valid_for: Duration,
        #[command(flatten)]
        identity: NodeIdentity,
    },
    Withdraw {
        #[arg(long)]
        route_id: Id,
        #[command(flatten)]
        identity: NodeIdentity,
    },
}

pub(super) async fn run(connection: Connection, operation: Operation) -> Result<()> {
    const DELETE: Method = Method::DELETE;
    const GET: Method = Method::GET;
    const POST: Method = Method::POST;
    const PUT: Method = Method::PUT;
    use Operation::*;

    let (auth, method, path, body) = match operation {
        #[cfg(target_os = "linux")]
        Administrator(operation) => return super::administrator::run(connection, operation).await,
        Network(self::Network::Create {
            name,
            ipv4_pool,
            ipv6_pool,
            network_id,
            bearer,
        }) => {
            ensure!(
                !name.is_empty() && ipv4_pool == ipv4_pool.trunc(),
                "network create requires --name and a canonical IPv4 --ipv4-pool"
            );
            let mut body = json!({"name": name, "ipv4_pool": ipv4_pool.to_string()});
            if let Some(pool) = ipv6_pool {
                ensure!(
                    pool == pool.trunc()
                        && pool.addr().to_ipv4_mapped().is_none()
                        && (64..=120).contains(&pool.prefix_len()),
                    "--ipv6-pool must be a canonical IPv6 /64 through /120"
                );
                body["ipv6_pool"] = json!(pool.to_string());
            }
            if let Some(id) = network_id {
                body["network_id"] = json!(id.to_string());
            }
            (
                Auth::Bearer(bearer),
                POST,
                "/v1/admin/networks".into(),
                Some(body),
            )
        }
        Network(self::Network::Get { network_id, bearer }) => (
            Auth::Bearer(bearer),
            GET,
            format!("/v1/admin/networks/{network_id}"),
            None,
        ),
        Network(self::Network::List { limit, bearer }) => (
            Auth::Bearer(bearer),
            GET,
            format!("/v1/admin/networks?limit={}", limit.limit),
            None,
        ),
        Node(self::Node::List { list, bearer }) => list_request(bearer, list, "nodes"),
        Node(self::Node::Revoke {
            node_id,
            reason,
            bearer,
        }) => {
            ensure!(!reason.trim().is_empty(), "node revoke requires --reason");
            (
                Auth::Bearer(bearer),
                POST,
                format!("/v1/admin/nodes/{node_id}/revoke"),
                Some(json!({"reason": reason})),
            )
        }
        Node(self::Node::Capabilities {
            node_id,
            subnet_router,
            exit_node,
            bearer,
        }) => {
            let capabilities =
                (u64::from(subnet_router) * SUBNET_ROUTER) | (u64::from(exit_node) * EXIT_NODE);
            (
                Auth::Bearer(bearer),
                PUT,
                format!("/v1/admin/nodes/{node_id}/capabilities"),
                Some(json!({"enabled_capabilities": capabilities})),
            )
        }
        Relay(self::Relay::List { list, bearer }) => list_request(bearer, list, "relays"),
        Relay(self::Relay::Register {
            network_id,
            service_id,
            node_id,
            name,
            endpoint,
            bearer,
        }) => {
            ensure!(
                !name.trim().is_empty() && !endpoint.trim().is_empty(),
                "relay register requires --name and --endpoint"
            );
            let mut body =
                json!({"service_id": service_id.to_string(), "name": name, "endpoint": endpoint});
            if let Some(id) = node_id {
                body["node_id"] = json!(id.to_string());
            }
            (
                Auth::Bearer(bearer),
                POST,
                format!("/v1/admin/networks/{network_id}/relays"),
                Some(body),
            )
        }
        Relay(self::Relay::Update {
            relay_id,
            name,
            endpoint,
            enabled,
            bearer,
        }) => {
            ensure!(
                !name.is_empty() && !endpoint.is_empty(),
                "relay update requires --name and --endpoint"
            );
            (
                Auth::Bearer(bearer),
                PUT,
                format!("/v1/admin/relays/{relay_id}"),
                Some(json!({"name": name, "endpoint": endpoint, "enabled": enabled})),
            )
        }
        Relay(self::Relay::Disable { relay_id, bearer }) => (
            Auth::Bearer(bearer),
            POST,
            format!("/v1/admin/relays/{relay_id}/disable"),
            None,
        ),
        Certificate(self::Certificate::List { list, bearer }) => {
            list_request(bearer, list, "certificates")
        }
        Certificate(self::Certificate::Revoke {
            network_id,
            serial,
            reason,
            bearer,
        }) => {
            ensure!(
                (2..=64).contains(&serial.len())
                    && serial.len() % 2 == 0
                    && !serial.starts_with("00")
                    && serial
                        .bytes()
                        .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')),
                "certificate revoke --serial must be canonical lowercase positive hexadecimal"
            );
            ensure!(
                !reason.trim().is_empty(),
                "certificate revoke requires --reason"
            );
            (
                Auth::Bearer(bearer),
                POST,
                format!("/v1/admin/networks/{network_id}/certificates/{serial}/revoke"),
                Some(json!({"reason": reason})),
            )
        }
        Acl(self::Acl::List { list, bearer }) => list_request(bearer, list, "acl-rules"),
        Acl(self::Acl::Add {
            network_id,
            priority,
            action,
            selector,
            description,
            bearer,
        }) => {
            let selector: Value = if let Some(path) = selector.selector_file {
                serde_json::from_slice(&read_file(&path, REQUEST_LIMIT)?)?
            } else {
                serde_json::from_str(selector.selector.as_deref().context("missing selector")?)?
            };
            (
                Auth::Bearer(bearer),
                POST,
                format!("/v1/admin/networks/{network_id}/acl-rules"),
                Some(
                    json!({"priority": priority, "action": action, "selector": selector, "description": description}),
                ),
            )
        }
        Acl(self::Acl::Delete { rule_id, bearer }) => (
            Auth::Bearer(bearer),
            DELETE,
            format!("/v1/admin/acl-rules/{rule_id}"),
            None,
        ),
        EnrollmentToken(self::EnrollmentToken::Issue {
            network_id,
            label,
            expires_in,
            class,
            session_lifetime,
            requested_name,
            connector,
            exit_node,
            bearer,
        }) => {
            ensure!(
                !label.is_empty() && !expires_in.is_zero(),
                "enrollment-token issue requires --label and a positive --expires-in"
            );
            ensure!(
                class == EnrollmentClass::Ephemeral || session_lifetime.is_zero(),
                "--session-lifetime is valid only for ephemeral enrollment"
            );
            ensure!(
                !(connector && exit_node),
                "choose either --connector or --exit-node"
            );
            let mut body = json!({"network_id": network_id.to_string(), "label": label, "expires_at_unix_seconds": deadline(expires_in)?, "enrollment_class": class.as_str()});
            if class == EnrollmentClass::Ephemeral {
                let seconds = if session_lifetime.is_zero() {
                    8 * 3600
                } else {
                    session_lifetime.as_secs()
                };
                if seconds != 0 {
                    body["session_lifetime_seconds"] = json!(seconds);
                }
            }
            if !requested_name.is_empty() {
                body["requested_name"] = json!(requested_name);
            }
            if connector || exit_node {
                body["enabled_capabilities"] =
                    json!(if connector { SUBNET_ROUTER } else { EXIT_NODE });
            }
            (
                Auth::Bearer(bearer),
                POST,
                "/v1/admin/enrollment-tokens".into(),
                Some(body),
            )
        }
        BootstrapBundle(self::BootstrapBundle::Create {
            payload_file,
            expires_at,
            bearer,
        }) => {
            let payload = protected_payload(&payload_file)?;
            let connection = Client::new(connection, Auth::Bearer(bearer))?;
            let response = connection
                .request(
                    POST,
                    "/v1/admin/bootstrap-bundles",
                    Some(
                        json!({"payload": payload.as_str(), "expires_at_unix_seconds": expires_at}),
                    ),
                )
                .await?;
            let id = response["bundle_id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .context("missing bootstrap bundle ID")?;
            ensure!(
                response["public_path"] == format!("/.well-known/laneway/bootstrap/{id}")
                    && response["expires_at_unix_seconds"] == expires_at,
                "invalid bootstrap bundle response"
            );
            return print_json(&response);
        }
        Route(self::Route::List { list, bearer }) => list_request(bearer, list, "routes"),
        Route(self::Route::Approve { route_id, bearer }) => (
            Auth::Bearer(bearer),
            POST,
            format!("/v1/admin/routes/{route_id}/approve"),
            None,
        ),
        Route(self::Route::Withdraw { route_id, identity }) => (
            Auth::Node(identity),
            DELETE,
            format!("/v1/routes/{route_id}"),
            None,
        ),
        Route(self::Route::Advertise {
            prefix,
            kind,
            mode,
            metric,
            valid_for,
            identity,
        }) => {
            let prefix = prefix
                .prefix
                .or(prefix.positional_prefix)
                .context("missing route prefix")?;
            ensure!(
                prefix == prefix.trunc(),
                "route advertise requires a canonical PREFIX"
            );
            let mut body =
                json!({"prefix": prefix.to_string(), "kind": kind, "mode": mode, "metric": metric});
            if !valid_for.is_zero() {
                body["valid_until_unix_seconds"] = json!(deadline(valid_for)?);
            }
            (Auth::Node(identity), POST, "/v1/routes".into(), Some(body))
        }
        Route(self::Route::Assign { assignment, bearer }) => {
            let client = Client::new(connection, Auth::Bearer(bearer))?;
            return super::inventory::assign(&client, assignment).await;
        }
        Overview {
            network_id,
            json,
            bearer,
        } => {
            let client = Client::new(connection, Auth::Bearer(bearer))?;
            return super::inventory::overview(&client, network_id, json).await;
        }
        Audit { list, bearer } => list_request(bearer, list, "audit"),
    };
    let client = Client::new(connection, auth)?;
    print_json(&client.request(method, &path, body).await?)
}

pub(super) fn print_json(value: &Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

fn list_request(
    bearer: Bearer,
    list: NetworkList,
    resource: &str,
) -> (Auth, Method, String, Option<Value>) {
    let NetworkList { network_id, limit } = list;
    (
        Auth::Bearer(bearer),
        Method::GET,
        format!(
            "/v1/admin/networks/{network_id}/{resource}?limit={}",
            limit.limit
        ),
        None,
    )
}

pub(super) fn parse_duration(value: &str) -> Result<Duration> {
    if value == "0" {
        return Ok(Duration::ZERO);
    }
    Ok(humantime::parse_duration(value)?)
}

pub(super) fn deadline(duration: Duration) -> Result<u64> {
    Ok(SystemTime::now()
        .checked_add(duration)
        .context("expiry exceeds supported time range")?
        .duration_since(UNIX_EPOCH)?
        .as_secs())
}

pub(super) fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read_limited(
        File::open(path).with_context(|| format!("open {}", path.display()))?,
        limit,
    )
}

fn read_limited(file: File, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "file exceeds {limit} bytes");
    Ok(bytes)
}

#[cfg(unix)]
fn protected_payload(path: &Path) -> Result<Zeroizing<String>> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    ensure!(path.is_absolute(), "--payload-file must be absolute");
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("open bootstrap payload")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "--payload-file must be a protected regular file"
    );
    let payload = Zeroizing::new(String::from_utf8(read_limited(file, 96 << 10)?)?);
    ensure!(!payload.is_empty(), "--payload-file must be nonempty");
    Ok(payload)
}

#[cfg(not(unix))]
fn protected_payload(_path: &Path) -> Result<Zeroizing<String>> {
    anyhow::bail!("protected bootstrap payload files require Unix")
}

pub(super) enum Auth {
    Bearer(Bearer),
    Node(NodeIdentity),
}

pub(super) struct Client {
    origin: Url,
    http: reqwest::Client,
    bearer: Option<Zeroizing<String>>,
}

impl Client {
    pub(super) fn new(connection: Connection, auth: Auth) -> Result<Self> {
        Self::with_dial_address(connection, auth, None)
    }

    pub(super) fn with_dial_address(
        connection: Connection,
        auth: Auth,
        dial: Option<std::net::SocketAddr>,
    ) -> Result<Self> {
        let mut origin = https_origin(
            connection
                .controller
                .as_deref()
                .context("--controller is required")?,
        )?;
        let server_name = connection
            .server_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                origin
                    .host_str()
                    .unwrap_or_default()
                    .trim_matches(['[', ']'])
            });
        let network_id = connection
            .controller_network_id
            .context("--controller-network-id is required")?;
        let service_id = connection
            .controller_service_id
            .context("--controller-service-id is required")?;
        let ca = read_file(&connection.ca, RESPONSE_LIMIT)?;
        let verifier = PinnedController::new(&ca, server_name, network_id, service_id)?;
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        let (config, bearer) = match auth {
            Auth::Node(identity) => {
                let chain = certificates(&read_file(&identity.cert, RESPONSE_LIMIT)?)?;
                let key = Zeroizing::new(read_file(&identity.key, RESPONSE_LIMIT)?);
                (
                    config.with_client_auth_cert(chain, private_key(&key)?)?,
                    None,
                )
            }
            Auth::Bearer(auth) => {
                let token = Zeroizing::new(String::from_utf8(read_file(
                    &auth.admin_token_file,
                    8 << 10,
                )?)?);
                let value = token.trim();
                ensure!(
                    !value.is_empty() && !value.contains(['\r', '\n']),
                    "admin token must be one nonempty line"
                );
                (
                    config.with_no_client_auth(),
                    Some(Zeroizing::new(value.to_owned())),
                )
            }
        };
        let mut http = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(30));
        if let Some(dial) = dial {
            let host = origin.host_str().context("missing controller host")?;
            if host.parse::<std::net::IpAddr>().is_ok() {
                origin
                    .set_ip_host(dial.ip())
                    .map_err(|()| anyhow::anyhow!("invalid controller dial IP"))?;
            } else {
                http = http.resolve(host, dial);
            }
            origin
                .set_port(Some(dial.port()))
                .map_err(|()| anyhow::anyhow!("invalid controller dial port"))?;
        }
        let http = http.build()?;
        Ok(Self {
            origin,
            http,
            bearer,
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn lifecycle(
        &self,
        method: Method,
        path: &str,
        secret: Option<bytes::Bytes>,
    ) -> Result<(
        reqwest::StatusCode,
        reqwest::header::HeaderMap,
        Zeroizing<Vec<u8>>,
    )> {
        use reqwest::{StatusCode, header};
        let mut request = self
            .http
            .request(method, self.origin.join(path)?)
            .header(header::ACCEPT, "application/json")
            .header(header::CACHE_CONTROL, "no-store");
        if let Some(secret) = secret {
            request = request
                .header(header::ORIGIN, self.origin.origin().ascii_serialization())
                .header(header::CONTENT_TYPE, "application/json")
                .body(secret);
        } else {
            let bearer = self.bearer.as_ref().context("admin token is required")?;
            request = request.bearer_auth(bearer.as_str());
        }
        let mut response = request
            .send()
            .await
            .context("controller administrator lifecycle request")?;
        let status = response.status();
        let headers = response.headers().clone();
        let mut cache = headers.get_all(header::CACHE_CONTROL).iter();
        ensure!(
            cache
                .next()
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("no-store"))
                && cache.next().is_none(),
            "controller administrator lifecycle response omitted cache protection"
        );
        ensure!(
            !headers.contains_key(header::SET_COOKIE),
            "controller administrator lifecycle response attempted to set a cookie"
        );
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read administrator lifecycle response")?
        {
            ensure!(
                chunk.len() <= (8 << 10) - body.len(),
                "administrator lifecycle response exceeds limit"
            );
            body.extend_from_slice(&chunk);
        }
        ensure!(
            status != StatusCode::NO_CONTENT
                || (body.is_empty()
                    && headers
                        .get(header::CONTENT_LENGTH)
                        .is_none_or(|value| value.as_bytes() == b"0")),
            "controller administrator lifecycle no-content response contained a body"
        );
        Ok((status, headers, body))
    }

    pub(super) async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut request = self
            .http
            .request(method, self.origin.join(path)?)
            .header("accept", "application/json");
        if let Some(token) = &self.bearer {
            request = request.bearer_auth(token.as_str());
        }
        if let Some(body) = body {
            let body = serde_json::to_vec(&body)?;
            ensure!(
                body.len() <= REQUEST_LIMIT,
                "controller request exceeds limit"
            );
            request = request
                .header("content-type", "application/json")
                .body(body);
        }
        let response = request.send().await.context("controller request")?;
        let status = response.status();
        let bytes = response_body(response).await?;
        if !status.is_success() {
            if let Ok(error) = serde_json::from_slice::<Value>(&bytes)
                && let Some(detail) = error["detail"].as_str().filter(|detail| !detail.is_empty())
            {
                anyhow::bail!(
                    "controller: {}: {detail}",
                    error["code"].as_str().unwrap_or_default()
                );
            }
            anyhow::bail!("controller returned {status}");
        }
        serde_json::from_slice(&bytes).context("decode controller response")
    }
}

pub(super) async fn response_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read response")? {
        ensure!(
            chunk.len() <= RESPONSE_LIMIT - bytes.len(),
            "response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
