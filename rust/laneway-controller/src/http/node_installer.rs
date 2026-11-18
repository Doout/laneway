use super::{
    Credential, Failure, INTERNAL, Reply, State, administrators::failure, credential,
    form::required_json_form, malformed, mutations::csrf_proof, response, with_session_headers,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header, http::uri::Authority};
use laneway_controller::{InstallerKind, NetworkError, SessionStore};
use laneway_protocol::Id;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Form {
    name: Option<String>,
    kind: Option<String>,
    install_mode: Option<String>,
}

#[derive(Serialize)]
struct Installer<'a> {
    installation_id: &'a str,
    command: &'a str,
    expires_at_unix_seconds: i64,
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    network: &str,
) -> Result<Reply, Failure> {
    if req.method() != Method::POST {
        let mut reply = Failure(
            S::METHOD_NOT_ALLOWED,
            "ERROR_CODE_MALFORMED",
            "method not allowed",
            false,
        )
        .reply(id, req.method() == Method::HEAD);
        reply
            .headers_mut()
            .insert(header::ALLOW, header::HeaderValue::from_static("POST"));
        return Ok(reply);
    }
    let caller = credential(req.headers())?;
    let csrf = csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers()));
    let authority = req
        .headers()
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .filter(|host| !host.contains(['@', '%', '\\', '\'', '"']))
        .and_then(|host| host.parse::<Authority>().ok())
        .filter(|host| !host.host().is_empty())
        .ok_or(malformed("invalid installer authority"))?;
    let network = network
        .parse::<Id>()
        .map_err(|_| malformed("invalid network_id"))?;
    let form = required_json_form::<Form>(req).await?;
    if form.install_mode.as_deref() != Some("systemd") {
        return Err(Failure(
            S::UNPROCESSABLE_ENTITY,
            "unsupported_mode",
            "installer mode is not supported",
            false,
        ));
    }
    let kind = match form.kind.as_deref() {
        Some("node") => InstallerKind::Node,
        Some("connector") => InstallerKind::Connector,
        Some("exit") => InstallerKind::Exit,
        _ => return Err(malformed("kind must be node, connector, or exit")),
    };
    let name = form.name.unwrap_or_default();
    let display_name = name.clone();
    let permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    let (token, meta) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let mut store = SessionStore::open(&state.database)?;
        Ok(match caller {
            Credential::Session(raw) => {
                let reply =
                    store.issue_node_installer(&raw, csrf.as_deref(), network, name, kind)?;
                (reply.list, Some((reply.id, reply.idle, reply.absolute)))
            }
            Credential::Bearer(raw) => (
                store.bearer_issue_node_installer(
                    &raw,
                    state.root.as_deref(),
                    network,
                    name,
                    kind,
                )?,
                None,
            ),
        })
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(|err| {
        if let Some(NetworkError::Malformed(detail)) = err.downcast_ref::<NetworkError>() {
            return malformed(detail);
        }
        failure(err)
    })?;
    let (installation, secret, expires) = token.installer_fields();
    let command = Zeroizing::new(format!(
        "token_file=$(mktemp); trap 'rm -f \"$token_file\"' EXIT; umask 077; printf %s {} > \"$token_file\"; sudo laneway node install {} --token-file \"$token_file\" --name {}",
        quote(secret),
        quote(&format!("https://{authority}")),
        quote(&display_name),
    ));
    let json = serde_json::to_vec(&Installer {
        installation_id: installation,
        command: &command,
        expires_at_unix_seconds: expires,
    })
    .map_err(|_| INTERNAL)?;
    let mut reply = response(S::CREATED, id, json, false);
    reply
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    reply.headers_mut().insert(
        header::LOCATION,
        format!("/v1/admin/node-installers/{installation}")
            .parse()
            .map_err(|_| INTERNAL)?,
    );
    with_session_headers(reply, meta)
}
