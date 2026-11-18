use super::{
    AUTH, Failure, INTERNAL, Reply, State, access_admin::parse, endpoint_status::failure,
    form::bounded_json_form, no_content, response,
};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{SessionStore, enrollment::renewal::NodeCredential};
use laneway_protocol::{
    Id,
    fleet_updates::{Poll, Report},
};
use rustls::pki_types::CertificateDer;

pub(super) enum Route<'a> {
    Poll,
    Result(&'a str),
}

impl<'a> Route<'a> {
    pub(super) fn parse(path: &'a str) -> Option<Self> {
        match path.strip_prefix("/v1/node/fleet-updates/")? {
            "poll" => Some(Self::Poll),
            suffix => {
                let id = suffix.strip_suffix("/result")?;
                (!id.contains('/')).then_some(Self::Result(id))
            }
        }
    }
}

enum RequestBody {
    Poll(Poll),
    Result(Id, Report),
}

pub(super) async fn handle(
    mut req: Request<Incoming>,
    state: State,
    id: &str,
    route: Route<'_>,
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
    let leaf = req
        .extensions_mut()
        .remove::<CertificateDer<'static>>()
        .ok_or(AUTH)?;
    let permit = state.queries.try_acquire_owned().map_err(|_| {
        Failure(
            S::SERVICE_UNAVAILABLE,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "controller busy",
            true,
        )
    })?;
    let (peer, mut store, permit) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let peer = NodeCredential::from_verified_peer(leaf.as_ref())?;
        let mut store = SessionStore::open(&state.database)?;
        store.check_node_peer(&peer)?;
        Ok((peer, store, permit))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    // Allow room for JSON escaping while bounding the pre-validation payload.
    const MAX_REQUEST: usize = 4_096;
    let body = match route {
        Route::Poll => RequestBody::Poll(bounded_json_form(req, MAX_REQUEST).await?),
        Route::Result(id) => {
            RequestBody::Result(parse(id)?, bounded_json_form(req, MAX_REQUEST).await?)
        }
    };
    let bytes = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        Ok(match body {
            RequestBody::Poll(poll) => {
                Some(serde_json::to_vec(&store.poll_fleet_update(&peer, poll)?)?)
            }
            RequestBody::Result(id, report) => {
                store.report_fleet_update(&peer, id, report)?;
                None
            }
        })
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    Ok(match bytes {
        Some(bytes) => response(S::OK, id, bytes, false),
        None => no_content(id),
    })
}
