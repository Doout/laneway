use super::{
    Failure, INTERNAL, Reply, State,
    form::{required_json_form, secret},
    malformed,
    mutations::DENIED,
    response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{SessionStore, enrollment::EnrollError};
use serde::Deserialize;
use std::{net::IpAddr, time::Instant};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Form {
    #[serde(deserialize_with = "secret")]
    recovery_token: Zeroizing<String>,
    pkcs10_csr_der: String,
}

pub(super) async fn handle(
    req: Request<Incoming>,
    state: State,
    id: &str,
    peer: IpAddr,
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
            .insert(header::ALLOW, "POST".parse().unwrap());
        return Ok(reply);
    }
    if !state
        .enrollments
        .lock()
        .map_err(|_| INTERNAL)?
        .admit(peer, Instant::now())
    {
        let mut reply = Failure(
            S::TOO_MANY_REQUESTS,
            "ERROR_CODE_RESOURCE_EXHAUSTED",
            "recovery rate limit exceeded; retry later",
            true,
        )
        .reply(id, false);
        reply.headers_mut().insert(header::RETRY_AFTER, 1.into());
        return Ok(reply);
    }
    // No administrator session or client certificate authorizes redemption.
    // Only the one-use approval and the signed, key-bound CSR are considered.
    let form = required_json_form::<Form>(req).await?;
    let der = STANDARD
        .decode(form.pkcs10_csr_der)
        .map_err(|_| malformed("invalid PKCS#10 encoding"))?;
    let permit = state
        .queries
        .try_acquire_owned()
        .map_err(|_| crate::http::QUERY_BUSY)?;
    let issuer = state.issuer.ok_or(INTERNAL)?;
    let (cancel, _request_alive) = tokio::sync::oneshot::channel::<()>();
    let chain = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?.recover_node_credential(
            &form.recovery_token,
            &der,
            &issuer,
            || cancel.is_closed(),
        )
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(|e| match e.downcast_ref::<EnrollError>() {
        Some(EnrollError::Denied) => DENIED,
        _ => INTERNAL,
    })?;
    let chain: Vec<String> = chain
        .certificates_der
        .iter()
        .map(|der| STANDARD.encode(der))
        .collect();
    let body = serde_json::to_vec(&serde_json::json!({"certificates_der": chain}))
        .map_err(|_| INTERNAL)?;
    Ok(response(S::OK, id, body, false))
}
