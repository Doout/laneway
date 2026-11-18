use super::{AUTH, COOKIE, CSRF, Failure, INTERNAL, REQUEST_ID, Reply, State, cookie, response};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, header};
use laneway_controller::{IssuedSession, SessionError, SessionStore};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::OwnedSemaphorePermit;

pub(super) const DENIED: Failure = Failure(
    StatusCode::FORBIDDEN,
    "ERROR_CODE_PERMISSION_DENIED",
    "permission denied",
    false,
);

pub(super) fn csrf_proof(headers: &HeaderMap) -> Option<String> {
    let cookie = cookie(headers, CSRF).ok()??;
    let mut values = headers.get_all("x-laneway-csrf").iter();
    let proof = values.next()?.as_bytes();
    (values.next().is_none() && bool::from(cookie.as_bytes().ct_eq(proof)))
        .then(|| cookie.to_owned())
}

pub(super) fn clear_cookies(reply: &mut Reply) {
    for name in [COOKIE, CSRF] {
        reply.headers_mut().append(header::SET_COOKIE,format!("{name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; HttpOnly; Secure; SameSite=Strict").parse().unwrap());
    }
}

pub(super) fn issued(id: &str, s: IssuedSession) -> Result<Reply, Failure> {
    let mut r = response(
        StatusCode::OK,
        id,
        serde_json::to_vec(&s.view).map_err(|_| INTERNAL)?,
        false,
    );
    let expires = UNIX_EPOCH
        .checked_add(Duration::from_secs(
            s.absolute.try_into().map_err(|_| INTERNAL)?,
        ))
        .ok_or(INTERNAL)?;
    // Format only representable HTTP dates; never panic on corrupt timestamps.
    if s.absolute >= 253402300800 {
        return Err(INTERNAL);
    }
    let max_age = expires
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs()
        .max(1);
    let expires = httpdate::fmt_http_date(expires);
    for (name, value) in [(COOKIE, s.token.as_str()), (CSRF, s.csrf.as_str())] {
        let mut h:hyper::header::HeaderValue=format!("{name}={value}; Path=/; Expires={expires}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict").parse().map_err(|_|INTERNAL)?;
        h.set_sensitive(true);
        r.headers_mut().append(header::SET_COOKIE, h);
    }
    for (name, value) in [
        ("x-laneway-session-id", s.id.to_string()),
        ("x-laneway-session-idle-expires-at", s.idle.to_string()),
        (
            "x-laneway-session-absolute-expires-at",
            s.absolute.to_string(),
        ),
    ] {
        r.headers_mut()
            .insert(name, value.parse().map_err(|_| INTERNAL)?);
    }
    Ok(r)
}
pub(super) async fn session(
    state: State,
    permit: OwnedSemaphorePermit,
    id: &str,
    token: String,
    headers: &HeaderMap,
    rotate: bool,
) -> Result<Reply, Failure> {
    let origin = crate::origin::same_origin(headers);
    let proof = csrf_proof(headers);
    if rotate {
        let proof = proof.filter(|_| origin);
        let s = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            SessionStore::open(&state.database)?.rotate(&token, proof.as_deref())
        })
        .await
        .map_err(|_| INTERNAL)?
        .map_err(|e| match e.downcast_ref::<SessionError>() {
            Some(SessionError::Denied) => DENIED,
            Some(_) => AUTH,
            None => INTERNAL,
        })?;
        return issued(id, s);
    }
    if !origin {
        return Err(DENIED);
    }
    let csrf = proof.ok_or(AUTH)?;
    let res = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        SessionStore::open(&state.database)?.logout(&token, &csrf)
    })
    .await;
    let mut reply = match res {
        Ok(Ok(())) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .header(REQUEST_ID, id)
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Ok(Err(e)) if e.is::<SessionError>() => AUTH.reply(id, false),
        _ => INTERNAL.reply(id, false),
    };
    clear_cookies(&mut reply);
    Ok(reply)
}
