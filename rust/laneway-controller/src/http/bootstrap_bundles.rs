use super::{
    AUTH, Credential, Failure, INTERNAL, Reply, State,
    administrators::failure,
    credential,
    form::{empty_secret, required_json_form, secret},
    malformed,
    mutations::csrf_proof,
    no_content, response, with_session_headers,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};
use laneway_controller::{
    SessionError, SessionStore,
    bootstrap_bundles::{BundleError, PUBLIC_PATH, valid_id, validate},
    enrollment::relay_configuration::RelayCredential,
};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const UNAVAILABLE: Failure = Failure(
    S::SERVICE_UNAVAILABLE,
    "ERROR_CODE_INTERNAL",
    "bootstrap service temporarily unavailable",
    true,
);
const BUSY: Failure = Failure(
    S::SERVICE_UNAVAILABLE,
    "ERROR_CODE_RESOURCE_EXHAUSTED",
    "controller busy",
    true,
);

#[derive(Default)]
pub(super) struct Bundles(Mutex<HashMap<String, Entry>>);

struct Entry {
    payload: Zeroizing<String>,
    expires: i64,
    deadline: Instant,
    ready: bool,
}

impl Entry {
    fn live(&self, now: i64, instant: Instant) -> bool {
        now < self.expires && instant < self.deadline
    }
}

#[derive(Debug, thiserror::Error)]
#[error("bootstrap bundle storage unavailable")]
struct StoreUnavailable;

struct Reservation {
    bundles: Arc<Bundles>,
    id: String,
    published: bool,
}

impl Bundles {
    fn stage(
        self: &Arc<Self>,
        payload: Zeroizing<String>,
        expires: i64,
        now: i64,
    ) -> anyhow::Result<Reservation> {
        validate(&payload, expires, now)?;
        let instant = Instant::now();
        let mut entries = self.0.lock().map_err(|_| StoreUnavailable)?;
        entries.retain(|_, entry| entry.live(now, instant));
        if entries.len() >= 1024 {
            return Err(StoreUnavailable.into());
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        for _ in 0..8 {
            getrandom::fill(raw.as_mut_slice()).map_err(|_| StoreUnavailable)?;
            let id = URL_SAFE_NO_PAD.encode(raw.as_slice());
            if entries.contains_key(&id) {
                continue;
            }
            let deadline = instant + Duration::from_secs((expires - now) as u64);
            entries.insert(
                id.clone(),
                Entry {
                    payload,
                    expires,
                    deadline,
                    ready: false,
                },
            );
            return Ok(Reservation {
                bundles: self.clone(),
                id,
                published: false,
            });
        }
        Err(StoreUnavailable.into())
    }

    fn take(&self, id: &str, now: i64) -> Option<Zeroizing<String>> {
        let mut entries = self.0.lock().ok()?;
        let entry = entries.get(id)?;
        if !entry.ready {
            return None;
        }
        let entry = entries.remove(id)?;
        entry.live(now, Instant::now()).then_some(entry.payload)
    }
}

impl Reservation {
    fn publish(mut self) -> anyhow::Result<Created> {
        let mut entries = self.bundles.0.lock().map_err(|_| StoreUnavailable)?;
        let entry = entries.get_mut(&self.id).ok_or(StoreUnavailable)?;
        if !entry.live(clock()?, Instant::now()) {
            return Err(StoreUnavailable.into());
        }
        entry.ready = true;
        self.published = true;
        Ok(Created {
            bundle_id: self.id.clone(),
            public_path: format!("{PUBLIC_PATH}{}", self.id),
            expires_at_unix_seconds: entry.expires,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.published
            && let Ok(mut entries) = self.bundles.0.lock()
        {
            entries.remove(&self.id);
        }
    }
}

fn clock() -> anyhow::Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Form {
    #[serde(default = "empty_secret", deserialize_with = "secret")]
    payload: Zeroizing<String>,
    expires_at_unix_seconds: Option<i64>,
}

#[derive(Serialize)]
struct Created {
    bundle_id: String,
    public_path: String,
    expires_at_unix_seconds: i64,
}

pub(super) async fn create(
    req: Request<Incoming>,
    state: State,
    id: &str,
) -> Result<Reply, Failure> {
    if req.method() != Method::POST {
        return method(id, "POST", req.method() == Method::HEAD);
    }
    let auth = credential(req.headers())?;
    let csrf = csrf_proof(req.headers()).filter(|_| crate::origin::same_origin(req.headers()));
    let pending = required_json_form::<Form>(req).await;
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    let (bundle, meta) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let stage = |now| {
            let form = pending?;
            state.bootstrap_bundles.stage(
                form.payload,
                form.expires_at_unix_seconds.unwrap_or_default(),
                now,
            )
        };
        let mut store = SessionStore::open(&state.database)?;
        let (pending, meta) = match auth {
            Credential::Session(token) => {
                let reply = store.stage_bootstrap_bundle(&token, csrf.as_deref(), stage)?;
                (reply.list, Some((reply.id, reply.idle, reply.absolute)))
            }
            Credential::Bearer(header) => (
                store.bearer_stage_bootstrap_bundle(&header, state.root.as_deref(), stage)?,
                None,
            ),
        };
        Ok((pending.publish()?, meta))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(|err| {
        if err.is::<StoreUnavailable>() {
            return UNAVAILABLE;
        }
        match err.downcast_ref::<BundleError>() {
            Some(BundleError::Payload) => {
                malformed("bootstrap payload must be a bounded bash script")
            }
            Some(BundleError::Expiry) => malformed("bootstrap expiry must be within 10 minutes"),
            None => failure(err),
        }
    })?;
    with_session_headers(
        response(
            S::CREATED,
            id,
            serde_json::to_vec(&bundle).map_err(|_| INTERNAL)?,
            false,
        ),
        meta,
    )
}

struct ProtectedBytes(Zeroizing<String>);
impl AsRef<[u8]> for ProtectedBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub(super) async fn fetch(
    mut req: Request<Incoming>,
    state: State,
    id: &str,
    bundle: &str,
) -> Result<Reply, Failure> {
    if req.method() != Method::GET {
        return method(id, "GET", req.method() == Method::HEAD);
    }
    let cert = req
        .extensions_mut()
        .remove::<CertificateDer<'static>>()
        .ok_or(AUTH)?;
    let bundle = (valid_id(bundle) && req.uri().query().is_none_or(str::is_empty))
        .then(|| bundle.to_owned());
    let permit = state.queries.try_acquire_owned().map_err(|_| BUSY)?;
    let payload = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let _permit = permit;
        let peer = RelayCredential::from_verified_peer(cert.as_ref())
            .map_err(|_| SessionError::Invalid)?;
        let mut store = SessionStore::open(&state.database)?;
        store
            .check_relay_peer(&peer)
            .map_err(|_| SessionError::Invalid)?;
        Ok(bundle.and_then(|id| state.bootstrap_bundles.take(&id, clock().ok()?)))
    })
    .await
    .map_err(|_| INTERNAL)?
    .map_err(failure)?;
    let Some(payload) = payload else {
        let mut reply = response(S::NOT_FOUND, id, b"404 page not found\n".to_vec(), false);
        reply.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        return Ok(reply);
    };
    let size = payload.len();
    let mut reply = no_content(id);
    *reply.status_mut() = S::OK;
    *reply.body_mut() = Full::new(Bytes::from_owner(ProtectedBytes(payload)));
    reply.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
    );
    reply
        .headers_mut()
        .insert(header::CONTENT_LENGTH, size.into());
    reply.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    Ok(reply)
}

fn method(id: &str, allow: &'static str, head: bool) -> Result<Reply, Failure> {
    let mut reply = Failure(
        S::METHOD_NOT_ALLOWED,
        "ERROR_CODE_MALFORMED",
        "method not allowed",
        false,
    )
    .reply(id, head);
    reply
        .headers_mut()
        .insert(header::ALLOW, header::HeaderValue::from_static(allow));
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_committed_unexpired_reservations_can_be_taken_once() {
        let bundles = Arc::new(Bundles::default());
        let now = clock().unwrap();
        let payload = || Zeroizing::new(String::from("#!/bin/bash\n:"));
        let abandoned = bundles.stage(payload(), now + 60, now).unwrap();
        let id = abandoned.id.clone();
        assert!(bundles.take(&id, now).is_none());
        drop(abandoned);
        assert!(bundles.0.lock().unwrap().is_empty());
        let live = bundles
            .stage(payload(), now + 60, now)
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(
            &*bundles.take(&live.bundle_id, now).unwrap(),
            "#!/bin/bash\n:"
        );
        assert!(bundles.take(&live.bundle_id, now).is_none());
        let expired = bundles
            .stage(payload(), now + 60, now)
            .unwrap()
            .publish()
            .unwrap();
        assert!(bundles.take(&expired.bundle_id, now + 60).is_none());
        assert!(bundles.stage(payload(), now + 601, now).is_err());
    }
}
