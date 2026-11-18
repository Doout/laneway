//! Immutable assets from the existing live Vite build; management routes must
//! never receive a browser shell in place of an API response.
#[cfg(unix)]
mod snapshot;

use super::{REQUEST_ID, Reply};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{HeaderMap, Method, Request, Response, StatusCode as S, header};
use std::{collections::HashMap, path::Path};

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

struct Asset {
    body: Bytes,
    content_type: &'static str,
    cache: &'static str,
    etag: Option<header::HeaderValue>,
}

pub(crate) struct Console {
    shell: Asset,
    assets: HashMap<String, Asset>,
}

impl Console {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            snapshot::load(path)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            anyhow::bail!("the static console snapshot loader requires Unix")
        }
    }

    pub(super) fn handle<B>(&self, req: &Request<B>, id: &str) -> Reply {
        let head = req.method() == Method::HEAD;
        if req.method() != Method::GET && !head {
            let mut reply = plain(S::METHOD_NOT_ALLOWED, id, "method not allowed\n", head);
            reply
                .headers_mut()
                .insert(header::ALLOW, value("GET, HEAD"));
            return reply;
        }
        let path = req.uri().path();
        if !canonical(path) {
            return plain(S::NOT_FOUND, id, "not found\n", head);
        }
        let asset = if let Some(asset) = self.assets.get(path) {
            asset
        } else if path == "/assets" || path.starts_with("/assets/") {
            return plain(S::NOT_FOUND, id, "asset not found\n", head);
        } else {
            &self.shell
        };
        let cached = asset.etag.as_ref().is_some_and(|etag| {
            req.headers()
                .get_all(header::IF_NONE_MATCH)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|tags| tags.split(','))
                .any(|tag| {
                    let tag = tag.trim();
                    tag == "*"
                        || tag.strip_prefix("W/").unwrap_or(tag).as_bytes() == etag.as_bytes()
                })
        });
        let mut reply = if cached {
            response(S::NOT_MODIFIED, id, Bytes::new())
        } else {
            let mut reply = response(
                S::OK,
                id,
                if head {
                    Bytes::new()
                } else {
                    asset.body.clone()
                },
            );
            reply
                .headers_mut()
                .insert(header::CONTENT_TYPE, value(asset.content_type));
            reply
                .headers_mut()
                .insert(header::CONTENT_LENGTH, asset.body.len().into());
            reply
        };
        reply
            .headers_mut()
            .insert(header::CACHE_CONTROL, value(asset.cache));
        if let Some(etag) = &asset.etag {
            reply.headers_mut().insert(header::ETAG, etag.clone());
        }
        reply
    }
}

pub(super) fn api_path(path: &str) -> bool {
    ["/v1", "/oauth", "/.well-known", "/applications/new"]
        .into_iter()
        .any(|prefix| {
            path.strip_prefix(prefix)
                .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
        })
}

fn canonical(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['%', '\\'])
        && !path.contains("//")
        && !path.split('/').any(|part| part.starts_with('.'))
}

fn value(s: &'static str) -> header::HeaderValue {
    header::HeaderValue::from_static(s)
}

fn response(status: S, id: &str, body: Bytes) -> Reply {
    let mut reply = Response::new(Full::new(body));
    *reply.status_mut() = status;
    let headers: &mut HeaderMap = reply.headers_mut();
    headers.insert(REQUEST_ID, id.parse().expect("canonical request id"));
    for (name, val) in [
        ("content-security-policy", CSP),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
    ] {
        headers.insert(name, value(val));
    }
    reply
}

fn plain(status: S, id: &str, message: &'static str, head: bool) -> Reply {
    let mut reply = response(
        status,
        id,
        if head {
            Bytes::new()
        } else {
            Bytes::from_static(message.as_bytes())
        },
    );
    reply
        .headers_mut()
        .insert(header::CACHE_CONTROL, value("no-store"));
    reply
        .headers_mut()
        .insert(header::CONTENT_TYPE, value("text/plain; charset=utf-8"));
    reply
        .headers_mut()
        .insert(header::CONTENT_LENGTH, message.len().into());
    reply
}
