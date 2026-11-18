use super::{Reply, State, response};
use hyper::{Method, Request, StatusCode as S, body::Incoming, header};

pub(super) async fn handle(req: Request<Incoming>, state: State, id: &str) -> Reply {
    let head = req.method() == Method::HEAD;
    let mut reply = match (req.method(), req.uri().query(), state.bootstrap_discovery) {
        (&Method::GET, None | Some(""), Some(discovery)) => {
            if let Ok(permit) = state.queries.try_acquire_owned() {
                match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    discovery.document(&state.database)
                })
                .await
                {
                    Ok(Ok(body)) => response(S::OK, id, body, false),
                    _ => unavailable(id),
                }
            } else {
                unavailable(id)
            }
        }
        _ => plain(S::NOT_FOUND, id, "404 page not found\n", head),
    };
    reply.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    reply
}

fn unavailable(id: &str) -> Reply {
    plain(
        S::SERVICE_UNAVAILABLE,
        id,
        "bootstrap metadata temporarily unavailable\n",
        false,
    )
}

fn plain(status: S, id: &str, text: &str, head: bool) -> Reply {
    let mut reply = response(status, id, text.as_bytes().to_vec(), head);
    reply.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    reply
}
