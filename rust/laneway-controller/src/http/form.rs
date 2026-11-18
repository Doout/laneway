use super::{Failure, malformed};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode, body::Incoming, header};
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

const MAX_JSON_BYTES: usize = 131072;
pub(super) fn empty_secret() -> Zeroizing<String> {
    Zeroizing::new(String::new())
}

pub(super) fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    Ok(Zeroizing::new(
        Option::<String>::deserialize(d)?.unwrap_or_default(),
    ))
}

pub(super) async fn json_form<T: serde::de::DeserializeOwned + Default>(
    req: Request<Incoming>,
) -> Result<T, Failure> {
    Ok(decode(req, MAX_JSON_BYTES).await?.unwrap_or_default())
}

pub(super) async fn required_json_form<T: serde::de::DeserializeOwned>(
    req: Request<Incoming>,
) -> Result<T, Failure> {
    bounded_json_form(req, MAX_JSON_BYTES).await
}

pub(super) async fn bounded_json_form<T: serde::de::DeserializeOwned>(
    req: Request<Incoming>,
    max_bytes: usize,
) -> Result<T, Failure> {
    decode(req, max_bytes)
        .await?
        .ok_or(malformed("JSON request is required"))
}

async fn decode<T: serde::de::DeserializeOwned>(
    req: Request<Incoming>,
    max_bytes: usize,
) -> Result<Option<T>, Failure> {
    let media = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<mime::Mime>().ok());
    if media
        .as_ref()
        .is_none_or(|m| m.essence_str() != "application/json")
    {
        return Err(Failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "ERROR_CODE_MALFORMED",
            "Content-Type must be application/json",
            false,
        ));
    }
    let mut body = req.into_body();
    let mut data = Zeroizing::new(Vec::new());
    while let Some(frame) = body.frame().await {
        if let Ok(bytes) = frame
            .map_err(|_| malformed("could not read request body"))?
            .into_data()
        {
            if bytes.len() > max_bytes - data.len() {
                return Err(Failure(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "ERROR_CODE_RESOURCE_EXHAUSTED",
                    "request body exceeds limit",
                    false,
                ));
            }
            data.extend_from_slice(&bytes);
        }
    }
    let mut de = serde_json::Deserializer::from_slice(&data);
    let form =
        Option::<T>::deserialize(&mut de).map_err(|_| malformed("malformed JSON request"))?;
    de.end()
        .map_err(|_| malformed("request must contain one JSON value"))?;
    Ok(form)
}
