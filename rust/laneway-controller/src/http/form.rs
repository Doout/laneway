use super::{Failure, malformed};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode, body::Incoming, header};
use serde::Deserialize;
use zeroize::Zeroizing;

pub(super) async fn json_form<T: serde::de::DeserializeOwned + Default>(
    req: Request<Incoming>,
) -> Result<T, Failure> {
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
            if bytes.len() > 131072 - data.len() {
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
    let form = Option::<T>::deserialize(&mut de)
        .map_err(|_| malformed("malformed JSON request"))?
        .unwrap_or_default();
    de.end()
        .map_err(|_| malformed("request must contain one JSON value"))?;
    Ok(form)
}
