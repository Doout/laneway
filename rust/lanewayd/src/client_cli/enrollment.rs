use std::io::{self, Read, Write};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use laneway_protocol::{
    Id,
    v1::{EnrollmentClass, EnrollmentRequest},
};
use prost::Message;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input<'a> {
    endpoint: &'a str,
    ca_pem: String,
    server_name: &'a str,
    service_id: &'a str,
    request: &'a str,
}

pub(super) async fn run() -> Result<()> {
    const MAX_INPUT: u64 = 256 << 10;
    let mut input = Zeroizing::new(Vec::new());
    io::stdin().take(MAX_INPUT + 1).read_to_end(&mut input)?;
    ensure!(
        input.len() as u64 <= MAX_INPUT,
        "enrollment input exceeds 256 KiB"
    );
    let input: Input<'_> =
        serde_json::from_slice(&input).context("decode native enrollment input")?;
    let body = Zeroizing::new(
        STANDARD
            .decode(input.request)
            .context("decode enrollment frame")?,
    );
    let request = EnrollmentRequest::decode(body.as_slice()).context("parse enrollment request")?;
    ensure!(
        matches!(
            EnrollmentClass::try_from(request.expected_enrollment_class),
            Ok(EnrollmentClass::RememberedUser
                | EnrollmentClass::EphemeralUser
                | EnrollmentClass::DurableNode)
        ),
        "a supported enrollment class is required"
    );
    let service = input
        .service_id
        .parse::<Id>()
        .context("invalid controller identity")?;
    let response = crate::rootless_cli::enroll::submit_enrollment(
        input.endpoint,
        input.ca_pem.as_bytes(),
        input.server_name,
        service,
        request,
    )
    .await?;
    io::stdout().lock().write_all(&response.encode_to_vec())?;
    Ok(())
}
