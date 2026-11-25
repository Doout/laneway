use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::{Id, v1::ErrorCode};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::store::Store;

use super::{
    AuditActor, EXIT_NODE, EnrollmentError, SUBNET_ROUTER, audit, clock, random_bytes, random_id,
    valid_name,
};

const MAX_TOKEN_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct IssueRequest {
    network_id: String,
    label: String,
    expires_at_unix_seconds: i64,
    enrollment_class: String,
    session_lifetime_seconds: i64,
    requested_name: String,
    enabled_capabilities: u64,
}

#[derive(Serialize)]
pub(crate) struct IssuedToken {
    token_id: String,
    enrollment_token: String,
    expires_at_unix_seconds: i64,
    enrollment_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_lifetime_seconds: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    requested_name: String,
    #[serde(skip_serializing_if = "is_zero")]
    enabled_capabilities: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Drop for IssuedToken {
    fn drop(&mut self) {
        self.enrollment_token.zeroize();
    }
}

/// The HTTP layer authenticates the root bearer; this rechecks its durable
/// service principal inside the same transaction that will issue the token.
pub(crate) fn issue_token(
    store: &mut Store,
    principal: Id,
    request: IssueRequest,
    canceled: &AtomicBool,
) -> Result<IssuedToken, EnrollmentError> {
    let network: Id = request
        .network_id
        .parse()
        .map_err(|_| EnrollmentError::malformed("invalid network_id"))?;
    let class = match request.enrollment_class.as_str() {
        "" | "durable" => "durable",
        "remembered" => "remembered",
        "ephemeral" => "ephemeral",
        _ => return Err(EnrollmentError::malformed("invalid request")),
    };
    let seconds = request.session_lifetime_seconds;
    let lifetime = if class == "ephemeral" {
        if !(300..=86400).contains(&seconds) {
            return Err(EnrollmentError::malformed("invalid request"));
        }
        Some(seconds)
    } else {
        if seconds != 0 {
            return Err(EnrollmentError::malformed("invalid request"));
        }
        None
    };
    if request.label.len() > 256
        || request.label.trim() != request.label
        || request.label.contains('\0')
        || (!request.requested_name.is_empty() && !valid_name(&request.requested_name))
        || request.enabled_capabilities & !((SUBNET_ROUTER | EXIT_NODE) as u64) != 0
    {
        return Err(EnrollmentError::malformed("invalid request"));
    }

    let tx = store.enrollment_transaction()?;
    let active_principal: Vec<u8> = tx.query_row(
        "SELECT root_service_principal_id FROM administrator_auth_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if Id::from_slice(&active_principal).context("invalid root service principal")? != principal {
        return Err(EnrollmentError::invalid_token());
    }
    let now = clock()?;
    if !request
        .expires_at_unix_seconds
        .checked_sub(now)
        .is_some_and(|seconds| (1..=MAX_TOKEN_SECONDS).contains(&seconds))
    {
        return Err(EnrollmentError::malformed("invalid request"));
    }
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
        [network.as_bytes()],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(EnrollmentError::new(
            404,
            ErrorCode::Malformed,
            "record not found",
        ));
    }

    let key = Zeroizing::new(random_bytes::<32>()?);
    let digest: [u8; 32] = Sha256::digest(key.as_slice()).into();
    let id = random_id()?;
    let name = (!request.requested_name.is_empty()).then_some(request.requested_name.as_str());
    tx.execute(
        "INSERT INTO enrollment_tokens
          (id,network_id,token_hash,label,expires_at,created_at,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![id.as_bytes(), network.as_bytes(), digest, request.label, request.expires_at_unix_seconds,
            now, class, lifetime, name, request.enabled_capabilities],
    )?;
    let mut details = serde_json::json!({
        "enrollment_class": class,
        "requested_name": request.requested_name,
        "enabled_capabilities": request.enabled_capabilities,
    });
    if let Some(seconds) = lifetime {
        details["session_lifetime_seconds"] = serde_json::json!(seconds);
    }
    audit(
        &tx,
        network,
        AuditActor::ServicePrincipal(principal),
        "enrollment_token.issue",
        "enrollment_token",
        id,
        &details.to_string(),
        now,
    )?;
    if canceled.load(Ordering::Acquire) {
        return Err(anyhow::anyhow!("enrollment token request canceled").into());
    }
    tx.commit()?;
    Ok(IssuedToken {
        token_id: id.to_string(),
        enrollment_token: URL_SAFE_NO_PAD.encode(key.as_slice()),
        expires_at_unix_seconds: request.expires_at_unix_seconds,
        enrollment_class: class.to_owned(),
        session_lifetime_seconds: lifetime,
        requested_name: request.requested_name,
        enabled_capabilities: request.enabled_capabilities,
    })
}
