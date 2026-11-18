//! Authorization and audit for ephemeral bootstrap capabilities. Payloads
//! belong to the listener, not the durable controller database.
use crate::{
    RootCredential, SessionReply, SessionStore, management_write::verify_browser_write,
    recovery::AuditActor,
};
use anyhow::{Result, ensure};
use rusqlite::Transaction;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("bootstrap payload must be a bounded bash script")]
    Payload,
    #[error("bootstrap expiry must be within 10 minutes")]
    Expiry,
}

pub const PUBLIC_PATH: &str = "/.well-known/laneway/bootstrap/";

pub fn valid_id(id: &str) -> bool {
    id.len() == 43
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub fn validate(payload: &str, expires: i64, now: i64) -> Result<()> {
    ensure!(
        payload.len() <= 96 * 1024
            && payload.starts_with("#!/bin/bash\n")
            && !payload.contains('\0'),
        BundleError::Payload
    );
    ensure!(
        expires > now && expires <= now.saturating_add(600),
        BundleError::Expiry
    );
    Ok(())
}

impl SessionStore {
    pub fn stage_bootstrap_bundle<T>(
        &mut self,
        token: &str,
        csrf: Option<&str>,
        stage: impl FnOnce(i64) -> Result<T>,
    ) -> Result<SessionReply<T>> {
        self.with_session(token, false, |tx, actor, session, _, now| {
            verify_browser_write(tx, session, csrf, false)?;
            audited(
                tx,
                AuditActor("administrator", Some(*actor.as_bytes())),
                now,
                stage,
            )
        })
    }

    pub fn bearer_stage_bootstrap_bundle<T>(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        stage: impl FnOnce(i64) -> Result<T>,
    ) -> Result<T> {
        self.bearer_write(header, root, |tx, actor, now| {
            actor.authorize(tx, "bootstrap_bundle.create", None)?;
            audited(
                tx,
                AuditActor("service_principal", Some(*actor.id.as_bytes())),
                now,
                stage,
            )
        })
    }
}

fn audited<T>(
    tx: &Transaction<'_>,
    actor: AuditActor,
    now: i64,
    stage: impl FnOnce(i64) -> Result<T>,
) -> Result<T> {
    let value = stage(now)?;
    actor.write(
        tx,
        "bootstrap_bundle.create",
        "bootstrap_bundle",
        None,
        json!({"storage":"ephemeral"}),
        now,
    )?;
    Ok(value)
}
