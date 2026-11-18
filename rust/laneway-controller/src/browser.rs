//! Browser discovery response data. The advertised permissions are for
//! presentation; they never authorize an operation on their own.
use crate::{SessionError, check_snapshot, open_existing};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{OpenFlags, Transaction};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub fn auth_state(database: &Path) -> Result<&'static str> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    let (root,owner,completed,generation): ([u8;16],Option<[u8;16]>,Option<i64>,i64) =
        tx.query_row("SELECT root_service_principal_id,initial_owner_principal_id,bootstrap_completed_at,recovery_generation FROM administrator_auth_state WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    Id::new(root)?;
    let owner = owner.map(Id::new).transpose()?;
    ensure!(
        generation >= 0 && owner.is_some() == completed.is_some(),
        "invalid administrator bootstrap state"
    );
    tx.commit()?;
    Ok(if owner.is_some() {
        "sign_in"
    } else {
        "bootstrap_required"
    })
}

// Keep the order of adminauth.Permissions, including the application grants.
const PERMISSIONS: &[(&str, u8)] = &[
    ("network.list", 3),
    ("network.read", 3),
    ("network.create", 1),
    ("enrollment.issue", 2),
    ("bootstrap_bundle.create", 1),
    ("node.read", 3),
    ("node.manage", 2),
    ("route.read", 3),
    ("route.manage", 2),
    ("acl.read", 3),
    ("acl.manage", 2),
    ("relay.read", 3),
    ("relay.manage", 2),
    ("certificate.read", 3),
    ("certificate.revoke", 2),
    ("audit.read", 3),
    ("audit.read_global", 1),
    ("principal.manage", 1),
    ("session.manage_others", 1),
    ("service_principal.manage", 1),
    ("application.read", 1),
    ("application.manage", 1),
    ("application_installation.read", 3),
    ("application_installation.manage", 2),
];

pub(super) fn session_view(
    tx: &Transaction<'_>,
    principal: Id,
    session: Id,
    all: bool,
    csrf: Option<&str>,
) -> Result<Value> {
    let csrf = csrf.ok_or(SessionError::Invalid)?;
    let mut raw = Zeroizing::new([0u8; 32]);
    ensure!(
        csrf.len() == 43 && URL_SAFE_NO_PAD.decode_slice(csrf, &mut *raw) == Ok(32),
        SessionError::Invalid
    );
    let (username,role,expected,lifetime):(String,String,[u8;32],i64) =
      tx.query_row("SELECT p.username,p.role,s.csrf_hash,s.idle_lifetime_seconds FROM administrator_principals p JOIN administrator_sessions s ON s.principal_id=p.id WHERE p.id=?1 AND s.id=?2",(principal.as_bytes(),session.as_bytes()),|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    let got = Sha256::new()
        .chain_update(b"laneway-admin-csrf-v1\0")
        .chain_update(csrf.as_bytes())
        .finalize();
    ensure!(bool::from(expected.ct_eq(&got)), SessionError::Invalid);
    let rank = match role.as_str() {
        "owner" => 1,
        "operator" => 2,
        "auditor" => 3,
        _ => return Err(SessionError::Invalid.into()),
    };
    let permissions: Vec<_> = PERMISSIONS
        .iter()
        .filter(|(_, r)| *r >= rank)
        .map(|(op, _)| *op)
        .collect();
    let mut stmt = tx.prepare("SELECT network_id FROM administrator_principal_networks WHERE principal_id=?1 ORDER BY network_id")?;
    let ids = stmt
        .query_map([principal.as_bytes()], |r| r.get::<_, [u8; 16]>(0))?
        .map(|row| Ok(Id::new(row?)?.to_string()))
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"principal_id":principal.to_string(),"username":username,"role":role,"permissions":permissions,
        "all_networks":all,"network_ids":ids,"session_id":session.to_string(),"idle_lifetime_seconds":lifetime,"csrf_token":csrf}),
    )
}
