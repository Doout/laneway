use crate::{
    SessionError, SessionStore, check_snapshot,
    sessions::{csrf_digest, session_digest},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::Transaction;
use rusqlite::{OptionalExtension, TransactionBehavior};
use std::collections::HashSet;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct IssuedSession {
    pub view: serde_json::Value,
    pub token: Zeroizing<String>,
    pub csrf: Zeroizing<String>,
    pub id: Id,
    pub idle: i64,
    pub absolute: i64,
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut v = Zeroizing::new([0; N]);
    getrandom::fill(&mut *v)
        .map_err(|_| anyhow::anyhow!("unable to generate administrator session secrets"))?;
    Ok(v)
}

fn revoke(
    tx: &Transaction<'_>,
    id: Id,
    actor: Option<Id>,
    action: &str,
    reason: &str,
    at: i64,
) -> Result<()> {
    ensure!(tx.execute("UPDATE administrator_sessions SET revoked_at=?1,revocation_reason=?2 WHERE id=?3 AND revoked_at IS NULL",(at,reason,id.as_bytes()))?==1,"administrator revocation failed");
    audit(
        tx,
        id,
        actor,
        action,
        serde_json::json!({"reason":reason}),
        at,
    )
}
fn audit(
    tx: &Transaction<'_>,
    id: Id,
    actor: Option<Id>,
    action: &str,
    detail: serde_json::Value,
    at: i64,
) -> Result<()> {
    let kind = if actor.is_some() {
        "administrator"
    } else {
        "system"
    };
    tx.execute("INSERT INTO audit_events(id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
        VALUES(randomblob(16),?1,?2,?3,'administrator_session',?4,?5,?6)",(kind,actor.as_ref().map(Id::as_bytes),action,id.as_bytes(),detail.to_string(),at))?;
    Ok(())
}

struct Policy {
    idle_lifetime: i64,
    cap: u8,
    absolute: i64,
    previous: Option<Id>,
}
fn issue(
    tx: &Transaction<'_>,
    owner: Id,
    credential: Id,
    all: bool,
    now: i64,
    policy: Policy,
) -> Result<IssuedSession> {
    ensure!(
        (1..=20).contains(&policy.cap)
            && (60..=86400).contains(&policy.idle_lifetime)
            && policy.absolute > now,
        SessionError::Invalid
    );
    let mut statement=tx.prepare("SELECT id,max(created_at,last_seen_at),min(idle_expires_at,absolute_expires_at) FROM administrator_sessions WHERE principal_id=? AND revoked_at IS NULL ORDER BY created_at,id")?;
    let mut live = Vec::new();
    let rows = statement
        .query_map([owner.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (raw, floor, expires) in rows {
        let id = Id::new(raw)?;
        if now >= expires {
            revoke(
                tx,
                id,
                None,
                "administrator.session.expire",
                "expired",
                now.max(floor),
            )?
        } else {
            live.push((id, now.max(floor)))
        }
    }
    for &(id, at) in live
        .iter()
        .take(live.len().saturating_sub(usize::from(policy.cap) - 1))
    {
        revoke(
            tx,
            id,
            Some(owner),
            "administrator.session.revoke",
            "concurrent session limit",
            at,
        )?
    }
    let id = Id::new(*random::<16>()?)?;
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(random::<32>()?.as_slice()));
    let csrf = Zeroizing::new(URL_SAFE_NO_PAD.encode(random::<32>()?.as_slice()));
    let idle = (now + policy.idle_lifetime).min(policy.absolute);
    tx.execute("INSERT INTO administrator_sessions(id,principal_id,credential_id,token_hash,csrf_hash,previous_session_id,created_at,last_seen_at,idle_lifetime_seconds,maximum_sessions,idle_expires_at,absolute_expires_at)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?7,?8,?9,?10,?11)",rusqlite::params![id.as_bytes(),owner.as_bytes(),credential.as_bytes(),session_digest(&token)?,csrf_digest(&csrf)?,policy.previous.as_ref().map(Id::as_bytes),now,policy.idle_lifetime,policy.cap,idle,policy.absolute])?;
    audit(
        tx,
        id,
        Some(owner),
        if policy.previous.is_some() {
            "administrator.session.rotate"
        } else {
            "administrator.login"
        },
        serde_json::json!({}),
        now,
    )?;
    let mut view = crate::browser::session_view(tx, owner, id, all, Some(&csrf))?;
    view["idle_expires_at_unix_seconds"] = idle.into();
    view["absolute_expires_at_unix_seconds"] = policy.absolute.into();
    Ok(IssuedSession {
        view,
        token,
        csrf,
        id,
        idle,
        absolute: policy.absolute,
    })
}

impl SessionStore {
    pub fn reject_active_login_cookie(&mut self, token: &str) -> Result<()> {
        match self.with_session(token, false, |_, _, _, _, _| Ok(())) {
            Ok(_) => Err(SessionError::Invalid.into()),
            Err(e)
                if matches!(
                    e.downcast_ref::<SessionError>(),
                    Some(SessionError::Expired | SessionError::Invalid)
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    pub fn issue_after_password(
        &mut self,
        candidate: crate::password::VerifiedPassword,
    ) -> Result<IssuedSession> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let owner = candidate.principal_id();
        let cred = candidate.credential_id();
        // The expensive verifier ran outside this transaction. Re-read the
        // very same immutable credential and principal before issuing secrets.
        let all: bool = tx
            .query_row(
                "SELECT p.all_networks FROM administrator_principals p
            JOIN administrator_credentials c ON c.principal_id=p.id
            WHERE p.id=?1 AND c.id=?2 AND c.credential_type='password' AND c.revoked_at IS NULL
            AND p.enabled=1 AND p.disabled_at IS NULL",
                (owner.as_bytes(), cred.as_bytes()),
                |r| r.get(0),
            )
            .optional()?
            .ok_or(SessionError::Invalid)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let s = issue(
            &tx,
            owner,
            cred,
            all,
            now,
            Policy {
                idle_lifetime: 1800,
                absolute: now + 28800,
                cap: 5,
                previous: None,
            },
        )?;
        tx.commit()?;
        Ok(s)
    }
    pub fn audit_login_failure(&mut self, busy: bool) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let reason = if busy {
            "verification_busy"
        } else {
            "credential_rejected"
        };
        tx.execute("INSERT INTO audit_events(id,actor_kind,action,target_type,details_json,created_at)
            VALUES(randomblob(16),'unauthenticated','administrator.login.failure','administrator_authentication',?1,unixepoch())",[serde_json::json!({"reason":reason}).to_string()])?;
        tx.commit()?;
        Ok(())
    }
    /// None means that the HTTP layer could not verify the origin or the
    /// CSRF cookie/header pair. Session validation still precedes denial.
    pub fn rotate(&mut self, token: &str, csrf: Option<&str>) -> Result<IssuedSession> {
        Ok(self.with_session(token,false,|tx,owner,previous,all,now|{
            let proof=csrf_digest(csrf.ok_or(SessionError::Denied)?).map_err(|_|SessionError::Denied)?;
            let (expected,cred,idle_lifetime,cap,absolute):([u8;32],[u8;16],i64,u8,i64)=tx.query_row(
                "SELECT csrf_hash,credential_id,idle_lifetime_seconds,maximum_sessions,absolute_expires_at FROM administrator_sessions WHERE id=?1",
                [previous.as_bytes()], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
            ensure!(bool::from(proof.ct_eq(&expected)), SessionError::Denied);
            revoke(tx,previous,Some(owner),"administrator.session.revoke","rotated",now)?;
            issue(tx,owner,Id::new(cred)?,all,now,Policy{idle_lifetime,cap,absolute,previous:Some(previous)})
        })?.list)
    }
    /// A logout can reach the controller just after rotation. Authenticate
    /// the original cookie pair and revoke all its live successors atomically.
    pub fn logout(&mut self, token: &str, csrf: &str) -> Result<()> {
        let digest = session_digest(token)?;
        let proof = csrf_digest(csrf)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let (start,owner,expected,revoked,reason):([u8;16],[u8;16],[u8;32],Option<i64>,String)=tx.query_row(
            "SELECT id,principal_id,csrf_hash,revoked_at,revocation_reason FROM administrator_sessions WHERE token_hash=?1",[digest],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?.ok_or(SessionError::Invalid)?;
        let owner = Id::new(owner)?;
        ensure!(
            bool::from(expected.ct_eq(&proof)) && (revoked.is_none() || reason == "rotated"),
            SessionError::Invalid
        );
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let mut current = Some(Id::new(start)?);
        let mut seen = HashSet::new();
        while let Some(id) = current {
            ensure!(
                seen.insert(id),
                "corrupt administrator session rotation cycle"
            );
            let (principal,revoked,floor):([u8;16],Option<i64>,i64)=tx.query_row(
                "SELECT principal_id,revoked_at,max(created_at,last_seen_at) FROM administrator_sessions WHERE id=?1",
                [id.as_bytes()], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            ensure!(
                owner.as_bytes() == &principal,
                "corrupt administrator session rotation family"
            );
            if revoked.is_none() {
                let at = now.max(floor);
                revoke(&tx, id, Some(owner), "administrator.logout", "logout", at)?;
            }
            current = tx
                .query_row(
                    "SELECT id FROM administrator_sessions WHERE previous_session_id=?1",
                    [id.as_bytes()],
                    |r| r.get::<_, [u8; 16]>(0),
                )
                .optional()?
                .map(Id::new)
                .transpose()?;
        }
        tx.commit()?;
        Ok(())
    }
}
