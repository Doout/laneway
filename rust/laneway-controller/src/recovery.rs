//! Go-compatible one-time administrator grants. Candidate validation is cheap;
//! redemption rechecks under a write lock after the password work finishes.
use crate::{
    RootCredential, SessionError, SessionStore, check_snapshot, password::PasswordHash,
    sessions::secret_digest,
};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub enum Purpose {
    Bootstrap,
    Owner,
}

impl Purpose {
    fn key(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap_owner",
            Self::Owner => "owner_recovery",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("administrator bootstrap is already complete")]
    BootstrapComplete,
    #[error("administrator not found")]
    Missing,
    #[error("administrator recovery write conflict")]
    Conflict,
}

pub struct IssuedGrant {
    pub secret: Zeroizing<String>,
    pub expires: i64,
}

pub struct Candidate {
    digest: [u8; 32],
    purpose: Purpose,
}

type RawId = [u8; 16];

struct Grant {
    id: RawId,
    generation: i64,
    target: Option<RawId>,
}

fn digest(secret: &str) -> Result<[u8; 32], SessionError> {
    secret_digest(b"laneway-admin-recovery-v1\0", secret)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| anyhow!("administrator randomness unavailable"))?;
    Ok(bytes)
}

pub fn valid_username(username: &str) -> bool {
    (3..=64).contains(&username.len())
        && username.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || (i > 0 && i + 1 < username.len() && matches!(b, b'.' | b'_' | b'-'))
        })
}

struct AuditActor(&'static str, Option<RawId>);

impl AuditActor {
    fn write(
        &self,
        tx: &Transaction<'_>,
        action: &str,
        kind: &str,
        target: Option<RawId>,
        details: Value,
        now: i64,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO audit_events(id,actor_id,actor_kind,action,target_type,target_id,details_json,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![random::<16>()?, self.1, self.0, action, kind, target, details.to_string(), now],
        )?;
        Ok(())
    }
}

fn revoke_grant(
    tx: &Transaction<'_>,
    actor: &AuditActor,
    grant: RawId,
    reason: &str,
    now: i64,
) -> Result<()> {
    ensure!(
        tx.execute(
            "UPDATE administrator_recovery_grants SET revoked_at=?2,revocation_reason=?3
             WHERE id=?1 AND consumed_at IS NULL AND revoked_at IS NULL",
            params![grant, now, reason],
        )? == 1,
        RecoveryError::Conflict
    );
    actor.write(
        tx,
        "administrator.recovery.revoke",
        "administrator_recovery_grant",
        Some(grant),
        json!({"reason": reason}),
        now,
    )
}

fn eligible(tx: &Transaction<'_>, candidate: &Candidate, now: i64) -> Result<Grant> {
    tx.query_row(
        "SELECT g.id,g.recovery_generation,g.target_principal_id
         FROM administrator_recovery_grants g
         JOIN administrator_auth_state s ON s.singleton=1 AND s.recovery_generation=g.recovery_generation
         LEFT JOIN administrator_principals p ON p.id=g.target_principal_id
         WHERE g.secret_hash=?1 AND g.purpose=?2
           AND g.consumed_at IS NULL AND g.revoked_at IS NULL AND g.created_at<=?3 AND g.expires_at>?3
           AND ((g.purpose='bootstrap_owner' AND g.target_principal_id IS NULL
                 AND s.initial_owner_principal_id IS NULL AND s.bootstrap_completed_at IS NULL)
             OR (g.purpose='owner_recovery' AND p.role='owner'))",
        params![candidate.digest, candidate.purpose.key(), now],
        |r| Ok(Grant { id: r.get(0)?, generation: r.get(1)?, target: r.get(2)? }),
    )
    .optional()?
    .ok_or_else(|| SessionError::Invalid.into())
}

fn insert_password(
    tx: &Transaction<'_>,
    principal: RawId,
    hash: &PasswordHash,
    now: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO administrator_credentials(id,principal_id,credential_type,secret_hash,created_at)
         VALUES(?1,?2,'password',?3,?4)",
        params![random::<16>()?, principal, hash.encoded(), now],
    )?;
    Ok(())
}

fn consume(tx: &Transaction<'_>, grant: &Grant, now: i64) -> Result<()> {
    ensure!(
        tx.execute(
            "UPDATE administrator_recovery_grants SET consumed_at=?2
             WHERE id=?1 AND consumed_at IS NULL AND revoked_at IS NULL",
            params![grant.id, now],
        )? == 1,
        SessionError::Invalid
    );
    Ok(())
}

fn bootstrap(
    tx: &Transaction<'_>,
    grant: &Grant,
    username: &str,
    hash: &PasswordHash,
    now: i64,
) -> Result<()> {
    ensure!(valid_username(username), "invalid administrator username");
    let duplicate: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM administrator_principals WHERE username=?1)",
        [username],
        |r| r.get(0),
    )?;
    ensure!(!duplicate, RecoveryError::Conflict);
    let principal = random::<16>()?;
    tx.execute(
        "INSERT INTO administrator_principals(id,username,role,all_networks,enabled,created_at,updated_at)
         VALUES(?1,?2,'owner',1,1,?3,?3)",
        params![principal, username, now],
    )?;
    insert_password(tx, principal, hash, now)?;
    consume(tx, grant, now)?;
    tx.execute(
        "UPDATE administrator_auth_state SET initial_owner_principal_id=?1,bootstrap_completed_at=?2
         WHERE singleton=1",
        params![principal, now],
    )?;
    AuditActor("recovery_grant", Some(grant.id)).write(
        tx,
        "administrator.bootstrap.complete",
        "administrator",
        Some(principal),
        json!({}),
        now,
    )
}

fn timed_rows(tx: &Transaction<'_>, sql: &str, key: RawId) -> Result<Vec<(RawId, i64)>> {
    Ok(tx
        .prepare(sql)?
        .query_map([key], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?)
}

fn recover(tx: &Transaction<'_>, grant: &Grant, hash: &PasswordHash, now: i64) -> Result<()> {
    let owner = grant.target.ok_or(SessionError::Invalid)?;
    let updated: i64 = tx.query_row(
        "SELECT max(created_at,updated_at) FROM administrator_principals WHERE id=?1",
        [owner],
        |r| r.get(0),
    )?;
    let credentials = timed_rows(tx, "SELECT id,created_at FROM administrator_credentials
        WHERE principal_id=?1 AND credential_type='password' AND revoked_at IS NULL ORDER BY created_at,id", owner)?;
    let sessions = timed_rows(
        tx,
        "SELECT id,max(created_at,last_seen_at) FROM administrator_sessions
        WHERE principal_id=?1 AND revoked_at IS NULL ORDER BY created_at,id",
        owner,
    )?;
    let stale = timed_rows(
        tx,
        "SELECT id,created_at FROM administrator_recovery_grants
        WHERE id<>?1 AND consumed_at IS NULL AND revoked_at IS NULL ORDER BY created_at,id",
        grant.id,
    )?;
    // A wall-clock rollback must not backdate revocation or create an
    // impossible timeline. Grant consumption still uses its validated time.
    let at = credentials
        .iter()
        .chain(&sessions)
        .chain(&stale)
        .map(|(_, at)| *at)
        .fold(now.max(updated), i64::max);
    let actor = AuditActor("recovery_grant", Some(grant.id));
    for (id, _) in credentials {
        tx.execute(
            "UPDATE administrator_credentials SET revoked_at=?2,revocation_reason='owner recovery'
            WHERE id=?1",
            params![id, at],
        )?;
        actor.write(
            tx,
            "administrator.credential.revoke",
            "administrator_credential",
            Some(id),
            json!({"reason": "owner recovery"}),
            at,
        )?;
    }
    for (id, _) in sessions {
        tx.execute(
            "UPDATE administrator_sessions SET revoked_at=?2,revocation_reason='owner recovery'
            WHERE id=?1",
            params![id, at],
        )?;
        actor.write(
            tx,
            "administrator.session.revoke",
            "administrator_session",
            Some(id),
            json!({"reason": "owner recovery"}),
            at,
        )?;
    }
    insert_password(tx, owner, hash, at)?;
    tx.execute(
        "UPDATE administrator_principals SET enabled=1,disabled_at=NULL,updated_at=?2
        WHERE id=?1",
        params![owner, at],
    )?;
    consume(tx, grant, now)?;
    for (id, _) in stale {
        revoke_grant(tx, &actor, id, "recovery generation advanced", at)?;
    }
    ensure!(tx.execute(
        "UPDATE administrator_auth_state SET recovery_generation=recovery_generation+1,last_recovered_at=?1
         WHERE singleton=1 AND recovery_generation=?2",
        params![at, grant.generation],
    )? == 1, SessionError::Invalid);
    actor.write(
        tx,
        "administrator.recovery.complete",
        "administrator",
        Some(owner),
        json!({}),
        at,
    )
}

impl SessionStore {
    pub fn issue_recovery_grant(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        target: Option<Id>,
    ) -> Result<IssuedGrant> {
        self.root_write(header, root, |tx, principal, now| {
            let (generation, bootstrapped): (i64, bool) = tx.query_row(
                "SELECT recovery_generation,initial_owner_principal_id IS NOT NULL
                 FROM administrator_auth_state WHERE singleton=1",
                [], |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let (purpose, target) = if let Some(target) = target {
                let role: String = tx.query_row("SELECT role FROM administrator_principals WHERE id=?1",
                    [target.as_bytes()], |r| r.get(0)).optional()?.ok_or(RecoveryError::Missing)?;
                ensure!(role == "owner", SessionError::Invalid);
                (Purpose::Owner, Some(*target.as_bytes()))
            } else {
                ensure!(!bootstrapped, RecoveryError::BootstrapComplete);
                (Purpose::Bootstrap, None)
            };
            let actor = AuditActor("service_principal", Some(*principal.as_bytes()));
            let superseded = tx.prepare(
                "SELECT id,created_at,expires_at<=?3 FROM administrator_recovery_grants
                 WHERE consumed_at IS NULL AND revoked_at IS NULL
                   AND ((purpose=?1 AND target_principal_id IS ?2) OR expires_at<=?3)
                 ORDER BY created_at,id",
            )?.query_map(params![purpose.key(), target, now],
                |r| Ok((r.get::<_, RawId>(0)?, r.get::<_, i64>(1)?, r.get::<_, bool>(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (grant, created, expired) in superseded {
                revoke_grant(tx, &actor, grant, if expired {"expired"} else {"superseded"}, now.max(created))?;
            }
            let random_secret = Zeroizing::new(random::<32>()?);
            let secret = Zeroizing::new(URL_SAFE_NO_PAD.encode(random_secret.as_slice()));
            let id = random::<16>()?;
            let expires = now + 600;
            tx.execute(
                "INSERT INTO administrator_recovery_grants
                 (id,secret_hash,purpose,target_principal_id,recovery_generation,created_at,expires_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![id, digest(&secret)?, purpose.key(), target, generation, now, expires],
            )?;
            actor.write(tx, "administrator.recovery.issue", "administrator_recovery_grant",
                Some(id), json!({"purpose": purpose.key()}), now)?;
            Ok(IssuedGrant { secret, expires })
        })
    }

    pub fn recovery_candidate(&mut self, secret: &str, purpose: Purpose) -> Result<Candidate> {
        let candidate = Candidate {
            digest: digest(secret)?,
            purpose,
        };
        let tx = self.db.transaction()?;
        check_snapshot(&tx)?;
        let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        eligible(&tx, &candidate, now)?;
        tx.commit()?;
        Ok(candidate)
    }

    pub fn redeem_recovery(
        &mut self,
        candidate: Candidate,
        username: &str,
        hash: PasswordHash,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let grant = eligible(&tx, &candidate, now)?;
        match candidate.purpose {
            Purpose::Bootstrap => bootstrap(&tx, &grant, username, &hash, now)?,
            Purpose::Owner => recover(&tx, &grant, &hash, now)?,
        }
        tx.commit()?;
        Ok(())
    }

    pub fn audit_recovery_failure(&mut self, busy: bool) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        AuditActor("unauthenticated", None).write(
            &tx,
            if busy {
                "administrator.login.failure"
            } else {
                "administrator.recovery.failure"
            },
            "administrator_authentication",
            None,
            json!({"reason": if busy { "verification_busy" } else { "recovery_rejected" }}),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
}
