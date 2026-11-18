//! Transactional redemption, rotation and revocation for application credentials.
use super::{
    authorization::installation_scopes,
    secrets::{Purpose, id, matches_pkce, new_secret, parse_secret, random},
};
use crate::{
    Network, SessionError, SessionStore, bearer::automation_digest, check_snapshot, read_network,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const ACCESS_SECONDS: i64 = 3600;
const REFRESH_SECONDS: i64 = 30 * 86400;
const REUSE_GRACE_SECONDS: i64 = 5;

pub struct Client {
    app: Id,
    credential: Id,
    digest: [u8; 32],
}

impl Client {
    pub fn from_basic(client_id: &str, secret: &str) -> Option<Self> {
        let app = client_id.strip_prefix("lnw_client_v1.")?.parse().ok()?;
        let (credential, digest) = parse_secret(Purpose::Client, secret)?;
        Some(Self {
            app,
            credential,
            digest,
        })
    }

    fn check(&self, tx: &Transaction<'_>) -> Result<()> {
        let stored: [u8; 32] = tx
            .query_row(
                "SELECT c.secret_hash FROM registered_application_credentials c
             JOIN registered_applications a ON a.id=c.application_id
             WHERE a.id=?1 AND a.client_id=?2 AND a.enabled=1 AND c.id=?3 AND c.revoked_at IS NULL",
                params![
                    self.app.as_bytes(),
                    format!("lnw_client_v1.{}", self.app),
                    self.credential.as_bytes()
                ],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(SessionError::Invalid)?;
        ensure!(
            bool::from(stored.ct_eq(&self.digest)),
            SessionError::Invalid
        );
        Ok(())
    }
}

pub struct Grant {
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    installation: Installation,
    network: Network,
}

impl Grant {
    pub fn encode(&self) -> serde_json::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Install<'a> {
            installation_id: String,
            application_id: String,
            network: &'a Network,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            access_token: &'a str,
            refresh_token: &'a str,
            token_type: &'static str,
            expires_in: i64,
            scope: String,
            installation: Install<'a>,
        }
        serde_json::to_vec(&Wire {
            access_token: &self.access,
            refresh_token: &self.refresh,
            token_type: "Bearer",
            expires_in: ACCESS_SECONDS,
            scope: self.installation.scopes.join(" "),
            installation: Install {
                installation_id: self.installation.id.to_string(),
                application_id: self.installation.app.to_string(),
                network: &self.network,
            },
        })
    }
}

struct Installation {
    id: Id,
    app: Id,
    network: Id,
    principal: Id,
    scopes: Vec<String>,
    enabled: bool,
}

fn installation(tx: &Transaction<'_>, id: Id) -> Result<Installation> {
    let (app,network,principal,enabled):([u8;16],[u8;16],[u8;16],bool)=tx.query_row(
        "SELECT application_id,network_id,service_principal_id,enabled FROM application_installations WHERE id=?1",
        [id.as_bytes()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).optional()?.ok_or(SessionError::Invalid)?;
    Ok(Installation {
        id,
        app: Id::new(app)?,
        network: Id::new(network)?,
        principal: Id::new(principal)?,
        scopes: installation_scopes(tx, id)?,
        enabled,
    })
}

impl Installation {
    fn verify(&self, tx: &Transaction<'_>, app: Id) -> Result<()> {
        ensure!(
            self.app == app && self.enabled && !self.scopes.is_empty(),
            SessionError::Invalid
        );
        let valid:bool=tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM automation_service_principals p
                WHERE p.id=?1 AND p.enabled=1 AND p.disabled_at IS NULL AND p.all_networks=0
                AND EXISTS(SELECT 1 FROM automation_service_principal_networks n WHERE n.principal_id=p.id AND n.network_id=?2)
                AND NOT EXISTS(SELECT 1 FROM automation_service_principal_networks n WHERE n.principal_id=p.id AND n.network_id<>?2))",
            params![self.principal.as_bytes(),self.network.as_bytes()],|r|r.get(0),
        )?;
        ensure!(valid, SessionError::Invalid);
        let permissions=tx.prepare(
            "SELECT operation FROM automation_service_principal_permissions WHERE principal_id=?1 ORDER BY operation",
        )?.query_map([self.principal.as_bytes()],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(permissions == self.scopes, SessionError::Invalid);
        Ok(())
    }
}

struct Code {
    installation: Id,
    app: Id,
    network: Id,
    redirect: String,
    scopes: String,
    hash: [u8; 32],
    challenge: String,
}

struct Refresh {
    family: Id,
    family_app: Id,
    installation: Id,
    hash: [u8; 32],
    access: Option<[u8; 16]>,
    created: i64,
    expires: i64,
    consumed: Option<i64>,
    family_created: i64,
    family_expires: i64,
    retired: bool,
}

fn refresh(tx: &Transaction<'_>, id: Id) -> Result<Option<Refresh>> {
    let row=tx.query_row(
        "SELECT t.family_id,f.application_id,f.installation_id,t.token_hash,t.access_token_id,
                t.created_at,t.expires_at,t.consumed_at,f.created_at,f.expires_at,f.revoked_at IS NOT NULL
         FROM application_refresh_tokens t JOIN application_refresh_token_families f ON f.id=t.family_id WHERE t.id=?1",
        [id.as_bytes()],|r|Ok((
            r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,
            r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,
        )),
    ).optional()?;
    row.map(
        |(
            family,
            app,
            installation,
            hash,
            access,
            created,
            expires,
            consumed,
            family_created,
            family_expires,
            retired,
        )| {
            Ok(Refresh {
                family: Id::new(family)?,
                family_app: Id::new(app)?,
                installation: Id::new(installation)?,
                hash,
                access,
                created,
                expires,
                consumed,
                family_created,
                family_expires,
                retired,
            })
        },
    )
    .transpose()
}

impl SessionStore {
    pub fn check_application_client(&mut self, client: &Client) -> Result<()> {
        let tx = self.db.transaction()?;
        check_snapshot(&tx)?;
        client.check(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub fn exchange_application_code(
        &mut self,
        client: &Client,
        code: &str,
        verifier: &str,
        redirect: &str,
    ) -> Result<Grant> {
        let (id, candidate) =
            parse_secret(Purpose::Authorization, code).ok_or(SessionError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        client.check(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let row=tx.query_row(
            "SELECT installation_id,application_id,network_id,redirect_uri,scopes_json,code_hash,pkce_challenge
             FROM application_authorization_codes WHERE id=?1 AND consumed_at IS NULL AND created_at<=?2 AND expires_at>?2",
            params![id.as_bytes(),now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
        ).optional()?.ok_or(SessionError::Invalid)?;
        let code = Code {
            installation: Id::new(row.0)?,
            app: Id::new(row.1)?,
            network: Id::new(row.2)?,
            redirect: row.3,
            scopes: row.4,
            hash: row.5,
            challenge: row.6,
        };
        ensure!(
            code.app == client.app
                && code.redirect == redirect
                && bool::from(code.hash.ct_eq(&candidate))
                && matches_pkce(&code.challenge, verifier),
            SessionError::Invalid
        );
        let installation = installation(&tx, code.installation)?;
        installation.verify(&tx, client.app)?;
        let scopes: Vec<String> = serde_json::from_str(&code.scopes)?;
        ensure!(
            code.network == installation.network && scopes == installation.scopes,
            SessionError::Invalid
        );
        ensure!(
            tx.execute(
                "UPDATE application_authorization_codes SET consumed_at=?2
            WHERE id=?1 AND consumed_at IS NULL",
                params![id.as_bytes(), now]
            )? == 1,
            SessionError::Invalid
        );
        let family = super::secrets::id()?;
        let expires = now + REFRESH_SECONDS;
        tx.execute("INSERT INTO application_refresh_token_families(id,installation_id,application_id,created_at,expires_at)
            VALUES(?1,?2,?3,?4,?5)",params![family.as_bytes(),installation.id.as_bytes(),client.app.as_bytes(),now,expires])?;
        let (grant, _) = issue(&tx, installation, family, now, expires)?;
        tx.commit()?;
        Ok(grant)
    }

    pub fn rotate_application_refresh(&mut self, client: &Client, raw: &str) -> Result<Grant> {
        let (id, digest) = parse_secret(Purpose::Refresh, raw).ok_or(SessionError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        client.check(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let current = refresh(&tx, id)?.ok_or(SessionError::Invalid)?;
        ensure!(
            current.family_app == client.app && bool::from(current.hash.ct_eq(&digest)),
            SessionError::Invalid
        );
        let installation = installation(&tx, current.installation)?;
        ensure!(installation.app == client.app, SessionError::Invalid);
        if let Some(consumed) = current.consumed {
            if now < consumed || now.saturating_sub(consumed) >= REUSE_GRACE_SECONDS {
                revoke_family(&tx, current.family, now, "refresh token reuse")?;
                audit(
                    &tx,
                    &installation,
                    current.family,
                    "application_refresh.reuse",
                    now,
                )?;
                tx.commit()?;
            }
            return Err(SessionError::Invalid.into());
        }
        ensure!(
            !current.retired
                && now >= current.created
                && now < current.expires
                && now >= current.family_created
                && now < current.family_expires,
            SessionError::Invalid
        );
        installation.verify(&tx, client.app)?;
        let (grant, next) = issue(
            &tx,
            installation,
            current.family,
            now,
            current.family_expires,
        )?;
        ensure!(tx.execute("UPDATE application_refresh_tokens SET consumed_at=?2,replaced_by=?3 WHERE id=?1 AND consumed_at IS NULL",
            params![id.as_bytes(),now,next.as_bytes()])?==1,SessionError::Invalid);
        if let Some(previous) = current.access {
            tx.execute("UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?2),revocation_reason='refresh token rotated'
               WHERE id=?1 AND revoked_at IS NULL",params![previous,now])?;
        }
        tx.commit()?;
        Ok(grant)
    }

    pub fn revoke_application_refresh(&mut self, client: &Client, raw: &str) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        client.check(&tx)?;
        // Valid clients receive the same response for unknown and foreign tokens.
        if let Some((id, digest)) = parse_secret(Purpose::Refresh, raw)
            && let Some(current) = refresh(&tx, id)?
            && current.family_app == client.app
            && bool::from(current.hash.ct_eq(&digest))
        {
            let installation = installation(&tx, current.installation)?;
            ensure!(installation.app == client.app, SessionError::Invalid);
            let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
            revoke_family(&tx, current.family, now, "client revocation")?;
            audit(
                &tx,
                &installation,
                current.family,
                "application_refresh.revoke",
                now,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn prune_application_credentials(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        expire_access(&tx, now)?;
        let expired=tx.prepare("SELECT id FROM application_refresh_token_families WHERE expires_at<=?1 ORDER BY expires_at,id LIMIT 100")?
            .query_map([now],|r|r.get::<_,[u8;16]>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        for family in expired {
            revoke_family(&tx, Id::new(family)?, now, "refresh family expired")?;
            tx.execute(
                "DELETE FROM application_refresh_token_families WHERE id=?1",
                [family],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn issue(
    tx: &Transaction<'_>,
    installation: Installation,
    family: Id,
    now: i64,
    expires: i64,
) -> Result<(Grant, Id)> {
    expire_access(tx, now)?;
    let access = id()?;
    let suffix = Zeroizing::new(URL_SAFE_NO_PAD.encode(random::<32>()?.as_slice()));
    let digest = automation_digest(access, &suffix);
    tx.execute("INSERT INTO automation_service_access_tokens(id,principal_id,label,token_hash,created_at,expires_at)
        VALUES(?1,?2,'application installation',?3,?4,?5)",
        params![access.as_bytes(),installation.principal.as_bytes(),digest,now,now+ACCESS_SECONDS])?;
    let access_secret = Zeroizing::new(format!("lnw_spat_v1.{access}.{}", suffix.as_str()));
    let refresh = id()?;
    let (refresh_secret, digest) = new_secret(Purpose::Refresh, refresh)?;
    tx.execute("INSERT INTO application_refresh_tokens(id,family_id,token_hash,access_token_id,created_at,expires_at)
        VALUES(?1,?2,?3,?4,?5,?6)",params![refresh.as_bytes(),family.as_bytes(),digest,access.as_bytes(),now,expires])?;
    let network = read_network(tx, installation.network)?;
    Ok((
        Grant {
            access: access_secret,
            refresh: refresh_secret,
            installation,
            network,
        },
        refresh,
    ))
}

fn expire_access(tx: &Transaction<'_>, now: i64) -> Result<()> {
    tx.execute("UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?1),revocation_reason='expired token cleanup'
        WHERE id IN (SELECT id FROM automation_service_access_tokens WHERE revoked_at IS NULL AND expires_at<=?1
            ORDER BY expires_at,id LIMIT 100)",[now])?;
    Ok(())
}

fn revoke_family(tx: &Transaction<'_>, family: Id, now: i64, reason: &str) -> Result<()> {
    tx.execute("UPDATE application_refresh_token_families SET revoked_at=max(created_at,?2),revocation_reason=?3
        WHERE id=?1 AND revoked_at IS NULL",params![family.as_bytes(),now,reason])?;
    tx.execute("UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?2),revocation_reason=?3
        WHERE revoked_at IS NULL AND id IN (SELECT access_token_id FROM application_refresh_tokens
            WHERE family_id=?1 AND access_token_id IS NOT NULL)",params![family.as_bytes(),now,reason])?;
    Ok(())
}

fn audit(
    tx: &Transaction<'_>,
    installation: &Installation,
    family: Id,
    action: &str,
    now: i64,
) -> Result<()> {
    tx.execute("INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
        VALUES(randomblob(16),?1,'service_principal',?2,?3,'application_refresh_family',?4,'{}',?5)",
        params![installation.network.as_bytes(),installation.principal.as_bytes(),action,family.as_bytes(),now])?;
    Ok(())
}
