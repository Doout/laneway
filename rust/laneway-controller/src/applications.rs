//! Application registration and reviewed manifests shared with the Go controller.
use crate::{
    ListError, RootCredential, SessionError, SessionReply, SessionStore,
    administrators::{AdministratorError, Caller},
    bearer, check_snapshot, open_existing,
};
use anyhow::{Result, ensure};
use hyper::Uri;
use laneway_protocol::Id;
use rusqlite::{OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeMap, fmt::Write, path::Path};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub mod authorization;
pub mod lifecycle;
mod secrets;
pub mod tokens;
use secrets::{Purpose, challenge_valid, id, matches_pkce, new_secret, parse_secret};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    name: String,
    homepage_uri: String,
    setup_uri: String,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
    token_endpoint_auth_method: String,
}

impl Manifest {
    pub fn validate(mut self, allow_loopback: bool) -> Result<Self> {
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 128
                && self.name == self.name.trim()
                && !self.name.contains('\0')
                && self.token_endpoint_auth_method == "client_secret_basic"
                && (1..=16).contains(&self.redirect_uris.len()),
            AdministratorError::Invalid
        );
        ensure!(
            valid_uri(&self.homepage_uri, allow_loopback)
                && valid_uri(&self.setup_uri, allow_loopback)
                && self
                    .redirect_uris
                    .iter()
                    .all(|uri| valid_uri(uri, allow_loopback)),
            AdministratorError::Invalid
        );
        self.redirect_uris.sort_unstable();
        ensure!(
            self.redirect_uris.windows(2).all(|pair| pair[0] != pair[1]),
            AdministratorError::Invalid
        );
        self.scopes = normalize_scopes(self.scopes)?;
        Ok(self)
    }
}

fn normalize_scopes(mut scopes: Vec<String>) -> Result<Vec<String>> {
    scopes.sort_unstable();
    ensure!(
        (1..=16).contains(&scopes.len())
            && scopes.windows(2).all(|p| p[0] != p[1])
            && scopes.iter().all(|s| matches!(
                s.as_str(),
                "network.read" | "node.read" | "enrollment.issue" | "route.read" | "route.manage"
            )),
        AdministratorError::Invalid
    );
    Ok(scopes)
}

fn valid_uri(raw: &str, allow_loopback: bool) -> bool {
    if raw.len() > 2048
        || !(raw.starts_with("https://") || (allow_loopback && raw.starts_with("http://")))
        || raw
            .bytes()
            .any(|b| b <= b' ' || b == 127 || matches!(b, b'\\' | b'#'))
    {
        return false;
    }
    let Ok(uri) = raw.parse::<Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let host = authority.host();
    !host.is_empty()
        && !authority.as_str().contains(['@', '*', '%'])
        && valid_percent(uri.path())
        && (raw.starts_with("https://")
            || host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.to_canonical().is_loopback()))
}

pub fn valid_percent(raw: &str) -> bool {
    raw.bytes().enumerate().all(|(i, b)| {
        b != b'%'
            || raw
                .as_bytes()
                .get(i + 1..i + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
    })
}

fn encode_query(out: &mut String, value: &str) {
    for c in value.bytes() {
        match c {
            b' ' => out.push('+'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            }
            _ => write!(out, "%{c:02X}").expect("write to String"),
        }
    }
}

fn callback(raw: &str, fields: &[(&str, &str)]) -> Result<Zeroizing<String>> {
    ensure!(valid_uri(raw, true), "invalid stored application callback");
    let (base, query) = raw.split_once('?').unwrap_or((raw, ""));
    let mut values = BTreeMap::<String, Vec<String>>::new();
    for (key, value) in query
        .split('&')
        .filter(|s| !s.contains(';') && valid_percent(s))
        .flat_map(|s| form_urlencoded::parse(s.as_bytes()))
    {
        values
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    for (key, value) in fields {
        values.insert((*key).into(), vec![(*value).into()]);
    }
    let mut out = Zeroizing::new(String::from(base));
    let mut sep = '?';
    for (key, entries) in values {
        for value in entries {
            out.push(sep);
            sep = '&';
            encode_query(&mut out, &key);
            out.push('=');
            encode_query(&mut out, &value);
        }
    }
    Ok(out)
}

#[derive(Serialize)]
pub struct Registered {
    pub application_id: String,
    pub client_id: String,
    #[serde(flatten)]
    pub manifest: Manifest,
    pub enabled: bool,
    created_at_unix_seconds: i64,
    updated_at_unix_seconds: i64,
}

impl Registered {
    pub fn name(&self) -> &str {
        &self.manifest.name
    }
}

struct Registration {
    manifest: Manifest,
    state: String,
    challenge: String,
    created: i64,
    expires: i64,
}

pub struct Exchanged {
    pub application: Registered,
    pub secret: Zeroizing<String>,
}

pub enum Read {
    Applications(i64),
    Application(Id),
    Registration(Id),
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Inventory {
    Applications {
        applications: Vec<Registered>,
    },
    Application(Registered),
    Registration {
        request_id: String,
        manifest: Manifest,
        expires_at_unix_seconds: i64,
    },
}

pub enum Consent {
    Approve,
    Cancel,
}

type ConsentResponse = (Zeroizing<String>, Option<(Id, i64, i64)>);

fn registration(tx: &Transaction<'_>, id: Id) -> Result<Registration> {
    let (payload, state, challenge, created, expires): (String, String, String, i64, i64) = tx
        .query_row(
            "SELECT manifest_json,state,pkce_challenge,created_at,expires_at
         FROM application_registration_requests WHERE id=?1 AND consumed_at IS NULL",
            [id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?
        .ok_or(ListError::Missing)?;
    Ok(Registration {
        manifest: serde_json::from_str(&payload)?,
        state,
        challenge,
        created,
        expires,
    })
}

fn application(tx: &Transaction<'_>, id: Id) -> Result<Registered> {
    let mut app = tx.query_row(
        "SELECT client_id,name,homepage_uri,setup_uri,token_endpoint_auth_method,enabled,created_at,updated_at
         FROM registered_applications WHERE id=?1",
        [id.as_bytes()], |r| Ok(Registered {
            application_id: id.to_string(), client_id: r.get(0)?, enabled: r.get(5)?,
            created_at_unix_seconds: r.get(6)?, updated_at_unix_seconds: r.get(7)?,
            manifest: Manifest {
                name: r.get(1)?, homepage_uri: r.get(2)?, setup_uri: r.get(3)?,
                token_endpoint_auth_method: r.get(4)?, redirect_uris: Vec::new(), scopes: Vec::new(),
            },
        }),
    ).optional()?.ok_or(ListError::Missing)?;
    let strings = |sql: &str| -> Result<Vec<String>> {
        Ok(tx
            .prepare(sql)?
            .query_map([id.as_bytes()], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    };
    app.manifest.redirect_uris = strings(
        "SELECT redirect_uri FROM registered_application_redirect_uris
        WHERE application_id=?1 ORDER BY redirect_uri",
    )?;
    app.manifest.scopes = strings(
        "SELECT scope FROM registered_application_scopes
        WHERE application_id=?1 ORDER BY scope",
    )?;
    Ok(app)
}

fn inventory(tx: &Transaction<'_>, query: Read, now: i64) -> Result<Inventory> {
    match query {
        Read::Applications(limit) => {
            ensure!((1..=1000).contains(&limit), ListError::Limit);
            let ids = tx.prepare("SELECT id FROM registered_applications ORDER BY enabled DESC,created_at DESC,id DESC LIMIT ?1")?
                .query_map([limit], |r| r.get::<_,[u8;16]>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Inventory::Applications {
                applications: ids
                    .into_iter()
                    .map(|raw| application(tx, Id::new(raw)?))
                    .collect::<Result<_>>()?,
            })
        }
        Read::Application(id) => Ok(Inventory::Application(application(tx, id)?)),
        Read::Registration(id) => {
            let pending = registration(tx, id)?;
            ensure!(now < pending.expires, ListError::Missing);
            Ok(Inventory::Registration {
                request_id: id.to_string(),
                manifest: pending.manifest,
                expires_at_unix_seconds: pending.expires,
            })
        }
    }
}

pub fn bearer_inventory(
    database: &Path,
    header: &str,
    root: Option<&RootCredential>,
    query: Result<Read>,
) -> Result<Inventory> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    bearer::authenticate(&tx, header, root)?.require_root()?;
    let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
    let reply = inventory(&tx, query?, now)?;
    tx.commit()?;
    Ok(reply)
}

impl SessionStore {
    pub fn application_inventory(
        &mut self,
        token: &str,
        query: Result<Read>,
    ) -> Result<SessionReply<Inventory>> {
        self.with_session(token, false, |tx, actor, _, _, now| {
            let owner: bool = tx.query_row(
                "SELECT role='owner' FROM administrator_principals WHERE id=?1",
                [actor.as_bytes()],
                |r| r.get(0),
            )?;
            ensure!(owner, SessionError::Denied);
            inventory(tx, query?, now)
        })
    }

    pub fn create_application_registration(
        &mut self,
        manifest: Manifest,
        state: &str,
        challenge: &str,
        allow_loopback: bool,
    ) -> Result<Id> {
        let payload = serde_json::to_string(&manifest.validate(allow_loopback)?)?;
        ensure!(
            payload.len() <= 32768
                && (1..=1024).contains(&state.len())
                && !state.contains('\0')
                && challenge_valid(challenge),
            AdministratorError::Invalid
        );
        let id = id()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        prune_registration(&tx, now)?;
        tx.execute(
            "INSERT INTO application_registration_requests(id,manifest_json,state,pkce_challenge,created_at,expires_at)
             VALUES(?1,?2,?3,?4,?5,?6)", params![id.as_bytes(), payload, state, challenge, now, now+600],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn application_consent(
        &mut self,
        caller: Caller<'_>,
        request: Result<Id>,
        consent: Consent,
    ) -> Result<ConsentResponse> {
        self.administrator_operation(caller, |tx, actor, browser, now| {
            let Some((owner, _)) = browser else { return Err(SessionError::Denied.into()) };
            let request = request?;
            let pending = registration(tx, request)?;
            let manifest = pending.manifest.validate(true)?;
            let redirect = match consent {
                Consent::Cancel => {
                    actor.write(tx, "application.registration_cancel", "application_registration_request",
                        Some(*request.as_bytes()), json!({}), now)?;
                    callback(&manifest.setup_uri, &[("error","access_denied"),("state",&pending.state)])?
                }
                Consent::Approve => {
                    ensure!(now >= pending.created && now < pending.expires, ListError::Missing);
                    let app = id()?;
                    let client_id = format!("lnw_client_v1.{app}");
                    tx.execute(
                        "INSERT INTO registered_applications(id,client_id,name,homepage_uri,setup_uri,token_endpoint_auth_method,
                         creator_principal_id,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)",
                        params![app.as_bytes(), client_id, manifest.name, manifest.homepage_uri, manifest.setup_uri,
                            manifest.token_endpoint_auth_method, owner.as_bytes(), now],
                    )?;
                    for uri in &manifest.redirect_uris {
                        tx.execute("INSERT INTO registered_application_redirect_uris VALUES(?1,?2)", params![app.as_bytes(), uri])?;
                    }
                    for scope in &manifest.scopes {
                        tx.execute("INSERT INTO registered_application_scopes VALUES(?1,?2)", params![app.as_bytes(), scope])?;
                    }
                    let code_id = id()?;
                    let (code, hash) = new_secret(Purpose::Registration, code_id)?;
                    tx.execute(
                        "INSERT INTO application_registration_codes(id,application_id,setup_uri,code_hash,pkce_challenge,created_at,expires_at)
                         VALUES(?1,?2,?3,?4,?5,?6,?7)",
                        params![code_id.as_bytes(), app.as_bytes(), manifest.setup_uri, hash, pending.challenge, now, now+300],
                    )?;
                    actor.write(tx, "application.create", "application", Some(*app.as_bytes()),
                        json!({"name": manifest.name, "scopes": manifest.scopes}), now)?;
                    callback(&manifest.setup_uri, &[("code", &code), ("state", &pending.state)])?
                }
            };
            ensure!(tx.execute(
                "UPDATE application_registration_requests SET consumed_at=?2 WHERE id=?1 AND consumed_at IS NULL",
                params![request.as_bytes(), now],
            )? == 1, AdministratorError::Conflict);
            Ok(redirect)
        })
    }

    pub fn exchange_application_registration(
        &mut self,
        code: &str,
        verifier: &str,
    ) -> Result<Exchanged> {
        let (code, digest) =
            parse_secret(Purpose::Registration, code).ok_or(SessionError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let (app, stored, challenge): ([u8; 16], [u8; 32], String) = tx
            .query_row(
                "SELECT application_id,code_hash,pkce_challenge FROM application_registration_codes
             WHERE id=?1 AND consumed_at IS NULL AND created_at<=?2 AND expires_at>?2",
                params![code.as_bytes(), now],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(SessionError::Invalid)?;
        ensure!(
            bool::from(stored.ct_eq(&digest)) && matches_pkce(&challenge, verifier),
            SessionError::Invalid
        );
        let app = Id::new(app)?;
        let application = application(&tx, app)?;
        ensure!(application.enabled, SessionError::Invalid);
        let key = id()?;
        let (secret, hash) = new_secret(Purpose::Client, key)?;
        tx.execute("INSERT INTO registered_application_credentials(id,application_id,secret_hash,created_at)
            VALUES(?1,?2,?3,?4)", params![key.as_bytes(), app.as_bytes(), hash, now])?;
        ensure!(tx.execute("UPDATE application_registration_codes SET consumed_at=?2 WHERE id=?1 AND consumed_at IS NULL",
            params![code.as_bytes(), now])? == 1, SessionError::Invalid);
        tx.commit()?;
        Ok(Exchanged {
            application,
            secret,
        })
    }
}

fn prune_registration(tx: &Transaction<'_>, now: i64) -> Result<()> {
    tx.execute("DELETE FROM application_registration_requests WHERE id IN
        (SELECT id FROM application_registration_requests WHERE expires_at<=?1 ORDER BY expires_at,id LIMIT 100)", [now])?;
    tx.execute("DELETE FROM application_registration_codes WHERE id IN
        (SELECT id FROM application_registration_codes WHERE expires_at<=?1 ORDER BY expires_at,id LIMIT 100)", [now])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callbacks_preserve_the_reviewed_authority_and_canonical_path() {
        for valid in [
            "https://Dispatch.Example",
            "https://dispatch.example:8443/hello%20world?q=literal",
            "https://[::1]/setup",
        ] {
            assert!(valid_uri(valid, false), "{valid}");
        }
        for invalid in [
            "https://example.org@another.example/setup",
            "https://example.org\\@another.example/setup",
            "https://example.org/setup#",
            "https://example.org/bad%pw",
            "http://example.org/setup",
        ] {
            assert!(!valid_uri(invalid, true), "{invalid}");
        }
        for loopback in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(valid_uri(loopback, true), "{loopback}");
            assert!(!valid_uri(loopback, false), "{loopback}");
        }
        assert_eq!(
            &*callback(
                "https://example.org/setup?z=%7E&state=old&z=a",
                &[("state", "+/&")]
            )
            .unwrap(),
            "https://example.org/setup?state=%2B%2F%26&z=~&z=a",
        );
    }
}
