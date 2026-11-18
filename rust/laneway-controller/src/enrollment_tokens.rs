//! Issue a single-use enrollment credential. Its secret is returned only after
//! the scoped grant, token digest and audit event have committed together.
use crate::{
    ListError, NetworkError, RootCredential, SessionReply, SessionStore,
    management_write::BrowserWrite, sessions::check_network,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

pub(crate) const ROUTER: u64 = 1 << 3;
pub(crate) const EXIT: u64 = 1 << 4;
const MAX_VALIDITY: i64 = 30 * 86400;

#[derive(Default)]
pub struct IssueEnrollmentToken {
    network_id: String,
    user_id: String,
    label: String,
    expires_at_unix_seconds: i64,
    enrollment_class: String,
    session_lifetime_seconds: i64,
    requested_name: String,
    enabled_capabilities: u64,
}

// Like the reference JSON decoder: reject unknown keys and wrong scalar types;
// field names ignore ASCII case, and null does not erase a preceding value.
impl<'de> Deserialize<'de> for IssueEnrollmentToken {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = IssueEnrollmentToken;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an enrollment token request")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut form = Self::Value::default();
                while let Some(key) = map.next_key::<String>()? {
                    macro_rules! field {
                        ($name:ident) => {
                            if let Some(v) = map.next_value::<Option<_>>()? {
                                form.$name = v
                            }
                        };
                    }
                    match key.to_ascii_lowercase().as_str() {
                        "network_id" => field!(network_id),
                        "user_id" => field!(user_id),
                        "label" => field!(label),
                        "expires_at_unix_seconds" => field!(expires_at_unix_seconds),
                        "enrollment_class" => field!(enrollment_class),
                        "requested_name" => field!(requested_name),
                        "enabled_capabilities" => field!(enabled_capabilities),
                        "session_lifetime_seconds" => field!(session_lifetime_seconds),
                        _ => return Err(A::Error::custom("unknown enrollment field")),
                    }
                }
                Ok(form)
            }
        }
        d.deserialize_map(Fields)
    }
}

#[derive(Serialize)]
pub struct IssuedEnrollmentToken {
    token_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    user_id: String,
    #[serde(serialize_with = "serialize_secret")]
    enrollment_token: Zeroizing<String>,
    expires_at_unix_seconds: i64,
    enrollment_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_lifetime_seconds: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    requested_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled_capabilities: Option<u64>,
}

fn serialize_secret<S: Serializer>(
    s: &Zeroizing<String>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(s)
}

#[derive(Serialize)]
struct Grant<'a> {
    enrollment_class: &'a str,
    requested_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_lifetime_seconds: Option<i64>,
    enabled_capabilities: u64,
}

impl IssueEnrollmentToken {
    fn target(&self) -> Result<(Id, Option<Id>)> {
        let net = self
            .network_id
            .parse()
            .map_err(|_| NetworkError::Malformed("invalid network_id"))?;
        let user = (!self.user_id.is_empty())
            .then(|| self.user_id.parse())
            .transpose()
            .map_err(|_| NetworkError::Malformed("invalid user_id"))?;
        Ok((net, user))
    }
    fn issue(
        mut self,
        tx: &Transaction<'_>,
        target: (Id, Option<Id>),
        actor_kind: &str,
        actor: Id,
        now: i64,
    ) -> Result<IssuedEnrollmentToken> {
        let (net, user) = target;
        let invalid = || NetworkError::Malformed("invalid request");
        ensure!(
            self.label.trim() == self.label
                && self.label.len() <= 256
                && !self.label.contains('\0'),
            invalid()
        );
        if self.enrollment_class.is_empty() {
            self.enrollment_class = "durable".into()
        }
        let ephemeral = self.enrollment_class == "ephemeral";
        ensure!(
            ephemeral || matches!(self.enrollment_class.as_str(), "remembered" | "durable"),
            invalid()
        );
        ensure!(
            self.requested_name.trim() == self.requested_name && self.requested_name.len() <= 253,
            invalid()
        );
        // The Go audit writer rejects names whose quoted form is not JSON.
        ensure!(
            !self
                .requested_name
                .bytes()
                .any(|b| matches!(b,0..=7|11|14..=31|127)),
            invalid()
        );
        let caps = self.enabled_capabilities;
        ensure!(
            caps & !(ROUTER | EXIT) == 0 && !(ephemeral && caps & EXIT != 0 && caps != EXIT),
            invalid()
        );
        let lifetime = if ephemeral {
            ensure!(
                (300..=86400).contains(&self.session_lifetime_seconds),
                invalid()
            );
            Some(self.session_lifetime_seconds)
        } else {
            ensure!(self.session_lifetime_seconds == 0, invalid());
            None
        };
        ensure!(
            self.expires_at_unix_seconds > now
                && self.expires_at_unix_seconds <= now + MAX_VALIDITY,
            invalid()
        );
        if let Some(id) = user {
            let enabled: Option<bool> = tx
                .query_row(
                    "SELECT enabled FROM access_users WHERE id=?1 AND network_id=?2",
                    (id.as_bytes(), net.as_bytes()),
                    |r| r.get(0),
                )
                .optional()?;
            ensure!(enabled.ok_or(ListError::Missing)?, NetworkError::Conflict);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [net.as_bytes()],
            |r| r.get(0),
        )?;
        ensure!(exists, ListError::Missing);
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *raw)?;
        let hash: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        let mut id = [0; 16];
        getrandom::fill(&mut id)?;
        let id = Id::new(id)?;
        tx.execute("INSERT INTO enrollment_tokens(id,network_id,token_hash,label,expires_at,created_at,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities,user_id)
          VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
          params![id.as_bytes(),net.as_bytes(),hash,self.label,self.expires_at_unix_seconds,now,self.enrollment_class,lifetime,
            (!self.requested_name.is_empty()).then_some(&self.requested_name),i64::try_from(caps)?,user.as_ref().map(Id::as_bytes)])?;
        let details = serde_json::to_string(&Grant {
            enrollment_class: &self.enrollment_class,
            requested_name: &self.requested_name,
            session_lifetime_seconds: lifetime,
            enabled_capabilities: caps,
        })?;
        tx.execute("INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
          VALUES(randomblob(16),?1,?2,?3,'enrollment_token.issue','enrollment_token',?4,?5,?6)",
          (net.as_bytes(),actor_kind,actor.as_bytes(),id.as_bytes(),details,now))?;
        Ok(IssuedEnrollmentToken {
            token_id: id.to_string(),
            user_id: self.user_id,
            enrollment_token: Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_slice())),
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            enrollment_class: self.enrollment_class,
            requested_name: self.requested_name,
            session_lifetime_seconds: lifetime,
            enabled_capabilities: (caps != 0).then_some(caps),
        })
    }
}

impl SessionStore {
    pub fn issue_enrollment(
        &mut self,
        token: &str,
        csrf: Option<&str>,
        form: Result<IssueEnrollmentToken>,
    ) -> Result<SessionReply<IssuedEnrollmentToken>> {
        self.browser_write(
            token,
            csrf,
            BrowserWrite::IssueEnrollment,
            |tx, actor, all, now| {
                let form = form?;
                let target = form.target()?;
                if !all {
                    check_network(tx, actor, target.0)?
                }
                form.issue(tx, target, "administrator", actor, now)
            },
        )
    }
    pub fn bearer_issue_enrollment(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        form: Result<IssueEnrollmentToken>,
    ) -> Result<IssuedEnrollmentToken> {
        self.bearer_write(header, root, |tx, actor, now| {
            let form = form?;
            let target = form.target()?;
            actor.authorize(tx, "enrollment.issue", Some(target.0))?;
            form.issue(tx, target, "service_principal", actor.id, now)
        })
    }
}
