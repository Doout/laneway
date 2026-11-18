//! Bounded verification of existing Go administrator credentials. This does
//! not issue a session: the caller must recheck these credential IDs in the
//! session-creation transaction after the expensive password check.
use crate::{check_snapshot, open_existing};
use anyhow::{Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{OpenFlags, OptionalExtension};
use std::{path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const PREFIX: &str = "$argon2id$v=19$m=65536,t=3,p=1$";

struct Hash {
    salt: [u8; 16],
    expected: Zeroizing<[u8; 32]>,
}
impl Hash {
    fn parse(encoded: &str) -> Result<Self> {
        let invalid = || anyhow::anyhow!("invalid administrator credential hash");
        let (salt, want) = encoded
            .strip_prefix(PREFIX)
            .and_then(|s| s.split_once('$'))
            .ok_or_else(invalid)?;
        ensure!(
            salt.len() == 22 && want.len() == 43,
            "invalid administrator credential hash length"
        );
        let mut parsed = Self {
            salt: [0; 16],
            expected: Zeroizing::new([0; 32]),
        };
        STANDARD_NO_PAD
            .decode_slice(salt, &mut parsed.salt)
            .map_err(|_| invalid())?;
        STANDARD_NO_PAD
            .decode_slice(want, &mut *parsed.expected)
            .map_err(|_| invalid())?;
        Ok(parsed)
    }
    fn verify(&self, password: &[u8]) -> Result<bool> {
        if !(15..=1024).contains(&password.len()) {
            return Ok(false);
        }
        // Never use cost parameters supplied by a request or read from SQLite.
        let mut got = Zeroizing::new([0u8; 32]);
        let kdf = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(65536, 3, 1, Some(32)).expect("fixed administrator Argon2 parameters"),
        );
        kdf.hash_password_into(password, &self.salt, &mut *got)
            .map_err(|_| anyhow::anyhow!("administrator password verification failed"))?;
        Ok(bool::from(got.ct_eq(&*self.expected)))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("administrator password verification busy")]
pub struct Busy;

pub struct VerifiedPassword {
    principal: Id,
    credential: Id,
}
impl VerifiedPassword {
    pub fn principal_id(&self) -> Id {
        self.principal
    }
    pub fn credential_id(&self) -> Id {
        self.credential
    }
}

pub struct PasswordVerifier {
    slots: Arc<Semaphore>,
    dummy: Arc<Hash>,
}
impl PasswordVerifier {
    pub fn new() -> Result<Self> {
        let mut dummy = Hash {
            salt: [0; 16],
            expected: Zeroizing::new([0; 32]),
        };
        getrandom::fill(&mut dummy.salt)
            .map_err(|_| anyhow::anyhow!("password verifier initialization failed"))?;
        getrandom::fill(&mut *dummy.expected)
            .map_err(|_| anyhow::anyhow!("password verifier initialization failed"))?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(2)),
            dummy: Arc::new(dummy),
        })
    }
    pub async fn verify(
        &self,
        database: PathBuf,
        username: String,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<Option<VerifiedPassword>> {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Busy)?;
        let dummy = Arc::clone(&self.dummy);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let row = {
                let mut db = open_existing(&database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let tx = db.transaction()?;
                check_snapshot(&tx)?;
                let row = tx
                    .query_row(
                        "SELECT p.id,c.id,c.secret_hash FROM administrator_principals p
                    JOIN administrator_credentials c ON c.principal_id=p.id
                    WHERE p.username=?1 AND p.enabled=1 AND p.disabled_at IS NULL
                    AND c.credential_type='password' AND c.revoked_at IS NULL",
                        [&username],
                        |r| {
                            Ok((
                                r.get::<_, [u8; 16]>(0)?,
                                r.get::<_, [u8; 16]>(1)?,
                                Zeroizing::new(r.get::<_, String>(2)?),
                            ))
                        },
                    )
                    .optional()?;
                tx.commit()?;
                row
            };
            if let Some((p, c, encoded)) = row {
                let candidate = VerifiedPassword {
                    principal: Id::new(p)?,
                    credential: Id::new(c)?,
                };
                Ok(Hash::parse(&encoded)?
                    .verify(&password)?
                    .then_some(candidate))
            } else {
                // Even an unknown or disabled username incurs the fixed KDF cost.
                std::hint::black_box(dummy.verify(&password)?);
                Ok(None)
            }
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Produced by Go x/crypto/argon2.IDKey using the Go controller settings.
    const FIXTURE: &str = "$argon2id$v=19$m=65536,t=3,p=1$CQkJCQkJCQkJCQkJCQkJCQ$fg4kiFPNkKgYfLNDJJYotdwfFCIUeucr+cJw4wD6IbY";
    #[test]
    fn exact_go_format_only() {
        let hash = Hash::parse(FIXTURE).unwrap();
        assert!(hash.verify(b"local browser fixture password").unwrap());
        assert!(!hash.verify(b"wrong browser fixture password").unwrap());
        assert!(!hash.verify(b"short").unwrap());
        for v in [
            FIXTURE.replace("65536", "99999999"),
            FIXTURE.replace("v=19", "v=16"),
            format!("{FIXTURE}="),
        ] {
            assert!(Hash::parse(&v).is_err());
        }
    }

    #[tokio::test]
    async fn candidate_is_bound_to_the_current_credential_and_work_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lab.db");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE schema_versions(version INTEGER PRIMARY KEY);
            WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM n WHERE v<18)
            INSERT INTO schema_versions SELECT v FROM n;
            CREATE TABLE administrator_principals(id BLOB, username TEXT,enabled INTEGER, disabled_at INTEGER,all_networks INTEGER);
            CREATE TABLE administrator_credentials(id BLOB,principal_id BLOB,secret_hash TEXT,credential_type TEXT,revoked_at INTEGER)").unwrap();
        db.execute(
            "INSERT INTO administrator_principals VALUES(?1,'owner',1,NULL,1)",
            [[1u8; 16]],
        )
        .unwrap();
        db.execute(
            "INSERT INTO administrator_credentials VALUES(?1,?2,?3,'password',NULL)",
            ([2u8; 16], [1u8; 16], FIXTURE),
        )
        .unwrap();
        let verifier = PasswordVerifier::new().unwrap();
        let verify = |user: &str| {
            verifier.verify(
                path.clone(),
                user.to_owned(),
                Zeroizing::new(b"local browser fixture password".to_vec()),
            )
        };
        let held = verifier.slots.clone().try_acquire_many_owned(2).unwrap();
        assert!(verify("owner").await.err().unwrap().is::<Busy>());
        drop(held);
        let candidate = verify("owner").await.unwrap().unwrap();
        assert_eq!(candidate.principal_id().as_bytes(), &[1; 16]);
        assert_eq!(candidate.credential_id().as_bytes(), &[2; 16]);
        db.execute(
            "UPDATE administrator_principals SET enabled=0,disabled_at=1",
            [],
        )
        .unwrap();
        assert!(verify("owner").await.unwrap().is_none());
        let error = crate::SessionStore::open(&path)
            .unwrap()
            .issue_after_password(candidate)
            .err()
            .expect("disablement must invalidate the verified candidate");
        assert!(matches!(
            error.downcast_ref::<crate::SessionError>(),
            Some(crate::SessionError::Invalid)
        ));
        assert!(verify("unknown").await.unwrap().is_none());
    }
}
