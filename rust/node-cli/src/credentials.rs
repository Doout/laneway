//! Named credentials for authenticating local proxy sessions.

use anyhow::{Context, Result, bail, ensure};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::private;

const MAX_NAME_BYTES: usize = 64;
const MAX_KEY_BYTES: usize = 255;
const MAX_CREDENTIALS: usize = 1024;
const AUTHENTICATION_CONCURRENCY: usize = 4;
const GENERATED_HASH_PREFIX: &str = "sha256:";
// A public synthetic PHC record with the same parameters as stored credentials.
// The verification result is ignored for unknown names.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$cHJveHktZHVtbXktc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Database {
    version: u8,
    credentials: BTreeMap<String, String>,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            version: 1,
            credentials: BTreeMap::new(),
        }
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_BYTES
        && key.bytes().all(|byte| !byte.is_ascii_control())
}

fn generate_key() -> Result<String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).context("generating proxy key")?;
    Ok(hex::encode(random))
}

fn hash_key(key: &str) -> Result<String> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).context("generating proxy password salt")?;
    let salt = SaltString::encode_b64(&random)
        .map_err(|err| anyhow::anyhow!("encoding proxy password salt: {err}"))?;
    Argon2::default()
        .hash_password(key.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| anyhow::anyhow!("hashing proxy key: {err}"))
}

fn load(path: &Path) -> Result<Database> {
    let bytes = match private::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Database::default()),
        Err(err) => return Err(err).context("reading proxy credentials"),
    };
    decode(&bytes)
}

fn decode(bytes: &[u8]) -> Result<Database> {
    let database: Database = serde_json::from_slice(bytes).context("decoding proxy credentials")?;
    ensure!(
        database.version == 1,
        "unsupported proxy credential file version"
    );
    ensure!(
        database.credentials.len() <= MAX_CREDENTIALS,
        "too many proxy credentials"
    );
    for (name, hash) in &database.credentials {
        ensure!(valid_name(name), "invalid stored proxy credential name");
        if let Some(digest) = hash.strip_prefix(GENERATED_HASH_PREFIX) {
            ensure!(
                hex::decode_to_slice(digest, &mut [0u8; 32]).is_ok(),
                "invalid stored generated proxy key digest"
            );
            continue;
        }
        let hash = PasswordHash::new(hash)
            .map_err(|_| anyhow::anyhow!("invalid stored proxy key hash"))?;
        let defaults = argon2::Params::default();
        ensure!(
            hash.algorithm == argon2::Algorithm::Argon2id.ident()
                && hash.version == Some(argon2::Version::V0x13 as u32)
                && hash.params.iter().count() == 3
                && hash.params.get_decimal("m") == Some(defaults.m_cost())
                && hash.params.get_decimal("t") == Some(defaults.t_cost())
                && hash.params.get_decimal("p") == Some(defaults.p_cost())
                && hash.salt.is_some()
                && hash
                    .hash
                    .is_some_and(|output| output.len() == argon2::Params::DEFAULT_OUTPUT_LEN),
            "unsupported stored proxy key hash"
        );
    }
    Ok(database)
}

fn save(path: &Path, database: &Database) -> Result<()> {
    let bytes = serde_json::to_vec(database).context("encoding proxy credentials")?;
    private::write(path, &bytes).context("writing proxy credentials")
}

fn edit_lock(path: &Path) -> Result<std::fs::File> {
    let name = path
        .file_name()
        .context("proxy credentials path has no filename")?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".lock");
    private::lock(&path.with_file_name(lock_name)).context("locking proxy credential file")
}

pub fn add(path: &Path, name: &str, key: &str) -> Result<()> {
    ensure!(
        valid_key(key),
        "proxy key must contain 1–255 bytes without ASCII control characters"
    );
    add_hash(path, name, || hash_key(key))
}

pub fn add_generated(path: &Path, name: &str) -> Result<String> {
    let key = generate_key()?;
    add_hash(path, name, || Ok(generated_hash(&key)))?;
    Ok(key)
}

fn generated_hash(key: &str) -> String {
    // Generated keys have 256 bits of entropy.
    format!(
        "{GENERATED_HASH_PREFIX}{}",
        hex::encode(Sha256::digest(key.as_bytes()))
    )
}

/// Create the initial local login once. An existing empty database records
/// deliberate revocation and must stay empty across configuration runs.
pub(crate) fn initial_key(path: &Path) -> Result<Option<String>> {
    let _guard = edit_lock(path)?;
    match private::read(path) {
        Ok(bytes) => {
            decode(&bytes)?;
            return Ok(None);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("read local proxy credentials"),
    }
    let key = generate_key()?;
    let mut database = Database::default();
    database
        .credentials
        .insert("local".into(), generated_hash(&key));
    save(path, &database)?;
    Ok(Some(key))
}

fn add_hash(path: &Path, name: &str, hash: impl FnOnce() -> Result<String>) -> Result<()> {
    ensure!(
        valid_name(name),
        "proxy credential name must contain 1–64 ASCII letters, digits, periods, hyphens, or underscores"
    );

    let _guard = edit_lock(path)?;
    let mut database = load(path)?;
    ensure!(
        !database.credentials.contains_key(name),
        "proxy credential already exists"
    );
    ensure!(
        database.credentials.len() < MAX_CREDENTIALS,
        "too many proxy credentials"
    );
    database.credentials.insert(name.to_string(), hash()?);
    save(path, &database)
}

pub fn remove(path: &Path, name: &str) -> Result<()> {
    let _guard = edit_lock(path)?;
    let mut database = load(path)?;
    if database.credentials.remove(name).is_none() {
        bail!("proxy credential does not exist");
    }
    save(path, &database)
}

pub fn list(path: &Path) -> Result<Vec<String>> {
    Ok(load(path)?.credentials.into_keys().collect())
}

struct Entry {
    hash: Arc<str>,
    sessions: CancellationToken,
}

#[derive(Default)]
struct Snapshot {
    stamp: Option<private::StateStamp>,
    entries: BTreeMap<String, Entry>,
}

struct State {
    path: PathBuf,
    snapshot: RwLock<Snapshot>,
    authentication_slots: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct Verifier {
    state: Arc<State>,
}

impl Verifier {
    pub fn open(path: PathBuf) -> Result<Self> {
        let verifier = Self {
            state: Arc::new(State {
                path,
                snapshot: RwLock::new(Snapshot::default()),
                authentication_slots: Arc::new(Semaphore::new(AUTHENTICATION_CONCURRENCY)),
            }),
        };
        verifier.reload()?;
        Ok(verifier)
    }

    /// Apply the current credential file. An invalid file invalidates existing sessions.
    pub fn reload(&self) -> Result<()> {
        let mut snapshot = self
            .state
            .snapshot
            .write()
            .expect("credential lock poisoned");
        let checked = private::read_if_changed(&self.state.path, snapshot.stamp.as_ref());
        let mut stamp = None;
        let database = match checked {
            Ok(None) => return Ok(()),
            Ok(Some((file_stamp, bytes))) => {
                let database = decode(&bytes);
                if database.is_ok() {
                    stamp = Some(file_stamp);
                }
                database
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Database::default()),
            Err(err) => Err(err).context("reading proxy credentials"),
        };
        let mut replacement = BTreeMap::new();
        if let Ok(database) = &database {
            for (name, hash) in &database.credentials {
                let existing = snapshot
                    .entries
                    .get(name)
                    .is_some_and(|entry| entry.hash.as_ref() == hash.as_str());
                let entry = if existing {
                    snapshot.entries.remove(name).expect("entry was just read")
                } else {
                    Entry {
                        hash: hash.as_str().into(),
                        sessions: CancellationToken::new(),
                    }
                };
                replacement.insert(name.clone(), entry);
            }
        }
        for removed in snapshot.entries.values() {
            removed.sessions.cancel();
        }
        *snapshot = Snapshot {
            stamp,
            entries: replacement,
        };
        database.map(|_| ())
    }

    pub async fn verify(&self, name: &str, key: &str) -> Option<CancellationToken> {
        if !valid_name(name) || !valid_key(key) {
            return None;
        }
        let (hash, session) = {
            let snapshot = self
                .state
                .snapshot
                .read()
                .expect("credential lock poisoned");
            match snapshot.entries.get(name) {
                Some(entry) => (Some(entry.hash.clone()), Some(entry.sessions.child_token())),
                None => (None, None),
            }
        };
        if let Some(digest) = hash
            .as_deref()
            .and_then(|hash| hash.strip_prefix(GENERATED_HASH_PREFIX))
        {
            let mut expected = [0u8; 32];
            if hex::decode_to_slice(digest, &mut expected).is_err() {
                return None;
            }
            let actual: [u8; 32] = Sha256::digest(key.as_bytes()).into();
            return session
                .filter(|session| bool::from(actual.ct_eq(&expected)) && !session.is_cancelled());
        }
        let permit = self
            .state
            .authentication_slots
            .clone()
            .try_acquire_owned()
            .ok()?;
        let key = key.to_owned();
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            PasswordHash::new(hash.as_deref().unwrap_or(DUMMY_HASH)).is_ok_and(|hash| {
                Argon2::default()
                    .verify_password(key.as_bytes(), &hash)
                    .is_ok()
            })
        })
        .await
        .unwrap_or(false);
        session.filter(|session| verified && !session.is_cancelled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn revocation_cancels_only_affected_sessions() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        private::ensure_directory(&directory).unwrap();
        let path = directory.join("proxy.json");

        add(&path, "first", "first-key").unwrap();
        add(&path, "second", "second-key").unwrap();
        assert!(add(&path, "first", "replacement-key").is_err());
        assert_eq!(list(&path).unwrap(), ["first", "second"]);
        let on_disk = String::from_utf8(private::read(&path).unwrap()).unwrap();
        assert!(on_disk.contains("argon2id"));
        assert!(!on_disk.contains("first-key"));
        let verifier = Verifier::open(path.clone()).unwrap();
        let first = verifier.verify("first", "first-key").await.unwrap();
        let second = verifier.verify("second", "second-key").await.unwrap();
        assert!(verifier.verify("first", "wrong-key").await.is_none());
        assert!(verifier.verify("unknown", "first-key").await.is_none());

        remove(&path, "first").unwrap();
        verifier.reload().unwrap();
        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());
        assert!(verifier.verify("first", "first-key").await.is_none());

        private::write(&path, b"invalid").unwrap();
        assert!(verifier.reload().is_err());
        assert!(second.is_cancelled());
    }

    #[tokio::test]
    async fn generated_keys_use_fast_verification_and_can_be_revoked() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        private::ensure_directory(&directory).unwrap();
        let path = directory.join("proxy.json");

        let generated = add_generated(&path, "generated").unwrap();
        assert_eq!(generated.len(), 64);
        assert!(generated.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(add_generated(&path, "generated").is_err());
        add(&path, "user_supplied_hex", &generated).unwrap();
        let tagged = format!("{GENERATED_HASH_PREFIX}{generated}");
        add(&path, "user_supplied_tag", &tagged).unwrap();

        let database = load(&path).unwrap();
        assert_eq!(
            database.credentials["generated"],
            format!(
                "{GENERATED_HASH_PREFIX}{}",
                hex::encode(Sha256::digest(generated.as_bytes()))
            )
        );
        for name in ["user_supplied_hex", "user_supplied_tag"] {
            assert!(database.credentials[name].starts_with("$argon2id$"));
        }
        assert!(
            !String::from_utf8(private::read(&path).unwrap())
                .unwrap()
                .contains(&generated)
        );

        let verifier = Verifier::open(path.clone()).unwrap();
        let slots = verifier
            .state
            .authentication_slots
            .try_acquire_many(AUTHENTICATION_CONCURRENCY as u32)
            .unwrap();
        let session = verifier.verify("generated", &generated).await.unwrap();
        assert!(verifier.verify("generated", "incorrect").await.is_none());
        assert!(
            verifier
                .verify("user_supplied_hex", &generated)
                .await
                .is_none()
        );
        drop(slots);
        assert!(
            verifier
                .verify("user_supplied_hex", &generated)
                .await
                .is_some()
        );
        assert!(
            verifier
                .verify("user_supplied_tag", &tagged)
                .await
                .is_some()
        );

        remove(&path, "generated").unwrap();
        verifier.reload().unwrap();
        assert!(session.is_cancelled());
        assert!(verifier.verify("generated", &generated).await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reload_revokes_on_changed_permissions_and_recovers() {
        use std::fs::{Permissions, set_permissions};
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("state");
        private::ensure_directory(&directory).unwrap();
        let path = directory.join("proxy.json");
        add(&path, "user", "their-key").unwrap();
        let verifier = Verifier::open(path.clone()).unwrap();
        let session = verifier.verify("user", "their-key").await.unwrap();
        verifier.reload().unwrap();
        assert!(!session.is_cancelled());

        set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        assert!(verifier.reload().is_err());
        assert!(session.is_cancelled());
        assert!(verifier.verify("user", "their-key").await.is_none());

        set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        verifier.reload().unwrap();
        assert!(verifier.verify("user", "their-key").await.is_some());
    }

    #[test]
    fn dummy_record_matches_configured_password_hash_parameters() {
        let bytes = serde_json::to_vec(&Database {
            version: 1,
            credentials: BTreeMap::from([("synthetic".to_string(), DUMMY_HASH.to_string())]),
        })
        .unwrap();
        decode(&bytes).unwrap();
    }

    #[test]
    fn generated_keys_fit_both_proxy_protocols() {
        let key = generate_key().unwrap();
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(key, generate_key().unwrap());
    }
}
