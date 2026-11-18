//! Bearer inventory never slides a browser session or writes to the database.
use crate::{
    InventoryList, ListError, Scope, SessionError, check_snapshot, nodes::read_nodes,
    open_existing, read_networks,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use laneway_protocol::Id;
use rusqlite::{OpenFlags, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct RootCredential {
    digest: [u8; 32],
    principal: Id,
}

/// Internal context for an application access token delegated by a verified
/// public relay. It is never a valid scheme on an incoming HTTP request.
pub const PUBLIC_APPLICATION_SCHEME: &str = "LanewayPublicApplication";

fn root_id(tx: &Transaction<'_>) -> Result<Id> {
    Ok(Id::new(tx.query_row(
        "SELECT root_service_principal_id FROM administrator_auth_state WHERE singleton=1",
        [],
        |r| r.get(0),
    )?)?)
}

impl RootCredential {
    fn matches(&self, header: &str) -> bool {
        header
            .strip_prefix("Bearer ")
            .is_some_and(|token| bool::from(self.digest.ct_eq(&Sha256::digest(token.as_bytes()))))
    }

    pub fn probe(&self, header: &str, database: &Path) -> Result<()> {
        ensure!(self.matches(header), SessionError::Invalid);
        let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tx = db.transaction()?;
        check_snapshot(&tx)?;
        ensure!(self.principal == root_id(&tx)?, SessionError::Invalid);
        tx.commit()?;
        Ok(())
    }

    /// Pin the root principal at startup, as the Go authorizer does. Only a
    /// digest survives startup, and no credential is accepted from argv.
    pub fn load(file: &Path, database: &Path) -> Result<Self> {
        let stream = File::open(file)?;
        let metadata = stream.metadata()?;
        ensure!(metadata.is_file(), "root token file must be a regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o037 == 0,
                "insecure root token file permissions"
            );
        }
        let mut raw = Zeroizing::new(Vec::new());
        stream.take(4097).read_to_end(&mut raw)?;
        let token = raw.trim_ascii();
        ensure!(
            raw.len() <= 4096 && token.len() >= 32,
            "invalid root token file length"
        );
        let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tx = db.transaction()?;
        check_snapshot(&tx)?;
        let principal = root_id(&tx)?;
        tx.commit()?;
        Ok(Self {
            digest: Sha256::digest(token).into(),
            principal,
        })
    }
}

fn automation_proof(token: &str) -> Result<(Id, [u8; 32]), SessionError> {
    let mut parts = token.split('.');
    let (Some("lnw_spat_v1"), Some(id), Some(secret), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(SessionError::Invalid);
    };
    let id: Id = id.parse().map_err(|_| SessionError::Invalid)?;
    let mut buf = Zeroizing::new([0u8; 32]);
    if secret.len() != 43 || URL_SAFE_NO_PAD.decode_slice(secret, &mut *buf) != Ok(32) {
        return Err(SessionError::Invalid);
    }
    Ok((id, automation_digest(id, secret)))
}

pub(crate) fn automation_digest(id: Id, secret: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"laneway-service-access-token-v1\0")
        .chain_update(id.as_bytes())
        .chain_update(secret.as_bytes())
        .finalize()
        .into()
}

pub(crate) struct BearerActor {
    pub(crate) id: Id,
    root: bool,
    all: bool,
}

pub(crate) fn authenticate(
    tx: &Transaction<'_>,
    header: &str,
    root: Option<&RootCredential>,
) -> Result<BearerActor> {
    let (scheme, token) = header.split_once(' ').ok_or(SessionError::Invalid)?;
    let public_app = scheme == PUBLIC_APPLICATION_SCHEME;
    if let Some(root) = root.filter(|r| r.matches(header)) {
        ensure!(root.principal == root_id(tx)?, SessionError::Invalid);
        return Ok(BearerActor {
            id: root.principal,
            root: true,
            all: true,
        });
    }
    ensure!(
        public_app || scheme.eq_ignore_ascii_case("bearer"),
        SessionError::Invalid
    );
    let (token_id, proof) = automation_proof(token)?;
    // Authenticate, authorize and read from the same SQLite snapshot. The
    // schema enforces valid principal names, operation names and distinct grants.
    let (id, stored, all): ([u8;16], [u8;32], bool) = tx.query_row(
            "SELECT p.id,t.token_hash,p.all_networks FROM automation_service_access_tokens t
             JOIN automation_service_principals p ON p.id=t.principal_id
             WHERE t.id=?1 AND t.revoked_at IS NULL AND t.created_at<=unixepoch() AND t.expires_at>unixepoch()
               AND p.enabled=1 AND p.disabled_at IS NULL
               AND EXISTS(SELECT 1 FROM automation_service_principal_permissions WHERE principal_id=p.id)
               AND NOT(p.all_networks=1 AND EXISTS(SELECT 1 FROM automation_service_principal_networks WHERE principal_id=p.id))
               AND (p.all_networks=1 OR EXISTS(SELECT 1 FROM automation_service_principal_networks WHERE principal_id=p.id))
                   = EXISTS(SELECT 1 FROM automation_service_principal_permissions WHERE principal_id=p.id
                       AND operation NOT IN ('network.create','bootstrap_bundle.create','audit.read_global'))
               AND (NOT ?2 OR EXISTS(
                   SELECT 1 FROM application_refresh_tokens r
                   JOIN application_refresh_token_families f ON f.id=r.family_id
                   JOIN application_installations i ON i.id=f.installation_id AND i.application_id=f.application_id
                   JOIN registered_applications a ON a.id=i.application_id
                   WHERE r.access_token_id=t.id AND i.service_principal_id=p.id
                     AND r.consumed_at IS NULL AND f.revoked_at IS NULL
                     AND f.created_at<=unixepoch() AND f.expires_at>unixepoch()
                     AND i.enabled=1 AND a.enabled=1 AND p.all_networks=0
               ))",
            (token_id.as_bytes(), public_app), |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(SessionError::Invalid)?;
    ensure!(bool::from(stored.ct_eq(&proof)), SessionError::Invalid);
    Ok(BearerActor {
        id: Id::new(id)?,
        root: false,
        all,
    })
}

impl BearerActor {
    pub(crate) fn require_root(&self) -> Result<()> {
        ensure!(self.root, SessionError::Denied);
        Ok(())
    }

    pub(crate) fn authorize(
        &self,
        tx: &Transaction<'_>,
        op: &str,
        network: Option<Id>,
    ) -> Result<()> {
        if self.root {
            return Ok(());
        }
        let principal = self.id;
        let granted: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM automation_service_principal_permissions WHERE principal_id=?1 AND operation=?2)", (principal.as_bytes(), op), |r|r.get(0))?;
        ensure!(granted, SessionError::Denied);
        if let Some(n) = network.filter(|_| !self.all) {
            let allowed:bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM automation_service_principal_networks WHERE principal_id=?1 AND network_id=?2)",(principal.as_bytes(), n.as_bytes()), |r|r.get(0))?;
            ensure!(allowed, SessionError::Denied);
        }
        Ok(())
    }
}

pub fn bearer_inventory(
    database: &Path,
    header: &str,
    root: Option<&RootCredential>,
    network: Result<Option<Id>, ListError>,
    limit: Result<usize, ListError>,
) -> Result<InventoryList> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    let actor = authenticate(&tx, header, root)?;
    let network = network?;
    actor.authorize(
        &tx,
        if network.is_some() {
            "node.read"
        } else {
            "network.list"
        },
        network,
    )?;
    let scope = (!actor.all).then_some(Scope::Automation(actor.id));
    let limit = limit?;
    ensure!((1..=1000).contains(&limit), ListError::Limit);
    let list = match network {
        Some(n) => InventoryList::Nodes(read_nodes(&tx, n, limit)?),
        None => InventoryList::Networks(read_networks(&tx, limit, scope)?),
    };
    tx.commit()?;
    Ok(list)
}

pub fn bearer_network(
    database: &Path,
    header: &str,
    root: Option<&RootCredential>,
    id: Result<Id, ListError>,
) -> Result<crate::Network> {
    let mut db = open_existing(database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = db.transaction()?;
    check_snapshot(&tx)?;
    let actor = authenticate(&tx, header, root)?;
    let id = id?;
    actor.authorize(&tx, "network.read", Some(id))?;
    let result = crate::read_network(&tx, id)?;
    tx.commit()?;
    Ok(result)
}
