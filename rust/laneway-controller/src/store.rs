use anyhow::{Context, Result, bail, ensure};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use laneway_protocol::{AuthenticatedIdentity, Id, Role};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::schema;
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use rustix::io::Errno;

pub(crate) struct InitialNetwork {
    pub id: Id,
    pub name: String,
    pub ipv4: Ipv4Net,
    pub ipv6: Option<Ipv6Net>,
}

impl InitialNetwork {
    pub(crate) fn new(id: Id, name: String, ipv4: Ipv4Net, ipv6: Option<Ipv6Net>) -> Result<Self> {
        ensure!(
            !name.is_empty() && name.len() <= 253 && name.trim() == name && !name.contains('\0'),
            "initial network name must be 1..253 trimmed bytes"
        );
        ensure!(
            (8..=30).contains(&ipv4.prefix_len()) && routable(IpNet::V4(ipv4)),
            "initial network IPv4 pool must be a canonical routable /8 through /30"
        );
        if let Some(ipv6) = ipv6 {
            ensure!(
                (64..=120).contains(&ipv6.prefix_len())
                    && ipv6.addr().to_ipv4_mapped().is_none()
                    && routable(IpNet::V6(ipv6)),
                "initial network IPv6 pool must be a canonical routable /64 through /120"
            );
        }
        Ok(Self {
            id,
            name,
            ipv4,
            ipv6,
        })
    }
}

fn routable(prefix: IpNet) -> bool {
    if prefix.addr() != prefix.network() {
        return false;
    }
    const FORBIDDEN: [&str; 8] = [
        "0.0.0.0/32",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
    ];
    !FORBIDDEN.iter().any(|text| {
        let blocked: IpNet = text.parse().expect("static prefix");
        prefix.contains(&blocked.addr()) || blocked.contains(&prefix.addr())
    })
}

pub(crate) struct Store {
    db: Connection,
    _lifecycle_lock: File,
}

impl Store {
    pub(crate) fn enrollment_transaction(&mut self) -> Result<Transaction<'_>> {
        Ok(self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?)
    }

    pub(crate) fn open(path: &Path) -> Result<Self> {
        ensure!(
            !path.as_os_str().to_string_lossy().trim().is_empty(),
            "database path is empty"
        );
        let path = std::path::absolute(path)?;
        let parent = path.parent().context("database parent is missing")?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .context("create controller database directory")?;
        let path = parent
            .canonicalize()?
            .join(path.file_name().context("database filename is missing")?);
        let lifecycle_lock = lock_database(&path)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) => ensure!(meta.is_file(), "controller database must be a regular file"),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .context("create private controller database")?;
            }
            Err(error) => return Err(error).context("inspect controller database"),
        }
        let db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        Ok(Self {
            db,
            _lifecycle_lock: lifecycle_lock,
        })
    }

    pub(crate) fn prepare(
        &mut self,
        configured: Option<&InitialNetwork>,
        identity: AuthenticatedIdentity,
        bootstrap: Option<Id>,
    ) -> Result<()> {
        ensure!(
            identity.role == Role::Controller,
            "invalid controller certificate role"
        );
        ensure!(
            configured.is_none_or(|network| network.id == identity.network_id),
            "initial network differs from controller certificate identity"
        );
        ensure!(
            bootstrap.is_none_or(|id| id == identity.network_id),
            "bootstrap network differs from controller certificate identity"
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let existing: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table')",
            [],
            |row| row.get(0),
        )?;
        if existing {
            schema::validate(&tx).context("validate pre-existing controller schema")?;
        }
        schema::migrate(&tx, now)?;
        schema::validate(&tx).context("validate controller schema")?;
        ensure_initial_network(&tx, configured, identity, now)?;
        if let Some(id) = bootstrap {
            ensure!(
                network_row(&tx, id)?.is_some(),
                "bootstrap network is missing"
            );
        }
        tx.commit()
            .context("commit controller startup database preparation")
    }
}

// Network identity, exact configured shape, and audit are checked or produced
// in the same immediate transaction as schema migration.
fn ensure_initial_network(
    tx: &Transaction<'_>,
    configured: Option<&InitialNetwork>,
    identity: AuthenticatedIdentity,
    mut now: i64,
) -> Result<()> {
    let AuthenticatedIdentity {
        network_id,
        subject_id,
        ..
    } = identity;
    let bound: Option<(Vec<u8>, Vec<u8>)> = tx.query_row(
        "SELECT network_id,controller_service_id FROM controller_identity_state WHERE singleton=1",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    if let Some((network, subject)) = bound {
        ensure!(
            Id::from_slice(&network)? == network_id && Id::from_slice(&subject)? == subject_id,
            "controller certificate identity differs from durable binding"
        );
        // The schema validator already checks the binding's timestamp and audit.
        let persisted = network_row(tx, network_id)?.context("bound network is missing")?;
        if let Some(configured) = configured {
            ensure!(
                persisted.matches(configured),
                "configured initial network differs from durable state"
            );
        }
        return Ok(());
    }
    let Some(configured) = configured else {
        return Ok(());
    };
    now = tx.query_row(
        "SELECT max(?,coalesce(max(created_at),?)) FROM audit_events",
        params![now, now],
        |row| row.get(0),
    )?;
    if let Some(persisted) = network_row(tx, configured.id)? {
        ensure!(
            persisted.matches(configured),
            "existing initial network differs from configuration"
        );
        now = now.max(persisted.created);
    } else {
        let count: i64 = tx.query_row("SELECT count(*) FROM networks", [], |row| row.get(0))?;
        ensure!(
            count == 0,
            "configured initial network is absent from nonempty controller state"
        );
        let v4 = configured.ipv4.addr().octets();
        let v6 = configured.ipv6.map(|pool| pool.addr().octets());
        let v6_len = configured.ipv6.map(|pool| pool.prefix_len());
        tx.execute(
            "INSERT INTO networks(id,name,ipv4_address,ipv4_prefix_length,created_at,ipv6_address,ipv6_prefix_length)
             VALUES(?,?,?,?,?,?,?)",
            params![network_id.as_bytes().as_slice(), configured.name, v4.as_slice(), configured.ipv4.prefix_len(),
                now, v6.as_ref().map(|addr| addr.as_slice()), v6_len],
        ).context("insert initial network")?;
        audit(
            tx,
            network_id,
            "network.create",
            "network",
            network_id,
            r#"{"source":"controller_initial_network"}"#,
            now,
        )?;
    }
    tx.execute("INSERT INTO controller_identity_state(singleton,network_id,controller_service_id,created_at)
        VALUES(1,?,?,?)", params![network_id.as_bytes().as_slice(), subject_id.as_bytes().as_slice(), now])?;
    audit(
        tx,
        network_id,
        "controller.identity.bind",
        "controller_service",
        subject_id,
        "{}",
        now,
    )?;
    Ok(())
}

struct NetworkRow {
    name: String,
    ipv4: Vec<u8>,
    ipv4_len: u8,
    ipv6: Option<Vec<u8>>,
    ipv6_len: Option<u8>,
    created: i64,
    epoch: i64,
}

impl NetworkRow {
    fn matches(&self, configured: &InitialNetwork) -> bool {
        self.name == configured.name
            && self.ipv4 == configured.ipv4.addr().octets()
            && self.ipv4_len == configured.ipv4.prefix_len()
            && self.ipv6 == configured.ipv6.map(|pool| pool.addr().octets().to_vec())
            && self.ipv6_len == configured.ipv6.map(|pool| pool.prefix_len())
    }
}

fn network_row(tx: &Transaction<'_>, id: Id) -> Result<Option<NetworkRow>> {
    let network = tx.query_row(
        "SELECT name,ipv4_address,ipv4_prefix_length,ipv6_address,ipv6_prefix_length,created_at,configuration_epoch
        FROM networks WHERE id=?",
        [id.as_bytes().as_slice()],
        |row| {
            Ok(NetworkRow {
                name: row.get(0)?,
                ipv4: row.get(1)?,
                ipv4_len: row.get(2)?,
                ipv6: row.get(3)?,
                ipv6_len: row.get(4)?,
                created: row.get(5)?,
                epoch: row.get(6)?,
            })
        },
    )
    .optional()
    .context("read controller network")?;
    if let Some(network) = &network {
        ensure!(
            network.ipv4.len() == 4 && network.epoch >= 1,
            "corrupt network row"
        );
        if let Some(ipv6) = &network.ipv6 {
            ensure!(
                ipv6.len() == 16 && network.ipv6_len.is_some(),
                "corrupt network IPv6 pool"
            );
        }
    }
    Ok(network)
}

fn audit(
    tx: &Transaction<'_>,
    network: Id,
    action: &str,
    target_type: &str,
    target: Id,
    details: &str,
    now: i64,
) -> Result<()> {
    let id = loop {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes)
            .map_err(|error| anyhow::anyhow!("generate audit event ID: {error}"))?;
        if bytes != [0; 16] {
            break bytes;
        }
    };
    if tx.execute(
        "INSERT INTO audit_events(id,network_id,actor_kind,action,target_type,target_id,details_json,created_at)
         VALUES(?,?,'system',?,?,?,?,?)",
        params![id.as_slice(), network.as_bytes().as_slice(), action, target_type, target.as_bytes().as_slice(), details, now],
    )? != 1 {
        bail!("failed to record controller persistence audit");
    }
    Ok(())
}

pub(crate) fn lock_database(database: &Path) -> Result<File> {
    let mut lock_path = database.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_file = File::from(
        open(
            Path::new(&lock_path),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .context("open controller lifecycle lock")?,
    );
    if !lock_file.metadata()?.is_file() {
        bail!("controller lifecycle lock is not a regular file");
    }
    match flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(lock_file),
        Err(Errno::WOULDBLOCK) => bail!("controller database is already in use"),
        Err(error) => Err(error).context("lock controller lifecycle"),
    }
}

#[derive(serde::Serialize)]
pub(crate) struct NetworkView {
    network_id: String,
    name: String,
    ipv4_pool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6_pool: Option<String>,
    configuration_epoch: u64,
    created_at_unix_seconds: i64,
}

impl Store {
    pub(crate) fn root_principal(&self) -> Result<Id> {
        let raw: Vec<u8> = self.db.query_row(
            "SELECT root_service_principal_id FROM administrator_auth_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        Ok(Id::from_slice(&raw)?)
    }

    pub(crate) fn network_view(&self, id: Id) -> Result<Option<NetworkView>> {
        let mut query = self.db.prepare(
            "SELECT id,name,ipv4_address,ipv4_prefix_length,ipv6_address,ipv6_prefix_length,
                    configuration_epoch,created_at FROM networks WHERE id=?",
        )?;
        let mut rows = query.query([id.as_bytes().as_slice()])?;
        rows.next()?.map(network_view).transpose()
    }

    pub(crate) fn network_views(&self, limit: usize) -> Result<Vec<NetworkView>> {
        ensure!((1..=1000).contains(&limit), "invalid network list limit");
        let mut query = self.db.prepare(
            "SELECT id,name,ipv4_address,ipv4_prefix_length,ipv6_address,ipv6_prefix_length,
                    configuration_epoch,created_at FROM networks ORDER BY created_at,id LIMIT ?",
        )?;
        let mut rows = query.query([limit])?;
        let mut networks = Vec::new();
        while let Some(row) = rows.next()? {
            networks.push(network_view(row)?);
        }
        Ok(networks)
    }
}

fn network_view(row: &rusqlite::Row<'_>) -> Result<NetworkView> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let id: Vec<u8> = row.get(0)?;
    let ipv4: Vec<u8> = row.get(2)?;
    let ipv4_len: u8 = row.get(3)?;
    let ipv6: Option<Vec<u8>> = row.get(4)?;
    let ipv6_len: Option<u8> = row.get(5)?;
    let epoch: u64 = row.get(6)?;
    ensure!(epoch > 0, "invalid network configuration epoch");
    let ipv4: [u8; 4] = ipv4
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid network IPv4 address"))?;
    let ipv6_pool = ipv6
        .map(|bytes| {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid network IPv6 address"))?;
            Ok::<_, anyhow::Error>(
                Ipv6Net::new(
                    Ipv6Addr::from(octets),
                    ipv6_len.context("missing IPv6 prefix length")?,
                )?
                .to_string(),
            )
        })
        .transpose()?;
    Ok(NetworkView {
        network_id: Id::from_slice(&id)?.to_string(),
        name: row.get(1)?,
        ipv4_pool: Ipv4Net::new(Ipv4Addr::from(ipv4), ipv4_len)?.to_string(),
        ipv6_pool,
        configuration_epoch: epoch,
        created_at_unix_seconds: row.get(7)?,
    })
}
