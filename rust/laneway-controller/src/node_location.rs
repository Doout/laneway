//! Controller-observed node presence and optional offline City lookups.
use crate::{
    DB_BUSY_TIMEOUT, SessionStore, access_admin::AccessError, check_snapshot,
    enrollment::renewal::NodeCredential,
};
use anyhow::{Result, ensure};
use ipnet::IpNet;
use laneway_protocol::Id;
use rusqlite::{Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs::File, io::Read, net::IpAddr, path::Path, sync::LazyLock, time::Duration};

#[derive(Deserialize, Serialize, Debug)]
pub struct Location {
    pub label: String,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_km: u16,
}
impl Location {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.label.trim().is_empty()
                && self.label.len() <= 253
                && !self.label.chars().any(char::is_control)
                && (-90.0..=90.0).contains(&self.latitude)
                && (-180.0..=180.0).contains(&self.longitude),
            AccessError::Invalid("location requires a label and valid latitude/longitude")
        );
        Ok(())
    }
}

static NON_PUBLIC: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    ]
    .map(|prefix| prefix.parse().expect("constant address range"))
    .to_vec()
});

fn public_ip(ip: IpAddr) -> Option<IpAddr> {
    let ip = ip.to_canonical();
    if matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xe000 != 0x2000)
        || NON_PUBLIC.iter().any(|network| network.contains(&ip))
    {
        return None;
    }
    Some(ip)
}

pub struct Database {
    reader: maxminddb::Reader<Vec<u8>>,
    provider: &'static str,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Record {
    city: City,
    country: Country,
    location: Coordinates,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct City {
    names: Names,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct Names {
    en: String,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct Country {
    iso_code: String,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct Coordinates {
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy_radius: u16,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        const MAX_BYTES: u64 = 512 << 20;
        let file = File::open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= MAX_BYTES,
            "invalid local City database size"
        );
        let mut contents = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut contents)?;
        ensure!(
            contents.len() as u64 <= MAX_BYTES,
            "oversized City database"
        );
        // Own the bytes so atomic file replacement cannot change results
        // midway through a lookup.
        let reader = maxminddb::Reader::from_source(contents)?;
        let kind = &reader.metadata().database_type;
        ensure!(
            kind.contains("City"),
            "location database must be a City database"
        );
        let provider = if kind.to_ascii_lowercase().contains("dbip") {
            "db-ip"
        } else {
            "maxmind"
        };
        reader.verify()?;
        Ok(Self { reader, provider })
    }
    pub fn provider(&self) -> &'static str {
        self.provider
    }
    fn lookup(&self, ip: IpAddr) -> Result<Option<Location>> {
        let Some(ip) = public_ip(ip) else {
            return Ok(None);
        };
        let Some(record) = self.reader.lookup(ip)?.decode::<Record>()? else {
            return Ok(None);
        };
        let (Some(latitude), Some(longitude)) =
            (record.location.latitude, record.location.longitude)
        else {
            return Ok(None);
        };
        if record.country.iso_code.is_empty() {
            return Ok(None);
        }
        let location = Location {
            label: if record.city.names.en.is_empty() {
                record.country.iso_code
            } else {
                format!("{}, {}", record.city.names.en, record.country.iso_code)
            },
            latitude,
            longitude,
            accuracy_km: record.location.accuracy_radius,
        };
        location.validate()?;
        Ok(Some(location))
    }
}

impl SessionStore {
    /// Only pass the remote address from the TLS socket or QUIC connection,
    /// never a header, request parameter or reported node address.
    pub fn observe_node(
        &mut self,
        peer: &NodeCredential,
        remote: IpAddr,
        resolver: Option<&Database>,
    ) -> Result<()> {
        let address = public_ip(remote);
        let location = address
            .zip(resolver)
            .and_then(|(ip, resolver)| resolver.lookup(ip).ok().flatten());
        let payload = location.as_ref().map(serde_json::to_string).transpose()?;
        let ip = address.map_or_else(String::new, |ip| ip.to_string());
        // A second lock after successful authorization must not consume a
        // snapshot's remaining lifetime. A later poll can refresh presence.
        self.db.busy_timeout(Duration::ZERO)?;
        let result = self.save_observation(peer, &ip, payload);
        self.db.busy_timeout(DB_BUSY_TIMEOUT)?;
        if result.as_ref().is_err_and(|error| {
            error
                .downcast_ref::<rusqlite::Error>()
                .is_some_and(|error| {
                    matches!(
                        error.sqlite_error_code(),
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        )
                    )
                })
        }) {
            return Ok(());
        }
        result
    }

    fn save_observation(
        &mut self,
        peer: &NodeCredential,
        ip: &str,
        payload: Option<String>,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        peer.binding(&tx, now)?;
        tx.execute(
            "INSERT INTO node_locations(node_id,automatic_json,observed_at,public_ip) VALUES(?,?,?,?)
             ON CONFLICT(node_id) DO UPDATE SET automatic_json=excluded.automatic_json,
               observed_at=excluded.observed_at,public_ip=excluded.public_ip
             WHERE excluded.observed_at>=node_locations.observed_at",
            params![peer.node.as_bytes(),payload,now,ip],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[derive(Serialize)]
struct NodeLocation {
    node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<Location>,
    source: String,
    observed_at_unix_seconds: i64,
    stale: bool,
    last_seen_unix_seconds: i64,
    online: bool,
    identity_active: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    public_ip: String,
}

pub(crate) fn inventory(
    tx: &Transaction<'_>,
    net: Id,
    now: i64,
    limit: usize,
    provider: Option<&str>,
) -> Result<Value> {
    ensure!(
        (1..=1000).contains(&limit),
        AccessError::Invalid("invalid limit")
    );
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?)",
        [net.as_bytes()],
        |r| r.get(0),
    )?;
    ensure!(exists, AccessError::Missing);
    let mut stmt = tx.prepare(
        "SELECT n.id,COALESCE(l.manual_json,l.automatic_json),
           CASE WHEN l.manual_json IS NOT NULL THEN 'manual' WHEN l.automatic_json IS NOT NULL THEN 'ip' ELSE 'unknown' END,
           CASE WHEN l.manual_json IS NOT NULL THEN l.manual_updated_at ELSE COALESCE(l.observed_at,0) END,
           COALESCE(l.observed_at,0),COALESCE(l.public_ip,''),
           n.revoked_at IS NULL AND (n.enrollment_class<>'ephemeral' OR COALESCE(n.lease_expires_at>?1,0))
             AND EXISTS(SELECT 1 FROM certificates c WHERE c.node_id=n.id AND c.network_id=n.network_id
                        AND c.revoked_at IS NULL AND c.not_before<=?1 AND c.not_after>?1)
         FROM nodes n LEFT JOIN node_locations l ON l.node_id=n.id
         WHERE n.network_id=?2 ORDER BY n.created_at,n.id LIMIT ?3"
    )?;
    let mut rows = stmt.query(params![now, net.as_bytes(), limit as i64])?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        let location = row
            .get::<_, Option<String>>(1)?
            .filter(|payload| !payload.is_empty())
            .map(|payload| serde_json::from_str::<Option<Location>>(&payload))
            .transpose()?
            .flatten();
        let source: String = row.get(2)?;
        let observed: i64 = row.get(3)?;
        let seen: i64 = row.get(4)?;
        let active: bool = row.get(6)?;
        output.push(NodeLocation {
            node_id: Id::new(row.get(0)?)?.to_string(),
            location,
            stale: source == "ip" && now.saturating_sub(observed) >= 86400,
            source,
            observed_at_unix_seconds: observed,
            last_seen_unix_seconds: seen,
            public_ip: row.get(5)?,
            identity_active: active,
            online: active && seen > 0 && now.saturating_sub(seen) < 360,
        });
    }
    Ok(
        json!({"node_locations":output, "automatic_enabled":provider.is_some(), "location_provider":provider.unwrap_or_default()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn city_lookup_uses_the_same_offline_fixture_as_go() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../go/internal/nodelocation/testdata/GeoIP2-City-Test.mmdb");
        let db = Database::open(&path).unwrap();
        assert_eq!(db.provider(), "maxmind");
        let data = db
            .lookup("::ffff:81.2.69.142".parse().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(data.label, "London, GB");
        assert!((51.0..52.0).contains(&data.latitude) && data.longitude < 0.0);
        for ip in ["1.1.1.1", "10.0.0.1", "::1"] {
            assert!(db.lookup(ip.parse().unwrap()).unwrap().is_none());
        }
        assert!(Database::open(&path.with_file_name("missing.mmdb")).is_err());
    }

    #[test]
    fn geography_excludes_private_and_transition_ranges() {
        for ip in ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(public_ip(ip.parse().unwrap()).is_some(), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "100.96.0.2",
            "169.254.1.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "0.1.2.3",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "64:ff9b::808:808",
            "::ffff:10.0.0.1",
        ] {
            assert!(public_ip(ip.parse().unwrap()).is_none(), "{ip}");
        }
    }
}
