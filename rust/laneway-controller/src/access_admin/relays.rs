//! Relay discovery and authority change together with their published epoch.
use super::{AccessError, conflict, next_id, subjects::Editor, validate_name};
use anyhow::{Context, Result, ensure};
use laneway_protocol::{
    Id,
    relay_endpoint::{MAX_RELAY_ENDPOINTS, canonical_host_port},
};
use rusqlite::{OptionalExtension, Row, params};
use serde::Serialize;
use serde_json::{Value, json};

const COLUMNS: &str = "id,service_id,node_id,name,endpoint,enabled,created_at";
struct Relay {
    id: [u8; 16],
    service: Option<[u8; 16]>,
    node: Option<[u8; 16]>,
    name: String,
    endpoint: String,
    enabled: bool,
    created: i64,
}

#[derive(Serialize)]
struct RelayView {
    relay_id: String,
    network_id: String,
    service_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_id: Option<String>,
    name: String,
    endpoint: String,
    enabled: bool,
    created_at_unix_seconds: i64,
    configuration_epoch: i64,
}

impl Relay {
    fn read(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            service: r.get(1)?,
            node: r.get(2)?,
            name: r.get(3)?,
            endpoint: r.get(4)?,
            enabled: r.get(5)?,
            created: r.get(6)?,
        })
    }
    fn view(self, net: Id, epoch: i64) -> Result<RelayView> {
        Ok(RelayView {
            relay_id: Id::new(self.id)?.to_string(),
            network_id: net.to_string(),
            service_id: Id::new(
                self.service
                    .context("legacy relay has no service identity")?,
            )?
            .to_string(),
            node_id: self.node.map(Id::new).transpose()?.map(|id| id.to_string()),
            name: self.name,
            endpoint: self.endpoint,
            enabled: self.enabled,
            created_at_unix_seconds: self.created,
            configuration_epoch: epoch,
        })
    }
}

impl Editor<'_, '_> {
    pub(super) fn list_relays(&self, limit: usize) -> Result<Value> {
        ensure!(
            (1..=1000).contains(&limit),
            AccessError::Invalid("invalid limit")
        );
        let epoch = self.current_epoch()?;
        let mut stmt = self.tx.prepare(&format!(
            "SELECT {COLUMNS} FROM relays WHERE network_id=? ORDER BY created_at,id LIMIT ?"
        ))?;
        let rows = stmt.query_map((self.net.as_bytes(), limit as i64), Relay::read)?;
        let mut relays = Vec::new();
        for row in rows {
            relays.push(row?.view(self.net, epoch)?);
        }
        Ok(json!({"relays":relays}))
    }

    fn relay(&self, id: Id) -> Result<Relay> {
        Ok(self
            .tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM relays WHERE id=? AND network_id=?"),
                (id.as_bytes(), self.net.as_bytes()),
                Relay::read,
            )
            .optional()?
            .ok_or(AccessError::Missing)?)
    }

    fn require_relay_capacity(&self) -> Result<()> {
        let count: i64 = self.tx.query_row(
            "SELECT count(*) FROM relays WHERE network_id=? AND enabled=1",
            [self.net.as_bytes()],
            |r| r.get(0),
        )?;
        ensure!(
            count < MAX_RELAY_ENDPOINTS as i64,
            AccessError::Invalid("network already has the maximum enabled relays")
        );
        Ok(())
    }

    pub(super) fn register_relay(
        &self,
        service: Id,
        node: Option<Id>,
        name: &str,
        endpoint: &str,
    ) -> Result<Value> {
        validate_name(name)?;
        let endpoint =
            canonical_host_port(endpoint).ok_or(AccessError::Invalid("invalid relay endpoint"))?;
        self.current_epoch()?;
        self.require_relay_capacity()?;
        if let Some(id) = node {
            let found: bool = self.tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes
                 WHERE id=? AND network_id=? AND revoked_at IS NULL)",
                (id.as_bytes(), self.net.as_bytes()),
                |r| r.get(0),
            )?;
            ensure!(found, AccessError::Missing);
        }
        let id = next_id()?;
        conflict(self.tx.execute(
            "INSERT INTO relays(id,network_id,service_id,node_id,name,endpoint,enabled,created_at) VALUES(?,?,?,?,?,?,1,?)",
            params![id.as_bytes(),self.net.as_bytes(),service.as_bytes(),node.as_ref().map(Id::as_bytes),name,endpoint,self.now],
        ))?;
        let epoch = self.record(
            "relay.register",
            "relay",
            id,
            json!({"service_id":service.to_string()}),
        )?;
        Ok(serde_json::to_value(
            self.relay(id)?.view(self.net, epoch)?,
        )?)
    }

    pub(super) fn update_relay(
        &self,
        id: Id,
        name: &str,
        endpoint: &str,
        enabled: bool,
    ) -> Result<Value> {
        validate_name(name)?;
        let endpoint =
            canonical_host_port(endpoint).ok_or(AccessError::Invalid("invalid relay endpoint"))?;
        let previous = self.relay(id)?;
        ensure!(previous.service.is_some(), AccessError::Conflict);
        if enabled && !previous.enabled {
            self.require_relay_capacity()?;
        }
        ensure!(
            previous.name != name || previous.endpoint != endpoint || previous.enabled != enabled,
            AccessError::Conflict
        );
        conflict(self.tx.execute(
            "UPDATE relays SET name=?,endpoint=?,enabled=? WHERE id=?",
            params![name, endpoint, enabled, id.as_bytes()],
        ))?;
        let epoch = self.record(
            "relay.update",
            "relay",
            id,
            json!({"name":name, "endpoint":endpoint, "enabled":enabled}),
        )?;
        Ok(serde_json::to_value(
            self.relay(id)?.view(self.net, epoch)?,
        )?)
    }

    pub(super) fn disable_relay(&self, id: Id) -> Result<i64> {
        let changed = self.tx.execute(
            "UPDATE relays SET enabled=0 WHERE id=? AND enabled=1",
            [id.as_bytes()],
        )?;
        ensure!(changed == 1, AccessError::Conflict);
        self.record("relay.disable", "relay", id, json!({}))
    }
}
