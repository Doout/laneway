//! The same durable manual ACL checkpoints as the Go fleet controller.
use super::{AccessError, conflict, epoch_reply, row_id, subjects::Editor};
use crate::{enrollment::snapshot_policy, schema};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};

const MAX_RULES: usize = 4096;
const MAX_REVISION: usize = 4 << 20;
const MAX_HISTORY: usize = 8 << 20;

#[derive(Serialize, Deserialize)]
struct Entry {
    rule_id: String,
    priority: u32,
    action: String,
    selector: Box<RawValue>,
    description: String,
    enabled: bool,
}

impl Editor<'_, '_> {
    pub(super) fn capture_policy(&self) -> Result<()> {
        let epoch = self.current_epoch()?;
        let exists: bool = self.tx.query_row("SELECT EXISTS(SELECT 1 FROM policy_revisions WHERE network_id=? AND configuration_epoch=?)", (self.net.as_bytes(), epoch), |r|r.get(0))?;
        if exists {
            return Ok(());
        }
        let mut statement = self.tx.prepare("SELECT id,priority,action,selector_json,description,enabled FROM acl_rules WHERE network_id=? ORDER BY priority,id LIMIT 4097")?;
        let mut rows = statement.query([self.net.as_bytes()])?;
        let mut rules = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let selector: String = row.get(3)?;
            let description: String = row.get(4)?;
            bytes += selector.len() + description.len() + 256;
            ensure!(
                rules.len() < MAX_RULES && bytes <= MAX_REVISION,
                "policy revision exceeds storage limit"
            );
            rules.push(Entry {
                rule_id: row_id(row, 0)?.to_string(),
                priority: row.get(1)?,
                action: row.get(2)?,
                selector: RawValue::from_string(selector)?,
                description,
                enabled: row.get(5)?,
            });
        }
        let raw = serde_json::to_string(&rules)?;
        ensure!(
            raw.len() <= MAX_REVISION,
            "policy revision exceeds storage limit"
        );
        self.tx.execute("INSERT INTO policy_revisions(network_id,revision,configuration_epoch,rules_json,created_at)
            SELECT ?1,coalesce(max(revision),0)+1,?2,?3,?4 FROM policy_revisions WHERE network_id=?1
            ON CONFLICT(network_id,configuration_epoch) DO NOTHING",
            params![self.net.as_bytes(), epoch, raw, self.now])?;
        Ok(())
    }

    pub(super) fn policy_history(&self, limit: usize) -> Result<Value> {
        ensure!(schema::is_fleet(self.tx)?, AccessError::Missing);
        ensure!(
            (1..=1000).contains(&limit),
            AccessError::Invalid("invalid limit")
        );
        self.current_epoch()?;
        let mut statement = self.tx.prepare(
            "SELECT revision,configuration_epoch,rules_json,created_at
            FROM policy_revisions WHERE network_id=? ORDER BY revision DESC LIMIT ?",
        )?;
        let mut rows = statement.query((self.net.as_bytes(), limit as i64))?;
        let mut revisions = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let raw: String = row.get(2)?;
            bytes += raw.len() + 128;
            ensure!(
                raw.len() <= MAX_REVISION && bytes <= MAX_HISTORY,
                "policy history exceeds response limit"
            );
            let rules: Vec<Entry> = serde_json::from_str(&raw)?;
            ensure!(
                rules.len() <= MAX_RULES,
                "policy revision exceeds rule limit"
            );
            revisions.push(json!({ "revision": row.get::<_, i64>(0)?, "configuration_epoch": row.get::<_, i64>(1)?,
                "created_at_unix_seconds": row.get::<_, i64>(3)?, "rules": rules }));
        }
        Ok(json!({"revisions":revisions,"scope":"manual_acl"}))
    }

    pub(super) fn restore_policy(&self, revision: i64, expected_epoch: i64) -> Result<Value> {
        ensure!(schema::is_fleet(self.tx)?, AccessError::Missing);
        ensure!(
            revision > 0 && expected_epoch > 0,
            AccessError::Invalid("revision and expected epoch must be positive")
        );
        let current = self.current_epoch()?;
        ensure!(
            expected_epoch == current && current < i64::MAX,
            AccessError::Conflict
        );
        let raw: String = self
            .tx
            .query_row(
                "SELECT rules_json FROM policy_revisions WHERE network_id=? AND revision=?",
                (self.net.as_bytes(), revision),
                |r| r.get(0),
            )
            .optional()?
            .ok_or(AccessError::Missing)?;
        ensure!(
            raw.len() <= MAX_REVISION,
            "policy revision exceeds storage limit"
        );
        let rules: Vec<Entry> = serde_json::from_str(&raw)?;
        ensure!(
            rules.len() <= MAX_RULES,
            "policy revision exceeds rule limit"
        );
        self.capture_policy()?;
        ensure!(self.tx.execute("UPDATE networks SET configuration_epoch=configuration_epoch+1 WHERE id=? AND configuration_epoch=?",
            (self.net.as_bytes(), expected_epoch))? == 1, AccessError::Conflict);
        self.tx.execute(
            "DELETE FROM acl_rules WHERE network_id=?",
            [self.net.as_bytes()],
        )?;
        for entry in rules {
            let id: Id = entry
                .rule_id
                .parse()
                .map_err(|_| AccessError::Invalid("invalid saved ACL identity"))?;
            let selector = entry.selector.get();
            ensure!(
                matches!(entry.action.as_str(), "accept" | "deny")
                    && entry.description.len() <= 1024
                    && !entry.description.contains('\0')
                    && (2..=16384).contains(&selector.len()),
                AccessError::Invalid("invalid saved ACL rule")
            );
            conflict(self.tx.execute("INSERT INTO acl_rules(id,network_id,priority,action,selector_json,description,enabled,created_at,updated_at)
                VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)", params![id.as_bytes(), self.net.as_bytes(), entry.priority,
                entry.action, selector, entry.description, entry.enabled, self.now]))?;
        }
        let epoch = current + 1;
        // Compile exactly what will go to nodes before any change commits.
        snapshot_policy::compile(self.tx, self.net, epoch.try_into()?)
            .map_err(|_| AccessError::Invalid("saved ACL policy is not valid"))?;
        self.capture_policy()?;
        self.tx.execute("INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
            VALUES(randomblob(16),?1,?2,?3,'policy.restore','network',NULL,?4,?5)",
            params![self.net.as_bytes(), self.actor.kind, self.actor.id.as_bytes(),
                json!({"restored_revision":revision,"previous_configuration_epoch":current,"configuration_epoch":epoch}).to_string(), self.now])?;
        Ok(epoch_reply(epoch))
    }
}
