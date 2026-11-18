use super::{AccessError, AclSelector, epoch_reply, next_id, row_id, subjects::Editor};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

const MAX_SELECTOR_BYTES: usize = 16 << 10;
pub struct AclRule {
    pub priority: u32,
    pub action: String,
    pub selector: AclSelector,
    pub description: String,
    pub enabled: bool,
}

impl Editor<'_, '_> {
    pub(super) fn list_acl_rules(&self, limit: usize) -> Result<Value> {
        ensure!(
            (1..=1000).contains(&limit),
            AccessError::Invalid("invalid limit")
        );
        let epoch = self.acl_epoch()?;
        let mut stmt = self.tx.prepare(
            "SELECT id,priority,action,selector_json,description,enabled FROM acl_rules
            WHERE network_id=? ORDER BY priority,id LIMIT ?",
        )?;
        let mut rows = stmt.query((self.net.as_bytes(), limit as i64))?;
        let mut result = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let raw: String = row.get(3)?;
            // Administrative inventory retains imported rows even if a newer
            // compiler would reject the selector. An admin can still fix them.
            let description: String = row.get(4)?;
            bytes += raw.len() + description.len() + 256;
            ensure!(bytes <= 20 << 20, "ACL inventory exceeds response limit");
            result.push(json!({"rule_id":row_id(row,0)?.to_string(),"network_id":self.net.to_string(),"priority":row.get::<_,u32>(1)?,
                "action":row.get::<_,String>(2)?,"selector":serde_json::from_str::<Value>(&raw)?,
                "description":description,"enabled":row.get::<_,bool>(5)?,"configuration_epoch":epoch}));
        }
        Ok(json!({"acl_rules":result}))
    }

    fn acl_epoch(&self) -> Result<i64> {
        Ok(self
            .tx
            .query_row(
                "SELECT configuration_epoch FROM networks WHERE id=?",
                [self.net.as_bytes()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(AccessError::Missing)?)
    }

    pub(super) fn write_acl_rule(&self, id: Option<Id>, rule: AclRule) -> Result<Value> {
        ensure!(
            matches!(rule.action.as_str(), "accept" | "deny"),
            AccessError::Invalid("action must be accept or deny")
        );
        ensure!(
            rule.description.len() <= 1024 && !rule.description.contains('\0'),
            AccessError::Invalid("invalid ACL description")
        );
        let selector = rule
            .selector
            .canonical_management_json()
            .map_err(|_| AccessError::Invalid("invalid ACL selector"))?;
        let stored = serde_json::to_string(&selector)?;
        ensure!(
            stored.len() <= MAX_SELECTOR_BYTES,
            AccessError::Invalid("ACL selector exceeds limit")
        );
        let (id, on, epoch) = if let Some(id) = id {
            ensure!(self.tx.execute("UPDATE acl_rules SET priority=?1,action=?2,selector_json=?3,description=?4,enabled=?5,updated_at=?6
                WHERE id=?7 AND network_id=?8",(rule.priority,&rule.action,&stored,&rule.description,rule.enabled,self.now,id.as_bytes(),self.net.as_bytes()))?==1,AccessError::Missing);
            (
                id,
                rule.enabled,
                self.record(
                    "acl_rule.update",
                    "acl_rule",
                    id,
                    json!({"enabled":rule.enabled}),
                )?,
            )
        } else {
            self.acl_epoch()?;
            let id = next_id()?;
            self.tx.execute("INSERT INTO acl_rules(id,network_id,priority,action,selector_json,description,enabled,created_at,updated_at)
                VALUES(?1,?2,?3,?4,?5,?6,1,?7,?7)",(id.as_bytes(),self.net.as_bytes(),rule.priority,&rule.action,&stored,&rule.description,self.now))?;
            (
                id,
                true,
                self.record("acl_rule.create", "acl_rule", id, json!({}))?,
            )
        };
        Ok(
            json!({"rule_id":id.to_string(),"network_id":self.net.to_string(),"priority":rule.priority,"action":rule.action,
            "selector":selector,"description":rule.description,"enabled":on,"configuration_epoch":epoch}),
        )
    }

    pub(super) fn delete_acl_rule(&self, id: Id) -> Result<Value> {
        ensure!(
            self.tx.execute(
                "DELETE FROM acl_rules WHERE id=? AND network_id=?",
                (id.as_bytes(), self.net.as_bytes())
            )? == 1,
            AccessError::Missing
        );
        Ok(epoch_reply(self.record(
            "acl_rule.delete",
            "acl_rule",
            id,
            json!({}),
        )?))
    }
}
