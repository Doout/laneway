use super::{
    AccessError, Actor, Subject, Target, change, conflict, epoch_reply, inventory, next_id,
    validate_name,
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::{Value, json};

pub(super) struct Editor<'a, 'c> {
    pub(super) tx: &'a Transaction<'c>,
    pub(super) net: Id,
    pub(super) actor: Actor,
    pub(super) now: i64,
}
pub(super) struct ResolvedSubject {
    pub id: Id,
    pub kind: &'static str,
    pub user: Option<Id>,
    pub team: Option<Id>,
}
impl Editor<'_, '_> {
    pub(super) fn create_subject(&self, name: &str, team: bool) -> Result<Value> {
        validate_name(name)?;
        let id = next_id()?;
        let (stmt, kind, action, key) = if team {
            (
                "INSERT INTO access_teams(id,network_id,name,created_at,updated_at) VALUES(?1,?2,?3,?4,?4)",
                "access_team",
                "access_team.create",
                "team_id",
            )
        } else {
            (
                "INSERT INTO access_users(id,network_id,name,created_at,updated_at) VALUES(?1,?2,?3,?4,?4)",
                "access_user",
                "access_user.create",
                "user_id",
            )
        };
        conflict(
            self.tx
                .execute(stmt, (id.as_bytes(), self.net.as_bytes(), name, self.now)),
        )?;
        self.record(action, kind, id, json!({}))?;
        let mut user = json!({"network_id":self.net.to_string(),"name":name,"created_at_unix_seconds":self.now,"updated_at_unix_seconds":self.now});
        user[key] = json!(id.to_string());
        if !team {
            user["enabled"] = json!(true)
        }
        Ok(user)
    }

    pub(super) fn set_user_enabled(&self, id: Id, on: bool) -> Result<Value> {
        let old: bool = self.tx.query_row(
            "SELECT enabled FROM access_users WHERE id=? AND network_id=?",
            (id.as_bytes(), self.net.as_bytes()),
            |r| r.get(0),
        )?;
        self.tx.execute(
            "UPDATE access_users SET enabled=?1,updated_at=?2 WHERE id=?3 AND network_id=?4",
            (on, self.now, id.as_bytes(), self.net.as_bytes()),
        )?;
        if old != on {
            self.record(
                "access_user.update",
                "access_user",
                id,
                json!({"enabled":on}),
            )?;
        }
        let mut stmt=self.tx.prepare("SELECT id,name,enabled,created_at,updated_at FROM access_users WHERE id=? AND network_id=?")?;
        let mut rows = stmt.query((id.as_bytes(), self.net.as_bytes()))?;
        inventory::user(rows.next()?.ok_or(AccessError::Missing)?, self.net)
    }

    pub(super) fn member(&self, team: Id, user: Id, present: bool) -> Result<Value> {
        let parent = self
            .tx
            .query_row(
                "SELECT network_id FROM access_users WHERE id=?",
                [user.as_bytes()],
                |r| r.get::<_, [u8; 16]>(0),
            )
            .optional()?
            .ok_or(AccessError::Missing)?;
        ensure!(
            Id::new(parent)? == self.net,
            AccessError::Invalid("team and user must belong to the same network")
        );
        let changed = if present {
            self.tx.execute("INSERT INTO access_team_members(network_id,team_id,user_id,created_at) VALUES(?,?,?,?)
                ON CONFLICT(team_id,user_id) DO NOTHING",(self.net.as_bytes(),team.as_bytes(),user.as_bytes(),self.now))?
        } else {
            self.tx.execute(
                "DELETE FROM access_team_members WHERE network_id=? AND team_id=? AND user_id=?",
                (self.net.as_bytes(), team.as_bytes(), user.as_bytes()),
            )?
        };
        let epoch = if changed == 1 {
            self.record(
                "access_team.member",
                "access_team",
                team,
                json!({"user_id":user.to_string(),"present":present}),
            )?
        } else {
            self.tx.query_row(
                "SELECT configuration_epoch FROM networks WHERE id=?",
                [self.net.as_bytes()],
                |r| r.get(0),
            )?
        };
        Ok(epoch_reply(epoch))
    }

    pub(super) fn grant(&self, subject: Subject, target: Target) -> Result<Value> {
        let ResolvedSubject {
            id: subject_id,
            kind,
            user,
            team,
        } = self.resolve_subject(subject)?;
        let (target_kind, node) = match target {
            Target::Network => ("network", None),
            Target::Node(id) => ("node", Some(id)),
            Target::Exit(id) => ("exit", Some(id)),
        };
        if let Some(node) = node {
            self.live_node(node)?;
            if matches!(target, Target::Exit(_)) {
                let live:bool=self.tx.query_row("SELECT EXISTS(SELECT 1 FROM routes WHERE node_id=? AND network_id=? AND state='approved' AND kind='exit'
                    AND (valid_until IS NULL OR valid_until>?))",(node.as_bytes(),self.net.as_bytes(),self.now),|r|r.get(0))?;
                ensure!(
                    live,
                    AccessError::Invalid("exit grant target has no approved Exit route")
                );
            }
        }
        let grant = next_id()?;
        conflict(self.tx.execute("INSERT INTO access_grants(id,network_id,subject_kind,user_id,team_id,target_kind,node_id,created_at)
            VALUES(?,?,?,?,?,?,?,?)",params![grant.as_bytes(),self.net.as_bytes(),kind,user.as_ref().map(Id::as_bytes),
                team.as_ref().map(Id::as_bytes),target_kind,node.as_ref().map(Id::as_bytes),self.now]))?;
        self.record("access_grant.create", "access_grant", grant, json!({}))?;
        let mut result = json!({"grant_id":grant.to_string(),"network_id":self.net.to_string(),"subject_kind":kind,
            "subject_id":subject_id.to_string(),"target_kind":target_kind,"created_at_unix_seconds":self.now});
        if let Some(node) = node {
            result["node_id"] = json!(node.to_string())
        }
        Ok(result)
    }

    pub(super) fn delete_grant(&self, id: Id) -> Result<Value> {
        ensure!(
            self.tx.execute(
                "DELETE FROM access_grants WHERE id=? AND network_id=?",
                (id.as_bytes(), self.net.as_bytes())
            )? == 1,
            AccessError::Missing
        );
        Ok(epoch_reply(self.record(
            "access_grant.delete",
            "access_grant",
            id,
            json!({}),
        )?))
    }

    pub(super) fn live_node(&self, node: Id) -> Result<()> {
        let live: bool = self.tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL
            AND (lease_expires_at IS NULL OR lease_expires_at>?))",
            (node.as_bytes(), self.net.as_bytes(), self.now),
            |r| r.get(0),
        )?;
        ensure!(live, AccessError::Missing);
        Ok(())
    }
    pub(super) fn resolve_subject(&self, subject: Subject) -> Result<ResolvedSubject> {
        Ok(match subject {
            Subject::User(id) => {
                self.require("SELECT 1 FROM access_users WHERE id=? AND network_id=?", id)?;
                ResolvedSubject {
                    id,
                    kind: "user",
                    user: Some(id),
                    team: None,
                }
            }
            Subject::Team(id) => {
                self.require("SELECT 1 FROM access_teams WHERE id=? AND network_id=?", id)?;
                ResolvedSubject {
                    id,
                    kind: "team",
                    user: None,
                    team: Some(id),
                }
            }
        })
    }
    pub(super) fn require(&self, sql: &str, id: Id) -> Result<()> {
        self.tx
            .query_row(sql, (id.as_bytes(), self.net.as_bytes()), |_| Ok(()))
            .optional()?
            .ok_or(AccessError::Missing)?;
        Ok(())
    }
    pub(super) fn current_epoch(&self) -> Result<i64> {
        Ok(self
            .tx
            .query_row(
                "SELECT configuration_epoch FROM networks WHERE id=?",
                [self.net.as_bytes()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(AccessError::Missing)?)
    }
    pub(super) fn record(&self, action: &str, kind: &str, id: Id, details: Value) -> Result<i64> {
        change(
            self.tx,
            self.net,
            &self.actor,
            self.now,
            action,
            (kind, id),
            details,
        )
    }
}
