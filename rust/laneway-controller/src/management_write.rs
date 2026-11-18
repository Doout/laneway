//! Common authentication boundary for native management writes. The caller
//! still has to authorize the specific operation and target inside the closure.
use crate::{
    RootCredential, SessionError, SessionReply, SessionStore, bearer, check_snapshot,
    sessions::csrf_digest,
};
use anyhow::{Result, ensure};
use laneway_protocol::Id;
use rusqlite::{Transaction, TransactionBehavior};
use subtle::ConstantTimeEq;

pub(crate) enum BrowserWrite {
    CreateNetwork,
    IssueEnrollment,
    ManageAccess,
}

impl SessionStore {
    pub fn deny_root_only_session<T>(&mut self, token: &str) -> Result<T> {
        self.with_session(token, false, |_, _, _, _, _| {
            Err(SessionError::Denied.into())
        })
        .map(|reply| reply.list)
    }

    pub(crate) fn root_write<T>(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        write: impl FnOnce(&Transaction<'_>, Id, i64) -> Result<T>,
    ) -> Result<T> {
        self.bearer_write(header, root, |tx, actor, now| {
            actor.require_root()?;
            write(tx, actor.id, now)
        })
    }

    pub(crate) fn browser_write<T>(
        &mut self,
        token: &str,
        csrf: Option<&str>,
        operation: BrowserWrite,
        write: impl FnOnce(&Transaction<'_>, Id, bool, i64) -> Result<T>,
    ) -> Result<SessionReply<T>> {
        self.with_session(token,true,|tx,principal,session,all,now|{
            let proof=csrf.and_then(|s| csrf_digest(s).ok()).ok_or(SessionError::Denied)?;
            let (role,stored):(String,[u8;32])=tx.query_row(
                "SELECT p.role,s.csrf_hash FROM administrator_sessions s JOIN administrator_principals p ON p.id=s.principal_id WHERE s.id=?1",
                [session.as_bytes()],|r|Ok((r.get(0)?,r.get(1)?)))?;
            ensure!(bool::from(stored.ct_eq(&proof)),SessionError::Denied);
            ensure!(role=="owner" || (role=="operator" && matches!(operation,BrowserWrite::IssueEnrollment | BrowserWrite::ManageAccess)),SessionError::Denied);
            write(tx,principal,all,now)
        })
    }
    pub(crate) fn bearer_write<T>(
        &mut self,
        header: &str,
        root: Option<&RootCredential>,
        write: impl FnOnce(&Transaction<'_>, bearer::BearerActor, i64) -> Result<T>,
    ) -> Result<T> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let actor = bearer::authenticate(&tx, header, root)?;
        let now = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        let result = write(&tx, actor, now)?;
        tx.commit()?;
        Ok(result)
    }
}
