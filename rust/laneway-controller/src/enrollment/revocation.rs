use super::{EnrollError, configuration::clock, renewal::NodeCredential};
use crate::{SessionStore, check_snapshot};
use anyhow::{Result, ensure};
use laneway_protocol::{Id, v1::CertificateRevocation};
use rusqlite::OptionalExtension;

pub enum RevocationStatus {
    Missing,
    NotRevoked,
    Revoked(CertificateRevocation),
}

impl SessionStore {
    pub fn certificate_revocation(
        &mut self,
        peer: &NodeCredential,
        serial: Option<Vec<u8>>,
    ) -> Result<RevocationStatus> {
        let tx = self.db.transaction()?;
        check_snapshot(&tx)?;
        peer.binding(&tx, clock(&tx)?)?;
        let serial = serial.ok_or(EnrollError::Malformed("invalid certificate serial"))?;
        ensure!(
            (1..=32).contains(&serial.len()),
            EnrollError::Malformed("invalid certificate serial")
        );
        let record: Option<([u8; 16], Option<i64>, String)> = tx.query_row(
            "SELECT node_id,revoked_at,revocation_reason FROM certificates WHERE network_id=? AND serial=?",
            (peer.net.as_bytes(), &serial), |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional()?;
        let status = match record {
            None => RevocationStatus::Missing,
            Some((_, None, _)) => RevocationStatus::NotRevoked,
            Some((node, Some(revoked), reason)) => {
                RevocationStatus::Revoked(CertificateRevocation {
                    certificate_serial: serial,
                    node_id: Id::new(node)?.as_bytes().to_vec(),
                    revoked_unix_seconds: revoked.try_into()?,
                    reason,
                })
            }
        };
        tx.commit()?;
        Ok(status)
    }
}
