//! One controller-timed observation per authenticated node, no history.
use crate::{
    SessionStore, access_admin::AccessError, check_snapshot, enrollment::renewal::NodeCredential,
};
use anyhow::{Context, Result, ensure};
use laneway_protocol::{
    Id,
    endpoint_status::{Carrier, Certificate, Configuration, Platform, Report, Route, SelectedExit},
};
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde_json::{Value, json};

impl SessionStore {
    pub fn record_endpoint_status(
        &mut self,
        peer: &NodeCredential,
        mut report: Report,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_snapshot(&tx)?;
        let now: i64 = tx.query_row("SELECT unixepoch()", [], |r| r.get(0))?;
        // Revalidate after reading the HTTP body so a revoked leaf cannot
        // update health on an already authenticated connection.
        peer.binding(&tx, now)?;
        report.validate().map_err(AccessError::Invalid)?;
        let epoch = network_epoch(&tx, peer.net)?;
        let reported = report.configuration_epoch as i64;
        ensure!(reported <= epoch, AccessError::Conflict);
        if reported < epoch {
            report.configuration_state = Configuration::Stale;
        }
        let expires = now
            .checked_add(i64::from(report.valid_for_seconds))
            .context("invalid endpoint expiry")?;
        let changed = tx.execute(
            "INSERT INTO endpoint_status_latest(node_id,network_id,observed_at,expires_at,valid_for_seconds,
               product_version,platform,certificate_state,configuration_state,carrier_state,route_state,
               selected_exit_state,cleanup_failure_count,configuration_epoch)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(node_id) DO UPDATE SET
               observed_at=excluded.observed_at,expires_at=excluded.expires_at,
               valid_for_seconds=excluded.valid_for_seconds,product_version=excluded.product_version,
               platform=excluded.platform,certificate_state=excluded.certificate_state,
               configuration_state=excluded.configuration_state,carrier_state=excluded.carrier_state,
               route_state=excluded.route_state,selected_exit_state=excluded.selected_exit_state,
               cleanup_failure_count=excluded.cleanup_failure_count,configuration_epoch=excluded.configuration_epoch
             WHERE excluded.observed_at >= endpoint_status_latest.observed_at",
            params![peer.node.as_bytes(),peer.net.as_bytes(),now,expires,report.valid_for_seconds,
                report.product_version,report.platform.as_str(),report.certificate_state.as_str(),
                report.configuration_state.as_str(),report.carrier_state.as_str(),report.route_state.as_str(),
                report.selected_exit_state.as_str(),report.cleanup_failure_count,reported],
        )?;
        ensure!(changed == 1, AccessError::Conflict);
        tx.commit()?;
        Ok(())
    }
}

fn network_epoch(tx: &Transaction<'_>, net: Id) -> Result<i64> {
    Ok(tx
        .query_row(
            "SELECT configuration_epoch FROM networks WHERE id=?",
            [net.as_bytes()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(AccessError::Missing)?)
}

#[derive(Serialize)]
struct Status {
    node_id: String,
    network_id: String,
    node_name: String,
    authoritative_configuration_epoch: i64,
    freshness: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_reported_at_unix_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_unix_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<Report>,
}

pub(crate) fn inventory(tx: &Transaction<'_>, net: Id, limit: usize, now: i64) -> Result<Value> {
    ensure!(
        (1..=1000).contains(&limit),
        AccessError::Invalid("invalid limit")
    );
    let epoch = network_epoch(tx, net)?;
    let network_id = net.to_string();
    let mut stmt = tx.prepare(
        "SELECT n.id,n.name,n.revoked_at,n.enrollment_class,n.lease_expires_at,
           s.observed_at,s.expires_at,s.valid_for_seconds,s.product_version,s.platform,
           s.certificate_state,s.configuration_state,s.carrier_state,s.route_state,
           s.selected_exit_state,s.cleanup_failure_count,s.configuration_epoch,
           EXISTS(SELECT 1 FROM certificates c WHERE c.node_id=n.id AND c.network_id=n.network_id
               AND c.revoked_at IS NULL AND c.not_before<=?1 AND c.not_after>?1)
         FROM nodes n LEFT JOIN endpoint_status_latest s ON s.node_id=n.id AND s.network_id=n.network_id
         WHERE n.network_id=?2 ORDER BY n.created_at,n.id LIMIT ?3"
    )?;
    let mut rows = stmt.query(params![now, net.as_bytes(), limit as i64])?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        let observed: Option<i64> = row.get(5)?;
        let expires: Option<i64> = row.get(6)?;
        let validity: Option<u32> = row.get(7)?;
        match (observed, expires, validity) {
            (Some(o), Some(e), Some(valid)) => ensure!(
                (10..=300).contains(&valid) && o.checked_add(i64::from(valid)) == Some(e),
                "corrupt endpoint status TTL"
            ),
            (None, None, None) => {}
            _ => anyhow::bail!("corrupt endpoint status timestamps"),
        }
        let revoked: Option<i64> = row.get(2)?;
        let has_certificate: bool = row.get(17)?;
        let lease: Option<i64> = row.get(4)?;
        let inactive = revoked.is_some()
            || !has_certificate
            || (row.get_ref(3)?.as_str()? == "ephemeral" && lease.is_none_or(|lease| now >= lease));
        let (freshness, report) = match (inactive, expires) {
            (true, _) => ("node_inactive", None),
            (false, None) => ("never_reported", None),
            (false, Some(end)) if now >= end => ("expired", None),
            (false, Some(_)) => ("current", Some(read_report(row, epoch)?)),
        };
        output.push(Status {
            node_id: Id::new(row.get(0)?)?.to_string(),
            network_id: network_id.clone(),
            node_name: row.get(1)?,
            authoritative_configuration_epoch: epoch,
            freshness,
            last_reported_at_unix_seconds: observed,
            expires_at_unix_seconds: expires,
            report,
        });
    }
    Ok(json!({"endpoint_statuses":output}))
}

fn read_state<T>(row: &Row<'_>, column: usize, parse: impl FnOnce(&str) -> Option<T>) -> Result<T> {
    parse(row.get_ref(column)?.as_str()?).context("corrupt endpoint status state")
}

fn read_report(row: &Row<'_>, current_epoch: i64) -> Result<Report> {
    let mut report = Report {
        valid_for_seconds: row.get(7)?,
        product_version: row.get(8)?,
        platform: read_state(row, 9, Platform::from_wire)?,
        certificate_state: read_state(row, 10, Certificate::from_wire)?,
        configuration_state: read_state(row, 11, Configuration::from_wire)?,
        carrier_state: read_state(row, 12, Carrier::from_wire)?,
        route_state: read_state(row, 13, Route::from_wire)?,
        selected_exit_state: read_state(row, 14, SelectedExit::from_wire)?,
        cleanup_failure_count: row.get(15)?,
        configuration_epoch: row.get::<_, i64>(16)?.try_into()?,
    };
    report.validate().map_err(anyhow::Error::msg)?;
    ensure!(
        report.configuration_epoch as i64 <= current_epoch,
        "corrupt endpoint status epoch"
    );
    if (report.configuration_epoch as i64) < current_epoch {
        report.configuration_state = Configuration::Stale;
    }
    Ok(report)
}
