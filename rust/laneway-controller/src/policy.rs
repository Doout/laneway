//! Durable authorization included in controller configuration snapshots.

mod revocation;

use std::cmp::Ordering;

use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::{
    DEFAULT_MAX_CONTROL_PAYLOAD, Id, certificate_serial_from_der,
    v1::{CertificateHealth, ConfigurationLease, PolicyAction, PolicyRule, PolicySnapshot},
};
use prost::{Message, length_delimiter_len};
use rusqlite::{Connection, params};
use x509_parser::parse_x509_certificate;

use crate::acl_admin::decode_selector_json;

pub(crate) use revocation::revocation_response;

pub(crate) enum EpochGate {
    Full,
    Unchanged(ConfigurationLease),
    Ahead,
}

pub(crate) fn epoch_gate(known: u64, current: u64, deadline: u64) -> EpochGate {
    match known.cmp(&current) {
        Ordering::Less => EpochGate::Full,
        Ordering::Equal => EpochGate::Unchanged(ConfigurationLease {
            configuration_epoch: current,
            valid_until_unix_seconds: deadline,
        }),
        Ordering::Greater => EpochGate::Ahead,
    }
}

// Each nested entry has a one-byte field tag and a length varint. ACL rules
// also have a mandatory 16-byte ID. These minimum sizes bound SQLite's result
// set without excluding entries that can fit on the wire.
const MIN_RULE_BYTES: usize = 1 + 1 + 1 + 1 + 16;
const MIN_SERIAL_BYTES: usize = 1 + 1 + 1;

fn account_entry(total: &mut usize, len: usize, resource: &'static str) -> Result<()> {
    *total += 1 + length_delimiter_len(len) + len;
    ensure!(
        *total <= DEFAULT_MAX_CONTROL_PAYLOAD,
        "{resource} exceeds snapshot wire limit"
    );
    Ok(())
}

pub(crate) fn policy_snapshot(db: &Connection, network: Id, epoch: u64) -> Result<PolicySnapshot> {
    let mut statement = db.prepare(
        "SELECT id, priority, action, selector_json, description
         FROM acl_rules WHERE network_id=?1 AND enabled=1 ORDER BY priority ASC, id ASC LIMIT ?2",
    )?;
    let mut rows = statement.query(params![
        network.as_bytes(),
        DEFAULT_MAX_CONTROL_PAYLOAD / MIN_RULE_BYTES + 1
    ])?;
    let mut policy = PolicySnapshot {
        network_id: network.as_bytes().to_vec(),
        configuration_epoch: epoch,
        rules: Vec::new(),
        default_action: PolicyAction::Deny as i32,
    };
    let mut wire_size = policy.encoded_len();
    while let Some(row) = rows.next()? {
        let raw: Vec<u8> = row.get(0)?;
        let id = Id::from_slice(&raw).context("invalid stored ACL rule ID")?;
        let action = match row.get::<_, String>(2)?.as_str() {
            "accept" => PolicyAction::Accept,
            "deny" => PolicyAction::Deny,
            _ => bail!("invalid stored ACL rule action"),
        };
        let selector_json: String = row.get(3)?;
        let selector =
            decode_selector_json(&selector_json).context("decode stored ACL selector")?;
        let rule = PolicyRule {
            rule_id: id.as_bytes().to_vec(),
            priority: row.get(1)?,
            action: action as i32,
            selector: Some(selector),
            description: row.get(4)?,
        };
        account_entry(&mut wire_size, rule.encoded_len(), "ACL policy")?;
        policy.rules.push(rule);
    }
    Ok(policy)
}

pub(crate) fn revoked_serials(db: &Connection, network: Id, now: i64) -> Result<Vec<Vec<u8>>> {
    let mut statement = db.prepare(
        "SELECT serial FROM certificates
         WHERE network_id=?1 AND revoked_at IS NOT NULL AND not_after>?2 ORDER BY serial LIMIT ?3",
    )?;
    let mut rows = statement.query(params![
        network.as_bytes(),
        now,
        DEFAULT_MAX_CONTROL_PAYLOAD / MIN_SERIAL_BYTES + 1,
    ])?;
    let mut serials = Vec::new();
    let mut wire_size = 0;
    while let Some(row) = rows.next()? {
        let serial: Vec<u8> = row.get(0)?;
        ensure!(
            (1..=32).contains(&serial.len()) && serial[0] != 0,
            "stored certificate has a noncanonical serial"
        );
        account_entry(&mut wire_size, serial.len(), "certificate revocations")?;
        serials.push(serial);
    }
    Ok(serials)
}

pub(crate) fn certificate_health(der: &[u8], revoked: &[Vec<u8>]) -> Result<CertificateHealth> {
    let (not_before, not_after) = certificate_times(der)?;
    ensure!(
        not_after > not_before,
        "invalid certificate validity window"
    );
    let duration = i128::from(not_after) - i128::from(not_before);
    let renew_after = i128::from(not_before) + duration * 2 / 3;
    let presented_serial = certificate_serial_from_der(der)?;
    Ok(CertificateHealth {
        revoked: revoked.contains(&presented_serial),
        presented_serial,
        not_after_unix_seconds: not_after.try_into().context("invalid certificate expiry")?,
        renew_after_unix_seconds: renew_after
            .try_into()
            .context("invalid certificate renewal deadline")?,
    })
}

fn certificate_times(der: &[u8]) -> Result<(i64, i64)> {
    let (trailing, certificate) = parse_x509_certificate(der)
        .map_err(|_| anyhow::anyhow!("invalid presented certificate"))?;
    ensure!(
        trailing.is_empty(),
        "trailing bytes in presented certificate"
    );
    let validity = certificate.validity();
    Ok((
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use laneway_protocol::v1::IpProtocol;

    fn network() -> Id {
        Id::new([1; 16]).expect("fixture ID")
    }

    #[test]
    fn acl_scope_order_disabled_rules_and_fail_closed_default() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE acl_rules (network_id BLOB, id BLOB, enabled INTEGER,
             priority INTEGER, action TEXT, selector_json TEXT, description TEXT);",
        )?;
        let entries = [
            ([1_u8; 16], [9_u8; 16], 1, 100, "deny"),
            ([1; 16], [3; 16], 1, 100, "accept"),
            ([1; 16], [8; 16], 1, 5, "deny"),
            ([1; 16], [4; 16], 0, 0, "accept"),
            ([2; 16], [7; 16], 1, 0, "accept"),
        ];
        let select =
            r#"{"ipProtocol":"IP_PROTOCOL_TCP","destinationPorts":[{"first":443,"last":443}]}"#;
        for (network, id, enabled, priority, action) in entries {
            db.execute(
                "INSERT INTO acl_rules VALUES (?1,?2,?3,?4,?5,?6,'fixture')",
                params![
                    network.as_slice(),
                    id.as_slice(),
                    enabled,
                    priority,
                    action,
                    select
                ],
            )?;
        }
        let policy = policy_snapshot(&db, network(), 42)?;
        assert_eq!(policy.network_id, network().as_bytes());
        assert_eq!(policy.configuration_epoch, 42);
        assert_eq!(policy.default_action, PolicyAction::Deny as i32);
        assert_eq!(
            policy
                .rules
                .iter()
                .map(|rule| rule.rule_id[0])
                .collect::<Vec<_>>(),
            [8, 3, 9]
        );
        assert_eq!(policy.rules[1].action, PolicyAction::Accept as i32);
        assert_eq!(
            policy.rules[1].selector.as_ref().unwrap().ip_protocol,
            IpProtocol::Tcp as i32
        );
        db.execute(
            "UPDATE acl_rules SET enabled=0 WHERE id=?1",
            [[3_u8; 16].as_slice()],
        )?;
        assert!(matches!(epoch_gate(42, 43, 900), EpochGate::Full));
        let after_withdrawal = policy_snapshot(&db, network(), 43)?;
        assert!(
            after_withdrawal
                .rules
                .iter()
                .all(|rule| rule.action == PolicyAction::Deny as i32)
        );
        db.execute(
            r#"UPDATE acl_rules SET selector_json='{"unknown":true}' WHERE priority=5"#,
            [],
        )?;
        assert!(policy_snapshot(&db, network(), 42).is_err());
        Ok(())
    }

    #[test]
    fn certificate_health_emits_canonical_serial_and_two_thirds_renewal_time() -> Result<()> {
        use rcgen::{CertificateParams, KeyPair, SerialNumber};
        use time::OffsetDateTime;

        let mut params = CertificateParams::default();
        params.not_before = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
        params.not_after = OffsetDateTime::from_unix_timestamp(1_700_000_100)?;
        params.serial_number = Some(SerialNumber::from_slice(&[0xe2, 0x01]));
        let certificate = params.self_signed(&KeyPair::generate()?)?;
        let health = certificate_health(certificate.der().as_ref(), &[vec![0xe2, 0x01]])?;
        assert_eq!(health.presented_serial, [0xe2, 0x01]);
        assert_eq!(health.not_after_unix_seconds, 1_700_000_100);
        assert_eq!(health.renew_after_unix_seconds, 1_700_000_066);
        assert!(health.revoked);
        assert!(!certificate_health(certificate.der().as_ref(), &[])?.revoked);
        Ok(())
    }

    #[test]
    fn epoch_cannot_be_reused_for_withdrawn_policy() {
        assert!(matches!(epoch_gate(41, 42, 900), EpochGate::Full));
        let EpochGate::Unchanged(lease) = epoch_gate(42, 42, 900) else {
            panic!("expected matching epoch lease");
        };
        assert_eq!(lease.configuration_epoch, 42);
        assert_eq!(lease.valid_until_unix_seconds, 900);
        assert!(matches!(epoch_gate(43, 42, 900), EpochGate::Ahead));
    }

    #[test]
    fn revocation_set_is_ordered_and_limited_to_current_network_and_lifetime() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE certificates (network_id BLOB, serial BLOB, not_after INTEGER, revoked_at INTEGER);")?;
        for (network, serial, deadline, revoked) in [
            ([1_u8; 16], 8_u8, 700, Some(100)),
            ([1; 16], 4, 600, Some(100)),
            ([1; 16], 3, 500, Some(100)),
            ([1; 16], 5, 600, None),
            ([2; 16], 6, 600, Some(100)),
        ] {
            db.execute(
                "INSERT INTO certificates VALUES (?1,?2,?3,?4)",
                params![network.as_slice(), [serial].as_slice(), deadline, revoked],
            )?;
        }
        assert_eq!(revoked_serials(&db, network(), 500)?, [vec![4], vec![8]]);
        assert!(revoked_serials(&db, network(), 700)?.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_acl_over_wire_limit_without_returning_a_partial_policy() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE acl_rules (network_id BLOB, id BLOB, enabled INTEGER,
             priority INTEGER, action TEXT, selector_json TEXT, description TEXT);",
        )?;
        let tx = db.transaction()?;
        let count = DEFAULT_MAX_CONTROL_PAYLOAD / 1024;
        {
            let mut insert = tx.prepare(
                r#"INSERT INTO acl_rules VALUES (?1,?2,1,10,'deny','{"ipProtocol":"IP_PROTOCOL_ANY"}',?3)"#
            )?;
            let description = "x".repeat(1024);
            for index in 1..count {
                insert.execute(params![
                    network().as_bytes(),
                    (index as u128).to_be_bytes(),
                    &description
                ])?;
            }
        }
        tx.commit()?;
        let error = policy_snapshot(&db, network(), 42).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ACL policy exceeds snapshot wire limit")
        );
        Ok(())
    }

    #[test]
    fn accepts_revocations_at_wire_limit_and_rejects_the_next_serial() -> Result<()> {
        let mut db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE certificates (network_id BLOB, serial BLOB, not_after INTEGER, revoked_at INTEGER);")?;
        let tx = db.transaction()?;
        let count = DEFAULT_MAX_CONTROL_PAYLOAD / (1 + length_delimiter_len(32) + 32);
        let serial = |index: usize| {
            let mut serial = [1_u8; 32];
            serial[24..].copy_from_slice(&(index as u64).to_be_bytes());
            serial
        };
        {
            let mut insert = tx.prepare("INSERT INTO certificates VALUES (?1,?2,200,100)")?;
            for index in 0..count {
                insert.execute(params![network().as_bytes(), serial(index)])?;
            }
        }
        tx.commit()?;
        assert_eq!(revoked_serials(&db, network(), 150)?.len(), count);
        db.execute(
            "INSERT INTO certificates VALUES (?1,?2,200,100)",
            params![network().as_bytes(), serial(count)],
        )?;
        let error = revoked_serials(&db, network(), 150).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("certificate revocations exceeds snapshot wire limit")
        );
        Ok(())
    }
}
