use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode, header};
use laneway_protocol::{
    Id,
    v1::{CertificateRevocation, ErrorCode, ProtocolError},
};
use prost::Message;
use rusqlite::{Connection, OptionalExtension, params};

use crate::{enrollment::NodePeer, store::Store};

type Reply = Response<Full<Bytes>>;

/// The HTTPS transport supplies a leaf only after verifying its chain and
/// proof of possession. Its durable binding is checked in the same database
/// transaction as the network-scoped revocation lookup.
pub(crate) fn revocation_response(
    store: &mut Store,
    verified_leaf: Option<&[u8]>,
    serial: &str,
    now: i64,
) -> Reply {
    let Some(node) = verified_leaf.and_then(|der| NodePeer::from_tls_leaf(der).ok()) else {
        return error(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthenticated,
            "authentication failed",
            false,
        );
    };
    let Ok(transaction) = store.enrollment_transaction() else {
        return internal_error();
    };
    if let Err(problem) = node.authenticate(&transaction, now) {
        return error(
            StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            problem.code,
            problem.detail,
            problem.retryable,
        );
    }
    let Some(serial) = parse_serial(serial) else {
        return error(
            StatusCode::BAD_REQUEST,
            ErrorCode::Malformed,
            "serial must be canonical lowercase hexadecimal",
            false,
        );
    };
    match lookup(&transaction, node.network_id, serial) {
        Ok(Some(Some(revocation))) => protobuf(StatusCode::OK, revocation),
        Ok(Some(None)) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .expect("static revocation response"),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            ErrorCode::Malformed,
            "record not found",
            false,
        ),
        Err(_) => internal_error(),
    }
}

fn parse_serial(serial: &str) -> Option<Vec<u8>> {
    if (2..=64).contains(&serial.len())
        && serial.len().is_multiple_of(2)
        && serial
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        hex::decode(serial).ok()
    } else {
        None
    }
}

fn lookup(
    db: &Connection,
    network: Id,
    serial: Vec<u8>,
) -> Result<Option<Option<CertificateRevocation>>> {
    let row = db
        .query_row(
            "SELECT node_id,revoked_at,revocation_reason FROM certificates
             WHERE network_id=?1 AND serial=?2",
            params![network.as_bytes().as_slice(), serial.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((_, None, _)) => Ok(Some(None)),
        Some((node, Some(revoked_at), reason)) => Ok(Some(Some(CertificateRevocation {
            node_id: Id::from_slice(&node)
                .context("invalid revoked certificate node ID")?
                .as_bytes()
                .to_vec(),
            certificate_serial: serial,
            revoked_unix_seconds: revoked_at.try_into().context("invalid revocation time")?,
            reason,
        }))),
    }
}

fn protobuf(status: StatusCode, packet: impl Message) -> Reply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Full::new(Bytes::from(packet.encode_to_vec())))
        .expect("static revocation response")
}

fn error(status: StatusCode, code: ErrorCode, detail: &str, retryable: bool) -> Reply {
    protobuf(
        status,
        ProtocolError {
            code: code as i32,
            detail: detail.to_owned(),
            retryable,
        },
    )
}

fn internal_error() -> Reply {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::Internal,
        "internal controller error",
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_canonical_serial_text() {
        assert_eq!(parse_serial("e201"), Some(vec![0xe2, 0x01]));
        for value in ["", "0", "abc", "0A", "00 ", "0/", "0g", &"ab".repeat(33)] {
            assert_eq!(parse_serial(value), None, "{value}");
        }
    }

    #[test]
    fn lookup_cannot_disclose_a_matching_serial_in_another_network() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(
            "CREATE TABLE certificates (network_id BLOB, serial BLOB, node_id BLOB,
             revoked_at INTEGER, revocation_reason TEXT);",
        )?;
        for (network, serial, node, revoked, reason) in [
            ([1_u8; 16], [0x80_u8], [4_u8; 16], Some(11_i64), "withdrawn"),
            ([1; 16], [0x81], [5; 16], None, ""),
            ([2; 16], [0x80], [6; 16], Some(22), "another network"),
            ([2; 16], [0x82], [7; 16], Some(33), "another network only"),
        ] {
            db.execute(
                "INSERT INTO certificates VALUES (?1,?2,?3,?4,?5)",
                params![
                    network.as_slice(),
                    serial.as_slice(),
                    node.as_slice(),
                    revoked,
                    reason
                ],
            )?;
        }
        let network = Id::new([1; 16])?;
        let revocation = lookup(&db, network, vec![0x80])?.flatten().unwrap();
        assert_eq!(revocation.node_id, [4; 16]);
        assert_eq!(revocation.revoked_unix_seconds, 11);
        assert_eq!(revocation.reason, "withdrawn");
        assert_eq!(lookup(&db, network, vec![0x81])?, Some(None));
        assert_eq!(lookup(&db, network, vec![0x82])?, None);
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_requires_current_durable_mtls_and_returns_wire_revocations() -> Result<()> {
        use http_body_util::BodyExt;
        use rcgen::{CertificateParams, KeyPair, SanType, SerialNumber};
        use time::OffsetDateTime;

        const NOW: i64 = 1_700_000_100;
        let network = Id::new([1; 16])?;
        let node = Id::new([2; 16])?;
        let mut leaf = CertificateParams::default();
        leaf.not_before = OffsetDateTime::from_unix_timestamp(NOW - 10)?;
        leaf.not_after = OffsetDateTime::from_unix_timestamp(NOW + 10)?;
        leaf.serial_number = Some(SerialNumber::from_slice(&[1]));
        leaf.subject_alt_names.push(SanType::URI(
            format!("spiffe://laneway/network/{network}/node/{node}").try_into()?,
        ));
        let leaf = leaf.self_signed(&KeyPair::generate()?)?;
        let der = leaf.der().as_ref();

        let work = tempfile::tempdir()?;
        let mut store = Store::open(&work.path().join("controller.sqlite"))?;
        let transaction = store.enrollment_transaction()?;
        crate::schema::migrate(&transaction, NOW)?;
        transaction.execute(
            "INSERT INTO networks (id,name,ipv4_address,ipv4_prefix_length,created_at)
             VALUES (?1,'fixture',X'64400000',24,?2)",
            params![network.as_bytes().as_slice(), NOW - 100],
        )?;
        transaction.execute(
            "INSERT INTO nodes (id,network_id,name,created_at) VALUES (?1,?2,'node',?3)",
            params![
                node.as_bytes().as_slice(),
                network.as_bytes().as_slice(),
                NOW - 100
            ],
        )?;
        transaction.execute(
            "INSERT INTO certificates (id,network_id,node_id,serial,der,not_before,not_after,created_at)
             VALUES (X'10101010101010101010101010101010',?1,?2,X'01',?3,?4,?5,?4)",
            params![network.as_bytes().as_slice(), node.as_bytes().as_slice(), der, NOW - 10, NOW + 10],
        )?;
        transaction.execute(
            "INSERT INTO certificates (id,network_id,node_id,serial,der,not_before,not_after,created_at,revoked_at,revocation_reason)
             VALUES (X'20202020202020202020202020202020',?1,?2,X'02',X'01',?3,?4,?3,?5,'superseded')",
            params![network.as_bytes().as_slice(), node.as_bytes().as_slice(), NOW - 10, NOW + 20, NOW - 1],
        )?;
        transaction.commit()?;

        assert_eq!(
            revocation_response(&mut store, None, "02", NOW).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            revocation_response(&mut store, Some(der), "01", NOW).status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            revocation_response(&mut store, Some(der), "0F", NOW).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            revocation_response(&mut store, Some(der), "03", NOW).status(),
            StatusCode::NOT_FOUND
        );
        let response = revocation_response(&mut store, Some(der), "02", NOW);
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await?.to_bytes();
        let message = CertificateRevocation::decode(bytes)?;
        assert_eq!(message.certificate_serial, [2]);
        assert_eq!(message.node_id, node.as_bytes());
        assert_eq!(message.revoked_unix_seconds, (NOW - 1) as u64);
        assert_eq!(message.reason, "superseded");

        let transaction = store.enrollment_transaction()?;
        transaction.execute(
            "UPDATE certificates SET revoked_at=?1 WHERE serial=X'01'",
            [NOW],
        )?;
        transaction.commit()?;
        assert_eq!(
            revocation_response(&mut store, Some(der), "02", NOW).status(),
            StatusCode::FORBIDDEN
        );
        Ok(())
    }
}
