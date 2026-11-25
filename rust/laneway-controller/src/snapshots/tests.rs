use super::*;
use crate::store::InitialNetwork;
use laneway_protocol::{
    certificate_serial_from_der,
    v1::{EnrollmentClass, PolicyAction},
};
use rcgen::{CertificateParams, KeyPair, SanType, SerialNumber};
use rusqlite::Connection;
use time::OffsetDateTime;

const NOW: i64 = 1_800_000_000;

fn id(value: u8) -> Id {
    Id::new([value; 16]).unwrap()
}

fn leaf(network: Id, role: &str, subject: Id, serial: u8) -> Vec<u8> {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.subject_alt_names.push(SanType::URI(
        format!("spiffe://laneway/network/{network}/{role}/{subject}")
            .try_into()
            .unwrap(),
    ));
    params.serial_number = Some(SerialNumber::from(u64::from(serial)));
    params.not_before = OffsetDateTime::from_unix_timestamp(NOW - 600).unwrap();
    params.not_after = OffsetDateTime::from_unix_timestamp(NOW + 600).unwrap();
    params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .to_vec()
}

fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(&directory.path().join("controller.db")).unwrap();
    store
        .prepare(
            Some(
                &InitialNetwork::new(
                    id(1),
                    "primary".to_owned(),
                    "100.96.0.0/16".parse().unwrap(),
                    None,
                )
                .unwrap(),
            ),
            AuthenticatedIdentity {
                network_id: id(1),
                role: Role::Controller,
                subject_id: id(2),
            },
            None,
        )
        .unwrap();
    (directory, store)
}

fn node_row(
    db: &Connection,
    node: Id,
    name: &str,
    lease: Option<i64>,
    address: u8,
    serial: u8,
) -> Vec<u8> {
    let der = leaf(id(1), "node", node, serial);
    let capabilities = laneway_protocol::v1::Capability::LanewaySubnetRouterV1 as u64;
    db.execute(
        "INSERT INTO nodes(id,network_id,name,enabled_capabilities,created_at,enrollment_class,lease_expires_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![node.as_bytes(), id(1).as_bytes(), name, capabilities, NOW-60,
                if lease.is_some() { "ephemeral" } else { "durable" }, lease],
    ).unwrap();
    db.execute(
        "INSERT INTO overlay_addresses(id,network_id,node_id,address,prefix_length,created_at) VALUES(?1,?2,?3,?4,32,?5)",
        params![id(address).as_bytes(), id(1).as_bytes(), node.as_bytes(), vec![100_u8,96,0,address], NOW-60],
    ).unwrap();
    db.execute(
        "INSERT INTO certificates(id,network_id,node_id,serial,der,not_before,not_after,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            id(serial + 40).as_bytes(),
            id(1).as_bytes(),
            node.as_bytes(),
            certificate_serial_from_der(&der).unwrap(),
            der,
            NOW - 600,
            NOW + 600,
            NOW - 60
        ],
    )
    .unwrap();
    der
}

fn relay_row(db: &Connection) -> Vec<u8> {
    db.execute(
        "INSERT INTO relays(id,network_id,name,endpoint,enabled,created_at,service_id)
         VALUES(?1,?2,'relay','relay.example.test:4433',1,?3,?4)",
        params![id(37).as_bytes(), id(1).as_bytes(), NOW, id(38).as_bytes()],
    )
    .unwrap();
    leaf(id(1), "relay", id(38), 30)
}

fn subnet(db: &Connection, expiry: i64) {
    db.execute(
        "INSERT INTO routes(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at,approved_at)
         VALUES(?1,?2,?3,x'c0000200',24,'subnet','nat',20,'approved',?4,?5,?5)",
        params![id(39).as_bytes(), id(1).as_bytes(), id(3).as_bytes(), expiry, NOW-60],
    ).unwrap();
}

fn read_node(body: Body) -> NodeConfiguration {
    match body {
        Body::NodeConfiguration(config) => config,
        _ => panic!("expected a complete node configuration"),
    }
}

#[test]
fn node_and_relay_snapshots_expire_authority_before_renewing_the_epoch() {
    let (_directory, mut store) = store();
    let (node_der, relay_der) = {
        let tx = store.enrollment_transaction().unwrap();
        let node_der = node_row(&tx, id(3), "z-durable", None, 10, 31);
        node_row(&tx, id(4), "a-ephemeral", Some(NOW + 60), 11, 32);
        subnet(&tx, NOW + 30);
        let relay_der = relay_row(&tx);
        tx.commit().unwrap();
        (node_der, relay_der)
    };
    let config = read_node(node(&mut store, &node_der, 0, NOW).unwrap());
    let initial = config.configuration_epoch;
    assert_eq!(config.valid_until_unix_seconds, (NOW + 30) as u64);
    assert_eq!(config.enrollment_class(), EnrollmentClass::DurableNode);
    assert_eq!(
        config
            .peers
            .iter()
            .map(|peer| peer.name.as_str())
            .collect::<Vec<_>>(),
        ["a-ephemeral", "z-durable"]
    );
    assert_eq!(config.overlay_addresses, [vec![100, 96, 0, 10]]);
    let policy = config.policy.unwrap();
    assert_eq!(policy.configuration_epoch, initial);
    assert_eq!(policy.default_action(), PolicyAction::Deny);
    let routes = config.routes.unwrap().routes;
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0].route_id, id(10).as_bytes());
    assert_eq!(routes[2].via_node_id, id(3).as_bytes());
    assert_eq!(routes[2].kind(), RouteKind::Subnet);
    assert_eq!(config.relays[0].service_id, id(38).as_bytes());
    assert_eq!(
        config.certificate_health.unwrap().presented_serial,
        vec![31]
    );

    let Body::RelayConfiguration(config) = relay(&mut store, &relay_der, 0, NOW).unwrap() else {
        panic!("expected full relay configuration")
    };
    assert_eq!(config.configuration_epoch, initial);
    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.peers[0].authorized_prefixes.len(), 2);
    assert_eq!(
        config.peers[0].authorized_prefixes[1].address,
        [192, 0, 2, 0]
    );
    assert_eq!(config.peers[1].authorized_prefixes.len(), 1);

    let Body::ConfigurationLease(lease) = node(&mut store, &node_der, initial, NOW + 1).unwrap()
    else {
        panic!("expected a lease")
    };
    assert_eq!(lease.configuration_epoch, initial);
    assert_eq!(lease.valid_until_unix_seconds, (NOW + 30) as u64);

    let config = read_node(node(&mut store, &node_der, initial, NOW + 30).unwrap());
    assert_eq!(config.configuration_epoch, initial + 1);
    assert_eq!(config.routes.unwrap().routes.len(), 2);
    assert_eq!(config.valid_until_unix_seconds, (NOW + 60) as u64);

    let Body::RelayConfiguration(config) =
        relay(&mut store, &relay_der, initial + 1, NOW + 60).unwrap()
    else {
        panic!("expected new relay configuration after identity expiry")
    };
    assert_eq!(config.configuration_epoch, initial + 2);
    assert_eq!(config.peers.len(), 1);
    assert_eq!(config.peers[0].authorized_prefixes.len(), 1);
    assert_eq!(config.revoked_certificate_serials, vec![vec![32]]);

    let tx = store.enrollment_transaction().unwrap();
    for action in ["route.expire", "ephemeral.expire"] {
        let count: usize = tx.query_row(
            "SELECT count(*) FROM audit_events WHERE action=?1 AND actor_kind='system' AND actor_id IS NULL",
            [action], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }
    let revoked: i64 = tx
        .query_row(
            "SELECT released_at FROM overlay_addresses WHERE id=?1",
            [id(11).as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revoked, NOW + 60);
}

#[test]
fn snapshots_reject_wrong_role_replaced_leaf_disabled_relay_and_ahead_epoch() {
    let (_directory, mut store) = store();
    let (node_der, relay_der) = {
        let tx = store.enrollment_transaction().unwrap();
        let node_der = node_row(&tx, id(3), "durable", None, 10, 31);
        let relay_der = relay_row(&tx);
        tx.commit().unwrap();
        (node_der, relay_der)
    };
    let forged = leaf(id(1), "node", id(3), 31);
    assert_eq!(
        node(&mut store, &forged, 0, NOW).unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    assert!(node(&mut store, &relay_der, 0, NOW).is_err());
    assert!(relay(&mut store, &node_der, 0, NOW).is_err());
    let unknown = leaf(id(1), "relay", id(3), 40);
    assert_eq!(
        relay(&mut store, &unknown, 0, NOW).unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    let other_network = leaf(id(5), "relay", id(38), 41);
    assert_eq!(
        relay(&mut store, &other_network, 0, NOW).unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    let expired_relay = relay(&mut store, &relay_der, 0, NOW + 600).unwrap_err();
    assert_eq!(expired_relay.code, ErrorCode::PermissionDenied);
    let ahead = node(&mut store, &node_der, u64::MAX, NOW).unwrap_err();
    assert_eq!(ahead.code, ErrorCode::StaleEpoch);
    assert!(!ahead.retryable);
    {
        let tx = store.enrollment_transaction().unwrap();
        tx.execute(
            "UPDATE relays SET enabled=0 WHERE service_id=?1",
            [id(38).as_bytes()],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert!(relay(&mut store, &relay_der, 0, NOW).is_err());
}

#[test]
fn pending_expiry_batch_never_renews_a_partially_expired_epoch() {
    let (_directory, mut store) = store();
    let (relay_der, previous) = {
        let tx = store.enrollment_transaction().unwrap();
        let relay_der = relay_row(&tx);
        let previous: u64 = tx
            .query_row(
                "SELECT configuration_epoch FROM networks WHERE id=?1",
                [id(1).as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        {
            let mut statement = tx.prepare(
                "INSERT INTO nodes(id,network_id,name,created_at,enrollment_class,lease_expires_at)
                 VALUES(?1,?2,?3,?4,'ephemeral',?5)",
            ).unwrap();
            for n in 1_u128..=1025 {
                let node = Id::new(n.to_be_bytes()).unwrap();
                statement
                    .execute(params![
                        node.as_bytes(),
                        id(1).as_bytes(),
                        format!("expired-{n}"),
                        NOW - 60,
                        NOW
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
        (relay_der, previous)
    };
    let unfinished = relay(&mut store, &relay_der, previous, NOW).unwrap_err();
    assert_eq!(unfinished.code, ErrorCode::ResourceExhausted);
    assert!(unfinished.retryable);
    let Body::RelayConfiguration(config) = relay(&mut store, &relay_der, previous, NOW).unwrap()
    else {
        panic!("expected a complete configuration after the last expired identity was processed")
    };
    assert_eq!(config.configuration_epoch, previous + 2);
    assert!(config.peers.is_empty());
}

#[test]
fn overdue_routes_are_withdrawn_in_bounded_batches_before_serving_snapshots() {
    let (_directory, mut store) = store();
    let (node_der, relay_der, previous) = {
        let tx = store.enrollment_transaction().unwrap();
        let node_der = node_row(&tx, id(3), "route-owner", None, 10, 31);
        let relay_der = relay_row(&tx);
        let previous: u64 = tx
            .query_row(
                "SELECT configuration_epoch FROM networks WHERE id=?1",
                [id(1).as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        {
            let mut insert = tx.prepare(
                "INSERT INTO routes(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at,approved_at)
                 VALUES(?1,?2,?3,?4,32,'subnet','nat',20,'approved',?5,?6,?6)"
            ).unwrap();
            for n in 1..=expiry::ROUTE_EXPIRY_BATCH + 1 {
                let route = Id::new((n as u128).to_be_bytes()).unwrap();
                let address = (u32::from_be_bytes([192, 0, 0, 0]) + n as u32).to_be_bytes();
                insert
                    .execute(params![
                        route.as_bytes(),
                        id(1).as_bytes(),
                        id(3).as_bytes(),
                        address,
                        NOW,
                        NOW - 60
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
        (node_der, relay_der, previous)
    };

    let unfinished = relay(&mut store, &relay_der, previous, NOW).unwrap_err();
    assert_eq!(unfinished.code, ErrorCode::ResourceExhausted);
    assert!(unfinished.retryable);
    {
        let tx = store.enrollment_transaction().unwrap();
        let remaining: usize = tx
            .query_row(
                "SELECT count(*) FROM routes WHERE state='approved'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let audited: usize = tx
            .query_row(
                "SELECT count(*) FROM audit_events WHERE action='route.expire'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
        assert_eq!(audited, expiry::ROUTE_EXPIRY_BATCH);
        tx.commit().unwrap();
    }

    let configuration = read_node(node(&mut store, &node_der, previous, NOW).unwrap());
    assert_eq!(configuration.configuration_epoch, previous + 2);
    assert_eq!(configuration.routes.unwrap().routes.len(), 1);
    let Body::ConfigurationLease(lease) = relay(&mut store, &relay_der, previous + 2, NOW).unwrap()
    else {
        panic!("expected a lease after expiry completed")
    };
    assert_eq!(lease.configuration_epoch, previous + 2);
}
