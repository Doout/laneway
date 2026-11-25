use super::*;
use crate::store::InitialNetwork;
use laneway_protocol::{AuthenticatedIdentity, Role};

fn fixture() -> (tempfile::TempDir, Store, Id, Id) {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(&directory.path().join("controller.db")).unwrap();
    let network = Id::new([1; 16]).unwrap();
    let bootstrap = InitialNetwork::new(
        network,
        "acl fixture".into(),
        "100.96.0.0/24".parse().unwrap(),
        None,
    )
    .unwrap();
    store
        .prepare(
            Some(&bootstrap),
            AuthenticatedIdentity {
                network_id: network,
                role: Role::Controller,
                subject_id: Id::new([2; 16]).unwrap(),
            },
            None,
        )
        .unwrap();
    let actor = store.root_principal().unwrap();
    (directory, store, network, actor)
}

fn rule(priority: u32, enabled: Option<bool>) -> Rule {
    let mut body = json!({
        "action":"accept", "priority":priority,
        "selector":{"ipProtocol":"IP_PROTOCOL_TCP","destinationPorts":[{"first":443,"last":443}]},
        "description":"HTTPS"
    });
    if let Some(value) = enabled {
        body["enabled"] = json!(value);
    }
    parse_rule(body.to_string().as_bytes(), enabled.is_none()).unwrap()
}

fn event_count(store: &mut Store) -> i64 {
    store
        .enrollment_transaction()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM audit_events WHERE target_type='acl_rule'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn writes_canonical_rules_and_actor_audits_in_epoch_order() {
    let (_keep, mut store, network, actor) = fixture();
    let run = |store: &mut Store, op| apply(store, actor, op, &AtomicBool::new(false)).unwrap();
    let (status, first) = run(&mut store, Operation::Create(network, rule(20, None)));
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(first["configuration_epoch"], 2);
    assert_eq!(first["selector"]["ip_protocol"], "IP_PROTOCOL_TCP");
    assert_eq!(first["enabled"], true);
    let first_id: Id = first["rule_id"].as_str().unwrap().parse().unwrap();
    let (_, second) = run(&mut store, Operation::Create(network, rule(10, None)));
    let (status, result) = run(&mut store, Operation::List(network, 1));
    assert_eq!(status, StatusCode::OK);
    let rules = result["acl_rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["rule_id"], second["rule_id"]);
    assert_eq!(rules[0]["configuration_epoch"], 3);
    let (_, updated) = run(
        &mut store,
        Operation::Update(first_id, rule(5, Some(false))),
    );
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["configuration_epoch"], 4);
    let (_, deleted) = run(&mut store, Operation::Delete(first_id));
    assert_eq!(deleted, json!({"configuration_epoch":5}));

    let tx = store.enrollment_transaction().unwrap();
    let mut statement = tx
        .prepare(
            "SELECT actor_kind,actor_id,action,details_json FROM audit_events
         WHERE target_type='acl_rule' AND target_id=?1 ORDER BY rowid",
        )
        .unwrap();
    let rows = statement
        .query_map([first_id.as_bytes()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(rows.len(), 3);
    for (row, action) in rows
        .iter()
        .zip(["acl_rule.create", "acl_rule.update", "acl_rule.delete"])
    {
        assert_eq!(row.0, "service_principal");
        assert_eq!(row.1, actor.as_bytes());
        assert_eq!(row.2, action);
    }
    assert_eq!(rows[1].3, r#"{"enabled":false}"#);
}

#[test]
fn authorization_and_epoch_exhaustion_do_not_change_acl_or_audit() {
    let (_keep, mut store, network, actor) = fixture();
    let canceled = AtomicBool::new(false);
    assert!(matches!(
        apply(
            &mut store,
            Id::new([9; 16]).unwrap(),
            Operation::Create(network, rule(1, None)),
            &canceled
        ),
        Err(Problem::Unauthenticated)
    ));
    let tx = store.enrollment_transaction().unwrap();
    tx.execute(
        "UPDATE networks SET configuration_epoch=9223372036854775807",
        [],
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        apply(
            &mut store,
            actor,
            Operation::Create(network, rule(1, None)),
            &canceled
        ),
        Err(Problem::Conflict)
    ));
    assert_eq!(event_count(&mut store), 0);
    let (_, result) = apply(&mut store, actor, Operation::List(network, 100), &canceled).unwrap();
    assert_eq!(result, json!({"acl_rules":[]}));
}

#[test]
fn failed_actor_audit_rolls_back_the_rule_and_epoch() {
    let (_keep, mut store, network, actor) = fixture();
    let tx = store.enrollment_transaction().unwrap();
    tx.execute_batch(
        "CREATE TRIGGER test_acl_audit_rejected BEFORE INSERT ON audit_events
         WHEN NEW.target_type='acl_rule' BEGIN SELECT RAISE(ABORT, 'test audit failure'); END;",
    )
    .unwrap();
    tx.commit().unwrap();

    let canceled = AtomicBool::new(false);
    assert!(matches!(
        apply(
            &mut store,
            actor,
            Operation::Create(network, rule(1, None)),
            &canceled,
        ),
        Err(Problem::Internal)
    ));
    assert_eq!(event_count(&mut store), 0);
    let tx = store.enrollment_transaction().unwrap();
    assert_eq!(network_epoch(&tx, network).unwrap(), 1);
    assert_eq!(list(&tx, network, 10).unwrap(), json!({"acl_rules":[]}));
}

#[test]
fn acl_requests_and_limits_are_strict() {
    assert!(matches("/v1/admin/networks/invalid/acl-rules"));
    assert!(matches("/v1/admin/acl-rules/invalid"));
    assert!(!matches("/v1/admin/networks/invalid/acl-rules/extra"));
    assert_eq!(query_limit(None).unwrap(), 100);
    assert_eq!(query_limit(Some("limit=12&limit=14")).unwrap(), 12);
    assert!(query_limit(Some("limit=1001")).is_err());
    for raw in [
        br#"{"action":"accept","enabled":null,"selector":{"ipProtocol":256}}"#.as_slice(),
        br#"{"action":"accept","selector":{"ipProtocol":256,"ip_protocol":6}}"#.as_slice(),
        br#"{"action":"accept","selector":{"ipProtocol":256}} {}"#.as_slice(),
        br#"{"action":"accept","description":"a\u0000b","selector":{"ipProtocol":256}}"#.as_slice(),
    ] {
        assert!(parse_rule(raw, true).is_err());
    }
}
