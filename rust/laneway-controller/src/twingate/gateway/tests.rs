use super::*;
use crate::twingate::Credentials;
use zeroize::Zeroizing;

fn creds(tenant: &str, key: &str) -> Credentials {
    Credentials {
        tenant: tenant.into(),
        api_token: Zeroizing::new(key.into()),
    }
}

fn candidate() -> Candidate {
    Candidate {
        existing: false,
        change_to: None,
        binding: Binding {
            gateway_id: random_id().unwrap(),
            selection: Selection {
                network_id: "11".repeat(16),
                client_node_id: "22".repeat(16),
                resource_id: "resource-a".into(),
                tcp_port: 22,
            },
            destination: Ipv4Addr::new(192, 168, 2, 14),
            phase: Phase::Planned,
            account_id: None,
            key_id: None,
            account_possible: false,
            worker_possible: false,
            key_expires_at: None,
            submitted_at: 0,
            last_confirmed: 0,
            retry_after: 0,
            not_found_since: None,
            next_scope_check: 0,
            pending_client: None,
            detail: None,
        },
    }
}

#[test]
fn private_journal_is_tenant_scoped_and_guards_provider_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("a.db");
    let other = dir.path().join("b.db");
    let store = Storage::for_database(&db);
    store.save(creds("first", "secret-a")).unwrap();
    let saved = store.saved().unwrap();
    let request = candidate();
    let id = request.binding.gateway_id.clone();
    store.request_gateway(&saved, request).unwrap();
    assert_eq!(
        store.gateway_status(&db, false).unwrap().state,
        "provisioning"
    );
    assert_eq!(
        Storage::for_database(&other)
            .gateway_status(&other, false)
            .unwrap()
            .state,
        "disabled"
    );
    assert_eq!(store.disconnect().err(), Some(Failure::GatewayConflict));
    assert_eq!(
        store.save(creds("other", "other-token")).err(),
        Some(Failure::GatewayConflict)
    );
    store.save(creds("first", "secret-b")).unwrap();
    assert_eq!(
        store.request_gateway(&saved, candidate()).err(),
        Some(Failure::ConnectionChanged)
    );
    let path = store.0.join("twingate-gateway.json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!std::fs::read_to_string(&path).unwrap().contains("secret-"));
    let public = serde_json::to_string(&store.gateway_status(&db, false).unwrap()).unwrap();
    assert!(!public.contains("account_id") && !public.contains("key_id"));
    assert_eq!(
        store.remove_gateway(None).err(),
        Some(Failure::GatewayChanged)
    );
    assert_eq!(
        store.remove_gateway(Some("stale")).err(),
        Some(Failure::GatewayChanged)
    );
    store.remove_gateway(Some(&id)).unwrap();
    assert_eq!(store.gateway_status(&db, false).unwrap().state, "removing");
}

#[tokio::test]
async fn restart_reconciles_removal_without_recreating_a_stale_binding() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("a.db");
    let mut conn = rusqlite::Connection::open(&db).unwrap();
    let tx = conn.transaction().unwrap();
    crate::schema::initialize(&tx, 1).unwrap();
    tx.commit().unwrap();
    let store = Storage::for_database(&db);
    store.save(creds("first", "token")).unwrap();
    let saved = store.saved().unwrap();
    store.request_gateway(&saved, candidate()).unwrap();
    let binding = store.binding().unwrap().unwrap();
    let lock = store.operation().unwrap();
    assert_eq!(
        store.remove_gateway(Some(&binding.gateway_id)).err(),
        Some(Failure::GatewayBusy)
    );
    drop(lock);
    // With no worker or bootstrap data, a persisted intent fails before provider effects.
    reconcile(&db, None).await.unwrap();
    assert_eq!(store.gateway_status(&db, false).unwrap().state, "degraded");
    assert!(!store.binding().unwrap().unwrap().account_possible);
    store.remove_gateway(Some(&binding.gateway_id)).unwrap();
    reconcile(&db, None).await.unwrap();
    assert_eq!(store.gateway_status(&db, false).unwrap().state, "disabled");
    assert_eq!(
        store
            .request_gateway(
                &saved,
                Candidate {
                    binding,
                    change_to: None,
                    existing: true
                }
            )
            .err(),
        Some(Failure::GatewayConflict)
    );
    store.remove_gateway(None).unwrap();
    store.disconnect().unwrap();
}

#[test]
fn missing_worker_state_after_restart_exposes_recoverable_retry() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("gateway.db");
    let store = Storage::for_database(&db);
    store.save(creds("first", "token")).unwrap();
    let mut request = candidate();
    request.binding.phase = Phase::Ready;
    request.binding.submitted_at = 10_000;
    request.binding.account_id = Some("owned-account".into());
    request.binding.key_id = Some("owned-key".into());
    request.binding.worker_possible = true;
    let saved = store.saved().unwrap();
    store.request_gateway(&saved, request).unwrap();
    let mut binding = store.binding().unwrap().unwrap();
    lifecycle::await_runtime(&store, &mut binding, RuntimeStatus::Starting, 10_050).unwrap();
    assert_eq!(
        store.gateway_status(&db, false).unwrap().state,
        "provisioning"
    );
    // Restore without the spool. Missing/stale generations are reported as Starting.
    let mut restarted = store.binding().unwrap().unwrap();
    lifecycle::await_runtime(&store, &mut restarted, RuntimeStatus::Starting, 10_600).unwrap();
    assert_eq!(store.gateway_status(&db, false).unwrap().state, "degraded");
    store
        .request_gateway(
            &saved,
            Candidate {
                binding: restarted,
                existing: true,
                change_to: None,
            },
        )
        .unwrap();
    let retry = store.binding().unwrap().unwrap();
    assert!(retry.phase == Phase::Retrying);
    assert_eq!(retry.account_id.as_deref(), Some("owned-account"));
    assert_eq!(retry.key_id.as_deref(), Some("owned-key"));
}
