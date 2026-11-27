use super::*;
use crate::twingate::{provider::ProviderError, verification_time};

fn fail(store: &Storage, binding: &mut Binding, detail: impl Into<String>) -> Result<(), Failure> {
    binding.phase = Phase::Failed;
    binding.detail = Some(detail.into());
    store.persist(binding)
}

pub async fn reconcile(database: &Path, discovery: Option<&Discovery>) -> Result<(), Failure> {
    let store = Storage::for_database(database);
    if store.binding()?.is_none() {
        return Ok(());
    }
    let _operation = store.operation()?;
    let Some(mut b) = store.binding()? else {
        return Ok(());
    };
    let spec = b.spec()?;
    if matches!(b.phase, Phase::Removing | Phase::Retrying | Phase::Failed) {
        if b.phase == Phase::Failed && !b.account_possible && !b.worker_possible {
            return Ok(());
        }
        let now = verification_time()?;
        if b.retry_after > now {
            return Ok(());
        }
        if cleanup(&store, database, &mut b, &spec).await.is_err() {
            b.retry_after = now.saturating_add(60);
            if b.phase != Phase::Failed {
                b.detail = Some("Cleanup is pending. Check the gateway worker and saved provisioning token. Laneway will retry automatically.".into());
            }
            store.persist(&b)?;
        }
        return Ok(());
    }
    if b.phase == Phase::ChangingClient {
        let client = b
            .pending_client
            .as_ref()
            .ok_or(Failure::Storage)?
            .parse()
            .map_err(|_| Failure::Storage)?;
        if overlay::change_client(database, &spec, client).is_ok() {
            b.selection.client_node_id = client.to_string();
            b.detail = None;
        } else {
            b.detail = Some("Could not switch the permitted client. Check that the new client and the gateway are active on this network.".into());
        }
        b.pending_client = None;
        b.phase = Phase::Ready;
        return store.persist(&b);
    }
    if matches!(
        b.phase,
        Phase::Submitted | Phase::WaitingForRoute | Phase::Ready
    ) {
        if !provider_scope_current(&store, database, &mut b, &spec).await? {
            return Ok(());
        }
        return observe(&store, database, &mut b, &spec);
    }
    provision(&store, database, &mut b, &spec, discovery).await
}

// Re-check provider grants and address while the gateway is active. An
// unavailable provider withdraws publication until it can confirm them again.
async fn provider_scope_current(
    store: &Storage,
    database: &Path,
    b: &mut Binding,
    spec: &GatewaySpec,
) -> Result<bool, Failure> {
    let now = verification_time()?;
    if now < b.next_scope_check {
        return Ok(true);
    }
    if b.retry_after > now {
        return Ok(false);
    }
    let connection = store.saved()?;
    let provider =
        Provider::from_credentials(connection.credentials()).map_err(|_| Failure::Rejected)?;
    let result = match provider
        .resolve_resource(&b.selection.resource_id, b.selection.tcp_port)
        .await
    {
        Ok(ip) if ip == b.destination => {
            provider
                .verify_service_account(
                    b.account_id.as_deref().ok_or(Failure::Storage)?,
                    &b.selection.resource_id,
                )
                .await
        }
        Ok(_) => Err(ProviderError::ResourceMismatch),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        overlay::deactivate(database, spec).map_err(|_| Failure::GatewayRoute)?;
        if matches!(
            error,
            ProviderError::ResourceMismatch | ProviderError::AccountScopeMismatch
        ) {
            fail(
                store,
                b,
                "Twingate changed or removed the gateway's approved resource or account grant. Disable the gateway and review the resource.",
            )?;
        } else {
            b.phase = Phase::Submitted;
            b.detail = Some("Twingate could not confirm the gateway's resource grant. Check the saved token. Laneway will retry automatically.".into());
            b.retry_after = now.saturating_add(60);
            store.persist(b)?;
        }
        return Ok(false);
    }
    b.next_scope_check = now.saturating_add(300);
    b.retry_after = 0;
    store.persist(b)?;
    Ok(true)
}

fn observe(
    store: &Storage,
    database: &Path,
    b: &mut Binding,
    spec: &GatewaySpec,
) -> Result<(), Failure> {
    if b.key_expires_at.is_some_and(|expiry| {
        let lead = (expiry.saturating_sub(b.submitted_at) / 10).min(7 * 86400);
        verification_time().is_ok_and(|now| now.saturating_add(lead) >= expiry)
    }) {
        b.phase = Phase::Retrying;
        b.detail = Some("Renewing the gateway service key.".into());
        return store.persist(b);
    }
    let available = actuator::available(database);
    let status = actuator::status(database, &b.gateway_id).unwrap_or(RuntimeStatus::Error);
    if available && status == RuntimeStatus::Online {
        match overlay::activate(database, spec) {
            Ok(true) => {
                let now = verification_time()?;
                if b.phase != Phase::Ready || now.saturating_sub(b.last_confirmed) >= 30 {
                    b.last_confirmed = now;
                    b.phase = Phase::Ready;
                    b.detail = None;
                    store.persist(b)?;
                }
            }
            Ok(false) => {
                await_runtime(store, b, RuntimeStatus::Starting, verification_time()?)?;
            }
            Err(err) if err.is::<overlay::GatewayRouteConflict>() => {
                overlay::deactivate(database, spec).map_err(|_| Failure::GatewayRoute)?;
                let detail = err.to_string();
                if b.phase != Phase::WaitingForRoute || b.detail.as_ref() != Some(&detail) {
                    b.phase = Phase::WaitingForRoute;
                    b.detail = Some(detail);
                    store.persist(b)?;
                }
            }
            Err(_) => {
                overlay::deactivate(database, spec).map_err(|_| Failure::GatewayRoute)?;
                return fail(
                    store,
                    b,
                    "Laneway could not publish the scoped route. Check the client, connector and overlapping routes.",
                );
            }
        }
    } else {
        overlay::deactivate(database, spec).map_err(|_| Failure::GatewayRoute)?;
        await_runtime(
            store,
            b,
            if available {
                status
            } else {
                RuntimeStatus::Error
            },
            verification_time()?,
        )?;
    }
    Ok(())
}

pub(super) fn await_runtime(
    store: &Storage,
    b: &mut Binding,
    status: RuntimeStatus,
    now: u64,
) -> Result<(), Failure> {
    let detail = if status == RuntimeStatus::Starting && now.saturating_sub(b.submitted_at) < 600 {
        None
    } else {
        Some(
            "The gateway worker has not confirmed a healthy connector. Check the worker, then retry setup if its enrollment or saved credentials were lost. Laneway will continue checking.",
        )
    };
    if b.phase != Phase::Submitted || b.detail.as_deref() != detail {
        b.phase = Phase::Submitted;
        b.detail = detail.map(str::to_owned);
        store.persist(b)?;
    }
    Ok(())
}

async fn provision(
    store: &Storage,
    database: &Path,
    b: &mut Binding,
    spec: &GatewaySpec,
    discovery: Option<&Discovery>,
) -> Result<(), Failure> {
    let Some(discovery) = discovery.filter(|_| actuator::available(database)) else {
        return fail(
            store,
            b,
            "A healthy gateway worker and tenant bootstrap profile are required.",
        );
    };
    let connection = store.saved()?;
    let provider =
        Provider::from_credentials(connection.credentials()).map_err(|_| Failure::Rejected)?;
    let name = b.name();
    if b.phase == Phase::CreatingKey {
        // A crash can lose the one-time response. Retry deletes the entire owned
        // account (including any unknown key) before creating a fresh generation.
        return fail(
            store,
            b,
            "Service key delivery was interrupted. Retry to revoke the incomplete gateway and provision a new key.",
        );
    }
    if b.phase == Phase::Planned {
        if overlay::preflight(database, spec).is_err() {
            return fail(
                store,
                b,
                "The selected client or route is unavailable. Check the network and overlapping routes.",
            );
        }
        match provider
            .resolve_resource(&b.selection.resource_id, b.selection.tcp_port)
            .await
        {
            Ok(ip) if ip == b.destination => (),
            _ => {
                return fail(
                    store,
                    b,
                    "The selected resource or TCP access changed. Disable the gateway and select the resource again.",
                );
            }
        }
        b.phase = Phase::CreatingAccount;
        b.account_possible = true;
        store.persist(b)?;
        match provider
            .create_service_account(&name, &b.selection.resource_id)
            .await
        {
            Ok(id) => b.account_id = Some(id),
            Err(error) => {
                b.account_possible = error.is_ambiguous_create();
                return fail(
                    store,
                    b,
                    format!("Could not create the Twingate service account. {error}."),
                );
            }
        }
    } else if b.phase == Phase::CreatingAccount {
        b.account_id = provider
            .find_service_account(&name)
            .await
            .map_err(|_| Failure::Unavailable)?;
        if b.account_id.is_none() {
            return fail(
                store,
                b,
                "Service account provisioning was interrupted. Retry to reconcile provider ownership.",
            );
        }
    }
    b.phase = Phase::AccountCreated;
    store.persist(b)?;
    let account = b.account_id.as_deref().ok_or(Failure::Storage)?;
    if provider
        .verify_service_account(account, &b.selection.resource_id)
        .await
        .is_err()
    {
        return fail(
            store,
            b,
            "Twingate did not confirm the exact resource grant for this gateway.",
        );
    }
    let enrollment = match overlay::issue(database, spec, discovery) {
        Ok(token) => token,
        Err(_) => {
            return fail(
                store,
                b,
                "Laneway could not issue a connector enrollment. Check the tenant bootstrap profile and relay.",
            );
        }
    };
    b.phase = Phase::CreatingKey;
    store.persist(b)?;
    let key = match provider.create_service_key(account, &name).await {
        Ok(key) => key,
        Err(error) => {
            return fail(
                store,
                b,
                format!("Could not issue the Twingate service key. {error}."),
            );
        }
    };
    b.key_expires_at = Some(key.expires_at_unix_seconds);
    b.key_id = Some(key.id);
    b.worker_possible = true;
    store.persist(b)?;
    if actuator::enable(
        database,
        &b.gateway_id,
        b.destination,
        b.selection.tcp_port,
        &key.json,
        &enrollment,
    )
    .is_err()
    {
        return fail(
            store,
            b,
            "Laneway could not deliver the gateway credentials to the worker.",
        );
    }
    b.phase = Phase::Submitted;
    b.submitted_at = verification_time()?;
    b.next_scope_check = b.submitted_at.saturating_add(300);
    b.detail = None;
    store.persist(b)
}

async fn cleanup(
    store: &Storage,
    database: &Path,
    b: &mut Binding,
    spec: &GatewaySpec,
) -> Result<(), Failure> {
    if let Some(client) = &b.pending_client {
        let pending = GatewaySpec {
            client: client.parse().map_err(|_| Failure::Storage)?,
            ..*spec
        };
        overlay::cleanup(database, &pending).map_err(|_| Failure::GatewayRoute)?;
    }
    overlay::cleanup(database, spec).map_err(|_| Failure::GatewayRoute)?;
    let runtime_stopped = if b.worker_possible {
        actuator::disable(database, &b.gateway_id).is_ok()
            && matches!(
                actuator::status(database, &b.gateway_id),
                Ok(RuntimeStatus::Disabled)
            )
    } else {
        true
    };
    if b.account_possible {
        let connection = store.saved()?;
        let provider =
            Provider::from_credentials(connection.credentials()).map_err(|_| Failure::Rejected)?;
        if b.account_id.is_none() {
            b.account_id = provider
                .find_service_account(&b.name())
                .await
                .map_err(|_| Failure::Unavailable)?;
            if b.account_id.is_none() {
                // A timed-out create can become visible after the first lookup.
                // Keep the journal and refuse to allocate another account while
                // the provider's result is still settling.
                let now = verification_time()?;
                let first = *b.not_found_since.get_or_insert(now);
                if now.saturating_sub(first) < 600 {
                    b.retry_after = now.saturating_add(60);
                    store.persist(b)?;
                    return Ok(());
                }
            }
            store.persist(b)?;
        }
        if let Some(id) = &b.key_id {
            provider
                .revoke_service_key(id)
                .await
                .map_err(|_| Failure::Unavailable)?;
            b.key_id = None;
            store.persist(b)?;
        }
        if let Some(id) = &b.account_id {
            provider
                .delete_service_account(id)
                .await
                .map_err(|_| Failure::Unavailable)?;
        }
        b.account_id = None;
        b.account_possible = false;
        store.persist(b)?;
    }
    if !runtime_stopped {
        if b.phase != Phase::Failed {
            let detail = "Waiting for the gateway worker to confirm removal.";
            if b.detail.as_deref() != Some(detail) {
                b.detail = Some(detail.into());
                store.persist(b)?;
            }
        }
        return Ok(());
    }
    if b.phase == Phase::Failed {
        b.worker_possible = false;
        b.key_expires_at = None;
        return store.persist(b);
    }
    if b.phase == Phase::Retrying {
        b.gateway_id = random_id()?;
        b.worker_possible = false;
        b.key_expires_at = None;
        b.not_found_since = None;
        b.next_scope_check = 0;
        b.pending_client = None;
        b.retry_after = 0;
        b.detail = None;
        b.phase = Phase::Planned;
        store.persist(b)
    } else {
        store.with_lock(|s| {
            std::fs::remove_file(s.0.join("twingate-gateway.json"))
                .map_err(|_| Failure::Storage)?;
            s.sync_directory()
        })
    }
}
