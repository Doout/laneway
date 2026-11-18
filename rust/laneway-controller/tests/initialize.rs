#![cfg(unix)]

use anyhow::Result;
use laneway_controller::{Inventory, SessionStore, auth_state, backup};
use laneway_protocol::Id;
use rusqlite::Connection;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn creates_a_recoverable_fleet_database_from_an_empty_directory() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let db = temp.path().join("controller.db");
    let network = Id::new([1; 16])?;
    let controller = Id::new([2; 16])?;
    backup::initialize(&db, network, controller, "initial-network", "100.96.0.0/16")?;
    assert_eq!(fs::metadata(&db)?.permissions().mode() & 0o777, 0o600);

    let networks = Inventory::open(&db)?.networks(100)?;
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].network_id, network.to_string());
    assert_eq!(networks[0].name, "initial-network");
    assert_eq!(networks[0].ipv4_pool, "100.96.0.0/16");
    assert!(SessionStore::open(&db)?.operational_alerts_available()?);
    assert_eq!(auth_state(&db)?, "bootstrap_required");
    let conn = Connection::open(&db)?;
    let audit: i64 = conn.query_row(
        "SELECT count(*) FROM audit_events WHERE network_id=?1 AND actor_kind='system' AND actor_id IS NULL
         AND ((action='network.create' AND target_id=?1) OR (action='controller.identity.bind' AND target_id=?2))",
        (network.as_bytes(), controller.as_bytes()),
        |row| row.get(0),
    )?;
    assert_eq!(audit, 2);

    let before = fs::read(&db)?;
    assert!(
        backup::initialize(&db, network, controller, "other-network", "100.97.0.0/16").is_err()
    );
    assert_eq!(fs::read(&db)?, before);
    let copy = temp.path().join("backup.db");
    let restored = temp.path().join("restored.db");
    backup::create(&db, &copy)?;
    backup::restore(&copy, &restored)?;
    assert_eq!(
        Inventory::open(&restored)?.networks(100)?[0].network_id,
        network.to_string()
    );
    Ok(())
}

#[test]
fn does_not_publish_on_invalid_input_or_replace_a_stale_sidecar_or_link() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;
    let db = temp.path().join("controller.db");
    let network = Id::new([1; 16])?;
    let controller = Id::new([2; 16])?;
    assert!(backup::initialize(&db, network, network, "network", "100.96.0.0/16").is_err());
    assert!(backup::initialize(&db, network, controller, "network", "100.96.0.1/16").is_err());
    assert!(!db.exists());
    let sidecar = temp.path().join("controller.db-wal");
    fs::write(&sidecar, "stale sidecar")?;
    assert!(backup::initialize(&db, network, controller, "network", "100.96.0.0/16").is_err());
    assert_eq!(fs::read_to_string(&sidecar)?, "stale sidecar");
    fs::remove_file(sidecar)?;

    let foreign = temp.path().join("foreign");
    symlink(&foreign, &db)?;
    assert!(backup::initialize(&db, network, controller, "network", "100.96.0.0/16").is_err());
    assert!(!foreign.exists());
    assert_eq!(fs::read_link(&db)?, foreign);
    Ok(())
}
