use std::{io, path::Path};

use anyhow::{Context, Result};

use crate::rootless_cli::{credentials, enroll, private, secret};

fn existing_identity(state: &Path) -> Result<Option<enroll::Identity>> {
    match enroll::Identity::load(state) {
        Ok(identity) => Ok(Some(identity)),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(crate) async fn configure(state: &Path, system: bool) -> Result<()> {
    let identity = if let Some(identity) = existing_identity(state)? {
        identity
    } else {
        let _lock = private::try_lock(&state.join("node.lock"))
            .context("node setup is already in progress")?;
        // A concurrent setup can finish between the first read and the lock.
        if let Some(identity) = existing_identity(state)? {
            identity
        } else {
            enroll::clean_staged_tls(state)?;
            let invitation = secret("Single-use invitation", enroll::MAX_SETUP_TOKEN)?;
            enroll::activate(state, &invitation).await?
        }
    };
    println!("Configured {} ({})", identity.name, identity.node_id);
    if !system && let Some(key) = credentials::initial_key(&state.join("credentials.json"))? {
        println!("SOCKS5 username: local\nSOCKS5 password (shown once): {key}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconfiguration_preserves_existing_and_revoked_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("node");
        private::ensure_directory(&state).unwrap();
        let path = state.join("credentials.json");
        assert_eq!(credentials::initial_key(&path).unwrap().unwrap().len(), 64);
        assert!(credentials::initial_key(&path).unwrap().is_none());
        assert_eq!(credentials::list(&path).unwrap(), ["local"]);
        credentials::remove(&path, "local").unwrap();
        assert!(credentials::initial_key(&path).unwrap().is_none());
        assert!(credentials::list(&path).unwrap().is_empty());
    }
}
