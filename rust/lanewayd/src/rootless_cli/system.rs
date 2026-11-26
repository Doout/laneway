use std::path::{Path, PathBuf};

use anyhow::Result;

#[cfg(not(target_os = "linux"))]
const UNSUPPORTED: &str =
    "system networking is supported on Linux; omit --system to use userspace networking";

#[cfg(not(target_os = "linux"))]
pub(crate) fn state_dir() -> Result<PathBuf> {
    anyhow::bail!(UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn run_explicit(_: &Path, _: bool) -> Result<()> {
    anyhow::bail!(UNSUPPORTED)
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn run_enrolled(_: &Path, _: bool) -> Result<()> {
    anyhow::bail!(UNSUPPORTED)
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{run_enrolled, run_explicit, state_dir};

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        io::ErrorKind,
        os::unix::fs::{DirBuilderExt, MetadataExt},
    };

    use anyhow::{Context, ensure};
    use lanewayd_rs::{Agent, Config, rootless::TransportOptions};
    use tokio::signal::unix::{SignalKind, signal};

    use super::{Path, PathBuf, Result};
    use crate::rootless_cli::{
        enroll::{self, Identity, TlsFiles},
        private,
        runtime::wait_for_renewal,
    };

    pub(crate) fn state_dir() -> Result<PathBuf> {
        ensure!(
            private::is_root(),
            "system enrollment and startup with an enrolled identity require root"
        );
        Ok(PathBuf::from("/var/lib/laneway-system"))
    }

    pub(crate) async fn run_explicit(file: &Path, check: bool) -> Result<()> {
        let agent = Agent::new(Config::load(file)?)?;
        if check {
            println!("configuration is valid");
            return Ok(());
        }
        agent.run_until(shutdown()?).await
    }

    pub(crate) async fn run_enrolled(state: &Path, check: bool) -> Result<()> {
        let _lock = private::try_lock(&state.join("node.lock"))
            .context("another system node is using the Laneway identity")?;
        enroll::clean_staged_tls(state)?;
        let mut identity = Identity::load(state)
            .context("load system node identity; configure with laneway configure --system")?;
        enroll::discard_completed_enrollment(state);
        if check {
            let tls = identity.tls_files()?;
            Agent::new(managed_config(state, &identity, &tls)?)?;
            println!("configuration is valid");
            return Ok(());
        }

        let shutdown = shutdown()?;
        tokio::pin!(shutdown);
        loop {
            let tls = identity.tls_files()?;
            let config = managed_config(state, &identity, &tls)?;
            prepare_socket_directory(&config.socket_path)?;
            let agent = Agent::new(config)?;
            let mut renewed = Ok(false);
            agent
                .run_until(async {
                    renewed = tokio::select! {
                        biased;
                        () = &mut shutdown => Ok(false),
                        result = wait_for_renewal(&mut identity) => result.map(|()| true),
                    };
                })
                .await?;
            if !renewed? {
                return Ok(());
            }
            tracing::info!("using renewed system node certificate");
        }
    }

    pub(crate) fn managed_config(
        state: &Path,
        identity: &Identity,
        tls: &TlsFiles,
    ) -> Result<Config> {
        TransportOptions {
            network: identity.network_id,
            node: identity.node_id,
            tls: tls.config(),
            controller: identity.controller_config(),
            relay_endpoint: identity.relay_endpoint.clone(),
            relay_service: identity.relay_service_id,
            tcp_fallback: None,
        }
        .system_config(state)
    }

    fn prepare_socket_directory(socket: &Path) -> Result<()> {
        let parent = socket
            .parent()
            .context("system socket requires a directory")?;
        match fs::DirBuilder::new().mode(0o755).create(parent) {
            Ok(()) => (),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error).context("create system socket directory"),
        }
        let metadata = fs::symlink_metadata(parent).context("open system socket directory")?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "system socket directory must be root-owned and protected from writes by other users"
        );
        Ok(())
    }

    fn shutdown() -> Result<impl std::future::Future<Output = ()>> {
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            tokio::select! {
                _ = interrupt.recv() => (),
                _ = terminate.recv() => (),
            }
        })
    }
}
