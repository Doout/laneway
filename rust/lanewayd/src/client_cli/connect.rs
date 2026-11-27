use std::{
    fs::{File, Permissions},
    io::{Seek, Write},
    net::IpAddr,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use clap::Args;
use ipnet::IpNet;
use laneway_protocol::{
    Id,
    v1::{EnrollmentClass, NodeConfiguration, RouteKind},
};
use lanewayd_rs::{
    Agent, Config, ForegroundRoutes, TlsConfig,
    rootless::{TransportOptions, get_configuration},
};
use sha2::{Digest, Sha256};

use super::{
    bootstrap::{self, Metadata},
    enrollment,
    profiles::{Credentials, Profile, Saved, Store},
};

#[derive(Args)]
pub(super) struct Options {
    domain: Option<String>,
    #[arg(long)]
    token_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "ephemeral")]
    remembered: bool,
    #[arg(long)]
    ephemeral: bool,
    #[arg(long)]
    route: Vec<IpNet>,
    #[arg(long)]
    exit: Option<String>,
    #[arg(long, default_value = "closed", value_parser = ["closed", "open"])]
    failure_mode: String,
    #[arg(long, requires = "exit")]
    dns: Vec<IpAddr>,
    #[arg(long, requires = "exit")]
    local_lan: Vec<IpNet>,
}

enum Session {
    Saved(Saved),
    Ephemeral {
        node: Id,
        tls: TlsConfig,
        _files: [File; 3],
        expires: u64,
    },
}

impl Session {
    fn node(&self) -> Result<Id> {
        match self {
            Self::Saved(saved) => Ok(saved.profile.node_id.parse()?),
            Self::Ephemeral { node, .. } => Ok(*node),
        }
    }

    fn tls(&self) -> TlsConfig {
        match self {
            Self::Saved(saved) => TlsConfig {
                ca: saved.files.ca.clone(),
                certificate: saved.files.certificate.clone(),
                private_key: saved.files.private_key.clone(),
            },
            Self::Ephemeral { tls, .. } => tls.clone(),
        }
    }

    fn renewal_at(&self) -> Result<u64> {
        match self {
            Self::Saved(saved) => saved.renewal_at(now()?),
            Self::Ephemeral { expires, .. } => Ok(*expires),
        }
    }
}

pub(super) async fn run(options: Options) -> Result<()> {
    #[cfg(target_os = "linux")]
    ensure!(
        laneway_private::is_root()
            && std::env::var("PATH").as_deref() == Ok("/usr/sbin:/usr/bin:/sbin:/bin"),
        "Linux foreground networking requires the installed privileged CLI; use sudo laneway connect"
    );

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let store = Store::from_environment();
    let domain = match options.domain.as_deref() {
        Some(domain) => domain.to_owned(),
        None => store.default_authority()?.context(
            "no saved login; run 'laneway login DOMAIN' or specify DOMAIN for an ephemeral connection"
        )?,
    };
    let mut metadata = bootstrap::fetch(&domain).await?;
    metadata.current_artifact()?;
    let network = metadata.network_id.parse::<Id>()?;
    let directory = tempfile::Builder::new()
        .prefix("laneway-connect-")
        .tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let mut session = prepare_session(&store, &domain, &metadata, &options).await?;
    if let Session::Saved(saved) = &session
        && saved.renewal_at(now()?)? <= now()?
    {
        session = Session::Saved(
            store
                .renew(&domain, &saved.profile.generation, &metadata)
                .await?,
        );
    }
    let node = session.node()?;
    let exit = if let Some(selector) = &options.exit {
        let config =
            get_configuration(&metadata.controller.config(), network, node, &session.tls()).await?;
        Some(resolve_exit(&config, selector, node)?)
    } else {
        None
    };

    let shutdown = crate::shutdown_signal()?;
    tokio::pin!(shutdown);
    loop {
        let config = config(
            directory.path(),
            &domain,
            &metadata,
            network,
            &session,
            &options,
            exit,
        )?;
        let deadline = Duration::from_secs(session.renewal_at()?.saturating_sub(now()?));
        let agent = Agent::new(config)?;
        let mut ended = None;
        agent
            .run_until(async {
                ended = tokio::select! {
                    biased;
                    () = &mut shutdown => Some(false),
                    () = tokio::time::sleep(deadline) => Some(true),
                };
            })
            .await?;
        if !ended.context("Rust foreground runtime stopped before the session ended")? {
            return Ok(());
        }
        let Session::Saved(saved) = &session else {
            return Ok(());
        };
        metadata = bootstrap::fetch(&domain)
            .await
            .context("refresh discovery before login renewal")?;
        let updated = store
            .renew(&domain, &saved.profile.generation, &metadata)
            .await?;
        println!(
            "laneway refreshed saved login network={network} node={node}; reconnecting authorized routes"
        );
        session = Session::Saved(updated);
    }
}

async fn prepare_session(
    store: &Store,
    domain: &str,
    metadata: &Metadata,
    options: &Options,
) -> Result<Session> {
    if options.ephemeral {
        let issued = enrollment::redeem(
            metadata,
            options.token_file.as_deref(),
            EnrollmentClass::EphemeralUser,
        )
        .await?;
        let (ca, ca_path) = anonymous_file(metadata.trust.ca_pem.as_bytes())?;
        let (certificate, certificate_path) = anonymous_file(&issued.certificate)?;
        let (private, key_path) = anonymous_file(issued.key.as_bytes())?;
        return Ok(Session::Ephemeral {
            node: issued.node,
            tls: TlsConfig {
                ca: ca_path,
                certificate: certificate_path,
                private_key: key_path,
            },
            _files: [ca, certificate, private],
            expires: issued.lease_expires,
        });
    }
    if let Some(saved) = store.load(domain)? {
        ensure!(
            options.token_file.is_none(),
            "--token-file is only used by login, --remembered enrollment, or --ephemeral sessions"
        );
        saved.confirm_binding(metadata)?;
        return Ok(Session::Saved(saved));
    }
    ensure!(
        options.remembered,
        "no saved login for {domain}; run 'laneway login {domain}' or use --ephemeral"
    );
    let _lock = store.lock(domain)?;
    ensure!(
        !store.exists(domain)?,
        "saved login was created by another process; retry connect"
    );
    let issued = enrollment::redeem(
        metadata,
        options.token_file.as_deref(),
        EnrollmentClass::RememberedUser,
    )
    .await?;
    store.save(
        Profile::new(
            domain,
            metadata.network_id.parse()?,
            metadata.controller.service_id.parse()?,
            issued.node,
        )?,
        Credentials {
            ca: metadata.trust.ca_pem.as_bytes(),
            certificate: &issued.certificate,
            private_key: issued.key.as_bytes(),
            wireguard_key: issued.wireguard.as_ref(),
        },
    )?;
    Ok(Session::Saved(
        store
            .load(domain)?
            .context("new saved login was not published")?,
    ))
}

fn config(
    directory: &Path,
    domain: &str,
    metadata: &Metadata,
    network: Id,
    session: &Session,
    options: &Options,
    exit: Option<Id>,
) -> Result<Config> {
    let relay = metadata
        .relays
        .first()
        .context("bootstrap metadata has no relay")?;
    let mut config = TransportOptions {
        network,
        node: session.node()?,
        tls: session.tls(),
        controller: metadata.controller.config(),
        relay_endpoint: relay.endpoint.clone(),
        relay_service: relay.service_id.parse()?,
        tcp_fallback: None,
    }
    .system_config(directory)?;
    config.socket_path = directory.join("laneway.sock");
    config.exit_intent_path = directory.join("exit-intent.json");
    config.tun.name = if cfg!(target_os = "macos") {
        "utun".into()
    } else {
        let hash = Sha256::digest(directory.as_os_str().as_encoded_bytes());
        format!("lwc{}", hex::encode(&hash[..6]))
    };
    config.foreground_routes = Some(ForegroundRoutes {
        policy_private: matches!(session, Session::Saved(_)) && options.route.is_empty(),
        requested: options.route.clone(),
    });
    let origin = bootstrap::discovery_url(domain)?;
    let host = &config.relay.server_name;
    if origin.host_str().is_some_and(|hostname| {
        hostname
            .trim_end_matches('.')
            .eq_ignore_ascii_case(host.trim_end_matches('.'))
    }) {
        let port = origin.port().unwrap_or(443);
        config.tcp_fallback =
            Some(toml::toml! { address = (format!("{host}:{port}")) }.try_into()?);
    }
    if let Some(exit) = exit {
        config.forwarding.dns_state_file = directory.join("dns-state.json");
        config.forwarding.exit_client = toml::toml! {
            enabled = true
            authorized = true
            selected_node = (exit.to_string())
            failure_mode = (options.failure_mode.as_str())
            local_lan_bypass = (options.local_lan.iter().map(ToString::to_string).collect::<Vec<_>>())
            dns_servers = (options.dns.iter().map(ToString::to_string).collect::<Vec<_>>())
        }.try_into()?;
    }
    Ok(config)
}

fn anonymous_file(bytes: &[u8]) -> Result<(File, PathBuf)> {
    let mut file = tempfile::tempfile()?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.rewind()?;
    let base = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let path = Path::new(base).join(file.as_raw_fd().to_string());
    Ok((file, path))
}

fn resolve_exit(config: &NodeConfiguration, selector: &str, local: Id) -> Result<Id> {
    let exit = match selector.parse::<Id>() {
        Ok(exit) => exit,
        Err(_) => {
            let mut peers = config.peers.iter().filter(|peer| peer.name == selector);
            let peer = peers.next().with_context(|| {
                format!("exit {selector:?} does not identify a controller peer")
            })?;
            ensure!(
                peers.next().is_none(),
                "exit name {selector:?} is ambiguous"
            );
            Id::from_slice(&peer.node_id)?
        }
    };
    ensure!(
        exit != local,
        "exit {selector:?} must identify a different controller peer"
    );
    ensure!(
        config.exit_policy.as_ref().is_some_and(|policy| policy
            .authorized_node_ids
            .iter()
            .any(|id| id == exit.as_bytes())),
        "exit {selector:?} is not controller-authorized"
    );
    ensure!(
        config.routes.as_ref().is_some_and(|routes| routes
            .routes
            .iter()
            .any(|route| route.kind == RouteKind::Exit as i32
                && route.via_node_id == exit.as_bytes())),
        "exit {selector:?} has no approved exit route"
    );
    Ok(exit)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
