use std::{
    fs::File,
    io::{self, Seek, Write},
    net::IpAddr,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use laneway_protocol::{Id, v1::EnrollmentClass};
use lanewayd_rs::{ControllerConfig, TlsConfig, rootless};
use tokio::{
    runtime::Runtime,
    signal::unix::{SignalKind, signal},
    sync::watch,
};
use zeroize::Zeroizing;

use crate::{
    bootstrap::{self, Metadata},
    enrollment, profile, session_runtime,
};

use super::{Options, filter};

const CONFIGURATION_DEADLINE: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
pub(crate) struct SessionOptions {
    pub selected_exit: Option<Id>,
    pub failure_mode: String,
    pub dns: Vec<IpAddr>,
    pub local_lan: Vec<IpNet>,
    pub runtime_dir: PathBuf,
    pub requested_routes: Vec<IpNet>,
}

pub(super) fn run(options: Options) -> Result<()> {
    let authority = options.authority()?;
    let failure_mode = options.failure_mode()?;
    let backend = Backend::new(
        !options.exit.is_empty(),
        failure_mode,
        options.dns.iter().any(|value| value.contains('%')),
    )?;
    let routes = parse_prefixes(&options.routes).context("--route")?;
    let dns = parse_addresses(&options.dns).context("--dns")?;
    let local_lan = parse_prefixes(&options.local_lan).context("--local-lan")?;
    let runtime = Runtime::new().context("create connect runtime")?;
    let mut stopping = runtime.block_on(async {
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let (stopped, receiver) = watch::channel(false);
        tokio::spawn(async move {
            tokio::select! {
                _ = interrupt.recv() => (),
                _ = terminate.recv() => (),
            }
            stopped.send_replace(true);
        });
        Ok::<_, io::Error>(receiver)
    })?;
    let mut metadata = bootstrap::fetch(&authority)?;
    profile::validate_platform_artifact(&metadata)?;
    if *stopping.borrow() {
        return Ok(());
    }
    let permissions = std::fs::Permissions::from_mode(0o700);
    let runtime_dir = tempfile::Builder::new()
        .prefix("laneway-connect-")
        .permissions(permissions.clone())
        .tempdir()
        .context("create temporary runtime directory")?;
    std::fs::set_permissions(runtime_dir.path(), permissions)
        .context("protect temporary runtime directory")?;

    let mut identity = load_identity(&options, &authority, &metadata)?;
    let mut selected_exit = None;
    loop {
        if *stopping.borrow() {
            break;
        }
        if let Identity::Saved(profile) = identity {
            let (due, _) = profile.renewal()?;
            if due {
                let profile = Box::new((*profile).renew(&metadata)?);
                println!(
                    "laneway refreshed saved login network={} node={}",
                    profile.network_id, profile.node_id
                );
                identity = Identity::Saved(profile);
            } else {
                identity = Identity::Saved(profile);
            }
        }

        let network: Id = metadata
            .network_id
            .parse()
            .context("invalid bootstrap network ID")?;
        let node = identity.node()?;
        let controller = controller_config(&metadata);
        let credentials = CredentialPaths::new(&identity, &metadata, runtime_dir.path())?;
        let initial = runtime
            .block_on(async {
                tokio::time::timeout(
                    CONFIGURATION_DEADLINE,
                    rootless::get_configuration(&controller, network, node, &credentials.tls),
                )
                .await?
            })
            .context("fetch temporary session configuration")?;
        if *stopping.borrow() {
            break;
        }
        identity.check_configuration(&initial)?;
        if selected_exit.is_none() {
            selected_exit = filter::resolve_exit(&initial, &options.exit, node)?;
        }
        let automatic = !options.ephemeral && routes.is_empty();
        filter::select(&initial, node, &routes, selected_exit, automatic)?;
        let deadline = identity.deadline()?;
        let stop_at = async {
            tokio::select! {
                _ = stopping.wait_for(|stopped| *stopped) => (),
                _ = wait_for_deadline(deadline) => (),
            }
        };

        match backend {
            #[cfg(target_os = "linux")]
            Backend::Linux => {
                use lanewayd_rs::{ConfigurationFilter, SessionRoute, rootless::TransportOptions};

                let relay = metadata
                    .relays
                    .first()
                    .context("bootstrap metadata contains no relay")?;
                let dial = TransportOptions {
                    network,
                    node,
                    tls: credentials.tls.clone(),
                    controller,
                    relay_endpoint: relay.endpoint.clone(),
                    relay_service: relay.service_id.parse()?,
                    tcp_fallback: None,
                };
                let session = SessionOptions {
                    selected_exit,
                    failure_mode: failure_mode.to_owned(),
                    dns: dns.iter().map(|(address, _)| *address).collect(),
                    local_lan: local_lan.clone(),
                    runtime_dir: runtime_dir.path().to_owned(),
                    requested_routes: routes.clone(),
                };
                let requested = routes.clone();
                let limit: ConfigurationFilter = std::sync::Arc::new(move |configuration| {
                    filter::select(configuration, node, &requested, selected_exit, automatic).map(
                        |routes| {
                            routes
                                .into_iter()
                                .map(|route| SessionRoute {
                                    id: route.id,
                                    prefix: route.prefix,
                                })
                                .collect()
                        },
                    )
                });
                runtime.block_on(crate::connect_linux::run(dial, &session, limit, stop_at))?;
            }
            Backend::Companion => {
                let materials = ConnectMaterials::load(&identity, &metadata)?;
                let metadata = serde_json::to_value(&metadata)?;
                let routes = display_list(&routes);
                let dns = dns
                    .iter()
                    .map(|(address, scope)| {
                        scope.as_ref().map_or_else(
                            || address.to_string(),
                            |scope| format!("{address}%{scope}"),
                        )
                    })
                    .collect::<Vec<_>>();
                let local_lan = display_list(&local_lan);
                let exit = selected_exit.map(|id| id.to_string()).unwrap_or_default();
                let network = network.to_string();
                let node = node.to_string();
                runtime.block_on(session_runtime::run(
                    &session_runtime::Session {
                        metadata: &metadata,
                        ca_pem: &materials.ca,
                        certificate_pem: &materials.certificate,
                        private_key_pem: &materials.key,
                        wireguard_private_key: &*materials.wireguard,
                        network_id: &network,
                        node_id: &node,
                        lease_expires_at: identity.lease_seconds()?,
                        saved_login: !options.ephemeral,
                        routes: &routes,
                        exit: &exit,
                        failure_mode,
                        dns: &dns,
                        local_lan: &local_lan,
                    },
                    stop_at,
                ))?;
            }
        }

        if *stopping.borrow()
            || options.ephemeral
            || deadline.is_none_or(|at| at > SystemTime::now())
        {
            break;
        }
        metadata =
            bootstrap::fetch(&authority).context("refresh discovery before login renewal")?;
        let Identity::Saved(profile) = identity else {
            unreachable!("ephemeral sessions do not renew")
        };
        profile.validate_metadata(&metadata)?;
        let profile = Box::new((*profile).renew(&metadata)?);
        println!(
            "laneway refreshed saved login network={} node={}; reconnecting authorized routes",
            profile.network_id, profile.node_id
        );
        identity = Identity::Saved(profile);
    }
    println!("laneway disconnected; temporary networking restored");
    Ok(())
}

enum Backend {
    #[cfg(target_os = "linux")]
    Linux,
    Companion,
}

impl Backend {
    fn new(exit_requested: bool, failure_mode: &str, scoped_dns: bool) -> Result<Self> {
        #[cfg(target_os = "macos")]
        let _ = (exit_requested, failure_mode, scoped_dns);
        #[cfg(target_os = "linux")]
        if !scoped_dns && crate::connect_linux::eligible(exit_requested, failure_mode) {
            crate::connect_linux::preflight()?;
            return Ok(Self::Linux);
        }
        session_runtime::preflight()?;
        Ok(Self::Companion)
    }
}

enum Identity {
    Saved(Box<profile::SavedProfile>),
    Ephemeral(enrollment::Credentials),
}

impl Identity {
    fn node(&self) -> Result<Id> {
        match self {
            Self::Saved(profile) => profile
                .node_id
                .parse()
                .context("invalid saved login NodeID"),
            Self::Ephemeral(credentials) => Ok(credentials.node_id),
        }
    }

    fn deadline(&self) -> Result<Option<SystemTime>> {
        match self {
            Self::Saved(profile) => Ok(Some(profile.renewal()?.1)),
            Self::Ephemeral(credentials) => Ok(credentials.lease_expires_at),
        }
    }

    fn lease_seconds(&self) -> Result<i64> {
        match self {
            Self::Ephemeral(credentials) => {
                let lease = credentials
                    .lease_expires_at
                    .context("ephemeral enrollment omitted lease")?;
                Ok(i64::try_from(lease.duration_since(UNIX_EPOCH)?.as_secs())?)
            }
            Self::Saved(_) => Ok(0),
        }
    }

    fn check_configuration(
        &self,
        configuration: &laneway_protocol::v1::NodeConfiguration,
    ) -> Result<()> {
        let class = match self {
            Self::Saved(_) => EnrollmentClass::RememberedUser,
            Self::Ephemeral(_) => EnrollmentClass::EphemeralUser,
        };
        ensure!(
            configuration.enrollment_class() == class,
            "controller configuration enrollment class differs from session identity"
        );
        ensure!(
            configuration.identity_lease_expires_at_unix_seconds
                == u64::try_from(self.lease_seconds()?)?,
            "controller configuration lease differs from session identity"
        );
        Ok(())
    }
}

fn load_identity(options: &Options, authority: &str, metadata: &Metadata) -> Result<Identity> {
    if options.ephemeral {
        let code = profile::read_enrollment_code(options.token_file.as_deref())?;
        let controller = enrollment::Controller {
            endpoint: &metadata.controller.enrollment_endpoint,
            quic_endpoint: &metadata.controller.quic_endpoint,
            server_name: &metadata.controller.server_name,
            network_id: metadata.network_id.parse()?,
            service_id: metadata.controller.service_id.parse()?,
            ca_pem: metadata.trust.ca_pem.as_bytes(),
        };
        let identity = enrollment::enroll(&controller, &code, EnrollmentClass::EphemeralUser)?;
        return Ok(Identity::Ephemeral(identity));
    }
    let result = match profile::load(authority) {
        Ok(profile) => {
            ensure!(
                options.token_file.is_none(),
                "--token-file is only used by login, --remembered enrollment, or --ephemeral sessions"
            );
            profile
        }
        Err(error) if profile::is_missing(&error) && options.remembered => {
            profile::enroll_remembered(authority, metadata, options.token_file.as_deref())?
        }
        Err(error) if profile::is_missing(&error) => bail!(
            "no saved login for {authority}; run 'laneway login {authority}' or use --ephemeral"
        ),
        Err(error) => return Err(error),
    };
    result.validate_metadata(metadata)?;
    Ok(Identity::Saved(Box::new(result)))
}

fn controller_config(metadata: &Metadata) -> ControllerConfig {
    ControllerConfig {
        endpoint: metadata.controller.enrollment_endpoint.clone(),
        quic_endpoint: Some(metadata.controller.quic_endpoint.clone()),
        server_name: metadata.controller.server_name.clone(),
        service_id: metadata.controller.service_id.clone(),
        poll_interval: POLL_INTERVAL,
        timeout: CONFIGURATION_DEADLINE,
    }
}

struct CredentialPaths {
    tls: TlsConfig,
    _open: Vec<File>,
}

impl CredentialPaths {
    fn new(identity: &Identity, metadata: &Metadata, runtime_dir: &Path) -> Result<Self> {
        let mut open = Vec::new();
        let tls = match identity {
            Identity::Saved(profile) => TlsConfig {
                ca: profile.ca.clone(),
                certificate: profile.certificate.clone(),
                private_key: profile.private_key.clone(),
            },
            Identity::Ephemeral(credentials) => {
                let mut stage = |data: &[u8]| -> Result<PathBuf> {
                    let (file, path) = anonymous_credential(runtime_dir, data)?;
                    open.push(file);
                    Ok(path)
                };
                TlsConfig {
                    ca: stage(metadata.trust.ca_pem.as_bytes())?,
                    certificate: stage(&credentials.certificate_pem)?,
                    private_key: stage(&credentials.private_key_pem)?,
                }
            }
        };
        Ok(Self { tls, _open: open })
    }
}

fn anonymous_credential(runtime_dir: &Path, data: &[u8]) -> Result<(File, PathBuf)> {
    let mut file =
        tempfile::tempfile_in(runtime_dir).context("create anonymous runtime credential")?;
    file.write_all(data)?;
    file.rewind()?;
    let descriptor = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    let path = PathBuf::from(descriptor).join(file.as_raw_fd().to_string());
    Ok((file, path))
}

struct ConnectMaterials {
    ca: Vec<u8>,
    certificate: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
    wireguard: Zeroizing<[u8; 32]>,
}

impl ConnectMaterials {
    fn load(identity: &Identity, metadata: &Metadata) -> Result<Self> {
        Ok(match identity {
            Identity::Saved(profile) => Self {
                ca: laneway_private::read(&profile.ca).context("read saved login CA")?,
                certificate: laneway_private::read(&profile.certificate)
                    .context("read saved login certificate")?,
                key: Zeroizing::new(
                    laneway_private::read(&profile.private_key).context("read saved login key")?,
                ),
                wireguard: Zeroizing::new(profile.read_wireguard_key()?),
            },
            Identity::Ephemeral(credentials) => Self {
                ca: metadata.trust.ca_pem.as_bytes().to_vec(),
                certificate: credentials.certificate_pem.to_vec(),
                key: Zeroizing::new(credentials.private_key_pem.to_vec()),
                wireguard: Zeroizing::new(*credentials.wireguard_private_key),
            },
        })
    }
}

async fn wait_for_deadline(deadline: Option<SystemTime>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep(
            deadline
                .duration_since(SystemTime::now())
                .unwrap_or_default(),
        )
        .await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn display_list<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn parse_addresses(values: &[String]) -> Result<Vec<(IpAddr, Option<String>)>> {
    let mut addresses = Vec::new();
    for value in values {
        let message = || format!("{value:?} is not a unicast IP address");
        let (address, scope) = value
            .split_once('%')
            .map_or((value.as_str(), None), |(addr, scope)| (addr, Some(scope)));
        let address: IpAddr = address.parse().with_context(message)?;
        ensure!(
            !address.is_unspecified()
                && !address.is_multicast()
                && address.to_canonical() == address
                && scope.is_none_or(|scope| address.is_ipv6() && !scope.is_empty()),
            "{}",
            message()
        );
        let entry = (address, scope.map(str::to_owned));
        if !addresses.contains(&entry) {
            addresses.push(entry);
        }
    }
    Ok(addresses)
}

fn parse_prefixes(values: &[String]) -> Result<Vec<IpNet>> {
    let forbidden = [
        "0.0.0.0/32",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
    ]
    .map(|value| value.parse::<IpNet>().expect("valid non-routable prefix"));
    let mut prefixes = Vec::new();
    for value in values {
        let message = || format!("{value:?} is not a canonical routable prefix");
        let prefix: IpNet = value.parse().with_context(message)?;
        ensure!(
            prefix == prefix.trunc()
                && prefix.prefix_len() != 0
                && prefix.addr().to_canonical() == prefix.addr()
                && !forbidden
                    .iter()
                    .any(|&excluded| filter::overlap(prefix, excluded).is_some()),
            "{}",
            message()
        );
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    Ok(prefixes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_reject_broad_ranges_that_overlap_reserved_addresses() {
        for invalid in [
            "0.0.0.0/0",
            "127.0.0.0/7",
            "169.254.1.0/24",
            "::ffff:192.0.2.0/120",
            "fe80::/64",
            "fc00::/6",
            "100.64.0.1/24",
        ] {
            assert!(parse_prefixes(&[invalid.to_owned()]).is_err(), "{invalid}");
        }
        assert_eq!(
            parse_prefixes(&[
                "192.0.2.0/24".to_owned(),
                "192.0.2.0/24".to_owned(),
                "fd00::/8".to_owned()
            ])
            .unwrap()
            .len(),
            2
        );
        assert!(parse_addresses(&["::ffff:192.0.2.1".to_owned()]).is_err());
        assert!(parse_addresses(&["192.0.2.1%eth0".to_owned()]).is_err());
        assert_eq!(
            parse_addresses(&["fe80::1%eth0".to_owned()]).unwrap(),
            [("fe80::1".parse().unwrap(), Some("eth0".to_owned()))]
        );
    }

    #[test]
    fn ephemeral_credentials_have_no_named_file_in_runtime_directory() {
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let (_file, descriptor) = anonymous_credential(directory.path(), b"test key").unwrap();
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read(descriptor).unwrap(), b"test key");
        assert_eq!(
            std::fs::metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[test]
    fn expired_ephemeral_deadline_signals_clean_shutdown() {
        Runtime::new().unwrap().block_on(async {
            let expired = SystemTime::now() - Duration::from_secs(1);
            tokio::time::timeout(Duration::from_millis(100), wait_for_deadline(Some(expired)))
                .await
                .unwrap();
        });
    }
}
