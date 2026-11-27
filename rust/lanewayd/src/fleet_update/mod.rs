//! Root-owned, opt-in updater for Linux Rust nodes and Docker Connectors.
mod activate;
pub(crate) mod connector;
mod journal;
pub(crate) mod release;
#[cfg(test)]
mod tests;

use self::{
    activate::{Activated, Install},
    journal::{Entry, Journal},
};
use crate::{
    Config, TlsConfig,
    controller::{Client, ClientOptions},
};
use anyhow::{Context, Result, bail, ensure};
use laneway_protocol::{
    Id,
    fleet_updates::{Assignment, Channel, Component, Outcome, Poll, Report, valid_version},
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    time::{sleep, timeout},
};

const CONFIG: &str = "/etc/laneway/managed-updates-rust.toml";
const NODE_CONFIG: &str = "/etc/laneway/node-rust.toml";
const STATE: &str = "/var/lib/laneway-updater";
const BINARY: &str = "/usr/local/sbin/lanewayd-rs";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    #[serde(default)]
    enabled: bool,
    channel: Channel,
    connector: Option<connector::Settings>,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
struct RuntimeIdentity {
    #[serde(rename = "network_id")]
    network: String,
    #[serde(rename = "node_id")]
    node: String,
}

impl RuntimeIdentity {
    fn checked(&self) -> Result<(Id, Id)> {
        Ok((self.network.parse()?, self.node.parse()?))
    }
}

#[derive(Deserialize)]
struct LiveStatus {
    #[serde(flatten)]
    identity: RuntimeIdentity,
    daemon_instance_id: String,
    product_version: String,
    running: bool,
    actor: String,
    #[serde(default)]
    interface: String,
    controller: ControlHealth,
}

#[derive(Deserialize)]
struct ControlHealth {
    certificate_presented_serial: String,
    certificate_not_after_unix_seconds: u64,
    identity_lease_expires_at_unix_seconds: u64,
    configuration_lease_valid_until_unix_seconds: u64,
    configuration_lease_expired: bool,
}

impl LiveStatus {
    fn version(&self) -> Result<String> {
        stable_tag(&self.product_version)
    }

    fn healthy(&self, identity: &RuntimeIdentity, tag: &str) -> Result<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let c = &self.controller;
        Ok(&self.identity == identity
            && self.identity.checked().is_ok()
            && self.daemon_instance_id.parse::<Id>().is_ok()
            && self.actor == "node"
            && self.running
            && self.version()? == tag
            && !c.certificate_presented_serial.is_empty()
            && c.certificate_not_after_unix_seconds > now
            && c.identity_lease_expires_at_unix_seconds == 0
            && !c.configuration_lease_expired
            && c.configuration_lease_valid_until_unix_seconds > now)
    }
}

trait Runtime {
    async fn status(&self) -> Result<LiveStatus>;
    async fn restart(&self) -> Result<()>;

    async fn await_restarted(&self, before: &LiveStatus, version: &str) -> bool {
        self.await_rollback(before, version, None).await
    }
    async fn await_rollback(
        &self,
        before: &LiveStatus,
        version: &str,
        rejected: Option<&str>,
    ) -> bool {
        for index in 0..20 {
            if let Ok(current) = self.status().await
                && current.daemon_instance_id != before.daemon_instance_id
                && rejected != Some(&current.daemon_instance_id)
                && current.healthy(&before.identity, version).unwrap_or(false)
            {
                return true;
            }
            if index != 19 {
                sleep(Duration::from_secs(3)).await;
            }
        }
        false
    }
}

struct SystemNode(reqwest::Client);
impl SystemNode {
    fn new(socket: &Path) -> Result<Self> {
        Ok(Self(
            reqwest::Client::builder()
                .unix_socket(socket)
                .timeout(Duration::from_secs(3))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()?,
        ))
    }
}

impl Runtime for SystemNode {
    async fn status(&self) -> Result<LiveStatus> {
        let mut reply = self
            .0
            .get("http://lanewayd/v1/status")
            .send()
            .await
            .context("cannot query local Rust node health")?;
        ensure!(
            reply.status() == reqwest::StatusCode::OK,
            "local Rust node did not return health"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = reply.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 1 << 20,
                "local health response is too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).context("local health response is invalid")
    }

    async fn restart(&self) -> Result<()> {
        activate::restart_systemd().await
    }
}

trait Control {
    async fn poll(&self, report: &Poll) -> Result<Option<Assignment>>;
    async fn ack(&self, id: Id, report: &Report) -> Result<()>;
}

impl Control for Client {
    async fn poll(&self, poll: &Poll) -> Result<Option<Assignment>> {
        Ok(self.claim_update(poll).await?.update)
    }
    async fn ack(&self, id: Id, report: &Report) -> Result<()> {
        self.acknowledge_update(id, report).await
    }
}

async fn client(config: &Config, identity: &RuntimeIdentity) -> Result<Client> {
    let ctrl = config
        .controller
        .as_ref()
        .context("managed updates need authenticated controller authority")?;
    pinned_client(
        &config.tls,
        identity,
        &ctrl.endpoint,
        &ctrl.server_name,
        ctrl.service_id.parse()?,
        ctrl.timeout.min(Duration::from_secs(20)),
    )
    .await
}

async fn pinned_client(
    tls: &TlsConfig,
    identity: &RuntimeIdentity,
    endpoint: &str,
    server_name: &str,
    service: Id,
    deadline: Duration,
) -> Result<Client> {
    let (network, node) = identity.checked()?;
    // The daemon may renew its own leaf, but it cannot choose who can issue
    // the controller's certificate or schedule a release for this host.
    journal::protect_parents(&tls.ca)?;
    let _ = journal::root_file(&tls.ca, 0o022, 1 << 20)
        .context("the controller trust anchor must be protected by root")?;
    crate::tls::validate_local(tls, network, node)
        .context("local node credential does not match its runtime identity")?;
    Client::new(ClientOptions {
        endpoint: endpoint.into(),
        quic_endpoint: None,
        server_name: server_name.into(),
        network,
        service,
        certificate: tls.certificate.clone(),
        private_key: tls.private_key.clone(),
        ca: tls.ca.clone(),
        timeout: deadline,
        exit_generation: None,
    })
    .await
}

enum Host {
    Node {
        config: Box<Config>,
        runtime: SystemNode,
        install: Install,
    },
    Connector(connector::Connector),
}

impl Host {
    fn for_settings(settings: Option<connector::Settings>) -> Result<Self> {
        if let Some(settings) = settings {
            return Ok(Self::Connector(connector::Connector::open(settings)?));
        }
        for path in [NODE_CONFIG, BINARY].map(Path::new) {
            journal::protect_parents(path)?;
        }
        let config: Config = toml::from_str(std::str::from_utf8(&journal::root_file(
            Path::new(NODE_CONFIG),
            0o022,
            1 << 20,
        )?)?)?;
        config.validate()?;
        let runtime = SystemNode::new(&config.socket_path)?;
        let install = Install::new(Path::new(BINARY));
        install.ready()?;
        Ok(Self::Node {
            config: Box::new(config),
            runtime,
            install,
        })
    }

    fn component(&self) -> Component {
        match self {
            Self::Node { .. } => Component::Node,
            Self::Connector(_) => Component::Connector,
        }
    }

    async fn status(&self) -> Result<LiveStatus> {
        match self {
            Self::Node {
                config, runtime, ..
            } => {
                let value = runtime.status().await?;
                ensure!(
                    value.identity.checked()? == config.ids()?,
                    "node status does not match the configured network and node"
                );
                Ok(value)
            }
            Self::Connector(connector) => connector.status().await,
        }
    }

    async fn client(&self, identity: &RuntimeIdentity, journal: &Journal) -> Result<Client> {
        match self {
            Self::Node { config, .. } => client(config, identity).await,
            Self::Connector(connector) => connector.client(identity, journal.root()).await,
        }
    }

    async fn update(
        &self,
        directory: &Path,
        before: &LiveStatus,
        tag: &str,
        id: Id,
    ) -> Result<Option<Activated>> {
        let preparation_error = match self {
            Self::Node {
                install, runtime, ..
            } => match release::obtain(tag, directory).await {
                Ok(binary) => return Ok(Some(install.apply(&binary, runtime, before, tag).await?)),
                Err(err) => err,
            },
            Self::Connector(connector) => match release::connector_image(tag, directory).await {
                Ok(reference) => match connector.prepare(&reference).await {
                    Ok(()) => return Ok(Some(connector.apply(&reference, before, tag, id).await?)),
                    Err(err) => err,
                },
                Err(err) => err,
            },
        };
        // These failures precede any stop/restart of the running daemon.
        eprintln!(
            "release verification or preparation failed; serving runtime unchanged: {preparation_error}"
        );
        Ok(None)
    }
}

/// Run one timer iteration, or reconcile an explicitly inspected local claim.
/// Returns false after a durably acknowledged failure or rollback.
pub async fn run(args: impl IntoIterator<Item = String>) -> Result<bool> {
    // SAFETY: geteuid has no IO, pointer, or process mutation.
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "managed updates must run as root"
    );
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [flag, name] if flag == "--connector" => return connector::manual_update(name, None).await,
        [flag, name, pin, tag] if flag == "--connector" && pin == "--version" => {
            return connector::manual_update(name, Some(tag)).await;
        }
        _ => {}
    }
    let reconcile = match args.as_slice() {
        [] => None,
        [flag, id, target, previous] if flag == "--reconcile" => Some((
            id.parse::<Id>()?,
            stable_tag(target)?,
            stable_tag(previous)?,
        )),
        _ => bail!(
            "usage: laneway-update-rs [--reconcile ID TARGET_VERSION PREVIOUS_VERSION | --connector NAME [--version TAG]]"
        ),
    };
    for path in [CONFIG, STATE].map(Path::new) {
        journal::protect_parents(path)?;
    }
    let settings: Settings = toml::from_str(std::str::from_utf8(&journal::root_file(
        Path::new(CONFIG),
        0o077,
        4096,
    )?)?)?;
    if !settings.enabled && reconcile.is_none() {
        return Ok(true);
    }
    let journal = if let Some(connector) = &settings.connector {
        ensure!(
            connector::valid_name(&connector.container),
            "invalid managed Connector name"
        );
        Journal::open_named(Path::new(STATE), Some(&connector.container))?
    } else {
        Journal::open(Path::new(STATE))?
    };
    let host = Host::for_settings(settings.connector)?;
    let pending = journal.read()?;
    let status = host.status().await?;
    let identity = status.identity.clone();
    if let Some((id, target, previous)) = reconcile {
        let (report, bound) = reconcile_report(pending, &status, id, &target, &previous)?;
        // Build a new pinned connection immediately before the ACK, as the
        // restarted daemon may have renewed its credential.
        let controller = host.client(&identity, &journal).await?;
        if !bound {
            // A lost claim response did not establish the supplied ID.
            // Keep the original intent on a rejected or lost ACK so a
            // mistyped reconciliation does not wedge the durable journal.
            controller
                .ack(id, &report)
                .await
                .context("reconciliation was not acknowledged; claim intent retained")?;
            journal.clear()?;
            return Ok(report.state == Outcome::Healthy);
        }
        let entry = terminal(&identity, id, report);
        journal.save(&entry)?;
        return retry_terminal(&journal, &controller, entry, &status).await;
    }
    if let Some(entry) = pending {
        return retry_terminal(
            &journal,
            &host.client(&identity, &journal).await?,
            entry,
            &status,
        )
        .await;
    }
    let previous = status.version()?;
    ensure!(
        status.healthy(&identity, &previous)?,
        "the running node must have a current authenticated controller lease before claiming"
    );
    if matches!(host, Host::Node { .. }) {
        ensure!(
            installed_version(Path::new(BINARY)).await? == previous,
            "installed Rust binary differs from the live node"
        );
    }
    let Some((id, tag)) = claim(
        &journal,
        &host.client(&identity, &journal).await?,
        &identity,
        &previous,
        host.component(),
        settings.channel,
    )
    .await?
    else {
        return Ok(true);
    };
    let report = if tag == previous {
        evidence(
            &identity,
            Outcome::Healthy,
            &tag,
            "target release already serving with a valid controller lease",
        )
    } else {
        let directory = tempfile::Builder::new()
            .prefix("release-")
            .tempdir_in(journal.root())?;
        match host.update(directory.path(), &status, &tag, id).await? {
            Some(Activated::Healthy) => evidence(
                &identity,
                Outcome::Healthy,
                &tag,
                "restarted runtime identity and authenticated controller lease verified",
            ),
            Some(Activated::RolledBack) => evidence(
                &identity,
                Outcome::RolledBack,
                &previous,
                "previous release restarted with a valid controller lease",
            ),
            None => evidence(
                &identity,
                Outcome::Failed,
                "",
                "release download, verification or preflight failed before activation",
            ),
        }
    };
    // Durable terminal evidence comes before connecting to the server. A
    // failed ACK or credential read may only retry evidence, never activation.
    let entry = terminal(&identity, id, report);
    journal.save(&entry)?;
    let updated = host.status().await?;
    retry_terminal(
        &journal,
        &host.client(&identity, &journal).await?,
        entry,
        &updated,
    )
    .await
}

async fn claim(
    journal: &Journal,
    controller: &impl Control,
    identity: &RuntimeIdentity,
    previous: &str,
    component: Component,
    channel: Channel,
) -> Result<Option<(Id, String)>> {
    journal.save(&Entry::Intent {
        identity: identity.clone(),
        previous: previous.into(),
    })?;
    let Some(assignment) = controller
        .poll(&Poll {
            runtime_node_id: identity.node.clone(),
            runtime_network_id: identity.network.clone(),
            current_version: previous.into(),
            component: component.clone(),
            channel: channel.clone(),
        })
        .await
        .context("claim response was not confirmed; inspect the durable intent")?
    else {
        journal.clear()?;
        return Ok(None);
    };
    ensure!(
        assignment.component == component
            && assignment.channel == channel
            && valid_version(&assignment.version),
        "assignment does not match the configured release lane"
    );
    let id: Id = assignment.id.parse()?;
    journal.save(&Entry::Claimed {
        identity: identity.clone(),
        id: id.to_string(),
        previous: previous.into(),
        target: assignment.version.clone(),
    })?;
    Ok(Some((id, assignment.version)))
}

fn evidence(identity: &RuntimeIdentity, state: Outcome, version: &str, detail: &str) -> Report {
    Report {
        runtime_node_id: identity.node.clone(),
        runtime_network_id: identity.network.clone(),
        state,
        observed_version: version.into(),
        detail: detail.into(),
    }
}

async fn retry_terminal(
    journal: &Journal,
    controller: &impl Control,
    entry: Entry,
    status: &LiveStatus,
) -> Result<bool> {
    let Entry::Terminal {
        identity,
        id,
        report,
    } = entry
    else {
        bail!("interrupted update requires local reconciliation; it will not be installed again");
    };
    ensure!(
        status.identity == identity,
        "live runtime identity differs from the durable result"
    );
    if report.state != Outcome::Failed {
        ensure!(
            status.healthy(&identity, &report.observed_version)?,
            "live runtime no longer proves the durable result"
        );
    }
    let id = id.parse()?;
    controller
        .ack(id, &report)
        .await
        .context("result not acknowledged; it remains in the durable journal")?;
    journal.clear()?;
    Ok(report.state == Outcome::Healthy)
}

fn terminal(identity: &RuntimeIdentity, id: Id, report: Report) -> Entry {
    Entry::Terminal {
        identity: identity.clone(),
        id: id.to_string(),
        report,
    }
}

fn reconcile_report(
    entry: Option<Entry>,
    status: &LiveStatus,
    id: Id,
    target: &str,
    previous: &str,
) -> Result<(Report, bool)> {
    let (expected, bound) = match entry {
        Some(Entry::Intent {
            identity,
            previous: observed,
        }) if observed == previous => (identity, false),
        Some(Entry::Claimed {
            identity,
            previous: observed,
            target: pinned,
            id: assigned,
        }) if observed == previous && pinned == target && assigned == id.to_string() => {
            (identity, true)
        }
        Some(Entry::Terminal { .. }) => {
            bail!("a terminal result is pending; run normally to acknowledge it")
        }
        _ => bail!("reconciliation parameters do not match the outstanding local claim"),
    };
    let observed = status.version()?;
    ensure!(
        status.healthy(&expected, &observed)?,
        "restore the same healthy runtime before reconciliation"
    );
    let state = if observed == target {
        Outcome::Healthy
    } else if observed == previous {
        Outcome::RolledBack
    } else {
        bail!("running version matches neither the scheduled nor the previous release");
    };
    Ok((
        evidence(
            &expected,
            state,
            &observed,
            "operator checked runtime identity and authenticated controller lease",
        ),
        bound,
    ))
}

fn stable_tag(value: &str) -> Result<String> {
    let value = if value.starts_with('v') {
        value.to_owned()
    } else {
        format!("v{value}")
    };
    ensure!(
        valid_version(&value),
        "expected an exact stable release version"
    );
    Ok(value)
}

fn clean_command(path: impl AsRef<Path>) -> Command {
    let mut command = Command::new(path.as_ref());
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
}

async fn checked_command(mut command: Command, deadline: Duration) -> Result<()> {
    let status = timeout(deadline, command.stdout(Stdio::null()).status()).await??;
    ensure!(status.success(), "local command did not succeed");
    Ok(())
}

async fn installed_version(path: &Path) -> Result<String> {
    timeout(Duration::from_secs(10), async {
        let mut child = clean_command(path)
            .arg("--version")
            .stdout(Stdio::piped())
            .spawn()?;
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .context("read node version")?
            .take(129)
            .read_to_end(&mut output)
            .await?;
        ensure!(
            output.len() <= 128 && child.wait().await?.success(),
            "local node could not report a valid release version"
        );
        stable_tag(std::str::from_utf8(&output)?.trim())
    })
    .await?
}
