//! Transactional replacement of one root-managed Docker Connector.
use super::{
    Activated, LiveStatus, RuntimeIdentity, STATE, clean_command, journal, release, stable_tag,
};
use crate::{TlsConfig, controller::Client};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    time::{sleep, timeout},
};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

const DOCKER: &str = "/usr/bin/docker";
const MAX_OUTPUT: usize = 1 << 20;
const STATE_MOUNT: &str = "/var/lib/laneway";
const LABEL: &str = "io.laneway.managed-update";
const DOCKER_TIMEOUT: Duration = Duration::from_secs(35);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    pub(super) container: String,
    endpoint: String,
    server_name: String,
    #[serde(deserialize_with = "deserialize_id")]
    service_id: laneway_protocol::Id,
    #[serde(deserialize_with = "deserialize_id")]
    network_id: laneway_protocol::Id,
    ca_file: PathBuf,
}

fn deserialize_id<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<laneway_protocol::Id, D::Error> {
    String::deserialize(de)?
        .parse()
        .map_err(serde::de::Error::custom)
}

pub(super) struct Connector {
    settings: Settings,
    docker: LocalDocker,
    _lock: Lock,
}

struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

impl Connector {
    pub(super) fn open(settings: Settings) -> Result<Self> {
        let lock = lock_connector(&settings.container)?;
        Ok(Self {
            settings,
            docker: LocalDocker,
            _lock: lock,
        })
    }

    pub(super) async fn status(&self) -> Result<LiveStatus> {
        let (_, status) = serving_connector(&self.docker, &self.settings.container).await?;
        ensure!(
            status.identity.network == self.settings.network_id.to_string(),
            "running Connector does not match the configured network"
        );
        Ok(status)
    }

    async fn profile(&self) -> Result<Profile> {
        local_profile(&self.docker, &self.settings.container).await
    }
}

fn lock_connector(name: &str) -> Result<Lock> {
    ensure!(valid_name(name), "invalid managed Connector name");
    let path = Path::new(DOCKER);
    journal::protect_parents(path)?;
    // Inspect only a locally installed executable; Docker contexts,
    // daemon hosts and registry settings cannot be inherited.
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "Docker CLI must not be a symlink"
    );
    journal::verify_file(&fs::File::open(path)?, 0o022)?;
    let dir = Path::new("/run/lock");
    journal::protect_parents(dir)?;
    let metadata = fs::symlink_metadata(dir)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == 0
            && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0),
        "Docker updater lock parent must be protected"
    );
    let lock = dir.join(format!("laneway-connector-update-{name}"));
    DirBuilder::new()
        .mode(0o700)
        .create(&lock)
        .context("Connector updater lock exists; inspect any interrupted update first")?;
    Ok(Lock(lock))
}

async fn local_profile(docker: &impl Docker, name: &str) -> Result<Profile> {
    ensure!(
        lookup(docker, &previous_name(name)).await?.is_none(),
        "an interrupted Connector replacement still has its previous container"
    );
    let id = lookup(docker, name)
        .await?
        .context("managed Connector does not exist")?;
    inspect(docker, &id, name).await
}

async fn serving_connector(docker: &impl Docker, name: &str) -> Result<(Profile, LiveStatus)> {
    let old = local_profile(docker, name).await?;
    let status = status(docker, &old.id).await?;
    ensure!(
        status.interface == "userspace",
        "running Connector is not a userspace runtime"
    );
    Ok((old, status))
}

impl Connector {
    pub(super) async fn client(&self, identity: &RuntimeIdentity, root: &Path) -> Result<Client> {
        let (network, node) = identity.checked()?;
        ensure!(
            network == self.settings.network_id,
            "configured Connector network does not match daemon"
        );
        let profile = self.profile().await?;
        let fresh = status(&self.docker, &profile.id).await?;
        ensure!(
            fresh.identity == *identity,
            "Connector identity changed before authentication"
        );
        let stage = tempfile::tempdir_in(root)?;
        let tls = TlsConfig {
            ca: self.settings.ca_file.clone(),
            certificate: copy_credential(&self.docker, &profile.id, "node.crt", stage.path())
                .await?,
            private_key: copy_credential(&self.docker, &profile.id, "node.key", stage.path())
                .await?,
        };
        super::pinned_client(
            &tls,
            identity,
            &self.settings.endpoint,
            &self.settings.server_name,
            self.settings.service_id,
            Duration::from_secs(20),
        )
        .await
        .with_context(|| format!("authenticate managed Connector {}", node))
    }

    /// Pull and check the new image without giving it network access or write
    /// access to the existing identity. Errors here leave the old container live.
    pub(super) async fn prepare(&self, reference: &str) -> Result<()> {
        let old = self.profile().await?;
        pull(&self.docker, reference, &old.volume).await
    }

    pub(super) async fn apply(
        &self,
        reference: &str,
        before: &LiveStatus,
        target: &str,
        update: laneway_protocol::Id,
    ) -> Result<Activated> {
        let old = self.profile().await?;
        apply(
            &self.docker,
            &self.settings.container,
            old,
            reference,
            before,
            target,
            update,
        )
        .await
    }
}

pub(super) async fn manual_update(name: &str, pin: Option<&str>) -> Result<bool> {
    ensure!(valid_name(name), "invalid managed Connector name");
    let tag = pin.map(stable_tag).transpose()?;
    journal::protect_parents(Path::new(STATE))?;
    let journal = journal::Journal::open_named(Path::new(STATE), Some(name))?;
    ensure!(
        journal.read()?.is_none(),
        "a fleet update is pending for this Connector; reconcile it first"
    );
    let _lock = lock_connector(name)?;
    let docker = LocalDocker;
    let (old, before) = serving_connector(&docker, name).await?;
    let previous = before.version()?;
    ensure!(
        before.healthy(&before.identity, &previous)?,
        "the Connector must have a current authenticated controller lease before updating"
    );
    let target = match tag {
        Some(tag) => tag,
        None => release::latest_tag().await?,
    };
    match release::compare_versions(&target, &previous)? {
        std::cmp::Ordering::Equal => {
            println!("{name} is already current ({target})");
            return Ok(true);
        }
        std::cmp::Ordering::Less => {
            anyhow::bail!("{target} would downgrade {name} from {previous}");
        }
        std::cmp::Ordering::Greater => {}
    }
    let directory = tempfile::Builder::new()
        .prefix("connector-release-")
        .tempdir_in(journal.root())?;
    let image = release::connector_image(&target, directory.path()).await?;
    pull(&docker, &image, &old.volume).await?;
    let prepared = local_profile(&docker, name).await?;
    ensure!(
        prepared.id == old.id,
        "Connector changed during release verification"
    );
    let outcome = apply(
        &docker,
        name,
        prepared,
        &image,
        &before,
        &target,
        crate::agent::random_id()?,
    )
    .await?;
    match outcome {
        Activated::Healthy => println!("{name} updated to {target}"),
        Activated::RolledBack => {
            eprintln!("{name} did not become healthy at {target}; restored {previous}")
        }
    }
    Ok(outcome == Activated::Healthy)
}

pub(super) fn valid_name(name: &str) -> bool {
    name.len() <= 90
        && name
            .strip_prefix("laneway-connector-")
            .is_some_and(|suffix| {
                suffix
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn previous_name(name: &str) -> String {
    format!("{name}-laneway-update-previous")
}

#[derive(Debug)]
struct Exit;
impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Docker rejected the operation")
    }
}
impl std::error::Error for Exit {}

trait Docker {
    async fn run(&self, args: &[&str], deadline: Duration) -> Result<Zeroizing<Vec<u8>>>;
    async fn settle(&self) {
        sleep(Duration::from_secs(3)).await;
    }
}

struct LocalDocker;
impl Docker for LocalDocker {
    async fn run(&self, args: &[&str], deadline: Duration) -> Result<Zeroizing<Vec<u8>>> {
        let mut command = clean_command(DOCKER);
        command
            .args(["--host", "unix:///var/run/docker.sock"])
            .args(args)
            .stdout(Stdio::piped());
        timeout(deadline, async {
            let mut child = command.spawn()?;
            let mut data = Zeroizing::new(Vec::new());
            child
                .stdout
                .take()
                .context("read Docker reply")?
                .take(MAX_OUTPUT as u64 + 1)
                .read_to_end(&mut data)
                .await?;
            ensure!(data.len() <= MAX_OUTPUT, "Docker output exceeded its bound");
            ensure!(child.wait().await?.success(), Exit);
            Ok(data)
        })
        .await
        .context("Docker operation outcome was not confirmed")?
    }
}

async fn json<T: DeserializeOwned>(docker: &impl Docker, args: &[&str]) -> Result<T> {
    let bytes = docker.run(args, DOCKER_TIMEOUT).await?;
    serde_json::from_slice(&bytes).context("invalid Docker response")
}

async fn lookup(docker: &impl Docker, name: &str) -> Result<Option<String>> {
    // Names have already been validated. Escape the only regexp operator in
    // this grammar so an unrelated name cannot match the Docker filter.
    let filter = format!("name=^/{}$", name.replace('.', "\\."));
    let bytes = docker
        .run(
            &[
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                &filter,
            ],
            DOCKER_TIMEOUT,
        )
        .await?;
    let value = std::str::from_utf8(&bytes)?.trim();
    if value.is_empty() {
        return Ok(None);
    }
    ensure!(
        valid_id(value),
        "Docker returned an ambiguous container name"
    );
    Ok(Some(value.into()))
}

async fn status(docker: &impl Docker, id: &str) -> Result<LiveStatus> {
    let bytes = docker
        .run(
            &[
                "exec",
                id,
                "/usr/local/bin/laneway",
                "status",
                "--socket",
                "/run/laneway/lanewayd.sock",
                "--json",
            ],
            Duration::from_secs(4),
        )
        .await?;
    serde_json::from_slice(&bytes).context("invalid Connector status")
}

async fn copy_credential(
    docker: &impl Docker,
    id: &str,
    name: &str,
    dir: &Path,
) -> Result<PathBuf> {
    let source = format!("{id}:/var/lib/laneway/connector/{name}");
    let bytes = docker
        .run(&["cp", &source, "-"], Duration::from_secs(5))
        .await?;
    ensure!(
        bytes.len() <= 256 << 10,
        "Connector credential archive exceeded its bound"
    );
    let data = single_file(&bytes, name)?;
    let path = dir.join(name);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?
        .write_all(&data)?;
    Ok(path)
}

fn single_file(bytes: &[u8], name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut tar = tar::Archive::new(bytes);
    let mut entries = tar.entries()?.raw(true);
    let mut file = entries
        .next()
        .context("Connector credential archive is empty")??;
    ensure!(
        file.header().entry_type().is_file()
            && file.path_bytes().as_ref() == name.as_bytes()
            && (1..=128 << 10).contains(&file.size()),
        "Connector credential is not one bounded regular file"
    );
    let mut body = Zeroizing::new(Vec::new());
    file.read_to_end(&mut body)?;
    ensure!(
        body.len() as u64 == file.size() && entries.next().is_none(),
        "ambiguous Connector credential archive"
    );
    Ok(body)
}

#[derive(Debug)]
struct Profile {
    id: String,
    hostname: String,
    network: String,
    volume: String,
    tmpfs: [String; 2],
}

async fn inspect(docker: &impl Docker, id: &str, name: &str) -> Result<Profile> {
    let mut rows: Vec<Value> = json(docker, &["container", "inspect", id]).await?;
    ensure!(rows.len() == 1, "ambiguous Docker inspection");
    profile(&rows.remove(0), id, name)
}

fn profile(row: &Value, id: &str, name: &str) -> Result<Profile> {
    let config = &row["Config"];
    let host = &row["HostConfig"];
    let volume = format!("{name}-state");
    let hostname = config["Hostname"]
        .as_str()
        .context("Connector hostname is missing")?;
    let network = host["NetworkMode"]
        .as_str()
        .context("Connector network is missing")?;
    let network_supported = matches!(network, "bridge" | "default")
        || network.strip_prefix("container:").is_some_and(valid_id);
    let mounts = row["Mounts"]
        .as_array()
        .context("Connector mounts are missing")?;
    let empty = |v: &Value| {
        v.is_null()
            || v.as_array().is_some_and(Vec::is_empty)
            || v.as_object().is_some_and(serde_json::Map::is_empty)
    };
    let root_mounts: Vec<_> = mounts.iter().filter(|m| m["Type"] != "tmpfs").collect();
    let tmpfs = host["Tmpfs"]
        .as_object()
        .context("standard Connector needs private tmpfs mounts")?;
    ensure!(
        tmpfs.len() == 2
            && mounts
                .iter()
                .filter(|m| m["Type"] == "tmpfs")
                .all(|m| m["Destination"] == "/tmp" || m["Destination"] == "/run/laneway"),
        "Connector mounts include unsupported tmpfs destinations"
    );
    let mount = |path: &str| -> Result<String> {
        let opts = tmpfs
            .get(path)
            .and_then(Value::as_str)
            .context("missing Connector tmpfs")?;
        ensure!(
            opts.len() <= 256
                && opts
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'=' | b'-'))
                && ["noexec", "nosuid", "nodev", "uid=65532", "gid=65532"]
                    .into_iter()
                    .all(|value| opts.split(',').any(|part| part == value)),
            "unsupported Connector tmpfs permissions"
        );
        Ok(format!("{path}:{opts}"))
    };
    let tmpfs = [mount("/tmp")?, mount("/run/laneway")?];
    let labels = config["Labels"].is_null()
        || config["Labels"].as_object().is_some_and(|labels| {
            labels
                .keys()
                .all(|l| l == LABEL || l.starts_with("org.opencontainers.image."))
        });
    let network_membership = if network.starts_with("container:") {
        empty(&row["NetworkSettings"]["Networks"])
    } else {
        row["NetworkSettings"]["Networks"]
            .as_object()
            .is_some_and(|networks| networks.len() == 1 && networks.contains_key("bridge"))
    };
    ensure!(
        row["Id"] == id
            && row["Name"] == format!("/{name}")
            && row["State"]["Running"] == true
            && config["Image"].as_str().is_some_and(official_rust_image)
            && config["User"] == "65532:65532"
            && config["Entrypoint"] == serde_json::json!(["/usr/local/bin/laneway"])
            && config["Cmd"] == serde_json::json!(["connector", "run"])
            && !hostname.is_empty()
            && !hostname.starts_with('-')
            && hostname.len() <= 64
            && hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
            && network_supported
            && network_membership
            && host["ReadonlyRootfs"] == true
            && host["Privileged"] == false
            && host["CapDrop"] == serde_json::json!(["ALL"])
            && host["SecurityOpt"] == serde_json::json!(["no-new-privileges:true"])
            && host["RestartPolicy"]["Name"] == "unless-stopped"
            && [
                "CapAdd",
                "PortBindings",
                "Devices",
                "DeviceRequests",
                "ExtraHosts",
                "Links",
                "Sysctls",
                "VolumesFrom"
            ]
            .into_iter()
            .all(|k| empty(&host[k]))
            && [
                "Memory",
                "MemorySwap",
                "MemoryReservation",
                "NanoCpus",
                "CpuShares",
                "CpuPeriod",
                "CpuQuota",
                "PidsLimit"
            ]
            .into_iter()
            .all(|k| host[k].is_null() || host[k] == 0)
            && ["CpusetCpus", "CpusetMems", "UsernsMode", "CgroupParent"]
                .into_iter()
                .all(|k| host[k].is_null() || host[k] == "")
            && host["PublishAllPorts"] == false
            && config["Env"].as_array().is_some_and(|env| env
                .iter()
                .all(|e| e.as_str().is_some_and(|e| e.starts_with("PATH=")
                    || e == "SETUP_TOKEN_FILE=/var/lib/laneway/setup.token")))
            && labels,
        "container is not a supported standard Rust Connector"
    );
    ensure!(
        root_mounts.len() == 1
            && root_mounts[0]["Type"] == "volume"
            && root_mounts[0]["Name"] == volume
            && root_mounts[0]["Destination"] == STATE_MOUNT
            && root_mounts[0]["RW"] == true,
        "Connector must use its own writable named identity volume"
    );
    Ok(Profile {
        id: id.into(),
        hostname: hostname.into(),
        network: network.into(),
        volume,
        tmpfs,
    })
}

fn official_rust_image(value: &str) -> bool {
    value
        .strip_prefix("ghcr.io/doout/lane-edge-rust")
        .is_some_and(|suffix| suffix.starts_with(':') || suffix.starts_with("@sha256:"))
}

async fn pull(docker: &impl Docker, image: &str, volume: &str) -> Result<()> {
    docker
        .run(&["pull", image], Duration::from_secs(180))
        .await?;
    validate_candidate(docker, image, volume).await
}

async fn validate_candidate(docker: &impl Docker, image: &str, volume: &str) -> Result<()> {
    let mount = format!("{volume}:{STATE_MOUNT}:ro");
    docker
        .run(
            &[
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--user",
                "65532:65532",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--volume",
                &mount,
                image,
                "connector",
                "validate",
            ],
            DOCKER_TIMEOUT,
        )
        .await?;
    Ok(())
}

async fn apply(
    docker: &impl Docker,
    name: &str,
    old: Profile,
    image: &str,
    before: &LiveStatus,
    target: &str,
    update: laneway_protocol::Id,
) -> Result<Activated> {
    let previous = previous_name(name);
    let old_version = before.version()?;
    let current = status(docker, &old.id).await?;
    ensure!(
        current.daemon_instance_id == before.daemon_instance_id
            && current.healthy(&before.identity, &old_version)?,
        "Connector changed during update preparation"
    );
    docker
        .run(&["stop", "--time", "15", &old.id], DOCKER_TIMEOUT)
        .await?;
    if let Err(error) = docker
        .run(&["rename", &old.id, &previous], DOCKER_TIMEOUT)
        .await
    {
        if error.is::<Exit>() && lookup(docker, name).await?.as_ref() == Some(&old.id) {
            docker.run(&["start", &old.id], DOCKER_TIMEOUT).await?;
            ensure!(
                restarted(docker, &old.id, before, &old_version).await,
                "Connector rename failed; previous runtime restarted but health was not confirmed"
            );
            return Ok(Activated::RolledBack);
        }
        return Err(
            error.context("Connector rename outcome is uncertain; inspect the preserved container")
        );
    }

    let volume = format!("{}:{STATE_MOUNT}", old.volume);
    let label = format!("{LABEL}={update}");
    let mut create = vec![
        "create",
        "--name",
        name,
        "--network",
        &old.network,
        "--restart",
        "unless-stopped",
        "--pull",
        "never",
        "--user",
        "65532:65532",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--tmpfs",
        &old.tmpfs[0],
        "--tmpfs",
        &old.tmpfs[1],
        "--volume",
        &volume,
        "--label",
        &label,
    ];
    if !old.network.starts_with("container:") {
        create.extend(["--hostname", &old.hostname]);
    }
    create.push(image);
    let candidate = docker.run(&create, DOCKER_TIMEOUT).await;
    let candidate = match candidate {
        Ok(bytes) => {
            let id = std::str::from_utf8(&bytes)?.trim().to_owned();
            ensure!(
                valid_id(&id) && id != old.id,
                "Docker did not identify the replacement container"
            );
            Some(id)
        }
        Err(err) if err.is::<Exit>() && lookup(docker, name).await?.is_none() => None,
        Err(err) => return Err(err.context(
            "Connector creation outcome is uncertain; inspect the journal and preserved container",
        )),
    };
    if let Some(id) = &candidate {
        match docker.run(&["start", id], DOCKER_TIMEOUT).await {
            Ok(_) if restarted(docker, id, before, target).await => {
                ensure!(
                    lookup(docker, name).await?.as_ref() == Some(id),
                    "Connector replacement no longer owns its name"
                );
                docker.run(&["rm", &old.id], DOCKER_TIMEOUT).await?;
                return Ok(Activated::Healthy);
            }
            Ok(_) => {}
            Err(err) if err.is::<Exit>() => {}
            Err(err) => return Err(err),
        }
        ensure!(
            lookup(docker, name).await?.as_ref() == Some(id),
            "a different container holds the Connector name"
        );
        docker.run(&["rm", "--force", id], DOCKER_TIMEOUT).await?;
    }
    ensure!(
        lookup(docker, name).await?.is_none(),
        "cannot restore over a different Connector"
    );
    docker
        .run(&["rename", &old.id, name], DOCKER_TIMEOUT)
        .await?;
    docker.run(&["start", &old.id], DOCKER_TIMEOUT).await?;
    ensure!(
        restarted(docker, &old.id, before, &old_version).await,
        "Connector restarted but rollback health was not confirmed"
    );
    Ok(Activated::RolledBack)
}

async fn restarted(docker: &impl Docker, id: &str, before: &LiveStatus, tag: &str) -> bool {
    for index in 0..20 {
        if let Ok(current) = status(docker, id).await
            && current.interface == "userspace"
            && current.daemon_instance_id != before.daemon_instance_id
            && current.healthy(&before.identity, tag).unwrap_or(false)
        {
            return true;
        }
        if index != 19 {
            docker.settle().await;
        }
    }
    false
}
