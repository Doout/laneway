use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

const MAX_JOURNAL_BYTES: u64 = 16 * 1024;

use crate::{config::Config, kernel::CommandRunner};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct DnsState {
    servers: Vec<String>,
    domains: Vec<String>,
    default_route: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    interface: String,
    prior: DnsState,
    desired: DnsState,
}

/// Transactional owner for systemd-resolved's lane0 link state.
pub(crate) struct DnsManager {
    command: String,
    interface: String,
    runner: Arc<dyn CommandRunner>,
    desired: DnsState,
    journal: PathBuf,
    prior: Option<DnsState>,
    active: bool,
}

impl DnsManager {
    pub(crate) fn configured(config: &Config, runner: Arc<dyn CommandRunner>) -> Option<Self> {
        if !config.forwarding.exit_client.enabled
            || config.forwarding.exit_client.dns_servers.is_empty()
        {
            return None;
        }
        Some(Self {
            command: config.forwarding.resolvectl_command.clone(),
            interface: config.tun.name.clone(),
            runner,
            desired: DnsState {
                servers: config
                    .forwarding
                    .exit_client
                    .dns_servers
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                domains: vec!["~.".to_owned()],
                default_route: Some(true),
            },
            journal: config.forwarding.dns_state_file.clone(),
            prior: None,
            active: false,
        })
    }

    pub(crate) fn apply(&mut self) -> Result<()> {
        if self.active {
            return Ok(());
        }
        self.recover_journal()?;
        let prior = self.snapshot().context("snapshot prior lane0 DNS")?;
        self.write_journal(&Journal {
            version: 1,
            interface: self.interface.clone(),
            prior: prior.clone(),
            desired: self.desired.clone(),
        })?;
        if let Err(error) = self.apply_state(&self.desired) {
            return match self
                .apply_state(&prior)
                .and_then(|()| self.remove_journal())
            {
                Ok(()) => Err(error),
                Err(rollback) => {
                    Err(error.context(format!("DNS apply rollback failed: {rollback:#}")))
                }
            };
        }
        self.prior = Some(prior);
        self.active = true;
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let applied = self.snapshot().context("verify owned lane0 DNS")?;
        ensure!(
            applied == self.desired,
            "lane0 DNS state changed externally; refusing to overwrite it"
        );
        let prior = self.prior.as_ref().context("prior DNS state missing")?;
        self.apply_state(prior).context("restore prior lane0 DNS")?;
        self.remove_journal()?;
        self.active = false;
        self.prior = None;
        Ok(())
    }

    fn snapshot(&self) -> Result<DnsState> {
        let servers = parse_values(&self.query("dns")?);
        let domains = parse_values(&self.query("domain")?);
        let default = parse_values(&self.query("default-route")?);
        ensure!(
            default.len() <= 1,
            "ambiguous per-link DNS default-route state"
        );
        let default_route = match default.first().map(|value| value.to_ascii_lowercase()) {
            None => None,
            Some(value) if value == "yes" => Some(true),
            Some(value) if value == "no" => Some(false),
            Some(value) => bail!("invalid per-link DNS default-route value {value:?}"),
        };
        Ok(DnsState {
            servers,
            domains,
            default_route,
        })
    }

    fn recover_journal(&self) -> Result<()> {
        let metadata = match fs::symlink_metadata(&self.journal) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("stat DNS ownership journal"),
        };
        ensure!(
            metadata.file_type().is_file()
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.len() <= MAX_JOURNAL_BYTES,
            "DNS ownership journal is invalid or oversized"
        );
        let raw = fs::read(&self.journal).context("read DNS ownership journal")?;
        let journal: Journal =
            serde_json::from_slice(&raw).context("decode DNS ownership journal")?;
        ensure!(
            journal.version == 1
                && journal.interface == self.interface
                && valid_state(&journal.prior)
                && valid_state(&journal.desired),
            "DNS ownership journal is not canonical for this interface"
        );
        let current = self.snapshot().context("snapshot stale owned DNS")?;
        ensure!(
            partial_owned(&current, &journal.prior, &journal.desired),
            "stale DNS journal does not own the current per-link state"
        );
        self.apply_state(&journal.prior)
            .context("restore crashed predecessor DNS state")?;
        self.remove_journal()
    }

    fn write_journal(&self, journal: &Journal) -> Result<()> {
        let parent = self.journal.parent().context("DNS journal has no parent")?;
        fs::create_dir_all(parent).context("create DNS journal directory")?;
        let bytes = serde_json::to_vec(journal).context("encode DNS ownership journal")?;
        ensure!(
            bytes.len() as u64 <= MAX_JOURNAL_BYTES,
            "DNS ownership journal exceeds bound"
        );
        let temporary = self
            .journal
            .with_extension(format!("tmp.{}", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .context("create DNS ownership journal")?;
        file.write_all(&bytes)
            .context("write DNS ownership journal")?;
        file.sync_all().context("sync DNS ownership journal")?;
        fs::rename(&temporary, &self.journal).context("publish DNS ownership journal")?;
        sync_parent(parent)?;
        Ok(())
    }

    fn remove_journal(&self) -> Result<()> {
        match fs::remove_file(&self.journal) {
            Ok(()) => sync_parent(self.journal.parent().context("DNS journal has no parent")?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("remove DNS ownership journal"),
        }
    }

    fn query(&self, property: &str) -> Result<Vec<u8>> {
        self.runner.run(
            &self.command,
            &[property.to_owned(), self.interface.clone()],
            None,
        )
    }

    fn apply_state(&self, state: &DnsState) -> Result<()> {
        self.run(&["revert".to_owned(), self.interface.clone()])?;
        if !state.servers.is_empty() {
            let mut arguments = vec!["dns".to_owned(), self.interface.clone()];
            arguments.extend(state.servers.iter().cloned());
            self.run(&arguments)?;
        }
        if !state.domains.is_empty() {
            let mut arguments = vec!["domain".to_owned(), self.interface.clone()];
            arguments.extend(state.domains.iter().cloned());
            self.run(&arguments)?;
        }
        if let Some(default_route) = state.default_route {
            self.run(&[
                "default-route".to_owned(),
                self.interface.clone(),
                if default_route { "yes" } else { "no" }.to_owned(),
            ])?;
        }
        Ok(())
    }

    fn run(&self, arguments: &[String]) -> Result<Vec<u8>> {
        self.runner.run(&self.command, arguments, None)
    }
}

fn valid_state(state: &DnsState) -> bool {
    state.servers.len() <= 16
        && state.domains.len() <= 32
        && state
            .servers
            .iter()
            .chain(state.domains.iter())
            .all(|value| {
                !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_whitespace)
            })
}

fn partial_owned(current: &DnsState, prior: &DnsState, desired: &DnsState) -> bool {
    (current.servers == prior.servers || current.servers == desired.servers)
        && (current.domains == prior.domains || current.domains == desired.domains)
        && (current.default_route == prior.default_route
            || current.default_route == desired.default_route)
}

fn sync_parent(parent: &Path) -> Result<()> {
    fs::File::open(parent)
        .context("open DNS journal directory")?
        .sync_all()
        .context("sync DNS journal directory")
}

impl Drop for DnsManager {
    fn drop(&mut self) {
        if self.active {
            tracing::error!(interface = %self.interface, "owned DNS state dropped without restore");
        }
    }
}

fn parse_values(output: &[u8]) -> Vec<String> {
    let mut text = String::from_utf8_lossy(output).trim().to_owned();
    if let Some((_, values)) = text.split_once(':') {
        text = values.trim().to_owned();
    }
    if text.is_empty() || text.eq_ignore_ascii_case("none") || text.eq_ignore_ascii_case("n/a") {
        Vec::new()
    } else {
        text.split_whitespace().map(str::to_owned).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeRunner {
        state: Mutex<DnsState>,
        fail_domain_once: Mutex<bool>,
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            command: &str,
            arguments: &[String],
            _input: Option<&[u8]>,
        ) -> Result<Vec<u8>> {
            ensure!(command == "resolvectl", "unexpected command");
            let property = arguments.first().context("missing property")?;
            let mut state = self.state.lock().expect("fake DNS state lock");
            match property.as_str() {
                "dns" if arguments.len() == 2 => {
                    Ok(format!("Link 7 (lane0): {}\n", state.servers.join(" ")).into_bytes())
                }
                "domain" if arguments.len() == 2 => {
                    Ok(format!("Link 7 (lane0): {}\n", state.domains.join(" ")).into_bytes())
                }
                "default-route" if arguments.len() == 2 => Ok(format!(
                    "Link 7 (lane0): {}\n",
                    state
                        .default_route
                        .map_or("", |value| if value { "yes" } else { "no" })
                )
                .into_bytes()),
                "revert" => {
                    *state = DnsState::default();
                    Ok(Vec::new())
                }
                "dns" => {
                    state.servers = arguments[2..].to_vec();
                    Ok(Vec::new())
                }
                "domain" => {
                    let mut fail = self.fail_domain_once.lock().expect("fake fail lock");
                    if *fail {
                        *fail = false;
                        bail!("injected domain failure");
                    }
                    state.domains = arguments[2..].to_vec();
                    Ok(Vec::new())
                }
                "default-route" => {
                    state.default_route =
                        Some(arguments.get(2).is_some_and(|value| value == "yes"));
                    Ok(Vec::new())
                }
                _ => bail!("unexpected resolvectl arguments {arguments:?}"),
            }
        }
    }

    fn manager(runner: Arc<FakeRunner>) -> DnsManager {
        DnsManager {
            command: "resolvectl".into(),
            interface: "lane0".into(),
            runner,
            desired: DnsState {
                servers: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()],
                domains: vec!["~.".into()],
                default_route: Some(true),
            },
            journal: tempfile::tempdir().unwrap().keep().join("dns-state.json"),
            prior: None,
            active: false,
        }
    }

    #[test]
    fn snapshot_apply_and_exact_restore() {
        let runner = Arc::new(FakeRunner::default());
        *runner.state.lock().unwrap() = DnsState {
            servers: vec!["192.0.2.53".into()],
            domains: vec!["corp.example".into()],
            default_route: Some(false),
        };
        let mut dns = manager(runner.clone());
        dns.apply().unwrap();
        assert_eq!(*runner.state.lock().unwrap(), dns.desired);
        dns.restore().unwrap();
        assert_eq!(runner.state.lock().unwrap().servers, ["192.0.2.53"]);
    }

    #[test]
    fn partial_apply_rolls_back_and_external_replacement_is_preserved() {
        let runner = Arc::new(FakeRunner::default());
        let prior = DnsState {
            servers: vec!["192.0.2.53".into()],
            domains: vec!["corp.example".into()],
            default_route: Some(false),
        };
        *runner.state.lock().unwrap() = prior.clone();
        *runner.fail_domain_once.lock().unwrap() = true;
        let mut dns = manager(runner.clone());
        assert!(dns.apply().is_err());
        assert_eq!(*runner.state.lock().unwrap(), prior);
        dns.apply().unwrap();
        runner.state.lock().unwrap().servers = vec!["8.8.8.8".into()];
        assert!(dns.restore().is_err());
        assert_eq!(runner.state.lock().unwrap().servers, ["8.8.8.8"]);
        // The fake intentionally leaves ownership dirty; avoid a misleading
        // Drop diagnostic after asserting the fail-safe behavior.
        dns.active = false;
    }

    #[test]
    fn crashed_predecessor_journal_recovers_exact_prior_state() {
        let runner = Arc::new(FakeRunner::default());
        let prior = DnsState {
            servers: vec!["192.0.2.53".into()],
            domains: vec!["corp.example".into()],
            default_route: Some(false),
        };
        *runner.state.lock().unwrap() = prior.clone();
        let mut crashed = manager(runner.clone());
        crashed.apply().unwrap();
        let journal = crashed.journal.clone();
        assert!(journal.exists());
        crashed.active = false;

        let mut recovered = manager(runner.clone());
        recovered.journal = journal;
        recovered.apply().unwrap();
        assert_eq!(*runner.state.lock().unwrap(), recovered.desired);
        recovered.restore().unwrap();
        assert_eq!(*runner.state.lock().unwrap(), prior);
        assert!(!recovered.journal.exists());
    }

    #[test]
    fn corrupt_or_externally_replaced_stale_journal_fails_safe() {
        let runner = Arc::new(FakeRunner::default());
        let mut crashed = manager(runner.clone());
        crashed.apply().unwrap();
        let journal = crashed.journal.clone();
        crashed.active = false;
        runner.state.lock().unwrap().servers = vec!["8.8.8.8".into()];
        let mut next = manager(runner.clone());
        next.journal = journal.clone();
        assert!(next.apply().is_err());
        assert_eq!(runner.state.lock().unwrap().servers, ["8.8.8.8"]);

        fs::write(&journal, b"not-json").unwrap();
        assert!(next.apply().is_err());
    }
}
