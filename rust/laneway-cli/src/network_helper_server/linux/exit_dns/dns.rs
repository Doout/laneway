use std::{
    fs,
    fs::File,
    io::ErrorKind,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::super::system::interface_index;
use super::Runner;

const CLEANUP: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    servers: Vec<String>,
    domains: Vec<String>,
    default_route: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    link: u32,
    prior: State,
    applied: State,
    previous: Option<State>,
}

pub(super) struct Dns {
    interface: String,
    runner: Runner,
    journal: PathBuf,
    owned: Option<Ownership>,
}

impl Dns {
    pub(super) fn new(
        interface: &str,
        state: &Path,
        lock: &std::fs::File,
        deadline: Instant,
    ) -> Result<Self> {
        let dns = Self {
            interface: interface.to_owned(),
            runner: Runner::new(state, lock)?,
            journal: state.join("dns.json"),
            owned: None,
        };
        let bytes = match laneway_private::read(&dns.journal) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(dns),
            Err(error) => return Err(error).context("read prior exit DNS state"),
        };
        let prior: Ownership = serde_json::from_slice(&bytes)?;
        if interface_index(&dns.interface)? != Some(prior.link) {
            dns.remove_journal()?;
            return Ok(dns);
        }
        let current = dns.snapshot(deadline)?;
        let candidates = [
            Some(&prior.prior),
            Some(&prior.applied),
            prior.previous.as_ref(),
        ];
        ensure!(
            (current.servers.is_empty()
                || candidates
                    .iter()
                    .flatten()
                    .any(|state| state.servers == current.servers))
                && (current.domains.is_empty()
                    || candidates
                        .iter()
                        .flatten()
                        .any(|state| state.domains == current.domains))
                && candidates
                    .iter()
                    .flatten()
                    .any(|state| state.default_route == current.default_route),
            "prior helper does not own the current per-link DNS state"
        );
        dns.set(&prior.prior, deadline)?;
        dns.remove_journal()?;
        Ok(dns)
    }

    pub(super) fn apply(&mut self, servers: &[IpAddr], deadline: Instant) -> Result<()> {
        let desired = State {
            servers: servers.iter().map(ToString::to_string).collect(),
            domains: vec!["~.".to_owned()],
            default_route: true,
        };
        let link = interface_index(&self.interface)?.context("exit DNS tunnel link disappeared")?;
        let current = self.snapshot(deadline)?;
        if let Some(owned) = &self.owned {
            ensure!(
                owned.link == link && owned.applied == current,
                "per-link DNS changed outside its helper owner"
            );
            if owned.applied == desired {
                return Ok(());
            }
        }
        let pending = Ownership {
            link,
            prior: self
                .owned
                .as_ref()
                .map_or_else(|| current.clone(), |owned| owned.prior.clone()),
            applied: desired,
            previous: Some(current.clone()),
        };
        self.persist(&pending)?;
        let stable = Ownership {
            previous: None,
            ..pending.clone()
        };
        if let Err(error) = self
            .set(&pending.applied, deadline)
            .and_then(|()| self.persist(&stable))
        {
            let cleanup = Instant::now() + CLEANUP;
            let rollback = self
                .set(&current, cleanup)
                .and_then(|()| match &self.owned {
                    Some(owned) => self.persist(owned),
                    None => self.remove_journal(),
                });
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => {
                    Err(error.context(format!("restore prior per-link DNS: {rollback:#}")))
                }
            };
        }
        self.owned = Some(stable);
        Ok(())
    }

    pub(super) fn restore(&mut self, deadline: Instant) -> Result<()> {
        let Some(owned) = self.owned.clone() else {
            return Ok(());
        };
        ensure!(
            interface_index(&self.interface)? == Some(owned.link),
            "exit DNS tunnel link was replaced"
        );
        let current = self.snapshot(deadline)?;
        ensure!(
            current == owned.applied,
            "per-link DNS changed outside its helper owner"
        );
        self.persist(&Ownership {
            link: owned.link,
            prior: owned.prior.clone(),
            applied: owned.prior.clone(),
            previous: Some(owned.applied.clone()),
        })?;
        if let Err(error) = self
            .set(&owned.prior, deadline)
            .and_then(|()| self.remove_journal())
        {
            let cleanup = Instant::now() + CLEANUP;
            let rollback = self
                .set(&owned.applied, cleanup)
                .and_then(|()| self.persist(&owned));
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => Err(error.context(format!(
                    "restore the active link DNS configuration: {rollback:#}"
                ))),
            };
        }
        self.owned = None;
        Ok(())
    }

    fn persist(&self, ownership: &Ownership) -> Result<()> {
        laneway_private::write(&self.journal, &serde_json::to_vec(ownership)?)
            .context("persist exit DNS ownership")
    }

    fn remove_journal(&self) -> Result<()> {
        match fs::remove_file(&self.journal) {
            Ok(()) => File::open(self.journal.parent().expect("DNS state has a parent"))?
                .sync_all()
                .map_err(Into::into),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn query(&self, command: &str, deadline: Instant) -> Result<Vec<String>> {
        let bytes = self
            .runner
            .run("resolvectl", &[command, &self.interface], deadline)?;
        let output = std::str::from_utf8(&bytes)?;
        let (link, values) = output
            .trim()
            .split_once(':')
            .context("invalid per-link DNS output")?;
        ensure!(
            link.starts_with("Link ") && link.ends_with(&format!(" ({})", self.interface)),
            "resolver returned another interface"
        );
        let values: Vec<_> = values
            .split_ascii_whitespace()
            .map(ToOwned::to_owned)
            .collect();
        ensure!(
            values.len() <= 32
                && values
                    .iter()
                    .all(|value| value.len() <= 253 && !value.starts_with('-')),
            "per-link DNS entries exceed helper bounds"
        );
        Ok(values)
    }

    fn snapshot(&self, deadline: Instant) -> Result<State> {
        let default = self.query("default-route", deadline)?;
        let default_route = match default.as_slice() {
            [value] if value == "yes" => true,
            [value] if value == "no" => false,
            _ => anyhow::bail!("invalid per-link DNS default route"),
        };
        Ok(State {
            servers: self.query("dns", deadline)?,
            domains: self.query("domain", deadline)?,
            default_route,
        })
    }

    fn set(&self, state: &State, deadline: Instant) -> Result<()> {
        for (name, values) in [("dns", &state.servers), ("domain", &state.domains)] {
            let mut args = vec![name, &self.interface];
            if values.is_empty() {
                args.push("");
            } else {
                args.extend(values.iter().map(String::as_str));
            }
            self.runner.run("resolvectl", &args, deadline)?;
        }
        self.runner.run(
            "resolvectl",
            &[
                "default-route",
                &self.interface,
                if state.default_route { "yes" } else { "no" },
            ],
            deadline,
        )?;
        Ok(())
    }
}
