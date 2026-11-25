use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::{
    super::{RoutePlan, combine, wire},
    system::{Ip, interface_index},
};

const JOURNAL_SIZE: usize = 1024 * 1024;
type Snapshot = Vec<String>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    prior: Snapshot,
    metrics: Vec<u32>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    interface: String,
    index: u32,
    entries: BTreeMap<IpNet, Entry>,
}

pub(super) struct Routes {
    path: PathBuf,
    journal: Journal,
    active: BTreeMap<IpNet, u32>,
    interrupted: bool,
}

impl Routes {
    pub(super) fn new(state: &Path, interface: String, index: u32) -> Self {
        Self {
            path: state.join("split-routes.json"),
            journal: Journal {
                version: 1,
                interface,
                index,
                entries: BTreeMap::new(),
            },
            active: BTreeMap::new(),
            interrupted: false,
        }
    }

    pub(super) fn recover(ip: &Ip, state: &Path, deadline: Instant) -> Result<()> {
        let path = state.join("split-routes.json");
        let contents = match laneway_private::read(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("read protected split-route recovery journal"),
        };
        let journal: Journal =
            serde_json::from_slice(&contents).context("decode split-route journal")?;
        ensure!(
            journal.version == 1 && wire::valid_interface(&journal.interface) && journal.index != 0,
            "invalid split-route journal identity"
        );
        journal.restore(ip, deadline)?;
        remove_journal(&path)
    }

    pub(super) fn apply(&mut self, ip: &Ip, plan: RoutePlan, deadline: Instant) -> Result<()> {
        ensure!(
            !self.interrupted,
            "an interrupted route change requires session cleanup"
        );
        self.journal.verify_interface()?;
        // The wire parser already removed destinations containing transport bypasses.
        let desired: BTreeMap<_, _> = plan
            .routes
            .into_iter()
            .map(|route| (route.prefix, kernel_metric(route.prefix, route.metric)))
            .collect();
        let mut pending = self.journal.clone();
        let mut operations = Vec::new();
        let mut prefixes: Vec<_> = desired.keys().chain(self.active.keys()).copied().collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        for prefix in prefixes {
            let old = self.active.get(&prefix).copied();
            let new = desired.get(&prefix).copied();
            let before = snapshot(ip, prefix, deadline)?;
            if let Some(metric) = old {
                ensure!(
                    pending.owns(prefix, &before, &[metric])?,
                    "owned route {prefix} changed"
                );
            }
            if old == new {
                continue;
            }
            let entry = pending.entries.entry(prefix).or_insert_with(|| Entry {
                prior: before.clone(),
                metrics: Vec::new(),
            });
            entry.metrics = old.into_iter().chain(new).collect();
            let after = new.map_or_else(
                || entry.prior.clone(),
                |metric| route_fields(prefix, &pending.interface, metric),
            );
            operations.push((prefix, before, after));
        }
        if operations.is_empty() {
            return Ok(());
        }
        // Record both the old and new kernel forms before issuing a mutation.
        persist(&self.path, &pending)?;
        let mut applied = Vec::new();
        for (prefix, before, after) in operations {
            applied.push((prefix, before, after));
            let (prefix, before, after) = applied.last().expect("operation recorded");
            let result = replace(ip, *prefix, before, after, deadline);
            if let Err(error) = result {
                let rollback_deadline = Instant::now() + Duration::from_secs(5);
                let mut undo = Ok(());
                for (prefix, before, after) in applied.into_iter().rev() {
                    let result = pending.undo(ip, prefix, &before, &after, rollback_deadline);
                    undo = combine(undo, result);
                }
                if undo.is_ok() {
                    // The pending journal still describes all restored states if
                    // trimming it fails. Keep it for later recovery.
                    let _ = persist(&self.path, &self.journal);
                } else {
                    self.interrupted = true;
                    self.journal = pending;
                }
                return combine(Err(error), undo);
            }
        }
        let mut committed = pending.clone();
        committed.entries.retain(|prefix, entry| {
            if let Some(metric) = desired.get(prefix) {
                entry.metrics = vec![*metric];
                true
            } else {
                false
            }
        });
        // Both the pending and committed journals describe the completed
        // snapshot. Do not undo a successful mutation if this compaction fails.
        if let Err(error) = persist(&self.path, &committed) {
            eprintln!("laneway: could not compact split-route recovery journal: {error}");
        }
        self.journal = committed;
        self.active = desired;
        Ok(())
    }

    pub(super) fn restore(&self, ip: &Ip, deadline: Instant) -> Result<()> {
        self.journal.restore(ip, deadline)?;
        remove_journal(&self.path)
    }
}

impl Journal {
    fn verify_interface(&self) -> Result<()> {
        ensure!(
            interface_index(&self.interface)? == Some(self.index),
            "helper interface {} changed identity",
            self.interface
        );
        Ok(())
    }

    fn owns(&self, prefix: IpNet, current: &[String], metrics: &[u32]) -> Result<bool> {
        if !metrics
            .iter()
            .any(|metric| current == route_fields(prefix, &self.interface, *metric))
        {
            return Ok(false);
        }
        Ok(interface_index(&self.interface)? == Some(self.index))
    }

    fn restore(&self, ip: &Ip, deadline: Instant) -> Result<()> {
        let mut result = Ok(());
        for (&prefix, entry) in &self.entries {
            result = combine(result, self.restore_entry(ip, prefix, entry, deadline));
        }
        result
    }

    fn restore_entry(
        &self,
        ip: &Ip,
        prefix: IpNet,
        entry: &Entry,
        deadline: Instant,
    ) -> Result<()> {
        let current = snapshot(ip, prefix, deadline)?;
        if current == entry.prior {
            return Ok(());
        }
        ensure!(
            current.is_empty() || self.owns(prefix, &current, &entry.metrics)?,
            "refusing to replace externally modified route {prefix}"
        );
        replace(ip, prefix, &current, &entry.prior, deadline)
    }

    fn undo(
        &self,
        ip: &Ip,
        prefix: IpNet,
        before: &[String],
        after: &[String],
        deadline: Instant,
    ) -> Result<()> {
        let current = snapshot(ip, prefix, deadline)?;
        if current == before {
            return Ok(());
        }
        let entry = &self.entries[&prefix];
        ensure!(
            current.is_empty()
                || (current == after
                    && (current == entry.prior || self.owns(prefix, &current, &entry.metrics)?)),
            "refusing to roll back externally modified route {prefix}"
        );
        replace(ip, prefix, &current, before, deadline)
    }
}

fn persist(path: &Path, journal: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec(journal)?;
    ensure!(
        bytes.len() <= JOURNAL_SIZE,
        "split-route recovery journal exceeds its limit"
    );
    laneway_private::write(path, &bytes).context("commit protected split-route journal")
}

fn remove_journal(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => File::open(
            path.parent()
                .context("journal must have a parent directory")?,
        )?
        .sync_all()?,
        Err(error) if error.kind() == ErrorKind::NotFound => (),
        Err(error) => return Err(error).context("remove recovered split-route journal"),
    }
    Ok(())
}

fn family(prefix: IpNet) -> &'static str {
    if prefix.addr().is_ipv4() { "-4" } else { "-6" }
}

fn kernel_metric(prefix: IpNet, metric: u32) -> u32 {
    if prefix.addr().is_ipv6() && metric == 0 {
        1024
    } else {
        metric
    }
}

fn route_fields(prefix: IpNet, interface: &str, metric: u32) -> Snapshot {
    let destination = if prefix.prefix_len() == if prefix.addr().is_ipv4() { 32 } else { 128 } {
        prefix.addr().to_string()
    } else {
        prefix.to_string()
    };
    let mut fields = vec![
        destination,
        "dev".into(),
        interface.into(),
        "proto".into(),
        "250".into(),
    ];
    if prefix.addr().is_ipv4() {
        fields.extend(["scope".into(), "253".into()]);
    }
    if metric != 0 {
        fields.extend(["metric".into(), metric.to_string()]);
    }
    if prefix.addr().is_ipv6() {
        fields.extend(["pref".into(), "medium".into()]);
    }
    fields
}

fn snapshot(ip: &Ip, prefix: IpNet, deadline: Instant) -> Result<Snapshot> {
    let output = ip.command(
        &[
            "-N",
            family(prefix),
            "-o",
            "route",
            "show",
            "table",
            "254",
            "exact",
            &prefix.to_string(),
        ],
        deadline,
    )?;
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let result = lines
        .next()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    ensure!(
        lines.next().is_none(),
        "multiple current routes for {prefix}"
    );
    Ok(result)
}

fn replace(
    ip: &Ip,
    prefix: IpNet,
    before: &[String],
    after: &[String],
    deadline: Instant,
) -> Result<()> {
    if before == after {
        return Ok(());
    }
    ensure!(
        snapshot(ip, prefix, deadline)? == before,
        "route {prefix} changed during reconciliation"
    );
    for (operation, fields) in [("del", before), ("add", after)] {
        if !fields.is_empty() {
            let mut args = vec![family(prefix), "route", operation, "table", "254"];
            args.extend(fields.iter().map(String::as_str));
            ip.command(&args, deadline)
                .with_context(|| format!("{operation} route {prefix}"))?;
        }
    }
    ensure!(
        snapshot(ip, prefix, deadline)? == after,
        "route {prefix} differs from its requested snapshot"
    );
    Ok(())
}
