use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    fs::File,
    io::ErrorKind,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::super::super::ExitPlan;
use super::super::system::interface_index;
use super::Runner;

const TABLE: &str = "51820";
const PRIORITY: &str = "11000";
const PROTO: &str = "251";
const ROUTE_METRIC: &str = "100";
const GUARD_METRIC: &str = "42760";
const CLEANUP: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    routes: BTreeMap<IpNet, Target>,
    families: BTreeSet<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Target {
    device: String,
    gateway: Option<IpAddr>,
    source: Option<IpAddr>,
    onlink: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    interface: String,
    before: Plan,
    after: Plan,
}

pub(super) struct Policy {
    interface: String,
    runner: Runner,
    policy_dir: PathBuf,
    lock: Option<File>,
    active: Plan,
}

impl Policy {
    pub(super) fn new(
        interface: &str,
        state: &Path,
        lock: &std::fs::File,
        deadline: Instant,
    ) -> Result<Self> {
        let policy_dir = state
            .parent()
            .context("exit state has no namespace directory")?
            .join(".exit-policy");
        laneway_private::ensure_directory(&policy_dir)?;
        let policy = Self {
            interface: interface.into(),
            runner: Runner::new(state, lock)?,
            policy_dir,
            lock: None,
            active: Plan::default(),
        };
        if policy.journal().try_exists()? {
            match laneway_private::try_lock(&policy.policy_dir.join("policy.lock")) {
                Ok(_lock) => policy.recover(deadline)?,
                Err(error) if error.kind() == ErrorKind::WouldBlock => (),
                Err(error) => return Err(error).context("lock prior exit state"),
            }
        }
        Ok(policy)
    }

    pub(super) fn active(&self) -> bool {
        !self.active.families.is_empty()
    }

    fn journal(&self) -> PathBuf {
        self.policy_dir.join("policy.json")
    }

    pub(super) fn apply(&mut self, plan: ExitPlan, deadline: Instant) -> Result<()> {
        if self.lock.is_none() {
            self.lock = Some(
                laneway_private::try_lock(&self.policy_dir.join("policy.lock"))
                    .context("another helper owns exit routing in this namespace")?,
            );
            self.recover(deadline)?;
        }
        let next = self.plan(plan, deadline)?;
        self.check_rule_precedence(&next, deadline)?;
        ensure!(
            self.active.families.is_empty() || self.active.families == next.families,
            "restore the current exit plan before changing its address families"
        );
        self.transact(next, deadline)
    }

    pub(super) fn restore(&mut self, deadline: Instant) -> Result<()> {
        if self.lock.is_none() {
            return Ok(());
        }
        self.transact(Plan::default(), deadline)?;
        self.lock.take();
        Ok(())
    }

    fn transact(&mut self, next: Plan, deadline: Instant) -> Result<()> {
        let previous = self.active.clone();
        let mut current = self.inspect(&previous, &previous, deadline)?;
        ensure!(
            current == previous,
            "exit routes or rules changed outside their owner"
        );
        if previous == next {
            return Ok(());
        }
        let journal = Journal {
            interface: self.interface.clone(),
            before: previous.clone(),
            after: next.clone(),
        };
        self.persist(&journal)?;
        let changed = self
            .reconcile(&mut current, &next, deadline)
            .and_then(|()| self.verify(&next, deadline))
            .and_then(|()| self.commit(&next));
        if let Err(error) = changed {
            let cleanup = Instant::now() + CLEANUP;
            let rollback = self
                .inspect(&previous, &next, cleanup)
                .and_then(|mut actual| {
                    self.reconcile(&mut actual, &previous, cleanup)?;
                    self.verify(&previous, cleanup)?;
                    self.commit(&previous)
                });
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => {
                    Err(error.context(format!("restore prior exit policy: {rollback:#}")))
                }
            };
        }
        self.active = next;
        Ok(())
    }

    fn verify(&self, plan: &Plan, deadline: Instant) -> Result<()> {
        ensure!(
            self.inspect(plan, plan, deadline)? == *plan,
            "kernel did not retain the complete exit policy"
        );
        Ok(())
    }

    fn check_rule_precedence(&self, plan: &Plan, deadline: Instant) -> Result<()> {
        for ipv4 in &plan.families {
            let raw =
                self.runner
                    .run("ip", &[family(*ipv4), "-N", "-j", "rule", "show"], deadline)?;
            for row in serde_json::from_slice::<Vec<Value>>(&raw)? {
                let priority = row["priority"]
                    .as_u64()
                    .context("policy rule omitted its priority")?;
                ensure!(
                    priority >= 11000
                        || (priority == 0 && row["src"] == "all" && row["table"] == "255"),
                    "an earlier policy rule prevents fail-closed exit routing"
                );
            }
        }
        Ok(())
    }

    fn recover(&self, deadline: Instant) -> Result<()> {
        let bytes = match laneway_private::read(&self.journal()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("read exit policy ownership journal"),
        };
        let journal: Journal =
            serde_json::from_slice(&bytes).context("decode exit policy ownership journal")?;
        ensure!(
            super::super::super::wire::valid_interface(&journal.interface),
            "invalid prior exit policy interface"
        );
        ensure!(
            interface_index(&journal.interface)?.is_none(),
            "prior exit interface remains attached"
        );
        let mut actual = self.inspect(&journal.before, &journal.after, deadline)?;
        self.reconcile(&mut actual, &Plan::default(), deadline)?;
        self.commit(&Plan::default())
    }

    fn commit(&self, plan: &Plan) -> Result<()> {
        if plan.families.is_empty() {
            match fs::remove_file(self.journal()) {
                Ok(()) => File::open(&self.policy_dir)?.sync_all().map_err(Into::into),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        } else {
            self.persist(&Journal {
                interface: self.interface.clone(),
                before: plan.clone(),
                after: plan.clone(),
            })
        }
    }

    fn persist(&self, journal: &Journal) -> Result<()> {
        laneway_private::write(&self.journal(), &serde_json::to_vec(journal)?)
            .context("write exit policy ownership journal")
    }

    fn plan(&self, plan: ExitPlan, deadline: Instant) -> Result<Plan> {
        let families: BTreeSet<_> = plan
            .tunnel_prefixes
            .iter()
            .map(|prefix| prefix.addr().is_ipv4())
            .collect();
        let mut routes = BTreeMap::new();
        let transport: Vec<_> = plan
            .transport_bypasses
            .into_iter()
            .map(host_prefix)
            .filter(|prefix| families.contains(&prefix.addr().is_ipv4()))
            .collect();
        ensure!(
            !transport.is_empty(),
            "the exit plan does not bypass an endpoint in its enabled families"
        );
        let transport = transport.into_iter();
        let exceptions: BTreeSet<_> = transport
            .chain(
                plan.local_lan_bypasses
                    .into_iter()
                    .filter(|prefix| families.contains(&prefix.addr().is_ipv4())),
            )
            .collect();
        for prefix in exceptions {
            ensure!(
                !plan.tunnel_prefixes.contains(&prefix),
                "exit bypass conflicts with a split default"
            );
            let target = self.native_target(prefix, deadline)?;
            ensure!(
                target.device != self.interface,
                "exit bypass points into its own tunnel"
            );
            routes.insert(prefix, target);
        }
        for ipv4 in &families {
            routes.insert(default_prefix(*ipv4), guard());
        }
        for prefix in plan.tunnel_prefixes {
            routes.insert(
                prefix,
                Target {
                    device: self.interface.clone(),
                    gateway: None,
                    source: None,
                    onlink: false,
                },
            );
        }
        Ok(Plan { routes, families })
    }

    fn native_target(&self, prefix: IpNet, deadline: Instant) -> Result<Target> {
        let address = prefix.addr();
        let family = family(address.is_ipv4());
        let rows = self.runner.run(
            "ip",
            &[
                family,
                "-N",
                "-j",
                "route",
                "show",
                "table",
                "main",
                "match",
                &address.to_string(),
            ],
            deadline,
        )?;
        let mut selected: Option<(u8, u64, Target)> = None;
        for row in serde_json::from_slice::<Vec<Value>>(&rows)? {
            let destination = parse_prefix(
                row.get("dst")
                    .and_then(Value::as_str)
                    .context("native route omitted destination")?,
                address.is_ipv4(),
            )?;
            if !destination.contains(&prefix) {
                continue;
            }
            let length = destination.prefix_len();
            let metric = row.get("metric").and_then(Value::as_u64).unwrap_or(0);
            if selected
                .as_ref()
                .is_some_and(|(old_length, old_metric, _)| {
                    (*old_length, std::cmp::Reverse(*old_metric))
                        > (length, std::cmp::Reverse(metric))
                })
            {
                continue;
            }
            ensure!(
                row.get("multipath").is_none()
                    && row.get("nexthops").is_none()
                    && row.get("nhid").is_none(),
                "native bypass route uses an unsupported next-hop group"
            );
            ensure!(
                row.get("type").is_none() || row["type"] == "1",
                "native bypass route is not unicast"
            );
            let target = parse_target(&row, address.is_ipv4())?;
            if let Some((old_length, old_metric, old_target)) = selected.as_ref() {
                ensure!(
                    (*old_length, *old_metric) != (length, metric) || old_target == &target,
                    "native bypass route is ambiguous"
                );
            }
            selected = Some((length, metric, target));
        }
        selected
            .map(|(_, _, route)| route)
            .with_context(|| format!("no native main-table route for {prefix}"))
    }

    fn inspect(&self, before: &Plan, after: &Plan, deadline: Instant) -> Result<Plan> {
        let mut actual = Plan::default();
        // Guards are reserved per enabled family and tracked separately by their /0 key.
        for ipv4 in [true, false] {
            let family = family(ipv4);
            let known = before.families.contains(&ipv4) || after.families.contains(&ipv4);
            let raw = self.runner.run(
                "ip",
                &[family, "-N", "-j", "rule", "show", "pref", PRIORITY],
                deadline,
            )?;
            let rules: Vec<Value> = serde_json::from_slice(&raw)?;
            ensure!(
                rules.len() <= 1,
                "exit policy priority is shared by multiple rules"
            );
            if let Some(rule) = rules.first() {
                ensure!(
                    known
                        && *rule
                            == serde_json::json!({"priority":11000,"src":"all","table":TABLE,"protocol":PROTO}),
                    "exit policy priority is owned by another program"
                );
                actual.families.insert(ipv4);
            }
            let (success, raw, error) = self.runner.output(
                "ip",
                &[family, "-N", "-j", "route", "show", "table", TABLE],
                deadline,
            )?;
            if !success {
                ensure!(
                    raw.iter().all(u8::is_ascii_whitespace) || raw == b"[]\n",
                    "exit policy table query returned unexpected data"
                );
                ensure!(
                    String::from_utf8_lossy(&error).contains("FIB table does not exist"),
                    "query exit policy table: {}",
                    String::from_utf8_lossy(&error)
                );
                continue;
            }
            for row in serde_json::from_slice::<Vec<Value>>(&raw)? {
                ensure!(
                    known && row.get("protocol").is_some_and(|value| value == PROTO),
                    "exit policy table contains foreign state"
                );
                let prefix = parse_prefix(
                    row.get("dst")
                        .and_then(Value::as_str)
                        .context("exit route omitted destination")?,
                    ipv4,
                )?;
                let target = if prefix.prefix_len() == 0 {
                    ensure!(
                        row["type"] == "7" && row["metric"] == 42760,
                        "unexpected exit fail-closed guard"
                    );
                    guard()
                } else {
                    ensure!(
                        row["metric"] == 100
                            && row.get("nexthops").is_none()
                            && row.get("multipath").is_none()
                            && row.get("nhid").is_none(),
                        "exit route fields changed outside their owner"
                    );
                    let target = parse_target(&row, ipv4)?;
                    ensure!(
                        before.routes.get(&prefix) == Some(&target)
                            || after.routes.get(&prefix) == Some(&target),
                        "exit route changed outside its owner"
                    );
                    target
                };
                ensure!(
                    actual.routes.insert(prefix, target).is_none(),
                    "exit route is duplicated"
                );
            }
        }
        Ok(actual)
    }

    fn reconcile(&self, current: &mut Plan, next: &Plan, deadline: Instant) -> Result<()> {
        // An existing selector and its guard remain live while exceptions are replaced.
        for (prefix, target) in &next.routes {
            match current.routes.get(prefix) {
                Some(existing) if existing == target => (),
                previous => self.change_route(
                    if previous.is_some() { "replace" } else { "add" },
                    *prefix,
                    target,
                    deadline,
                )?,
            }
        }
        for ipv4 in next.families.difference(&current.families) {
            self.change_rule("add", *ipv4, deadline)?;
        }
        // Removing a selector is reserved for explicit release or rollback of a newly acquired family.
        for ipv4 in current.families.difference(&next.families) {
            self.change_rule("del", *ipv4, deadline)?;
        }
        for (prefix, target) in &current.routes {
            if !next.routes.contains_key(prefix) {
                self.change_route("del", *prefix, target, deadline)?;
            }
        }
        *current = next.clone();
        Ok(())
    }

    fn change_rule(&self, verb: &str, ipv4: bool, deadline: Instant) -> Result<()> {
        self.runner.run(
            "ip",
            &[
                family(ipv4),
                "rule",
                verb,
                "priority",
                PRIORITY,
                "lookup",
                TABLE,
                "protocol",
                PROTO,
            ],
            deadline,
        )?;
        Ok(())
    }

    fn change_route(
        &self,
        verb: &str,
        prefix: IpNet,
        target: &Target,
        deadline: Instant,
    ) -> Result<()> {
        let destination = prefix.to_string();
        let gateway = target.gateway.as_ref().map(ToString::to_string);
        let source = target.source.as_ref().map(ToString::to_string);
        let mut args = vec![
            family(prefix.addr().is_ipv4()),
            "route",
            verb,
            "table",
            TABLE,
        ];
        if prefix.prefix_len() == 0 {
            args.extend(["unreachable", "default", "metric", GUARD_METRIC]);
        } else {
            args.push(&destination);
            if let Some(gateway) = &gateway {
                args.extend(["via", gateway]);
            }
            args.extend(["dev", &target.device, "metric", ROUTE_METRIC]);
            if let Some(source) = &source {
                args.extend(["src", source]);
            }
            if target.onlink {
                args.push("onlink");
            }
        }
        args.extend(["proto", PROTO]);
        self.runner.run("ip", &args, deadline)?;
        Ok(())
    }
}

fn parse_target(row: &Value, ipv4: bool) -> Result<Target> {
    let device = row
        .get("dev")
        .and_then(Value::as_str)
        .context("route has no native interface")?;
    ensure!(
        !device.is_empty()
            && device.len() < 16
            && !device.starts_with('-')
            && device
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')),
        "route interface name is outside policy bounds"
    );
    let parse_address = |key| -> Result<Option<IpAddr>> {
        row.get(key)
            .map(|value| -> Result<IpAddr> {
                let address: IpAddr = value.as_str().context("invalid route address")?.parse()?;
                ensure!(
                    address.is_ipv4() == ipv4
                        && !address.is_unspecified()
                        && !address.is_multicast(),
                    "native route address is not usable"
                );
                Ok(address)
            })
            .transpose()
    };
    let flags = row["flags"].as_array().context("route flags are missing")?;
    ensure!(
        flags
            .iter()
            .all(|flag| flag == "onlink" || flag == "linkdown"),
        "native route uses unsupported attributes"
    );
    Ok(Target {
        device: device.to_owned(),
        gateway: parse_address("gateway")?,
        source: parse_address("prefsrc")?,
        onlink: flags.iter().any(|flag| flag == "onlink"),
    })
}

fn parse_prefix(value: &str, ipv4: bool) -> Result<IpNet> {
    if value == "default" {
        return Ok(default_prefix(ipv4));
    }
    Ok(if value.contains('/') {
        value.parse::<IpNet>()?
    } else {
        host_prefix(value.parse()?)
    })
}

fn default_prefix(ipv4: bool) -> IpNet {
    (if ipv4 { "0.0.0.0/0" } else { "::/0" })
        .parse()
        .expect("fixed default")
}

fn host_prefix(address: IpAddr) -> IpNet {
    IpNet::new(address, if address.is_ipv4() { 32 } else { 128 }).expect("host prefix")
}

fn guard() -> Target {
    Target {
        device: String::new(),
        gateway: None,
        source: None,
        onlink: false,
    }
}

fn family(ipv4: bool) -> &'static str {
    if ipv4 { "-4" } else { "-6" }
}
