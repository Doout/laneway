use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::IpAddr,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use laneway_protocol::Id;
use wait_timeout::ChildExt;

use crate::{
    config::{Config, ExitFailureMode, ForwardMode, RouteKind, SubnetForwardConfig},
    dns::DnsManager,
    nft_state::{
        self, Chain, Rule, Shape, accept, masquerade, match_ct_states, match_meta, match_prefix,
    },
};

const IPV4_FORWARD: &str = "net.ipv4.ip_forward";
const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";
const OWNER_CHAIN: &str = "laneway_owner";
const FORWARD_CHAIN: &str = "laneway_forward";
const NAT_CHAIN: &str = "laneway_nat";
const SESSION_PREFIX: &str = "laneway-rust-session-v1-";

pub(crate) trait CommandRunner: Send + Sync {
    fn run(&self, command: &str, arguments: &[String], input: Option<&[u8]>) -> Result<Vec<u8>>;
}

struct ExecRunner {
    timeout: Duration,
}

impl CommandRunner for ExecRunner {
    fn run(&self, command: &str, arguments: &[String], input: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut child = Command::new(command)
            .args(arguments)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("run {command} {}", arguments.join(" ")))?;
        if let Some(input) = input {
            child
                .stdin
                .take()
                .context("command stdin missing")?
                .write_all(input)
                .context("write command input")?;
        }
        let mut stdout = child.stdout.take().context("command stdout missing")?;
        let mut stderr = child.stderr.take().context("command stderr missing")?;
        let (status, stdout, stderr) = std::thread::scope(|scope| -> Result<_> {
            let stdout = scope.spawn(move || {
                let mut output = Vec::new();
                stdout.read_to_end(&mut output)?;
                std::io::Result::Ok(output)
            });
            let stderr = scope.spawn(move || {
                let mut output = Vec::new();
                stderr.read_to_end(&mut output)?;
                std::io::Result::Ok(output)
            });
            let status = match child
                .wait_timeout(self.timeout)
                .context("wait for command deadline")?
            {
                Some(status) => status,
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!(
                        "{command} {} exceeded {:?}",
                        arguments.join(" "),
                        self.timeout
                    )
                }
            };
            Ok((
                status,
                stdout.join().expect("stdout reader panicked")?,
                stderr.join().expect("stderr reader panicked")?,
            ))
        })?;
        ensure!(
            status.success(),
            "{command} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        );
        Ok(stdout)
    }
}

#[derive(Clone)]
struct TablePlan {
    shape: Shape,
    script: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PolicyRoute {
    family: &'static str,
    prefix: IpNet,
    arguments: Vec<String>,
}

#[derive(Clone, Default)]
struct PolicyState {
    routes: Vec<PolicyRoute>,
    families: BTreeSet<&'static str>,
}

/// Owns all Linux forwarding, nftables, and exit-policy state installed by one
/// native agent process. Startup reconciles only an exact crashed predecessor.
pub(crate) struct KernelManager {
    config: Arc<Config>,
    runner: Arc<dyn CommandRunner>,
    tables: Vec<TablePlan>,
    session: String,
    prior_forwarding: BTreeMap<&'static str, String>,
    touched_forwarding: BTreeSet<&'static str>,
    policy: PolicyState,
    dns: Option<DnsManager>,
    dynamic_bypasses: BTreeMap<IpAddr, usize>,
    exit_path_available: bool,
    stale_tables: bool,
    active: bool,
}

impl KernelManager {
    pub(crate) fn apply(config: Arc<Config>) -> Result<Self> {
        let timeout = config.forwarding.shutdown_timeout;
        Self::apply_with_runner(config, Arc::new(ExecRunner { timeout }))
    }

    pub(crate) fn configuration(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }

    pub(crate) fn selected_exit_node(&self) -> Option<Id> {
        self.config
            .forwarding
            .exit_client
            .selected_node
            .as_deref()?
            .parse()
            .ok()
    }

    /// Applies the configured leak policy after a hysteresis decision. Closed
    /// mode keeps the split defaults; open mode removes exit DNS and policy.
    pub(crate) fn set_exit_path_available(&mut self, available: bool) -> Result<()> {
        let exit = &self.config.forwarding.exit_client;
        if !exit.enabled || exit.failure_mode != ExitFailureMode::Open {
            return Ok(());
        }
        if self.exit_path_available == available {
            return Ok(());
        }
        if !available {
            let mut failures = Vec::new();
            if let Some(dns) = self.dns.as_mut()
                && let Err(error) = dns.restore()
            {
                failures.push(error);
            }
            if !self.policy.routes.is_empty() {
                match self.remove_policy(&self.policy, true) {
                    Ok(()) => self.policy = PolicyState::default(),
                    Err(error) => failures.push(error),
                }
            }
            if self.policy.routes.is_empty() {
                self.exit_path_available = false;
            }
            if failures.is_empty() {
                return Ok(());
            }
            bail!("fail-open exit deactivation: {failures:?}")
        }

        let next = self.build_policy()?;
        self.install_policy(&next)?;
        self.policy = next;
        if let Some(dns) = self.dns.as_mut()
            && let Err(error) = dns.apply()
        {
            let rollback = self.remove_policy(&self.policy, true);
            self.policy = PolicyState::default();
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => error.context(format!(
                    "exit DNS recovery failed and policy rollback failed: {rollback:#}"
                )),
            });
        }
        self.exit_path_available = true;
        Ok(())
    }

    /// Adds a native host-route reservation for a relay-issued direct endpoint.
    pub(crate) fn reserve_transport_bypass(&mut self, address: IpAddr) -> Result<()> {
        let previous = self.dynamic_bypasses.get(&address).copied().unwrap_or(0);
        self.dynamic_bypasses.insert(address, previous + 1);
        if previous == 0
            && self.config.forwarding.exit_client.enabled
            && self.exit_path_available
            && let Err(error) = self.rebuild_policy()
        {
            self.dynamic_bypasses.remove(&address);
            return Err(error.context("install dynamic direct transport bypass"));
        }
        Ok(())
    }

    pub(crate) fn release_transport_bypass(&mut self, address: IpAddr) -> Result<()> {
        let Some(count) = self.dynamic_bypasses.get(&address).copied() else {
            return Ok(());
        };
        if count > 1 {
            self.dynamic_bypasses.insert(address, count - 1);
            return Ok(());
        }
        self.dynamic_bypasses.remove(&address);
        if self.config.forwarding.exit_client.enabled
            && self.exit_path_available
            && let Err(error) = self.rebuild_policy()
        {
            self.dynamic_bypasses.insert(address, 1);
            return Err(error.context("remove dynamic direct transport bypass"));
        }
        Ok(())
    }

    pub(crate) fn adopt_dynamic_bypasses(
        &mut self,
        bypasses: BTreeMap<IpAddr, usize>,
    ) -> Result<()> {
        self.dynamic_bypasses = bypasses;
        if self.config.forwarding.exit_client.enabled && self.exit_path_available {
            self.rebuild_policy()?;
        }
        Ok(())
    }

    fn rebuild_policy(&mut self) -> Result<()> {
        let previous = self.policy.clone();
        let next = self.build_policy()?;
        if previous.routes == next.routes && previous.families == next.families {
            return Ok(());
        }
        if !previous.routes.is_empty() {
            self.remove_policy(&previous, true)?;
        }
        if let Err(error) = self.install_policy(&next) {
            let rollback = if previous.routes.is_empty() {
                Ok(())
            } else {
                self.install_policy(&previous)
            };
            self.policy = previous;
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => error.context(format!(
                    "dynamic bypass update failed and policy rollback failed: {rollback:#}"
                )),
            });
        }
        self.policy = next;
        Ok(())
    }

    fn apply_with_runner(config: Arc<Config>, runner: Arc<dyn CommandRunner>) -> Result<Self> {
        let tables = table_plans(&config, "")?;
        let required = forwarding_keys(&config);
        let mut manager = Self {
            config,
            runner,
            tables,
            session: String::new(),
            prior_forwarding: BTreeMap::new(),
            touched_forwarding: BTreeSet::new(),
            policy: PolicyState::default(),
            dns: None,
            dynamic_bypasses: BTreeMap::new(),
            exit_path_available: true,
            stale_tables: false,
            active: false,
        };
        let (recovered, stale_tables) = manager.recover_tables(&required)?;
        manager.stale_tables = stale_tables;
        for key in &required {
            let prior = if let Some(prior) = recovered.get(key) {
                prior.clone()
            } else {
                manager.read_forwarding(key)?
            };
            manager.prior_forwarding.insert(key, prior);
        }
        manager.session = manager.new_session(&required)?;
        manager.tables = table_plans(&manager.config, &manager.session)?;
        if let Err(error) = manager.activate(&required) {
            let rollback = manager.restore();
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => {
                    Err(error.context(format!("kernel rollback failed: {rollback:#}")))
                }
            };
        }
        manager.active = true;
        Ok(manager)
    }

    fn activate(&mut self, required: &BTreeSet<&'static str>) -> Result<()> {
        if !self.tables.is_empty() {
            let mut commands = Vec::new();
            if self.stale_tables {
                commands.extend(
                    self.tables
                        .iter()
                        .map(|table| format!("delete table inet {}", table.shape.table)),
                );
            }
            commands.extend(
                self.tables
                    .iter()
                    .flat_map(|table| table.script.iter().cloned()),
            );
            self.nft_transaction(commands)?;
            self.stale_tables = false;
        }
        for key in required {
            if self
                .prior_forwarding
                .get(key)
                .is_some_and(|value| value == "0")
            {
                self.write_forwarding(key, "1")?;
                self.touched_forwarding.insert(key);
            }
        }
        if self.config.forwarding.exit_client.enabled {
            let policy = self.build_policy()?;
            self.recover_policy(&policy)?;
            self.install_policy(&policy)?;
            self.policy = policy;
            self.dns = DnsManager::configured(&self.config, Arc::clone(&self.runner));
            if let Some(dns) = self.dns.as_mut()
                && let Err(error) = dns.apply()
            {
                let rollback = self.remove_policy(&self.policy, true);
                self.policy = PolicyState::default();
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback) => error.context(format!(
                        "DNS activation failed and exit-policy rollback failed: {rollback:#}"
                    )),
                });
            }
        }
        Ok(())
    }

    /// Restores only state whose complete ownership still matches this process.
    pub(crate) fn restore(&mut self) -> Result<()> {
        if !self.active && self.session.is_empty() {
            return Ok(());
        }
        let mut failures = Vec::new();
        if let Some(dns) = self.dns.as_mut()
            && let Err(error) = dns.restore()
        {
            failures.push(error);
        }
        if !self.policy.routes.is_empty() {
            match self.remove_policy(&self.policy, true) {
                Ok(()) => self.policy = PolicyState::default(),
                Err(error) => failures.push(error),
            }
        }
        let tables_owned = !self.tables.is_empty()
            && self.tables.iter().all(|table| {
                self.nft_json(&table.shape.table)
                    .and_then(|raw| nft_state::validate(&raw, &table.shape))
                    .is_ok_and(|session| session == self.session)
            });
        if !self.tables.is_empty() && !tables_owned {
            failures.push(anyhow::anyhow!(
                "owned nftables state changed externally; refusing cleanup"
            ));
        }
        // Restore forwarding while the exact ownership marker still exists. If
        // the process is killed here, the marker preserves the prior value for
        // the next startup instead of leaving an unrecoverable sysctl change.
        if (self.tables.is_empty() || tables_owned) && self.policy.routes.is_empty() {
            let keys: Vec<_> = self.touched_forwarding.iter().copied().collect();
            for key in keys.into_iter().rev() {
                match self.read_forwarding(key) {
                    Ok(value) if value == "1" => {
                        let prior = self.prior_forwarding[key].clone();
                        if let Err(error) = self.write_forwarding(key, &prior) {
                            failures.push(error);
                        } else {
                            self.touched_forwarding.remove(key);
                        }
                    }
                    Ok(_) => {
                        failures.push(anyhow::anyhow!("forwarding state {key} changed externally"))
                    }
                    Err(error) => failures.push(error),
                }
            }
        }
        if tables_owned && self.touched_forwarding.is_empty() {
            let deletes = self
                .tables
                .iter()
                .map(|table| format!("delete table inet {}", table.shape.table))
                .collect();
            if let Err(error) = self.nft_transaction(deletes) {
                failures.push(error);
            } else {
                self.tables.clear();
            }
        }
        if failures.is_empty() {
            self.active = false;
            Ok(())
        } else {
            bail!("restore owned kernel state: {failures:?}")
        }
    }

    fn recover_tables(
        &self,
        required: &BTreeSet<&'static str>,
    ) -> Result<(BTreeMap<&'static str, String>, bool)> {
        let configured = [
            self.config.forwarding.subnet_table.as_str(),
            self.config.forwarding.exit_table.as_str(),
        ];
        let listing = self.run(
            &self.config.forwarding.nft_command,
            &["list", "tables"],
            None,
        )?;
        let listing = String::from_utf8(listing).context("nft table list is non-UTF8")?;
        let existing: BTreeSet<_> = listing
            .lines()
            .filter_map(|line| line.trim().strip_prefix("table inet "))
            .collect();
        let expected: BTreeSet<_> = self
            .tables
            .iter()
            .map(|table| table.shape.table.as_str())
            .collect();
        let owned_existing: BTreeSet<_> = configured
            .into_iter()
            .filter(|table| existing.contains(table))
            .collect();
        if owned_existing.is_empty() {
            return Ok((BTreeMap::new(), false));
        }
        ensure!(
            owned_existing == expected,
            "partial or disabled Laneway nftables state exists"
        );
        let mut session = None;
        for table in &self.tables {
            let raw = self.nft_json(&table.shape.table)?;
            let actual = nft_state::validate(&raw, &table.shape)
                .context("existing nftables table is not exact Laneway state")?;
            if let Some(previous) = &session {
                ensure!(previous == &actual, "stale table sessions differ");
            }
            session = Some(actual);
        }
        let prior = parse_session(
            session
                .as_deref()
                .context("stale tables omitted session marker")?,
            required,
        )?;
        for key in required {
            let actual = self.read_forwarding(key)?;
            let expected_prior = prior.get(key).context("stale sysctl metadata missing")?;
            ensure!(
                actual == "1" || &actual == expected_prior,
                "stale forwarding state was replaced externally"
            );
        }
        Ok((prior, true))
    }

    fn new_session(&self, required: &BTreeSet<&'static str>) -> Result<String> {
        let mut token = [0_u8; 16];
        getrandom::fill(&mut token).context("create kernel ownership token")?;
        let state = |key| {
            if required.contains(key) {
                self.prior_forwarding
                    .get(key)
                    .map(String::as_str)
                    .unwrap_or("n")
            } else {
                "n"
            }
        };
        Ok(format!(
            "{SESSION_PREFIX}{}-4{}-6{}",
            hex::encode(token),
            state(IPV4_FORWARD),
            state(IPV6_FORWARD)
        ))
    }

    fn read_forwarding(&self, key: &str) -> Result<String> {
        let output = self.run(&self.config.forwarding.sysctl_command, &["-n", key], None)?;
        let value = String::from_utf8(output)
            .context("sysctl output is non-UTF8")?
            .trim()
            .to_owned();
        ensure!(matches!(value.as_str(), "0" | "1"), "invalid sysctl value");
        Ok(value)
    }

    fn write_forwarding(&self, key: &str, value: &str) -> Result<()> {
        self.run(
            &self.config.forwarding.sysctl_command,
            &["-w", &format!("{key}={value}")],
            None,
        )?;
        Ok(())
    }

    fn nft_json(&self, table: &str) -> Result<Vec<u8>> {
        self.run(
            &self.config.forwarding.nft_command,
            &["-j", "list", "table", "inet", table],
            None,
        )
    }

    fn nft_transaction(&self, commands: Vec<String>) -> Result<()> {
        if commands.is_empty() {
            return Ok(());
        }
        let mut script = commands.join("\n");
        script.push('\n');
        self.run(
            &self.config.forwarding.nft_command,
            &["-f", "-"],
            Some(script.as_bytes()),
        )?;
        Ok(())
    }

    fn build_policy(&self) -> Result<PolicyState> {
        let exit = &self.config.forwarding.exit_client;
        let mut routes = Vec::new();
        let mut seen = BTreeSet::new();
        let mut families = BTreeSet::new();
        for route in self
            .config
            .routes
            .iter()
            .filter(|route| route.kind == RouteKind::Exit)
        {
            families.insert(family(route.prefix));
        }
        for address in self.config.exit_transport_bypass() {
            let prefix = host_prefix(address);
            if families.contains(family(prefix)) && seen.insert(prefix) {
                routes.push(self.native_route(prefix)?);
            }
        }
        for address in self.dynamic_bypasses.keys().copied() {
            let prefix = host_prefix(address);
            if families.contains(family(prefix)) && seen.insert(prefix) {
                routes.push(self.native_route(prefix)?);
            }
        }
        for prefix in &exit.local_lan_bypass {
            if families.contains(family(*prefix)) && seen.insert(*prefix) {
                routes.push(self.native_route(*prefix)?);
            }
        }
        for route in self
            .config
            .routes
            .iter()
            .filter(|route| route.kind == RouteKind::Exit)
        {
            let halves: &[&str] = match route.prefix {
                IpNet::V4(_) => &["0.0.0.0/1", "128.0.0.0/1"],
                IpNet::V6(_) => &["::/1", "8000::/1"],
            };
            for half in halves {
                let prefix: IpNet = half.parse().expect("constant split default");
                if seen.insert(prefix) {
                    routes.push(PolicyRoute {
                        family: family(prefix),
                        prefix,
                        arguments: vec![
                            prefix.to_string(),
                            "dev".to_owned(),
                            self.config.tun.name.clone(),
                        ],
                    });
                }
            }
        }
        routes.sort_by_key(|route| {
            (
                route.family,
                std::cmp::Reverse(route.prefix.prefix_len()),
                route.prefix,
            )
        });
        Ok(PolicyState { routes, families })
    }

    fn native_route(&self, prefix: IpNet) -> Result<PolicyRoute> {
        let family = family(prefix);
        let output = self.run(
            &self.config.forwarding.ip_command,
            &[
                family,
                "-N",
                "-o",
                "route",
                "show",
                "table",
                "main",
                "match",
                &prefix.addr().to_string(),
            ],
            None,
        )?;
        let line = String::from_utf8(output).context("ip route output is non-UTF8")?;
        let mut candidates = line
            .lines()
            .filter_map(|line| {
                let destination = line.split_whitespace().next()?;
                let route: IpNet = if destination == "default" {
                    match prefix {
                        IpNet::V4(_) => "0.0.0.0/0",
                        IpNet::V6(_) => "::/0",
                    }
                    .parse()
                    .expect("constant default prefix")
                } else {
                    destination.parse().ok()?
                };
                route
                    .contains(&prefix.addr())
                    .then_some((route.prefix_len(), line))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(length, _)| std::cmp::Reverse(*length));
        let (_, selected) = candidates.first().context("native route is missing")?;
        ensure!(
            candidates
                .get(1)
                .is_none_or(|(length, _)| *length < candidates[0].0),
            "ambiguous native bypass route"
        );
        let fields: Vec<_> = selected.split_whitespace().collect();
        let device = field_after(&fields, "dev").context("native route has no device")?;
        ensure!(device != self.config.tun.name, "bypass already uses tunnel");
        let mut arguments = vec![prefix.to_string()];
        if let Some(gateway) = field_after(&fields, "via") {
            arguments.extend(["via".to_owned(), gateway.to_owned()]);
        }
        arguments.extend(["dev".to_owned(), device.to_owned()]);
        if let Some(source) = field_after(&fields, "src") {
            arguments.extend(["src".to_owned(), source.to_owned()]);
        }
        Ok(PolicyRoute {
            family,
            prefix,
            arguments,
        })
    }

    fn recover_policy(&self, policy: &PolicyState) -> Result<()> {
        let exit = &self.config.forwarding.exit_client;
        for family in ["-4", "-6"] {
            let rule = self.run(
                &self.config.forwarding.ip_command,
                &[
                    family,
                    "-N",
                    "-o",
                    "rule",
                    "show",
                    "priority",
                    &exit.rule_priority.to_string(),
                ],
                None,
            )?;
            let rule = String::from_utf8(rule).context("ip rule output is non-UTF8")?;
            let rule_lines: Vec<_> = rule
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();
            let routes = self.policy_snapshot(family)?;
            let expected: Vec<_> = policy
                .routes
                .iter()
                .filter(|route| route.family == family)
                .collect();
            if rule_lines.is_empty() && routes.is_empty() {
                continue;
            }
            let rule_owned = rule_lines.len() == 1
                && owned_rule(rule_lines[0], exit.rule_priority, exit.route_table);
            ensure!(
                policy.families.contains(family)
                    && (rule_lines.is_empty() || rule_owned)
                    && route_snapshot_matches(&routes, &expected, exit.route_protocol),
                "existing exit policy state is not exact Laneway ownership: family={family} rules={rule_lines:?} routes={routes:?}"
            );
            // A predecessor can die after adding its routes but before exposing
            // the lookup rule. That exact partial state is safe to reclaim.
            self.remove_policy_family(family, &expected, rule_owned)?;
        }
        Ok(())
    }

    fn install_policy(&self, policy: &PolicyState) -> Result<()> {
        let exit = &self.config.forwarding.exit_client;
        let mut installed = PolicyState::default();
        for route in &policy.routes {
            let mut arguments = vec![
                route.family.to_owned(),
                "route".to_owned(),
                "replace".to_owned(),
                "table".to_owned(),
                exit.route_table.to_string(),
            ];
            arguments.extend(route.arguments.clone());
            arguments.extend(["proto".to_owned(), exit.route_protocol.to_string()]);
            if let Err(error) = self.run_owned(&self.config.forwarding.ip_command, &arguments, None)
            {
                let rollback = self.remove_policy(&installed, false);
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback) => {
                        error.context(format!("partial exit-policy rollback failed: {rollback:#}"))
                    }
                });
            }
            installed.routes.push(route.clone());
            installed.families.insert(route.family);
        }
        for family in &policy.families {
            if let Err(error) = self.run(
                &self.config.forwarding.ip_command,
                &[
                    family,
                    "rule",
                    "add",
                    "priority",
                    &exit.rule_priority.to_string(),
                    "lookup",
                    &exit.route_table.to_string(),
                ],
                None,
            ) {
                let rollback = self.remove_policy(&installed, false);
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback) => {
                        error.context(format!("partial exit-policy rollback failed: {rollback:#}"))
                    }
                });
            }
        }
        Ok(())
    }

    fn remove_policy(&self, policy: &PolicyState, require_rules: bool) -> Result<()> {
        let mut failures = Vec::new();
        for family in policy.families.iter().rev() {
            let expected: Vec<_> = policy
                .routes
                .iter()
                .filter(|route| route.family == *family)
                .collect();
            if let Err(error) = self.remove_policy_family(family, &expected, require_rules) {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("remove exit policy: {failures:?}")
        }
    }

    fn remove_policy_family(
        &self,
        family: &str,
        expected: &[&PolicyRoute],
        rule_expected: bool,
    ) -> Result<()> {
        let exit = &self.config.forwarding.exit_client;
        let rule = self.run(
            &self.config.forwarding.ip_command,
            &[
                family,
                "-N",
                "-o",
                "rule",
                "show",
                "priority",
                &exit.rule_priority.to_string(),
            ],
            None,
        )?;
        let rule = String::from_utf8(rule).context("ip rule output is non-UTF8")?;
        let lines: Vec<_> = rule
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        if rule_expected || !lines.is_empty() {
            ensure!(
                lines.len() == 1 && owned_rule(lines[0], exit.rule_priority, exit.route_table),
                "exit policy rule ownership changed"
            );
            self.run(
                &self.config.forwarding.ip_command,
                &[
                    family,
                    "rule",
                    "del",
                    "priority",
                    &exit.rule_priority.to_string(),
                    "lookup",
                    &exit.route_table.to_string(),
                ],
                None,
            )?;
        }
        let routes = self.policy_snapshot(family)?;
        ensure!(
            route_snapshot_matches(&routes, expected, exit.route_protocol),
            "exit policy routes changed externally"
        );
        for route in expected.iter().rev() {
            self.run(
                &self.config.forwarding.ip_command,
                &[
                    family,
                    "route",
                    "del",
                    "table",
                    &exit.route_table.to_string(),
                    &route.prefix.to_string(),
                    "proto",
                    &exit.route_protocol.to_string(),
                ],
                None,
            )?;
        }
        Ok(())
    }

    fn policy_snapshot(&self, family: &str) -> Result<Vec<String>> {
        let result = self.runner.run(
            &self.config.forwarding.ip_command,
            &[
                family.to_owned(),
                "-N".to_owned(),
                "-o".to_owned(),
                "route".to_owned(),
                "show".to_owned(),
                "table".to_owned(),
                self.config.forwarding.exit_client.route_table.to_string(),
            ],
            None,
        );
        match result {
            Ok(output) => Ok(String::from_utf8(output)
                .context("ip route snapshot is non-UTF8")?
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect()),
            Err(error) if format!("{error:#}").contains("FIB table does not exist") => {
                Ok(Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    fn run(&self, command: &str, arguments: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        let arguments: Vec<_> = arguments.iter().map(|value| (*value).to_owned()).collect();
        self.run_owned(command, &arguments, input)
    }

    fn run_owned(
        &self,
        command: &str,
        arguments: &[String],
        input: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.runner.run(command, arguments, input)
    }
}

impl Drop for KernelManager {
    fn drop(&mut self) {
        if self.active {
            tracing::error!("owned kernel state dropped without explicit restore");
        }
    }
}

fn forwarding_keys(config: &Config) -> BTreeSet<&'static str> {
    let mut keys = BTreeSet::new();
    let prefixes = config
        .forwarding
        .subnet_routes
        .iter()
        .map(|route| route.prefix)
        .chain(config.forwarding.exit_gateway_sources.iter().copied());
    for prefix in prefixes {
        keys.insert(match prefix {
            IpNet::V4(_) => IPV4_FORWARD,
            IpNet::V6(_) => IPV6_FORWARD,
        });
    }
    keys
}

fn table_plans(config: &Config, session: &str) -> Result<Vec<TablePlan>> {
    let mut plans = Vec::new();
    if config.forwarding.subnet_router {
        plans.push(subnet_table(config, session)?);
    }
    if config.forwarding.exit_gateway {
        plans.push(exit_table(config, session)?);
    }
    Ok(plans)
}

fn subnet_table(config: &Config, session: &str) -> Result<TablePlan> {
    let routes = &config.forwarding.subnet_routes;
    let has_nat = routes.iter().any(|route| route.mode == ForwardMode::Nat);
    let fields = routes.iter().flat_map(|route| {
        [
            route.prefix.to_string(),
            format!("{:?}", route.mode),
            route.output_interface.clone(),
        ]
    });
    let marker = nft_state::marker(
        "subnet",
        [
            config.forwarding.subnet_table.clone(),
            config.tun.name.clone(),
        ]
        .into_iter()
        .chain(fields),
    );
    build_table(
        &config.forwarding.subnet_table,
        marker,
        session,
        has_nat,
        routes.iter().flat_map(|route| subnet_rules(config, route)),
    )
}

fn subnet_rules(config: &Config, route: &SubnetForwardConfig) -> Vec<Rule> {
    let protocol = protocol(route.prefix);
    let prefix = route.prefix;
    let mut rules = vec![
        Rule {
            chain: FORWARD_CHAIN.to_owned(),
            comment: "laneway-rust-subnet-out".to_owned(),
            expressions: vec![
                match_meta("iifname", &config.tun.name),
                match_meta("oifname", &route.output_interface),
                match_prefix(
                    protocol,
                    "daddr",
                    &prefix.addr().to_string(),
                    prefix.prefix_len(),
                ),
                accept(),
            ],
        },
        Rule {
            chain: FORWARD_CHAIN.to_owned(),
            comment: "laneway-rust-subnet-in".to_owned(),
            expressions: vec![
                match_meta("iifname", &route.output_interface),
                match_meta("oifname", &config.tun.name),
                match_prefix(
                    protocol,
                    "saddr",
                    &prefix.addr().to_string(),
                    prefix.prefix_len(),
                ),
                accept(),
            ],
        },
    ];
    if route.mode == ForwardMode::Nat {
        rules.push(Rule {
            chain: NAT_CHAIN.to_owned(),
            comment: "laneway-rust-subnet-nat".to_owned(),
            expressions: vec![
                match_meta("iifname", &config.tun.name),
                match_meta("oifname", &route.output_interface),
                match_prefix(
                    protocol,
                    "daddr",
                    &prefix.addr().to_string(),
                    prefix.prefix_len(),
                ),
                masquerade(),
            ],
        });
    }
    rules
}

fn exit_table(config: &Config, session: &str) -> Result<TablePlan> {
    let output = config
        .forwarding
        .exit_output_interface
        .as_deref()
        .context("exit output interface missing after validation")?;
    let marker = nft_state::marker(
        "exit",
        [
            config.forwarding.exit_table.clone(),
            config.tun.name.clone(),
            output.to_owned(),
        ]
        .into_iter()
        .chain(
            config
                .forwarding
                .exit_gateway_sources
                .iter()
                .map(ToString::to_string),
        ),
    );
    let rules = config
        .forwarding
        .exit_gateway_sources
        .iter()
        .flat_map(|prefix| exit_rules(config, output, *prefix));
    build_table(&config.forwarding.exit_table, marker, session, true, rules)
}

fn exit_rules(config: &Config, output: &str, prefix: IpNet) -> Vec<Rule> {
    let protocol = protocol(prefix);
    vec![
        Rule {
            chain: FORWARD_CHAIN.to_owned(),
            comment: "laneway-rust-exit-out".to_owned(),
            expressions: vec![
                match_meta("iifname", &config.tun.name),
                match_meta("oifname", output),
                match_prefix(
                    protocol,
                    "saddr",
                    &prefix.addr().to_string(),
                    prefix.prefix_len(),
                ),
                accept(),
            ],
        },
        Rule {
            chain: FORWARD_CHAIN.to_owned(),
            comment: "laneway-rust-exit-in".to_owned(),
            expressions: vec![
                match_meta("iifname", output),
                match_meta("oifname", &config.tun.name),
                match_prefix(
                    protocol,
                    "daddr",
                    &prefix.addr().to_string(),
                    prefix.prefix_len(),
                ),
                match_ct_states(),
                accept(),
            ],
        },
        Rule {
            chain: NAT_CHAIN.to_owned(),
            comment: "laneway-rust-exit-nat".to_owned(),
            expressions: vec![
                match_meta("oifname", output),
                match_prefix(
                    protocol,
                    "saddr",
                    &prefix.addr().to_string(),
                    prefix.prefix_len(),
                ),
                masquerade(),
            ],
        },
    ]
}

fn build_table(
    table: &str,
    marker: String,
    session: &str,
    nat: bool,
    rules: impl IntoIterator<Item = Rule>,
) -> Result<TablePlan> {
    let rules: Vec<_> = rules.into_iter().collect();
    let mut chains = vec![
        Chain::regular(OWNER_CHAIN),
        Chain::base(FORWARD_CHAIN, "filter", "forward", 0),
    ];
    if nat {
        chains.push(Chain::base(NAT_CHAIN, "nat", "postrouting", 100));
    }
    let shape = Shape {
        table: table.to_owned(),
        owner_chain: OWNER_CHAIN.to_owned(),
        marker: marker.clone(),
        session_prefix: SESSION_PREFIX.to_owned(),
        chains,
        rules: rules.clone(),
    };
    let mut script = vec![
        format!("add table inet {table}"),
        format!("add chain inet {table} {OWNER_CHAIN}"),
        format!("add rule inet {table} {OWNER_CHAIN} counter comment \"{marker}\""),
        format!("add rule inet {table} {OWNER_CHAIN} counter comment \"{session}\""),
        format!(
            "add chain inet {table} {FORWARD_CHAIN} {{ type filter hook forward priority 0; policy accept; }}"
        ),
    ];
    if nat {
        script.push(format!(
            "add chain inet {table} {NAT_CHAIN} {{ type nat hook postrouting priority 100; policy accept; }}"
        ));
    }
    for rule in &rules {
        script.push(rule_command(table, rule)?);
    }
    Ok(TablePlan { shape, script })
}

fn rule_command(table: &str, rule: &Rule) -> Result<String> {
    let mut parts = vec![format!("add rule inet {table} {}", rule.chain)];
    for expression in &rule.expressions {
        if expression == &accept() {
            parts.push("accept".to_owned());
        } else if expression == &masquerade() {
            parts.push("masquerade".to_owned());
        } else if expression == &match_ct_states() {
            parts.push("ct state established,related".to_owned());
        } else {
            let match_value = expression
                .get("match")
                .context("unsupported nft expression")?;
            let left = match_value.get("left").context("match left missing")?;
            let right = match_value.get("right").context("match right missing")?;
            if let Some(meta) = left.get("meta") {
                parts.push(format!(
                    "meta {} \"{}\"",
                    meta.get("key")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default(),
                    right.as_str().unwrap_or_default()
                ));
            } else if let Some(payload) = left.get("payload") {
                let prefix = right.get("prefix").context("prefix match missing")?;
                parts.push(format!(
                    "{} {} {}/{}",
                    payload
                        .get("protocol")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default(),
                    payload
                        .get("field")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default(),
                    prefix
                        .get("addr")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default(),
                    prefix
                        .get("len")
                        .and_then(|value| value.as_u64())
                        .unwrap_or_default()
                ));
            } else {
                bail!("unsupported nft match")
            }
        }
    }
    parts.push(format!("comment \"{}\"", rule.comment));
    Ok(parts.join(" "))
}

fn parse_session(
    session: &str,
    required: &BTreeSet<&'static str>,
) -> Result<BTreeMap<&'static str, String>> {
    let value = session
        .strip_prefix(SESSION_PREFIX)
        .context("invalid kernel session prefix")?;
    let (token, state) = value.split_once("-4").context("invalid kernel session")?;
    ensure!(
        token.len() == 32 && token.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid kernel session token"
    );
    let (ipv4, ipv6) = state.split_once("-6").context("invalid kernel session")?;
    ensure!(
        matches!(ipv4, "0" | "1" | "n") && matches!(ipv6, "0" | "1" | "n"),
        "invalid kernel forwarding session"
    );
    let mut result = BTreeMap::new();
    for (key, value) in [(IPV4_FORWARD, ipv4), (IPV6_FORWARD, ipv6)] {
        ensure!(
            required.contains(key) == (value != "n"),
            "stale forwarding families differ from configuration"
        );
        if value != "n" {
            result.insert(key, value.to_owned());
        }
    }
    Ok(result)
}

fn protocol(prefix: IpNet) -> &'static str {
    match prefix {
        IpNet::V4(_) => "ip",
        IpNet::V6(_) => "ip6",
    }
}

fn family(prefix: IpNet) -> &'static str {
    match prefix {
        IpNet::V4(_) => "-4",
        IpNet::V6(_) => "-6",
    }
}

fn host_prefix(address: IpAddr) -> IpNet {
    match address {
        IpAddr::V4(address) => ipnet::Ipv4Net::new(address, 32).expect("valid host").into(),
        IpAddr::V6(address) => ipnet::Ipv6Net::new(address, 128)
            .expect("valid host")
            .into(),
    }
}

fn field_after<'a>(fields: &'a [&str], name: &str) -> Option<&'a str> {
    fields
        .windows(2)
        .find_map(|pair| (pair[0] == name).then_some(pair[1]))
}

fn owned_rule(line: &str, priority: u32, table: u32) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    let priority = priority.to_string();
    let table = table.to_string();
    fields
        .first()
        .is_some_and(|value| value.trim_end_matches(':') == priority)
        && field_after(&fields, "lookup").is_some_and(|value| value == table)
}

fn route_snapshot_matches(actual: &[String], expected: &[&PolicyRoute], protocol: u8) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    let protocol = protocol.to_string();
    let mut normalized = BTreeSet::new();
    for line in actual {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(first) = fields.first() else {
            return false;
        };
        let prefix = match first.parse::<IpNet>() {
            Ok(prefix) => prefix,
            Err(_) => match first.parse::<IpAddr>() {
                Ok(address) => host_prefix(address),
                Err(_) => return false,
            },
        };
        let allowed = ["via", "dev", "proto", "scope", "src"];
        let mut index = 1;
        while index < fields.len() {
            if !allowed.contains(&fields[index]) || index + 1 >= fields.len() {
                return false;
            }
            index += 2;
        }
        if field_after(&fields, "proto") != Some(protocol.as_str()) {
            return false;
        }
        normalized.insert((
            prefix,
            field_after(&fields, "via").map(str::to_owned),
            field_after(&fields, "dev").map(str::to_owned),
            field_after(&fields, "src").map(str::to_owned),
        ));
    }
    let expected: BTreeSet<_> = expected
        .iter()
        .map(|route| {
            let fields: Vec<_> = route.arguments.iter().map(String::as_str).collect();
            (
                route.prefix,
                field_after(&fields, "via").map(str::to_owned),
                field_after(&fields, "dev").map(str::to_owned),
                field_after(&fields, "src").map(str::to_owned),
            )
        })
        .collect();
    normalized == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel_config() -> Arc<Config> {
        let mut config: Config = toml::from_str(
            r#"
mode = "node"
[identity]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
[tls]
certificate = "unused.crt"
private_key = "unused.key"
ca = "unused-ca.crt"
[tun]
name = "lane0"
mtu = 1280
addresses = ["100.96.0.1/32", "fd00::1/128"]
[relay]
address = "192.0.2.1:4433"
server_name = "relay.test"
service_id = "303132333435363738393a3b3c3d3e3f"
[forwarding]
subnet_router = true
exit_gateway = true
owned_prefixes = ["10.50.0.0/24", "fd50::/64"]
exit_gateway_sources = ["100.96.0.0/24", "fd00::/64"]
exit_output_interface = "wan0"
subnet_table = "laneway_rs_test_subnet"
exit_table = "laneway_rs_test_exit"

[forwarding.exit_client]
enabled = true
authorized = true
selected_node = "202122232425262728292a2b2c2d2e2f"
failure_mode = "open"
local_lan_bypass = ["10.50.0.0/24"]

[[forwarding.subnet_routes]]
prefix = "10.50.0.0/24"
mode = "nat"
output_interface = "lan0"

[[forwarding.subnet_routes]]
prefix = "fd50::/64"
mode = "routed"
output_interface = "lan0"

[[routes]]
prefix = "100.96.0.2/32"
via_node = "202122232425262728292a2b2c2d2e2f"

[[routes]]
prefix = "0.0.0.0/0"
via_node = "202122232425262728292a2b2c2d2e2f"
kind = "exit"
"#,
        )
        .unwrap();
        if let Ok(command) = std::env::var("LANEWAY_TEST_RESOLVECTL") {
            config.forwarding.resolvectl_command = command;
            config.forwarding.dns_state_file = std::env::var("LANEWAY_TEST_DNS_JOURNAL")
                .expect("LANEWAY_TEST_DNS_JOURNAL accompanies resolver shim")
                .into();
            config.forwarding.exit_client.dns_servers = vec![
                "1.1.1.1".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ];
        }
        Arc::new(config)
    }

    #[test]
    fn session_round_trip_is_family_exact() {
        let required = BTreeSet::from([IPV4_FORWARD, IPV6_FORWARD]);
        let parsed = parse_session(
            "laneway-rust-session-v1-00112233445566778899aabbccddeeff-40-61",
            &required,
        )
        .unwrap();
        assert_eq!(parsed[IPV4_FORWARD], "0");
        assert_eq!(parsed[IPV6_FORWARD], "1");
        assert!(
            parse_session(
                "laneway-rust-session-v1-00112233445566778899aabbccddeeff-40-6n",
                &required,
            )
            .is_err()
        );
    }

    #[test]
    fn route_snapshot_requires_exact_next_hops() {
        let route = PolicyRoute {
            family: "-4",
            prefix: "192.0.2.1/32".parse().unwrap(),
            arguments: vec![
                "192.0.2.1/32".into(),
                "via".into(),
                "10.0.0.1".into(),
                "dev".into(),
                "eth0".into(),
                "src".into(),
                "10.0.0.2".into(),
            ],
        };
        let expected = [&route];
        assert!(route_snapshot_matches(
            &["192.0.2.1/32 via 10.0.0.1 dev eth0 proto 251 src 10.0.0.2".into()],
            &expected,
            251,
        ));
        assert!(!route_snapshot_matches(
            &["192.0.2.1/32 via 10.0.0.9 dev eth0 proto 251 src 10.0.0.2".into()],
            &expected,
            251,
        ));
    }

    #[test]
    #[ignore = "requires a disposable network namespace with CAP_NET_ADMIN"]
    fn privileged_nft_crash_reconciliation_and_restore() {
        let config = kernel_config();
        config.validate().unwrap();
        let ipv4 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap();
        let ipv6 = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").unwrap();

        let first = KernelManager::apply(Arc::clone(&config)).unwrap();
        if !config.forwarding.exit_client.dns_servers.is_empty() {
            assert!(config.forwarding.dns_state_file.exists());
            assert_eq!(
                resolver_value(&config, "dns"),
                "1.1.1.1 2606:4700:4700::1111"
            );
            assert_eq!(resolver_value(&config, "domain"), "~.");
            assert_eq!(resolver_value(&config, "default-route"), "yes");
        }
        std::mem::forget(first);
        let mut second = KernelManager::apply(Arc::clone(&config)).unwrap();
        let candidate: IpAddr = "198.51.100.77".parse().unwrap();
        second.reserve_transport_bypass(candidate).unwrap();
        let bypass = Command::new("ip")
            .args([
                "-4",
                "route",
                "show",
                "table",
                "51820",
                "exact",
                "198.51.100.77/32",
            ])
            .output()
            .unwrap();
        assert!(bypass.stdout.starts_with(b"198.51.100.77"));
        second.release_transport_bypass(candidate).unwrap();
        second.set_exit_path_available(false).unwrap();
        let down = Command::new("ip")
            .args(["-4", "rule", "show", "priority", "11000"])
            .output()
            .unwrap();
        assert!(down.stdout.is_empty());
        second.set_exit_path_available(true).unwrap();
        let recovered = Command::new("ip")
            .args(["-4", "rule", "show", "priority", "11000"])
            .output()
            .unwrap();
        assert!(!recovered.stdout.is_empty());
        second.restore().unwrap();
        if !config.forwarding.exit_client.dns_servers.is_empty() {
            assert!(!config.forwarding.dns_state_file.exists());
            assert_eq!(resolver_value(&config, "dns"), "192.0.2.53");
            assert_eq!(resolver_value(&config, "domain"), "corp.example");
            assert_eq!(resolver_value(&config, "default-route"), "no");

            let mut closed_config = (*config).clone();
            closed_config.forwarding.exit_client.failure_mode = ExitFailureMode::Closed;
            let mut closed = KernelManager::apply(Arc::new(closed_config)).unwrap();
            closed.set_exit_path_available(false).unwrap();
            let retained = Command::new("ip")
                .args(["-4", "rule", "show", "priority", "11000"])
                .output()
                .unwrap();
            assert!(!retained.stdout.is_empty());
            assert_eq!(resolver_value(&config, "domain"), "~.");
            closed.restore().unwrap();
            assert_eq!(resolver_value(&config, "domain"), "corp.example");
        }

        assert_eq!(
            std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap(),
            ipv4
        );
        assert_eq!(
            std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").unwrap(),
            ipv6
        );
        for table in ["laneway_rs_test_subnet", "laneway_rs_test_exit"] {
            assert!(
                Command::new("nft")
                    .args(["list", "table", "inet", table])
                    .output()
                    .is_ok_and(|output| !output.status.success())
            );
        }
        let rules = Command::new("ip")
            .args(["-4", "rule", "show", "priority", "11000"])
            .output()
            .unwrap();
        assert!(rules.status.success());
        assert!(rules.stdout.is_empty());
        let routes = Command::new("ip")
            .args(["-4", "route", "show", "table", "51820"])
            .output()
            .unwrap();
        assert!(routes.stdout.is_empty());
    }

    fn resolver_value(config: &Config, property: &str) -> String {
        let output = Command::new(&config.forwarding.resolvectl_command)
            .args([property, &config.tun.name])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .split_once(':')
            .map_or("", |(_, value)| value)
            .trim()
            .to_owned()
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires a disposable network namespace with CAP_NET_ADMIN"]
    async fn privileged_sigterm_drives_owned_cleanup() {
        use tokio::{
            signal::unix::{SignalKind, signal},
            time::timeout,
        };

        let config = kernel_config();
        config.validate().unwrap();
        let mut manager = KernelManager::apply(config).unwrap();
        let mut terminate = signal(SignalKind::terminate()).unwrap();
        let status = Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        timeout(Duration::from_secs(2), terminate.recv())
            .await
            .expect("SIGTERM was not delivered");
        manager.restore().unwrap();
        for table in ["laneway_rs_test_subnet", "laneway_rs_test_exit"] {
            assert!(
                Command::new("nft")
                    .args(["list", "table", "inet", table])
                    .output()
                    .is_ok_and(|output| !output.status.success())
            );
        }
    }
}
