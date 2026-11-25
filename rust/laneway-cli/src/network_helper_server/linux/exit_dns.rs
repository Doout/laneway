mod dns;
mod policy;

use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};

use super::{
    super::{Change, combine},
    system::Runner,
};
use anyhow::{Result, bail, ensure};

pub(super) struct ExitDns {
    exit: policy::Policy,
    dns: dns::Dns,
}

impl ExitDns {
    pub(super) fn new(
        interface: &str,
        state: &Path,
        lock: &File,
        deadline: Instant,
    ) -> Result<Self> {
        let dns = dns::Dns::new(interface, state, lock, deadline)?;
        let exit = policy::Policy::new(interface, state, lock, deadline)?;
        Ok(Self { exit, dns })
    }

    pub(super) fn apply(&mut self, change: Change, deadline: Instant) -> Result<()> {
        match change {
            Change::Exit(plan) => self.exit.apply(plan, deadline),
            Change::RestoreExit => {
                self.dns.restore(deadline)?;
                self.exit.restore(deadline)
            }
            Change::Dns(servers) => {
                ensure!(self.exit.active(), "exit DNS requires active exit routing");
                self.dns.apply(&servers, deadline)
            }
            Change::RestoreDns => self.dns.restore(deadline),
            Change::Routes(_) => bail!("split routing belongs to the TUN route owner"),
        }
    }

    pub(super) fn restore(&mut self, deadline: Instant) -> Result<()> {
        // Reserve time for terminal routing cleanup even if the resolver is
        // unresponsive. DNS state belonging to another owner stays untouched.
        let dns_deadline = deadline
            .checked_sub(Duration::from_secs(3))
            .unwrap_or(deadline);
        let dns = self.dns.restore(dns_deadline);
        let exit = self.exit.restore(deadline);
        combine(dns, exit)
    }
}
