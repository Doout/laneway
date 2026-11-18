use std::{fmt::Write, time::Instant};

use serde_json::Value;
use time::OffsetDateTime;

use super::{LinuxBackend, marker};
use crate::{Egress, Ingress, Network, Result, conflict};

fn table(network: &Network) -> String {
    format!("laneway_{}", &network.bridge[4..])
}

impl LinuxBackend {
    pub(super) fn firewall_handle(
        &self,
        network: &Network,
        deadline: Instant,
    ) -> Result<Option<u64>> {
        let name = table(network);
        let response = self.nft(
            &["-j", "-a", "list", "table", "inet", &name],
            None,
            deadline,
        )?;
        if response.missing() {
            return Ok(None);
        }
        let output: Value = response.json("inspect network firewall ownership")?;
        let Some(objects) = output["nftables"].as_array() else {
            return Err(conflict("invalid nftables response"));
        };
        let handle = objects
            .iter()
            .filter_map(|obj| obj.get("table"))
            .find(|table| table["family"] == "inet" && table["name"] == name)
            .and_then(|table| table["handle"].as_u64());
        let owner = marker(network);
        let matches = objects
            .iter()
            .filter_map(|obj| obj.get("rule"))
            .filter(|rule| {
                rule["family"] == "inet"
                    && rule["table"] == name
                    && rule["chain"] == "owner"
                    && rule["comment"] == owner
            })
            .count();
        if matches != 1 || handle.is_none() {
            return Err(conflict(format!(
                "refusing to touch unowned nftables table {name}"
            )));
        }
        Ok(handle)
    }

    pub(super) fn apply_firewall(
        &self,
        network: &Network,
        old: Option<u64>,
        lease: Option<OffsetDateTime>,
        deadline: Instant,
    ) -> Result<()> {
        let script = firewall_script(network, &self.tunnel, old, lease);
        self.nft(&["-f", "-"], Some(&script), deadline)?
            .check("apply atomic network firewall")
    }
}

pub(super) fn firewall_script(
    network: &Network,
    tunnel: &str,
    old: Option<u64>,
    lease: Option<OffsetDateTime>,
) -> String {
    let name = table(network);
    let owner = marker(network);
    let bridge = &network.bridge;
    let mut script = String::new();
    if let Some(handle) = old {
        writeln!(script, "delete table inet handle {handle}").unwrap();
    }
    writeln!(script, "create table inet {name}").unwrap();
    writeln!(script, "add chain inet {name} owner").unwrap();
    writeln!(
        script,
        "add rule inet {name} owner counter comment \"{owner}\""
    )
    .unwrap();
    writeln!(
        script,
        "add chain inet {name} forward {{ type filter hook forward priority 0; policy accept; }}"
    )
    .unwrap();
    writeln!(script, "add chain inet {name} postrouting {{ type nat hook postrouting priority 100; policy accept; }}").unwrap();
    if network.policy.egress != Egress::Direct {
        let mark = format!("0x4c{:04x}", network.table);
        writeln!(script, "add chain inet {name} premark {{ type filter hook prerouting priority mangle; policy accept; }}").unwrap();
        writeln!(script, "add rule inet {name} premark iifname \"{tunnel}\" ip daddr {} ct state new ct mark set {mark}", network.subnet).unwrap();
        writeln!(
            script,
            "add rule inet {name} premark iifname \"{bridge}\" ct mark != 0 meta mark set ct mark"
        )
        .unwrap();
    }
    if network.policy.needs_grant() {
        writeln!(
            script,
            "add set inet {name} live_grant {{ typeof iifname; flags timeout; }}"
        )
        .unwrap();
        // Use an absolute cutoff as well as a monotonic timeout. The cutoff
        // covers delays applying a transaction; the timeout covers clock rollback.
        if let Some(until) = lease {
            let millis = (until - OffsetDateTime::now_utc()).whole_milliseconds();
            if millis > 0 {
                writeln!(
                    script,
                    "add element inet {name} live_grant {{ \"{bridge}\" timeout {millis}ms }}"
                )
                .unwrap();
            }
        }
    }
    let mut forward = |body: &str| {
        writeln!(script, "add rule inet {name} forward {body}").unwrap();
    };
    if network.policy.needs_grant() {
        for interface in ["iifname", "oifname"] {
            forward(&format!(
                "{interface} \"{bridge}\" {interface} != @live_grant drop"
            ));
            if let Some(until) = lease {
                forward(&format!(
                    "{interface} \"{bridge}\" meta time >= {} drop",
                    until.unix_timestamp()
                ));
            }
        }
    }
    // The plugin allocates only IPv4. A container's independently configured
    // IPv6 address must not bypass its IPv4 policy.
    forward(&format!("iifname \"{bridge}\" meta nfproto ipv6 drop"));
    forward(&format!("oifname \"{bridge}\" meta nfproto ipv6 drop"));
    forward(&format!(
        "oifname \"{bridge}\" ct state established,related accept"
    ));
    if network.policy.ingress == Ingress::Allow {
        for source in &network.policy.ingress_sources {
            forward(&format!("oifname \"{bridge}\" ip saddr {source} accept"));
        }
    }
    forward(&format!("oifname \"{bridge}\" reject"));
    match network.policy.egress {
        Egress::Direct => forward(&format!("iifname \"{bridge}\" accept")),
        Egress::Selective => {
            for prefix in &network.policy.egress_cidrs {
                forward(&format!(
                    "iifname \"{bridge}\" ip daddr {prefix} oifname != \"{tunnel}\" reject"
                ));
            }
            forward(&format!("iifname \"{bridge}\" accept"));
        }
        Egress::FullTunnel => {
            for bypass in &network.bypass_cidrs {
                forward(&format!("iifname \"{bridge}\" ip daddr {bypass} accept"));
            }
            forward(&format!(
                "iifname \"{bridge}\" oifname != \"{tunnel}\" reject"
            ));
        }
        Egress::Isolated => {
            for prefix in &network.policy.egress_cidrs {
                forward(&format!(
                    "iifname \"{bridge}\" ip daddr {prefix} oifname \"{tunnel}\" accept"
                ));
            }
            forward(&format!("iifname \"{bridge}\" reject"));
        }
    }
    if network.policy.nat {
        writeln!(script, "add rule inet {name} postrouting iifname \"{bridge}\" oifname != \"{tunnel}\" masquerade").unwrap();
    }
    script
}
