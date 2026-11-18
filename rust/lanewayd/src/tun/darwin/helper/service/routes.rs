//! Scoped ownership of routes on the new utun only. Never replace a host route.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::IpAddr,
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use wait_timeout::ChildExt;

use crate::tun::darwin::helper::RoutePlan;

pub(super) fn routable(prefix: IpNet) -> bool {
    prefix.prefix_len() != 0
        && prefix == prefix.trunc()
        && !matches!(prefix.addr(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
        && ![
            "0.0.0.0/32",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "::/128",
            "::1/128",
            "::ffff:0:0/96",
            "fe80::/10",
            "ff00::/8",
        ]
        .into_iter()
        .map(|raw| raw.parse::<IpNet>().expect("constant CIDR"))
        .any(|reserved| prefix.contains(&reserved) || reserved.contains(&prefix))
}

pub(super) fn validate(plan: RoutePlan) -> Result<BTreeSet<IpNet>> {
    ensure!(
        plan.routes.len() <= 1024 && plan.bypasses.len() <= 64,
        "route plan exceeds helper limits"
    );
    let mut bypasses = Vec::with_capacity(plan.bypasses.len());
    for raw in plan.bypasses {
        let ip = raw.parse::<IpAddr>()?;
        ensure!(
            !ip.is_unspecified()
                && !ip.is_multicast()
                && !matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()),
            "invalid transport bypass address"
        );
        bypasses.push(ip);
    }
    let mut routes = BTreeMap::new();
    for route in plan.routes {
        let prefix = route.prefix.parse::<IpNet>()?;
        ensure!(
            routable(prefix),
            "helper only accepts canonical unicast split routes"
        );
        if bypasses.iter().any(|bypass| prefix.contains(bypass)) {
            continue;
        }
        let prior = routes.insert(prefix, route.metric);
        ensure!(
            prior.is_none_or(|metric| metric == route.metric),
            "conflicting duplicate route"
        );
    }
    Ok(routes.into_keys().collect())
}

pub(super) struct Routes {
    name: String,
    owned: BTreeSet<IpNet>,
}

impl Routes {
    pub(super) fn new(name: String) -> Self {
        Self {
            name,
            owned: BTreeSet::new(),
        }
    }
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn replace(&mut self, desired: BTreeSet<IpNet>, deadline: Instant) -> Result<()> {
        let stale: Vec<_> = self.owned.difference(&desired).copied().collect();
        let added: Vec<_> = desired.difference(&self.owned).copied().collect();
        for prefix in stale {
            self.remove(prefix, deadline)?;
            self.owned.remove(&prefix);
        }
        for prefix in added {
            ensure!(
                self.lookup(prefix, deadline)?.is_none(),
                "refusing to replace existing route {prefix}"
            );
            let family = family(prefix);
            run(
                "/sbin/route",
                &[
                    "-n",
                    "add",
                    family,
                    "-net",
                    &prefix.to_string(),
                    "-interface",
                    &self.name,
                ],
                deadline,
            )?
            .success("add utun route")?;
            self.owned.insert(prefix);
        }
        Ok(())
    }

    pub(super) fn clear(&mut self, deadline: Instant) -> Result<()> {
        let mut error = None;
        for prefix in self.owned.clone() {
            match self.remove(prefix, deadline) {
                Ok(()) => {
                    self.owned.remove(&prefix);
                }
                Err(cause) => {
                    error.get_or_insert(cause);
                }
            }
        }
        error.map_or(Ok(()), Err)
    }

    fn remove(&self, prefix: IpNet, deadline: Instant) -> Result<()> {
        let Some(interface) = self.lookup(prefix, deadline)? else {
            return Ok(());
        };
        ensure!(
            interface == self.name,
            "owned route {prefix} now uses a different interface; not deleting it"
        );
        run(
            "/sbin/route",
            &[
                "-n",
                "delete",
                family(prefix),
                "-net",
                &prefix.to_string(),
                "-interface",
                &self.name,
            ],
            deadline,
        )?
        .success("delete owned utun route")
    }

    fn lookup(&self, prefix: IpNet, deadline: Instant) -> Result<Option<String>> {
        let output = run(
            "/sbin/route",
            &["-n", "get", family(prefix), "-net", &prefix.to_string()],
            deadline,
        )?;
        if output.text.contains("not in table") || output.text.contains("No such process") {
            return Ok(None);
        }
        ensure!(output.ok, "query macOS route: {}", output.text);
        lookup_exact(&output.text, prefix)
    }
}

fn family(prefix: IpNet) -> &'static str {
    if prefix.addr().is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    }
}

fn lookup_exact(text: &str, prefix: IpNet) -> Result<Option<String>> {
    let (mut destination, mut mask, mut interface) = (None, None, None);
    for (field, value) in text.lines().filter_map(|line| line.split_once(':')) {
        match field.trim() {
            "destination" => destination = Some(value.trim()),
            "mask" | "netmask" => mask = Some(value.trim()),
            "interface" => interface = Some(value.trim()),
            _ => (),
        }
    }
    let destination = destination.context("macOS route reply omitted its destination")?;
    if destination == "default" {
        return Ok(None);
    }
    if let Ok(network) = destination.parse::<IpNet>() {
        if network.trunc() != prefix {
            return Ok(None);
        }
    } else {
        let destination = destination
            .split('%')
            .next()
            .and_then(|value| value.parse::<IpAddr>().ok())
            .context("invalid destination in macOS route reply")?;
        if destination != prefix.addr() {
            return Ok(None);
        }
        let bits = match mask {
            None => IpNet::from(destination).prefix_len(),
            Some(value) => {
                mask_bits(destination, value).context("invalid mask in macOS route reply")?
            }
        };
        if bits != prefix.prefix_len() {
            return Ok(None);
        }
    }
    Ok(Some(
        interface
            .context("existing macOS route has no interface")?
            .to_owned(),
    ))
}

fn mask_bits(destination: IpAddr, raw: &str) -> Option<u8> {
    fn contiguous(bits: u128, width: u32) -> Option<u8> {
        let ones = bits.count_ones();
        let expected = if ones == 0 {
            0
        } else {
            (u128::MAX << (128 - ones)) >> (128 - width)
        };
        (expected == bits).then_some(ones as u8)
    }
    match destination {
        IpAddr::V4(_) => {
            let bits = if let Some(hex) = raw.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                u32::from(raw.parse::<std::net::Ipv4Addr>().ok()?)
            };
            contiguous(u128::from(bits), 32)
        }
        IpAddr::V6(_) => contiguous(u128::from(raw.parse::<std::net::Ipv6Addr>().ok()?), 128),
    }
}

pub(super) struct Output {
    ok: bool,
    text: String,
}

impl Output {
    pub(super) fn success(self, operation: &str) -> Result<()> {
        ensure!(self.ok, "{operation}: {}", self.text.trim());
        Ok(())
    }
}

pub(super) fn run(program: &str, args: &[&str], deadline: Instant) -> Result<Output> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    ensure!(
        !timeout.is_zero(),
        "macOS route operation exceeded its deadline"
    );
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let waited = child.wait_timeout(timeout);
    let status = match waited {
        Ok(Some(status)) => status,
        result => {
            let _ = child.kill();
            let _ = child.wait();
            result?;
            bail!("macOS route command timed out");
        }
    };
    let mut text = String::new();
    child
        .stdout
        .take()
        .context("missing macOS command stdout")?
        .take(8192)
        .read_to_string(&mut text)?;
    child
        .stderr
        .take()
        .context("missing macOS command stderr")?
        .take(8192)
        .read_to_string(&mut text)?;
    ensure!(text.len() < 8192, "unexpectedly large macOS route response");
    Ok(Output {
        ok: status.success(),
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::darwin::helper::Route;

    #[test]
    fn split_routes_do_not_capture_transport_or_reserved_addresses() -> Result<()> {
        let plan = |routes: &[&str]| RoutePlan {
            routes: routes
                .iter()
                .map(|prefix| Route {
                    prefix: (*prefix).to_owned(),
                    metric: 100,
                })
                .collect(),
            bypasses: vec!["10.1.2.3".into(), "2001:db8:1::1".into()],
        };
        assert_eq!(
            validate(plan(&[
                "10.1.0.0/16",
                "10.2.0.0/16",
                "2001:db8:1::/48",
                "2001:db8:2::/48"
            ]))?,
            BTreeSet::from(["10.2.0.0/16".parse()?, "2001:db8:2::/48".parse()?])
        );
        for rejected in [
            "0.0.0.0/0",
            "::/0",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "10.2.3.4/16",
            "fe80::/10",
            "::ffff:10.2.0.0/112",
        ] {
            assert!(validate(plan(&[rejected])).is_err(), "accepted {rejected}");
        }
        Ok(())
    }

    #[test]
    fn native_route_parser_distinguishes_exact_owned_routes_from_fallbacks() -> Result<()> {
        let v4 = "10.1.0.0/16".parse()?;
        let v6 = "2001:db8:1::/48".parse()?;
        assert_eq!(
            lookup_exact(
                "destination: 10.1.0.0\nmask: 255.255.0.0\ninterface: utun7\n",
                v4
            )?
            .as_deref(),
            Some("utun7")
        );
        assert_eq!(
            lookup_exact(
                "destination: 10.1.0.0\nmask: 0xffff0000\ninterface: en0\n",
                v4
            )?
            .as_deref(),
            Some("en0")
        );
        assert_eq!(
            lookup_exact("destination: default\ninterface: en0\n", v4)?,
            None
        );
        assert_eq!(
            lookup_exact(
                "destination: 10.1.0.0\nmask: 255.255.255.0\ninterface: en0\n",
                v4
            )?,
            None
        );
        assert_eq!(
            lookup_exact(
                "destination: 2001:db8:1::\nmask: ffff:ffff:ffff::\ninterface: utun7\n",
                v6
            )?
            .as_deref(),
            Some("utun7")
        );
        assert!(
            lookup_exact(
                "destination: 10.1.0.0\nmask: 255.0.255.0\ninterface: en0\n",
                v4
            )
            .is_err()
        );
        Ok(())
    }
}
