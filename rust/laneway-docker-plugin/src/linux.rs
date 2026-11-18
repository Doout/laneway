//! Linux host networking. Use typed, bounded iproute2 operations and one
//! atomic nftables transaction per firewall change.
mod firewall;
mod routing;
#[cfg(test)]
mod tests;

use std::{
    fs::File,
    io::{Read, Seek, Write},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::Value;
use wait_timeout::ChildExt;

use crate::{
    Backend, Egress, Endpoint, Error, Network, Result, conflict, invalid, model::endpoint_names,
};

pub struct LinuxBackend {
    tunnel: String,
    ip_path: &'static str,
    nft_path: &'static str,
}

impl LinuxBackend {
    pub fn new(tunnel: &str) -> Result<Self> {
        if tunnel.is_empty()
            || tunnel.len() > 15
            || tunnel.starts_with('-')
            || !tunnel
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid("invalid Linux tunnel interface name"));
        }
        Ok(Self {
            tunnel: tunnel.into(),
            ip_path: executable(&["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"])?,
            nft_path: executable(&["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"])?,
        })
    }

    fn ip(&self, args: &[&str], deadline: Instant) -> Result<Output> {
        run(self.ip_path, args, None, deadline)
    }

    fn nft(&self, args: &[&str], input: Option<&str>, deadline: Instant) -> Result<Output> {
        run(self.nft_path, args, input, deadline)
    }

    fn link(&self, name: &str, deadline: Instant) -> Result<Option<Value>> {
        let output = self.ip(&["-j", "-d", "link", "show", "dev", name], deadline)?;
        if output.missing() {
            return Ok(None);
        }
        let mut items: Vec<Value> = output.json("inspect Linux interface")?;
        if items.len() != 1 || items[0]["ifname"] != name {
            return Err(conflict("ambiguous Linux interface record"));
        }
        Ok(items.pop())
    }

    fn owned_link(
        &self,
        name: &str,
        kind: &str,
        marker: &str,
        deadline: Instant,
    ) -> Result<Option<Value>> {
        let Some(record) = self.link(name, deadline)? else {
            return Ok(None);
        };
        if record["linkinfo"]["info_kind"] != kind || record["ifalias"] != marker {
            return Err(conflict(format!(
                "refusing to touch unowned interface {name}"
            )));
        }
        Ok(Some(record))
    }

    fn bridge(&self, network: &Network, existing: bool, deadline: Instant) -> Result<()> {
        let name = network.bridge.as_str();
        let mtu = network.policy.mtu.to_string();
        if !existing {
            self.ip(&["link", "add", "name", name, "type", "bridge"], deadline)?
                .check("create bridge")?;
            if let Err(error) = self
                .ip(
                    &["link", "set", "dev", name, "alias", &marker(network)],
                    deadline,
                )
                .and_then(|output| output.check("mark bridge ownership"))
            {
                let _ = self.ip(
                    &["link", "del", "dev", name, "type", "bridge"],
                    operation_deadline(),
                );
                return Err(error);
            }
        }
        let gateway = format!("{}/{}", network.gateway, network.subnet.prefix_len());
        self.ip(&["link", "set", "dev", name, "mtu", &mtu], deadline)?
            .check("set bridge MTU")?;
        self.ip(&["-4", "addr", "replace", &gateway, "dev", name], deadline)?
            .check("assign bridge gateway")
    }
}

impl Backend for LinuxBackend {
    fn apply(&self, network: &Network) -> Result<()> {
        network.validate(&network.id)?;
        let deadline = operation_deadline();
        if network.policy.egress != Egress::Direct && self.link(&self.tunnel, deadline)?.is_none() {
            return Err(Error::Backend(
                "configured tunnel interface is unavailable".into(),
            ));
        }
        let bridge = self.owned_link(&network.bridge, "bridge", &marker(network), deadline)?;
        let table = self.firewall_handle(network, deadline)?;
        let routes = self.plan_routes(network, deadline)?;
        self.bridge(network, bridge.is_some(), deadline)?;
        // Install the fail-closed packet filter before adding policy routes
        // or bringing up a newly created bridge.
        self.apply_firewall(network, table, deadline)?;
        self.apply_routes(network, routes, deadline)?;
        self.ip(&["link", "set", "dev", &network.bridge, "up"], deadline)?
            .check("bring bridge up")
    }

    fn remove(&self, network: &Network) -> Result<()> {
        network.validate(&network.id)?;
        let deadline = operation_deadline();
        // A bridge or table name alone is not ownership. Resolve both before
        // deleting anything, and leave the persistent record on failure.
        let bridge = self.owned_link(&network.bridge, "bridge", &marker(network), deadline)?;
        let table = self.firewall_handle(network, deadline)?;
        if bridge.is_some() {
            let ports: Vec<Value> = self
                .ip(&["-j", "link", "show", "master", &network.bridge], deadline)?
                .json("inspect bridge ports")?;
            if !ports.is_empty() {
                return Err(conflict(
                    "refusing to delete a bridge with attached interfaces",
                ));
            }
            self.ip(
                &["link", "del", "dev", &network.bridge, "type", "bridge"],
                deadline,
            )?
            .check("delete owned bridge")?;
        }
        self.remove_routes(network, deadline)?;
        if let Some(handle) = table {
            self.nft(
                &["delete", "table", "inet", "handle", &handle.to_string()],
                None,
                deadline,
            )?
            .check("delete owned firewall")?;
        }
        Ok(())
    }

    fn join(&self, network: &Network, endpoint: &Endpoint) -> Result<()> {
        check_endpoint(network, endpoint)?;
        let deadline = operation_deadline();
        if self
            .owned_link(&network.bridge, "bridge", &marker(network), deadline)?
            .is_none()
        {
            return Err(conflict("recorded bridge is missing"));
        }
        let host = endpoint.host_veth.as_str();
        let peer = endpoint.peer_veth.as_str();
        let owner = endpoint_marker(network, endpoint);
        let mtu = network.policy.mtu.to_string();
        let existing = self.owned_link(host, "veth", &owner, deadline)?;
        if let Some(link) = &existing {
            if link
                .get("master")
                .is_some_and(|master| master != &network.bridge)
            {
                return Err(conflict("owned endpoint is attached to another bridge"));
            }
            if link["master"] == network.bridge
                && link["mtu"] == network.policy.mtu
                && link["flags"]
                    .as_array()
                    .is_some_and(|flags| flags.iter().any(|value| value == "UP"))
            {
                return Ok(());
            } // Docker can have moved the peer out of this namespace.
            if link["link"] != peer {
                return Err(conflict("incomplete owned veth pair cannot be verified"));
            }
        } else {
            if self.link(peer, deadline)?.is_some() {
                return Err(conflict("endpoint peer name is already in use"));
            }
            self.ip(
                &[
                    "link", "add", "name", host, "type", "veth", "peer", "name", peer,
                ],
                deadline,
            )?
            .check("create endpoint veth")?;
            if let Err(error) = self
                .ip(&["link", "set", "dev", host, "alias", &owner], deadline)
                .and_then(|output| output.check("mark endpoint ownership"))
            {
                let _ = self.ip(
                    &["link", "del", "dev", host, "type", "veth"],
                    operation_deadline(),
                );
                return Err(error);
            }
        }
        for args in [
            vec!["link", "set", "dev", host, "mtu", &mtu],
            vec!["link", "set", "dev", peer, "mtu", &mtu],
            vec!["link", "set", "dev", host, "master", &network.bridge],
            vec!["link", "set", "dev", host, "up"],
        ] {
            self.ip(&args, deadline)?
                .check("configure owned endpoint veth")?;
        }
        Ok(())
    }

    fn leave(&self, network: &Network, endpoint: &Endpoint) -> Result<()> {
        check_endpoint(network, endpoint)?;
        let deadline = operation_deadline();
        let host = endpoint.host_veth.as_str();
        if self
            .owned_link(host, "veth", &endpoint_marker(network, endpoint), deadline)?
            .is_some()
        {
            self.ip(&["link", "del", "dev", host, "type", "veth"], deadline)?
                .check("delete owned endpoint veth")?;
        }
        Ok(())
    }
}

fn check_endpoint(network: &Network, endpoint: &Endpoint) -> Result<()> {
    network.validate(&network.id)?;
    let (host, peer) = endpoint_names(&endpoint.id);
    if !endpoint.has_link_intent()
        || endpoint.host_veth != host
        || endpoint.peer_veth != peer
        || network
            .endpoints
            .get(&endpoint.id)
            .is_none_or(|record| record.address != endpoint.address)
    {
        return Err(conflict("endpoint does not match its recorded ownership"));
    }
    Ok(())
}

fn marker(network: &Network) -> String {
    format!("laneway-docker-v1:{}", network.id)
}
fn endpoint_marker(network: &Network, endpoint: &Endpoint) -> String {
    format!("laneway-docker-endpoint-v1:{}:{}", network.id, endpoint.id)
}
fn operation_deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn executable(paths: &[&'static str]) -> Result<&'static str> {
    paths
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
        .ok_or_else(|| Error::Backend(format!("missing required Linux executable {}", paths[0])))
}

struct Output {
    success: bool,
    text: String,
    diagnostics: String,
}

impl Output {
    fn missing(&self) -> bool {
        !self.success
            && [
                "No such file or directory",
                "No such process",
                "does not exist",
                "Cannot find device",
            ]
            .iter()
            .any(|pattern| self.diagnostics.contains(pattern))
    }

    fn check(&self, action: &str) -> Result<()> {
        if self.success {
            Ok(())
        } else {
            Err(Error::Backend(format!(
                "{action}: {}",
                self.diagnostics.trim()
            )))
        }
    }

    fn json<T: serde::de::DeserializeOwned>(&self, action: &str) -> Result<T> {
        self.check(action)?;
        serde_json::from_str(&self.text)
            .map_err(|error| Error::Backend(format!("{action}: {error}")))
    }
}

fn run(program: &str, args: &[&str], script: Option<&str>, deadline: Instant) -> Result<Output> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(Error::Backend(
            "Linux networking operation timed out".into(),
        ));
    }
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    if let Some(script) = script {
        let mut input = tempfile::tempfile()?;
        input.write_all(script.as_bytes())?;
        input.rewind()?;
        command.stdin(input);
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command.spawn()?;
    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        result => {
            let _ = child.kill();
            let _ = child.wait();
            result?;
            return Err(Error::Backend("Linux networking command timed out".into()));
        }
    };
    fn read(file: &mut File) -> Result<String> {
        const LIMIT: u64 = 2 << 20;
        if file.metadata()?.len() > LIMIT {
            return Err(Error::Backend(
                "unexpectedly large Linux command output".into(),
            ));
        }
        file.rewind()?;
        let mut text = Vec::new();
        file.take(LIMIT).read_to_end(&mut text)?;
        Ok(String::from_utf8_lossy(&text).into_owned())
    }
    Ok(Output {
        success: status.success(),
        text: read(&mut stdout)?,
        diagnostics: read(&mut stderr)?,
    })
}
