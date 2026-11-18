use std::{
    collections::BTreeMap,
    path::Path,
    process::{Child, Command},
    time::{Duration, Instant},
};

use super::{LinuxBackend, firewall::firewall_script, marker, operation_deadline};
use crate::{Backend, Egress, Endpoint, Network, Policy, Result};
use time::OffsetDateTime;

fn lease(seconds: i64) -> Option<OffsetDateTime> {
    Some(OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
}

fn fixture() -> Network {
    let state: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../testvectors/docker-plugin/state-v1.json"
    ))
    .unwrap();
    serde_json::from_value(state["networks"]["net-fixture"].clone()).unwrap()
}

#[test]
fn firewall_plan_keeps_transport_bypasses_and_guard_order() {
    let mut network = fixture();
    network.policy = Policy::from_options(Some(&serde_json::json!({"laneway.policy":"full-tunnel", "laneway.exit":"east", "laneway.nat":"true"}))).unwrap();
    network.bypass_cidrs = vec!["192.0.2.0/24".parse().unwrap()];
    let script = firewall_script(&network, "lane0", Some(123), lease(60));
    assert!(
        script.starts_with("delete table inet handle 123\ncreate table inet laneway_e528879dad\n")
    );
    assert!(script.contains("owner counter comment \"laneway-docker-v1:net-fixture\""));
    assert!(
        script.find("ip daddr 192.0.2.0/24 accept").unwrap()
            < script.find("oifname != \"lane0\" reject").unwrap()
    );
    assert!(script.contains("oifname != \"lane0\" masquerade"));
    assert!(script.contains("meta nfproto ipv6 drop"));
    assert!(
        script.find("!= @live_grant drop").unwrap() < script.find("ct state established").unwrap()
    );
    network.policy = Policy::from_options(None).unwrap();
    assert!(!firewall_script(&network, "lane0", None, None).contains("live_grant"));
}

fn ip(args: &[&str]) -> bool {
    Command::new("ip").args(args).status().unwrap().success()
}

fn require_isolated_namespace(backend: &LinuxBackend) -> Result<()> {
    assert_eq!(
        std::env::var("LANEWAY_ISOLATED_DOCKER_PLUGIN_TEST").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").is_file(), "never run on the host");
    let interfaces: Vec<serde_json::Value> = backend
        .ip(&["-j", "link", "show"], operation_deadline())?
        .json("inspect test namespace")?;
    assert_eq!(
        interfaces.len(),
        1,
        "requires an isolated --network none namespace"
    );
    assert_eq!(interfaces[0]["ifname"], "lo");
    Ok(())
}

#[test]
#[ignore = "requires CAP_NET_ADMIN inside a Docker container started with --network none"]
fn linux_backend_real_ownership_and_policy_lifecycle() -> Result<()> {
    let backend = LinuxBackend::new("lane0")?;
    require_isolated_namespace(&backend)?;
    let network = fixture();
    assert_eq!(network.policy.egress, Egress::Selective);

    let endpoint: Endpoint = network.endpoints["endpoint-fixture"].clone();
    let mut empty_network = network.clone();
    empty_network.endpoints = BTreeMap::new();
    assert!(backend.apply(&network, lease(60)).is_err()); // no tunnel available
    assert!(ip(&["link", "add", "name", "lane0", "type", "dummy"]));
    assert!(ip(&["link", "set", "dev", "lane0", "up"]));

    assert!(ip(&[
        "link",
        "add",
        "name",
        &network.bridge,
        "type",
        "bridge"
    ]));
    assert!(backend.apply(&network, lease(60)).is_err());
    assert!(backend.remove(&empty_network).is_err());
    assert!(
        backend
            .link(&network.bridge, operation_deadline())?
            .is_some()
    );
    assert!(ip(&["link", "del", "dev", &network.bridge]));

    let priority = network.table.to_string();
    assert!(ip(&[
        "-4",
        "rule",
        "add",
        "priority",
        &priority,
        "from",
        "192.0.2.0/24",
        "lookup",
        "main"
    ]));
    assert!(backend.apply(&network, lease(60)).is_err());
    assert!(
        backend
            .link(&network.bridge, operation_deadline())?
            .is_none()
    );
    assert!(ip(&[
        "-4",
        "rule",
        "del",
        "priority",
        &priority,
        "from",
        "192.0.2.0/24",
        "lookup",
        "main"
    ]));

    backend.apply(&network, lease(60))?;
    backend.apply(&network, lease(60))?;
    backend.join(&network, &endpoint)?;
    backend.join(&network, &endpoint)?;
    let host = backend
        .link(&endpoint.host_veth, operation_deadline())?
        .unwrap();
    assert_eq!(host["master"], network.bridge);
    assert_eq!(host["mtu"], network.policy.mtu);
    let bridge = backend
        .link(&network.bridge, operation_deadline())?
        .unwrap();
    assert_eq!(bridge["ifalias"], marker(&network));
    assert!(
        backend
            .firewall_handle(&network, operation_deadline())?
            .is_some()
    );
    assert!(backend.remove(&empty_network).is_err()); // cannot detach another interface
    // A foreign rule and route added after startup are outside our ownership.
    assert!(ip(&[
        "-4",
        "rule",
        "add",
        "priority",
        &priority,
        "from",
        "192.0.2.0/24",
        "lookup",
        "main"
    ]));
    assert!(ip(&[
        "-4",
        "route",
        "add",
        "table",
        &priority,
        "198.51.100.0/24",
        "dev",
        "lane0",
        "proto",
        "static"
    ]));
    backend.leave(&network, &endpoint)?;
    backend.leave(&network, &endpoint)?;
    backend.remove(&empty_network)?;
    backend.remove(&empty_network)?;
    assert!(
        backend
            .link(&network.bridge, operation_deadline())?
            .is_none()
    );
    assert!(
        backend
            .link(&endpoint.host_veth, operation_deadline())?
            .is_none()
    );
    assert!(
        backend
            .firewall_handle(&network, operation_deadline())?
            .is_none()
    );
    let rules = backend.ip(&["-j", "-4", "rule", "show"], operation_deadline())?;
    assert!(rules.text.contains("192.0.2.0"));
    assert!(!rules.text.contains("172.30.60.0"));
    let routes = backend.ip(
        &["-j", "-4", "route", "show", "table", &priority],
        operation_deadline(),
    )?;
    assert!(routes.text.contains("198.51.100.0/24"));
    assert!(!routes.text.contains("10.60.0.0/16"));
    Ok(())
}

struct Namespace {
    process: Child,
    pid: String,
}

impl Namespace {
    fn create() -> Self {
        let process = Command::new("unshare")
            .args(["--net", "sleep", "30"])
            .spawn()
            .unwrap();
        let namespace = Self {
            pid: process.id().to_string(),
            process,
        };
        let parent = std::fs::read_link("/proc/self/ns/net").unwrap();
        let path = format!("/proc/{}/ns/net", namespace.pid);
        let start = Instant::now();
        loop {
            if std::fs::read_link(&path).is_ok_and(|target| target != parent) {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "network namespace did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(namespace.run("ip", &["link", "set", "lo", "up"]));
        namespace
    }

    fn run(&self, program: &str, args: &[&str]) -> bool {
        Command::new("nsenter")
            .args(["-t", &self.pid, "-n", program])
            .args(args)
            .status()
            .unwrap()
            .success()
    }

    fn move_link(&self, interface: &str, address: &str) {
        assert!(ip(&["link", "set", "dev", interface, "netns", &self.pid]));
        assert!(self.run("ip", &["addr", "add", address, "dev", interface]));
        assert!(self.run("ip", &["link", "set", "dev", interface, "up"]));
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[test]
#[ignore = "changes only the disposable --network none test namespace"]
fn linux_backend_packet_path_fails_closed_without_grant_or_tunnel() -> Result<()> {
    let backend = LinuxBackend::new("lane0")?;
    require_isolated_namespace(&backend)?;
    let network = fixture();
    let client = Namespace::create();
    let remote = Namespace::create();
    let fallback = Namespace::create();
    assert!(
        Command::new("sysctl")
            .args([
                "-q",
                "-w",
                "net.ipv4.ip_forward=1",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0"
            ])
            .status()
            .unwrap()
            .success()
    );
    for (host, peer, host_addr, peer_addr, namespace) in [
        (
            "lane0",
            "remotepeer",
            "192.0.2.1/30",
            "192.0.2.2/30",
            &remote,
        ),
        (
            "testwan",
            "fallbackpeer",
            "203.0.113.1/30",
            "203.0.113.2/30",
            &fallback,
        ),
    ] {
        assert!(ip(&[
            "link", "add", "name", host, "type", "veth", "peer", "name", peer
        ]));
        namespace.move_link(peer, peer_addr);
        assert!(ip(&["addr", "add", host_addr, "dev", host]));
        assert!(ip(&["link", "set", host, "up"]));
        assert!(namespace.run("ip", &["addr", "add", "10.60.0.2/32", "dev", "lo"]));
    }
    assert!(remote.run(
        "ip",
        &["route", "add", "172.30.60.0/24", "via", "192.0.2.1"]
    ));
    assert!(fallback.run(
        "ip",
        &["route", "add", "172.30.60.0/24", "via", "203.0.113.1"]
    ));
    assert!(ip(&["route", "add", "10.60.0.2/32", "via", "203.0.113.2"]));

    backend.apply(&network, lease(60))?;
    let endpoint = &network.endpoints["endpoint-fixture"];
    backend.join(&network, endpoint)?;
    client.move_link(&endpoint.peer_veth, "172.30.60.2/24");
    assert!(client.run("ip", &["route", "add", "default", "via", "172.30.60.1"]));
    assert!(
        client.run("ping", &["-c", "1", "-W", "2", "10.60.0.2"]),
        "authorized tunnel traffic failed"
    );
    backend.set_authorization(&network, None)?;
    assert!(
        !client.run("ping", &["-c", "1", "-W", "1", "10.60.0.2"]),
        "traffic passed after revocation"
    );
    let expires = lease(5).unwrap();
    backend.set_authorization(&network, Some(expires))?;
    assert!(
        client.run("ping", &["-c", "1", "-W", "2", "10.60.0.2"]),
        "renewal did not restore tunnel traffic"
    );
    std::thread::sleep(
        (expires - OffsetDateTime::now_utc())
            .try_into()
            .unwrap_or(Duration::ZERO),
    );
    assert!(backend.link("lane0", operation_deadline())?.is_some());
    assert!(
        !client.run("ping", &["-c", "1", "-W", "1", "10.60.0.2"]),
        "traffic passed after lease expiry with the tunnel still up"
    );
    backend.set_authorization(&network, lease(60))?;
    assert!(ip(&["link", "del", "dev", "lane0"]));
    assert!(
        Command::new("ping")
            .args(["-c", "1", "-W", "2", "10.60.0.2"])
            .status()
            .unwrap()
            .success(),
        "test must leave a functional host fallback"
    );
    assert!(
        !client.run("ping", &["-c", "1", "-W", "1", "10.60.0.2"]),
        "selective traffic leaked to the host fallback"
    );
    backend.leave(&network, endpoint)?;
    let mut empty = network;
    empty.endpoints.clear();
    backend.remove(&empty)?;
    Ok(())
}
