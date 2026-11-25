use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use laneway_protocol::Id;
use url::Url;

use crate::model::{Bootstrap, Config, ControllerInitialNetwork};

const SECOND: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * SECOND;

impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.mode.as_str(), "node" | "relay" | "controller"),
            "mode must be \"node\", \"relay\", or \"controller\""
        );
        ensure!(
            self.mode == "controller" || !self.controller.initial_network.configured(),
            "controller.initial_network is valid only in controller mode"
        );
        ensure!(
            !self.state_dir.is_empty() && !self.socket_path.is_empty(),
            "state_dir and socket_path are required"
        );
        ensure!(
            !self.tls.certificate.is_empty()
                && !self.tls.private_key.is_empty()
                && !self.tls.ca.is_empty(),
            "tls.certificate, tls.private_key, and tls.ca are required"
        );
        ensure!(
            self.node.reconnect_min.nanos() > 0
                && self.node.reconnect_max.nanos() >= self.node.reconnect_min.nanos(),
            "node reconnect bounds are invalid"
        );
        let relay = &self.relay;
        ensure!(
            (1..=65536).contains(&relay.queue_depth),
            "relay.queue_depth must be between 1 and 65536"
        );
        let rate = relay.packet_rate_bits_per_second;
        let burst = relay.packet_burst_bytes;
        ensure!(
            (rate == 0) == (burst == 0)
                && rate <= 1_000_000_000_000
                && (0..=(64 << 20)).contains(&burst)
                && (rate == 0 || burst >= 1285),
            "relay packet limiter requires rate and burst together, rate <= 1Tbps, and burst from 1285 bytes through 64MiB"
        );
        ensure!(
            relay.handshake_timeout.nanos() > 0 && relay.idle_timeout.nanos() > 0,
            "relay timeout values must be positive"
        );
        let fall = &self.tcp_fallback;
        ensure!(
            fall.handshake_timeout.nanos() > 0
                && fall.write_timeout.nanos() > 0
                && fall.idle_timeout.nanos() > 0
                && fall.keepalive_period.nanos() > 0
                && fall.keepalive_period.nanos() < fall.idle_timeout.nanos()
                && (SECOND..=5 * MINUTE).contains(&fall.quic_probe_interval.nanos()),
            "tcp_fallback timeouts are invalid"
        );
        ensure!(
            (1..=4096).contains(&fall.queue_depth),
            "tcp_fallback.queue_depth must be between 1 and 4096"
        );
        let direct = &self.direct;
        ensure!(
            (1..=10 * MINUTE).contains(&direct.candidate_ttl.nanos())
                && (1..=SECOND).contains(&direct.probe_interval.nanos())
                && (1..=30 * SECOND).contains(&direct.probe_timeout.nanos())
                && (SECOND..=5 * MINUTE).contains(&direct.rendezvous_interval.nanos())
                && (1..=32).contains(&direct.max_candidates),
            "direct candidate, probe, and timeout bounds are invalid"
        );
        self.validate_mode()?;
        self.validate_networking()
    }

    fn validate_mode(&self) -> Result<()> {
        let controller = &self.controller;
        let managed = !controller.endpoint.is_empty();
        let direct = self.direct.enabled.unwrap_or_default();
        let wireguard = &self.wireguard;
        let fallback = &self.tcp_fallback;
        let public = &self.public_https;
        if self.mode != "node" {
            ensure!(
                !direct && !wireguard.enabled,
                "direct connectivity and WireGuard are only valid in node mode"
            );
        }
        if managed && matches!(self.mode.as_str(), "node" | "relay") {
            ensure!(
                controller.poll_interval.nanos() > 0 && !controller.quic_endpoint.is_empty(),
                "controller.quic_endpoint and a positive controller.poll_interval are required when controller.endpoint is configured"
            );
            ensure!(
                self.peers.is_empty(),
                "static peers and controller.endpoint are mutually exclusive"
            );
        }
        match self.mode.as_str() {
            "node" => {
                ensure!(
                    !self.node.relay_address.is_empty(),
                    "node.relay_address is required in node mode"
                );
                validate_id(&self.node.relay_network_id).context("node.relay_network_id")?;
                validate_id(&self.node.relay_service_id).context("node.relay_service_id")?;
                ensure!(
                    managed || !self.node.overlay_addresses.is_empty(),
                    "at least one node.overlay_addresses entry is required without a controller"
                );
                ensure!(
                    !managed || self.node.overlay_addresses.is_empty(),
                    "static node.overlay_addresses and controller.endpoint are mutually exclusive"
                );
                ensure!(
                    fallback.listen.is_empty(),
                    "tcp_fallback.listen is only valid in relay mode"
                );
                ensure!(
                    !direct || !self.direct.listen.is_empty(),
                    "direct.listen is required when direct connectivity is enabled"
                );
                ensure!(
                    !wireguard.enabled
                        || (!wireguard.private_key.is_empty()
                            && !wireguard.interface.is_empty()
                            && wireguard.mtu == 1280),
                    "wireguard.private_key, interface, and MTU 1280 are required when WireGuard is enabled"
                );
                ensure!(
                    !self.connector.userspace
                        || !(wireguard.enabled
                            || !self.routing.output_interface.is_empty()
                            || !self.routing.advertise.is_empty()
                            || self.exit.enabled
                            || self.exit.serve),
                    "userspace Connector mode cannot use WireGuard, native routing, or full packet Exit mode"
                );
            }
            "relay" => {
                ensure!(
                    !self.relay.listen.is_empty(),
                    "relay.listen is required in relay mode"
                );
                ensure!(
                    managed || !self.peers.is_empty(),
                    "at least one static peer or controller.endpoint is required in relay mode"
                );
                ensure!(
                    fallback.address.is_empty(),
                    "tcp_fallback.address is only valid in node mode"
                );
                ensure!(
                    public.server_name.is_empty() == public.cache_dir.is_empty(),
                    "public_https requires server_name and cache_dir together"
                );
                if !public.server_name.is_empty() {
                    ensure!(
                        !fallback.listen.is_empty() && managed,
                        "public_https requires tcp_fallback.listen and controller.endpoint"
                    );
                    dns_name(&public.server_name).context("public_https.server_name")?;
                    ensure!(
                        clean_absolute_path(&public.cache_dir),
                        "public_https.cache_dir must be a clean absolute path"
                    );
                }
            }
            "controller" => {
                ensure!(
                    !controller.listen.is_empty()
                        && !controller.quic_listen.is_empty()
                        && !controller.database.is_empty()
                        && !controller.ca_private_key.is_empty()
                        && !controller.admin_token_file.is_empty(),
                    "controller.listen, controller.quic_listen, controller.database, controller.ca_private_key, and controller.admin_token_file are required in controller mode"
                );
                ensure!(
                    controller.leaf_validity.nanos() > 0,
                    "controller.leaf_validity must be positive"
                );
                controller.initial_network.validate()?;
                ensure!(
                    fallback.listen.is_empty() && fallback.address.is_empty(),
                    "tcp_fallback endpoints are not valid in controller mode"
                );
                self.bootstrap.validate()?;
                ensure!(
                    !controller.initial_network.configured()
                        || self.bootstrap.network_id.is_empty()
                        || self.bootstrap.network_id == controller.initial_network.network_id,
                    "bootstrap.network_id must match controller.initial_network.network_id"
                );
            }
            _ => unreachable!("mode checked before dispatch"),
        }
        ensure!(
            self.mode == "controller" || !self.bootstrap.configured(),
            "bootstrap listener is valid only in controller mode"
        );
        ensure!(
            self.mode == "relay" || (public.server_name.is_empty() && public.cache_dir.is_empty()),
            "public_https is valid only in relay mode"
        );
        ensure!(
            self.mode == "node" || !self.connector.userspace,
            "userspace Connector mode is valid only in node mode"
        );
        if managed {
            validate_id(&controller.network_id).context("controller.network_id")?;
            validate_id(&controller.service_id).context("controller.service_id")?;
        }
        Ok(())
    }

    fn validate_networking(&self) -> Result<()> {
        let managed = !self.controller.endpoint.is_empty();
        let exit = &self.exit;
        ensure!(
            !self.routing.output_interface.is_empty()
                || (!exit.serve && self.routing.advertise.is_empty()),
            "routing.output_interface is required for subnet or exit gateway forwarding"
        );
        if exit.enabled {
            ensure!(
                managed,
                "controller.endpoint is required when an exit node is selected"
            );
            validate_id(&exit.selected_node_id).context("exit.selected_node_id")?;
            ensure!(
                matches!(exit.failure_mode.as_str(), "open" | "closed"),
                "exit.failure_mode must be explicitly set to open or closed"
            );
        }
        ensure!(
            !exit.serve || managed,
            "controller.endpoint is required when serving as an exit node"
        );
        for value in &exit.dns_servers {
            let address = parse_address(value).with_context(|| {
                format!("exit DNS server {value:?} is not a unicast IP address")
            })?;
            ensure!(
                !mapped(address) && !address.is_unspecified() && !address.is_multicast(),
                "exit DNS server {value:?} is not a unicast IP address"
            );
        }
        for value in &exit.local_lan_bypasses {
            routable_prefix(value).with_context(|| {
                format!("exit local LAN bypass {value:?} is not a canonical non-default IP prefix")
            })?;
        }
        for value in &self.node.overlay_addresses {
            canonical_prefix(value)?;
        }
        for value in &self.routing.advertise {
            routable_prefix(value).with_context(|| {
                format!(
                    "advertised prefix {value:?} is not a canonical routable non-default prefix"
                )
            })?;
        }
        for (index, peer) in self.peers.iter().enumerate() {
            validate_id(&peer.network_id).with_context(|| format!("peers[{index}].network_id"))?;
            validate_id(&peer.node_id).with_context(|| format!("peers[{index}].node_id"))?;
            ensure!(
                trimmed_name(&peer.name),
                "peers[{index}].name must be empty or a trimmed name of at most 253 bytes"
            );
            ensure!(
                !peer.prefixes.is_empty(),
                "peers[{index}].prefixes is empty"
            );
            for value in &peer.prefixes {
                routable_prefix(value).with_context(|| format!("peers[{index}] prefix {value:?} is not a canonical routable non-default prefix"))?;
            }
        }
        Ok(())
    }
}

impl ControllerInitialNetwork {
    pub fn configured(&self) -> bool {
        [
            &self.network_id,
            &self.name,
            &self.ipv4_pool,
            &self.ipv6_pool,
        ]
        .iter()
        .any(|value| !value.is_empty())
    }

    fn validate(&self) -> Result<()> {
        if !self.configured() {
            return Ok(());
        }
        ensure!(
            !self.network_id.is_empty() && !self.name.is_empty() && !self.ipv4_pool.is_empty(),
            "controller.initial_network requires network_id, name, and ipv4_pool"
        );
        validate_id(&self.network_id).context("controller.initial_network.network_id")?;
        ensure!(
            trimmed_name(&self.name),
            "controller.initial_network.name must be 1..253 trimmed bytes"
        );
        validate_pool(&self.ipv4_pool, 8..=30, true).context(
            "controller.initial_network.ipv4_pool must be a canonical routable IPv4 /8 through /30",
        )?;
        if !self.ipv6_pool.is_empty() {
            validate_pool(&self.ipv6_pool, 64..=120, false).context("controller.initial_network.ipv6_pool must be a canonical routable IPv6 /64 through /120")?;
        }
        Ok(())
    }
}

impl Bootstrap {
    fn configured(&self) -> bool {
        [
            &self.listen,
            &self.certificate,
            &self.private_key,
            &self.network_id,
            &self.controller_endpoint,
            &self.controller_quic_endpoint,
            &self.controller_server_name,
        ]
        .iter()
        .any(|value| !value.is_empty())
            || !self.artifacts.is_empty()
    }

    fn validate(&self) -> Result<()> {
        if !self.configured() {
            return Ok(());
        }
        ensure!(
            !self.network_id.is_empty()
                && !self.controller_endpoint.is_empty()
                && !self.controller_quic_endpoint.is_empty()
                && !self.controller_server_name.is_empty(),
            "bootstrap requires network_id, controller_endpoint, controller_quic_endpoint, and controller_server_name"
        );
        ensure!(
            self.listen.is_empty() == self.certificate.is_empty()
                && self.listen.is_empty() == self.private_key.is_empty(),
            "bootstrap listen, certificate, and private_key must be specified together"
        );
        validate_id(&self.network_id).context("bootstrap.network_id")?;
        let url = https_url(&self.controller_endpoint)
            .context("bootstrap.controller_endpoint must be an HTTPS origin")?;
        let raw_tail = self.controller_endpoint.split_once("://").unwrap().1;
        let raw_hierarchical = raw_tail.split(['?', '#']).next().unwrap_or_default();
        let raw_path = raw_hierarchical
            .find('/')
            .map_or("", |index| &raw_hierarchical[index..]);
        ensure!(
            matches!(raw_path, "" | "/") && url.query().unwrap_or("").is_empty(),
            "bootstrap.controller_endpoint must be an HTTPS origin"
        );
        host_port(&self.controller_quic_endpoint)
            .context("bootstrap.controller_quic_endpoint must be a canonical host:port")?;
        dns_name(&self.controller_server_name).context("bootstrap.controller_server_name")?;
        let mut platforms = HashSet::new();
        for (index, artifact) in self.artifacts.iter().enumerate() {
            ensure!(
                matches!(artifact.os.as_str(), "linux" | "darwin")
                    && matches!(artifact.arch.as_str(), "amd64" | "arm64"),
                "bootstrap.artifacts[{index}] must target linux or darwin on amd64 or arm64"
            );
            https_url(&artifact.url).with_context(|| {
                format!(
                    "bootstrap.artifacts[{index}].url must be HTTPS without credentials or fragment"
                )
            })?;
            ensure!(
                artifact.sha256.len() == 64
                    && artifact
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "bootstrap.artifacts[{index}].sha256 must be canonical lowercase SHA-256"
            );
            ensure!(
                (1..=(512 << 20)).contains(&artifact.size_bytes),
                "bootstrap.artifacts[{index}].size_bytes is invalid"
            );
            ensure!(
                platforms.insert((&artifact.os, &artifact.arch)),
                "bootstrap.artifacts[{index}] duplicates platform"
            );
        }
        Ok(())
    }
}

fn validate_id(value: &str) -> Result<()> {
    value.parse::<Id>()?;
    Ok(())
}

fn trimmed_name(value: &str) -> bool {
    value.trim() == value && value.len() <= 253 && !value.contains('\0')
}

fn validate_pool(value: &str, bits: std::ops::RangeInclusive<u8>, v4: bool) -> Result<()> {
    let prefix = routable_prefix(value)?;
    ensure!(
        bits.contains(&prefix.prefix_len()) && matches!(prefix, IpNet::V4(_)) == v4,
        "pool address family or prefix length is invalid"
    );
    Ok(())
}

fn mapped(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
}

fn canonical_prefix(value: &str) -> Result<IpNet> {
    let prefix: IpNet = value
        .parse()
        .with_context(|| format!("prefix {value:?} is invalid or noncanonical"))?;
    ensure!(
        prefix.addr() == prefix.network() && !mapped(prefix.addr()),
        "prefix {value:?} is invalid or noncanonical"
    );
    Ok(prefix)
}

fn routable_prefix(value: &str) -> Result<IpNet> {
    let prefix = canonical_prefix(value)?;
    const FORBIDDEN: [&str; 8] = [
        "0.0.0.0/32",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
    ];
    ensure!(
        prefix.prefix_len() != 0
            && !FORBIDDEN.iter().any(|value| {
                let blocked: IpNet = value.parse().expect("static prefix");
                prefix.contains(&blocked.addr()) || blocked.contains(&prefix.addr())
            }),
        "prefix {value:?} is not routable"
    );
    Ok(prefix)
}

fn clean_absolute_path(value: &str) -> bool {
    Path::new(value).is_absolute()
        && (value == "/"
            || value
                .strip_prefix('/')
                .is_some_and(|rest| rest.split('/').all(|part| !matches!(part, "" | "." | ".."))))
}

fn parse_address(value: &str) -> Result<IpAddr> {
    if let Some((address, zone)) = value.split_once('%') {
        ensure!(!zone.is_empty(), "empty IP zone");
        return Ok(IpAddr::V6(address.parse()?));
    }
    Ok(value.parse()?)
}

fn https_url(value: &str) -> Result<Url> {
    let Some((scheme, rest)) = value.split_once("://") else {
        bail!("URL has no scheme");
    };
    let (without_fragment, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let hierarchical = without_fragment
        .split_once('?')
        .map_or(without_fragment, |parts| parts.0);
    let (authority, raw_path) = hierarchical.split_once('/').unwrap_or((hierarchical, ""));
    ensure!(
        scheme.eq_ignore_ascii_case("https")
            && !authority.is_empty()
            && !authority.contains(['@', '\\'])
            && fragment.is_empty()
            && !value.bytes().any(|byte| byte.is_ascii_control()),
        "URL must be HTTPS without credentials or fragment"
    );
    let escaped = raw_path.as_bytes();
    for (index, byte) in escaped.iter().enumerate() {
        if *byte == b'%' {
            ensure!(
                escaped
                    .get(index + 1..index + 3)
                    .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)),
                "invalid URL path escape"
            );
        }
    }
    // Go's net/url recognizes a numeric port syntactically even when its
    // value cannot be used for a connection. Rust's URL parser limits ports
    // to 16 bits, so validate the rest against that parser with the port omitted.
    let parsed = if let Some((_, port)) = authority.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_err()
    {
        let port_start = scheme.len() + 3 + authority.len() - port.len() - 1;
        let authority_end = scheme.len() + 3 + authority.len();
        Url::parse(&format!(
            "{}{}",
            &value[..port_start],
            &value[authority_end..]
        ))?
    } else {
        Url::parse(value)?
    };
    ensure!(parsed.host().is_some(), "HTTPS URL has no host");
    Ok(parsed)
}

fn dns_labels(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn dns_name(value: &str) -> Result<()> {
    ensure!(
        dns_labels(value) && value.parse::<IpAddr>().is_err(),
        "must be a canonical lowercase DNS name"
    );
    Ok(())
}

fn host_port(value: &str) -> Result<()> {
    let (raw_host, port) = value.rsplit_once(':').context("endpoint has no port")?;
    let host = if raw_host.starts_with('[') {
        raw_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .context("invalid brackets")?
    } else {
        ensure!(!raw_host.contains(':'), "unbracketed IPv6 endpoint");
        raw_host
    };
    ensure!(
        port.bytes().all(|byte| byte.is_ascii_digit()) && port.parse::<u16>()? > 0,
        "invalid endpoint port"
    );
    if let Ok(address) = host.parse::<IpAddr>() {
        ensure!(
            !mapped(address)
                && !address.is_unspecified()
                && !address.is_multicast()
                && address != IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
            "invalid endpoint IP"
        );
    } else {
        ensure!(
            dns_labels(&host.trim_end_matches('.').to_ascii_lowercase()) && !host.ends_with(".."),
            "invalid endpoint hostname"
        );
    }
    Ok(())
}
