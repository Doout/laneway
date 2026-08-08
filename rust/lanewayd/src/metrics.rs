use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Lock-free dataplane counters.
#[allow(missing_docs)]
#[derive(Debug, Default)]
pub struct Metrics {
    /// Packets accepted from TUN.
    pub tun_packets: AtomicU64,
    /// Packets injected into TUN.
    pub injected_packets: AtomicU64,
    /// Packets transmitted over relay.
    pub relay_packets: AtomicU64,
    /// Packets transmitted over direct paths.
    pub direct_packets: AtomicU64,
    /// Invalid or unauthorized packets dropped.
    pub invalid_drops: AtomicU64,
    /// Packets dropped because a bounded queue was full.
    pub queue_drops: AtomicU64,
    /// Packets dropped because no usable path existed.
    pub no_path_drops: AtomicU64,
    /// Packet-pool misses requiring a fallback allocation.
    pub packet_pool_misses: AtomicU64,
    /// Direct handshakes/probes rejected at the configured concurrency bound.
    pub direct_saturation_drops: AtomicU64,
    /// Successful relay carrier sessions.
    pub connections_total: AtomicU64,
    /// Successful carrier sessions after the first.
    pub reconnects_total: AtomicU64,
    /// Raw IP packets accepted for transmission.
    pub packets_sent_total: AtomicU64,
    /// Raw IP bytes accepted for transmission.
    pub bytes_sent_total: AtomicU64,
    /// Raw IP packets accepted from authenticated carriers.
    pub packets_received_total: AtomicU64,
    /// Raw IP bytes accepted from authenticated carriers.
    pub bytes_received_total: AtomicU64,
    /// Malformed packet/frame drops.
    pub malformed_drops: AtomicU64,
    /// Identity/source-ownership drops.
    pub auth_drops: AtomicU64,
    /// ACL/capability policy drops.
    pub policy_drops: AtomicU64,
    /// Relay QUIC connection attempts and failures.
    pub quic_attempts: AtomicU64,
    pub quic_failures: AtomicU64,
    /// Relay TLS/TCP fallback attempts and failures.
    pub tcp_attempts: AtomicU64,
    /// Successful relay TLS/TCP fallback sessions.
    pub tcp_connections_total: AtomicU64,
    pub tcp_failures: AtomicU64,
    /// Direct probe/handshake attempts and probe/handshake/carrier failures.
    pub direct_attempts: AtomicU64,
    pub direct_failures: AtomicU64,
    /// Successful changes onto a direct carrier.
    pub direct_switches: AtomicU64,
    /// Current authenticated direct carrier count.
    pub direct_active_paths: AtomicU64,
    /// Selected exit path state (one healthy, zero unavailable/not selected).
    pub exit_path_available: AtomicU64,
    /// Traffic forwarded by an active Exit Node.
    pub exit_forwarded_packets_total: AtomicU64,
    pub exit_forwarded_bytes_total: AtomicU64,
    /// Exit Node kernel forwarding/NAT readiness and failed cleanup attempts.
    pub exit_forwarding_ready: AtomicU64,
    pub exit_nat_ready: AtomicU64,
    pub exit_namespace_cleanup_failures_total: AtomicU64,
    /// Controller candidate-exchange and local-certificate state.
    pub controller_candidate_exchange_enabled: AtomicU64,
    pub controller_certificate_renewal_forced: AtomicU64,
    pub controller_certificate_renew_after_seconds: AtomicU64,
    pub controller_certificate_not_after_seconds: AtomicU64,
    /// Current relay carrier state.
    pub quic_active: AtomicU64,
    pub tcp_active: AtomicU64,
    /// Current aggregate bounded packet queue depth.
    pub queue_depth: AtomicU64,
    /// Current TUN-to-carrier outbound queue depth.
    pub outbound_queue_depth: AtomicU64,
    /// Current carrier-to-TUN injection queue depth.
    pub inject_queue_depth: AtomicU64,
    /// Maximum observed bounded packet queue depth.
    pub queue_depth_max: AtomicU64,
}

impl Metrics {
    pub(crate) fn increment(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add(counter: &AtomicU64, value: usize) {
        counter.fetch_add(value as u64, Ordering::Relaxed);
    }

    pub(crate) fn set(counter: &AtomicU64, value: bool) {
        counter.store(u64::from(value), Ordering::Relaxed);
    }

    pub(crate) fn set_value(counter: &AtomicU64, value: usize) {
        counter.store(value as u64, Ordering::Relaxed);
    }

    pub(crate) fn set_outbound_queue_depth(&self, value: usize) {
        Self::set_value(&self.outbound_queue_depth, value);
        self.refresh_queue_depth();
    }

    pub(crate) fn set_inject_queue_depth(&self, value: usize) {
        Self::set_value(&self.inject_queue_depth, value);
        self.refresh_queue_depth();
    }

    fn refresh_queue_depth(&self) {
        let depth = self
            .outbound_queue_depth
            .load(Ordering::Relaxed)
            .saturating_add(self.inject_queue_depth.load(Ordering::Relaxed));
        self.queue_depth.store(depth, Ordering::Relaxed);
        self.queue_depth_max.fetch_max(depth, Ordering::Relaxed);
    }

    /// Returns a stable numeric snapshot for logging and diagnostics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.snapshot_at(unix_now())
    }

    fn snapshot_at(&self, now_unix_seconds: u64) -> MetricsSnapshot {
        let renewal_forced = self
            .controller_certificate_renewal_forced
            .load(Ordering::Relaxed);
        let renew_after = self
            .controller_certificate_renew_after_seconds
            .load(Ordering::Relaxed);
        MetricsSnapshot {
            tun_packets: self.tun_packets.load(Ordering::Relaxed),
            injected_packets: self.injected_packets.load(Ordering::Relaxed),
            relay_packets: self.relay_packets.load(Ordering::Relaxed),
            direct_packets: self.direct_packets.load(Ordering::Relaxed),
            invalid_drops: self.invalid_drops.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
            no_path_drops: self.no_path_drops.load(Ordering::Relaxed),
            packet_pool_misses: self.packet_pool_misses.load(Ordering::Relaxed),
            direct_saturation_drops: self.direct_saturation_drops.load(Ordering::Relaxed),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            reconnects_total: self.reconnects_total.load(Ordering::Relaxed),
            packets_sent_total: self.packets_sent_total.load(Ordering::Relaxed),
            bytes_sent_total: self.bytes_sent_total.load(Ordering::Relaxed),
            packets_received_total: self.packets_received_total.load(Ordering::Relaxed),
            bytes_received_total: self.bytes_received_total.load(Ordering::Relaxed),
            malformed_drops: self.malformed_drops.load(Ordering::Relaxed),
            auth_drops: self.auth_drops.load(Ordering::Relaxed),
            policy_drops: self.policy_drops.load(Ordering::Relaxed),
            quic_attempts: self.quic_attempts.load(Ordering::Relaxed),
            quic_failures: self.quic_failures.load(Ordering::Relaxed),
            tcp_attempts: self.tcp_attempts.load(Ordering::Relaxed),
            tcp_connections_total: self.tcp_connections_total.load(Ordering::Relaxed),
            tcp_failures: self.tcp_failures.load(Ordering::Relaxed),
            direct_attempts: self.direct_attempts.load(Ordering::Relaxed),
            direct_failures: self.direct_failures.load(Ordering::Relaxed),
            direct_switches: self.direct_switches.load(Ordering::Relaxed),
            direct_active_paths: self.direct_active_paths.load(Ordering::Relaxed),
            exit_path_available: self.exit_path_available.load(Ordering::Relaxed),
            exit_forwarded_packets_total: self.exit_forwarded_packets_total.load(Ordering::Relaxed),
            exit_forwarded_bytes_total: self.exit_forwarded_bytes_total.load(Ordering::Relaxed),
            exit_forwarding_ready: self.exit_forwarding_ready.load(Ordering::Relaxed),
            exit_nat_ready: self.exit_nat_ready.load(Ordering::Relaxed),
            exit_namespace_cleanup_failures_total: self
                .exit_namespace_cleanup_failures_total
                .load(Ordering::Relaxed),
            controller_candidate_exchange_enabled: self
                .controller_candidate_exchange_enabled
                .load(Ordering::Relaxed),
            controller_certificate_renewal_needed: u64::from(
                renewal_forced != 0 || (renew_after != 0 && now_unix_seconds >= renew_after),
            ),
            controller_certificate_renew_after_seconds: renew_after,
            controller_certificate_not_after_seconds: self
                .controller_certificate_not_after_seconds
                .load(Ordering::Relaxed),
            quic_active: self.quic_active.load(Ordering::Relaxed),
            tcp_active: self.tcp_active.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            outbound_queue_depth: self.outbound_queue_depth.load(Ordering::Relaxed),
            inject_queue_depth: self.inject_queue_depth.load(Ordering::Relaxed),
            queue_depth_max: self.queue_depth_max.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn prometheus(&self) -> String {
        let snapshot = self.snapshot();
        let mut output = String::new();
        macro_rules! metric {
            ($name:literal, $kind:literal, $value:expr) => {{
                output.push_str(concat!(
                    "# TYPE laneway_rust_node_",
                    $name,
                    " ",
                    $kind,
                    "\n"
                ));
                output.push_str(concat!("laneway_rust_node_", $name, " "));
                output.push_str(&$value.to_string());
                output.push('\n');
            }};
        }
        metric!("connections_total", "counter", snapshot.connections_total);
        metric!("reconnects_total", "counter", snapshot.reconnects_total);
        metric!("packets_sent_total", "counter", snapshot.packets_sent_total);
        metric!("bytes_sent_total", "counter", snapshot.bytes_sent_total);
        metric!(
            "packets_received_total",
            "counter",
            snapshot.packets_received_total
        );
        metric!(
            "bytes_received_total",
            "counter",
            snapshot.bytes_received_total
        );
        metric!("malformed_drops_total", "counter", snapshot.malformed_drops);
        metric!("auth_drops_total", "counter", snapshot.auth_drops);
        metric!("policy_drops_total", "counter", snapshot.policy_drops);
        metric!("queue_drops_total", "counter", snapshot.queue_drops);
        metric!("no_path_drops_total", "counter", snapshot.no_path_drops);
        metric!("quic_attempts_total", "counter", snapshot.quic_attempts);
        metric!("quic_failures_total", "counter", snapshot.quic_failures);
        metric!("tcp_attempts_total", "counter", snapshot.tcp_attempts);
        metric!(
            "tcp_connections_total",
            "counter",
            snapshot.tcp_connections_total
        );
        metric!("tcp_failures_total", "counter", snapshot.tcp_failures);
        metric!("direct_attempts_total", "counter", snapshot.direct_attempts);
        metric!("direct_failures_total", "counter", snapshot.direct_failures);
        metric!("direct_switches_total", "counter", snapshot.direct_switches);
        metric!("direct_active_paths", "gauge", snapshot.direct_active_paths);
        metric!("exit_path_available", "gauge", snapshot.exit_path_available);
        metric!(
            "exit_forwarded_packets_total",
            "counter",
            snapshot.exit_forwarded_packets_total
        );
        metric!(
            "exit_forwarded_bytes_total",
            "counter",
            snapshot.exit_forwarded_bytes_total
        );
        metric!(
            "exit_forwarding_ready",
            "gauge",
            snapshot.exit_forwarding_ready
        );
        metric!("exit_nat_ready", "gauge", snapshot.exit_nat_ready);
        metric!(
            "exit_namespace_cleanup_failures_total",
            "counter",
            snapshot.exit_namespace_cleanup_failures_total
        );
        metric!(
            "controller_candidate_exchange_enabled",
            "gauge",
            snapshot.controller_candidate_exchange_enabled
        );
        metric!(
            "controller_certificate_renewal_needed",
            "gauge",
            snapshot.controller_certificate_renewal_needed
        );
        metric!(
            "controller_certificate_renew_after_seconds",
            "gauge",
            snapshot.controller_certificate_renew_after_seconds
        );
        metric!(
            "controller_certificate_not_after_seconds",
            "gauge",
            snapshot.controller_certificate_not_after_seconds
        );
        metric!("quic_active", "gauge", snapshot.quic_active);
        metric!("tcp_active", "gauge", snapshot.tcp_active);
        metric!("queue_depth", "gauge", snapshot.queue_depth);
        metric!(
            "outbound_queue_depth",
            "gauge",
            snapshot.outbound_queue_depth
        );
        metric!("inject_queue_depth", "gauge", snapshot.inject_queue_depth);
        metric!("queue_depth_max", "gauge", snapshot.queue_depth_max);
        metric!("tun_packets_total", "counter", snapshot.tun_packets);
        metric!(
            "injected_packets_total",
            "counter",
            snapshot.injected_packets
        );
        metric!("relay_packets_total", "counter", snapshot.relay_packets);
        metric!("direct_packets_total", "counter", snapshot.direct_packets);
        metric!("invalid_drops_total", "counter", snapshot.invalid_drops);
        metric!(
            "packet_pool_misses_total",
            "counter",
            snapshot.packet_pool_misses
        );
        metric!(
            "direct_saturation_drops_total",
            "counter",
            snapshot.direct_saturation_drops
        );
        output
    }
}

/// Copyable metric values.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Packets accepted from TUN.
    pub tun_packets: u64,
    /// Packets injected into TUN.
    pub injected_packets: u64,
    /// Relay transmissions.
    pub relay_packets: u64,
    /// Direct transmissions.
    pub direct_packets: u64,
    /// Invalid/unauthorized drops.
    pub invalid_drops: u64,
    /// Full-queue drops.
    pub queue_drops: u64,
    /// Missing-path drops.
    pub no_path_drops: u64,
    /// Packet-pool misses requiring a fallback allocation.
    pub packet_pool_misses: u64,
    /// Direct handshakes/probes rejected at the concurrency bound.
    pub direct_saturation_drops: u64,
    pub connections_total: u64,
    pub reconnects_total: u64,
    pub packets_sent_total: u64,
    pub bytes_sent_total: u64,
    pub packets_received_total: u64,
    pub bytes_received_total: u64,
    pub malformed_drops: u64,
    pub auth_drops: u64,
    pub policy_drops: u64,
    pub quic_attempts: u64,
    pub quic_failures: u64,
    pub tcp_attempts: u64,
    pub tcp_connections_total: u64,
    pub tcp_failures: u64,
    pub direct_attempts: u64,
    pub direct_failures: u64,
    pub direct_switches: u64,
    pub direct_active_paths: u64,
    pub exit_path_available: u64,
    pub exit_forwarded_packets_total: u64,
    pub exit_forwarded_bytes_total: u64,
    pub exit_forwarding_ready: u64,
    pub exit_nat_ready: u64,
    pub exit_namespace_cleanup_failures_total: u64,
    pub controller_candidate_exchange_enabled: u64,
    pub controller_certificate_renewal_needed: u64,
    pub controller_certificate_renew_after_seconds: u64,
    pub controller_certificate_not_after_seconds: u64,
    pub quic_active: u64,
    pub tcp_active: u64,
    pub queue_depth: u64,
    pub outbound_queue_depth: u64,
    pub inject_queue_depth: u64,
    pub queue_depth_max: u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_includes_carrier_drop_queue_and_exit_classes() {
        let metrics = Metrics::default();
        Metrics::increment(&metrics.connections_total);
        Metrics::set(&metrics.quic_active, true);
        metrics.set_inject_queue_depth(3);
        let text = metrics.prometheus();
        for required in [
            "laneway_rust_node_connections_total 1",
            "laneway_rust_node_malformed_drops_total 0",
            "laneway_rust_node_quic_active 1",
            "laneway_rust_node_tcp_active 0",
            "laneway_rust_node_direct_active_paths 0",
            "laneway_rust_node_exit_path_available 0",
            "laneway_rust_node_exit_forwarded_packets_total 0",
            "laneway_rust_node_exit_forwarding_ready 0",
            "laneway_rust_node_exit_nat_ready 0",
            "laneway_rust_node_exit_namespace_cleanup_failures_total 0",
            "laneway_rust_node_controller_certificate_renew_after_seconds 0",
            "laneway_rust_node_outbound_queue_depth 0",
            "laneway_rust_node_inject_queue_depth 3",
            "laneway_rust_node_queue_depth 3",
            "laneway_rust_node_queue_depth_max 3",
        ] {
            assert!(text.contains(required), "missing {required}");
        }
    }

    #[test]
    fn certificate_renewal_health_flips_at_deadline_and_honors_forced_failure() {
        let metrics = Metrics::default();
        metrics
            .controller_certificate_renew_after_seconds
            .store(1_000, Ordering::Relaxed);

        let before = metrics.snapshot_at(999);
        assert_eq!(before.controller_certificate_renewal_needed, 0);
        assert_eq!(before.controller_certificate_renew_after_seconds, 1_000);
        assert_eq!(
            metrics
                .snapshot_at(1_000)
                .controller_certificate_renewal_needed,
            1
        );

        metrics
            .controller_certificate_renewal_forced
            .store(1, Ordering::Relaxed);
        assert_eq!(
            metrics
                .snapshot_at(999)
                .controller_certificate_renewal_needed,
            1
        );
    }
}
