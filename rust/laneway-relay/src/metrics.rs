use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Lock-free relay counters. Counters are monotonic except `sessions`, which is a gauge.
#[derive(Debug, Default)]
pub struct Metrics {
    pub(crate) sessions: AtomicU64,
    pub(crate) registrations: AtomicU64,
    pub(crate) unregistrations: AtomicU64,
    pub(crate) sessions_replaced: AtomicU64,
    pub(crate) bindings_created: AtomicU64,
    pub(crate) bindings_released: AtomicU64,
    pub(crate) candidate_publications: AtomicU64,
    pub(crate) candidate_pairs: AtomicU64,
    pub(crate) forwarded_packets: AtomicU64,
    pub(crate) forwarded_bytes: AtomicU64,
    pub(crate) dropped_malformed: AtomicU64,
    pub(crate) dropped_unknown_handle: AtomicU64,
    pub(crate) dropped_source: AtomicU64,
    pub(crate) dropped_destination: AtomicU64,
    pub(crate) dropped_too_large: AtomicU64,
    pub(crate) dropped_capability: AtomicU64,
    pub(crate) dropped_queue_full: AtomicU64,
    pub(crate) dropped_closed: AtomicU64,
    pub(crate) quic_connection_attempts: AtomicU64,
    pub(crate) quic_connection_failures: AtomicU64,
    pub(crate) tcp_connection_attempts: AtomicU64,
    pub(crate) tcp_connection_failures: AtomicU64,
    pub(crate) tcp_packet_pool_misses: AtomicU64,
    pub(crate) queue_depth: AtomicU64,
    pub(crate) queue_depth_peak: AtomicU64,
    pub(crate) controller_certificate_renewal_forced: AtomicU64,
    pub(crate) controller_certificate_renew_after_seconds: AtomicU64,
    pub(crate) controller_certificate_not_after_seconds: AtomicU64,
}

/// Point-in-time copy of every relay counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Successful instrumented process allocation calls since start, excluding
    /// allocations used solely to serve diagnostics.
    pub allocator_allocations: u64,
    /// Bytes requested by instrumented process allocations since start,
    /// excluding allocations used solely to serve diagnostics.
    pub allocator_allocated_bytes: u64,
    /// Live authenticated sessions.
    pub sessions: u64,
    /// Successful registrations.
    pub registrations: u64,
    /// Completed cleanup operations.
    pub unregistrations: u64,
    /// Duplicate identities replaced by a new authenticated connection.
    pub sessions_replaced: u64,
    /// Directional route handles created.
    pub bindings_created: u64,
    /// Directional route handles released.
    pub bindings_released: u64,
    /// Accepted relay-observed endpoint publications.
    pub candidate_publications: u64,
    /// Fresh rendezvous token pairs distributed to two nodes.
    pub candidate_pairs: u64,
    /// Packets accepted and enqueued to recipients.
    pub forwarded_packets: u64,
    /// Framed packet bytes accepted for forwarding.
    pub forwarded_bytes: u64,
    /// Structurally invalid packet frames.
    pub dropped_malformed: u64,
    /// Unknown or stale route handles.
    pub dropped_unknown_handle: u64,
    /// Source ownership failures.
    pub dropped_source: u64,
    /// Destination ownership failures.
    pub dropped_destination: u64,
    /// Negotiated payload limit failures.
    pub dropped_too_large: u64,
    /// Packets using a family not negotiated by both sessions.
    pub dropped_capability: u64,
    /// Full bounded outbound queues.
    pub dropped_queue_full: u64,
    /// Packets targeting closed sessions.
    pub dropped_closed: u64,
    /// QUIC connection tasks accepted by the relay.
    pub quic_connection_attempts: u64,
    /// QUIC connection tasks refused or ending with an error.
    pub quic_connection_failures: u64,
    /// TLS/TCP fallback connection tasks accepted by the relay.
    pub tcp_connection_attempts: u64,
    /// TLS/TCP fallback connection tasks refused or ending with an error.
    pub tcp_connection_failures: u64,
    /// TLS/TCP packet records that could not reuse a prewarmed buffer.
    pub tcp_packet_pool_misses: u64,
    /// Packets queued or holding a real bounded channel-slot reservation.
    pub queue_depth: u64,
    /// Highest aggregate queued-or-channel-reserved count observed since start.
    pub queue_depth_peak: u64,
    /// One when the controller-accepted local relay certificate is due for renewal.
    pub controller_certificate_renewal_needed: u64,
    /// Controller-accepted renewal deadline as Unix seconds.
    pub controller_certificate_renew_after_seconds: u64,
    /// Controller-accepted local relay certificate expiry as Unix seconds.
    pub controller_certificate_not_after_seconds: u64,
}

impl Metrics {
    /// Takes an acquire-ordered snapshot suitable for logging or export.
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.snapshot_at(unix_now())
    }

    pub(crate) fn snapshot_at(&self, now_unix_seconds: u64) -> MetricsSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Acquire);
        let (allocator_allocations, allocator_allocated_bytes) = crate::allocator::snapshot();
        let renewal_forced = load(&self.controller_certificate_renewal_forced);
        let renew_after = load(&self.controller_certificate_renew_after_seconds);
        MetricsSnapshot {
            allocator_allocations,
            allocator_allocated_bytes,
            sessions: load(&self.sessions),
            registrations: load(&self.registrations),
            unregistrations: load(&self.unregistrations),
            sessions_replaced: load(&self.sessions_replaced),
            bindings_created: load(&self.bindings_created),
            bindings_released: load(&self.bindings_released),
            candidate_publications: load(&self.candidate_publications),
            candidate_pairs: load(&self.candidate_pairs),
            forwarded_packets: load(&self.forwarded_packets),
            forwarded_bytes: load(&self.forwarded_bytes),
            dropped_malformed: load(&self.dropped_malformed),
            dropped_unknown_handle: load(&self.dropped_unknown_handle),
            dropped_source: load(&self.dropped_source),
            dropped_destination: load(&self.dropped_destination),
            dropped_too_large: load(&self.dropped_too_large),
            dropped_capability: load(&self.dropped_capability),
            dropped_queue_full: load(&self.dropped_queue_full),
            dropped_closed: load(&self.dropped_closed),
            quic_connection_attempts: load(&self.quic_connection_attempts),
            quic_connection_failures: load(&self.quic_connection_failures),
            tcp_connection_attempts: load(&self.tcp_connection_attempts),
            tcp_connection_failures: load(&self.tcp_connection_failures),
            tcp_packet_pool_misses: load(&self.tcp_packet_pool_misses),
            queue_depth: load(&self.queue_depth),
            queue_depth_peak: load(&self.queue_depth_peak),
            controller_certificate_renewal_needed: u64::from(
                renewal_forced != 0 || (renew_after != 0 && now_unix_seconds >= renew_after),
            ),
            controller_certificate_renew_after_seconds: renew_after,
            controller_certificate_not_after_seconds: load(
                &self.controller_certificate_not_after_seconds,
            ),
        }
    }

    pub(crate) fn queue_enqueue_started(&self) -> u64 {
        self.queue_depth.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub(crate) fn queue_enqueue_completed(&self, depth: u64) {
        self.queue_depth_peak.fetch_max(depth, Ordering::AcqRel);
    }

    pub(crate) fn queue_removed(&self, count: u64) {
        if count == 0 {
            return;
        }
        let _ = self
            .queue_depth
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
                Some(depth.saturating_sub(count))
            });
    }
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
    fn certificate_renewal_health_flips_at_deadline_and_honors_forced_failure() {
        let metrics = Metrics::default();
        metrics
            .controller_certificate_renew_after_seconds
            .store(1_000, Ordering::Release);

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
            .store(1, Ordering::Release);
        assert_eq!(
            metrics
                .snapshot_at(999)
                .controller_certificate_renewal_needed,
            1
        );
    }
}
