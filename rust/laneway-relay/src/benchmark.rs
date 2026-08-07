//! Stable adapter exposing production relay packet validation and handle
//! retagging to the native benchmark binary.

use std::net::IpAddr;

use laneway_protocol::{PacketHeader, decode_packet};

use crate::registry::{BenchmarkForwarder, packet_addresses};

/// Prewarmed, single-threaded driver for the production immutable relay
/// forwarding snapshot. Construction performs all session, authorization,
/// route, queue, and packet-pool allocation outside the measured interval.
pub struct ForwardingHarness {
    inner: BenchmarkForwarder,
}

impl ForwardingHarness {
    /// Creates a production forwarding graph for 1 to 100 logical flows.
    pub fn new(flows: usize, queue_depth: usize) -> anyhow::Result<Self> {
        Ok(Self {
            inner: BenchmarkForwarder::new(flows, queue_depth)?,
        })
    }

    /// Authenticates, authorizes, retags, enqueues, drains, and recycles one
    /// stable-v1 frame through the production relay fast path.
    pub fn forward(&mut self, frame: &[u8]) -> bool {
        self.inner.forward(frame)
    }
}

/// Decodes a stable-v1 frame, validates its exact IP source/destination with
/// the production parser, and retags its route handle in caller-owned storage.
pub fn validate_and_retag(
    frame: &mut [u8],
    expected_source: IpAddr,
    expected_destination: IpAddr,
    return_handle: u32,
) -> bool {
    let Ok((_, packet)) = decode_packet(frame) else {
        return false;
    };
    let Ok((source, destination)) = packet_addresses(packet) else {
        return false;
    };
    if source != expected_source || destination != expected_destination || return_handle == 0 {
        return false;
    }
    let Ok(header) = (PacketHeader {
        version: 1,
        flags: 0,
        route_handle: return_handle,
    })
    .encode() else {
        return false;
    };
    frame[..5].copy_from_slice(&header);
    true
}
