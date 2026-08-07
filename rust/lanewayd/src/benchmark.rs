//! Stable adapters exposing the production routing and framing primitives to
//! the native benchmark binary.

use laneway_protocol::{Id, PacketHeader};

use crate::{RoutingTable, packet_meta};

/// Routes a raw IP packet with the production immutable table and encodes the
/// stable-v1 relay header into caller-owned preallocated storage.
pub fn route_and_frame(
    routes: &RoutingTable,
    packet: &[u8],
    route_handle: u32,
    output: &mut [u8],
) -> Option<(Id, usize)> {
    let meta = packet_meta(packet).ok()?;
    let route = routes.lookup(meta.destination)?;
    let length = packet.len().checked_add(5)?;
    if route_handle == 0 || output.len() < length {
        return None;
    }
    output[..5].copy_from_slice(
        &PacketHeader {
            version: 1,
            flags: 0,
            route_handle,
        }
        .encode()
        .ok()?,
    );
    output[5..length].copy_from_slice(packet);
    Some((route.via, length))
}
