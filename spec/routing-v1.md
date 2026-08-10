# Laneway Routing v1

Laneway routes IP prefixes to authenticated nodes using controller-authorized
policy and an immutable local dataplane snapshot. An implementation MUST
advertise only address-family and route capabilities it supports.

## Routes and addresses

A route contains:

- an address family and canonical prefix;
- destination `NodeID`;
- kind `OVERLAY`, `SUBNET`, or `EXIT`;
- `NAT` or `ROUTED` mode for subnet and exit routes, and unspecified mode for
  overlay routes;
- a metric used after prefix length; and
- a stable controller-assigned nonzero 16-byte `route_id`.

The snapshot supplies NetworkID and configuration epoch. Prefix host bits MUST
be clear. Invalid, noncanonical, multicast, unspecified, loopback, and
link-local advertisements MUST be rejected unless another v1 rule explicitly
allows the prefix.

The controller assigns unique overlay addresses within a NetworkID. IPv4 and
IPv6 assignments produce `/32` and `/128` routes respectively. Two active
nodes MUST NOT own the same address. A node MUST source packets only from its
assigned addresses or prefixes it is authorized to route. Manual authorities
MUST enforce the same uniqueness and identity binding.

## Advertisement and approval

An advertisement is only a request to originate a prefix. The controller or
manual authority MUST approve its exact NetworkID, NodeID, prefix, kind, and
policy before use. Withdrawal or expiry removes authorization; relays and
receivers MUST reject sources no longer covered by active authorization.

A gateway MUST forward only approved routes owned by its authenticated NodeID.
Subnet and exit permissions are independent. A default prefix is always
`EXIT`, never `SUBNET`.

## Selection and snapshots

After policy authorization, route selection uses:

1. longest matching prefix;
2. lowest metric among equal-length prefixes.

An unauthorized specific route MUST NOT shadow an authorized route. Only the
newest committed complete snapshot applies; epochs MUST NOT be merged. Two
candidates with equal prefix and metric are ambiguous and invalidate the
snapshot.

Without an authorized route, traffic follows ordinary host routing. If the OS
has already sent it to `lane0`, `lanewayd` MUST drop it and SHOULD report an
unreachable condition when safe.

A replacement snapshot MUST be fully validated and its required path, handle,
and OS state prepared before one atomic publication. Failure MUST leave the
previous complete snapshot active.

## Handles and source validation

Route lookup selects a destination and active authenticated path; that path
maps the destination to a session-local directional 32-bit handle. Handles are
forwarding state, not routes or authority. A packet requires both an authorized
route and an active path/handle. Reconnection invalidates old handles.

The authorized source set contains assigned overlay addresses and prefixes the
node may route in that direction. Senders SHOULD reject other local sources.
Relays MUST validate source against the authenticated sender and destination
against its handle binding. Destinations MUST validate again before injection
or forwarding, including when the relay is authenticated. Validation uses
explicit authorization; asymmetric routes do not require reverse-path equality.

## Subnet and exit routes

An approved subnet router originates a non-default prefix for devices without
Laneway. Stable v1 supports:

- `NAT` (default), requiring no private-LAN return route; and
- `ROUTED`, requiring a return route outside Laneway.

`LANEWAY_SUBNET_ROUTER_V1` MUST be mutually negotiated and policy-authorized.
Without it, subnet activation MUST be rejected or ignored, never treated as an
overlay route.

Only `0.0.0.0/0` and `::/0` are exit prefixes. The controller MUST approve an
exit, and the client MUST explicitly select it; split tunnel remains the
default. Before installing an exit route, the client MUST preserve bypasses for
the relay, controller, exit transport endpoint, and required local network. It
MUST keep an explicit fail-open or fail-closed setting and MUST NOT change it on
failure. IPv4 and IPv6 selection are independent; an IPv4-only exit MUST NOT
attract IPv6.

## ACLs

A packet requires both a route and ACL permission. Neither implies the other.
Policy inputs MUST use authenticated identities and parsed packet attributes,
not node names. Controller deployments use ordered source identity,
destination identity/prefix, IP protocol, and port selectors from
`policy.proto`; no matching allow rule means deny. Manual policy MUST provide
equivalent bounded authorization.
