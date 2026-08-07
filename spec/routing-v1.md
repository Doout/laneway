# Laneway Routing v1

Status: Stable-v1 normative overlay, subnet, and exit routing model.

Normative terms have the meaning defined in BCP 14.

## 1. Model

Laneway routes IP prefixes to authenticated nodes. Route policy is controller-authorized; route lookup is a local dataplane operation over an immutable snapshot. The reference Linux dataplane installs IPv4 and IPv6 overlay, approved subnet, and explicitly selected exit routes. An implementation MUST advertise only the address-family and route capabilities it actually supports.

A route contains at least:

- address family and canonical prefix;
- destination `NodeID`;
- route kind: `OVERLAY`, `SUBNET`, or `EXIT`;
- explicit `NAT` or `ROUTED` mode for subnet and exit routes (overlay routes
  use the unspecified/none mode);
- numeric metric used only after prefix length; and
- a stable controller-assigned 16-byte nonzero `route_id`.

The containing snapshot supplies the NetworkID and authorization/configuration epoch. Advertisement validity and approval state belong to control-plane objects, not to the forwarding route itself.

An address prefix MUST have all host bits cleared. Invalid, noncanonical, multicast, unspecified, loopback, or link-local advertisements MUST be rejected unless an explicit later specification authorizes a precise use.

## 2. Overlay addresses

The controller assigns each node one or more unique overlay addresses within its NetworkID. An IPv4 assignment produces a `/32` route; an IPv6 assignment produces a `/128` route. Two active nodes MUST NOT own the same overlay address in one network.

An overlay host route targets the node that owns the address. A node MUST use only controller-assigned local overlay addresses as packet sources. Names and message claims MUST NOT override the authenticated assignment.

Manual static configurations act as a local authority and MUST enforce the same uniqueness and identity binding.

## 3. Advertisement and approval

A route advertisement is a request by a node to originate a prefix. It MUST NOT become usable merely because the node sent it. The controller or manual static authority MUST approve the exact NetworkID, NodeID, prefix, route kind, and relevant policy.

Approval creates an authorized route in a configuration epoch. Withdrawal or expiry removes that authorization. A relay and receiving node MUST reject packets whose claimed source is no longer covered by the sender's active authorized source prefixes.

A gateway MUST apply forwarding only for approved routes owned by its
authenticated NodeID. Neither an advertisement nor a mode value by itself
grants packet-forwarding authority.

Subnet and exit advertisement capabilities are independent. A node with subnet permission does not thereby have exit permission, and a default prefix MUST be classified as `EXIT`, never as an ordinary subnet route.

## 4. Route selection

For a destination IP address, a node selects routes in this order:

1. longest matching prefix;
2. lowest numeric metric among routes with the same prefix length.

Policy authorization is evaluated before the route becomes a candidate. A more-specific unauthorized route MUST NOT shadow an authorized route. Equal routes from different epochs MUST resolve from the newest committed complete snapshot only; snapshots MUST NOT be merged ad hoc.

Equal-prefix routes with different metrics are valid. Two candidates with the same prefix and metric are ambiguous and the snapshot MUST be rejected rather than choosing an implementation-specific winner.

If no authorized route exists, the packet is not a Laneway packet and follows the host's ordinary routing policy. If the OS has already delivered it to `lane0`, `lanewayd` MUST drop it and SHOULD report an unreachable condition where safe.

## 5. Route snapshots

The active route table is an immutable snapshot associated with one NetworkID and configuration epoch. Applying a new snapshot MUST:

1. fully validate identity references, prefixes, capabilities, and policy;
2. prepare required path/handle state;
3. update OS routes safely where applicable; and
4. publish one atomic dataplane snapshot.

If any required step fails, the previous complete snapshot MUST remain active. Readers MUST NOT take a global mutable lock per packet. Old snapshots MAY remain alive until current readers finish, then MUST be reclaimed.

OS route installation is derived state. On shutdown, failed startup, identity change, or configuration withdrawal, the daemon MUST remove only routes it owns and restore any displaced state it recorded. It MUST NOT broadly flush system routes.

## 6. Route handles

Route lookup yields a destination node and path. The active authenticated path maps that destination to a session-local directional 32-bit handle. Handles are transport forwarding state, not routes: changing a handle does not change policy, and possessing one does not authorize a prefix.

A packet may be sent only when both an authorized route and an active handle/path exist. If the path fails, packets MAY enter a bounded queue while a replacement is established. On exhaustion, packets MUST be dropped according to explicit policy. Reconnection invalidates old handles.

## 7. Source validation

Each active node has an authorized source set:

- its assigned overlay host addresses; and
- prefixes it is authorized to route in the relevant direction.

The sender SHOULD reject locally sourced packets outside its source set before transport. The relay MUST validate a received packet's source against the authenticated sender's set and destination against its handle binding. The destination node or gateway MUST validate again before local injection or forwarding. These checks are mandatory even with an authenticated relay.

Reverse-path equality is not required because subnet and exit routing can be asymmetric. Validation uses explicit authorization, not inferred arrival interface alone.

## 8. Subnet routes

An approved subnet router originates a non-default prefix for devices that may not run Laneway. Remote nodes install that prefix through `lane0` toward the router. Stable v1 supports an explicit forwarding mode:

- `NAT`, the default, requires no route back from the private LAN; or
- `ROUTED`, which requires correct return routing outside Laneway.

Enabling `LANEWAY_SUBNET_ROUTER_V1` MUST be mutual and policy-authorized. Implementations without the capability MUST reject or ignore subnet route activation without treating it as an overlay route.

## 9. Exit routes

Only `0.0.0.0/0` and `::/0` are exit prefixes. Advertising an exit is insufficient: the controller MUST approve the node as an exit and the client MUST explicitly select it. Split tunnel is always the default.

Before installing an exit route, a client MUST install or preserve bypass routes for the relay, controller, exit transport endpoint, and required local network. It MUST have an explicit fail-open or fail-closed setting and MUST NOT change that choice on failure. IPv4 and IPv6 selection are independent; an IPv4-only exit MUST NOT attract IPv6.

An implementation MUST NOT install a default route merely because an exit advertisement exists; explicit local selection remains mandatory.

## 10. ACL interaction

Routing answers where a packet could go; ACL policy answers whether it may go. A packet MUST satisfy both. Route availability MUST NOT imply permission, and an ACL grant MUST NOT synthesize a route. Policy evaluation inputs MUST use authenticated identities and parsed packet attributes, never user-provided node names.

ACL encoding is defined by `policy.proto`. Controller-backed deployments evaluate ordered source identity, destination identity/prefix, IP protocol, and port selectors; absence of an accepting rule means deny. Manual deployments MUST use an equivalently bounded static authorization policy.
