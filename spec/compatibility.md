# Laneway Compatibility Policy

Laneway v1 interoperability is defined by documented wire bytes and semantics,
not source APIs, product versions, implementation languages, or benchmarks. A
conforming implementation MUST interoperate over the negotiated intersection
of v1 features.

Every wire-affecting change MUST update its specification, schema, capability
registry, and golden vectors in the same change.

## Version boundaries

Laneway versions these dimensions independently:

| Dimension | v1 value or purpose |
| --- | --- |
| ALPN | Transport family: `laneway-relay/1`, `laneway-peer/1`, `laneway-fallback/1`, or `laneway-control/1` |
| `protocol_major` | Incompatible control semantics; v1 is `1` |
| `protocol_minor` | Backward-compatible control additions |
| Capabilities | Optional negotiated features |
| Packet version | Four-bit binary-frame version; v1 is `1` |
| Protobuf package | Stable schema namespace `laneway.v1` |

An implementation MUST NOT infer one dimension from another.

## Compatible changes

Within control major 1, a change is compatible when normal Protobuf rules and
capability gating permit it. This includes:

- a new optional field with a new number and safe absence semantics;
- a message older peers need not send or understand;
- an assigned capability bit and behavior gated by it;
- a nonfatal error code unknown peers may treat as generic failure; and
- a tighter local resource limit that still reports bounded failure.

A new field MUST define absence semantics. Absence or a zero value MUST NOT
grant authorization, weaken authentication, select full tunnel, or enable a
feature. Older implementations MUST treat new enum values as unknown, never as
an authorization-granting default.

## Incompatible changes

These changes require a new control major, packet version, ALPN revision, or
another explicit negotiation boundary:

- incompatibly changing an existing Protobuf field's number, type, encoding,
  or meaning;
- reusing a removed Protobuf field number or name;
- reassigning a capability bit;
- changing identifier widths or certificate URI semantics;
- changing an existing packet field's byte order, size, or meaning;
- changing the forwarding authority of a valid frame;
- weakening authentication, source validation, or explicit exit selection; or
- requiring an unnegotiated formerly optional message.

Removed Protobuf fields and enum numbers MUST remain `reserved`.

## Negotiation and encoding

An endpoint MUST advertise only capabilities it implements and local policy
allows. The negotiated set is the bitwise intersection of client support,
server support, and policy. Absent capabilities MUST NOT be used. Unknown bits
MUST be ignored during intersection and MUST NOT be echoed without independent
support. Capability dependencies are defined in
[control-protocol-v1.md](control-protocol-v1.md).

Schemas live under `api/proto/laneway/v1/`; generated code is not the
specification. Vector writers SHOULD use deterministic encodings, but receivers
MUST accept any valid Protobuf encoding. Map and unknown-field ordering are not
protocol semantics. Integer mappings MUST reject overflow. New timestamps MUST
define epoch, unit, range, and clock-skew rules. Interoperable errors MUST use
numeric enums rather than implementation strings.

Raw IP and opaque WireGuard packets MUST NOT be encoded in Protobuf. Binary
packet parsing and evolution follow [packet-format-v1.md](packet-format-v1.md).
`LANEWAY_IPV6_V1` permits IPv6 packet and route processing; negotiation alone
does not assign an address or create a route.

## Conformance

Canonical vectors under `testvectors/` MUST have machine-readable outcomes and
cover identity, control framing, capability negotiation, packet bytes and
rejections, and route selection and validation. Positive binary vectors SHOULD
state exact bytes; negative vectors SHOULD state a stable error category. Every
protocol implementation MUST pass the same vectors without language-specific
exceptions.

Experimental extensions MUST use assigned capabilities or ALPN values and MUST
NOT emit incompatible bytes while claiming v1 conformance. Product version
comparison MUST NOT replace wire negotiation.
