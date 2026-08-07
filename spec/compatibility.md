# Laneway Compatibility Policy

Status: Stable-v1 interoperability and evolution policy.

Normative terms have the meaning defined in BCP 14.

## 1. Compatibility promise

Laneway is a protocol implemented by Go, Rust, and potentially other languages. The compatibility boundary is the documented wire bytes and semantics, not source APIs or implementation behavior.

Laneway v1 is stable. Every wire-affecting change MUST follow the compatible-change rules below and update the relevant specification, schema, capability registry, and golden vectors in the same change. A conforming v1 implementation MUST interoperate with any other conforming v1 implementation for their negotiated feature intersection.

## 2. Version dimensions

Laneway uses separate evolution mechanisms:

- ALPN identifies the transport/application family (`laneway-relay/1`, `laneway-peer/1`, `laneway-fallback/1`, or `laneway-control/1`).
- Control `protocol_major` identifies incompatible control semantics. v1 uses major `1`.
- Control `protocol_minor` identifies backward-compatible additions within a major.
- Capabilities enable optional, independently deployable features.
- The packet header's four-bit version identifies its binary format. v1 uses value `1`.
- Protobuf package `laneway.v1` identifies the stable schema namespace, not a product release number.

Implementations MUST NOT infer one dimension from another. For example, ALPN `/1` does not authorize all capability bits, and control major 1 does not permit an unsupported packet version.

## 3. Compatible changes

Within control major 1, the following changes are compatible when normal Protobuf rules and capability gating are followed:

- adding an optional Protobuf field with a new field number and safe absence semantics;
- adding a message type that older peers are not required to send or understand;
- assigning a previously unassigned capability bit;
- defining behavior gated by a newly assigned capability;
- adding a nonfatal error code that unknown peers may treat as a generic failure; and
- tightening local resource limits while still reporting bounded failure.

A new field MUST define the meaning of absence. Its zero value MUST NOT silently grant authorization, weaken authentication, select full tunnel, or enable a feature. New enum values MUST be handled as unknown by older code and MUST NOT default to an authorization-granting value.

## 4. Incompatible changes

The following require a new control major, packet version, ALPN family revision, or other explicitly negotiated boundary as applicable:

- changing the type, number, encoding, or meaning of an existing Protobuf field incompatibly;
- reusing a removed Protobuf field number or name;
- reassigning a capability bit;
- changing identifier widths or canonical certificate URI semantics;
- changing byte order, size, or meaning of an existing packet-header field;
- treating a previously valid frame as having different forwarding authority;
- weakening mandatory authentication, source validation, or explicit exit selection; or
- requiring peers to understand a formerly optional message without negotiation.

Removed Protobuf fields and enum numbers MUST be marked `reserved` permanently.

## 5. Capability negotiation

An endpoint advertises only capabilities it fully implements and is prepared to use under local policy. The negotiated set is the bitwise intersection of client support, server support, and allowed policy. A capability absent from the negotiated set MUST NOT be used.

Capabilities are positive assertions; there are no implicit capabilities based on product version, implementation language, or node role. Unknown bits MUST be ignored when intersecting and MUST NOT be echoed without independent support. Reserved capability names in the architecture do not permit sending their messages or routes.

Dependencies MUST be stated by each capability. `LANEWAY_QUIC_DATAGRAM_V1` and `LANEWAY_TCP_FALLBACK_V1` packet exchange each require `LANEWAY_RELAY_V1`; a carrier advertises only the transport capability it can use on that connection. `LANEWAY_IPV6_V1` modifies packet and route acceptance but does not by itself create an IPv6 address or route.

## 6. Protobuf rules

All protocol schemas live under `api/proto/laneway/v1/`, outside language-specific trees. Generated code MUST NOT be treated as the specification.

Writers SHOULD produce deterministic encodings for golden vectors, but receivers MUST accept any valid Protobuf encoding. Map ordering and unknown-field ordering MUST NOT be protocol semantics. Implementations MUST use explicit fixed-width or documented varint integer fields and MUST reject overflow when mapping into local types.

Timestamps, when introduced, MUST define epoch, units, range, and clock-skew behavior. Error interoperability MUST use numeric enums, not Go or Rust error strings.

## 7. Binary packet rules

Raw IP packets MUST NOT be encoded in Protobuf. Packet-header integers use network byte order. Reserved v1 flag bits MUST be zero on send and cause v1 rejection when nonzero. A new flag may be introduced only after its semantics and capability/version interaction are specified.

A receiver MUST validate the complete frame rather than relying on struct casts, native alignment, endianness, or pointer width. Implementations SHOULD parse from byte slices with explicit bounds checks.

## 8. Golden vectors

Canonical vectors under `testvectors/` are part of the conformance suite. They MUST cover:

- certificate identity acceptance and rejection;
- canonical ID and URI encodings;
- `Hello`, `Welcome`, errors, and route control frames including exact length prefixes;
- capability intersection and unknown-bit behavior;
- IPv4 and IPv6 packet frames with exact bytes;
- invalid versions, flags, handles, lengths, and addresses; and
- routing prefix canonicalization, longest-prefix and metric selection, ambiguous-tie rejection, and source validation.

Each vector MUST include a machine-readable expected outcome. Positive binary vectors SHOULD state exact bytes; negative vectors SHOULD state the stable error category. Go and every Rust protocol implementation MUST pass the same vectors without language-specific exceptions.

## 9. Interoperability matrix

For each supported negotiated feature set, CI SHOULD exercise at least:

```text
Go node   -> Go relay   -> Go node
Go node   -> Rust relay -> Go node
Rust node -> Go relay   -> Go node
Rust node -> Rust relay -> Rust node
```

Rows involving a feature that one implementation does not advertise are outside that negotiated intersection, not presumed passing. Benchmark superiority does not permit protocol divergence.

## 10. Phase and stability labels

The Phase 0 specifications were the implementation contract for the benchmark and protocol foundation. The stable-v1 gate has now frozen the v1 wire meanings documented here. Documents and schemas MUST state their status. Experimental extensions MUST use separately assigned capability bits or ALPN values and MUST NOT emit incompatible bytes while claiming baseline v1 conformance.

An implementation SHOULD expose its product version, control versions, packet versions, and capability set separately in diagnostics. Product version comparison MUST NOT replace wire negotiation.
