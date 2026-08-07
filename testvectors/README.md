# Laneway golden vectors

This directory is the language-neutral stable-v1 conformance corpus, originally
introduced for the Phase 0 completion gate. `manifest.json` is the authoritative
index. Each entry names a fixture, its representation,
expected result, byte length (after decoding when applicable), and SHA-256 digest
of the file as stored. Paths are relative to this directory.

Hex fixtures contain ASCII hexadecimal with optional ASCII whitespace. Consumers
must remove whitespace and decode pairs of hex digits. JSON fixtures are UTF-8
and their semantics are described by `kind` and `expected` in the manifest.

The Protobuf bytes are canonical examples, not a requirement that implementations
re-encode unknown fields or map entries byte-for-byte. Decoders must accept valid
Protobuf encodings. The four-byte control frame length and all packet-header
integers are unsigned, network byte order.

The stable corpus includes positive IPv4 and IPv6 packet frames, exact header
and family-boundary cases, Hello, Welcome, protocol-error and version/capability
negotiation cases, a direct-path probe, and a TLS/TCP fallback record. The
negative and semantic tables cover malformed IP lengths, reserved packet bits,
identity, IPv4/IPv6 routing, deterministic ties, and source ownership.
Implementations may support only a negotiated subset (for example IPv4-only),
but their parsers preserve the specified version and capability boundaries.

The route corpus includes a `NodeConfiguration` carrying the canonical overlay
route snapshot inside a `ControllerEnvelope`, with its exact four-byte
big-endian control-frame length prefix. Both language suites decode the frame
through their bounded production framer before validating the route semantics.

For relay packet v1, the high nibble of the first byte is the version and the low
nibble contains flags. Version 1 with no flags is therefore `0x10`; it is
followed by the four-byte route handle and the complete raw IP packet. Version 1
with flag bit 0 is `0x11` and carries one structurally validated, opaque
WireGuard UDP message. Shared vectors cover both forms.

Certificate identity cases include both declarative URI/claim decisions and
actual DER leaf certificates consumed by the production Go and Rust X.509/SAN
parsers. They cover unrelated SANs, node and service roles, missing identity,
ambiguous multiple identities, malformed canonical IDs, and invalid DER. Chain,
validity, and EKU checks remain the TLS layer's responsibility and are exercised
with ephemeral integration PKI. No private keys are committed.

When adding or changing a fixture, update its digest in `manifest.json`. The
manifest does not hash itself.
