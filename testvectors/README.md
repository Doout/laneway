# Golden vectors

`manifest.json` indexes the language-neutral v1 fixtures and records each
file's representation, expected result, decoded length where applicable, and
SHA-256 digest.

- Hex fixtures are ASCII hex with optional whitespace.
- JSON fixtures use the manifest's `kind` and `expected` fields.
- Protobuf fixtures are examples; decoders must accept any valid encoding.
- Frame lengths and packet-header integers use network byte order.

Go and Rust tests consume the same packet, identity, control, routing, and
invalid-input corpus. Packet byte `0x10` starts a raw IP frame and `0x11` an
opaque WireGuard frame; both are followed by a four-byte route handle.

After changing a fixture, update its digest in `manifest.json`. The manifest
does not hash itself. Never add private keys.
