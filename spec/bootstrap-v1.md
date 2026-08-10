# Laneway Bootstrap v1

## Discovery

A client MUST fetch `/.well-known/laneway/bootstrap.json` from a canonical DNS
HTTPS origin using TLS 1.3, hostname validation, and public Web PKI roots. It
MUST reject IP authorities, redirects, credentials, alternate paths, unknown
JSON fields, trailing JSON, non-JSON content, and documents larger than 256
KiB. The public listener MUST NOT expose enrollment, administration, or node
control operations.

The authenticated document pins the private controller HTTPS origin, QUIC
endpoint, optional DNS name, NetworkID, controller ServiceID, CA bundle,
enabled relay endpoints and ServiceIDs, protocol versions, capabilities, and
release artifacts. Private controller connections MUST validate the discovered
CA, configured DNS name when present, controller role, NetworkID, and ServiceID.
DNS resolution does not establish identity.

## Freshness and bounds

- `schema_version` MUST equal `1`.
- The interval from `generated_at_unix_seconds` to
  `valid_until_unix_seconds` MUST NOT exceed ten minutes.
- Clients MUST allow no more than two minutes of positive clock skew and MUST
  reject expired documents.
- A document contains 1..32 unique enabled relays and 1..16 unique artifact
  platforms.
- IDs are canonical, nonzero, 128-bit lowercase hexadecimal values.

Each artifact specifies `os`, `arch`, an HTTPS URL, an exact size from 1 byte
through 512 MiB, and a canonical lowercase SHA-256 digest. Stable v1 requires
Linux AMD64 and ARM64 artifacts and MAY include macOS AMD64 and ARM64 clients.
A downloader consuming this metadata MUST reject short or excess data and
digest mismatches before extraction or privileged use.

## Enrollment

An invitation is a cryptographically random enrollment secret. Its NetworkID,
enrollment class, expiry, optional device name, and ephemeral session lifetime
are immutable. The controller stores only its SHA-256 hash and consumes it
atomically with node identity, address, and certificate creation. Product
invitations default to ten minutes and MUST NOT exceed one hour.

Interactive clients MUST read invitations from a controlling terminal with
echo disabled. They MUST NOT accept them in argv, URLs, bootstrap metadata,
logs, or diagnostics. Automation MAY use a protected regular file.

The client sends `expected_network_id` from the bootstrap document. The
controller MUST compare it with the invitation's NetworkID; a mismatch fails
before consumption with a permission error. A product invitation binds
`requested_name`: omission selects the bound name, while a different name fails
before consumption. Advanced tokens MAY be name-unbound.

The enrollment endpoint MUST apply a bounded per-source rate limit using the
transport peer address, not forwarding headers. Invalid, expired, replayed,
wrong-network, and throttled requests MUST NOT issue credentials. A request
MUST NOT select or upgrade the token's durable, ephemeral, or remembered class.
