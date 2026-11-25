# Controller replacement compatibility

The production controller is built from `go/cmd/laneway-controller`. Its
release artifact and the control-plane image must continue to accept the
installed configuration, command line, certificate and key material, and
SQLite volumes.

The Rust candidate implements SQLite online backup, Linux restore, startup validation and migration, HTTPS enrollment, and root-bearer network reads and token issuance. Linux `-serve-controller-candidate` also serves node and relay configuration over mutually authenticated QUIC, certificate renewal over QUIC and HTTPS, and ACL management. Go clients can keep the same certificates, requests and conditional configuration leases. Production packages still start the Go controller. Build the candidate with `cargo build --locked --manifest-path rust/Cargo.toml -p laneway-controller`. See the [candidate commands and verification gates](../rust/laneway-controller/README.md).

| Surface | Required behavior |
| --- | --- |
| Startup | Check the administrator bearer file, CA issuer chain, TLS role, and configured network against the controller certificate before opening or migrating SQLite. Preserve the legacy startup path for installations without an initial-network section. Atomically create or adopt the configured network and bind the verified controller service identity. Restart with the same settings and reject mismatched authority. |
| SQLite | Preserve `schema_versions`, all published migrations and their ordering, SQLite types and constraints, identifier and timestamp encodings, foreign keys, WAL, and immediate transactions. Version 8 is the published administrator foundation. Version 9 hardens administrator state and introduces root-token rotations. Version 10 adds the immutable controller identity binding and its corresponding audit invariant. Preserve transaction boundaries for lease issuance, administrator changes, epochs, and audit. |
| Backup and restore | Keep `-backup` consistent on a live controller, publish to an absent path without overwriting it, and preserve the source schema. The Go restore validator fingerprints administrator DDL and triggers. Keep `-restore` Linux lifecycle locking interoperable on the same `<database>.lock` path. Validate the schema, foreign keys, and controller identity binding. Restore into a missing database only and invalidate administrator session and recovery secrets in the restored copy. |
| Node and relay | Preserve HTTPS enrollment, authenticated protobuf control over QUIC, and snapshot contents, expiration, and conditional refresh. Test existing Go and Rust nodes and relays against the candidate and exercise route, ACL, revocation, and reconnect behavior. |
| Administrator | Preserve the management API paths, response and error envelopes, request IDs, root token rotation, role and network scope enforcement, audit behavior, and browser session cookies, origin checks, and CSRF handling. Validate the client and console over actual HTTPS. |
| Bootstrap, console, and diagnostics | Keep direct public bootstrap metadata separate from relayed one-time bundles. Preserve artifact metadata and relay discovery, browser-compatible console certificate selection, static console hosting, and loopback health and metrics used by the deployment. |
| Release and recovery | Run fresh install, restart, upgrade, and backup/restore rehearsals with the actual image, Compose scripts, health checks, CLI, and web console. Rehearse rollback with the previous image and a pre-upgrade backup when schema versions differ. |

## Executable compatibility check

Build the current executable for a baseline and run the same test with the
absolute path to a replacement binary. The test creates a disposable v9
database and uses the normal controller flags. It checks that a certificate
mismatch leaves the database untouched, then adopts the existing network and
uses the Go management client and a mutually authenticated relay QUIC client.
It exercises a live backup, repeat backup refusal, restart and, on Linux,
restore lock contention and recovery into a fresh database. The Go reference
implementation restores the candidate backup, and the candidate restores a Go
backup.

```sh
test_dir=$(mktemp -d)
go -C go build -o "$test_dir/laneway-controller" ./cmd/laneway-controller
LANEWAY_CONTROLLER_BIN="$test_dir/laneway-controller" \
  go -C go test -count=1 -run '^TestControllerBinaryCompatibility$' -v ./cmd/laneway-controller
```

The existing controller store, HTTP, administrator lifecycle, and privileged
network suites cover the remaining cases. The Rust-controller-node namespace
test currently starts a Go service fixture, so run the production executable
test and real-image workflows independently. See the [integration test
guide](../integration/README.md).
