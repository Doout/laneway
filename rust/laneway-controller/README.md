# Rust controller candidate

The Rust controller works with existing Go controller databases and credentials.
Linux evaluation modes support HTTPS enrollment, authenticated QUIC
configuration, certificate renewal and network ACL management. Production
deployments continue to use the Go controller.

```sh
cargo run --manifest-path rust/Cargo.toml -p laneway-controller -- \
  -config /etc/laneway/controller.toml -backup /var/backups/controller.db

cargo run --manifest-path rust/Cargo.toml -p laneway-controller -- \
  -config /etc/laneway/controller.toml -restore /var/backups/controller.db
```

The candidate validates the shared Laneway TOML schema before selecting the
controller database. Serving-process dependencies are exercised separately.
Backup supports schema versions 1 through 10. It checks integrity, foreign keys,
administrator schema fingerprints, and identity-binding invariants, copies
via SQLite's online backup API, then checks the result before publishing it
with mode 0600. SQLite coordinates concurrent operations through its normal
journal locks. Backup can run while the Go controller is serving and does
not acquire its lifecycle lock or migrate the source. The destination
directory must support hard links and directory fsync.

Restore uses the Go controller's Linux `<database>.lock` protocol and publishes
only into a missing destination with no SQLite sidecars. It applies the same
published SQL as Go to a private copy, invalidates administrator sessions and
unconsumed recovery grants, advances the recovery generation, and records the
system restore audit event. The private copy is compacted before publication to remove deleted
credential material from unused pages. Existing administrator passwords and the
root service principal are preserved. The operator must stop the controller
before restore.

Run the focused tests with
`cargo test --manifest-path rust/Cargo.toml -p laneway-controller`. Tests
exercise the published Go migration SQL to detect divergence in the
security-critical schema checks.

For cross-implementation restore tests on Linux, set
`LANEWAY_CONTROLLER_RESTORE_BIN` to the absolute path of the built candidate
and run `go -C go test ./internal/controller -run '^TestRestoreBinaryCompatibility$'`.
The test uses a Go-produced backup with active v8 administrator secrets and
validates the result with Go's current SQLite validator.

On Linux, `-prepare-startup` verifies the administrator token file, the
controller PKI and SPIFFE identity, and the configured network pin before
opening SQLite. It then locks and migrates the database and atomically creates
or adopts the configured initial network and durable identity binding. A
successful repeat validates the same records without issuing duplicate audit
events. This explicit operation may mutate the database. It opens no listeners
and does not validate settings used only by the serving process.

```sh
cargo run --manifest-path rust/Cargo.toml -p laneway-controller -- \
  -config /etc/laneway/controller.toml -prepare-startup
```

On Linux use `LANEWAY_CONTROLLER_STARTUP_BIN` with
`go -C go test ./cmd/laneway-controller -run '^TestStartupPreparationBinaryCompatibility$'`
to exercise the candidate against Go-issued intermediate and controller
certificates and existing Go v9 storage.

The explicit Linux serving candidate exposes the root bearer probe and
read-only network list/get over TLS 1.3 HTTPS. Browser-session and scoped
credentials are rejected. Other route families are unavailable in this mode.
Diagnostics expose process counters over a separate, optional loopback
listener.

```sh
cargo run --manifest-path rust/Cargo.toml -p laneway-controller -- \
  -config /etc/laneway/controller.toml -serve-readonly -diagnostics 127.0.0.1:6060
```

To test the serving slice with the installed protocol, set
`LANEWAY_CONTROLLER_SERVE_BIN` and `LANEWAY_GO_CONFIG_BIN` to absolute paths
to the built candidate and Go CLI. Run
`go -C go test ./cmd/laneway-controller -run '^TestReadonlyServingBinaryCompatibility$'`.

On Linux, `-serve-enrollment-candidate` also enables `POST /v1/enroll`.
It uses the configured issuer and existing Go-issued enrollment tokens. The
candidate verifies the CSR signature and expected class, network and device
name, preserves the WireGuard public key binding, and commits token
consumption, the node, its addresses, certificate, epoch, and audit entries
together. Ephemeral certificates expire no later than the identity lease.
The route applies per-source rate limits and bounds the protobuf body.

The same mode enables root-bearer token issuance at
`POST /v1/admin/enrollment-tokens`. It checks the durable root service
principal inside the issuance transaction, records the actor in audit,
and stores the token hash. Browser and scoped administrator credentials
cannot authorize this route.

Use an isolated copy of a Go controller backup for evaluation.

```sh
cargo run --manifest-path rust/Cargo.toml -p laneway-controller -- \
  -config /path/to/isolated/controller.toml -serve-enrollment-candidate
```

Linux `-serve-controller-candidate` additionally accepts node certificate
renewal over authenticated QUIC and legacy HTTPS. Every renewal checks
the exact issued certificate against durable node and certificate state.
A WireGuard key change commits with the certificate, epoch, and audit
entry. A request that omits its WireGuard key retains the existing
binding. As with Go, the previous certificate remains usable until it
expires or is revoked.

The Linux compatibility check restores a live Go backup, exercises token
issuance, enrollment, replay, and Go and Rust credential renewal over
QUIC. It also renews via legacy HTTPS and confirms Go can renew after
reopening the resulting database:

```sh
python3 integration/controller-enrollment.py \
  --go-controller /path/to/go-controller --candidate /path/to/rust-controller \
  --go-cli /path/to/go-laneway --rust-cli /path/to/rust-laneway
```

The Linux `-serve-controller-candidate` mode retains the candidate HTTPS
management and enrollment endpoints and also starts authenticated QUIC.
QUIC uses the configured `controller.quic_listen` address and requires a
verified node or relay certificate. It supports node and relay configuration
requests, conditional leases, and node renewal. The listener advertises
`QUIC=ADDR` in its startup line.

In this mode, the root bearer can list, create, update and delete network
ACL rules over HTTPS. Mutations commit the rule, configuration epoch and
audit event together. A node with an older epoch receives the updated
policy on refresh. Current-epoch requests receive a bounded lease.

```sh
cargo run --locked --manifest-path rust/Cargo.toml -p laneway-controller -- \
  -config /path/to/isolated/controller.toml -serve-controller-candidate
```

To check the wire contract, set `LANEWAY_GO_CONTROLLER_BIN` and
`LANEWAY_CONTROLLER_QUIC_BIN` to the Go and Rust executable paths, then run
`go -C go test ./cmd/laneway-controller -run '^TestControllerQUICCandidateCompatibility$'`.
