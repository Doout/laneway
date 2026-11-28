# Laneway runtime and releases

The Laneway runtime is built from the [Rust workspace](https://github.com/Doout/laneway/blob/main/rust/README.md).
Linux and macOS use the signed `laneway` client archive. The same node runtime
runs rootless or manages system networking when explicitly configured to do
so. A client install does not start a tunnel or enable a service.

## Choose a deployment

| Deployment | Starting point |
| --- | --- |
| Rootless Linux or macOS client | [Loopback SOCKS5 setup](rootless.md) |
| System client on Linux or macOS | [System tunnel quick start](../README.md#3-enroll-a-client) |
| Managed Linux host node | [Managed nodes and service operations](operations.md) |
| Control plane, Docker Connector, or durable Exit Node | [Compose deployment and recovery](https://github.com/Doout/laneway/blob/main/deploy/compose/README.md) |
| Multiple tenants on one controller and relay | [Shared control plane](https://github.com/Doout/laneway/blob/main/docs/shared-tenant-control-plane.md) |
| Temporary Exit Node on a shared Linux host | [Ephemeral Exit deployment](ephemeral-shared-host-exit.md) |
| Docker network driver | [Managed plugin](https://github.com/Doout/laneway/blob/main/deploy/docker-plugin/README.md) |

Fresh control-plane deployments use the signed `console`, `relay`, and
`edge` images under `ghcr.io/doout/laneway`. Console includes the management
API and web UI. Edge defaults to Connector mode and also contains the
administration CLI and the durable Exit Node runtime. The Compose Exit Node
profile grants TUN and network administration in the container namespace.

## Release checks

The release workflow builds native AMD64 and ARM64 artifacts. It scans and
signs images by digest and checks the signed Linux installation on disposable
infrastructure. The installation gate exercises HTTPS discovery, Connector
enrollment and restart, approved Exit Node forwarding and NAT, and encrypted
backup and restore into a separate volume.

Pin a signed tag with `LANEWAY_VERSION` when deploying a prerelease or selecting
an exact version. Before promoting it, rehearse upgrade and recovery with the
same OS and service manager as production. Verify client traffic and identity
renewal, then restore a backup into an empty volume. Only one controller
should write to a given database.

## Existing deployments

Current tooling recognizes older signed image names and preserves supported
on-disk configuration, identities, and protocol formats. Refresh the
[Compose deployment files](https://github.com/Doout/laneway/blob/main/deploy/compose/README.md#docker-connector)
from a verified package before upgrading across the image rename. Keep the
old signed release and a tested recovery copy until the new deployment is
healthy. Changes to a shared tenant manifest require the shared deployment
procedure.

The durable Exit Node still reads its installed `exit-node.toml`. Connector
updates keep the existing identity volume. The updater verifies the signed
manifest and image, checks the volume read-only, and expects the same
network and node identities and a current controller lease after restart.

## Managed update timer

Linux packages ship the opt-in `laneway-rust-updater.timer` and
`examples/managed-updates-rust.toml`. The updater can service a managed
`lanewayd-rs.service` installation or a standard durable Docker Connector.
Its configuration and trust roots must be root-owned and protected from
daemon writes. Follow the example to pin the controller identity.
Installing the package does not enable the updater.

The controller supplies a release tag. The updater verifies that release,
preserves node identity, and verifies authenticated health before accepting
activation. A failed activation restores the previous runtime. Before
enabling the timer, verify activation and rollback in an isolated deployment.
