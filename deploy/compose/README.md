# Hardened control-plane Compose stack

This stack runs the controller, relay, and opt-in administrative CLI as separate
non-root containers. Controller state survives container recreation in the
`laneway-controller-state` volume. The root CA private key must never be copied
to this directory or VPS.

Published releases use the pinned images in `compose.yaml`. Until those images
are published, developers can add `-f compose.dev.yaml` to build equivalent
images from this checkout.

## Prerequisites

- Docker Engine 26 or newer with Compose v2
- public DNS for the control host
- inbound TCP+UDP 8443, UDP 4433, and TCP 443
- an offline root, an online intermediate, and service identities created as
  described in [../../docs/operations.md](../../docs/operations.md)

Copy `.env.example` to `.env` and pin a release. Download that release's
`image-digests.txt`, verify the release as described below, and copy each
service's immutable `sha256:` manifest digest into `.env`. Compose retains the
semantic version for readability but pulls and runs only the exact signed
multi-architecture manifest named by the digest. Set `LANEWAY_BIND_ADDRESS` to
the public service address; use `127.0.0.1` for local-only validation. The published-port defaults are
controller TCP+UDP 8443, relay UDP 4433, and relay fallback TCP 443; change them
only when DNS/firewall/bootstrap metadata use the same values. Set
`LANEWAY_CONTROLLER_SERVER_NAME` to a DNS SAN in the controller certificate; the
readiness probe verifies that identity. Create the `generated/config`,
`generated/pki`, `generated/secrets`, and `generated/backups` directories. Copy
the example TOML files without their `.example` suffix, replace every
`REPLACE_...` value, and install only these files:

| Path | Mode | Content |
| --- | --- | --- |
| `generated/pki/ca.crt` | `0444` | offline root public certificate |
| `generated/pki/intermediate-chain.crt` | `0444` | online intermediate followed by root |
| `generated/pki/intermediate.key` | `0400` | online intermediate private key |
| `generated/pki/controller.{crt,key}` | `0444`,`0400` | controller identity |
| `generated/pki/relay.{crt,key}` | `0444`,`0400` | relay identity |
| `generated/pki/exit-node.{crt,key}` | `0444`,`0400` | optional Exit Node identity |
| `generated/secrets/admin.token` | `0400` | independent random bearer secret, at least 32 characters |
| `generated/config/*.toml` | `0444` | strict service configuration |

Public certificates and configurations are world-readable *inside the dedicated
deployment directory* because the fixed container UID must read bind mounts;
the deployment and generated configuration directories MUST be root-owned mode
`0700`. The backup directory is the exception: it is UID 65532-owned mode
`0700`, and each snapshot is UID 65532-owned mode `0600`. Private keys and the
admin token MUST be owned by UID 65532 and mode `0400`. Do not grant another
host account traversal permission. The validator rejects symlinks, incorrect
modes, and incorrectly owned secrets or backups.

```sh
cd deploy/compose
sudo chown root:root . generated generated/pki generated/secrets generated/config
sudo chmod 0700 . generated generated/pki generated/secrets generated/config
sudo install -d -m 0700 -o 65532 -g 65532 generated/backups
sudo ./bootstrap.sh
```

The packaged `./lane` wrapper is the normal operator entry point. `lane init`
performs the same idempotent validation/bootstrap, `lane status` reports the
Compose health state, and `lane invite --name DEVICE` issues a single-use token
through the isolated admin container. `lane backup [NAME.db]` and
`lane restore NAME.db` use the guarded database maintenance modes documented
below.

For an upgrade, prepare a complete candidate environment file with the new
semantic version and four signed manifest digests, leaving deployment identity
and endpoint values unchanged, then run `sudo ./lane upgrade CANDIDATE.env`.
The wrapper validates Compose, verifies every image with Cosign against the
tagged release workflow identity, pulls all images, takes a database backup,
and only then gracefully stops and recreates the stack. If readiness fails, it
restores the prior image/config selection and restarts it; database state is
never independently rolled back. `sudo ./lane rollback` applies the same
verification and backup sequence to the previously successful selection.
Runtime rollback metadata is private under `generated/lifecycle` and never
contains PKI keys or the admin token.

Before the first pull or an upgrade, verify the checksum signature, artifact
provenance, and image signatures. Replace `VERSION` and each digest with the
values from the release; do not verify a mutable tag:

```sh
cosign verify-blob \
  --bundle checksums.sigstore.json \
  --certificate-identity "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/vVERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check checksums.txt
gh attestation verify laneway_linux_amd64.tar.gz --repo Doout/laneway
cosign verify \
  --certificate-identity "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/vVERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/doout/laneway-controller@sha256:REPLACE_DIGEST
```

Repeat the image verification for relay, admin, and Exit Node. The release also
contains an SPDX JSON SBOM for each binary archive and image. A tag whose
signature identity, provenance repository, checksum, digest, or SBOM does not
match must be rejected before `docker compose pull`.

For a source build, replace the last two commands with:

```sh
sudo docker compose -f compose.yaml -f compose.dev.yaml build controller relay admin
sudo ./bootstrap.sh --dev
```

Docker's service health is a local listener-readiness check. End-to-end
readiness additionally requires registering the relay identity with the
controller and successfully fetching its initial authorization snapshot. Use
the `admin` tools profile for administrative commands; it is not a long-running
service:

```sh
sudo docker compose --profile tools run --rm admin version
```

## Isolated Exit Node profile

The optional `exit-node` profile runs the node dataplane in Docker's bridge
network namespace. It is not privileged and does not use host networking. Its
only added capability is `NET_ADMIN`, and its only device is `/dev/net/tun`.
The entrypoint uses one-shot `SETUID`, `SETGID`, and `SETPCAP` bootstrap
capabilities to become UID/GID 65532, reduce its bounding set to `NET_ADMIN`,
enable `no-new-privileges`, and only then start the minimal init and daemon.
The long-running process and the networking tools it invokes therefore have
only `NET_ADMIN`; the health check has no effective capability.
The root filesystem is read-only; `/var/lib/laneway` is the named persistent
state volume and `/run/laneway` plus `/tmp` are size-bounded tmpfs mounts. Laneway's
TUN, policy routes, forwarding sysctls, and nftables table therefore remain in
the container namespace and cannot alter the host ruleset.

Issue an ordinary controller-authorized node identity with Exit capability,
install its certificate/key using the modes above, and copy
`generated/config/exit-node.toml.example` to `exit-node.toml`. Replace every
identity and DNS placeholder, then validate and start only that profile:

```sh
sudo ./validate.sh
sudo docker compose --profile exit-node up -d --wait exit-node
```

The container publishes fixed UDP port `LANEWAY_EXIT_DIRECT_PORT` (4434 by
default) for direct rendezvous. Its `lane0` MTU is 1200, leaving conservative
headroom for the TUN, encrypted overlay, and Docker bridge. IPv4 and IPv6
forwarding are enabled only in the container namespace; IPv6 exit service is
effective only when the controller authorizes an IPv6 default and the Docker
network has IPv6 egress. Without both, IPv6 fails closed.

Bridge mode usually applies Laneway masquerade in the container and Docker
masquerade on the host. This double NAT is deliberate isolation but makes
inbound Internet connections unsuitable and adds modest conntrack overhead.
Use routed Docker networking only as an operator-reviewed deployment variant.
Graceful stop restores the owned nftables table and routes before exit; after
an abrupt stop Docker destroys the namespace, so no Laneway network state can
remain on the host. The persistent volume contains only credentials-independent
runtime state and may be retained across container recreation.

Never expose diagnostics ports. Copying a live SQLite file is not a valid
backup. Create a consistent, private snapshot while the controller is running:

```sh
backup="controller-$(date -u +%Y%m%dT%H%M%SZ).db"
sudo docker compose run --rm --no-deps controller \
  -config /etc/laneway/controller.toml -backup "/backups/$backup"
sudo test "$(stat -c %a "generated/backups/$backup")" = 600
```

The command validates SQLite integrity, foreign keys, and schema before it
atomically publishes the backup. It never overwrites an existing path. Preserve
the matching `.env` and `generated/config`, `generated/pki`, and
`generated/secrets` directories through an encrypted offline backup; they are
not bundled with the database because that would place private keys beside an
online snapshot.

Restore is deliberately fresh-state only. On a replacement host, install the
matching configuration and secrets, leave the controller volume empty, copy the
database backup to `generated/backups`, then run:

```sh
backup=controller-YYYYmmddTHHMMSSZ.db
sudo ./validate.sh
sudo docker compose run --rm --no-deps controller \
  -config /etc/laneway/controller.toml -restore "/backups/$backup"
sudo docker compose up -d --wait controller relay
```

Restore validates the source and refuses to replace an existing database. This
prevents an operator typo from mutating a running deployment. Host firewall
rules remain operator-owned and are intentionally not modified by Compose.
