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
- `age` and `age-keygen` for encrypted recovery bundles
- public DNS for the control host
- inbound TCP+UDP 8443, UDP 4433, and TCP 443
- an offline root and an exported online-intermediate bundle created as
  described below and in [../../docs/operations.md](../../docs/operations.md)

On an offline Linux workstation, create the root and online intermediate. Keep
the entire `offline-root` directory offline and backed up; only the three files
shown in `issuer-export` may be transferred to the control host:

```sh
install -d -m 0700 offline-root issuer-export
laneway pki init --out-dir offline-root --name "Laneway Offline Root"
laneway pki intermediate \
  --ca-cert offline-root/ca.crt --ca-key offline-root/ca.key \
  --out-cert issuer-export/intermediate-chain.crt \
  --out-key issuer-export/intermediate.key
cp offline-root/ca.crt issuer-export/ca.crt
chmod 0400 issuer-export/intermediate.key
test ! -e issuer-export/ca.key
```

After completing `.env`, run `sudo ./lane init --issuer /path/to/issuer-export`.
The command validates that the online key matches an ordered, currently valid
chain anchored by the exact offline root certificate. It generates controller
and relay service identities, strict configurations, and an independent admin
token, publishes them without overwriting, verifies host/DNS/port prerequisites
read-only, verifies signed images, and starts the ready stack. A root private
key or unexpected private key in the export is rejected. Repeating the command
with the same completed material is idempotent; partial generated state is
rejected for manual inspection.

Create the recovery identity on a separate trusted workstation and keep its
private file off the control host. Put the printed public recipient in `.env`
as `LANEWAY_BACKUP_RECIPIENT`:

```sh
age-keygen -o laneway-recovery.identity
age-keygen -y laneway-recovery.identity
chmod 0400 laneway-recovery.identity
```

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
`0700`. The database staging directory is the exception: it is UID 65532-owned
mode `0700`. Encrypted long-term bundles are written to root-owned mode-`0700`
`generated/recovery`, outside the controller's writable mount. Private keys and the
admin token MUST be owned by UID 65532 and mode `0400`. Do not grant another
host account traversal permission. The validator rejects symlinks, incorrect
modes, and incorrectly owned secrets or backups.

```sh
cd deploy/compose
sudo chown root:root . generated generated/pki generated/secrets generated/config
sudo chmod 0700 . generated generated/pki generated/secrets generated/config
sudo install -d -m 0700 generated/backups
sudo chown 65532:65532 generated/backups
sudo ./bootstrap.sh
```

The packaged `./lane` wrapper is the normal operator entry point. `lane init`
performs idempotent validation/bootstrap. `lane status` reports controller,
relay, limiter, optional Exit Node, and live Exit direct-path health, and exits
nonzero for an unhealthy required service. `lane invite --name DEVICE` issues a single-use token
through the isolated admin container. `sudo lane backup [NAME.age]` creates a
complete encrypted recovery bundle, and `sudo lane restore BUNDLE.age
--identity FILE` performs a guarded fresh-state restore as documented below.

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
The image assigns permitted-only `NET_ADMIN` to the node binary, while Docker
bounds the container to that same single capability. The node runs as UID/GID
65532, activates only `NET_ADMIN`, and irreversibly enables
`no-new-privileges` before it initializes networking.
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

Never expose diagnostics ports. Copying a live SQLite file or separately
copying credentials is not a valid recovery procedure. Create a consistent,
encrypted bundle while the controller is running:

```sh
sudo ./lane backup
sudo ls -l generated/recovery/recovery-*.age
```

The command takes an online SQLite snapshot, validates the deployment, bundles
the matching `.env`, strict configuration, online intermediate, service
identities, admin token, and optional Exit identity, hashes every entry, and
encrypts the result to the off-host age recipient. The temporary database
staging area is controller-writable, but the final bundle is a root-owned
mode-`0600` file in `generated/recovery`. It never includes the offline root key
and never overwrites an existing path. Copy completed bundles to separately
controlled storage; do not treat the VPS copy as a backup.

Restore is deliberately fresh-state only. On a replacement host, install the
same signed Laneway release into a deployment directory with no `.env`, no
generated credentials, and an empty controller volume. Transfer one encrypted
bundle plus the age identity through separate trusted channels, then run:

```sh
sudo ./lane restore /trusted/control-recovery.age \
  --identity /trusted/laneway-recovery.identity
sudo ./lane init
```

Restore accepts only the fixed versioned file set, rejects duplicate,
unexpected, non-regular, partial, or checksum-invalid archive entries, restores
the fixed UID/modes, and refuses a running controller, existing deployment
file, symlink, or existing database. On failure, newly published files are
removed. `lane init` then re-verifies immutable image digests and signatures
before starting the ready stack. Neither command changes host firewall rules,
routes, interfaces, or DNS configuration.
