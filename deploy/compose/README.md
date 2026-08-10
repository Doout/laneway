# Hardened control-plane Compose stack

This stack runs the controller, relay, and opt-in administrative CLI as separate
non-root containers. Controller state survives container recreation in the
`laneway-controller-state` volume. The root CA private key must never be copied
to this directory or VPS.

Published releases use the pinned images in `compose.yaml`. Until those images
are published, developers can add `-f compose.dev.yaml` to build equivalent
images from this checkout.

## Quick install, explicit production check

Prepare public DNS, then run the interactive installer from the signed Laneway
package:

```sh
sudo /usr/local/share/laneway/deploy/compose/install-control-plane.sh
```

On a fresh host, the top-level installer installs the selected signed package
and launches the same wizard in one flow:

```sh
curl -fsSLO https://raw.githubusercontent.com/Doout/laneway/main/install.sh
less install.sh
sudo sh install.sh --control-plane
```

To update an existing control plane to the latest stable release:

```sh
sudo laneway control update
```

This detects the Docker Compose installation, downloads and verifies the signed
latest stable package, refreshes `laneway-control`, and upgrades only the
release-selected containers. It preserves deployment identity, PKI, state,
endpoints, firewall rules, and host networking, and it uses the normal encrypted
backup, readiness, and rollback sequence. Unsupported installation types fail
without making deployment changes.

The convenience path generates a recovery identity, an offline root in memory-only
temporary storage, and an online intermediate. It encrypts the offline root,
deploys only the online intermediate, takes an initial encrypted recovery
backup, and leaves one mode-`0700` recovery-kit directory. Copy that entire
directory off the server, verify it, and remove the server copy. The running
control plane never retains the offline root key or recovery identity. Use the
separate-host path below when the production host must never observe the root
key or recovery identity, even transiently during setup.

The wizard also downloads the release's image manifest, attempts to verify every
immutable image against the tagged GitHub Actions signing identity, generates
independent service IDs, writes the protected `.env`, and runs `lane init`.
Hashes remain in the generated file so later starts cannot silently follow a
moved registry tag; operators only select the semantic release tag.

The default `quick` profile continues with a prominent warning if Sigstore or a
registry signature endpoint is temporarily unavailable. It generates
`/opt/laneway/PRODUCTION-CHECKLIST.md`. Before production traffic, complete that
checklist and run:

```sh
sudo laneway control production-check
```

That command is fail-closed: it verifies every image signature, configuration,
DNS/preflight state, required service health, and the presence of an encrypted
recovery backup. Success creates a root-only
`generated/lifecycle/production-verified` marker. To require the same strict
signature behavior during the initial install, use
`sudo sh install.sh --control-plane --production`.

Defaults cover the usual production ports, public binding, network name, and
overlay pool. Before confirmation, the wizard shows every listener it will
publish. It does not configure or modify the host firewall, routes, interfaces,
DNS, or sysctls. Validated non-secret answers are remembered in the root-owned,
mode-`0600` `/var/lib/laneway-installer/control-plane.answers`, so a failed or
cancelled attempt does not require retyping the domain, paths, pool, or ports.
The file never contains a recovery identity, CA private key, admin token, or
generated deployment secret. Explicit environment variables override it.

## One-command Docker Connector

Generate a role-bound, single-use Docker command from the control plane:

```sh
sudo laneway-control invite --name egress-one --docker --connector
```

Invitation issuance uses the signed Laneway CLI already installed on the host;
it does not pull or start the optional administrative container. Copy the
resulting `docker run` command through a trusted administrative channel and run
it as root on a Linux Docker host. The command exposes only one `SETUP_TOKEN`
environment variable. That versioned capsule carries public endpoint and
identity pins plus a short-lived, one-time enrollment code; it is compact, not
encrypted from a Docker administrator. It grants only the Connector role and
an approved IPv4 default route and never contains the control-plane admin token.

The digest-pinned Connector runs as UID/GID 65532 with every Linux capability
dropped, container-level `no-new-privileges`, a read-only root filesystem, no
TUN device, no forwarding sysctl, and no published port. It proxies only
controller-authorized TCP and UDP flows using ordinary outbound host sockets,
so it requires no inbound firewall opening. Use the separate full Exit Node
profile for raw IP forwarding, ICMP, or full-tunnel egress.

The durable Connector identity is stored in a named Docker volume, so replacing
the container during an image upgrade does not enroll it again. `SETUP_TOKEN`
remains visible in Docker metadata, but its enrollment code is invalid after
successful first use. Treat Docker access as root-equivalent regardless.

To upgrade, pull the new digest-pinned Connector image, remove only the old
container, and rerun the generated `docker run` command with the new image
reference and the same `laneway-connector-NAME-state` volume. The entrypoint
finds the complete identity in that volume and ignores `SETUP_TOKEN`; no new
enrollment occurs. Never remove the named volume during an ordinary upgrade.

The packaged updater automates that replacement, verifies the latest stable
release and Connector image with Cosign, waits for health, and restores the old
container automatically if the replacement fails:

```sh
sudo laneway-update-connector laneway-connector-egress-one
```

It is idempotent and safe to invoke periodically. For example, after reviewing
the installed script, root's crontab can check hourly without restarting a
current Connector:

```cron
17 * * * * /usr/local/sbin/laneway-update-connector laneway-connector-egress-one >>/var/log/laneway-connector-update.log 2>&1
```

After the Connector enrolls, assign a reachable private destination without
copying credentials or route IDs between hosts:

```sh
sudo laneway control route add --connector ibmcloud --to 10.240.64.6 --allow laptop
```

The operation is idempotent and accepts either a single IP or a canonical CIDR.
It preserves existing Connector capabilities, approves the route, and creates
a destination-scoped user authorization. Omit `--allow` only when every
enrolled user should reach the destination.

## Local-user login tokens

Issue a short-lived, single-use token for a remembered local user:

```sh
sudo laneway control user-token --name laptop
```

The user runs `laneway login DOMAIN` once and `laneway connect` after that. If
several logins are saved, use `laneway connect DOMAIN` to select one. The token
is exchanged for a locally protected, renewable mTLS identity;
it is not stored as a permanent bearer credential. Remembered connections
install only controller-policy-authorized private prefixes. Default-route
egress remains explicit with `--exit`.

Omit `--ephemeral` for a persistent production Exit Node; use ephemeral
enrollment for tests or intentionally short-lived egress capacity.

## Prerequisites

- Docker Engine 26 or newer with Compose v2
- `age` and `age-keygen` for encrypted recovery bundles
- Cosign is optional on the host; the top-level installer uses a checksum-pinned
  Cosign 3.1.3 verifier when the host copy is missing or incompatible
- `curl`, `getent`, and `ss` for downloads and read-only preflight checks
- public DNS for the control host
- inbound TCP+UDP 8443, UDP 4433, and TCP 443

TCP 443 serves both relay fallback and the public bootstrap document by TLS
ALPN. The relay obtains and renews the public certificate automatically with
ACME TLS-ALPN validation and stores it in the persistent
`laneway-relay-public-certs` volume. No additional port or manually copied
certificate is required. The discovery handler is rate-limited globally and
by source network; an IP is temporarily promoted only after authenticated
Laneway mutual TLS succeeds.

## Separate-host preparation

For the strongest offline-root boundary, run the signed preparation flow on a
separate trusted Linux host that has `age`, `age-keygen`, and Cosign:

```sh
curl -fsSLO https://raw.githubusercontent.com/Doout/laneway/main/install.sh
less install.sh
sudo sh install.sh --prepare-control-plane
```

It creates one protected recovery kit with two categories of material:

- `laneway-recovery.identity` and `offline-root.tar.age` stay on the trusted
  host and are backed up;
- only `control-plane-input/` is copied to the production server.

Run the normal `--control-plane` installer on production and enter the copied
directory at the optional prepared-input prompt. The recovery recipient is
loaded automatically. After deployment, copy the initial encrypted recovery
bundle shown by the installer back to the recovery kit, then delete the
production copy of `control-plane-input`.

## Manual issuer preparation

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

After completing `.env`, run `sudo laneway control init --issuer /path/to/issuer-export`.
The command validates that the online key matches an ordered, currently valid
chain anchored by the exact offline root certificate. It generates controller
and relay service identities, strict configurations, and an independent admin
token, publishes them without overwriting, verifies host/DNS/port prerequisites
read-only, verifies signed images, and starts the ready stack. A root private
key or unexpected private key in the export is rejected. Repeating the command
with the same completed material is idempotent; partial generated state is
rejected for manual inspection.

For a fully manual import, create the recovery identity on a separate trusted
workstation and keep its private file off the control host. Put the printed
public recipient in `.env` as `LANEWAY_BACKUP_RECIPIENT`:

```sh
age-keygen -o laneway-recovery.identity
age-keygen -y laneway-recovery.identity
chmod 0400 laneway-recovery.identity
```

For manual installation, copy `.env.example` to `.env` and pin a release.
Download that release's `image-digests.txt`, verify the release as described
below, and copy each service's immutable `sha256:` manifest digest into `.env`.
The quick installer performs these steps automatically. Compose retains the
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

The `laneway-control` command is the normal operator entry point.
`laneway-control init` performs idempotent validation/bootstrap.
`laneway-control status` reports controller, relay, limiter, optional Exit Node,
and live Exit direct-path health, and exits nonzero for an unhealthy required
service. `laneway-control invite --name DEVICE` uses the installed CLI to issue
a single-use token without starting an administrative container.
`sudo laneway-control backup [NAME.age]` creates a complete encrypted recovery
bundle, and `sudo laneway-control restore BUNDLE.age --identity FILE` performs a
guarded fresh-state restore as documented below.

For an upgrade, prepare a complete candidate environment file with the new
semantic version and four signed manifest digests, leaving deployment identity
and endpoint values unchanged, then run
`sudo laneway-control upgrade CANDIDATE.env`.
The wrapper validates Compose, verifies every image with Cosign against the
tagged release workflow identity, pulls all images, takes a database backup,
and only then gracefully stops and recreates the stack. If readiness fails, it
restores the prior image/config selection and restarts it; database state is
never independently rolled back. `sudo laneway control rollback` applies the same
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
The non-root launcher alone receives `NET_ADMIN` from the image, while Docker
bounds the container to that same single capability. It raises `NET_ADMIN`
into the inheritable and ambient sets, irreversibly enables
`no-new-privileges`, and only then starts the minimal init and Go runtime as
UID/GID 65532.
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
sudo laneway control backup
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
sudo laneway control restore /trusted/control-recovery.age \
  --identity /trusted/laneway-recovery.identity
sudo laneway control init
```

Restore accepts only the fixed versioned file set, rejects duplicate,
unexpected, non-regular, partial, or checksum-invalid archive entries, restores
the fixed UID/modes, and refuses a running controller, existing deployment
file, symlink, or existing database. On failure, newly published files are
removed. `lane init` then re-verifies immutable image digests and signatures
before starting the ready stack. Neither command changes host firewall rules,
routes, interfaces, or DNS configuration.
