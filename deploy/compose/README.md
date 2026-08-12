# Control-plane deployment

The Compose deployment runs the controller and relay as separate non-root
containers. State and public relay certificates survive container replacement;
the offline root CA key does not remain on the server.

## Requirements

- Linux on AMD64 or ARM64
- Docker Engine 26+ with Compose v2
- `age`, `age-keygen`, `curl`, `getent`, `jq`, and `ss`
- public DNS for the control-plane host
- inbound TCP+UDP `8443`, UDP `4433`, and TCP `443`

## Install

Prepare DNS and firewall rules, replace the domain, then run:

```sh
export LANEWAY_DOMAIN=lane.example.com; curl -fsSL https://github.com/Doout/laneway/releases/latest/download/install.sh | sudo env LANEWAY_DOMAIN="$LANEWAY_DOMAIN" bash
```

The installer verifies a stable release and pinned images, creates the PKI and
configuration, starts the stack, and prints a recovery-kit path. Copy that
directory off the server and remove the server copy after verifying it.

Before production traffic:

```sh
sudo laneway control production-check
sudo laneway control status
```

The first command is fail-closed. The installer does not change host DNS,
firewall rules, routes, interfaces, or sysctls.

## Update

```sh
sudo laneway control update
```

The updater verifies the release, takes an encrypted backup and a root-only
database snapshot after quiescing the controller, then replaces the containers
with health checks.
If candidate startup fails after a database migration, it restores the prior
image and configuration, replaces only the managed controller-state volume,
and restores the snapshot through the prior controller image before restarting
the stack. After a verified start, the snapshot is retained with the prior
image and configuration as one checksummed release generation under the
root-only lifecycle directory. A later explicit rollback restores that
point-in-time database and therefore discards management changes made after the
upgrade. An incomplete automatic recovery retains its protected source
snapshot and reports the path. Deployment identity, PKI, endpoints, and host
networking remain unchanged.

## Docker Connector

```sh
sudo laneway control invite --name office --docker --connector --bootstrap
```

Run the generated command within ten minutes. Its rate-limited URL is consumed
by the first download; later requests return `404`. A one-shot container enrolls
the digest-pinned scratch `lane-edge` image, then a clean runtime container starts
without the setup token, bootstrap key, or temporary mount.

## Backup and restore

Create a recovery bundle and copy it off-host:

```sh
sudo laneway control backup
sudo ls -l /opt/laneway/generated/recovery/
```

The encrypted bundle contains the database, release selection, service
configuration, online issuer, credentials, and admin token. It does not contain
the offline root key.

Restore is fresh-state only. On a replacement host, install the same signed
release, copy its packaged Compose directory to an empty `/opt/laneway`, then
run:

```sh
sudo /opt/laneway/laneway-control restore /trusted/recovery.age \
  --identity /trusted/laneway-recovery.identity
sudo /opt/laneway/laneway-control init
```

Transfer the bundle and age identity through separate trusted channels. Restore
refuses existing deployment state, malformed archives, checksum failures, and a
running controller. Test this procedure before relying on the deployment.

## Prepare keys on another host

To keep the root key and recovery identity entirely off production, run on a
trusted Linux host:

```sh
curl -fsSL https://github.com/Doout/laneway/releases/latest/download/install.sh | \
  sudo env LANEWAY_NONINTERACTIVE=true sh -s -- --prepare-control-plane
```

Back up `laneway-recovery.identity` and `offline-root.tar.age`. Copy only the
generated `control-plane-input/` directory to production and pass its path as
`LANEWAY_PREPARED_INPUT_DIR` when installing the control plane.

For actor privileges and the optional full Exit Node profile, see the
[deployment contract](../../spec/deployment-contract.md). For daily operation,
see the [operations guide](../../docs/operations.md).
