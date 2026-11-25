# Control-plane deployment

The Compose deployment runs the controller and relay as separate non-root
containers. State and public relay certificates survive container replacement;
the offline root CA key does not remain on the server.

## Requirements

- Linux on AMD64 or ARM64
- Docker Engine 26+ with Compose v2
- `age`, `age-keygen`, `awk`, `curl`, `getent`, `jq`, and `ss`
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

`laneway control init` holds the shared lifecycle lock while it validates and
starts the stack. Before opening listeners or reporting healthy, the controller
atomically creates or verifies the configured `[controller.initial_network]`
row and binds it to the network and service identities authenticated from its
certificate. After controller health succeeds, init verifies the exact network
name and IPv4 pool through the controller API, registers or verifies the relay,
then waits for relay health. It never races the controller by creating the same
network through the post-start admin API. Configuration, certificate, `.env`,
or durable identity drift fails closed without overwriting controller state.

## Administrator access

Create the first owner from a terminal on the control-plane host:

```sh
sudo laneway control administrator bootstrap --username owner
```

To recover an existing owner, supply its exact canonical username:

```sh
sudo laneway control administrator recover --username owner
```

Both commands require root and a controlling terminal. They read the new
password and confirmation from `/dev/tty` with terminal echo disabled; stdin is
not used. Passwords, one-use grants, and the root bearer are never accepted in
argv or environment variables and are not printed. Neither command creates a
browser session; sign in normally after it succeeds. Recovery atomically
replaces the password, re-enables the owner, and revokes its prior sessions and
all outstanding administrator recovery grants.

Rotate the static root credential with:

```sh
sudo laneway control administrator root-token rotate
```

The command atomically replaces
`generated/secrets/admin.token` below the deployment directory (normally
`/opt/laneway`), recreates the controller, and
verifies that the new credential is accepted and the old credential is
rejected. Existing file-based automation continues to use the same
`--admin-token-file` path. See the operations guide for interrupted-rotation
recovery.

The browser console supports password-backed administrator sessions only.
OIDC/SAML SSO and SCIM are unavailable and must remain disabled. Never expose
the static root bearer to a browser.

## Update

```sh
sudo laneway update server
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

## Native rootless client and Connector

Install the signed `lanewayd` release as the account that will run it.
Continue to use `laneway control` to administer the controller.
Release assets cover Linux, macOS, and Windows on amd64 and arm64.
The Linux binaries are statically linked with musl. The installation
commands below use GitHub CLI and Cosign. Replace `vX.Y.Z`
with a stable release tag that includes the rootless client.

On Linux and macOS:

```sh
version=vX.Y.Z
gh release download "$version" --repo Doout/laneway --pattern install-node.sh &&
  gh attestation verify install-node.sh --repo Doout/laneway \
    --signer-workflow Doout/laneway/.github/workflows/release.yml --source-ref "refs/tags/$version" &&
  sh ./install-node.sh "$version"
```

Use `$HOME/.local/bin/lanewayd` or add that directory to your PATH.

On Windows, from PowerShell 7:

```powershell
$version = 'vX.Y.Z'
gh release download $version --repo Doout/laneway --pattern install-node.ps1
if ($LASTEXITCODE -ne 0) { throw 'Download failed' }
gh attestation verify install-node.ps1 --repo Doout/laneway `
    --signer-workflow Doout/laneway/.github/workflows/release.yml --source-ref "refs/tags/$version"
if ($LASTEXITCODE -ne 0) { throw 'Provenance verification failed' }
.\install-node.ps1 -Version $version
```

Run `lanewayd.exe` from `%LOCALAPPDATA%\Laneway\bin`, or add
that directory to your user PATH. Each installer verifies the executable
against the checksum manifest signed by the release workflow at the selected
tag before installing it.

After installation, an operator can issue an invite:

```sh
sudo laneway control invite --name laptop --native --remembered
sudo laneway control invite --name office --native --connector
```

Give each recipient their own single-use setup token through a private channel.
On the target, run `laneway configure` and enter the token at its hidden prompt. First setup prints a password for the SOCKS5 username `local`. Run `laneway start` to use the authenticated proxy on `127.0.0.1:1080`. For a connector that only serves assigned routes, use `laneway start --no-proxy`. Apply route approvals
on the controller with `laneway control route add` as for a Docker Connector.

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
running controller. A bundle restores the root bearer captured when it was
created. Immediately rotate that bearer after every restore, then create and
store a fresh encrypted bundle. If suspected credential compromise prompted a
rotation, quarantine and retire every pre-rotation bundle under the applicable
retention policy. Test this procedure before relying on the deployment.
Restored databases that contain the durable controller binding still require
the same certificate network and service identities. A release rollback may
restore a legacy controller configuration without the new initial-network
table; it also restores the protected pre-migration database, so the old image
never receives an unknown config field and the candidate's management changes
are discarded together.

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
