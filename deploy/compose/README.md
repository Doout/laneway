# Control-plane deployment

The Compose deployment runs the Rust controller and relay as separate non-root
containers. The Go operator CLI is a host tool, not a service. State and public relay certificates survive container replacement;
the offline root CA key does not remain on the server.

## Requirements

- Linux on AMD64 or ARM64
- Docker Engine 26+ with Compose v2
- Python 3.11+, OpenSSL, `age`, `age-keygen`, `curl`, `getent`, `jq`, and `ss`
- public DNS for the control-plane host
- inbound TCP+UDP `8443`, UDP `4433`, and TCP `443`

## Install

Prepare DNS and firewall rules, replace the domain, then run:

```sh
export LANEWAY_DOMAIN=lane.example.com; curl -fsSL https://github.com/Doout/laneway/releases/latest/download/install.sh | sudo env LANEWAY_DOMAIN="$LANEWAY_DOMAIN" bash
```

The installer requires a signed release and verifies immutable image digests.
It creates the PKI and configuration, starts Rust on an empty deployment, and
prints the path to the initial encrypted backup and recovery kit. Copy them
off the server and remove the on-host recovery kit after verifying the copy.

Before production traffic:

```sh
sudo laneway-control readiness
sudo laneway-control status
```

The first command is fail-closed. The installer does not change host DNS,
firewall rules, routes, interfaces, or sysctls.

Readiness checks the running Rust image digests, health, authenticated
inventory, and signed bootstrap artifacts served over public HTTPS. Allow
time for the relay to obtain its first public certificate. The installer
keeps the release metadata under `/opt/laneway/release-metadata`.

## Administrator access

Create the first owner from a terminal on the control-plane host:

```sh
sudo laneway-control administrator bootstrap --username owner
```

To recover an existing owner, supply its exact canonical username:

```sh
sudo laneway-control administrator recover --username owner
```

Both commands require root and a controlling terminal. They read the new
password and confirmation from `/dev/tty` with terminal echo disabled; stdin is
not used. Passwords, one-use grants, and the root bearer are never accepted in
argv or environment variables and are not printed. Neither command creates a
browser session; sign in normally after it succeeds. Recovery atomically
replaces the password, re-enables the owner, and revokes its prior sessions and
all outstanding administrator recovery grants.

The browser console supports password-backed administrator sessions only.
OIDC/SAML SSO and SCIM are unavailable and must remain disabled. Never expose
the static root bearer to a browser.

Open the console at `https://lane.example.com/` with no port suffix. The relay
terminates public Web-PKI HTTPS on TCP `443` and carries console and
administrator API requests to the controller over its authenticated internal
connection. TCP+UDP `8443` is the private controller transport for Laneway
identities; ordinary browsers must not connect to it directly.

Do not use the legacy `update`, `upgrade`, or `rollback` commands on a Rust
deployment. They target the Go runtime and refuse to operate here.

## Docker Connector

```sh
sudo laneway-control invite --name office --docker --connector
```

Run the generated command within ten minutes. Its rate-limited URL is consumed
by the first download; later requests return `404`. A one-shot container enrolls
the digest-pinned `lane-edge-rust` image, then a clean runtime container starts
without the setup token, bootstrap key, or temporary mount. On the Connector
host, update it with `sudo laneway-update-connector laneway-connector-office`.

## Backup and restore

Create a recovery bundle and copy it off-host:

```sh
sudo laneway-control backup
sudo ls -l /opt/laneway/generated/recovery/
```

The encrypted bundle contains the database, release selection, service
configuration, online issuer, credentials, and admin token. It does not contain
the offline root key.

Restore is fresh-state only. On a replacement host, install the same signed
release, copy its packaged Compose directory to an empty `/opt/laneway`, then
run:

```sh
sudo /opt/laneway/laneway-control --rust restore /trusted/recovery.age \
  --identity /trusted/laneway-recovery.identity
cd /opt/laneway
sudo sh ./verify-rust-release.sh --install vVERSION /trusted/release-metadata
```

Compare the verified pins with the restored `.env` before starting. Then:

```sh
sudo docker compose --env-file .env -f compose.yaml -f compose.rust.yaml up -d --wait controller relay
sudo ./laneway-control --rust readiness /trusted/release-metadata
```

Transfer the bundle and age identity through separate trusted channels. Restore
refuses existing deployment state, malformed archives, checksum failures, and a
running controller. A bundle restores the root bearer captured when it was
created. Do not restore a bundle containing credentials you suspect were
compromised. Test recovery on a separate host before relying on the deployment.

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
