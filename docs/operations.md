# Operations

Use the [root README](../README.md) for first-time setup and the
[Compose guide](../deploy/compose/README.md) for deployment and recovery.

## Boundaries

| Component | Listener | Host access |
| --- | --- | --- |
| Relay | UDP `4433`; TCP `443` fallback | Public; no network-admin capability |
| Controller | TCP+UDP `8443` | No network-admin capability |
| Docker Connector | None | Outbound only; no capabilities or TUN |
| Host Node | `/run/laneway/lanewayd.sock` | `/dev/net/tun` and `NET_ADMIN` |
| Diagnostics | Disabled | Loopback only |

Keep service keys private and keep the offline root CA key and recovery identity
off the control-plane host. Laneway does not manage the host firewall.

## Routine control-plane work

```sh
sudo laneway control status
sudo laneway control update
sudo laneway control backup
```

`status` exits nonzero when a required service is unhealthy. `update` verifies
the release, creates a backup, and retains the prior release for rollback.

Connector identities persist in named Docker volumes. Do not remove the volume
during an upgrade. Update a Connector with:

```sh
sudo laneway-update-connector laneway-connector-office
```

## Administrator lifecycle

The browser console uses revocable administrator sessions. The static root
bearer is reserved for bootstrap, recovery, root-token rotation, and deliberate
non-browser automation.

### First owner and owner recovery

Run administrator lifecycle commands as root on the control-plane host:

```sh
sudo laneway control administrator bootstrap --username owner
sudo laneway control administrator recover --username owner
```

Bootstrap succeeds only before the first owner has been created. Recovery
requires the exact canonical username of an existing owner; matching is not
case-folded or prefix-based. Usernames are 3–64 lowercase ASCII bytes, begin and
end with a letter or digit, and may contain `.`, `_`, or `-` internally.

Both commands require a controlling terminal. If they are invoked through SSH,
allocate one explicitly. The command reads a valid UTF-8 password of 15–1024
bytes and its confirmation from `/dev/tty` with echo disabled. It does not read
the password from stdin and accepts no password or recovery-grant flag.
Passwords, grants, and bearer values are not placed in argv, environment
variables, lifecycle logs, or command output.

After prompting, the command obtains and immediately consumes a ten-minute,
one-use grant. If an attempt is interrupted before consumption, a retry
supersedes an inaccessible prior grant. If the controller commits consumption
but its response is lost, bootstrap is already complete and recovery has
already installed the new password; verify by signing in before deliberately
running recovery again. Successful bootstrap creates the first enabled owner.
Successful recovery replaces the owner password, re-enables the owner, and
atomically revokes all existing sessions and outstanding administrator
recovery grants. Neither operation creates a browser session, so sign in
normally afterward.

Only password-backed administrator sessions are supported. OIDC/SAML SSO and
SCIM are unavailable; leave them disabled. Never paste or otherwise expose the
root bearer in the browser.

### Root bearer automation and rotation

Controller CLI automation must read the bearer from its protected file:

```text
--admin-token-file DEPLOYMENT_DIR/generated/secrets/admin.token
```

The default deployment directory is `/opt/laneway`.

Do not copy the bearer into a command line or environment variable. Automation
should reopen the file for each invocation; restart any long-lived process that
cached the old value after rotation.

Encrypted recovery bundles contain the bearer that existed when each bundle
was created. After restoring any bundle, immediately rotate the root token and
create a fresh encrypted bundle. If suspected credential compromise prompted a
rotation, quarantine and retire pre-rotation bundles under the site's retention
policy instead of returning them to the recovery set.

Rotate the credential with:

```sh
sudo laneway control administrator root-token rotate
```

Rotation uses the same shared lifecycle lock as backup, restore, update,
upgrade, rollback, bootstrap, and recovery. It atomically publishes the
replacement at the existing token path and force-recreates only the controller.
Expect a brief control-plane interruption.

Protected progress and credential copies are kept under:

```text
DEPLOYMENT_DIR/generated/lifecycle/administrator-root-token-rotation/
```

Treat the entire directory as secret: do not print, copy, edit, or remove its
contents. Before the commit point, the wrapper attempts to leave the live
credential unchanged or restore and verify the prior credential. If automatic
restore, controller recreation, or proof cannot finish, it retains protected
state for a safe rerun instead of discarding either credential. Commit occurs
only after the new credential authenticates and the prior credential is
rejected. After that proof, rollback is forbidden: the new credential remains
authoritative even if completion auditing or cleanup fails.

Rerun the same rotation command after an interruption. It resumes the recorded
phase, completes a pending rollback, or republishes and verifies the committed
new credential before retrying completion. If it reports that the prior
credential was restored and verified, run it once more to begin a fresh
rotation. Successful completion removes the protected rotation directory.

## Client lifecycle

With one saved login, `laneway connect` remembers its domain. With several,
specify it:

```sh
laneway connect lane.example.com
```

Use an ephemeral session when no identity should be saved:

```sh
laneway connect lane.example.com --ephemeral
```

Remove a saved login with `laneway logout lane.example.com`. This does not
revoke the device; revoke its NodeID at the controller when it is retired, lost,
or compromised.

Full-tunnel routing is never automatic. It requires an authorized Exit Node and
an explicit `--exit NAME`. The macOS client supports private split routes only.

## Managed Linux Nodes

Create a durable invitation on the control-plane host:

```sh
sudo laneway control invite --name server-one
```

Install Laneway on the Node, save the invitation code in a mode-`0600` file,
then enroll it:

```sh
sudo laneway node install lane.example.com --token-file ./laneway.code
sudo laneway node status
```

The command writes managed configuration and credentials, enables direct paths,
and starts the systemd unit. Use `--no-direct` for relay-only operation or
`--no-start` when another tool owns activation.

```sh
sudo laneway node peers
sudo laneway node routes
sudo laneway node renew
sudo laneway node uninstall
```

`node uninstall --keep-state` preserves `/var/lib/laneway`. Managed commands
refuse to remove files they do not own.

After a package update:

```sh
sudo systemctl restart lanewayd
sudo laneway node status
```

## Monitoring

```sh
sudo laneway control status
sudo laneway node status -json
sudo laneway node peers
systemctl status laneway-relay laneway-controller lanewayd
journalctl -u laneway-relay --since '30 minutes ago' --no-pager
```

Node status reports addresses, routes, carrier, certificate and configuration
lease health, and Exit selection. Peer status reports `direct`, `relay-quic`,
`tcp-fallback`, or `disconnected`.

Alert on credentials approaching expiry, sustained relay throttling, loss of
all paths, cleanup failures, or an Exit Node whose forwarding/NAT readiness is
zero. Diagnostic listeners must remain on loopback; see the
[observability profile](../spec/observability-v1.md).

## Troubleshooting

### Cannot connect

1. Check system time and certificate validity.
2. Resolve the controller and relay names from the affected host.
3. Test controller TCP+UDP and relay UDP separately from relay TCP fallback.
4. If TCP works but QUIC does not, inspect UDP filtering, NAT timeouts, and MTU.
5. Restart after an intentional DNS endpoint change; addresses are pinned for
   the process lifetime.

### Connected but traffic fails

1. Compare `laneway node routes` with the approved control-plane route.
2. Confirm source and destination authorization.
3. Check Node and relay drop counters.
4. Check the host firewall on `lane0`.

Docker Connectors carry TCP and UDP, not ICMP. Test them with an application
connection rather than `ping`.

### Subnet routing fails

Confirm the advertised prefix and output interface, then inspect:

```sh
sudo nft list table inet laneway
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
```

Routed mode needs a LAN return route to the overlay pool. NAT mode changes the
observed source but does not need that route. Never flush nftables; follow the
[nftables guide](../deploy/nftables/README.md) when recovery fails.

### Exit routing is wrong

Check the selected Exit and failure mode, native bypass routes, policy rule
`11000`, table `51820`, and `resolvectl` state for `lane0`. Disable the Exit and
confirm routes and DNS are restored:

```sh
sudo laneway node exit disable
```

Do not delete exit-intent or DNS ownership journals to force startup.

### Controller updates stop

Check controller QUIC/UDP reachability, mTLS identity, audit events, and the
configuration epoch. Services retain the last complete snapshot only until its
lease expires, then fail closed.

## Shutdown and crash recovery

Stop Nodes normally so they can restore routes, DNS, nftables, sysctls, and TUN
state:

```sh
sudo systemctl stop lanewayd
```

After a crash, Laneway reclaims only exact state carrying its ownership markers.
If startup refuses recovery, stop every Laneway process, inspect the conflicting
objects, remove only confirmed Laneway residue, and restore the site's recorded
baseline.

### Stale control-plane lifecycle lock

A host crash or uncatchable process termination can leave the conservative
shared lock at:

```text
DEPLOYMENT_DIR/generated/lifecycle/operator.lock
```

The commands below use the default deployment directory, `/opt/laneway`.

Do not assume the lock is stale from its age. First coordinate with other
operators, inspect the process tree and protected state without reading file
contents, and check controller health:

```sh
sudo ps -ef --forest
sudo stat -c '%F %a %U:%G %n' \
  /opt/laneway/generated/lifecycle/operator.lock
sudo find /opt/laneway/generated/lifecycle -mindepth 1 -maxdepth 2 \
  -printf '%M %u:%g %p\n'
sudo laneway control status
```

Confirm that no `laneway-control`, recovery or upgrade helper, or related
Docker Compose child remains. Only when the exact lock path is a real, empty,
root-owned directory and the originating operation is known to have stopped,
remove it with the non-recursive command:

```sh
sudo rmdir -- /opt/laneway/generated/lifecycle/operator.lock
```

If `rmdir` refuses, stop and investigate; do not substitute recursive removal.
Never delete another object under `generated/lifecycle` to clear the lock. In
particular, if `administrator-root-token-rotation` exists, leave it intact,
remove only the confirmed stale lock, and rerun
`sudo laneway control administrator root-token rotate` so the recorded state
machine can recover safely.

Controller, relay, and `lane-edge` Connector containers run non-root with
read-only scratch roots. The full Exit Node alone needs `NET_ADMIN` and
`/dev/net/tun`, inside its own container namespace. Do not give it host
networking, the Docker socket, or privileged mode.
