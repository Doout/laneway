# Laneway node

`lanewayd` runs in the foreground. Its default userspace mode serves approved private TCP and UDP routes and gives local applications an authenticated SOCKS5 proxy on loopback. Both use ordinary sockets and the existing Laneway controller and relay. This mode needs no container, TUN device, host routing changes, or elevated privileges.

Use `laneway configure` and `laneway start` as your normal user. On Linux the same node executable supports system networking with a TUN interface and host routes. With the system package installed, use a native invitation for this host:

```sh
sudo laneway configure --system
sudo laneway start --system
```

Linux system mode stores its own identity in `/var/lib/laneway-system` and requires TUN and network administration privileges to run. For an explicitly managed TOML configuration, use `sudo laneway start --system --config PATH`. On macOS, `laneway configure --system` configures the native helper and `laneway start --system` uses a saved client login. Windows supports userspace mode. See [Linux system node configuration](rust-controller-node.md).

Earlier Linux packages installed `sbin/lanewayd` as an alias for the Go node. If a custom service used `lanewayd -config PATH` with a Go configuration, use `laneway node run -config PATH` to keep using the installed configuration. Packaged services already use that command. Existing per-user enrollments retain their state directory and proxy credentials.

For a foreground client that installs host routes, the commands are still `laneway login DOMAIN` followed by `laneway connect`. Login saves a renewable profile and can reuse profiles created by the Go CLI. Native host routing requires network privileges or the installed platform helper. Use the userspace proxy when applications can connect over SOCKS5 and the host must keep its existing network configuration.

The Linux and macOS packages use Rust for the privileged network helper.
Existing Linux sudo rules continue to work. On macOS the installer places the
helper at the existing privileged-helper path. The default per-user
`configure` and `start` commands run independently of this helper.

Linux host-route sessions use `/dev/net/tun`, iproute2 and a kernel with
`SO_NETNS_COOKIE`. The helper uses that cookie and the boot ID to identify the
network namespace when recovering interrupted route changes. Per-link exit
DNS uses `systemd-resolved` and `resolvectl`.

On Linux, ordinary-user exit sessions and foreground connections using
`--exit` with closed failure mode still use the Go packet runtime. The Rust
helper sets up and restores their host routes and per-link DNS settings.

## Install and enroll

To try a checkout on Linux or macOS, build the public CLI, daemon and compatibility helper into the same directory.

```sh
make build
export PATH="$PWD/rust/target/debug:$PATH"
```

The release installer puts the three matching executables together automatically. When staging files manually, the Rust CLI asset starts with `laneway-native_` and installs as `laneway`. Install the corresponding `lanewayd` and `laneway-compat` assets alongside it. Windows uses the same names with the `.exe` extension. Its small Rust compatibility executable provides the version check used by existing signed installers.

Choose a stable release that includes the native node assets for your platform. The release targets Linux, macOS, and Windows on amd64 and arm64. Download the corresponding installer from that release. With no version argument it selects the latest stable release. To pin a version, pass its tag. Both installers require `cosign` to verify the signed release manifest and executable checksum before installing.

| Platform | Installer invocation | Executable directory |
| --- | --- | --- |
| Linux and macOS | `sh ./install-node.sh` | `$HOME/.local/bin` |
| Windows with PowerShell 7 | `pwsh -File ./install-node.ps1` | `%LOCALAPPDATA%\Laneway\bin` |

Put that directory on your `PATH` or invoke the executable by its full path. On the control-plane host, create one invitation per rootless peer. In this example, `laptop` originates traffic and `office` serves the office LAN.

```sh
sudo laneway control invite --name laptop --native --connector
sudo laneway control invite --name office --native --connector
```

Transfer each single-use `st1.` setup token privately to the corresponding peer. Run `laneway configure` there and paste the token at the hidden prompt. Enrollment also accepts one token line on standard input from a secret provider for unattended use. Keep tokens out of command arguments and shell history.

Use `--native --connector` on a peer that will serve an approved route. For a proxy-only peer, `--native` also issues a setup token and leaves subnet serving authorization unset. The example enrolls both peers as Connectors so either can serve a route. A peer only serves a private prefix after the controller assigns it a NAT route for that prefix.

By default, identity and credentials are stored in a private per-user directory.

| Platform | State directory |
| --- | --- |
| Linux | `$XDG_STATE_HOME/laneway/rootless` when `XDG_STATE_HOME` is an absolute path, otherwise `$HOME/.local/state/laneway/rootless` |
| macOS | `$HOME/Library/Application Support/laneway/rootless` |
| Windows | `%LOCALAPPDATA%\laneway\rootless` |

Use `--state-dir` with an absolute path to keep multiple identities separate. Use the same path for enrollment, runtime, and credential commands for a given identity.

## Approve and use a route

After both peers have enrolled, approve a private destination through the Connector that can reach it. `laneway control route add --connector office --to 10.20.0.10/32 --allow laptop` creates the route and a forward allow rule. Laneway v1 checks ACLs on each packet, so the example below also allows replies from `10.20.0.10/32` to `laptop`. Run it on the control-plane host with `jq`. Adjust `controller` and `deployment` for a custom Compose installation.

```sh
deployment=/opt/laneway
controller=https://127.0.0.1:8443
setting() { sudo sed -n "s/^$1=//p" "$deployment/.env"; }
network_id=$(setting LANEWAY_NETWORK_ID)
controller_admin() {
  sudo /usr/local/bin/laneway controller "$@" \
    --network-id "$network_id" --controller "$controller" \
    --ca "$deployment/generated/pki/ca.crt" \
    --server-name "$(setting LANEWAY_CONTROLLER_SERVER_NAME)" \
    --controller-network-id "$network_id" \
    --controller-service-id "$(setting LANEWAY_CONTROLLER_SERVICE_ID)" \
    --admin-token-file "$deployment/generated/secrets/admin.token"
}
approve_route() {
  # Arguments are the Connector name, service IP, and initiating peer name.
  forward_rule=$(sudo laneway control route add --connector "$1" --to "$2/32" --allow "$3") || return
  selector=$(printf '%s\n' "$forward_rule" | jq -ce '
    .acl_rule.selector | {
      source_prefixes: .destination_prefixes,
      destination_node_ids: .source_node_ids,
      ip_protocol: "IP_PROTOCOL_ANY"
    } | select(.source_prefixes | length == 1) | select(.destination_node_ids | length == 1)
  ') || return
  controller_admin acl add --priority 100 --action accept --selector "$selector" \
    --description "Replies from $2 to $3"
}
approve_route office 10.20.0.10 laptop
```

For a port-restricted policy, use the service port as the destination port on requests. Replies are addressed to the proxy's dynamically allocated ports. See [Routing v1](../spec/routing-v1.md#acls).

On `office`, start the Connector. Leave it running while peers use the approved route.

```sh
laneway start --no-proxy
```

On `laptop`, run `laneway start`. Use the SOCKS5 username `local` and the password printed by the first `laneway configure`. To create another login later, use `laneway credential add workstation`.

The default listener is `127.0.0.1:1080`. Use `laneway start --listen '[::1]:1080'` to choose another loopback address. Use `laneway start --proxy-only` to originate application traffic without serving assigned subnets. For a TCP smoke test, run this from another terminal on the laptop and enter the password at curl's prompt.

```sh
curl --proxy socks5h://127.0.0.1:1080 --proxy-user local http://10.20.0.10:8080/
```

To initiate connections in the other direction, run `approve_route laptop 10.30.0.10 office` on the control-plane host for a service reachable from `laptop`. On `office`, stop the Connector with Ctrl-C, add a local credential, and restart with `laneway start`. Use the same curl command on `office` with `10.30.0.10` as the target. Each peer's proxy uses its own credential list. `laneway credential list` prints names and `laneway credential remove workstation` revokes that login and disconnects its sessions.

## Traffic coverage and checks

On the host, a socket listing shows the loopback SOCKS listener, outbound Laneway transport sockets, and destination sockets for services currently in use. QUIC uses an ephemeral UDP port for replies. The rootless node opens that endpoint in client mode. Routes, TCP state, and UDP associations live in the process. When the controller replaces or withdraws the routing policy, the node closes existing flows and applications can reconnect under the new policy. Renewing the same lease preserves flows.

- Applications must opt into SOCKS5. Transparent system traffic and ICMP are outside the rootless dataplane. A successful `ping` is therefore unrelated to proxy connectivity.
- Hostnames sent through SOCKS5 use the initiating peer's system resolver. Use private IPs when that resolver cannot resolve private names. The proxy only connects to destinations permitted by the controller snapshot.
- The native dataplane uses the configured relay over QUIC, with TCP on the invitation's controller hostname at port `443` as fallback when the deployment exposes it.
- TCP clients use SOCKS5 `CONNECT`. UDP clients must support authenticated `UDP ASSOCIATE`, bind a local UDP socket first, and supply its nonzero port in the association request. Keep the control TCP connection open while sending datagrams and use the UDP endpoint returned by the proxy.
- The overlay MTU is 1280 bytes. Keep UDP payloads at or below 1252 bytes for IPv4 and 1232 bytes for IPv6. SOCKS5 UDP fragmentation is unsupported.
- For a manual check, start with an IP and port known to be reachable from the Connector. Confirm the correct local credential, approved route, and ACLs for request and reply traffic. Then check that an unapproved destination or invalid credential is denied.
- `python3 integration/rootless.py` runs the controller/relay integration on Linux as an ordinary user. It covers TCP and UDP, denied traffic, live revocation, restart, and relay reconnection. Add `--measure` for idle and concurrent-flow measurements. In an isolated environment where the test user can already bind loopback port 443, `--tcp-fallback` exercises the same flows with relay QUIC unavailable. The [rootless CI workflow](../.github/workflows/node.yml) builds and tests each release target.

## Upgrade or uninstall

Stop the foreground process with Ctrl-C. To upgrade, run `laneway update client` and start the peer again with its existing state directory. To uninstall, remove `laneway` and `lanewayd` from `$HOME/.local/bin` or `laneway.exe` and `lanewayd.exe` from `%LOCALAPPDATA%\Laneway\bin`. If retiring the node, have an administrator revoke its identity and remove obsolete route and ACL entries before deleting its state directory. On Windows, the executable directory `Laneway\bin` and the state directory `laneway\rootless` are siblings under the same case-insensitive parent. Remove only the directory you intend to clear.
