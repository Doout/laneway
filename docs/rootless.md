# Rootless SOCKS5 client

Run Laneway in your regular user account on Linux or macOS to give selected applications access to private routes through a local SOCKS5 proxy. The node uses its own userspace packet stack and receives its route and ACL policy from the controller. It does not create a host network interface or change system routes, DNS, firewall rules, or forwarding settings. Applications that connect directly keep using the host network.

## Configure and start

1. Install the signed Laneway client as your regular user with `sh install.sh --rootless`.
2. Ask the network operator for a native setup invitation. The operator can issue one from an existing control-plane deployment.

   ```sh
   sudo laneway control invite --name laptop --native
   ```

3. Run the client commands as your regular user. Paste the setup invitation into `laneway configure` when prompted.

   ```sh
   laneway configure
   laneway start
   ```

On first configuration, Laneway displays the username `local` and its generated password once. Save the password and configure the application to use SOCKS5 at `127.0.0.1:1080` with that username and password. Keep `laneway start` running while applications use the proxy. The proxy endpoint supports TCP CONNECT and UDP ASSOCIATE when the application's SOCKS5 implementation supports those operations.

If setup is interrupted, run `laneway configure` again with the same invitation. Laneway saves the original keys and request in the private state directory and asks the controller to recover the enrollment. A controller that predates enrollment recovery can report that the invitation was already used. If the invitation is permanently refused or unavailable, ask your network operator to check whether a node was created and to issue a fresh invitation. Run `laneway configure --discard-pending` before using the replacement invitation. This abandons the local pending request and preserves any configured identity and proxy credentials. Repeat any `--state-dir` or Linux `--system` option from the original configuration.

The userspace client carries traffic through an authenticated relay. Private destinations require an approved route and an ACL that permits this node's traffic. Ask the operator for the destination's private IP and port. A browser or other application may also need its own settings for name resolution.

## State and credentials

The default Linux state directory is `${XDG_STATE_HOME:-$HOME/.local/state}/laneway/rootless`. The default macOS location is `~/Library/Application Support/laneway/rootless`. Treat this directory as private because it holds the node's enrollment identity and local credentials. The same state is reused on subsequent starts.

Use a separate username for each application when you need to revoke its access independently.

```sh
laneway credential add app
laneway credential list
laneway credential remove app
```

Adding a credential generates a password displayed once. Keep it in the application's credential store. To supply your own password, use `laneway credential add app --password-stdin` and provide it over standard input. Removing a credential disables its corresponding SOCKS5 sessions.

Use `--state-dir DIRECTORY` on the configure, start, and credential commands to select a separate enrolled identity and credential set. Use `laneway start --listen 127.0.0.1:PORT` when port 1080 is already in use. Use `laneway start --proxy-only` to prevent the instance from forwarding other nodes' traffic to a locally assigned route.

## Update or use system networking

Run `laneway update client` from the installed CLI to update the per-user CLI and its matching runtime from a signed release. Existing credential and enrollment files stay in the state directory.

For a Linux system tunnel, install the system package using `sh install.sh --system`. Then run `sudo laneway configure --system` with a native invitation and `sudo laneway start --system`. An existing service configuration can be selected with `--config PATH`.

## Run the Linux integration test

Run with the binaries from an extracted Linux package and an ordinary Linux user. The test provisions a temporary production Rust controller and relay, then exercises both nodes through the packaged `laneway` command. It sends TCP and UDP traffic to listeners it creates on a local non-loopback IP and checks controller policy, credential changes, and the host network before and after the test.

```sh
python3 integration/rootless.py --bin-dir /path/to/extracted/laneway
```

Use `--target-ip ADDRESS` to select a specific non-loopback IPv4 address assigned to the runner.

Add `--check-renewal` to exercise automatic certificate renewal with a short-lived fixture certificate.
