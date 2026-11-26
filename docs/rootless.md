# Rootless SOCKS5 client

Run Laneway in your regular user account on Linux or macOS to give selected applications access to private routes through a local SOCKS5 proxy. The node uses its own userspace packet stack and receives its route and ACL policy from the controller. It does not create a host network interface or change system routes, DNS, firewall rules, or forwarding settings. Applications that connect directly keep using the host network.

## Configure and start

1. Install the official Laneway package with its companion runtime. Run the official installer as your regular user with `sh install.sh --rootless` to select a per-user installation.
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

Private destinations still require an approved route and an ACL that permits this node's traffic. Ask the operator for the destination's private IP and port. A browser or other application may also need its own settings for name resolution.

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

## Run the Linux integration test

Run with the binaries from an extracted Linux package and an ordinary Linux user. The test provisions a temporary production Rust controller and relay, then exercises both nodes through the packaged `laneway` command. It sends TCP and UDP traffic to listeners it creates on a local non-loopback IP and checks controller policy, credential changes, and the host network before and after the test.

```sh
python3 integration/rootless.py --bin-dir /path/to/extracted/laneway
```

Use `--target-ip ADDRESS` to select a specific non-loopback IPv4 address assigned to the runner.

Add `--check-renewal` to exercise automatic certificate renewal with a short-lived fixture certificate.
