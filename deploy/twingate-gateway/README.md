# Managed Twingate gateway worker

A tenant owner selects an enrolled Laneway client and a Twingate IPv4 Resource and TCP port in Integrations. On a supported control-plane server, the controller supplies the Service Key and creates the single-use connector invitation. The host worker owns both containers. The tenant's computer needs only its Laneway client.

The packaged Rust Docker installer enables this worker automatically on Linux systemd hosts with local rootful Docker and `/dev/net/tun`. Its preflight checks for iproute2, nftables and nsenter. Each service runs on the existing Docker bridge in its own network namespace shared only with its paired connector. Nothing listens on a host port. The only container with NET_ADMIN and a TUN device is the Twingate Client. The unprivileged Rust connector has a read-only root filesystem.

## Upgrade a shared or existing Linux deployment

Install the gateway-capable controller release first. On the same host, run the worker installer from its trusted release deployment directory. The optional numeric argument selects the controller's UID and group (both 65532 in the packaged images).

```sh
sudo sh /usr/local/share/laneway/deploy/twingate-gateway/install.sh
```

The installer pulls the official Twingate Client by multi-platform digest. It verifies the pinned Laneway connector digest against the v0.3.10 GitHub Actions release signer using Cosign, then pulls it. It enables the worker at boot. Neither image selection nor the container command comes from a tenant request. The provider image uses content digest pinning. This installer does not verify a provider signing identity.

Include this directory's `compose.yaml` as the last Compose overlay for an existing controller service, or add its single bind mount to the deployment's persistent Compose definition. Recreate just the controller with its usual deployment files and environment. The bind source is `/var/lib/laneway-gateways/spool`, the destination is `/run/laneway-gateways`, and the controller needs write access to the `requests` subdirectory. Never mount the Docker socket or worker state directory into the controller. For an existing native systemd shared controller, set `LANEWAY_GATEWAY_DIR=/var/lib/laneway-gateways/spool` and grant its unit write access to the requests subdirectory. Restart the controller through the operator's normal rollout procedure.

Use one trusted controller process per spool. Shared-mode tenants receive individual spool records derived from their canonical database paths. Keep those paths stable across container upgrades. The spool and sibling work directory contain private credentials. Protect their disk and backups as you protect the controller's database and issuing keys.

## Readiness and removal

The worker checks the actual route to the protected IP, requires a TUN interface, installs a namespace-local filter, and connects to the selected TCP port before starting the connector. The filter drops packets for that IP on any other interface or port. It also drops unsolicited inbound traffic. The kernel enforces this rule even when a provider route disappears between checks. A live controller configuration lease and an active connector path are required for online status. The worker checks local state every five seconds, probes the remote TCP endpoint once a minute, and backs off failed TCP probes up to five minutes. Online status expires within 90 seconds of the successful probe and requires a fresh worker heartbeat. These TCP health checks can appear as short connections in resource logs.

Removing the gateway through the console asks the controller to withdraw its route and provider credentials and asks the worker to delete its two containers and their private local state. An interrupted cleanup resumes on restart. Use `systemctl status laneway-twingate-gateway` to inspect worker availability. The worker suppresses container logs and reports sanitized errors.

## Local runtime test

Run `integration/twingate-gateway/run.sh` from this repository with Docker available. It launches a disposable, privileged inner Docker engine. A synthetic provider moves real TCP traffic through a two-ended Linux TUN. Real v0.3.10 controller, relay and Rust-backed connector images issue and redeem disposable invitations. Tests check stable node identity after restart, tenant isolation, resource reachability, and the kernel's deny rule with a separately reachable bypass endpoint. The fixture contacts registries for its test images.
