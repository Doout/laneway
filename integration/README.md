# Integration tests

The normal suite is unprivileged and safe to run on a workstation:

```sh
./integration/nonprivileged.sh
```

It covers the real mTLS QUIC relay overlay, TCP fallback, cross-carrier relay
delivery, and the memory/fake-command versions of subnet and exit management.
These tests also run as part of `go test ./...`.

## Privileged Linux network namespaces

`linux-netns.sh` builds test binaries first, creates a disposable network
namespace, and runs the following checks inside it:

- real `/dev/net/tun` creation, MTU/address configuration, overlay route
  installation, and close cleanup;
- real nftables NAT-to-routed reconciliation and IPv4/IPv6 forwarding-sysctl
  restoration;
- real split-default `/1` exit routes, transport/LAN bypasses, and DNS apply
  rollback through an isolated `resolvectl` state machine;
- process-crash behavior: TUN file-descriptor cleanup, exact nftables and exit
  policy-table ownership validation, automatic residue/sysctl takeover, and
  successful restart with no operator cleanup; and
- TCP fallback while a namespace output rule drops every UDP packet;
- IPv4 and IPv6 application UDP traffic crossing two real `lane0` kernel TUN
  devices and the authenticated QUIC relay, with dual-family address and route
  assertions;
- IPv4/IPv6 NAT and routed subnet-gateway traffic to a separate LAN namespace,
  including verification of the source address observed by the LAN application
  and real NAT66 where supported by the test kernel;
- selected IPv4 and IPv6 split-default exit flows through the real exit route
  and gateway managers to an external namespace, including NAT66; and
- direct-path promotion between nodes behind two deterministic nftables NATs,
  with the relay packet counter checked to prove the application packet did
  not take the relay path; and
- one stable dual-stack kernel WireGuard interface carrying encrypted packets
  over relay QUIC, forced relay TCP when external UDP is blocked, automatic
  QUIC recovery, direct WireGuard promotion, and direct-failure demotion without
  recreating the interface or changing its controller-assigned addresses. The
  same gate selects a controller-approved WireGuard exit, verifies protected
  underlay bypasses, and carries a real Internet-side packet through gateway
  NAT while the encrypted tunnel uses relay QUIC. A forced node `SIGKILL`
  followed by restart proves exact WireGuard/Exit ownership reconciliation,
  restored direct traffic, and final graceful device cleanup; and
- the foreground `laneway connect` User workflow using authenticated public
  bootstrap discovery, mode-0600 single-use ephemeral invites, the privileged
  network-helper protocol, forced relay QUIC traffic, direct-path promotion,
  controller-approved Exit Node selection over relay and direct carriers,
  split-default/local-LAN routing, temporary DNS ownership, gateway NAT,
  SIGTERM restoration, requester `SIGKILL` cleanup, and a successful next-run
  reconciliation; and
- a controller-backed product lifecycle using the real HTTPS/mTLS controller,
  admin and node CLIs, single-use enrollment, relay registration, capabilities,
  ACLs, route advertisement/approval/withdrawal, and node revocation. The live
  relay and both `lanewayd` processes poll those snapshots; the test verifies a
  controller-approved subnet route in the client kernel, gateway nftables and
  forwarding state, a real NATed application flow, ACL fail-close, transactional
  withdrawal cleanup, audit records, and revocation-driven relay disconnect.

The suite is deliberately opt-in. It requires Linux, root, `/dev/net/tun`,
`iproute2`, `iputils` (`ping`), `nftables`, `sysctl`, and Go. All switches,
routers, LAN hosts, and external hosts are disposable network namespaces; the
host's routes and firewall are not used for the packet-flow assertions:

```sh
sudo --preserve-env=LANEWAY_RUN_PRIVILEGED \
  env LANEWAY_RUN_PRIVILEGED=1 ./integration/linux-netns.sh
```

Set `LANEWAY_KERNEL_BENCHMARK_OUTPUT` to an absolute JSONL path to add eight
bounded measurements over the live topology: native Laneway relay QUIC,
direct WireGuard, WireGuard-over-relay QUIC, WireGuard-over-relay TCP, subnet
NAT, subnet routed mode, static selected-exit NAT, and controller-approved,
CLI-selected exit NAT. Four additional rows report direct↔relay-QUIC and
relay-QUIC↔relay-TCP promotion/demotion time while the same kernel WireGuard
interface remains installed. Each echo workload crosses the production kernel
TUN/WireGuard device, route policy, selected carrier, gateway forwarding, and
nftables state and reports
throughput, successful-send loss, bounded latency-sample percentiles, client
CPU/RSS/allocations, and GC. `duration_ms` is the active send window used for
throughput; `resource_duration_ms` covers that window plus the bounded reply
drain used for CPU, allocation, GC, and final receive accounting.
Generated-versus-sent errors and the exact latency sample count are recorded
explicitly. The
scheduled privileged workflow enables this mode and archives the validated
12-row JSONL; it is intentionally distinct from the unprivileged forwarding
adapter.

Without `LANEWAY_RUN_PRIVILEGED=1`, the script exits successfully with a clear
skip message. The Go package also skips when invoked directly, which prevents
an ordinary `go test ./...` from mutating host networking. The script always
removes its namespace and temporary binaries through a trap.

`rust-kernel-netns.sh` is a narrower Rust-native ownership check. It simulates
a crashed predecessor and proves exact subnet/exit nftables, IPv4/IPv6
forwarding-sysctl, dedicated exit-policy reconciliation, dynamic direct
endpoint bypass lifetime, and open/closed selected-path behavior. Its
injectable `resolvectl` shim also verifies DNS apply, exact graceful restore,
and journal-based crash recovery without touching the host resolver:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 ./integration/rust-kernel-netns.sh
```

`rust-node-interop.sh` is the executable cross-language packet gate. In
disposable namespaces it carries bidirectional IPv4 and IPv6 UDP, ICMP, and
TCP application traffic between Go and Rust nodes; forces a Rust node onto the
Rust relay's TLS/TCP fallback; proves authenticated direct QUIC with a zero
relay-forward counter; and sends Go-client traffic through a Rust subnet
router in both NAT and routed modes and through a Rust dual-stack exit gateway.
The LAN and external application logs assert the exact preserved or translated
source address, rather than treating a reply alone as proof of the forwarding
mode.

The scheduled/manual `Privileged Linux integration` GitHub Actions workflow
runs this suite, the Rust kernel suite, and the executable Go/Rust node
interoperability and Go-controller-to-Rust-node authority suites as
fail-independent jobs. Each job verifies TUN, network-namespace, and nftables
capabilities first and archives its complete log plus runner/tool versions.
The Go job additionally archives the kernel-datapath benchmark JSONL.
These suites are not required on pull requests because hosted-runner kernel
capabilities are outside the unit-test contract.

## Isolated Docker Exit lifecycle

`docker-exit-node.sh` is the clean-host Docker gate for the default Exit image.
It builds the pinned controller, relay, administrative, and Exit images; creates
uniquely labelled Docker networks and state volumes; enrolls a client and Exit
with the real controller; grants and approves the Exit capability/default
route; and verifies fixed-port direct traffic plus capped-relay fallback. A
second disposable NAT container proves the documented bridge/double-NAT source
translation at an Internet-side application. The gate also checks the 1200-byte
TUN MTU, graceful restart, `SIGKILL` restart, controller health during direct
failure, and exact restoration of the host routes, stateless nftables rules,
and all pre-existing Docker containers/networks/volumes.

Every resource deletion is preceded by a matching, unguessable ownership-label
check. Temporary enrollment/admin secrets live only in a mode-0600 temporary
directory that is deleted rather than archived. Failure logs are bounded and
redact token-shaped fields. Do not run this gate on a shared Docker host:

```sh
sudo env LANEWAY_RUN_PRIVILEGED=1 ./integration/docker-exit-node.sh
```

The scheduled workflow executes it independently on native Linux AMD64 and
ARM64 runners. The matrix as a whole covers:

| Requirement | Executable gate |
| --- | --- |
| Node↔Node, User→Node, User→Exit, Node→Exit; direct and relay | `fullstack-netns.sh` WireGuard and foreground cases |
| QUIC failure → TCP fallback → QUIC recovery | `fullstack-netns.sh` stable WireGuard carrier case |
| Relay saturation with healthy control/rendezvous | Docker Exit saturation/re-promotion case and relay limiter unit tests |
| Open/cone-like, restrictive, UDP-blocked, and double NAT | direct same-switch; `direct-nat`; peer-UDP filter; TCP fallback; Docker Exit double-NAT gate |
| Exit bridge forwarding, NAT, MTU, graceful/crash restart | `docker-exit-node.sh` |
| User Ctrl-C/SIGTERM/SIGKILL and reconciliation | foreground connect case and helper namespace tests |
| Upgrade, backup, restore, rollback, removal | `lane-workflows.sh`, `lane-recovery.sh`, node lifecycle tests |
| AMD64/ARM64 and Go/Rust interoperability | Docker Exit native-arch jobs, release/architecture workflows, `rust-node-interop.sh` |
| Foreign-state preservation and secret-safe diagnostics | exact namespace/Docker ownership assertions and bounded workflow artifacts |
