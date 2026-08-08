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
  NAT while the encrypted tunnel uses relay QUIC; and
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

Set `LANEWAY_KERNEL_BENCHMARK_OUTPUT` to an absolute JSONL path to add four
bounded measurements over the live topology: subnet NAT, subnet routed mode,
static selected-exit NAT, and controller-approved, CLI-selected exit NAT. Each
echo workload crosses the production kernel TUN,
route policy, relay, gateway forwarding, and nftables state and reports
throughput, successful-send loss, bounded latency-sample percentiles, client
CPU/RSS/allocations, and GC. `duration_ms` is the active send window used for
throughput; `resource_duration_ms` covers that window plus the bounded reply
drain used for CPU, allocation, GC, and final receive accounting.
Generated-versus-sent errors and the exact latency sample count are recorded
explicitly. The
scheduled privileged workflow enables this mode and archives the validated
JSONL; it is intentionally distinct from the unprivileged forwarding adapter.

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
