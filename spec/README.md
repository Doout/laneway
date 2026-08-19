# Protocol specifications

These documents define Laneway v1. Capitalized requirement words use BCP 14.

| Area | Documents |
| --- | --- |
| System model | [Architecture](architecture.md), [deployment contract](deployment-contract.md), [threat model](threat-model.md) |
| Trust and identity | [Bootstrap](bootstrap-v1.md), [identity](identity-v1.md) |
| Control plane | [Control protocol](control-protocol-v1.md) |
| Packet path | [Packet format](packet-format-v1.md), [routing](routing-v1.md), [direct paths](direct-path-v1.md), [TCP fallback](tcp-fallback-v1.md) |
| End-to-end encryption | [WireGuard hybrid dataplane](wireguard-hybrid-v1.md) |
| Operations and evolution | [Desktop endpoint client](desktop-client-v1.md), [observability](observability-v1.md), [compatibility](compatibility.md) |

The schemas live in `api/proto/laneway/v1/`. Language-neutral conformance
fixtures live in [`testvectors/`](../testvectors/).
