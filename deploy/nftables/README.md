# nftables deployment guidance

`host-firewall.nft` is a reviewable example, not an installer. Replace its
documentation addresses, preserve the host's management path, and merge the
rules into the existing firewall rather than loading two competing base
policies. The example includes both IPv4 and IPv6 documentation sources so an
IPv6-selected controller endpoint is not accidentally blocked. Replace both
source sets with the site's actual management/node networks. Validate a
candidate without applying it:

```sh
sudo nft --check --file deploy/nftables/host-firewall.nft
```

The public relay needs inbound UDP for QUIC and inbound TCP only when fallback
is enabled. The controller needs both TCP for HTTPS administration/enrollment
and UDP for the authenticated `laneway-control/1` QUIC stream, normally
restricted to management and node source networks. Nodes initiate outbound
connections and do not require a public inbound rule for the relay path.

Subnet routers create a separate `table inet laneway` at runtime; exit gateways
use `table inet laneway_exit`. Each table has a deterministic marker bound to
its Laneway role, schema, chain names, and interfaces, plus a random per-process
session record containing the pre-activation forwarding state. Do not declare
either table in a persistent firewall ruleset. Rules outside those tables
remain operator-owned and may still drop forwarded traffic; inspect the
complete forward path when debugging.

After an ungraceful process death, restart with the same configuration and
controller-authorized plan. Laneway compares the complete JSON nftables table
shape—not just the marker—and automatically replaces exact crash residue while
retaining the original forwarding-sysctl baseline. A missing, additional, or
changed object makes recovery fail closed. Inspect a refused table with:

```sh
sudo nft list table inet laneway
sudo nft list chain inet laneway laneway_owner
```

For an exit gateway, substitute `laneway_exit`. If recovery was refused because
the desired plan or interfaces intentionally changed, stop every Laneway
process and establish the table's provenance before removing only that exact
table. Then reconcile forwarding against the documented host baseline:

```sh
sudo nft delete table inet laneway
sudo sysctl -w net.ipv4.ip_forward=0   # or the site's documented baseline
sudo sysctl -w net.ipv6.conf.all.forwarding=0 # or the site's documented baseline
```

Never flush the global nftables ruleset as a Laneway cleanup procedure.
