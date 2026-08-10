# nftables guidance

`host-firewall.nft` is an example, not an installer. Replace its documentation
addresses, preserve the host's management path, and merge it into the existing
policy. Validate it before applying it:

```sh
sudo nft --check --file deploy/nftables/host-firewall.nft
```

Open the component ports listed in the
[operations runbook](../../docs/operations.md). Nodes and Connectors initiate
outbound connections.

Laneway creates `table inet laneway` for subnet routing and
`table inet laneway_exit` for exit routing. Do not add either table to a
persistent ruleset.

After a crash, Laneway reclaims only an exact table it created. If recovery
fails, stop Laneway and inspect the table before removing anything:

```sh
sudo nft list table inet laneway
sudo nft list chain inet laneway laneway_owner
```

Use `laneway_exit` for an Exit Node. Remove a table only after confirming its
ownership, then restore forwarding sysctls to the site's recorded baseline.
Never flush the global nftables ruleset as a Laneway cleanup step.
