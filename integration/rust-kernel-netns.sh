#!/usr/bin/env bash
set -euo pipefail

if [[ "${LANEWAY_RUN_PRIVILEGED:-0}" != "1" ]]; then
  echo "SKIP: set LANEWAY_RUN_PRIVILEGED=1 to run Rust kernel ownership tests"
  exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "ERROR: Rust kernel ownership tests require root" >&2
  exit 1
fi
for command in cargo ip nft sysctl bash; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "ERROR: required command is missing: ${command}" >&2
    exit 1
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
namespace="lw-rust-kernel-$$"
resolver_state="$(mktemp -d)"
dns_journal="${resolver_state}/dns-owner.json"
cleanup() {
  ip netns delete "${namespace}" >/dev/null 2>&1 || true
  rm -rf -- "${resolver_state}"
}
trap cleanup EXIT INT TERM

ip netns add "${namespace}"
ip -n "${namespace}" link set lo up
for interface in lane0 lan0 wan0; do
  ip -n "${namespace}" link add "${interface}" type dummy
  ip -n "${namespace}" link set "${interface}" up
done
ip -n "${namespace}" address add 10.50.0.1/24 dev lan0
ip -n "${namespace}" address add 192.0.2.2/24 dev wan0
ip -n "${namespace}" route add default dev wan0
printf '%s\n' '192.0.2.53' >"${resolver_state}/dns"
printf '%s\n' 'corp.example' >"${resolver_state}/domain"
printf '%s\n' 'no' >"${resolver_state}/default-route"
ip netns exec "${namespace}" \
  env CARGO_TARGET_DIR="${repo_root}/rust/target" \
  LANEWAY_TEST_RESOLVECTL="${repo_root}/integration/resolvectl-shim.sh" \
  LANEWAY_TEST_DNS_JOURNAL="${dns_journal}" \
  LANEWAY_RESOLVECTL_STATE_DIR="${resolver_state}" \
  cargo test --locked --manifest-path "${repo_root}/rust/Cargo.toml" \
    -p lanewayd-rs kernel::tests::privileged_nft_crash_reconciliation_and_restore \
    -- --ignored --exact --nocapture
ip netns exec "${namespace}" \
  env CARGO_TARGET_DIR="${repo_root}/rust/target" \
  cargo test --locked --manifest-path "${repo_root}/rust/Cargo.toml" \
    -p lanewayd-rs kernel::tests::privileged_sigterm_drives_owned_cleanup \
    -- --ignored --exact --nocapture

echo "PASS: Rust subnet/exit nft, sysctl, exit-policy/DNS crash recovery, open/closed path policy, dynamic bypass, and SIGTERM cleanup"
