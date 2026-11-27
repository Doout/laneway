#!/usr/bin/env bash
# Sourced by the packet gate only on a marked disposable systemd VM.

systemd_unit=""
systemd_runtime=""
systemd_sources=""
systemd_mounted=0

remove_systemd_sources() {
  if [[ -n "${systemd_sources}" ]]; then
    rm -f -- "${systemd_sources}/"{ca.crt,node.crt,node.key,wireguard.key,laneway.toml,invitation}
    rmdir -- "${systemd_sources}"
    systemd_sources=""
  fi
}

cleanup_systemd_exit() {
  if [[ -n "${systemd_unit}" ]]; then
    systemctl stop "${systemd_unit}" >/dev/null 2>&1 || true
  fi
  remove_systemd_sources
  if [[ -n "${lab_carrier_cleanup_unit:-}" ]]; then
    finish_lab_carrier || return 1
    systemd_mounted=0
    systemd_runtime=""
  fi
  if [[ -n "${systemd_runtime}" ]]; then
    if [[ "${systemd_mounted}" == 1 ]]; then
      umount -- "${systemd_runtime}" || return 1
      systemd_mounted=0
    fi
    rmdir -- "${systemd_runtime}"
    systemd_runtime=""
  fi
  systemd_unit=""
}

systemd_failure() {
  printf 'ERROR: %s\n' "$1" >&2
  systemctl status --no-pager "${systemd_unit}" >&2 || true
  journalctl --unit "${systemd_unit}" --lines 20 --no-pager >&2 || true
  return 1
}

stage_systemd_exit() {
  local transient_name candidate
  transient_name="laneway-ephemeral-exit-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "${transient_name}" =~ ^laneway-ephemeral-exit-[0-9a-f]{16}$ ]]
  candidate="/run/${transient_name}"
  mkdir -m 0700 -- "${candidate}"
  systemd_runtime="${candidate}"
  systemd_unit="${transient_name}.service"
  mount -t tmpfs -o rw,nosuid,nodev,exec,mode=0700,size=256M tmpfs "${systemd_runtime}"
  systemd_mounted=1
  systemd_sources="$(mktemp -d /run/laneway-lab-creds.XXXXXX)"
}

run_systemd_exit() {
  stage_systemd_exit
  install -m 0400 "${work_dir}/pki/ca.crt" "${systemd_sources}/ca.crt"
  install -m 0400 "${work_dir}/pki/rust.crt" "${systemd_sources}/node.crt"
  install -m 0400 "${work_dir}/pki/rust.key" "${systemd_sources}/node.key"
  install -m 0400 "${work_dir}/pki/rust.wireguard.key" "${systemd_sources}/wireguard.key"
  (umask 0377; write_shared_exit_config "${systemd_unit%.service}" >"${systemd_sources}/laneway.toml")
  start_staged_systemd_exit "$1"
}

start_staged_systemd_exit() {
  local transport="$1" pid="" private_network
  install -m 0555 "${work_dir}/rust-node" "${systemd_runtime}/lanewayd-rs"
  printf 'nameserver 10.254.0.1\n' >"${systemd_runtime}/resolv.conf"
  chmod 0444 "${systemd_runtime}/resolv.conf"
  stage_exit_entrypoint "${systemd_runtime}"
  (
    # Record failures for disposable credentials in this lab only.
    systemd-run() {
      local argument
      local -a arguments=()
      for argument; do
        case "${argument}" in
          --property=StandardOutput=null) arguments+=(--property=StandardOutput=journal) ;;
          --property=StandardError=null) arguments+=(--property=StandardError=journal) ;;
          *) arguments+=("${argument}") ;;
        esac
      done
      command systemd-run "${arguments[@]}"
    }
    start_transient_exit "${systemd_unit}" "${systemd_runtime}" "${systemd_sources}" 5min
  ) || { systemd_failure 'could not start the transient Exit'; return 1; }
  pid="$(systemctl show -p MainPID --value "${systemd_unit}")"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || { systemd_failure 'transient Exit is not running'; return 1; }
  private_network="$(readlink "/proc/${pid}/ns/net")"
  [[ "${private_network}" != "$(readlink /proc/1/ns/net)" ]] ||
    { systemd_failure 'Exit shares the VM network namespace'; return 1; }

  if [[ -n "${lab_carrier_cleanup_unit:-}" ]]; then
    connect_lab_carrier "${pid}"
  else
    # Keep a handle to the unit's private netns after shutdown to check
    # teardown and move the fixture veths to the next unit.
    ip -n "${rust_ns}" link set eth0 netns "${pid}"
    ip -n "${rust_ns}" link set uplink0 netns "${pid}"
    ip netns delete "${rust_ns}"
    ip netns attach "${rust_ns}" "${pid}"
    ip -n "${rust_ns}" link set lo up
    ip -n "${rust_ns}" address add 10.254.0.3/24 dev eth0
    if [[ "${node_controller}" == rust ]]; then
      ip -n "${rust_ns}" address add "${location_node_ip}/28" dev eth0
    fi
    ip -n "${rust_ns}" address add 203.0.113.1/24 dev uplink0
    ip -n "${rust_ns}" link set eth0 up
    ip -n "${rust_ns}" link set uplink0 up
  fi
  ip netns exec "${rust_ns}" sysctl -qw net.ipv4.ip_forward=0
  if [[ "${transport}" == tcp ]]; then
    block_udp_relay
  fi
  touch -- "${systemd_runtime}/network.ready"

  for _ in $(seq 1 200); do
    if [[ "$(readlink "/proc/${pid}/exe" 2>/dev/null || true)" == "${systemd_runtime}/lanewayd-rs" ]] &&
      ip -n "${rust_ns}" link show dev lane0 >/dev/null 2>&1; then
      break
    fi
    systemctl is-active --quiet "${systemd_unit}" || break
    sleep 0.05
  done
  [[ "$(readlink "/proc/${pid}/exe" 2>/dev/null || true)" == "${systemd_runtime}/lanewayd-rs" ]] &&
    ip -n "${rust_ns}" link show dev lane0 >/dev/null 2>&1 ||
    { systemd_failure 'verified binary did not bring up the WireGuard device'; return 1; }
  [[ "$(systemctl show -p DynamicUser --value "${systemd_unit}")" == yes ]]
  [[ "$(systemctl show -p NoNewPrivileges --value "${systemd_unit}")" == yes ]]
  awk '$1 == "Uid:" { uid = $2 } $1 == "VmLck:" { lock = $2 } END { exit !(uid > 0 && lock > 0) }' "/proc/${pid}/status"
  local loaded="/proc/${pid}/root/run/credentials/${systemd_unit}"
  [[ -f "${loaded}/wireguard.key" && -f "${loaded}/config" ]]
  [[ "$(findmnt -n -N "${pid}" -o OPTIONS --mountpoint "/run/credentials/${systemd_unit}")" == ro,* ]]
  if [[ -n "${lab_carrier_cleanup_unit:-}" ]]; then
    install -m 0600 /dev/null "${lab_carrier_ready_path}"
  fi
  remove_systemd_sources
  rm -f -- "${systemd_runtime}/"{resolv.conf,entrypoint,lanewayd-rs,network.ready}
  echo "verified private systemd namespace, dynamic UID, locked memory and protected credentials"
}

verify_systemd_transport() {
  local transport="$1" tcp_connections
  tcp_connections="$(ip netns exec "${rust_ns}" ss -Htn state established 'dport = :4435')"
  if [[ "${transport}" == tcp ]]; then
    [[ -n "${tcp_connections}" ]]
  else
    [[ -z "${tcp_connections}" ]]
  fi
}

wait_systemd_drain() {
  local table="$1"
  for _ in $(seq 1 640); do
    if ip netns exec "${rust_ns}" nft list table inet "${table}" 2>/dev/null | grep -E 'ct state.*jump inbound' >/dev/null; then
      return 0
    fi
    systemctl is-active --quiet "${systemd_unit}" || break
    sleep 0.05
  done
  systemd_failure 'transient Exit did not enter drain mode'
}

wait_systemd_revocation() {
  for _ in $(seq 1 200); do
    if ! systemctl is-active --quiet "${systemd_unit}" &&
      ! ip -n "${rust_ns}" link show dev lane0 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  systemd_failure 'transient Exit survived revocation'
}

stop_systemd_exit() {
  local stopped_unit="${systemd_unit}"
  if systemctl is-active --quiet "${stopped_unit}"; then
    systemctl stop "${stopped_unit}"
  fi
  [[ ! -e "/run/credentials/${stopped_unit}" ]]
  [[ "$(ip netns exec "${rust_ns}" sysctl -n net.ipv4.ip_forward)" == 0 ]]
  if ip netns exec "${rust_ns}" nft list table inet laneway_rs_exit >/dev/null 2>&1; then
    echo 'ERROR: exit NAT rules survived transient unit shutdown' >&2
    return 1
  fi
  cleanup_systemd_exit
}
