#!/usr/bin/env bash
# The fake host has no route out of the test topology. The installer still
# creates the actual carrier and the system manager runs its real cleanup.

lab_carrier_namespace=""
lab_carrier_cleanup_unit=""

prepare_lab_carrier() {
  local carrier_source="81.2.69.138"
  lab_carrier_namespace="${prefix}h"
  lab_original_forwarding="$(sysctl -n net.ipv4.ip_forward)"
  add_namespace "${lab_carrier_namespace}"
  attach_switch "${lab_carrier_namespace}" eth0 10.254.0.5/24
  ip -n "${lab_carrier_namespace}" address add "${carrier_source}/28" dev eth0
  attach_wireguard_uplink "${lab_carrier_namespace}" egress0
  ip netns exec "${lab_carrier_namespace}" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "${controller_ns}" nft add rule ip lab_health prerouting \
    iifname eth0 ip saddr "${carrier_source}" ip daddr "${location_controller_ip}" tcp dport 9443 dnat to 127.0.0.1:9443

  # Exercise the Docker forwarding branch and leave a separate rule in the
  # chain as an ownership sentinel for the cleanup.
  ip netns exec "${lab_carrier_namespace}" iptables -N DOCKER-USER
  ip netns exec "${lab_carrier_namespace}" iptables -A FORWARD -j DOCKER-USER
  ip netns exec "${lab_carrier_namespace}" iptables -P FORWARD DROP
  ip netns exec "${lab_carrier_namespace}" iptables -A DOCKER-USER \
    -m comment --comment lab-unrelated-rule -j RETURN
  ip netns exec "${lab_carrier_namespace}" nft list chain ip filter DOCKER-USER >/dev/null
  lab_carrier_docker_baseline="$(ip netns exec "${lab_carrier_namespace}" iptables -S DOCKER-USER)"

  local transient_name="${systemd_unit%.service}" work cleanup_unit
  work="$(mktemp -d /run/laneway-lab-carrier.XXXXXX)"
  cleanup_unit="${transient_name}-cleanup.service"
  lab_carrier_cleanup_path="/run/.${transient_name}.cleanup"
  lab_carrier_ready_path="/run/.${transient_name}.cleanup.ready"
  describe_exit_carrier "${transient_name}"
  stage_exit_cleanup "${work}" "${systemd_runtime}" "${systemd_unit}" \
    "${lab_carrier_cleanup_path}" "${lab_carrier_ready_path}"
  # Only relocate the fake host's network. Keep the shared /run mount so
  # unmounting the exit's tmpfs affects the test VM's main mount namespace.
  start_exit_cleanup "${cleanup_unit}" "${lab_carrier_cleanup_path}" \
    --property="NetworkNamespacePath=/run/netns/${lab_carrier_namespace}" --property=PrivateMounts=no
  lab_carrier_cleanup_unit="${cleanup_unit}"
}

connect_lab_carrier() {
  local pid="$1"
  ip netns exec "${lab_carrier_namespace}" bash -euo pipefail -c '
    source "$1"
    describe_exit_carrier "$2"
    attach_exit_carrier "$3"
  ' bash "${repo_root}/deploy/ephemeral-exit/bootstrap.sh" "${systemd_unit%.service}" "${pid}"
  # Retire the enrollment-only namespace. All runtime packets must use the
  # carrier created by the installer, not the initial connection to the bridge.
  ip netns delete "${rust_ns}"
  ip netns attach "${rust_ns}" "${pid}"
  ip -n "${rust_ns}" -j route show default |
    jq -e --arg gateway "${carrier_host}" 'length==1 and .[0].dev=="uplink0" and .[0].gateway==$gateway' >/dev/null
  ip netns exec "${lab_carrier_namespace}" iptables -C DOCKER-USER -i "${host_if}" \
    -m comment --comment "${marker}" -j ACCEPT
  ip netns exec "${lab_carrier_namespace}" iptables -C DOCKER-USER -o "${host_if}" \
    -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "${marker}" -j ACCEPT
}

finish_lab_carrier() {
  # Also let cleanup proceed when a failed test never got as far as readiness.
  if [[ -e "${lab_carrier_cleanup_path}" && ! -e "${lab_carrier_ready_path}" ]]; then
    install -m 0600 /dev/null "${lab_carrier_ready_path}"
  fi
  for _ in $(seq 1 100); do
    if [[ ! -e "${lab_carrier_cleanup_path}" && ! -e "${lab_carrier_ready_path}" && ! -e "${systemd_runtime}" ]] &&
      ! systemctl is-active --quiet "${lab_carrier_cleanup_unit}"; then
      lab_carrier_cleanup_unit=""
      return 0
    fi
    sleep 0.05
  done
  echo 'ERROR: installer cleanup did not remove the transient runtime' >&2
  systemctl status --no-pager "${lab_carrier_cleanup_unit}" >&2 || true
  return 1
}

verify_lab_carrier_cleanup() {
  if ip -n "${lab_carrier_namespace}" link show dev "${host_if}" >/dev/null 2>&1 ||
    ip netns exec "${lab_carrier_namespace}" nft list table inet "${nft_table}" >/dev/null 2>&1; then
    echo 'ERROR: a Laneway carrier interface or firewall table survived cleanup' >&2
    return 1
  fi
  ip -n "${lab_carrier_namespace}" link show dev egress0 >/dev/null
  [[ "$(ip netns exec "${lab_carrier_namespace}" iptables -S DOCKER-USER)" == "${lab_carrier_docker_baseline}" ]]
  [[ "$(sysctl -n net.ipv4.ip_forward)" == "${lab_original_forwarding}" ]]
  echo 'verified carrier cleanup preserved unrelated forwarding state'
}
