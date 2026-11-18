#!/usr/bin/env bash
# Sourced only by the marked systemd VM packet fixture.
# shellcheck disable=SC2154
packaged_node_owned=false
packaged_node_user=false
packaged_node_group=false
packaged_node_started=false
packaged_node_unit=/run/systemd/system/lanewayd-rs.service
packaged_node_dropin=/run/systemd/system/lanewayd-rs.service.d

cleanup_packaged_node() {
  [[ $packaged_node_owned == true ]] || return 0
  if [[ $packaged_node_started == true ]]; then
    systemctl stop lanewayd-rs.service || {
      echo 'Cannot stop the fixture unit; retain its files for lab inspection' >&2
      return 1
    }
    packaged_node_started=false
  fi
  systemctl reset-failed lanewayd-rs.service 2>/dev/null || true
  for path in "$packaged_node_unit" "$packaged_node_dropin" /usr/local/sbin/lanewayd-rs \
    /etc/laneway /run/laneway /var/lib/laneway; do
    if [[ -e "$path" ]]; then find "$path" -depth -delete; fi
  done
  systemctl daemon-reload
  if [[ $packaged_node_user == true ]]; then userdel laneway; fi
  if [[ $packaged_node_group == true ]] && getent group laneway >/dev/null; then groupdel laneway; fi
  packaged_node_owned=false
}

check_packaged_node() {
  local installed="$packaged_node/usr/local" path before after key_hash pid
  local cert=/var/lib/laneway/identity/node.crt key=/etc/laneway/node.key
  local log=/var/lib/laneway/fixture.log socket=/run/laneway/lanewayd.sock
  local probe_pid
  for path in "$packaged_node_unit" "$packaged_node_dropin" /usr/local/sbin/lanewayd-rs \
    /etc/laneway /run/laneway /var/lib/laneway; do
    [[ ! -e "$path" && ! -L "$path" ]] || { echo "refusing to replace $path" >&2; return 1; }
  done
  [[ $(systemctl show --property=LoadState --value lanewayd-rs.service) == not-found &&
    $(systemctl show --property=LoadState --value lanewayd.service) == not-found ]] ||
    { echo 'existing Laneway unit in systemd VM' >&2; return 1; }
  if getent passwd laneway >/dev/null || getent group laneway >/dev/null; then
    echo 'existing Laneway account in systemd VM' >&2
    return 1
  fi
  [[ -x "$installed/sbin/lanewayd-rs" && -x "$installed/sbin/laneway-healthcheck-rs" &&
    -f "$installed/lib/systemd/system/lanewayd-rs.service" ]] || return 1

  packaged_node_owned=true
  groupadd --system laneway
  packaged_node_group=true
  useradd --system --gid laneway --home-dir /var/lib/laneway --shell /usr/sbin/nologin laneway
  packaged_node_user=true
  install -m 0755 "$installed/sbin/lanewayd-rs" /usr/local/sbin/lanewayd-rs
  install -d -m 0750 -o root -g laneway /etc/laneway
  install -d -m 0700 -o laneway -g laneway /var/lib/laneway/identity
  install -m 0400 -o laneway -g laneway "$work_dir/pki/rust.crt" "$cert"
  install -m 0440 -o root -g laneway "$work_dir/pki/rust.key" "$key"
  install -m 0440 -o root -g laneway "$work_dir/pki/ca.crt" /etc/laneway/ca.crt
  sed -e "s@$work_dir/rust.sock@$socket@" -e "s@$work_dir/rust-exit-intent.json@/var/lib/laneway/exit-intent.json@" \
    -e "s@$work_dir/pki/rust.crt@$cert@" -e "s@$work_dir/pki/rust.key@$key@" \
    -e "s@$work_dir/pki/ca.crt@/etc/laneway/ca.crt@" "$work_dir/rust.toml" >"$work_dir/installed-node.toml"
  install -m 0440 -o root -g laneway "$work_dir/installed-node.toml" /etc/laneway/node-rust.toml
  install -m 0644 "$installed/lib/systemd/system/lanewayd-rs.service" "$packaged_node_unit"
  mkdir "$packaged_node_dropin"
  # The only lab settings are the isolated namespace and a captured log.
  cat >"$packaged_node_dropin/fixture.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/$rust_ns
Environment=RUST_LOG=info
StandardOutput=append:$log
StandardError=inherit
EOF
  systemctl daemon-reload

  start_process "$relay_ns" "$work_dir/relay.log" "$work_dir/laneway-relay" -config "$work_dir/relay.toml"
  wait_log "$last_pid" "$work_dir/relay.log" listening
  start_process "$gateway_ns" "$work_dir/gateway.log" "$work_dir/lanewayd" -config "$work_dir/gateway.toml"
  wait_log "$last_pid" "$work_dir/gateway.log" interface=lane0
  before=$("$work_dir/netprobe" certificate-info -cert "$cert")
  key_hash=$(sha256sum "$key")
  packaged_node_started=true
  systemctl start lanewayd-rs.service
  pid=$(systemctl show --property=MainPID --value lanewayd-rs.service)
  [[ $pid =~ ^[1-9][0-9]*$ ]]
  wait_log "$pid" "$log" 'renewed node certificate; restarting authenticated connections'
  [[ $(readlink "/proc/$pid/exe") == /usr/local/sbin/lanewayd-rs ]]
  [[ $(awk '/^Uid:/ {print $3}' "/proc/$pid/status") == "$(id -u laneway)" &&
    $(awk '/^Gid:/ {print $3}' "/proc/$pid/status") == "$(id -g laneway)" ]]
  after=$("$work_dir/netprobe" certificate-info -cert "$cert")
  [[ ${before% serial=*} == "${after% serial=*}" && ${before##* serial=} != "${after##* serial=}" ]]
  [[ $(sha256sum "$key") == "$key_hash" && $(stat -c '%u:%g:%a' "$cert") == "$(id -u laneway):$(id -g laneway):400" ]]

  start_process "$gateway_ns" "$work_dir/installed-node-udp.log" "$work_dir/netprobe" udp-server -listen "$gateway_address:9777"
  probe_pid=$last_pid
  wait_log "$probe_pid" "$work_dir/installed-node-udp.log" ready=udp-server
  ip netns exec "$rust_ns" "$work_dir/netprobe" udp-client -target "$gateway_address:9777" -message packaged-node -timeout 15s
  wait "$probe_pid"
  unset "active_processes[$probe_pid]"
  "$installed/sbin/laneway-healthcheck-rs" -unix "$socket"
  systemctl stop lanewayd-rs.service
  packaged_node_started=false
  [[ ! -e "$socket" ]] && ! ip -n "$rust_ns" link show lane0 >/dev/null 2>&1
  cleanup_packaged_node
  echo 'PASS: packaged systemd node renewed as laneway, exchanged traffic with a Go peer, and removed its socket and tunnel.'
}
