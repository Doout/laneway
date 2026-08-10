#!/bin/sh
set -eu

die() { echo "laneway connector: $*" >&2; exit 1; }
required() {
  [ -n "$2" ] || die "required environment variable is missing: $1"
}

state_dir=/var/lib/laneway/connector
config_file=$state_dir/connector.toml
ca_file=$state_dir/ca.crt
cert_file=$state_dir/node.crt
key_file=$state_dir/node.key
wireguard_key_file=$state_dir/wireguard.key

# Packaged Compose deployments already provide identity files and an explicit
# config argument. Preserve that mode while the public Connector image uses the
# environment-driven first-run path below.
if [ "$#" -gt 0 ]; then
  exec /bin/setpriv --inh-caps=+net_admin --ambient-caps=+net_admin --no-new-privs \
    /sbin/tini -- /usr/local/bin/laneway node run "$@"
fi

identity_count=0
for path in "$config_file" "$ca_file" "$cert_file" "$key_file" "$wireguard_key_file"; do
  [ ! -f "$path" ] || identity_count=$((identity_count + 1))
done

if [ "$identity_count" -ne 5 ]; then
  [ "$identity_count" -eq 0 ] || die "persistent volume contains an incomplete Connector identity"
  required SETUP_TOKEN "${SETUP_TOKEN:-}"
  /usr/local/bin/laneway connector activate --setup-token "$SETUP_TOKEN" --state-dir "$state_dir"
fi

unset SETUP_TOKEN
exec /sbin/tini -- /usr/local/bin/laneway node run -config "$config_file"
