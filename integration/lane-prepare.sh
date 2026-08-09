#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "lane-prepare integration must run as root" >&2; exit 1; }
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'find "$test_dir" -depth -delete' EXIT HUP INT TERM
compose_dir=$test_dir/compose
issuer_dir=$test_dir/offline-export
fake_bin=$test_dir/bin
log=$test_dir/calls.log
mkdir -p "$compose_dir/generated/backups" "$issuer_dir" "$fake_bin"
cp "$repo_dir/deploy/compose/laneway-control" "$repo_dir/deploy/compose/prepare.sh" "$repo_dir/deploy/compose/preflight.sh" "$compose_dir/"
chmod 0755 "$compose_dir/laneway-control" "$compose_dir/prepare.sh" "$compose_dir/preflight.sh"
: > "$compose_dir/compose.yaml"
: > "$log"
printf '%s\n' root-public > "$issuer_dir/ca.crt"
printf '%s\n' issuer-chain > "$issuer_dir/intermediate-chain.crt"
printf '%s\n' issuer-private > "$issuer_dir/intermediate.key"
chmod 0400 "$issuer_dir/intermediate.key"

cat > "$compose_dir/validate.sh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' validate >> "$LANE_TEST_LOG"
EOF
cat > "$compose_dir/bootstrap.sh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' bootstrap >> "$LANE_TEST_LOG"
EOF
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
printf 'docker <%s>\n' "$*" >> "$LANE_TEST_LOG"
if [ "${1:-} ${2:-}" = "version --format" ]; then printf '26.1.0\n'; fi
EOF
cat > "$fake_bin/getent" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fake_bin/ss" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fake_bin/cosign" <<'EOF'
#!/bin/sh
set -eu
printf 'cosign <%s>\n' "$*" >> "$LANE_TEST_LOG"
EOF
cat > "$fake_bin/age" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fake_bin/laneway" <<'EOF'
#!/bin/sh
set -eu
printf 'laneway <%s>\n' "$*" >> "$LANE_TEST_LOG"
if [ "${1:-}" = id ]; then
  printf '%s\n' 0123456789abcdef0123456789abcdef
  exit 0
fi
if [ "${1:-} ${2:-}" = "pki verify-authority" ]; then exit 0; fi
case "${1:-} ${2:-}" in
  "pki controller"|"pki relay")
    out_cert=; out_key=
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --out-cert) out_cert=$2; shift 2 ;;
        --out-key) out_key=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    [ -n "$out_cert" ] && [ -n "$out_key" ]
    printf '%s\n' certificate > "$out_cert"
    printf '%s\n' private-key > "$out_key"
    ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$compose_dir/validate.sh" "$compose_dir/bootstrap.sh" "$fake_bin/docker" "$fake_bin/cosign" "$fake_bin/laneway" "$fake_bin/getent" "$fake_bin/ss" "$fake_bin/age"

cat > "$compose_dir/.env" <<'EOF'
LANEWAY_VERSION=1.0.0
LANEWAY_INSTALL_PROFILE=quick
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111
LANEWAY_RELAY_IMAGE_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333
LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:4444444444444444444444444444444444444444444444444444444444444444
LANEWAY_BIND_ADDRESS=127.0.0.1
LANEWAY_CONTROLLER_PORT=8443
LANEWAY_RELAY_QUIC_PORT=4433
LANEWAY_RELAY_TCP_PORT=443
LANEWAY_EXIT_DIRECT_PORT=4434
LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test
LANEWAY_NETWORK_ID=11111111111111111111111111111111
LANEWAY_CONTROLLER_SERVICE_ID=22222222222222222222222222222222
LANEWAY_RELAY_SERVICE_ID=33333333333333333333333333333333
LANEWAY_NETWORK_NAME=production
LANEWAY_IPV4_POOL=100.96.0.0/16
LANEWAY_RELAY_PUBLIC_ENDPOINT=relay.example.test:4433
LANEWAY_BACKUP_RECIPIENT=age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
chmod 0600 "$compose_dir/.env"
export PATH="$fake_bin:$PATH" LANE_TEST_LOG="$log"

"$compose_dir/laneway-control" init --issuer "$issuer_dir"
for path in \
  generated/config/controller.toml generated/config/relay.toml \
  generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/intermediate.key \
  generated/pki/controller.crt generated/pki/controller.key generated/pki/relay.crt generated/pki/relay.key \
  generated/secrets/admin.token
do
  if [ ! -f "$compose_dir/$path" ] || [ -L "$compose_dir/$path" ]; then
    echo "missing prepared $path" >&2
    exit 1
  fi
done
for path in generated/pki/intermediate.key generated/pki/controller.key generated/pki/relay.key generated/secrets/admin.token; do
  [ "$(stat -c '%a:%u:%g' "$compose_dir/$path")" = 400:65532:65532 ] || { echo "unsafe ownership for $path" >&2; exit 1; }
done
for path in generated/config/controller.toml generated/config/relay.toml generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/controller.crt generated/pki/relay.crt; do
  [ "$(stat -c '%a:%u:%g' "$compose_dir/$path")" = 444:0:0 ] || { echo "unsafe public material mode for $path" >&2; exit 1; }
done
grep -F 'network_id = "11111111111111111111111111111111"' "$compose_dir/generated/config/relay.toml" >/dev/null
grep -F 'server_name = "lane.example.test"' "$compose_dir/generated/config/relay.toml" >/dev/null
[ ! -e "$compose_dir/generated/pki/ca.key" ]
[ "$(grep -c 'pki controller' "$log")" -eq 1 ]
[ "$(grep -c 'pki relay' "$log")" -eq 1 ]

"$compose_dir/laneway-control" init --issuer "$issuer_dir"
[ "$(grep -c 'pki controller' "$log")" -eq 1 ] || { echo "idempotent init reissued controller identity" >&2; exit 1; }

printf '%s\n' forbidden-root-key > "$issuer_dir/ca.key"
if "$compose_dir/laneway-control" init --issuer "$issuer_dir" >/dev/null 2>&1; then
  echo "init accepted an offline root private key" >&2
  exit 1
fi

echo "Lane clean init preserves the offline-root boundary and restrictive ownership"
