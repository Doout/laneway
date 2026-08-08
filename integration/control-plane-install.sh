#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
cleanup() { [ ! -e "$test_root" ] || find "$test_root" -depth -delete; }
trap cleanup EXIT HUP INT TERM

source_dir=$test_root/package/deploy/compose
mock_bin=$test_root/bin
issuer_dir=$test_root/issuer
destination=$test_root/control-plane
log_file=$test_root/calls.log
counter_file=$test_root/id-counter
mkdir -p "$source_dir" "$mock_bin" "$issuer_dir"
printf '0.2.8\n' > "$test_root/package/VERSION"
cp "$repo_dir/deploy/compose/install-control-plane.sh" "$source_dir/install-control-plane.sh"
for name in compose.yaml bootstrap.sh preflight.sh prepare.sh recovery.sh validate.sh README.md; do
  printf 'fixture %s\n' "$name" > "$source_dir/$name"
done
cat > "$source_dir/lane" <<'EOF'
#!/bin/sh
printf 'lane %s\n' "$*" >> "$LANEWAY_TEST_LOG"
test "$1" = init
test "$2" = --issuer
test -d "$3"
EOF
chmod 0755 "$source_dir/lane" "$source_dir/install-control-plane.sh"
for name in ca.crt intermediate-chain.crt intermediate.key; do
  printf 'fixture %s\n' "$name" > "$issuer_dir/$name"
done

cat > "$mock_bin/docker" <<'EOF'
#!/bin/sh
test "$1" = compose
test "$2" = version
EOF
cat > "$mock_bin/age" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$mock_bin/getent" <<'EOF'
#!/bin/sh
test "$1" = ahosts
printf '203.0.113.10 STREAM %s\n' "$2"
EOF
cat > "$mock_bin/cosign" <<'EOF'
#!/bin/sh
printf 'cosign %s\n' "$*" >> "$LANEWAY_TEST_LOG"
test "$1" = verify
EOF
cat > "$mock_bin/curl" <<'EOF'
#!/bin/sh
destination=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) destination=$2; shift 2 ;;
    *) shift ;;
  esac
done
test -n "$destination"
cp "$LANEWAY_TEST_DIGESTS" "$destination"
EOF
cat > "$mock_bin/laneway" <<'EOF'
#!/bin/sh
test "$1" = id
count=$(cat "$LANEWAY_TEST_COUNTER")
case "$count" in
  0) value=000102030405060708090a0b0c0d0e0f ;;
  1) value=101112131415161718191a1b1c1d1e1f ;;
  2) value=202122232425262728292a2b2c2d2e2f ;;
  *) exit 1 ;;
esac
printf '%s\n' $((count + 1)) > "$LANEWAY_TEST_COUNTER"
printf '%s\n' "$value"
EOF
chmod 0755 "$mock_bin"/*

cat > "$test_root/image-digests.txt" <<'EOF'
ghcr.io/doout/laneway-admin@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ghcr.io/doout/laneway-controller@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ghcr.io/doout/laneway-exit-node@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
ghcr.io/doout/laneway-relay@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
EOF
printf '0\n' > "$counter_file"

recipient=age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_DEPLOY_DIR="$destination" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=deploy \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  "$source_dir/install-control-plane.sh" >/dev/null

test "$(stat -c %a "$destination")" = 700
test "$(stat -c %a "$destination/.env")" = 600
grep -Fx 'LANEWAY_VERSION=0.2.8' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_RELAY_PUBLIC_ENDPOINT=lane.example.test:4433' "$destination/.env" >/dev/null
grep -Fx 'LANEWAY_NETWORK_ID=000102030405060708090a0b0c0d0e0f' "$destination/.env" >/dev/null
test "$(grep -c '^cosign verify ' "$log_file")" -eq 4
grep -Fx "lane init --issuer $issuer_dir" "$log_file" >/dev/null

cancelled=$test_root/cancelled
printf '0\n' > "$counter_file"
if env \
  PATH="$mock_bin:$PATH" \
  LANEWAY_NONINTERACTIVE=true \
  LANEWAY_VERSION=0.2.8 \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_DEPLOY_DIR="$cancelled" \
  LANEWAY_BACKUP_RECIPIENT="$recipient" \
  LANEWAY_ISSUER_DIR="$issuer_dir" \
  LANEWAY_CONFIRM=no \
  LANEWAY_RELEASE_BASE_URL=https://release.invalid/v0.2.8 \
  LANEWAY_TEST_DIGESTS="$test_root/image-digests.txt" \
  LANEWAY_TEST_COUNTER="$counter_file" \
  LANEWAY_TEST_LOG="$log_file" \
  "$source_dir/install-control-plane.sh" >/dev/null 2>&1; then
  echo "installer accepted a deployment without explicit confirmation" >&2
  exit 1
fi
test ! -e "$cancelled"

echo "Interactive control-plane installer contract is valid"
