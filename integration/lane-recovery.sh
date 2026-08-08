#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "lane-recovery integration must run as root" >&2; exit 1; }
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d)
trap 'find "$test_dir" -depth -delete' EXIT HUP INT TERM
fake_bin=$test_dir/bin
source_dir=$test_dir/source
fresh_dir=$test_dir/fresh
mkdir -p "$fake_bin" "$source_dir/generated/config" "$source_dir/generated/pki" \
  "$source_dir/generated/secrets" "$source_dir/generated/backups"

if [ "${LANE_TEST_REAL_AGE:-0}" = 0 ]; then
  cat > "$fake_bin/age" <<'EOF'
#!/bin/sh
set -eu
output=; input=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --encrypt|--decrypt) shift ;;
    -r|-i) shift 2 ;;
    -o) output=$2; shift 2 ;;
    *) input=$1; shift ;;
  esac
done
[ -n "$output" ] && [ -n "$input" ]
cp "$input" "$output"
EOF
  chmod 0755 "$fake_bin/age"
fi
cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
case " $* " in
  *" ps --status running -q controller "*)
    [ "${LANE_TEST_CONTROLLER_RUNNING:-0}" = 0 ] || printf '%s\n' controller-id
    ;;
  *" -backup /backups/"*)
    name=${*##* /backups/}; name=${name%% *}
    printf '%s\n' sqlite-backup > "$LANE_TEST_BASE/generated/backups/$name"
    printf '%s\n' sqlite-wal > "$LANE_TEST_BASE/generated/backups/$name-wal"
    printf '%s\n' sqlite-shm > "$LANE_TEST_BASE/generated/backups/$name-shm"
    printf '%s\n' sqlite-journal > "$LANE_TEST_BASE/generated/backups/$name-journal"
    chmod 0600 "$LANE_TEST_BASE/generated/backups/$name"
    chown 65532:65532 "$LANE_TEST_BASE/generated/backups/$name"
    [ "${LANE_TEST_BACKUP_FAIL:-0}" = 0 ] || exit 1
    ;;
  *" -restore /backups/"*)
    name=${*##* /backups/}; name=${name%% *}
    printf '%s\n' sqlite-wal > "$LANE_TEST_BASE/generated/backups/$name-wal"
    printf '%s\n' sqlite-shm > "$LANE_TEST_BASE/generated/backups/$name-shm"
    printf '%s\n' sqlite-journal > "$LANE_TEST_BASE/generated/backups/$name-journal"
    printf '%s\n' restored > "$LANE_TEST_BASE/restored.db"
    ;;
esac
EOF
chmod 0755 "$fake_bin/docker"

install_runtime() {
  destination=$1
  cp "$repo_dir/deploy/compose/recovery.sh" "$destination/recovery.sh"
  cp "$repo_dir/deploy/compose/validate.sh" "$destination/validate.sh"
  chmod 0755 "$destination/recovery.sh" "$destination/validate.sh"
  : > "$destination/compose.yaml"
}
install_runtime "$source_dir"

identity=$test_dir/identity.txt
if [ "${LANE_TEST_REAL_AGE:-0}" = 1 ]; then
  command -v age >/dev/null 2>&1
  command -v age-keygen >/dev/null 2>&1
  age-keygen -o "$identity" >/dev/null
  recipient=$(age-keygen -y "$identity")
else
  recipient=age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  printf '%s\n' AGE-SECRET-KEY-TEST > "$identity"
fi
chmod 0400 "$identity"
cat > "$source_dir/.env" <<EOF
LANEWAY_VERSION=1.0.0
LANEWAY_CONTROLLER_IMAGE_DIGEST=sha256:1111111111111111111111111111111111111111111111111111111111111111
LANEWAY_RELAY_IMAGE_DIGEST=sha256:2222222222222222222222222222222222222222222222222222222222222222
LANEWAY_ADMIN_IMAGE_DIGEST=sha256:3333333333333333333333333333333333333333333333333333333333333333
LANEWAY_EXIT_NODE_IMAGE_DIGEST=sha256:4444444444444444444444444444444444444444444444444444444444444444
LANEWAY_CONTROLLER_SERVER_NAME=lane.example.test
LANEWAY_NETWORK_ID=11111111111111111111111111111111
LANEWAY_CONTROLLER_SERVICE_ID=22222222222222222222222222222222
LANEWAY_RELAY_SERVICE_ID=33333333333333333333333333333333
LANEWAY_NETWORK_NAME=production
LANEWAY_IPV4_POOL=100.96.0.0/16
LANEWAY_RELAY_PUBLIC_ENDPOINT=relay.example.test:4433
LANEWAY_BACKUP_RECIPIENT=$recipient
EOF
chmod 0600 "$source_dir/.env"
for relative in \
  generated/config/controller.toml generated/config/relay.toml generated/config/exit-node.toml \
  generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/controller.crt \
  generated/pki/relay.crt generated/pki/exit-node.crt; do
  printf '%s\n' "$relative" > "$source_dir/$relative"
  chmod 0444 "$source_dir/$relative"
done
for relative in \
  generated/pki/intermediate.key generated/pki/controller.key generated/pki/relay.key \
  generated/pki/exit-node.key generated/secrets/admin.token; do
  printf '%s\n' "$relative" > "$source_dir/$relative"
  chmod 0400 "$source_dir/$relative"
  chown 65532:65532 "$source_dir/$relative"
done

export PATH="$fake_bin:$PATH" LANE_TEST_BASE="$source_dir"
"$source_dir/recovery.sh" backup control-recovery.age
if find "$source_dir/generated/backups" -mindepth 1 -maxdepth 1 -print | grep .; then
  echo "recovery backup left plaintext database staging files" >&2
  exit 1
fi
bundle=$test_dir/control-recovery.age
cp "$source_dir/generated/recovery/control-recovery.age" "$bundle"
[ "$(stat -c '%a:%u:%g' "$source_dir/generated/recovery/control-recovery.age")" = 600:0:0 ]
if "$source_dir/recovery.sh" backup control-recovery.age >/dev/null 2>&1; then
  echo "recovery backup overwrote an existing bundle" >&2
  exit 1
fi

LANE_TEST_BACKUP_FAIL=1; export LANE_TEST_BACKUP_FAIL
if "$source_dir/recovery.sh" backup failed-recovery.age >/dev/null 2>&1; then
  echo "recovery backup accepted a failed database snapshot" >&2
  exit 1
fi
unset LANE_TEST_BACKUP_FAIL
[ ! -e "$source_dir/generated/recovery/failed-recovery.age" ]
if find "$source_dir/generated/backups" -mindepth 1 -maxdepth 1 -print | grep .; then
  echo "failed recovery backup left plaintext database staging files" >&2
  exit 1
fi

mkdir -p "$fresh_dir"
install_runtime "$fresh_dir"
LANE_TEST_BASE=$fresh_dir; export LANE_TEST_BASE
"$fresh_dir/recovery.sh" restore "$bundle" "$identity"
[ -f "$fresh_dir/restored.db" ]
if find "$fresh_dir/generated/backups" -mindepth 1 -maxdepth 1 -print | grep .; then
  echo "recovery restore left plaintext database staging files" >&2
  exit 1
fi
for relative in \
  .env generated/config/controller.toml generated/config/relay.toml generated/config/exit-node.toml \
  generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/intermediate.key \
  generated/pki/controller.crt generated/pki/controller.key generated/pki/relay.crt generated/pki/relay.key \
  generated/pki/exit-node.crt generated/pki/exit-node.key generated/secrets/admin.token; do
  if [ ! -f "$fresh_dir/$relative" ] || [ -L "$fresh_dir/$relative" ]; then
    echo "fresh restore omitted $relative" >&2
    exit 1
  fi
done
[ "$(stat -c '%a:%u:%g' "$fresh_dir/generated/pki/intermediate.key")" = 400:65532:65532 ]
[ "$(stat -c '%a:%u:%g' "$fresh_dir/generated/config/controller.toml")" = 444:0:0 ]

if [ "${LANE_TEST_REAL_AGE:-0}" = 1 ]; then
  tampered=$test_dir/tampered.age
  cp "$bundle" "$tampered"
  printf '%s\n' tampered >> "$tampered"
  tamper_dir=$test_dir/tamper-target
  mkdir -p "$tamper_dir"
  install_runtime "$tamper_dir"
  LANE_TEST_BASE=$tamper_dir; export LANE_TEST_BASE
  if "$tamper_dir/recovery.sh" restore "$tampered" "$identity" >/dev/null 2>&1; then
    echo "recovery restore accepted tampered age ciphertext" >&2
    exit 1
  fi
  [ ! -e "$tamper_dir/.env" ]
else
  forged=$test_dir/forged.age
  cp "$bundle" "$forged"
  printf '%s\n' unexpected > "$test_dir/unexpected"
  tar -rf "$forged" -C "$test_dir" unexpected
  forged_dir=$test_dir/forged-target
  mkdir -p "$forged_dir"
  install_runtime "$forged_dir"
  LANE_TEST_BASE=$forged_dir; export LANE_TEST_BASE
  if "$forged_dir/recovery.sh" restore "$forged" "$identity" >/dev/null 2>&1; then
    echo "recovery restore accepted an unexpected archive entry" >&2
    exit 1
  fi
  [ ! -e "$forged_dir/.env" ]
fi

foreign_dir=$test_dir/foreign
mkdir -p "$foreign_dir"
install_runtime "$foreign_dir"
printf '%s\n' foreign > "$foreign_dir/.env"
LANE_TEST_BASE=$foreign_dir; export LANE_TEST_BASE
if "$foreign_dir/recovery.sh" restore "$bundle" "$identity" >/dev/null 2>&1; then
  echo "recovery restore overwrote foreign state" >&2
  exit 1
fi
grep -Fx foreign "$foreign_dir/.env" >/dev/null

running_dir=$test_dir/running
mkdir -p "$running_dir"
install_runtime "$running_dir"
LANE_TEST_BASE=$running_dir LANE_TEST_CONTROLLER_RUNNING=1
export LANE_TEST_BASE LANE_TEST_CONTROLLER_RUNNING
if "$running_dir/recovery.sh" restore "$bundle" "$identity" >/dev/null 2>&1; then
  echo "recovery restore accepted a running controller" >&2
  exit 1
fi
[ ! -e "$running_dir/.env" ]

echo "Encrypted recovery bundles restore complete fixed-UID state without overwriting foreign state"
