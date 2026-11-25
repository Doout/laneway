#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || exec sudo -n "$0" "$@"
repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
trusted_mock_dir=/usr/local/sbin
trusted_mocks=
cleanup() {
  for trusted_mock in $trusted_mocks; do
    [ ! -e "$trusted_mock" ] || find "$trusted_mock" -maxdepth 0 -delete
  done
  [ ! -e "$test_root" ] || find "$test_root" -depth -delete
}
trap cleanup EXIT HUP INT TERM

mock_bin=$test_root/bin
output=$test_root/recovery-kit
mkdir -p "$mock_bin"
recipient=age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq

cat > "$mock_bin/age-keygen" <<EOF
#!/bin/sh
case "\$1" in
  -o) printf 'AGE-SECRET-KEY-fixture\n' > "\$2" ;;
  -y) printf '%s\n' '$recipient' ;;
  *) exit 1 ;;
esac
EOF
cat > "$mock_bin/age" <<'EOF'
#!/bin/sh
output=
input=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --encrypt|-r) [ "$1" = -r ] && shift 2 || shift ;;
    -o) output=$2; shift 2 ;;
    *) input=$1; shift ;;
  esac
done
cp "$input" "$output"
EOF
cat > "$mock_bin/laneway" <<'EOF'
#!/bin/sh
test "$PATH" = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
test "${ENV+x}" != x
test "${BASH_ENV+x}" != x
test "${CDPATH+x}" != x
test "$1" = pki
operation=$2
shift 2
case "$operation" in
  init)
    while [ "$#" -gt 0 ]; do
      case "$1" in --out-dir) directory=$2; shift 2 ;; *) shift ;; esac
    done
    printf 'root certificate\n' > "$directory/ca.crt"
    printf 'root private key\n' > "$directory/ca.key"
    ;;
  intermediate)
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --out-cert) certificate=$2; shift 2 ;;
        --out-key) key=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    printf 'intermediate chain\n' > "$certificate"
    printf 'intermediate private key\n' > "$key"
    ;;
  verify-authority) ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$mock_bin"/*

publish_mock() {
  mock_name=$1
  mock_source=${2:-$mock_bin/$mock_name}
  mock_target=$trusted_mock_dir/$mock_name
  [ ! -e "$mock_target" ] && [ ! -L "$mock_target" ] || {
    echo "trusted mock target already exists: $mock_target" >&2
    exit 1
  }
  /usr/bin/install -m 0755 -o 0 -g 0 "$mock_source" "$mock_target"
  trusted_mocks="$mock_target $trusted_mocks"
}
for mock_name in age age-keygen laneway; do publish_mock "$mock_name"; done

PATH="$mock_bin:$PATH" ENV="$test_root/hostile-env" \
  BASH_ENV="$test_root/hostile-bash-env" CDPATH="$test_root" \
  "$repo_dir/deploy/compose/prepare-control-plane.sh" "$output" >/dev/null

test "$(stat -c %a "$output")" = 700
test "$(stat -c %a "$output/laneway-recovery.identity")" = 400
test "$(stat -c %a "$output/offline-root.tar.age")" = 600
test "$(stat -c %a "$output/control-plane-input/intermediate.key")" = 400
grep -Fx "$recipient" "$output/control-plane-input/recovery-recipient.txt" >/dev/null
test ! -e "$output/control-plane-input/ca.key"
tar -tf "$output/offline-root.tar.age" | grep -Fx 'offline-root/ca.key' >/dev/null
(cd "$output" && sha256sum -c MANIFEST.sha256 >/dev/null)

# Canonical, physical output resolution keeps recovery material off tmpfs even
# through aliases, and rejects writable ancestors before generating keys.
ln -s /dev/shm "$test_root/shm-alias"
for unsafe_output in \
  /tmp/../dev/shm/laneway-unsafe-output \
  "$test_root/shm-alias/laneway-unsafe-output"
do
  unsafe_name=$(printf '%s' "$unsafe_output" | tr '/.' '__')
  if PATH="$mock_bin:$PATH" "$repo_dir/deploy/compose/prepare-control-plane.sh" \
    "$unsafe_output" >/dev/null 2>"$test_root/$unsafe_name.err"; then
    echo "preparer accepted unsafe output $unsafe_output" >&2
    exit 1
  fi
  test ! -e /dev/shm/laneway-unsafe-output
done

unsafe_parent=$test_root/unsafe-parent
mkdir "$unsafe_parent"
chmod 0777 "$unsafe_parent"
if PATH="$mock_bin:$PATH" "$repo_dir/deploy/compose/prepare-control-plane.sh" \
  "$unsafe_parent/recovery" >/dev/null 2>"$test_root/unsafe-parent.err"; then
  echo "preparer accepted a replaceable output parent" >&2
  exit 1
fi
test ! -e "$unsafe_parent/recovery"

tar_options_output=$test_root/tar-options-output
if TAR_OPTIONS=--ignore-failed-read PATH="$mock_bin:$PATH" \
  "$repo_dir/deploy/compose/prepare-control-plane.sh" "$tar_options_output" \
  >/dev/null 2>"$test_root/tar-options.err"; then
  echo "preparer accepted ambient TAR_OPTIONS" >&2
  exit 1
fi
test ! -e "$tar_options_output"

# Inject an entry-claim race. The preparer must fail and must not clean the
# directory that the competing creator won.
race_bin=$test_root/race-bin
race_output=$test_root/raced-output
mkdir "$race_bin"
cat > "$race_bin/mkdir" <<'EOF'
#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = "$LANEWAY_TEST_RACE_OUTPUT" ]; then
  /bin/mkdir "$1"
  printf 'competitor\n' > "$1/owner"
  exit 1
fi
exec /bin/mkdir "$@"
EOF
chmod 0755 "$race_bin/mkdir"
publish_mock mkdir "$race_bin/mkdir"
if LANEWAY_TEST_RACE_OUTPUT="$race_output" PATH="$race_bin:$mock_bin:$PATH" \
  "$repo_dir/deploy/compose/prepare-control-plane.sh" "$race_output" \
  >/dev/null 2>"$test_root/race.err"; then
  echo "preparer won an injected output claim race" >&2
  exit 1
fi
grep -Fx competitor "$race_output/owner" >/dev/null

echo "Separate-host control-plane preparation keeps the offline root out of transfer input"
