#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
cleanup() { [ ! -e "$test_root" ] || find "$test_root" -depth -delete; }
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

PATH="$mock_bin:$PATH" "$repo_dir/deploy/compose/prepare-control-plane.sh" "$output" >/dev/null

test "$(stat -c %a "$output")" = 700
test "$(stat -c %a "$output/laneway-recovery.identity")" = 400
test "$(stat -c %a "$output/offline-root.tar.age")" = 600
test "$(stat -c %a "$output/control-plane-input/intermediate.key")" = 400
grep -Fx "$recipient" "$output/control-plane-input/recovery-recipient.txt" >/dev/null
test ! -e "$output/control-plane-input/ca.key"
tar -tf "$output/offline-root.tar.age" | grep -Fx 'offline-root/ca.key' >/dev/null
(cd "$output" && sha256sum -c MANIFEST.sha256 >/dev/null)

echo "Separate-host control-plane preparation keeps the offline root out of transfer input"
