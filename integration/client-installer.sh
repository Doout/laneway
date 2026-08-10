#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d)
trap 'find "$work_dir" -depth -delete' EXIT HUP INT TERM
mkdir -p "$work_dir/bin" "$work_dir/fixture"

cat > "$work_dir/fixture/laneway_darwin_arm64" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$LANEWAY_INSTALLER_TEST_RECORD"
EOF
chmod 0755 "$work_dir/fixture/laneway_darwin_arm64"
(
  cd "$work_dir/fixture"
  shasum -a 256 laneway_darwin_arm64 > checksums.txt
)

cat > "$work_dir/bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) echo Darwin ;;
  -m) echo arm64 ;;
  *) echo Darwin ;;
esac
EOF
cat > "$work_dir/bin/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = -u ] && { echo 501; exit 0; }
exit 1
EOF
cat > "$work_dir/bin/sudo" <<'EOF'
#!/bin/sh
echo "test installer unexpectedly invoked sudo itself" >&2
exit 1
EOF
cat > "$work_dir/bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o|--output) output=$2; shift 2 ;;
    --header|--write-out|--proto) shift 2 ;;
    --tlsv1.2|--fail|--location|--silent|--show-error) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */releases/latest\?laneway_cache_bust=*)
    [ "$output" = /dev/null ]
    printf '%s' 'https://github.com/Doout/laneway/releases/tag/v9.8.7'
    ;;
  */laneway_darwin_arm64)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/laneway_darwin_arm64" "$output"
    ;;
  */checksums.txt)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/checksums.txt" "$output"
    ;;
  *)
    echo "unexpected installer URL: $url" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 "$work_dir/bin/"*

record=$work_dir/configure-record
output=$(env \
  PATH="$work_dir/bin:$PATH" \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
  LANEWAY_INSTALLER_TEST_RECORD="$record" \
  sh "$repo_dir/install-client.sh")

grep -Fx 'configure --yes' "$record" >/dev/null
grep -Fx 'configure --check' "$record" >/dev/null
grep -F 'Laneway v9.8.7 is ready.' <<EOF >/dev/null
$output
EOF

echo "macOS one-line client installer detects, verifies, configures, and checks the client"
