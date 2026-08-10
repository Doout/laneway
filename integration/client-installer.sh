#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d)
trap 'find "$work_dir" -depth -delete' EXIT HUP INT TERM
mkdir -p "$work_dir/bin" "$work_dir/fixture/darwin/laneway/bin" \
  "$work_dir/fixture/linux/laneway"

cat > "$work_dir/fixture/darwin/laneway/bin/laneway" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$LANEWAY_INSTALLER_TEST_RECORD"
EOF
chmod 0755 "$work_dir/fixture/darwin/laneway/bin/laneway"

cat > "$work_dir/fixture/linux/laneway/install.sh" <<'EOF'
#!/bin/sh
printf 'package install DESTDIR=%s PREFIX=%s\n' "$DESTDIR" "$PREFIX" \
  >> "$LANEWAY_INSTALLER_TEST_RECORD"
EOF
chmod 0755 "$work_dir/fixture/linux/laneway/install.sh"

tar -C "$work_dir/fixture/darwin" -czf "$work_dir/fixture/laneway_darwin_arm64.tar.gz" laneway
tar -C "$work_dir/fixture/linux" -czf "$work_dir/fixture/laneway_linux_arm64.tar.gz" laneway
(
  cd "$work_dir/fixture"
  sha256sum laneway_darwin_arm64.tar.gz laneway_linux_arm64.tar.gz > checksums.txt
)

cat > "$work_dir/bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf '%s\n' "$LANEWAY_INSTALLER_TEST_OS" ;;
  -m) echo arm64 ;;
  *) printf '%s\n' "$LANEWAY_INSTALLER_TEST_OS" ;;
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
  */laneway_darwin_arm64.tar.gz)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/laneway_darwin_arm64.tar.gz" "$output"
    ;;
  */laneway_linux_arm64.tar.gz)
    cp "$LANEWAY_INSTALLER_TEST_FIXTURE/laneway_linux_arm64.tar.gz" "$output"
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

darwin_record=$work_dir/darwin-record
darwin_output=$(env \
  PATH="$work_dir/bin:$PATH" \
  LANEWAY_DOMAIN=lane.example.test \
  LANEWAY_INSTALLER_TEST_OS=Darwin \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
  LANEWAY_INSTALLER_TEST_RECORD="$darwin_record" \
  sh "$repo_dir/install.sh")

grep -Fx 'configure --yes' "$darwin_record" >/dev/null
grep -Fx 'configure --check' "$darwin_record" >/dev/null
grep -F 'Laneway v9.8.7 is ready.' <<EOF >/dev/null
$darwin_output
EOF
grep -F 'laneway login lane.example.test' <<EOF >/dev/null
$darwin_output
EOF

linux_record=$work_dir/linux-record
env \
  PATH="$work_dir/bin:$PATH" \
  DESTDIR="$work_dir/linux-root" \
  LANEWAY_INSTALLER_TEST_OS=Linux \
  LANEWAY_INSTALLER_TEST_FIXTURE="$work_dir/fixture" \
  LANEWAY_INSTALLER_TEST_RECORD="$linux_record" \
  sh "$repo_dir/install.sh"

grep -Fx "package install DESTDIR=$work_dir/linux-root PREFIX=/usr/local" \
  "$linux_record" >/dev/null

echo "one installer detects, verifies, and installs Laneway on macOS and Linux"
