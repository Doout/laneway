#!/bin/sh
set -eu

umask 077
work=
output=
complete=false

die() { echo "Laneway preparation: $*" >&2; exit 1; }

cleanup() {
  if [ -n "$work" ] && [ -e "$work" ]; then
    find "$work" -depth -delete 2>/dev/null || true
  fi
  if [ "$complete" = false ] && [ -n "$output" ] && [ -e "$output" ]; then
    find "$output" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command in age age-keygen awk date find grep install laneway mktemp sha256sum sync tar; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done

if [ ! -d /dev/shm ] || [ -L /dev/shm ] || \
  ! awk '$2 == "/dev/shm" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts; then
  die "/dev/shm must be a real tmpfs so plaintext offline-root material never reaches persistent storage"
fi

if [ "$#" -gt 1 ]; then
  die "usage: prepare-control-plane.sh [OUTPUT_DIRECTORY]"
fi
if [ "$#" -eq 1 ]; then
  output=$1
else
  output=$PWD/laneway-recovery-kit-$(date -u +%Y%m%dT%H%M%SZ)
fi
case "$output" in /*) ;; *) output=$PWD/$output ;; esac
case "$output" in /|/dev/shm|/dev/shm/*) die "recovery kit must be written to persistent storage outside /dev/shm" ;; esac
if [ -e "$output" ] || [ -L "$output" ]; then
  die "output already exists; refusing to overwrite it: $output"
fi

install -d -m 0700 "$output" "$output/control-plane-input"
work=$(mktemp -d /dev/shm/laneway-issuer.XXXXXX)
chmod 0700 "$work"
install -d -m 0700 "$work/offline-root" "$work/issuer-export"

age-keygen -o "$output/laneway-recovery.identity" >/dev/null
chmod 0400 "$output/laneway-recovery.identity"
recipient=$(age-keygen -y "$output/laneway-recovery.identity")
printf '%s\n' "$recipient" | grep -Eq '^age1[0-9a-z]{58}$' || die "age-keygen produced an invalid recovery recipient"

laneway pki init --out-dir "$work/offline-root" --name "Laneway Offline Root"
laneway pki intermediate \
  --ca-cert "$work/offline-root/ca.crt" \
  --ca-key "$work/offline-root/ca.key" \
  --out-cert "$work/issuer-export/intermediate-chain.crt" \
  --out-key "$work/issuer-export/intermediate.key"
install -m 0444 "$work/offline-root/ca.crt" "$work/issuer-export/ca.crt"
laneway pki verify-authority \
  --root "$work/issuer-export/ca.crt" \
  --issuer "$work/issuer-export/intermediate-chain.crt" \
  --key "$work/issuer-export/intermediate.key"

(
  cd "$work"
  tar -cf offline-root.tar offline-root/ca.crt offline-root/ca.key
)
age --encrypt -r "$recipient" -o "$output/offline-root.tar.age" "$work/offline-root.tar"
chmod 0600 "$output/offline-root.tar.age"

install -m 0444 "$work/issuer-export/ca.crt" "$output/control-plane-input/ca.crt"
install -m 0444 "$work/issuer-export/intermediate-chain.crt" "$output/control-plane-input/intermediate-chain.crt"
install -m 0400 "$work/issuer-export/intermediate.key" "$output/control-plane-input/intermediate.key"
printf '%s\n' "$recipient" > "$output/control-plane-input/recovery-recipient.txt"
chmod 0444 "$output/control-plane-input/recovery-recipient.txt"

cat > "$output/README.txt" <<'EOF'
LANEWAY CONTROL-PLANE RECOVERY KIT

Keep this directory private and backed up. It contains the age identity needed
to decrypt Laneway recovery bundles and an encrypted copy of the offline root.

For a separate-host preparation flow, copy ONLY control-plane-input/ to the
production server. Never copy laneway-recovery.identity or offline-root.tar.age
to the production server. Delete the copied input after installation succeeds.

To inspect the encrypted offline root during disaster recovery:
  age --decrypt -i laneway-recovery.identity -o offline-root.tar offline-root.tar.age
  install -d -m 0700 restored-offline-root
  tar -xf offline-root.tar -C restored-offline-root
  rm -f offline-root.tar

The decrypted ca.key is the offline root private key. Never install it on a
controller, relay, or node.
EOF
chmod 0600 "$output/README.txt"
(
  cd "$output"
  sha256sum README.txt laneway-recovery.identity offline-root.tar.age \
    control-plane-input/ca.crt control-plane-input/intermediate-chain.crt \
    control-plane-input/intermediate.key control-plane-input/recovery-recipient.txt > MANIFEST.sha256
)
chmod 0600 "$output/MANIFEST.sha256"
sync -f "$output/MANIFEST.sha256"
sync -f "$output"

complete=true
cat <<EOF

Laneway recovery kit created:
  $output

Back up that entire directory securely.

For a separate production server, copy only:
  $output/control-plane-input

At the production installer's prepared-input prompt, enter the copied
control-plane-input directory. Never copy laneway-recovery.identity or
offline-root.tar.age to the production server.
EOF
