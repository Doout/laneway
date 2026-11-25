#!/bin/sh -p
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH
IFS=$(printf ' \t\n_'); IFS=${IFS%_}
set -eu

for trusted_command_dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin; do
  [ -d "$trusted_command_dir" ] && [ ! -L "$trusted_command_dir" ] && \
    [ "$(/usr/bin/stat -c '%u:%g' "$trusted_command_dir")" = 0:0 ] || {
      echo "Laneway preparation: trusted command directory is unsafe: $trusted_command_dir" >&2
      exit 1
    }
  trusted_command_mode=$((0$(/usr/bin/stat -c %a "$trusted_command_dir")))
  [ $((trusted_command_mode & 0022)) -eq 0 ] || {
    echo "Laneway preparation: trusted command directory is writable by group or other: $trusted_command_dir" >&2
    exit 1
  }
done

umask 077
work=
output=
complete=false
output_claimed=false

die() { echo "Laneway preparation: $*" >&2; exit 1; }

[ "${TAR_OPTIONS+x}" != x ] || die "TAR_OPTIONS is not allowed"

cleanup() {
  if [ -n "$work" ] && [ -e "$work" ]; then
    find "$work" -depth -delete 2>/dev/null || true
  fi
  if [ "$complete" = false ] && [ "$output_claimed" = true ] && \
    [ -n "$output" ] && [ -e "$output" ]; then
    find "$output" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command in age age-keygen awk chmod date dirname find grep install laneway mkdir mktemp sha256sum stat sync tar; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done

if [ ! -d /dev/shm ] || [ -L /dev/shm ] || \
  [ "$(stat -c '%a:%u:%g' /dev/shm)" != 1777:0:0 ] || \
  ! awk '$2 == "/dev/shm" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts; then
  die "/dev/shm must be a root-owned sticky real tmpfs so plaintext offline-root material remains protected"
fi

trusted_directory_chain() {
  checked_path=$1
  while :; do
    [ -d "$checked_path" ] && [ ! -L "$checked_path" ] || return 1
    directory_stat=$(stat -c '%u:%g:%a' "$checked_path") || return 1
    directory_uid=${directory_stat%%:*}
    directory_remainder=${directory_stat#*:}
    directory_gid=${directory_remainder%%:*}
    directory_mode=${directory_remainder#*:}
    [ "$directory_uid" -eq 0 ] && [ "$directory_gid" -eq 0 ] || return 1
    directory_mode_value=$((0$directory_mode))
    if [ $((directory_mode_value & 0022)) -ne 0 ] && \
      [ "$directory_mode" != 1777 ]; then
      return 1
    fi
    [ "$checked_path" != / ] || break
    checked_path=$(dirname "$checked_path")
  done
}

resolve_new_output() {
  candidate=$1
  case "$candidate" in /*) ;; *) candidate=$(pwd -P)/$candidate ;; esac
  case "$candidate" in
    /|*/|*//*|*/./*|*/../*|*/.|*/..|*[!A-Za-z0-9_./-]*)
      die "output must be a canonical safe absolute path"
      ;;
  esac
  candidate_parent=${candidate%/*}
  candidate_leaf=${candidate##*/}
  [ -n "$candidate_parent" ] || candidate_parent=/
  physical_parent=$(CDPATH='' cd -- "$candidate_parent" 2>/dev/null && pwd -P) || \
    die "output parent must already exist"
  case "$physical_parent" in *[!A-Za-z0-9_./-]*) die "output parent resolves to an unsafe path" ;; esac
  trusted_directory_chain "$physical_parent" || \
    die "output parent ancestry must be root-owned and non-replaceable"
  if [ "$physical_parent" = / ]; then
    output=/$candidate_leaf
  else
    output=$physical_parent/$candidate_leaf
  fi
  case "$output" in
    /dev/shm|/dev/shm/*)
      die "recovery kit must be written to persistent storage outside /dev/shm"
      ;;
  esac
}

if [ "$#" -gt 1 ]; then
  die "usage: prepare-control-plane.sh [OUTPUT_DIRECTORY]"
fi
if [ "$#" -eq 1 ]; then
  requested_output=$1
else
  requested_output=$(pwd -P)/laneway-recovery-kit-$(date -u +%Y%m%dT%H%M%SZ)
fi
resolve_new_output "$requested_output"
if [ -e "$output" ] || [ -L "$output" ]; then
  die "output already exists; refusing to overwrite it: $output"
fi

mkdir "$output" 2>/dev/null || \
  die "output appeared before publication; refusing to reuse it: $output"
output_claimed=true
chmod 0700 "$output"
install -d -m 0700 "$output/control-plane-input"
work_candidate=$(mktemp -d /dev/shm/laneway-issuer.XXXXXX)
work=$work_candidate
[ "${work_candidate%/*}" = /dev/shm ] && [ -d "$work_candidate" ] && \
  [ ! -L "$work_candidate" ] || die "temporary issuer directory escaped /dev/shm"
[ "$(stat -c '%u:%g:%a' "$work")" = 0:0:700 ] || \
  die "temporary issuer directory must be root-owned with mode 0700"
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
