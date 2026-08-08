#!/bin/sh
set -eu

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
env_file=$base_dir/.env
backup_dir=$base_dir/generated/backups
recovery_dir=$base_dir/generated/recovery
work=
published=
database_snapshot=
umask 077

cleanup() {
  if [ -n "$published" ]; then
    for path in $published; do
      [ ! -e "$path" ] || find "$path" -maxdepth 0 -delete
    done
  fi
  [ -z "$database_snapshot" ] || [ ! -e "$database_snapshot" ] || find "$database_snapshot" -maxdepth 0 -delete
  [ -z "$work" ] || [ ! -e "$work" ] || find "$work" -depth -delete
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

die() { echo "lane recovery: $*" >&2; exit 1; }
compose() {
  docker compose --project-directory "$base_dir" --env-file "$env_file" -f "$base_dir/compose.yaml" "$@"
}
read_setting() {
  key=$1
  value=$(sed -n "s/^${key}=//p" "$env_file")
  [ -n "$value" ] && [ "$(printf '%s\n' "$value" | wc -l)" -eq 1 ] || die "missing or duplicate $key in .env"
  printf '%s' "$value"
}
validate_name() {
  case "$1" in ''|.*|*/*|*[!A-Za-z0-9._-]*|*.age.*) die "bundle name must be a simple NAME.age" ;; esac
  case "$1" in *.age) ;; *) die "bundle name must end in .age" ;; esac
}
require_regular() {
  [ -f "$1" ] && [ ! -L "$1" ] || die "required regular file is missing or unsafe: $1"
}

[ "$(id -u)" -eq 0 ] || die "run as root to read and restore fixed-UID secrets safely"
for command in age chown docker find grep install sed sha256sum sort sync tar; do
  command -v "$command" >/dev/null 2>&1 || die "required command is missing: $command"
done

case "${1:-}" in
  backup)
    [ "$#" -eq 2 ] || die "usage: recovery.sh backup NAME.age"
    name=$2; validate_name "$name"
    require_regular "$env_file"
    recipient=$(read_setting LANEWAY_BACKUP_RECIPIENT)
    printf '%s\n' "$recipient" | grep -Eq '^age1[0-9a-z]{58}$' || die "LANEWAY_BACKUP_RECIPIENT must be an age X25519 recipient"
    [ ! -e "$recovery_dir/$name" ] && [ ! -L "$recovery_dir/$name" ] || die "recovery bundle already exists: $name"
    "$base_dir/validate.sh"
    install -d -m 0700 "$backup_dir"
    chown 65532:65532 "$backup_dir"
    if [ -e "$recovery_dir" ] || [ -L "$recovery_dir" ]; then
      [ -d "$recovery_dir" ] && [ ! -L "$recovery_dir" ] || die "generated/recovery must be a real directory"
    fi
    install -d -m 0700 -o 0 -g 0 "$recovery_dir"
    work=$(mktemp -d "$base_dir/generated/.recovery-backup.XXXXXX")
    install -d -m 0700 "$work/database" "$work/generated/config" "$work/generated/pki" "$work/generated/secrets"
    database_name=.lane-recovery-$PPID-$$.db
    database_snapshot=$backup_dir/$database_name
    compose run --rm --no-deps controller -config /etc/laneway/controller.toml -backup "/backups/$database_name"
    require_regular "$database_snapshot"
    install -m 0600 "$database_snapshot" "$work/database/controller.db"
    find "$database_snapshot" -maxdepth 0 -delete
    database_snapshot=

    files="
generated/config/controller.toml
generated/config/relay.toml
generated/pki/ca.crt
generated/pki/intermediate-chain.crt
generated/pki/intermediate.key
generated/pki/controller.crt
generated/pki/controller.key
generated/pki/relay.crt
generated/pki/relay.key
generated/secrets/admin.token"
    install -m 0600 "$env_file" "$work/.env"
    for relative in $files; do
      require_regular "$base_dir/$relative"
      install -D -m 0600 "$base_dir/$relative" "$work/$relative"
    done
    exit_files="generated/config/exit-node.toml generated/pki/exit-node.crt generated/pki/exit-node.key"
    exit_count=0
    for relative in $exit_files; do [ ! -e "$base_dir/$relative" ] || exit_count=$((exit_count + 1)); done
    [ "$exit_count" -eq 0 ] || [ "$exit_count" -eq 3 ] || die "optional Exit Node recovery material is partial"
    if [ "$exit_count" -eq 3 ]; then
      for relative in $exit_files; do
        require_regular "$base_dir/$relative"
        install -D -m 0600 "$base_dir/$relative" "$work/$relative"
        files="$files
$relative"
      done
    fi
    printf '%s\n' 'LANEWAY_RECOVERY_VERSION=1' > "$work/FORMAT"
    (
      cd "$work"
      # Every value in files is an internally fixed, whitespace-free relative path.
      # shellcheck disable=SC2086
      sha256sum FORMAT .env database/controller.db $files > MANIFEST.sha256
      # shellcheck disable=SC2086
      tar -cf recovery.tar FORMAT MANIFEST.sha256 .env database/controller.db $files
    )
    age --encrypt -r "$recipient" -o "$work/$name" "$work/recovery.tar"
    chmod 0600 "$work/$name"; chown 0:0 "$work/$name"
    ln "$work/$name" "$recovery_dir/$name"
    published="$recovery_dir/$name"
    sync -f "$recovery_dir/$name"
    sync -f "$recovery_dir"
    published=
    echo "lane: encrypted recovery bundle: generated/recovery/$name"
    ;;
  restore)
    [ "$#" -eq 3 ] || die "usage: recovery.sh restore BUNDLE.age IDENTITY"
    bundle=$2; identity=$3
    require_regular "$bundle"; require_regular "$identity"
    case "$(basename "$bundle")" in *.age) ;; *) die "recovery bundle must end in .age" ;; esac
    work=$(mktemp -d "$base_dir/.recovery-restore.XXXXXX")
    age --decrypt -i "$identity" -o "$work/recovery.tar" "$bundle"
    LC_ALL=C tar -tvf "$work/recovery.tar" > "$work/list.verbose"
    if grep -Ev '^-rw------- |^-r-------- |^-rw-r--r-- |^-r--r--r-- ' "$work/list.verbose" >/dev/null; then
      die "recovery archive contains a non-regular entry"
    fi
    tar -tf "$work/recovery.tar" | LC_ALL=C sort > "$work/list"
    if uniq -d "$work/list" | grep . >/dev/null; then die "recovery archive contains duplicate entries"; fi
    allowed='FORMAT
MANIFEST.sha256
.env
database/controller.db
generated/config/controller.toml
generated/config/relay.toml
generated/config/exit-node.toml
generated/pki/ca.crt
generated/pki/intermediate-chain.crt
generated/pki/intermediate.key
generated/pki/controller.crt
generated/pki/controller.key
generated/pki/relay.crt
generated/pki/relay.key
generated/pki/exit-node.crt
generated/pki/exit-node.key
generated/secrets/admin.token'
    while IFS= read -r entry; do
      printf '%s\n' "$allowed" | grep -Fx "$entry" >/dev/null || die "unexpected recovery archive entry: $entry"
    done < "$work/list"
    for entry in FORMAT MANIFEST.sha256 .env database/controller.db \
      generated/config/controller.toml generated/config/relay.toml \
      generated/pki/ca.crt generated/pki/intermediate-chain.crt generated/pki/intermediate.key \
      generated/pki/controller.crt generated/pki/controller.key generated/pki/relay.crt \
      generated/pki/relay.key generated/secrets/admin.token; do
      grep -Fx "$entry" "$work/list" >/dev/null || die "recovery archive is missing: $entry"
    done
    exit_count=$(grep -Ec '^(generated/config/exit-node.toml|generated/pki/exit-node.crt|generated/pki/exit-node.key)$' "$work/list" || true)
    [ "$exit_count" -eq 0 ] || [ "$exit_count" -eq 3 ] || die "recovery archive has partial Exit Node material"
    install -d -m 0700 "$work/extracted/database" "$work/extracted/generated/config" \
      "$work/extracted/generated/pki" "$work/extracted/generated/secrets"
    tar --extract --file "$work/recovery.tar" --directory "$work/extracted" \
      --no-same-owner --no-same-permissions --keep-old-files
    [ "$(cat "$work/extracted/FORMAT")" = LANEWAY_RECOVERY_VERSION=1 ] || die "unsupported recovery bundle format"
    (cd "$work/extracted" && sha256sum --check --strict MANIFEST.sha256 >/dev/null) || die "recovery bundle integrity check failed"
    while IFS= read -r entry; do require_regular "$work/extracted/$entry"; done < "$work/list"

    targets=".env
generated/config/controller.toml
generated/config/relay.toml
generated/pki/ca.crt
generated/pki/intermediate-chain.crt
generated/pki/intermediate.key
generated/pki/controller.crt
generated/pki/controller.key
generated/pki/relay.crt
generated/pki/relay.key
generated/secrets/admin.token"
    [ "$exit_count" -eq 0 ] || targets="$targets
generated/config/exit-node.toml
generated/pki/exit-node.crt
generated/pki/exit-node.key"
    for relative in $targets; do
      [ ! -e "$base_dir/$relative" ] && [ ! -L "$base_dir/$relative" ] || die "refusing to overwrite existing deployment state: $relative"
    done
    for directory in generated generated/config generated/pki generated/secrets generated/backups; do
      if [ -e "$base_dir/$directory" ] || [ -L "$base_dir/$directory" ]; then
        [ -d "$base_dir/$directory" ] && [ ! -L "$base_dir/$directory" ] || die "restore target is not a real directory: $directory"
      fi
    done
    install -d -m 0700 "$base_dir/generated" "$base_dir/generated/config" "$base_dir/generated/pki" "$base_dir/generated/secrets"
    install -d -m 0700 "$backup_dir"
    chown 65532:65532 "$backup_dir"
    for relative in $targets; do
      case "$relative" in
        *.key|*.token) mode=0400; owner=65532:65532 ;;
        .env) mode=0600; owner=0:0 ;;
        *) mode=0444; owner=0:0 ;;
      esac
      chmod "$mode" "$work/extracted/$relative"
      chown "$owner" "$work/extracted/$relative"
      ln "$work/extracted/$relative" "$base_dir/$relative"
      published="$published $base_dir/$relative"
    done
    if [ -n "$(compose ps --status running -q controller)" ]; then die "restore requires a stopped controller"; fi
    "$base_dir/validate.sh"
    restore_db=$backup_dir/.lane-restore-$PPID-$$.db
    install -m 0600 "$work/extracted/database/controller.db" "$restore_db"
    chown 65532:65532 "$restore_db"
    database_snapshot=$restore_db
    compose run --rm --no-deps controller -config /etc/laneway/controller.toml -restore "/backups/$(basename "$restore_db")"
    published=
    find "$restore_db" -maxdepth 0 -delete
    database_snapshot=
    echo "lane: recovery bundle restored; run ./lane init to verify signed images and start the stack"
    ;;
  *) die "usage: recovery.sh <backup NAME.age|restore BUNDLE.age IDENTITY>" ;;
esac
