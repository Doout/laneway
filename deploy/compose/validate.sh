#!/bin/sh
set -eu

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${LANEWAY_VERSION:-}" ]; then
  version=$LANEWAY_VERSION
else
  version=$(sed -n 's/^LANEWAY_VERSION=//p' "$base_dir/.env")
  if [ "$(printf '%s\n' "$version" | wc -l)" -ne 1 ]; then
    echo "LANEWAY_VERSION must appear exactly once in .env" >&2
    exit 1
  fi
fi
if ! printf '%s\n' "$version" | grep -E '^(dev|[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)$' >/dev/null; then
  echo "LANEWAY_VERSION must be dev or a pinned semantic release such as 0.1.0" >&2
  exit 1
fi

read_setting() {
  key=$1
  value=$(sed -n "s/^${key}=//p" "$base_dir/.env")
  if [ -z "$value" ] || [ "$(printf '%s\n' "$value" | wc -l)" -ne 1 ]; then
    echo "missing or duplicate $key in .env" >&2
    exit 1
  fi
  case "$value" in
    *[!A-Za-z0-9._:/-]*)
      echo "$key contains an unsafe character" >&2
      exit 1
      ;;
  esac
  printf '%s' "$value"
}

network_id=$(read_setting LANEWAY_NETWORK_ID)
controller_id=$(read_setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(read_setting LANEWAY_RELAY_SERVICE_ID)
case "$network_id:$controller_id:$relay_id" in
  REPLACE_*|*:*:*:*|*[!0-9a-f:]* )
    echo "network, controller, and relay IDs must be distinct 32-character lowercase hex values" >&2
    exit 1
    ;;
esac
if [ "${#network_id}" -ne 32 ] || [ "${#controller_id}" -ne 32 ] || \
   [ "${#relay_id}" -ne 32 ] || [ "$network_id" = "$controller_id" ] || \
   [ "$network_id" = "$relay_id" ] || [ "$controller_id" = "$relay_id" ]; then
  echo "network, controller, and relay IDs must be distinct 32-character lowercase hex values" >&2
  exit 1
fi
read_setting LANEWAY_CONTROLLER_SERVER_NAME >/dev/null
read_setting LANEWAY_NETWORK_NAME >/dev/null
read_setting LANEWAY_IPV4_POOL >/dev/null
read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT >/dev/null

for path in \
  generated/config/controller.toml \
  generated/config/relay.toml \
  generated/pki/ca.crt \
  generated/pki/intermediate-chain.crt \
  generated/pki/intermediate.key \
  generated/pki/controller.crt \
  generated/pki/controller.key \
  generated/pki/relay.crt \
  generated/pki/relay.key \
  generated/secrets/admin.token
do
  target=$base_dir/$path
  if [ ! -f "$target" ] || [ -L "$target" ]; then
    echo "missing regular, non-symlink file: $path" >&2
    exit 1
  fi
  mode=$(stat -c '%a' "$target")
  case "$path" in
    *.key|*.token)
      if [ "$mode" != 400 ]; then
        echo "$path must have mode 0400 (found $mode)" >&2
        exit 1
      fi
      owner=$(stat -c '%u' "$target")
      if [ "$owner" != 65532 ]; then
        echo "$path must be owned by container UID 65532 (found $owner)" >&2
        exit 1
      fi
      ;;
    *)
      if [ "$mode" != 444 ]; then
        echo "$path must have mode 0444 (found $mode)" >&2
        exit 1
      fi
      ;;
  esac
done

exit_artifacts="generated/config/exit-node.toml generated/pki/exit-node.crt generated/pki/exit-node.key"
exit_configured=false
for path in $exit_artifacts; do
  if [ -e "$base_dir/$path" ]; then
    exit_configured=true
  fi
done
if [ "$exit_configured" = true ]; then
  for path in $exit_artifacts; do
    target=$base_dir/$path
    if [ ! -f "$target" ] || [ -L "$target" ]; then
      echo "missing regular, non-symlink Exit Node file: $path" >&2
      exit 1
    fi
    mode=$(stat -c '%a' "$target")
    case "$path" in
      *.key)
        [ "$mode" = 400 ] || { echo "$path must have mode 0400 (found $mode)" >&2; exit 1; }
        owner=$(stat -c '%u' "$target")
        [ "$owner" = 65532 ] || { echo "$path must be owned by container UID 65532 (found $owner)" >&2; exit 1; }
        ;;
      *)
        [ "$mode" = 444 ] || { echo "$path must have mode 0444 (found $mode)" >&2; exit 1; }
        ;;
    esac
  done
  if grep -E 'REPLACE_|CHANGE_ME|latest([:@]|$)' "$base_dir/generated/config/exit-node.toml" >/dev/null 2>&1; then
    echo "generated Exit Node configuration still contains a placeholder or mutable tag" >&2
    exit 1
  fi
fi

if grep -E 'REPLACE_|CHANGE_ME|latest([:@]|$)' \
  "$base_dir/generated/config/controller.toml" \
  "$base_dir/generated/config/relay.toml" \
  "$base_dir/.env" >/dev/null 2>&1; then
  echo "generated configuration still contains a placeholder or mutable tag" >&2
  exit 1
fi

mkdir -p "$base_dir/generated/backups"
chmod 0700 "$base_dir/generated/backups"

docker compose --project-directory "$base_dir" \
  --env-file "$base_dir/.env" \
  -f "$base_dir/compose.yaml" config --quiet
if [ "$exit_configured" = true ]; then
  docker compose --project-directory "$base_dir" --profile exit-node \
    --env-file "$base_dir/.env" -f "$base_dir/compose.yaml" config --quiet
fi
echo "Laneway Compose inputs are valid"
