#!/bin/sh
set -eu

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
compose_files="-f $base_dir/compose.yaml"
case "${1:-}" in
  '') ;;
  --dev) compose_files="$compose_files -f $base_dir/compose.dev.yaml" ;;
  *) echo "usage: bootstrap.sh [--dev]" >&2; exit 1 ;;
esac
if [ "$#" -gt 1 ]; then
  echo "usage: bootstrap.sh [--dev]" >&2
  exit 1
fi

read_setting() {
  key=$1
  value=$(sed -n "s/^${key}=//p" "$base_dir/.env")
  if [ -z "$value" ] || [ "$(printf '%s\n' "$value" | wc -l)" -ne 1 ]; then
    echo "missing or duplicate $key in .env" >&2
    exit 1
  fi
  printf '%s' "$value"
}

network_id=$(read_setting LANEWAY_NETWORK_ID)
controller_id=$(read_setting LANEWAY_CONTROLLER_SERVICE_ID)
relay_id=$(read_setting LANEWAY_RELAY_SERVICE_ID)
network_name=$(read_setting LANEWAY_NETWORK_NAME)
ipv4_pool=$(read_setting LANEWAY_IPV4_POOL)
relay_endpoint=$(read_setting LANEWAY_RELAY_PUBLIC_ENDPOINT)
server_name=$(read_setting LANEWAY_CONTROLLER_SERVER_NAME)

compose() {
  # Paths are derived from this script's directory and contain no whitespace in
  # the supported packaged layout.
  # shellcheck disable=SC2086
  docker compose --project-directory "$base_dir" --env-file "$base_dir/.env" \
    $compose_files "$@"
}

admin() {
  compose --profile tools run --rm admin "$@"
}

"$base_dir/validate.sh"
compose up -d controller --wait

common="--controller https://controller:8443 --ca /run/laneway-secrets/ca.crt --server-name $server_name --controller-network-id $network_id --controller-service-id $controller_id --admin-token-file /run/laneway-secrets/admin.token"

# Values are validated as delimiter-free atoms by validate.sh. Intentional word
# splitting turns the fixed option string into argv without evaluating it.
# shellcheck disable=SC2086
networks=$(admin controller network list $common --limit 1000)
network_count=$(printf '%s\n' "$networks" | jq --arg id "$network_id" '[.networks[] | select(.network_id == $id)] | length')
case "$network_count" in
  0)
    # shellcheck disable=SC2086
    admin controller network create $common --network-id "$network_id" \
      --name "$network_name" --ipv4-pool "$ipv4_pool" >/dev/null
    ;;
  1)
    if ! printf '%s\n' "$networks" | jq -e --arg id "$network_id" \
      --arg name "$network_name" --arg pool "$ipv4_pool" \
      '.networks[] | select(.network_id == $id) | .name == $name and .ipv4_pool == $pool' >/dev/null; then
      echo "existing network $network_id does not match .env; refusing to overwrite it" >&2
      exit 1
    fi
    ;;
  *)
    echo "controller returned duplicate immutable network IDs" >&2
    exit 1
    ;;
esac

# shellcheck disable=SC2086
relays=$(admin controller relay list $common --network-id "$network_id" --limit 1000)
relay_count=$(printf '%s\n' "$relays" | jq --arg id "$relay_id" '[.relays[] | select(.service_id == $id)] | length')
case "$relay_count" in
  0)
    # shellcheck disable=SC2086
    admin controller relay register $common --network-id "$network_id" \
      --service-id "$relay_id" --name relay --endpoint "$relay_endpoint" >/dev/null
    ;;
  1)
    if ! printf '%s\n' "$relays" | jq -e --arg id "$relay_id" \
      --arg endpoint "$relay_endpoint" \
      '.relays[] | select(.service_id == $id) | .enabled == true and .endpoint == $endpoint' >/dev/null; then
      echo "existing relay $relay_id does not match .env; refusing to overwrite it" >&2
      exit 1
    fi
    ;;
  *)
    echo "controller returned duplicate relay service IDs" >&2
    exit 1
    ;;
esac

compose up -d relay --wait
compose ps
