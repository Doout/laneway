#!/bin/sh
set -eu

base_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mode=standard
case "${1:-}" in
  '') ;;
  --dev) mode=dev ;;
  --rust) mode=rust ;;
  *) echo "usage: bootstrap.sh [--dev | --rust]" >&2; exit 1 ;;
esac
if [ "$#" -gt 1 ]; then
  echo "usage: bootstrap.sh [--dev | --rust]" >&2
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

# Compose interpolates the release overlay before selecting the local images.
dev_version_env() {
  placeholder=sha256:0000000000000000000000000000000000000000000000000000000000000000
  export LANEWAY_VERSION=dev LANEWAY_RUST_VERSION=dev
  export LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST="$placeholder"
  export LANEWAY_RUST_RELAY_IMAGE_DIGEST="$placeholder"
  export LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST="$placeholder"
}

compose() {
  case "$mode" in
    dev)
      dev_version_env
      set -- -f "$base_dir/compose.rust.yaml" -f "$base_dir/compose.dev.yaml" "$@"
      ;;
    rust) set -- -f "$base_dir/compose.rust.yaml" "$@" ;;
  esac
  docker compose --project-directory "$base_dir" --env-file "$base_dir/.env" \
    -f "$base_dir/compose.yaml" "$@"
}

admin() {
  compose --profile tools run --rm admin "$@"
}

if [ "$mode" != standard ]; then
  [ "$(id -u)" -eq 0 ] || { echo "Rust bootstrap must run as root" >&2; exit 1; }
  # The signed pins and deployment settings are staged in .env. Environment
  # values take precedence in Compose unless removed before rendering.
  unset LANEWAY_CONSOLE_REPOSITORY LANEWAY_RELAY_REPOSITORY LANEWAY_EDGE_REPOSITORY
  unset LANEWAY_VERSION LANEWAY_ADMIN_IMAGE_DIGEST LANEWAY_RUST_VERSION LANEWAY_RUST_IMAGE_SUFFIX \
    LANEWAY_RUST_CONTROLLER_IMAGE_DIGEST LANEWAY_RUST_RELAY_IMAGE_DIGEST \
    LANEWAY_RUST_EXIT_NODE_IMAGE_DIGEST LANEWAY_BIND_ADDRESS LANEWAY_CONTROLLER_PORT \
    LANEWAY_RELAY_QUIC_PORT LANEWAY_RELAY_TCP_PORT LANEWAY_EXIT_DIRECT_PORT LANEWAY_CONTROLLER_SERVER_NAME
  if [ "$mode" = rust ]; then
    [ "$(read_setting LANEWAY_RUST_VERSION)" = "$(read_setting LANEWAY_VERSION)" ] ||
      { echo "Rust bootstrap and the admin image must use the same release version" >&2; exit 1; }
    "$base_dir/validate.sh" --rust
  else
    "$base_dir/validate.sh" --dev
    if [ ! -e "$base_dir/generated/config/bootstrap.rust.json" ] &&
       [ ! -e "$base_dir/generated/config/relay.rust.toml" ]; then
      python3 "$base_dir/prepare-rust.py" --lab
    fi
    spool_dir="$base_dir/generated/gateway-spool"
    if [ -L "$spool_dir" ] || { [ -e "$spool_dir" ] && [ ! -d "$spool_dir" ]; }; then
      echo "Development gateway spool must be a real directory" >&2
      exit 1
    fi
    if [ ! -e "$spool_dir" ]; then
      install -d -m 0700 -o 65532 -g 65532 "$spool_dir"
    fi
    compose --profile tools build controller relay admin
  fi
  existing=$(compose --profile exit-node ps --all --quiet controller relay exit-node)
  if [ -n "$existing" ]; then
    echo "Rust bootstrap requires a new deployment without existing service containers" >&2
    exit 1
  fi
  compose run --rm --no-deps controller init /var/lib/laneway-controller/controller.db \
    /run/laneway-secrets/controller.crt "$network_name" "$ipv4_pool"
else
  "$base_dir/validate.sh"
fi
compose up -d controller --wait

common="--controller https://controller:8443 --ca /run/laneway-secrets/ca.crt --server-name $server_name --controller-network-id $network_id --controller-service-id $controller_id --admin-token-file /run/laneway-secrets/admin.token"

# Values are validated as delimiter-free atoms by validate.sh. Intentional word
# splitting turns the fixed option string into argv without evaluating it.
# shellcheck disable=SC2086
networks=$(admin controller network list $common --limit 1000)
network_count=$(printf '%s\n' "$networks" | jq --arg id "$network_id" '[.networks[] | select(.network_id == $id)] | length')
case "$network_count" in
  0)
    if [ "$mode" != standard ]; then
      echo "The Rust controller's initial network does not match .env; refusing to create another" >&2
      exit 1
    fi
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
