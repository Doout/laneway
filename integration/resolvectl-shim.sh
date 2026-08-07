#!/usr/bin/env bash
set -euo pipefail

state_dir="${LANEWAY_RESOLVECTL_STATE_DIR:?LANEWAY_RESOLVECTL_STATE_DIR is required}"
property="${1:?property is required}"
interface="${2:?interface is required}"
mkdir -p "${state_dir}"

state_file="${state_dir}/${property}"
case "${property}" in
  dns|domain|default-route)
    if [[ "$#" == "2" ]]; then
      value=""
      if [[ -f "${state_file}" ]]; then
        value="$(<"${state_file}")"
      fi
      printf 'Link 7 (%s): %s\n' "${interface}" "${value}"
      exit 0
    fi
    printf '%s\n' "${*:3}" >"${state_file}"
    ;;
  revert)
    : >"${state_dir}/dns"
    : >"${state_dir}/domain"
    : >"${state_dir}/default-route"
    ;;
  *)
    printf 'unsupported resolver property: %s\n' "${property}" >&2
    exit 2
    ;;
esac
