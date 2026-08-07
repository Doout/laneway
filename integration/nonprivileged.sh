#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}/go"

go test ./integration/relay ./internal/subnet ./internal/exitnode ./internal/tcpfallback
