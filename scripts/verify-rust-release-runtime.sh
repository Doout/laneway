#!/bin/sh
# Verify the prebuilt package inputs without invoking cross-architecture code.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: sh verify-rust-release-runtime.sh DIRECTORY amd64|arm64" >&2
  exit 2
fi
directory=$1
case "$2" in
  amd64) machine='Advanced Micro Devices X86-64' ;;
  arm64) machine='AArch64' ;;
  *) echo "unsupported Rust runtime architecture: $2" >&2; exit 2 ;;
esac
for name in laneway-controller-rs laneway-healthcheck-rs laneway-relay-rs laneway-update-rs lanewayd-rs; do
  binary="$directory/$name"
  if [ ! -f "$binary" ] || [ -L "$binary" ] || [ ! -x "$binary" ]; then
    echo "the Rust runtime is missing an executable regular file: $name" >&2
    exit 1
  fi
  elf=$(LC_ALL=C readelf -hW -lW -dW -- "$binary") || exit 1
  if ! printf '%s\n' "$elf" | awk -v expected="$machine" '
    $1 == "Class:" && $2 == "ELF64" { elf64 = 1 }
    $1 == "Machine:" {
      sub(/^[^:]*:[[:space:]]*/, "")
      if ($0 == expected) architecture = 1
    }
    $1 == "Type:" && ($2 == "EXEC" || $2 == "DYN") { executable = 1 }
    $1 == "INTERP" || $2 == "(NEEDED)" { dynamic = 1 }
    END { exit !(elf64 && architecture && executable && !dynamic) }
  '; then
    echo "the Rust runtime is not a static Linux $2 executable: $name" >&2
    exit 1
  fi
done
