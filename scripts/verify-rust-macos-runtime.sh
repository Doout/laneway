#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: sh verify-rust-macos-runtime.sh BINARY amd64|arm64" >&2
  exit 2
fi
case "$2" in
  amd64) machine=x86_64 ;;
  arm64) machine=arm64 ;;
  *) echo "unsupported macOS runtime architecture: $2" >&2; exit 2 ;;
esac
if [ ! -f "$1" ] || [ -L "$1" ] || [ ! -x "$1" ]; then
  echo "the Rust runtime must be an executable regular file" >&2
  exit 1
fi
description=$(LC_ALL=C file -b -- "$1")
case "$description" in
  "Mach-O 64-bit executable $machine"|"Mach-O 64-bit executable $machine "*|"Mach-O 64-bit executable $machine,"*) ;;
  *) echo "the Rust runtime must be a thin macOS $2 executable: $description" >&2; exit 1 ;;
esac
