#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/build/bin/eboot_diff"

if [[ ! -x "${BIN}" ]]; then
  echo "eboot_diff binary not found at ${BIN}" >&2
  exit 1
fi

strace -e trace=openat,read,write "${BIN}" --self-test >/tmp/eboot_diff_strace.log 2>&1
