#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/build/bin/eboot_diff"

if [[ ! -x "${BIN}" ]]; then
  echo "eboot_diff binary not found at ${BIN}" >&2
  exit 1
fi

valgrind --leak-check=full --error-exitcode=42 "${BIN}" --self-test
