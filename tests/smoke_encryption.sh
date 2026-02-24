#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Run the standard smoke suite with SMB3 session encryption enabled.
export SAMBAM_ENABLE_SMB3_ENCRYPTION=1
export SMOKE_VERBOSE_FLAGS="${SMOKE_VERBOSE_FLAGS:--vvv}"

exec "${ROOT_DIR}/tests/smoke.sh" "$@"
