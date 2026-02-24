#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Run the Windows-over-SSH smoke suite with SMB3 session encryption enabled.
export SAMBAM_ENABLE_SMB3_ENCRYPTION=1

exec "${ROOT_DIR}/tests/windows_ssh_smoke.sh" "$@"
