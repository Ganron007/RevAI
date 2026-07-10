#!/bin/bash
# run_agent_v2.sh — default entry for v2 agents (bwrap when available).
# Set CADRE_USE_SANDBOX=0 to disable.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT="$1"
shift
if [[ "${CADRE_USE_SANDBOX:-1}" == "1" && -x "${SCRIPT_DIR}/run_agent_sandbox.sh" ]]; then
  exec "${SCRIPT_DIR}/run_agent_sandbox.sh" "$AGENT" "$@"
fi
exec python3 "$AGENT" "$@"
