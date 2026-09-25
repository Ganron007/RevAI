#!/usr/bin/env bash
# winre-llm-env.sh - one-place LLM config for WinRE's own CLI.
#
# When RevAI drives WinRE, the runner exports the LLM variables automatically.
# Running WinRE's CLI directly? The model still lives in exactly one place:
#
#   ./scripts/winre-llm-env.sh --check                      # what would be used
#   eval "$(./scripts/winre-llm-env.sh)"                    # exports for this shell
#   ./scripts/winre-llm-env.sh --run python3 -m winre.pipeline <sample> --mode agentic
#
# Precedence: process environment > /opt/winre/.env > /opt/revai/config/llm.env.
# An explicit WINRE_LLM_* in WinRE's own .env always wins, so WinRE can be
# pointed at a different model deliberately. The key is never printed unless you
# eval the exports, and it is never written anywhere new.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_GUESS="${REVAI_ROOT:-$(dirname "$SCRIPT_DIR")}"
if [ -f "$ROOT_GUESS/revai/winre_llm_env.py" ]; then
    exec python3 "$ROOT_GUESS/revai/winre_llm_env.py" "$@"
fi
exec python3 "$SCRIPT_DIR/winre_llm_env.py" "$@"
