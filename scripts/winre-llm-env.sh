#!/usr/bin/env bash
# winre-llm-env.sh - WinRE-owned LLM config for its CLI and RevAI bridge.
#
# When RevAI drives WinRE, the runner exports the LLM variables automatically.
# Running WinRE's CLI directly? Use the same WinRE-owned settings:
#
#   ./scripts/winre-llm-env.sh --check                      # what would be used
#   eval "$(./scripts/winre-llm-env.sh)"                    # exports for this shell
#   ./scripts/winre-llm-env.sh --run python3 -m winre.pipeline <sample> --mode agentic
#
# Precedence: WINRE_LLM_* process environment > WinRE's own env file.
# RevAI's model/provider/key are never borrowed. The key is never printed unless you
# eval the exports, and it is never written anywhere new.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_GUESS="${REVAI_ROOT:-$(dirname "$SCRIPT_DIR")}"
if [ -f "$ROOT_GUESS/revai/winre_llm_env.py" ]; then
    exec python3 "$ROOT_GUESS/revai/winre_llm_env.py" "$@"
fi
exec python3 "$SCRIPT_DIR/winre_llm_env.py" "$@"
