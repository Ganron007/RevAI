#!/usr/bin/env bash
# verify-release.sh - one-command release verification gate for RevAI.
#
# Steps (each must pass):
#   1. wiring/coherence harness      revai/verify_pipeline.py
#   2. unit + regression tests       pytest tests/
#   3. parser parity vs pefile       optional: REVAI_PE_PARITY_SAMPLE=<real PE>
#   4. VM smoke + endpoints          optional: REVAI_VM_SSH=<user@host>
#
# Usage:
#   ./scripts/verify-release.sh
#   REVAI_VM_SSH=remnux@192.168.77.43 ./scripts/verify-release.sh
#   REVAI_PE_PARITY_SAMPLE=/opt/samples/.../sample \
#     REVAI_VM_SSH=remnux@192.168.77.43 ./scripts/verify-release.sh

set -uo pipefail

# Layout-aware: works in a source checkout (revai/ + tests/) and on the VM's flat
# runtime directory (/opt/scripts). Override with REVAI_ROOT if needed.
REPO_ROOT="${REVAI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPO_ROOT"
STATUS=0

HARNESS="revai/verify_pipeline.py"
[ -f "$HARNESS" ] || HARNESS="verify_pipeline.py"

# Interpreters are overridable because environments differ: the analysis VM runs
# tests from its own venv (/tmp/rtvenv/bin/python), a source checkout may use the
# system python.
PYTHON="${REVAI_PYTHON:-python3}"
PYTEST="${REVAI_PYTEST:-$PYTHON -m pytest}"

step() { echo; echo "=== $1 ==="; }
fail() { echo "  -> FAILED: $1"; STATUS=1; }

step "1/4 wiring + coherence"
"$PYTHON" "$HARNESS" || fail "verify_pipeline"

step "2/4 unit + regression tests"
$PYTEST tests/ -q || fail "pytest"

step "3/4 parser parity vs pefile (optional)"
if [ -n "${REVAI_PE_PARITY_SAMPLE:-}" ]; then
    REVAI_PE_PARITY_SAMPLE="$REVAI_PE_PARITY_SAMPLE" \
        $PYTEST tests/test_pe_parser.py -q || fail "pe parity"
else
    echo "  skipped - set REVAI_PE_PARITY_SAMPLE to a real PE to enable"
fi

step "4/4 VM smoke + endpoints (optional)"
if [ -n "${REVAI_VM_SSH:-}" ]; then
    ssh "$REVAI_VM_SSH" "python3 /opt/scripts/verify_pipeline.py" | tail -3 \
        || fail "VM verification harness"
    ssh "$REVAI_VM_SSH" 'python3 /opt/scripts/v2_validate.py --smoke-only' | tail -1 \
        || fail "VM smoke"
    ssh "$REVAI_VM_SSH" 'curl -s localhost:5000/api/graph | python3 -c "import json,sys; d=json.load(sys.stdin); print(\"api/graph ok=\", d.get(\"ok\"), \"tools=\", len(d.get(\"tools\") or []))"' \
        || fail "VM /api/graph"
else
    echo "  skipped - set REVAI_VM_SSH=user@host to enable"
fi

echo
if [ "$STATUS" -eq 0 ]; then
    echo "VERIFY-RELEASE: PASS"
else
    echo "VERIFY-RELEASE: FAIL"
fi
exit "$STATUS"
