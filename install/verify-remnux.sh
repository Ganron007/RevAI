#!/usr/bin/env bash
# verify-remnux.sh — verify a CADRE-RevAI REMnux deployment
# Run as the remnux user or root. This script is read-only; it does not modify files.
#
# Usage:
#   ./install/verify-remnux.sh

set -euo pipefail

ERR=0
WARN=0

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1"; ((WARN++)) || true; }
fail() { echo "  [FAIL] $1"; ((ERR++)) || true; }

echo "=== CADRE-RevAI / REMnux verification ==="

# OS
echo ""
echo "--- OS ---"
if [[ -f /etc/os-release ]]; then
    grep -E '^PRETTY_NAME=' /etc/os-release || true
else
    warn "/etc/os-release not found"
fi

# System tools
echo ""
echo "--- System tools ---"
for cmd in python3 r2 rasm2 yara floss ghidra; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd present"
    else
        fail "$cmd missing"
    fi
done

# Optional tools
echo ""
echo "--- Optional tools ---"
if command -v idasql >/dev/null 2>&1; then
    ok "idasql present (IDA optional): $(idasql --version 2>&1 | head -1)"
else
    warn "idasql not found (IDA optional; pipeline will use Ghidra)"
fi

if command -v capa >/dev/null 2>&1; then ok "capa present"; else warn "capa missing"; fi
if command -v speakeasy >/dev/null 2>&1; then ok "speakeasy present"; else warn "speakeasy missing"; fi

# Python imports
echo ""
echo "--- Python imports ---"
python3 - <<'PYEOF' || fail "Python imports check failed"
import pefile, lief, frida, capa, speakeasy, oletools, yara_x, z3, angr, faiss, sentence_transformers, fastapi, uvicorn
print("  [OK]   all required Python imports successful")
PYEOF

# Directory layout
echo ""
echo "--- Directory layout ---"
for d in /opt/samples /opt/scripts /opt/cadre-v3-tools /opt/cadre-v4-tools /opt/revai/config; do
    if [[ -d "$d" ]]; then ok "$d exists"; else fail "$d missing"; fi
done

# Env files
echo ""
echo "--- Env files ---"
if [[ -f /opt/cadre-v3-tools/llm.env ]]; then
    ok "llm.env exists"
    if grep -qE 'REVENG_LLM_API_KEY=.+[^[:space:]]' /opt/cadre-v3-tools/llm.env; then
        warn "llm.env appears to contain an API key; ensure it is not committed to git"
    fi
else
    warn "llm.env not configured (copy from config/llm.env.template)"
fi

if [[ -f /opt/cadre-v3-tools/rag.env ]]; then
    ok "rag.env exists"
else
    warn "rag.env not configured (copy from config/rag.env.template)"
fi

# Pipeline files
echo ""
echo "--- Pipeline files ---"
for f in /opt/scripts/intake_v2.py /opt/scripts/quick_scan_v2.py /opt/scripts/deep_dive_v2.py \
         /opt/scripts/yara_gen_v2.py /opt/scripts/publish_report_v2.py /opt/scripts/app.py \
         /opt/scripts/v2_lib.py; do
    if [[ -f "$f" ]]; then ok "$(basename "$f") deployed"; else fail "$(basename "$f") not deployed"; fi
done

# Smoke test (if deployed)
echo ""
echo "--- Smoke test ---"
if [[ -f /opt/scripts/v2_validate.py ]]; then
    if python3 /opt/scripts/v2_validate.py --smoke-only 2>&1 | grep -q "V2_SMOKE_OK"; then
        ok "v2_validate.py --smoke-only: V2_SMOKE_OK"
    else
        fail "v2_validate.py --smoke-only did not report V2_SMOKE_OK"
    fi
else
    warn "v2_validate.py not deployed; skipping smoke test"
fi

# Summary
echo ""
echo "=== Verification complete ==="
if [[ $ERR -eq 0 ]]; then
    echo "Result: PASS ($WARN warnings, $ERR failures)"
else
    echo "Result: FAIL ($WARN warnings, $ERR failures)"
    exit 1
fi
