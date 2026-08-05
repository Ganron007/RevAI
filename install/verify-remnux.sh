#!/usr/bin/env bash
# verify-remnux.sh — verify a RevAI REMnux deployment (read-only)
#
# Usage:
#   ./install/verify-remnux.sh

set -euo pipefail

ERR=0
WARN=0
ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1"; ((WARN++)) || true; }
fail() { echo "  [FAIL] $1"; ((ERR++)) || true; }

echo "=== RevAI / REMnux verification ==="

echo ""
echo "--- OS ---"
if [[ -f /etc/os-release ]]; then
  grep -E '^PRETTY_NAME=' /etc/os-release || true
else
  warn "/etc/os-release not found"
fi

echo ""
echo "--- Required system tools ---"
for cmd in python3 r2 yara; do
  if command -v "$cmd" >/dev/null 2>&1; then ok "$cmd present"; else fail "$cmd missing"; fi
done

echo ""
echo "--- Ghidra ---"
if [[ -x /opt/ghidra/support/analyzeHeadless ]]; then
  ok "analyzeHeadless at /opt/ghidra"
elif [[ -x /opt/ghidra/support/ghidraRun ]]; then
  ok "ghidraRun at /opt/ghidra (analyzeHeadless missing — check install)"
else
  fail "Ghidra missing at /opt/ghidra (see docs/PREREQUISITES.md)"
fi

echo ""
echo "--- CADRE PE Loader (required for intake) ---"
if [[ -f /opt/ghidra/Ghidra/Extensions/CADRE/lib/CADRE.jar ]]; then
  ok "CADRE PE Loader at /opt/ghidra/Ghidra/Extensions/CADRE/"
else
  fail "CADRE PE Loader missing — install from extensions/cadre-pe-loader/ (see docs/PREREQUISITES.md)"
fi

echo ""
echo "--- ghidrasql ---"
if command -v ghidrasql >/dev/null 2>&1 || [[ -x /usr/local/bin/ghidrasql ]]; then
  BIN="$(command -v ghidrasql 2>/dev/null || echo /usr/local/bin/ghidrasql)"
  if "$BIN" --help >/dev/null 2>&1; then ok "ghidrasql OK ($BIN)"; else fail "ghidrasql present but --help failed"; fi
else
  fail "ghidrasql missing — run: sudo ./install/install-ghidrasql.sh"
fi

echo ""
echo "--- Malcat (optional — pipeline runs with --skip-malcat) ---"
if [[ -f /opt/malcat/bin/malcat.mcp.py ]]; then
  ok "Malcat MCP at /opt/malcat/bin/malcat.mcp.py"
else
  warn "Malcat not installed — pipeline runs with --skip-malcat (see docs/PREREQUISITES.md)"
fi

echo ""
echo "--- YARA engine (required for quick_scan) ---"
if python3 -c "import yara_x" >/dev/null 2>&1; then
  ok "yara_x Python module present (in-process scan engine)"
else
  fail "yara_x Python module missing — pip install yara-x (see requirements.txt)"
fi
if command -v yr >/dev/null 2>&1; then
  ok "yr CLI present (optional — in-process engine is primary)"
else
  warn "yr CLI not found (optional — pipeline uses the in-process yara_x engine)"
fi

echo ""
echo "--- Optional tools ---"
if command -v idasql >/dev/null 2>&1; then ok "idasql present"; else warn "idasql not found (IDA optional)"; fi
if command -v capa >/dev/null 2>&1 || python3 -c "import capa" 2>/dev/null; then ok "capa present"; else warn "capa missing"; fi
if command -v floss >/dev/null 2>&1 || python3 -c "import floss" 2>/dev/null; then ok "floss present"; else warn "floss missing"; fi
if command -v speakeasy >/dev/null 2>&1 || python3 -c "import speakeasy" 2>/dev/null; then ok "speakeasy present"; else warn "speakeasy missing"; fi

echo ""
echo "--- Core Python imports (LLM-only product) ---"
if python3 - <<'PY'
import flask, requests, yaml, pefile, lief, frida, capa, speakeasy, oletools, yara_x
import langgraph, langchain_core, langchain_openai
print("ok")
PY
then
  ok "core Python imports"
else
  fail "core Python imports failed — pip install -r requirements.txt"
fi

echo ""
echo "--- Optional RAG imports (not required) ---"
if python3 -c "import faiss, sentence_transformers" 2>/dev/null; then
  ok "optional RAG packages present"
else
  warn "RAG packages not installed (OK — product default is RAG off)"
fi

echo ""
echo "--- Directory layout ---"
for d in /opt/samples /opt/scripts /opt/revai /opt/revai/config; do
  if [[ -d "$d" ]]; then ok "$d exists"; else fail "$d missing"; fi
done

echo ""
echo "--- Env files ---"
if [[ -f /opt/revai/config/llm.env ]]; then
  ok "llm.env exists (/opt/revai/config/llm.env)"
else
  fail "llm.env missing — cp config/llm.env.template /opt/revai/config/llm.env"
fi

echo ""
echo "--- Pipeline files ---"
for f in intake_v2.py quick_scan_v2.py deep_dive_v2.py deep_dive_agentic.py \
         yara_gen_v2.py publish_report_v2.py section_publisher.py audit_pipeline.py \
         stage_orchestrator.py pipeline_single.py report_quality.py \
         app.py v2_lib.py agentic_langgraph.py v2_validate.py; do
  if [[ -e "/opt/scripts/$f" ]]; then ok "$f deployed"; else fail "$f not deployed — run ./scripts/deploy.sh"; fi
done
if [[ -e /opt/scripts/ui/index.html ]]; then
  ok "Console UI deployed (ui/index.html)"
else
  warn "Console UI not built — run ./scripts/deploy.sh with Node.js installed"
fi

echo ""
echo "--- Core import sanity ---"
if python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/scripts")
import v2_lib  # noqa: F401
import report_quality  # noqa: F401
print("core_imports_ok")
PY
then
  ok "core modules import"
else
  fail "core module import check failed"
fi

echo ""
echo "--- Smoke preflight ---"
if [[ -f /opt/scripts/v2_validate.py ]]; then
  if python3 /opt/scripts/v2_validate.py --smoke-only 2>&1 | tee /tmp/revai_smoke.out | grep -q "V2_SMOKE_OK"; then
    ok "v2_validate.py --smoke-only: V2_SMOKE_OK"
  else
    fail "v2_validate.py --smoke-only did not report V2_SMOKE_OK (see /tmp/revai_smoke.out)"
  fi
else
  fail "v2_validate.py not deployed"
fi

echo ""
echo "=== Verification complete ==="
if [[ $ERR -eq 0 ]]; then
  echo "Result: PASS ($WARN warnings, $ERR failures)"
else
  echo "Result: FAIL ($WARN warnings, $ERR failures)"
  exit 1
fi
