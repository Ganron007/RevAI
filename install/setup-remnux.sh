#!/usr/bin/env bash
# setup-remnux.sh — install CADRE-RevAI on a REMnux / Ubuntu 24.04 analysis VM
# Run as root or with sudo.
#
# Usage:
#   sudo ./install/setup-remnux.sh
#
# See docs/PREREQUISITES.md for Malcat (vendor) and Ghidra expectations.

set -euo pipefail

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; NC=''
fi
ok()   { echo -e "${GREEN}[OK]${NC}   $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
hdr()  { echo -e "\n${YELLOW}=== $1 ===${NC}"; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"

# =========================================================================
hdr "Step 1/9 — apt packages"
# =========================================================================
apt-get update -qq
apt-get install -y --no-install-recommends \
  nmap foremost dcfldd stegsnow testdisk pdfid oledump poppler-utils \
  dex2jar curl wget git build-essential cmake ninja-build pkg-config \
  libssl-dev libffi-dev zlib1g-dev python3-dev \
  python3-venv python3-pip python3-olefile python3-oletools python3-requests python3-yaml \
  radare2 yara openjdk-21-jdk gradle \
  ghidra || true
# ghidra apt package may place files outside /opt/ghidra — normalize below
ok "apt packages installed"

# =========================================================================
hdr "Step 2/9 — Locate / normalize Ghidra → /opt/ghidra"
# =========================================================================
if [[ ! -x /opt/ghidra/support/analyzeHeadless ]]; then
  FOUND=""
  for candidate in /opt/ghidra /usr/share/ghidra /usr/lib/ghidra \
    /opt/ghidra_* /opt/ghidra-* /usr/local/ghidra*; do
    if [[ -d "$candidate" ]] && [[ -x "$candidate/support/analyzeHeadless" || -x "$candidate/support/ghidraRun" ]]; then
      FOUND="$candidate"
      break
    fi
  done
  if [[ -n "$FOUND" && "$FOUND" != "/opt/ghidra" ]]; then
    ln -sfn "$FOUND" /opt/ghidra
    ok "symlinked $FOUND → /opt/ghidra"
  fi
fi
if [[ -x /opt/ghidra/support/analyzeHeadless || -x /opt/ghidra/support/ghidraRun ]]; then
  export GHIDRA_INSTALL_DIR=/opt/ghidra
  ok "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
else
  warn "Ghidra not found at /opt/ghidra — install Ghidra and re-run, or set GHIDRA_INSTALL_DIR"
fi

ENV_FILE="/home/remnux/.cadre-env"
if [[ -d /home/remnux ]]; then
  cat > "$ENV_FILE" <<EOF
# CADRE-RevAI environment
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR}"
export PATH="\$HOME/.local/bin:/usr/local/bin:\$PATH"
EOF
  chown remnux:remnux "$ENV_FILE" 2>/dev/null || true
  ok "Env saved to $ENV_FILE"
fi

# =========================================================================
hdr "Step 3/9 — Python packages (LLM-only core)"
# =========================================================================
PIP_FLAGS=""
if pip install --help 2>&1 | grep -q "break-system-packages"; then
  PIP_FLAGS="--break-system-packages --ignore-installed pip"
fi
pip install $PIP_FLAGS -r "$REPO_ROOT/requirements.txt"
ok "Python packages from requirements.txt"

# =========================================================================
hdr "Step 4/9 — capa rules + YARA flat rules"
# =========================================================================
if [[ ! -d /opt/capa-rules ]]; then
  git clone --depth 1 https://github.com/mandiant/capa-rules.git /opt/capa-rules
  chown -R remnux:remnux /opt/capa-rules 2>/dev/null || true
  ok "capa-rules cloned"
else
  ok "capa-rules already present"
fi
mkdir -p /opt/samples/rules/flat
if [[ -d /usr/local/yara-rules ]]; then
  find /usr/local/yara-rules -name "*.yar" -not -name "*_index.yar" -not -name "index.yar" 2>/dev/null | \
  while read -r f; do
    bn=$(basename "$f")
    if [[ ! -f "/opt/samples/rules/flat/$bn" ]]; then
      cp "$f" "/opt/samples/rules/flat/$bn"
    fi
  done
  ok "YARA flat rules: $(ls /opt/samples/rules/flat 2>/dev/null | wc -l)"
else
  warn "/usr/local/yara-rules not found; add rules under /opt/samples/rules/flat/ later"
fi
chown -R remnux:remnux /opt/samples/rules 2>/dev/null || true

# =========================================================================
hdr "Step 5/9 — Lab directories"
# =========================================================================
mkdir -p /opt/samples/incoming/{manual-drop,vr-hunt-pull,cadre-push}
mkdir -p /opt/samples/{corpus,shortlist,logs,sessions}
mkdir -p /opt/scripts /opt/cadre-v3-tools /opt/revai/config
chown -R remnux:remnux /opt/samples /opt/scripts /opt/cadre-v3-tools /opt/revai 2>/dev/null || true
ok "lab dirs ready"

# =========================================================================
hdr "Step 6/10 — Build and install ghidrasql"
# =========================================================================
if command -v ghidrasql >/dev/null 2>&1 || [[ -x /usr/local/bin/ghidrasql ]]; then
  ok "ghidrasql already installed: $(command -v ghidrasql || echo /usr/local/bin/ghidrasql)"
elif [[ -x /opt/ghidra/support/analyzeHeadless || -x /opt/ghidra/support/ghidraRun ]]; then
  bash "$REPO_ROOT/install/install-ghidrasql.sh"
else
  warn "Skipping ghidrasql build (Ghidra missing). Install Ghidra, then: sudo ./install/install-ghidrasql.sh"
fi

# =========================================================================
hdr "Step 7/10 — Extensions and tools"
# =========================================================================
# deobfuscation / CFF-deflatten / force_pe_imports / capa-signatures / CADRE PE Loader
REPO_EXT="$REPO_ROOT/extensions"

# Deobfuscation tools (z3 MBA / angr) — used by deep_dive_agentic z3_solve tool
if [[ -d "$REPO_EXT/deobfuscation" ]]; then
  mkdir -p /opt/cadre-v3-tools/deobfuscation
  cp -r "$REPO_EXT/deobfuscation/"* /opt/cadre-v3-tools/deobfuscation/
  chown -R remnux:remnux /opt/cadre-v3-tools/deobfuscation 2>/dev/null || true
  ok "deobfuscation tools installed to /opt/cadre-v3-tools/deobfuscation"
else
  warn "extensions/deobfuscation not found in repo"
fi

# CFF-deflatten (angr-based control-flow-flattening recovery)
if [[ -d "$REPO_EXT/cff-deflatten" ]]; then
  mkdir -p /opt/cadre-v3-tools/cff-deflatten
  cp -r "$REPO_EXT/cff-deflatten/"* /opt/cadre-v3-tools/cff-deflatten/
  chown -R remnux:remnux /opt/cadre-v3-tools/cff-deflatten 2>/dev/null || true
  ok "cff-deflatten installed to /opt/cadre-v3-tools/cff-deflatten"
else
  warn "extensions/cff-deflatten not found in repo"
fi

# force_pe_imports GhidraScript (re-runs PE ImportTable analyzer when stock
# analysis skips it — e.g. VB6 / mixed-mode .NET PEs)
for f in force_pe_imports.py force_pe_imports.java; do
  if [[ -f "$REPO_ROOT/scripts/$f" ]]; then
    cp "$REPO_ROOT/scripts/$f" /opt/scripts/"$f"
    ok "$f deployed to /opt/scripts/"
  fi
done

# capa-signatures (empty dir so standalone capa does not error on missing sigs)
mkdir -p /opt/capa-signatures
chown remnux:remnux /opt/capa-signatures 2>/dev/null || true
ok "/opt/capa-signatures ready"

# CADRE PE Loader Ghidra extension (robust PE import loader — forces external
# references for packed / compound / VB6 binaries)
CADRE_EXT="$REPO_EXT/cadre-pe-loader"
GHIDRA_EXT="${GHIDRA_INSTALL_DIR:-/opt/ghidra}/Ghidra/Extensions/CADRE"
if [[ -f "$CADRE_EXT/lib/CADRE.jar" ]]; then
  mkdir -p "$GHIDRA_EXT/lib" "$GHIDRA_EXT/data/languages"
  cp "$CADRE_EXT/lib/CADRE.jar" "$GHIDRA_EXT/lib/"
  cp "$CADRE_EXT/Module.manifest" "$GHIDRA_EXT/"
  cp "$CADRE_EXT/extension.properties" "$GHIDRA_EXT/"
  [[ -f "$CADRE_EXT/data/languages/CADRE.opinion" ]] && \
    cp "$CADRE_EXT/data/languages/CADRE.opinion" "$GHIDRA_EXT/data/languages/"
  ok "CADRE PE Loader installed to $GHIDRA_EXT"
else
  warn "extensions/cadre-pe-loader/lib/CADRE.jar not found"
fi

# LibGhidraHost patch: include external symbols in ListSymbols RPC so
# ghidrasql `imports` and `functions` tables see what the CADRE PE Loader
# created (essential for VB6 / packed PE — stock symbols runtime omits them).
LIBGHIDRA_JAR="${GHIDRA_INSTALL_DIR:-/opt/ghidra}/Ghidra/Extensions/LibGhidraHost/lib/LibGhidraHost.jar"
PATCH_SRC="$REPO_EXT/libghidra-patch/SymbolsRuntime.java"
if [[ -f "$LIBGHIDRA_JAR" && -f "$PATCH_SRC" ]]; then
  # compile patched SymbolsRuntime against Ghidra classpath
  _CP=""
  while IFS= read -r -d '' _jar; do
    _CP="$_CP:$_jar"
  done < <(find "${GHIDRA_INSTALL_DIR:-/opt/ghidra}" -name "*.jar" -print0)
  _TMPDIR=$(mktemp -d)
  javac -cp "$_CP" -d "$_TMPDIR" "$PATCH_SRC" >/dev/null 2>&1 || warn "LibGhidraHost patch compile failed (SymbolsRuntime)"
  if [[ -f "$_TMPDIR/libghidra/host/runtime/SymbolsRuntime.class" ]]; then
    cp "$LIBGHIDRA_JAR" "$LIBGHIDRA_JAR.pre-patch"
    jar uf "$LIBGHIDRA_JAR" -C "$_TMPDIR" libghidra/host/runtime/SymbolsRuntime.class
    ok "LibGhidraHost patched (external symbols in ListSymbols)"
  fi
  rm -rf "$_TMPDIR"
else
  warn "LibGhidraHost patch skipped — jar=$LIBGHIDRA_JAR patch=$PATCH_SRC"
fi

# =========================================================================
hdr "Step 8/10 — Malcat (vendor — OPTIONAL, soft-fail)"
# =========================================================================
# Malcat is optional. The pipeline soft-fails (falls back to Mandiant capa +
# FLOSS + pe_imports) when it is absent. If a Malcat archive ships with the
# repo at internal/malcat_ubuntu24_*.zip we auto-install it; otherwise we
# warn and continue. Licensing is the user's responsibility (activate via
# the Malcat GUI once after install).
if [[ -f /opt/malcat/bin/malcat.mcp.py ]]; then
  ok "Malcat present at /opt/malcat (native capa engine available)"
elif compgen -G "$REPO_ROOT/internal/malcat_ubuntu24_*.zip" >/dev/null; then
  MALCAT_ZIP="$(ls "$REPO_ROOT"/internal/malcat_ubuntu24_*.zip | head -1)"
  warn "Malcat archive found ($MALCAT_ZIP) — installing (optional)..."
  mkdir -p /opt/malcat
  if unzip -o -q "$MALCAT_ZIP" -d /opt/malcat; then
    chmod +x /opt/malcat/bin/malcat /opt/malcat/bin/*.py /opt/malcat/bin/*.so 2>/dev/null || true
    pip install $PIP_FLAGS -r /opt/malcat/requirements.txt >/dev/null 2>&1 || true
    if python3 - <<'PY' 2>/dev/null
import importlib.util
sys.exit(0 if importlib.util.find_spec("malcat") else 1)
PY
    then
      ok "Malcat python module importable (system path)"
    else
      echo "/opt/malcat/bin" > /usr/lib/python3/dist-packages/malcat.pth 2>/dev/null || true
      ok "Malcat registered via malcat.pth"
    fi
    chown -R remnux:remnux /opt/malcat 2>/dev/null || true
    ok "Malcat files installed to /opt/malcat — activate your license via the GUI"
    ok "Verify: python3 /opt/malcat/bin/malcat.mcp.py --help"
  else
    warn "Malcat unzip failed — skipping (pipeline soft-fails without it)"
  fi
else
  warn "Malcat NOT installed and no internal/malcat_ubuntu24_*.zip found"
  warn "Pipeline runs without it (soft-fail: Mandiant capa fallback)."
  warn "Optional: download from https://malcat.fr/download.html and re-run,"
  warn "         or place the archive at internal/malcat_ubuntu24_*.zip"
fi

# =========================================================================
hdr "Step 9/10 — Core Python import check"
# =========================================================================
python3 - <<'PY' || fail "core Python imports failed"
import flask, requests, yaml, pefile, lief, frida, capa, speakeasy, oletools, yara_x
import langgraph, langchain_core, langchain_openai, z3
print("core imports OK")
PY
ok "core imports OK (including z3)"

# =========================================================================
hdr "Step 10/10 — Next steps"
# =========================================================================
cat <<EOF

============================================================
  SETUP COMPLETE — CADRE-RevAI
============================================================

Installed:
  - Ghidra + ghidrasql + CADRE PE Loader extension
  - LibGhidraHost patch (external symbols for VB6/packed PE)
  - Deobfuscation tools (z3 MBA, angr CFF, force_pe_imports)
  - capa rules + empty capa-signatures (standalone capa ready)
  - LLM stack (flask, langgraph, langchain-openai)
  - Malcat optional (pipeline degrades gracefully)

Next:
  1. source \$HOME/.cadre-env   (or add to ~/.bashrc)
  2. cp config/llm.env.template /opt/cadre-v3-tools/llm.env   # REQUIRED — fill API key
  3. ./scripts/deploy.sh --restart
  4. ./install/verify-remnux.sh
  5. Open http://<host>:5000

EOF
