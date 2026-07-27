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
hdr "Step 6/9 — Build and install ghidrasql"
# =========================================================================
if command -v ghidrasql >/dev/null 2>&1 || [[ -x /usr/local/bin/ghidrasql ]]; then
  ok "ghidrasql already installed: $(command -v ghidrasql || echo /usr/local/bin/ghidrasql)"
elif [[ -x /opt/ghidra/support/analyzeHeadless || -x /opt/ghidra/support/ghidraRun ]]; then
  bash "$REPO_ROOT/install/install-ghidrasql.sh"
else
  warn "Skipping ghidrasql build (Ghidra missing). Install Ghidra, then: sudo ./install/install-ghidrasql.sh"
fi

# =========================================================================
hdr "Step 7/9 — Malcat (vendor — required)"
# =========================================================================
if [[ -f /opt/malcat/bin/malcat.mcp.py ]]; then
  ok "Malcat present at /opt/malcat"
else
  warn "Malcat NOT found at /opt/malcat/bin/malcat.mcp.py"
  warn "Download from https://malcat.fr/download.html and install to /opt/malcat"
  warn "See docs/PREREQUISITES.md — audited runs require Malcat"
fi

# =========================================================================
hdr "Step 8/9 — Core Python import check (LLM-only)"
# =========================================================================
python3 - <<'PY' || fail "core Python imports failed"
import flask, requests, yaml, pefile, lief, frida, capa, speakeasy, oletools, yara_x
import langgraph, langchain_core, langchain_openai
print("core imports OK")
PY
ok "core imports OK"

# =========================================================================
hdr "Step 9/9 — Next steps"
# =========================================================================
cat <<EOF

============================================================
  SETUP COMPLETE — CADRE-RevAI
============================================================

Next:
  1. source \$HOME/.cadre-env   (or add to ~/.bashrc)
  2. cp config/llm.env.template /opt/cadre-v3-tools/llm.env   # REQUIRED — fill API key
  3. Install Malcat to /opt/malcat if missing (docs/PREREQUISITES.md)
  4. ./scripts/deploy.sh --restart
  5. ./install/verify-remnux.sh
  6. Open http://<host>:5000

EOF
