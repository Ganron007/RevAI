#!/usr/bin/env bash
# setup-remnux.sh — install CADRE-RevAI dependencies on a REMnux VM
# Target: REMnux 202602 / Ubuntu 24.04 LTS
# Run as root or with sudo.
#
# Usage:
#   sudo ./install/setup-remnux.sh

set -e

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

ok()   { echo -e "${GREEN}[OK]${NC}   $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
hdr()  { echo -e "\n${YELLOW}=== $1 ===${NC}"; }

# =========================================================================
# Step 1 — apt update + system packages
# =========================================================================
hdr "Step 1/8 — apt update + system packages"

apt-get update -qq

# Core REMnux/RE tooling
apt-get install -y --no-install-recommends \
    nmap foremost dcfldd stegsnow testdisk pdfid oledump poppler-utils \
    dex2jar curl wget git build-essential libssl-dev libffi-dev python3-dev \
    python3-venv python3-pip python3-olefile python3-oletools python3-requests python3-yaml \
    radare2 yara ghidra z3 libz3-dev python3-z3

ok "apt packages installed"

# =========================================================================
# Step 2 — Install uv (for ghidra-rpc)
# =========================================================================
hdr "Step 2/8 — Install uv"

if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # shellcheck disable=SC1091
    source "$HOME/.local/bin/env"
    ok "uv installed: $(uv --version)"
else
    ok "uv already present: $(uv --version)"
fi

# =========================================================================
# Step 3 — Install ghidra-rpc via uv
# =========================================================================
hdr "Step 3/8 — Install ghidra-rpc"

if ! command -v ghidra-rpc >/dev/null 2>&1; then
    uv tool install ghidra-rpc
    ok "ghidra-rpc installed"
else
    ok "ghidra-rpc already present"
fi

# Auto-detect Ghidra install
if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
    for candidate in /opt/ghidra /usr/local/ghidra /opt/ghidra_* /opt/ghidra-*; do
        if [[ -d "$candidate" ]] && { [[ -x "$candidate/ghidraRun" ]] || [[ -x "$candidate/support/ghidraRun" ]]; }; then
            export GHIDRA_INSTALL_DIR="$candidate"
            ok "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR"
            break
        fi
    done
    if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
        warn "Ghidra install not auto-detected; set GHIDRA_INSTALL_DIR manually if ghidra-rpc fails"
        GHIDRA_INSTALL_DIR=/opt/ghidra
    fi
fi

# Persist env vars
ENV_FILE="$HOME/.cadre-env"
cat > "$ENV_FILE" <<EOF
# CADRE-RevAI environment
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR}"
export PATH="\$HOME/.local/bin:\$PATH"
EOF
ok "Env saved to $ENV_FILE (add 'source \$HOME/.cadre-env' to ~/.bashrc)"

# =========================================================================
# Step 4 — Python RE ecosystem (pip)
# =========================================================================
hdr "Step 4/8 — Python RE ecosystem (pip)"

PIP_FLAGS=""
if pip install --help 2>&1 | grep -q "break-system-packages"; then
    PIP_FLAGS="--break-system-packages"
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pip install $PIP_FLAGS -r "$REPO_ROOT/requirements.txt"

ok "Python packages installed"

# =========================================================================
# Step 5 — capa rules + YARA flat rules
# =========================================================================
hdr "Step 5/8 — capa rules + YARA flat rules"

if [[ ! -d /opt/capa-rules ]]; then
    git clone --depth 1 https://github.com/mandiant/capa-rules.git /opt/capa-rules
    chown -R remnux:remnux /opt/capa-rules
    ok "capa-rules cloned to /opt/capa-rules"
else
    ok "capa-rules already at /opt/capa-rules"
fi

if [[ ! -d /opt/samples/rules/flat ]] || [[ -z "$(ls -A /opt/samples/rules/flat 2>/dev/null)" ]]; then
    mkdir -p /opt/samples/rules/flat
    chown remnux:remnux /opt/samples/rules/flat
    if [[ -d /usr/local/yara-rules ]]; then
        find /usr/local/yara-rules -name "*.yar" -not -name "*_index.yar" -not -name "index.yar" 2>/dev/null | \
        while read -r f; do
            bn=$(basename "$f")
            [[ ! -f "/opt/samples/rules/flat/$bn" ]] && cp "$f" "/opt/samples/rules/flat/$bn"
        done
        chown -R remnux:remnux /opt/samples/rules/flat
        ok "YARA rules flattened: $(ls /opt/samples/rules/flat | wc -l) rules"
    else
        warn "/usr/local/yara-rules not found; skipping YARA flat build"
    fi
else
    ok "YARA flat rules already at /opt/samples/rules/flat"
fi

# =========================================================================
# Step 6 — Lab directory structure
# =========================================================================
hdr "Step 6/8 — Lab directory structure"

mkdir -p /opt/samples/incoming/{manual-drop,vr-hunt-pull,cadre-push}
mkdir -p /opt/samples/corpus
mkdir -p /opt/samples/shortlist
mkdir -p /opt/scripts
mkdir -p /opt/samples/logs
mkdir -p /opt/cadre-v3-tools
mkdir -p /opt/cadre-v4-tools
mkdir -p /opt/revai/config
chown -R remnux:remnux /opt/samples /opt/scripts /opt/cadre-v3-tools /opt/cadre-v4-tools /opt/revai
ok "Lab directory structure created"

# =========================================================================
# Step 7 — GhidraSQL skills extension
# =========================================================================
hdr "Step 7/8 — GhidraSQL skills extension"

if [[ ! -d /opt/ghidrasql-skills ]]; then
    git clone https://github.com/0xeb/ghidrasql-skills /opt/ghidrasql-skills
    ok "ghidrasql-skills cloned to /opt/ghidrasql-skills"
else
    ok "ghidrasql-skills already at /opt/ghidrasql-skills"
fi

# =========================================================================
# Step 8 — Final verification
# =========================================================================
hdr "Step 8/8 — Final verification"

python3 -c "import pefile, lief, frida, capa, speakeasy, oletools, z3, angr, faiss, sentence_transformers, fastapi, uvicorn" && ok "Python imports OK" || warn "Some Python imports failed"

echo ""
echo "============================================================"
echo "  SETUP COMPLETE — CADRE-RevAI on REMnux"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Source the env:                 source \$HOME/.cadre-env"
echo "  2. Add to ~/.bashrc:                echo 'source \$HOME/.cadre-env' >> ~/.bashrc"
echo "  3. Configure LLM:                   cp config/llm.env.template /opt/cadre-v3-tools/llm.env"
echo "  4. Configure RAG:                   cp config/rag.env.template /opt/cadre-v3-tools/rag.env"
echo "  5. Deploy pipeline:                 ./scripts/deploy.sh"
echo "  6. Start service:                   sudo systemctl start revai"
echo "  7. Verify:                          python3 /opt/scripts/v2_validate.py --smoke-only"
echo ""
