#!/usr/bin/env bash
# setup-remnux.sh — install RevAI on a REMnux / Ubuntu 24.04 analysis VM
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
hdr "Step 1/13 — apt packages"
# =========================================================================
apt-get update -qq
apt-get install -y --no-install-recommends \
  nmap foremost dcfldd stegsnow testdisk pdfid oledump poppler-utils \
  dex2jar curl wget git unzip build-essential cmake ninja-build pkg-config \
  libssl-dev libffi-dev zlib1g-dev python3-dev \
  python3-venv python3-pip python3-olefile python3-oletools python3-requests python3-yaml \
  radare2 yara openjdk-21-jdk gradle \
  ghidra || true
# ghidra apt package may place files outside /opt/ghidra — normalize below
ok "apt packages installed"

# =========================================================================
hdr "Step 2/13 — Locate / normalize Ghidra → /opt/ghidra"
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
# RevAI environment
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR}"
export PATH="\$HOME/.local/bin:/usr/local/bin:\$PATH"
EOF
  chown remnux:remnux "$ENV_FILE" 2>/dev/null || true
  ok "Env saved to $ENV_FILE"
fi

# =========================================================================
hdr "Step 3/13 — Python packages (LLM-only core)"
# =========================================================================
PIP_FLAGS=""
if pip install --help 2>&1 | grep -q "break-system-packages"; then
  PIP_FLAGS="--break-system-packages --ignore-installed pip"
fi
pip install $PIP_FLAGS -r "$REPO_ROOT/requirements.txt"
ok "Python packages from requirements.txt"

# =========================================================================
hdr "Step 4/13 — pipx + angr (deobfuscation / symbolic execution)"
# =========================================================================
# The deobfuscation wrapper (extensions/deobfuscation/invoke_z3_or_angr.py)
# invokes angr through its pipx venv:
#   /home/remnux/.local/share/pipx/venvs/angr/bin/python
if ! command -v pipx >/dev/null 2>&1; then
  apt-get install -y --no-install-recommends pipx >/dev/null 2>&1 || true
fi
if command -v pipx >/dev/null 2>&1; then
  if [[ -x /home/remnux/.local/share/pipx/venvs/angr/bin/python ]]; then
    ok "angr already installed (pipx venv)"
  else
    warn "Installing angr via pipx (heavy; may take several minutes)..."
    if sudo -u remnux -H bash -lc 'pipx install angr' >/tmp/revai-angr-install.log 2>&1; then
      ok "angr installed for remnux (pipx)"
    else
      warn "angr install failed — see /tmp/revai-angr-install.log (deobfuscation pass degrades honestly)"
    fi
  fi
else
  warn "pipx unavailable — angr not installed (deobfuscation pass degrades honestly)"
fi

# =========================================================================
hdr "Step 5/13 — capa rules + YARA flat rules"
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
hdr "Step 6/13 — Lab directories"
# =========================================================================
mkdir -p /opt/samples/incoming/{manual-drop,vr-hunt-pull,cadre-push}
mkdir -p /opt/samples/{corpus,shortlist,logs,sessions}
mkdir -p /opt/scripts
# RevAI runtime home: config (llm.env), bin (capa-rs), hitl, signatures, extensions.
mkdir -p /opt/revai/{config,bin,hitl,signatures,deobfuscation,cff-deflatten}
chown -R remnux:remnux /opt/samples /opt/scripts /opt/revai 2>/dev/null || true
ok "lab dirs ready"

# =========================================================================
hdr "Step 7/13 — Build and install ghidrasql"
# =========================================================================
if command -v ghidrasql >/dev/null 2>&1 || [[ -x /usr/local/bin/ghidrasql ]]; then
  ok "ghidrasql already installed: $(command -v ghidrasql || echo /usr/local/bin/ghidrasql)"
elif [[ -x /opt/ghidra/support/analyzeHeadless || -x /opt/ghidra/support/ghidraRun ]]; then
  bash "$REPO_ROOT/install/install-ghidrasql.sh"
else
  warn "Skipping ghidrasql build (Ghidra missing). Install Ghidra, then: sudo ./install/install-ghidrasql.sh"
fi

# =========================================================================
hdr "Step 8/13 — Extensions and tools"
# =========================================================================
# deobfuscation / CFF-deflatten / force_pe_imports / capa-signatures / CADRE PE Loader
REPO_EXT="$REPO_ROOT/extensions"

# Deobfuscation tools (z3 MBA / angr) — used by deep_dive_agentic z3_solve tool
if [[ -d "$REPO_EXT/deobfuscation" ]]; then
  mkdir -p /opt/revai/deobfuscation
  cp -r "$REPO_EXT/deobfuscation/"* /opt/revai/deobfuscation/
  chown -R remnux:remnux /opt/revai/deobfuscation 2>/dev/null || true
  ok "deobfuscation tools installed to /opt/revai/deobfuscation"
else
  warn "extensions/deobfuscation not found in repo"
fi

# CFF-deflatten (angr-based control-flow-flattening recovery)
if [[ -d "$REPO_EXT/cff-deflatten" ]]; then
  mkdir -p /opt/revai/cff-deflatten
  cp -r "$REPO_EXT/cff-deflatten/"* /opt/revai/cff-deflatten/
  chown -R remnux:remnux /opt/revai/cff-deflatten 2>/dev/null || true
  ok "cff-deflatten installed to /opt/revai/cff-deflatten"
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
hdr "Step 9/13 — Extended RE tool stack (optional, soft-fail)"
# =========================================================================
# GoReSym (Go symbol recovery) → /opt/goresym/GoReSym
if [[ -x /opt/goresym/GoReSym ]]; then
  ok "GoReSym already installed"
else
  _tmp="$(mktemp -d)"
  if curl -fsSL -o "$_tmp/goresym.zip" \
      https://github.com/mandiant/GoReSym/releases/download/v3.4.1/GoReSym-linux.zip \
     && echo "a557124857f95a589f8ce3525119c2d18c7c7fc7c4225c92ff94e3effb38748d  $_tmp/goresym.zip" | sha256sum -c - >/dev/null 2>&1
  then
    unzip -o -q "$_tmp/goresym.zip" -d "$_tmp/x" 2>/dev/null || true
    _bin="$(find "$_tmp/x" -type f -name 'GoReSym*' -print -quit 2>/dev/null || true)"
    if [[ -n "$_bin" ]]; then
      mkdir -p /opt/goresym
      install -m 0755 "$_bin" /opt/goresym/GoReSym
      ok "GoReSym installed to /opt/goresym/GoReSym"
    else
      warn "GoReSym archive layout unexpected — install manually to /opt/goresym/"
    fi
  else
    warn "GoReSym download/verify failed (optional) — skipping"
  fi
  rm -rf "$_tmp"
fi

# RIFT (Rust metadata) → /opt/rift/rift_cli.py
if [[ -f /opt/rift/rift_cli.py ]]; then
  ok "RIFT already installed"
else
  if git clone --depth 1 https://github.com/microsoft/RIFT.git /opt/rift >/dev/null 2>&1; then
    pip install $PIP_FLAGS ar lief Requests >/dev/null 2>&1 || warn "RIFT python deps install failed"
    cat > /opt/rift/rift_config_linux.cfg <<'CFG'
[Default]
PcfPath = /opt/ida/pcf
SigmakePath = /opt/ida/sigmake
WorkFolder = /opt/rift/work
CargoProjFolder = /opt/rift/tmp
RustcHashes = /opt/rift/data/rustc_hashes.json
StringsTool = /usr/bin/strings

[RiftServer]
server_mode = local
Ip = 127.0.0.1
Port = 5001
flirt_dir = /opt/rift/ServerStorage
ApiKey =
TlsCert =
TlsKey =
CFG
    mkdir -p /opt/rift/work /opt/rift/tmp /opt/rift/ServerStorage
    chown -R remnux:remnux /opt/rift 2>/dev/null || true
    ok "RIFT installed to /opt/rift (metadata mode; FLIRT gen needs IDA pcf/sigmake)"
  else
    warn "RIFT clone failed (optional) — skipping"
  fi
fi

# FindCrypt (crypto constants via a Ghidra postScript) — script + signature DB
_FC_SCRIPTS="${GHIDRA_INSTALL_DIR:-/opt/ghidra}/Ghidra/Features/BytePatterns/ghidra_scripts"
if [[ -f "$_FC_SCRIPTS/FindCrypt.java" && -d /home/remnux/findcrypt_ghidra ]]; then
  ok "FindCrypt already installed"
else
  _tmp="$(mktemp -d)"
  if git clone --depth 1 https://github.com/d3v1l401/FindCrypt-Ghidra.git "$_tmp/fc" >/dev/null 2>&1; then
    if [[ -d "$_FC_SCRIPTS" ]]; then
      if cp "$_tmp/fc/FindCrypt.java" "$_FC_SCRIPTS/"; then
        ok "FindCrypt.java installed to Ghidra scripts"
      else
        warn "FindCrypt.java copy failed ($_FC_SCRIPTS)"
      fi
    else
      warn "Ghidra scripts dir not found ($_FC_SCRIPTS) — FindCrypt skipped"
    fi
    if cp -r "$_tmp/fc/findcrypt_ghidra" /home/remnux/ 2>/dev/null; then
      chown -R remnux:remnux /home/remnux/findcrypt_ghidra 2>/dev/null || true
      ok "FindCrypt signature DB at /home/remnux/findcrypt_ghidra"
    else
      warn "FindCrypt DB copy failed (optional)"
    fi
  else
    warn "FindCrypt clone failed (optional) — skipping"
  fi
  rm -rf "$_tmp"
fi

# =========================================================================
hdr "Step 10/13 — IDA Pro (optional): idasql CLI + plugin"
# =========================================================================
# Only when IDA Pro is installed. idasql is by Elias Bachaalany
# (github.com/allthingsida/idasql), Human-Origin Source License v1.0.
# The pipeline uses the CLI alongside ghidrasql; absence is a documented
# soft-fail (Ghidra SQL only).
if [[ ! -d /opt/ida ]]; then
  ok "IDA Pro not installed — Ghidra SQL only (documented soft-fail)"
elif command -v idasql >/dev/null 2>&1; then
  ok "idasql already installed: $(command -v idasql)"
else
  _ida_ver=""
  for _f in /opt/ida/Uninstall*Professional*.desktop; do
    if [[ -e "$_f" ]]; then
      _ida_ver="${_f##*Professional }"
      _ida_ver="${_ida_ver%.desktop}"
      break
    fi
  done
  case "${_ida_ver:-}" in
    9.2) _tag=ida92; _sha=a8d06205867fbd2eb89d2e9e5909bcb9ef67eff6c8fe35e4cd0cee512fed4fe0 ;;
    9.3) _tag=ida93; _sha=aedb99178ad83351a63616cff00d5e41b2aa5295dec1e55ac13e4a350fbe476a ;;
    9.4) _tag=ida94; _sha=5a6f2f15c6604f8d54f510ce92a35ea93fbab9a6162152e7c56b18f8bce9e8cc ;;
    *)   _tag=ida93; _sha=aedb99178ad83351a63616cff00d5e41b2aa5295dec1e55ac13e4a350fbe476a
         warn "IDA version '${_ida_ver:-unknown}' not in the idasql build matrix — defaulting to the IDA 9.3 build" ;;
  esac
  _tmp="$(mktemp -d)"
  if curl -fsSL -o "$_tmp/idasql.zip" \
      "https://github.com/allthingsida/idasql/releases/download/v0.0.18.1/idasql-v0.0.18.1-${_tag}.zip" \
     && echo "$_sha  $_tmp/idasql.zip" | sha256sum -c - >/dev/null 2>&1
  then
    unzip -o -q "$_tmp/idasql.zip" -d "$_tmp/x" 2>/dev/null || true
    _cli="$(find "$_tmp/x" -type f -path '*linux-x86_64/cli/idasql' -print -quit 2>/dev/null || true)"
    if [[ -n "$_cli" ]]; then
      # The CLI has RUNPATH $ORIGIN and NEEDS libida.so/libidalib.so — keep the
      # real binary next to the IDA install and expose it on PATH via symlink.
      install -m 0755 "$_cli" /opt/ida/idasql
      ln -sfn /opt/ida/idasql /usr/local/bin/idasql
      if idasql --version >/dev/null 2>&1; then
        ok "idasql CLI installed (/usr/local/bin/idasql -> /opt/ida/idasql, ${_tag})"
      else
        warn "idasql installed but 'idasql --version' failed — check libida.so in /opt/ida"
      fi
    else
      warn "idasql CLI not found in the archive — install manually (docs/PREREQUISITES.md)"
    fi
    if [[ -d /opt/ida/plugins ]]; then
      _plug="$(find "$_tmp/x" -type f -path '*linux-x86_64/plugin/idasql.so' -print -quit 2>/dev/null || true)"
      _pj="$(find "$_tmp/x" -type f -path '*linux-x86_64/plugin/ida-plugin.json' -print -quit 2>/dev/null || true)"
      if [[ -n "$_plug" ]]; then
        cp "$_plug" /opt/ida/plugins/
        if [[ -n "$_pj" ]]; then cp "$_pj" /opt/ida/plugins/; fi
        ok "idasql IDA plugin installed to /opt/ida/plugins/"
      fi
    fi
  else
    warn "idasql download/verify failed — install manually (docs/PREREQUISITES.md)"
  fi
  rm -rf "$_tmp"
fi

# =========================================================================
hdr "Step 11/13 — Dynamic companion (WinRE — OPTIONAL, soft-fail)"
# =========================================================================
# RevAI is static-first. WinRE (github.com/Ganron007/WinRE) adds optional
# Windows detonation on an isolated FlareVM; without it the pipeline and the
# reports are unchanged (dynamic corroboration is presence-gated). Install it
# here with:
#     REVAI_WITH_WINRE=1 sudo -E ./install/setup-remnux.sh
# or drop a WinRE archive at internal/winre.zip (air-gapped installs).
WINRE_DIR="${REVAI_WINRE_DIR:-/opt/winre}"
if [[ -f "$WINRE_DIR/winre/pipeline.py" ]]; then
  ok "WinRE present at $WINRE_DIR"
elif [[ "${REVAI_WITH_WINRE:-0}" != "1" && ! -f "$REPO_ROOT/internal/winre.zip" ]]; then
  warn "WinRE not installed (optional) — static-only reports"
  warn "Enable dynamic analysis with: REVAI_WITH_WINRE=1 sudo -E ./install/setup-remnux.sh"
else
  _winre_ok=0
  if [[ -f "$REPO_ROOT/internal/winre.zip" ]]; then
    mkdir -p "$WINRE_DIR"
    if unzip -o -q "$REPO_ROOT/internal/winre.zip" -d "$WINRE_DIR"; then _winre_ok=1; fi
  elif command -v git >/dev/null 2>&1; then
    if git clone --depth 1 --branch "${REVAI_WINRE_REF:-master}" \
        "${REVAI_WINRE_REPO:-https://github.com/Ganron007/WinRE.git}" "$WINRE_DIR" >/dev/null 2>&1; then
      _winre_ok=1
    fi
  fi
  if [[ "$_winre_ok" == "1" ]]; then
    # System-site-packages so WinRE reuses the RevAI-installed deps (pefile, ...).
    python3 -m venv --system-site-packages "$WINRE_DIR/venv" >/dev/null 2>&1 || true
    if [[ -x "$WINRE_DIR/venv/bin/pip" ]]; then
      "$WINRE_DIR/venv/bin/pip" install -q langgraph langchain-openai \
        langchain-core pydantic >/dev/null 2>&1 || warn "WinRE venv dependency install failed"
    fi
    if [[ ! -f "$WINRE_DIR/.env" && -f "$WINRE_DIR/.env.template" ]]; then
      cp "$WINRE_DIR/.env.template" "$WINRE_DIR/.env"
      chmod 600 "$WINRE_DIR/.env" 2>/dev/null || true
      ok "WinRE .env scaffolded ($WINRE_DIR/.env) — fill in your own values, never commit"
    fi
    chown -R remnux:remnux "$WINRE_DIR" 2>/dev/null || true
    ok "WinRE installed at $WINRE_DIR (control plane)"
    warn "Next: set up the FlareVM side (WinRE install/setup-flarevm.ps1), then"
    warn "      Console -> Settings -> Dynamic analysis (WinRE): address, user, SSH key"
    warn "      (or env: FLARE_HOST / FLARE_USER / FLARE_SSH_KEY)"
  else
    warn "WinRE install failed (optional) — static-only; see docs/WINRE-REMOTE.md"
  fi
fi

# =========================================================================
hdr "Step 12/13 — Malcat (vendor — OPTIONAL, soft-fail)"
# =========================================================================
# Malcat is optional. The pipeline soft-fails (falls back to Mandiant capa +
# FLOSS + pe_imports) when it is absent. If a Malcat archive ships with the
# repo at internal/malcat.zip we auto-install it; otherwise we warn and
# continue. Licensing is the user's responsibility (activate via the Malcat
# GUI once after install).
if [[ -f /opt/malcat/bin/malcat.mcp.py ]]; then
  ok "Malcat present at /opt/malcat (native capa engine available)"
  # Ensure python deps + module registration even for an existing install
  # (idempotent; a manually extracted package may lack either).
  if [[ -f /opt/malcat/requirements.txt ]]; then
    if pip install $PIP_FLAGS -q -r /opt/malcat/requirements.txt >/dev/null 2>&1; then
      ok "Malcat python deps present"
    else
      warn "Malcat python deps install failed — check /opt/malcat/requirements.txt"
    fi
  fi
  if [[ -f /usr/lib/python3/dist-packages/malcat.pth ]]; then
    ok "Malcat module registered (malcat.pth)"
  else
    echo "/opt/malcat/bin" > /usr/lib/python3/dist-packages/malcat.pth 2>/dev/null || true
    ok "Malcat registered via malcat.pth"
  fi
  ok "Activate the Malcat license once via the GUI if not already done"
elif [[ -f "$REPO_ROOT/internal/malcat.zip" ]]; then
  MALCAT_ZIP="$REPO_ROOT/internal/malcat.zip"
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
  warn "Malcat NOT installed and no internal/malcat.zip found"
  warn "Pipeline runs without it (soft-fail: Mandiant capa fallback)."
  warn "Optional: download from https://malcat.fr/download.html, rename the"
  warn "         package to malcat.zip, place it at internal/malcat.zip, and"
  warn "         re-run the installer."
fi

# =========================================================================
hdr "Step 13/13 — Core Python import check"
# =========================================================================
python3 - <<'PY' || fail "core Python imports failed"
import flask, requests, yaml, pefile, lief, frida, capa, speakeasy, oletools, yara_x
import langgraph, langchain_core, langchain_openai, z3
print("core imports OK")
PY
ok "core imports OK (including z3)"

# =========================================================================
hdr "Setup summary"
# =========================================================================
cat <<EOF

============================================================
  SETUP COMPLETE — RevAI
============================================================

Installed:
  - Ghidra + ghidrasql + CADRE PE Loader extension
  - LibGhidraHost patch (external symbols for VB6/packed PE)
  - Deobfuscation tools (z3 MBA, angr via pipx, force_pe_imports)
  - Extended tool stack: GoReSym, RIFT, FindCrypt (soft-fail)
  - capa rules + empty capa-signatures (standalone capa ready)
  - LLM stack (flask, langgraph, langchain-openai)
  - idasql + IDA plugin (only when IDA Pro is installed)
  - Malcat optional (pipeline degrades gracefully)
  - WinRE dynamic companion optional (statics unchanged without it)

Next:
  1. source \$HOME/.cadre-env   (or add to ~/.bashrc)
  2. sudo mkdir -p /opt/revai/config && sudo cp config/llm.env.template /opt/revai/config/llm.env   # REQUIRED — fill API key
  3. ./scripts/deploy.sh --restart
  4. ./install/verify-remnux.sh
  5. Open http://<host>:5000
     - Dynamic analysis (optional): install WinRE with
       REVAI_WITH_WINRE=1 sudo -E ./install/setup-remnux.sh
       then set the FlareVM address/key in Settings -> Dynamic analysis (WinRE)
       (docs/WINRE-REMOTE.md has the full two-machine guide)

EOF
