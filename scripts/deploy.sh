#!/usr/bin/env bash
# deploy.sh — deploy RevAI to a REMnux analysis VM.
# Run from the repo root as a user with passwordless sudo, or as root.
#
# Usage:
#   ./scripts/deploy.sh [--restart]

set -euo pipefail

RESTART=0
if [[ "${1:-}" == "--restart" ]]; then
    RESTART=1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

ok()   { echo "[OK]   $1"; }
warn() { echo "[WARN] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }

# Ensure target directories exist
sudo mkdir -p /opt/scripts
sudo mkdir -p /opt/revai/{config,bin,hitl,signatures}
sudo mkdir -p /opt/samples/{incoming,shortlist,corpus,logs,sessions}

# ---------------------------------------------------------------------------
# Deploy the pipeline (everything in revai/ except the hitl/ and ui/ subdirs)
# ---------------------------------------------------------------------------
ok "Deploying pipeline to /opt/scripts/ ..."
find "$REPO_ROOT/revai" -mindepth 1 -maxdepth 1 \
    -not -name "hitl" \
    -not -name "ui" \
    -not -name "__pycache__" \
    -print0 | sudo xargs -0 -I {} cp -a {} /opt/scripts/

# ---------------------------------------------------------------------------
# Deploy HITL helpers (used by the Flask critical-impact gate)
# ---------------------------------------------------------------------------
if [[ -d "$REPO_ROOT/revai/hitl" ]]; then
    ok "Deploying hitl helpers to /opt/revai/hitl/ ..."
    sudo mkdir -p /opt/revai/hitl
    sudo cp -a "$REPO_ROOT/revai/hitl"/. /opt/revai/hitl/
fi

# ---------------------------------------------------------------------------
# Build + deploy the Console UI (React/Vite -> /opt/scripts/ui)
# ---------------------------------------------------------------------------
if [[ -d "$REPO_ROOT/revai/ui" ]]; then
    if command -v npm >/dev/null 2>&1; then
        ok "Building Console UI ..."
        pushd "$REPO_ROOT/revai/ui" >/dev/null
        (npm ci || npm install) >/dev/null 2>&1
        npm run build
        popd >/dev/null
        sudo mkdir -p /opt/scripts/ui
        sudo cp -a "$REPO_ROOT/revai/ui/dist/." /opt/scripts/ui/
        ok "Console UI deployed to /opt/scripts/ui"
    else
        warn "npm not found — skipping Console UI build. Install Node.js (>=18) to build it."
    fi
fi

# ---------------------------------------------------------------------------
# Deploy tests
# ---------------------------------------------------------------------------
if [[ -d "$REPO_ROOT/tests" ]]; then
    ok "Deploying tests to /opt/scripts/tests/ ..."
    sudo mkdir -p /opt/scripts/tests
    sudo cp -a "$REPO_ROOT/tests"/test_*.py /opt/scripts/tests/ 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Deploy the release gate (layout-aware: source checkout or flat VM runtime)
# ---------------------------------------------------------------------------
if [[ -f "$REPO_ROOT/scripts/verify-release.sh" ]]; then
    ok "Deploying release gate to /opt/scripts/ ..."
    sudo cp "$REPO_ROOT/scripts/verify-release.sh" /opt/scripts/
fi

# ---------------------------------------------------------------------------
# Deploy the offline Windows-API lookup index (api_lookup)
#
# The bundled index is the small malapi default. A VM may instead carry a
# full-corpus index built from MicrosoftDocs/sdk-api (tens of MB) that is
# deliberately kept out of git - its presence must survive a deploy, so the
# default is only installed when no index exists (force with
# REVAI_FORCE_API_INDEX=1).
# ---------------------------------------------------------------------------
API_INDEX_DST=/opt/revai/api_index/api_index.db
sudo mkdir -p /opt/revai/api_index
if [[ -f "$REPO_ROOT/assets/api_index/api_index.db" ]]; then
    if [[ ! -f "$API_INDEX_DST" || "${REVAI_FORCE_API_INDEX:-0}" == "1" ]]; then
        ok "Deploying bundled API lookup index to /opt/revai/api_index/ ..."
        sudo cp -a "$REPO_ROOT/assets/api_index/api_index.db" "$API_INDEX_DST"
    else
        warn "Keeping existing $API_INDEX_DST (set REVAI_FORCE_API_INDEX=1 to replace it with the bundled default)"
    fi
    sudo cp -a "$REPO_ROOT/assets/api_index/malapi.json" /opt/revai/api_index/
    sudo cp -a "$REPO_ROOT/assets/api_index/NOTICE.md" /opt/revai/api_index/
else
    warn "assets/api_index/api_index.db missing - api_lookup will be unavailable. Build it with: python3 revai/api_index_build.py --malapi assets/api_index/malapi.json --out assets/api_index/api_index.db"
fi

# ---------------------------------------------------------------------------
# Record the deployed commit for report provenance banners
# (revai_provenance reads /opt/revai/config/REVAI_COMMIT; "-dirty" when the
# working tree differs from HEAD, e.g. a hot-patched deploy)
# ---------------------------------------------------------------------------
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
    _revai_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    if [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then
        _revai_commit="${_revai_commit}-dirty"
    fi
    printf '%s\n' "$_revai_commit" | sudo tee /opt/revai/config/REVAI_COMMIT >/dev/null
    ok "Recorded REVAI_COMMIT=$_revai_commit"
else
    warn "git metadata unavailable - report provenance will show commit unknown"
fi

# Fix ownership
sudo chown -R remnux:remnux /opt/scripts /opt/revai /opt/samples

# Install systemd service
ok "Installing systemd service ..."
sudo cp "$REPO_ROOT/install/revai.service" /etc/systemd/system/revai.service
sudo systemctl daemon-reload

if [[ "$RESTART" -eq 1 ]]; then
    ok "Restarting revai service ..."
    sudo systemctl restart revai
fi

ok "Deployment complete."

if [[ "$RESTART" -eq 1 ]]; then
    echo ""
    echo "Service restarted. Verify with:"
    echo "  python3 /opt/scripts/v2_validate.py --smoke-only"
else
    echo ""
    echo "Start the service with:"
    echo "  sudo systemctl start revai"
    echo "Then verify with:"
    echo "  python3 /opt/scripts/v2_validate.py --smoke-only"
fi
