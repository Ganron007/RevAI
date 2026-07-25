#!/usr/bin/env bash
# deploy.sh — deploy CADRE-RevAI to a REMnux analysis VM.
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
sudo mkdir -p /opt/cadre-v3-tools
sudo mkdir -p /opt/samples/{incoming,shortlist,corpus,logs,sessions}
sudo mkdir -p /opt/revai/config

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
    ok "Deploying hitl helpers to /opt/cadre-v3-tools/hitl/ ..."
    sudo mkdir -p /opt/cadre-v3-tools/hitl
    sudo cp -a "$REPO_ROOT/revai/hitl"/. /opt/cadre-v3-tools/hitl/
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

# Fix ownership
sudo chown -R remnux:remnux /opt/scripts /opt/cadre-v3-tools /opt/samples
sudo chown -R remnux:remnux /opt/revai/config 2>/dev/null || true

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
