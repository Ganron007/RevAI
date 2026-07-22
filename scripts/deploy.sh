#!/usr/bin/env bash
# deploy.sh — deploy CADRE-RevAI to a REMnux VM
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
sudo mkdir -p /opt/cadre-v4-tools
sudo mkdir -p /opt/samples/{incoming,shortlist,corpus,logs,sessions}
sudo mkdir -p /opt/revai/config

# Deploy v2 pipeline (everything in revai/ except v3/v4 subdirectories)
ok "Deploying v2 pipeline to /opt/scripts/ ..."
find "$REPO_ROOT/revai" -mindepth 1 -maxdepth 1 \
    -not -name "rag" \
    -not -name "deobfuscation" \
    -not -name "cff-deflatten" \
    -not -name "hitl" \
    -not -name "regression" \
    -not -name "v4" \
    -print0 | sudo xargs -0 -I {} cp -a {} /opt/scripts/

# Deploy v3 add-ons to /opt/cadre-v3-tools/
for dir in rag deobfuscation cff-deflatten hitl regression; do
    if [[ -d "$REPO_ROOT/revai/$dir" ]]; then
        ok "Deploying v3/$dir to /opt/cadre-v3-tools/$dir/ ..."
        sudo mkdir -p "/opt/cadre-v3-tools/$dir"
        sudo cp -a "$REPO_ROOT/revai/$dir"/* "/opt/cadre-v3-tools/$dir/"
    fi
done

# Deploy v4 agentic recovery to /opt/cadre-v4-tools/
if [[ -d "$REPO_ROOT/revai/v4" ]]; then
    ok "Deploying v4 agentic recovery to /opt/cadre-v4-tools/ ..."
    sudo cp -a "$REPO_ROOT/revai/v4"/* /opt/cadre-v4-tools/
fi

# Deploy v2 tests
if [[ -d "$REPO_ROOT/tests" ]]; then
    ok "Deploying v2 tests to /opt/scripts/tests/ ..."
    sudo mkdir -p /opt/scripts/tests
    sudo cp -a "$REPO_ROOT/tests"/test_*.py /opt/scripts/tests/ 2>/dev/null || true
fi

# Deploy v3 tests into their native directories so regression-runner can find them
for src in angr_cff_tests.py z3_mba_tests.py bench_z3_vs_angr.py; do
    if [[ -f "$REPO_ROOT/tests/$src" ]]; then
        ok "Deploying v3/deobfuscation test $src ..."
        sudo cp -a "$REPO_ROOT/tests/$src" /opt/cadre-v3-tools/deobfuscation/
    fi
done
for src in test_hybrid_search.py rag_benchmark.py; do
    if [[ -f "$REPO_ROOT/tests/$src" ]]; then
        ok "Deploying v3/rag test $src ..."
        sudo mkdir -p /opt/cadre-v3-tools/rag/tests
        sudo cp -a "$REPO_ROOT/tests/$src" /opt/cadre-v3-tools/rag/tests/
    fi
done

# Fix ownership
sudo chown -R remnux:remnux /opt/scripts /opt/cadre-v3-tools /opt/cadre-v4-tools /opt/samples
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
