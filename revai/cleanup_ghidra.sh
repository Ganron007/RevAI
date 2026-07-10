#!/bin/bash
# cleanup_ghidra.sh — kill orphan analyzeHeadless + remove stale .lock files.
# Run on Remnux when Ghidra sessions leave locks behind.
set -euo pipefail
PID_DIR="/home/remnux/ghidra-sessions"
if compgen -G "$PID_DIR/*.lock*" > /dev/null; then
  rm -fv "$PID_DIR"/*.lock*
fi
echo "cleanup_ghidra ran (no locks to clean)"
