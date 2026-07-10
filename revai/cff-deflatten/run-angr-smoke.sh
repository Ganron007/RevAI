#!/bin/bash
# run-angr-smoke.sh - run angr availability + CFG + sym-exec smoke test on the
# synthetic CFF fixture built by rebuild-cff-fixtures.sh.
#
# The fixture (cff_flat.exe) is built into /tmp/cff-test/ by
# rebuild-cff-fixtures.sh. The angr scripts live alongside this file in
# the cff-deflatten/ source tree.
set +e
HERE="$(cd "$(dirname "$0")" && pwd)"
ANGR_PY="/home/remnux/.local/share/pipx/venvs/angr/bin/python"
TARGET="/tmp/cff-test/cff_flat.exe"

if [ ! -f "$TARGET" ]; then
  echo "(cff_flat.exe not found; running rebuild-cff-fixtures.sh)"
  bash "$HERE/rebuild-cff-fixtures.sh" 2>&1 | tail -5
fi

if [ ! -f "$TARGET" ]; then
  echo "FAIL: $TARGET still missing after rebuild; aborting."
  exit 1
fi

"$ANGR_PY" "$HERE/angr_smoke.py" 2>&1 | grep -v "Filling register\|Filling memory\|Tried to look up\|__chkstk_ms\|WARNING\|ERROR.*unicorn" | head -60
