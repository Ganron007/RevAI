#!/bin/bash
# Rebuild the CFF control fixtures under /tmp/cff-test.
#
# Two families, both used to calibrate cff_deflatten.find_dispatchers:
#   * the while-switch fixtures (cff_flat / cff_orig) -- a state machine and
#     its unflattened original
#   * the computed-goto positive control (cff_computed_goto) -- real indirect
#     dispatch, the shape the detector must catch
#
# ELF builds use the VM's gcc and always run. The Windows-PE builds need
# mingw-w64 and are skipped (not failed) when it is absent; the detector
# analyses blocks, not format, so ELF is a valid control substrate.
#
# 2026-10-03: -O2 variants added because the open calibration question
# ("-O2 needs --min-case-targets 1") is only reproducible when the -O2
# control exists as a first-class artifact.
set +e
mkdir -p /tmp/cff-test
cd "$(dirname "$0")"

# --- sources ----------------------------------------------------------------
cp cff_orig.c cff_flat.c tests/cff_computed_goto.c /tmp/cff-test/ 2>/dev/null

# --- ELF builds (always available) -----------------------------------------
gcc -O0 -o /tmp/cff-test/cff_orig.elf      /tmp/cff-test/cff_orig.c
gcc -O2 -o /tmp/cff-test/cff_orig_O2.elf   /tmp/cff-test/cff_orig.c
gcc -O0 -o /tmp/cff-test/cff_flat.elf      /tmp/cff-test/cff_flat.c
gcc -O2 -o /tmp/cff-test/cff_flat_O2.elf   /tmp/cff-test/cff_flat.c
gcc -O0 -o /tmp/cff-test/cff_goto.elf      /tmp/cff-test/cff_computed_goto.c
gcc -O2 -o /tmp/cff-test/cff_goto_O2.elf   /tmp/cff-test/cff_computed_goto.c

# --- Windows-PE builds (optional) ------------------------------------------
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -O0 -o /tmp/cff-test/cff_orig.exe    /tmp/cff-test/cff_orig.c
    x86_64-w64-mingw32-gcc -O0 -o /tmp/cff-test/cff_flat.exe    /tmp/cff-test/cff_flat.c
    x86_64-w64-mingw32-gcc -O2 -o /tmp/cff-test/cff_orig_O2.exe /tmp/cff-test/cff_orig.c
    x86_64-w64-mingw32-gcc -O2 -o /tmp/cff-test/cff_flat_O2.exe /tmp/cff-test/cff_flat.c
else
    echo "[fixtures] mingw-w64 absent -- skipping the Windows-PE builds"
fi

ls -la /tmp/cff-test/
file /tmp/cff-test/cff_goto.elf /tmp/cff-test/cff_goto_O2.elf 2>/dev/null
