# CFF Deflatten v1.0

RevAI extension: automated detection and edge-recovery for control-flow flattening (CFF) obfuscation patterns. Built on Ghidra's PyGhidra Python interface.

## What it does

Given a PE/ELF binary, the script:

1. Walks every basic block in the program via `BasicBlockModel`.
2. For blocks with high outdegree (>=3 destinations), counts how many of those destinations are "case bodies" — sub-graphs whose *only* outgoing edges return to the candidate.
3. If >= 2 case bodies return to the candidate, classifies it as a dispatcher block (the CFF state-machine hub).
4. For each detected case body, scans the last `STORE <constant>` p-code before the loop-back — that's the `state = K` assignment that drives the CFF.
5. Emits a recovered edge list: `case_target → next_state → (resolves to next case body)`.

## Run

```bash
# basic scan
python3 cff_deflatten.py --input /path/to/binary.exe

# JSON output (machine-readable)
python3 cff_deflatten.py --input /path/to/binary.exe --json
```

Requires:
- Ghidra 12+ installed at `/opt/ghidra` (or `%PROGRAMFILES%\GHIDRA` on Windows)
- Python 3 with `pyghidra` and `jpype1` installed
- Run via `pyghidra.start()` + `open_program()` inside the script

## Algorithm sources

Well-known CFF deflattening lineage: published academic work on dispatcher detection via back-edge density. Implementation here is original to this project.

## Test fixtures

Two synthetic PEs in `tests/`:

- `cff_orig.exe` — original (non-flattened) C compiler output for ground truth
- `cff_flat.exe` — manually-flattened with the classic `while(1) switch(state)` idiom

Build:

```bash
x86_64-w64-mingw32-gcc -O0 -o cff_orig.exe cff_orig.c
x86_64-w64-mingw32-gcc -O0 -o cff_flat.exe cff_flat.c
```

## Known limitations

1. **Jump-table resolution dependency**: Ghidra's basic-block analysis must enumerate the dispatcher's indirect jump destinations. When this fails (e.g., when Ghidra splits the function into sub-functions), the script sees `outdegree=1` instead of the expected 8, and misses the dispatcher.
2. **Deflattening not implemented**: v1 reports recovered edges but does not re-emit a deflattened function. v2 would patch the Ghidra listing.
3. **State recovery heuristic incomplete**: detection finds dispatchers (19 on APT29 TrojanCozyBear.bin), but `find_state_assignment()` returns 0 recovered edges. The companion `angr_cff_solver.py` (pre-existing in this dir) takes a different approach (symbolic exec from function entry) and DOES recover state on the synthetic `cff_flat.exe` fixture.

## Companion tools

- `tests/cff_*.c` — synthetic fixtures (this dir)
- `angr_cff_solver.py` — symbolic-exec CFF solver (pre-existing, works on synthetic fixture)
- `angr_smoke.py` — angr availability / CFG build smoke test
- `rebuild-cff-fixtures.sh` — builds the synthetic CFF test fixtures
- `run-angr-smoke.sh`, `run-cff-solver.sh` — wrapper scripts (note: path bug — they point to `/tmp/cff-deflatten/` but files are in this dir; fix before running)
- Tool catalog: `CADRE-Eva7ion/tools/deployment/Tools-Catalog.csv` rows `cff-deflatten` and `z3`

## Setup notes (Remnux .41)

```bash
sudo apt install -y z3           # Z3 4.8.12 (CLI + python3-z3)
pip install --user --break-system-packages \
    /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.1.0-py3-none-any.whl
```

PyGhidra install also pulls `jpype1` 1.5.2.

## Status (2026-07-04)

- ✅ Script written, ~220 lines, fully self-contained
- ✅ Compiles/parses, imports correctly under PyGhidra 3.1
- ✅ Basic-block + stack-based traversal working
- ✅ Detection works on real samples: 19 dispatcher candidates on APT29 TrojanCozyBear.bin (`--min-outdegree 2 --min-case-targets 1`)
- ⚠️ Detection returns 0 candidates on synthetic `cff_flat.exe` due to Ghidra's auto-analysis fragmenting the function (case bodies get classified as separate `__do_global_*` stubs); the companion `angr_cff_solver.py` solves this for the same fixture via Z3-backed symbolic exec
- ⚠️ State-recovery (`recovered_edges`) is 0 for all candidates — DEFERRED (research-level)
- ✅ Bug fixes (2026-07-04): `global` declaration moved to top of `main()`; PcodeOp array access changed from `.size()/.get(i)` to `len(pcode)/pcode[i]` (Jython/Java-array semantics)
