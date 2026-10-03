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

Synthetic fixtures in `tests/`:

- `cff_orig.c` — original (non-flattened) C compiler output for ground truth
- `cff_flat.c` — manually-flattened with the classic `while(1) switch(state)` idiom
- `cff_computed_goto.c` — real indirect dispatch via computed goto (the strong
  positive control: the detector must find it at the shipped defaults)

Build everything with `rebuild-cff-fixtures.sh` (ELF builds via the system gcc
always run; Windows-PE builds via `x86_64-w64-mingw32-gcc` are skipped when
mingw is absent — the detector analyses blocks, not format):

```bash
bash rebuild-cff-fixtures.sh     # fixtures land in /tmp/cff-test/
```

## Calibration — thresholds and controls (measured 2026-10-03)

`find_dispatchers` requires outdegree >= 3 and >= 2 case targets returning to
the candidate (`--min-outdegree` / `--min-case-targets` override per run).
The defaults are calibrated against the fixtures above:

| Control | -O0 | -O2 |
|---|---|---|
| computed goto (`cff_goto`) | **fires**: 1 candidate, `cff_goto_demo`, outdeg=5, back=4 | silent — GCC devirtualises the computed goto into direct branches; NOT a valid -O2 control |
| while-switch (`cff_flat`) | silent on this small ELF (Ghidra fragments the function) | silent at default; 1 candidate (`main`, inlined, outdeg=3, back=1) with `--min-case-targets 1` |
| original (`cff_orig`) | silent | silent |

The `--min-case-targets 1` case is the documented reason the default must NOT
be lowered: a single returning arm is what a compiler's own switch lowering
produces (and what inlining collapses to), so threshold 1 would flag ordinary
code. Real flattened samples show two or more returning arms — on
Cryptowall/APT29 TrojanCozyBear.bin the operator used explicit
`--min-outdegree 2 --min-case-targets 1` and got 19 candidates, a per-sample
override rather than a default change.

## Known limitations

1. **Jump-table resolution dependency**: Ghidra's basic-block analysis must enumerate the dispatcher's indirect jump destinations. When this fails (e.g., when Ghidra splits the function into sub-functions), the script sees `outdegree=1` instead of the expected 8, and misses the dispatcher.
2. **Deflattening not implemented**: v1 reports recovered edges but does not re-emit a deflattened function. v2 would patch the Ghidra listing.
3. **State recovery heuristic incomplete**: detection finds dispatchers (19 on APT29 TrojanCozyBear.bin), but `find_state_assignment()` returns 0 recovered edges. The companion `angr_cff_solver.py` (pre-existing in this dir) takes a different approach (symbolic exec from function entry) and DOES recover state on the synthetic `cff_flat.exe` fixture.

## Companion tools

- `tests/cff_*.c` — synthetic fixtures (this dir)
- `angr_cff_solver.py` — symbolic-exec CFF solver (pre-existing, works on synthetic fixture)
- `angr_smoke.py` — angr availability / CFG build smoke test
- `rebuild-cff-fixtures.sh` — builds all synthetic CFF fixtures (-O0/-O2, ELF + optional PE)
- `run-angr-smoke.sh`, `run-cff-solver.sh` — wrapper scripts
- Tool catalog rows `cff-deflatten` and `z3`

## Setup notes (Remnux .41)

```bash
sudo apt install -y z3           # Z3 4.8.12 (CLI + python3-z3)
pip install --user --break-system-packages \
    /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-3.1.0-py3-none-any.whl
```

PyGhidra install also pulls `jpype1` 1.5.2.

## Status (2026-10-03)

- Script written, fully self-contained; runs under PyGhidra 3.1/Ghidra 12.1.2.
- **Detector defects fixed 2026-10-01** (pinned in
  `tests/test_cff_detector.py`): blocks were compared with `==` on
  separately-obtained Ghidra wrappers (reference equality — no case arm was
  ever recognised as returning), and a case arm had to have the dispatcher as
  *every* successor (real arms also fall through). With both fixed the
  computed-goto positive control fires at the shipped defaults and names the
  function.
- Detection works on real samples: 19 dispatcher candidates on APT29
  TrojanCozyBear.bin (`--min-outdegree 2 --min-case-targets 1`); silent over
  10304 blocks on winservices.exe (a real, unflattened sample — the negative
  direction holds).
- Threshold calibration measured 2026-10-03 (see above); the defaults of 2/3
  are deliberate and must not be lowered to make a weak control pass.
- State-recovery (`recovered_edges`) is 0 for all candidates — DEFERRED
  (research-level).
- Bug fixes (2026-07-04): `global` declaration moved to top of `main()`;
  PcodeOp array access changed from `.size()/.get(i)` to `len(pcode)/pcode[i]`
  (Jython/Java-array semantics).
