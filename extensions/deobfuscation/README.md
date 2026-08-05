# deobfuscation/ — Z3 + angr + auto-invoke wrapper (component 4 of v3 plan)

> **Status (2026-07-04):** All three backends (Z3, angr, cff_deflatten) verified
> end-to-end. invoke_z3_or_angr.py self-test 4/4. z3_mba_tests 14/14. angr_cff_tests
> 4/4. bench_z3_vs_angr runs all three. v2 integration patch written (opt-in,
> not yet applied). cff_deflatten detection works (19 candidates on APT29);
> state-recovery still DEFERRED.

## What lives here

| File | Status | Purpose |
|------|--------|---------|
| `README.md` | done | this file |
| `invoke_z3_or_angr.py` | **DONE** | the auto-invoke wrapper (Z3 + angr + cff_deflatten). 4/4 self-test pass. |
| `z3_mba_tests.py` | **DONE** | 14-test Z3 MBA / opaque-predicate suite. 14/14 PASS in ~0.15s. |
| `angr_cff_tests.py` | **DONE** | 4-test angr suite (import, CFG, dispatcher search, sym exec). 4/4 PASS in ~3s. |
| `bench_z3_vs_angr.py` | **DONE** | benchmarks all three backends. Z3 ~6ms, angr ~1s, cff_deflatten 0.1-60s. |
| `v2-validate-integration.patch.txt` | done | opt-in patch for /opt/scripts/v2_validate.py (not yet applied; flips `ENABLE_DEOBFUSCATION_PASS=True`) |

## Component 4 spec (from v3-plan.md §6 + §13.1)

The wrapper is auto-invoked by `quick_scan_v2.py` when v1/LLM flags the right signature.
**Constraint:** when `enable_deobfuscation_pass = False` (v2 default), this wrapper is a no-op.
v3 enables it via the `enable_deobfuscation_pass` flag in `v2_validate.py` (see integration patch).

### Invocation rules (from v3-plan.md §13.1)

| Trigger | Tool | Action |
|---------|------|--------|
| `v1.flags("cff_dispatcher_count > 0")` OR `family in {"vmprotect", "themida", "confuserex", "obfuscator-llvm", "dotnet reactor"}` | cff_deflatten.py | invoke the GhidraScript CFF deflatten |
| `v1.flags("mba_claim_detected")` OR `llm_rationale contains "MBA" / "opaque" / "constant unfolding"` | Z3 | verify MBA identity (Z3 is faster than angr for pure identities) |
| `v1.flags("path_constraint_needed")` OR `llm_rationale contains "what input" / "reach BB"` | angr | symbolic execution for path constraints |

### Wrapper contract (from v3-plan.md §13.1)

```python
def invoke_z3_or_angr(claim_type: str, sample_path: str, *, timeout: int = 60,
                       claim_text=None, find_addr=None, avoid_addrs=None) -> dict:
    """Returns {"tool": "z3"|"angr"|"cff_deflatten", "result": ..., "duration_s": ...,
                "evidence": ..., "raw": {...}}
    Falls back to {"tool": None, "result": "untested", "duration_s": 0} on timeout/error.
    Never raises - always returns a structured dict so quick_scan_v2 never breaks."""
```

The wrapper writes `verdict["z3_results"]` (or `verdict["angr_results"]`,
`verdict["cff_results"]`) for the v3_validate step to consume.

## Self-test (verified 2026-07-01)

```bash
$ python3 /opt/revai/deobfuscation/invoke_z3_or_angr.py --test
=== invoke_z3_or_angr self-test ===
  Test 1 (x^y + 2*(x&y) == x+y): tool=z3 result=unsat duration=0.00s
    evidence: Z3 verified: equality holds (unsat). timeout=10s
  Test 2 (x*x - x always even): tool=z3 result=unsat
  Test 3 (x == y is not tautology): tool=z3 result=sat
  Test 4 (no-op default): tool=None result=untested
  ALL TESTS PASSED
```

| Test | Claim | Expected | Got |
|------|-------|----------|-----|
| 1 | MBA identity: `(x^y) + 2*(x&y) == x+y` | unsat (Z3 proves) | unsat |
| 2 | Opaque predicate: `(x*x - x) & 1 == 0` (always even) | unsat (Z3 proves) | unsat |
| 3 | Counterexample: `x == y` is not a tautology | sat (Z3 finds counterexample) | sat |
| 4 | No-op default (enable_deobfuscation_pass = False) | untested (no call) | untested |

## Available tools (already installed on Remnux)

- **Z3** 4.8.12 (apt + python3-z3) at `/usr/bin/z3` + Python module
- **angr** 9.2.222 (pipx) at `/home/remnux/.local/share/pipx/venvs/angr/bin/python` (used via subprocess)
- **GhidraScript CFF deflatten v1.0** at `/opt/revai/cff-deflatten/cff_deflatten.py` (used via subprocess)
- **Ghidra 12** (chocolatey on Remnux) at `/opt/ghidra/support/analyzeHeadless` (referenced but not directly called by wrapper; cff_deflatten script uses pyghidra which is its own load)

See `Tools-Catalog.csv` rows `z3/remnux`, `angr/remnux`, `cff-deflatten/remnux`.

## v2 integration (deferred)

The wrapper is in `ENABLE_DEOBFUSCATION_PASS = False` mode by default. To wire
into the v2 pipeline, see `v2-validate-integration.patch.txt` in this folder.
Apply the patch + set `ENABLE_DEOBFUSCATION_PASS=1` env var when v3 ships.

## Cross-references

- v3 plan: `Tools/v3-deploy/v3-plan.md` §6, §13.1
- v2 deep-dive: `Tools/v2-deploy/deep_dive_v2.py`
- v2 cff detector: `Tools/v2-deploy/cff_detect.py` (heuristic; v3 wires Z3 into it)
- CFF deflatten PoC: `Tools/v3-deploy/cff-deflatten/`
- Z3 + angr + PyGhidra smoke tests: see SESSION 2026-07-01c
- Integration patch: `v2-validate-integration.patch.txt` (in this folder)
