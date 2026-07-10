# deobfuscation/ — Z3 + angr + CFF deflatten wrapper

This folder contains the optional deobfuscation verification backend for CADRE-RevAI.

| File | Purpose |
|------|---------|
| `invoke_z3_or_angr.py` | Auto-invoke wrapper (Z3 + angr + cff_deflatten). |
| `z3_mba_tests.py` | Z3 MBA / opaque-predicate test suite. |
| `angr_cff_tests.py` | angr CFG + symbolic execution tests. |
| `bench_z3_vs_angr.py` | Benchmark all three backends. |

## Wrapper

`invoke_z3_or_angr(claim_type, sample_path, *, timeout=60, ...)` returns a structured dict:

```python
{"tool": "z3"|"angr"|"cff_deflatten", "result": ..., "duration_s": ..., "evidence": ..., "raw": {...}}
```

It falls back to `{"tool": None, "result": "untested", "duration_s": 0}` on timeout/error so the pipeline never breaks.

The wrapper is invoked by `quick_scan_v2.py` when v1/LLM flags the right signature. It is a no-op when `enable_deobfuscation_pass = False` (the v2 default).

### Invocation rules

| Trigger | Tool | Action |
|---------|------|--------|
| `v1.flags("cff_dispatcher_count > 0")` OR `family in {"vmprotect", "themida", "confuserex", "obfuscator-llvm", "dotnet reactor"}` | cff_deflatten.py | invoke the GhidraScript CFF deflatten |
| `v1.flags("mba_claim_detected")` OR `llm_rationale contains "MBA" / "opaque" / "constant unfolding"` | Z3 | verify MBA identity |
| `v1.flags("path_constraint_needed")` OR `llm_rationale contains "what input" / "reach BB"` | angr | symbolic execution for path constraints |

## Self-test

```bash
python3 /opt/cadre-v3-tools/deobfuscation/invoke_z3_or_angr.py --test
```

## Tools

- **Z3** 4.8.12 (apt + python3-z3)
- **angr** 9.2.222 (pipx)
- **GhidraScript CFF deflatten** at `/opt/cadre-v3-tools/cff-deflatten/cff_deflatten.py`
- **Ghidra 12** at `/opt/ghidra/support/analyzeHeadless`
