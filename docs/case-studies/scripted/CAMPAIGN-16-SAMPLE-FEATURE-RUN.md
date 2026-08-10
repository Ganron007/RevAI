# 16-Sample Feature Run - 2026-08-09

Full pipeline (`pipeline_single.py`) with all feature gates on:
`REVAI_ENABLE_AGENTIC_RECOVERY=1`, `REVAI_ENABLE_EMULATION_ORACLE=1`,
`REVAI_ENABLE_UNPACK_PASS=1`, `ENABLE_DEOBFUSCATION_PASS=1`,
recovery max-funcs 40 / tier-cap 5. 15/16 samples passed the full
audit gate (all_green).

Feature definitions, env gates and per-feature status: see
[`../../FEATURES.md`](../../FEATURES.md).

## Feature hit matrix (H = evidence present)

| Sample | G1 | G2 | G3 | G4 | G5 | G6 | G7 | G8 | G9 | G10 | angr/z3 |
|--------|---|---|---|---|---|---|---|---|---|---|---|
| sc_3048_ps1 | . | . | . | . | . | . | H | . | H | H | . |
| sc_angr_crackme2 | H | . | H | . | H | H | H | H | H | H | H |
| sc_crackme7 | H | . | H | . | H | H | H | H | H | H | . |
| sc_darkside | H | H | H | H | H | H | H | H | H | H | . |
| sc_fgg_js | . | . | . | . | . | . | H | . | H | H | . |
| sc_guloader | H | . | . | . | H | H | H | H | H | H | H |
| sc_nspack | H | . | H | H | H | H | H | H | H | H | . |
| sc_order_docm | . | . | . | . | . | . | H | . | H | H | . |
| sc_space1 | H | H | H | . | H | H | H | H | H | H | . |
| sc_steel_saz | . | . | . | . | . | . | H | . | H | H | . |
| sc_string_encryption | H | . | . | . | H | H | H | H | H | H | . |
| sc_sunburst | . | . | . | . | . | H | H | H | H | H | . |
| sc_tasksche | H | . | . | . | H | H | H | H | H | H | . |
| sc_upack037 | H | . | H | . | . | H | H | H | H | H | . |
| sc_vdaudio_dll | . | . | H | . | H | H | H | H | H | H | . |
| sc_worddoc_shellcode | . | . | . | . | . | . | H | . | H | H | . |

- **G1**: 9/16 samples with evidence
- **G2**: 2/16 samples with evidence
- **G3**: 7/16 samples with evidence
- **G4**: 2/16 samples with evidence
- **G5**: 9/16 samples with evidence
- **G6**: 11/16 samples with evidence
- **G7**: 16/16 samples with evidence
- **G8**: 11/16 samples with evidence
- **G9**: 16/16 samples with evidence
- **G10**: 16/16 samples with evidence
- **angr/z3**: 2/16 samples with evidence

## Verdicts

| Sample | Verdict |
|--------|---------|
| sc_3048_ps1 | malicious |
| sc_angr_crackme2 | suspicious |
| sc_crackme7 | crackme |
| sc_darkside | malicious |
| sc_fgg_js | malicious |
| sc_guloader | malicious |
| sc_nspack | malicious |
| sc_order_docm | malicious |
| sc_space1 | malicious |
| sc_steel_saz | suspicious |
| sc_string_encryption | suspicious |
| sc_sunburst | malicious |
| sc_tasksche | malicious |
| sc_upack037 | malicious |
| sc_vdaudio_dll | malicious |
| sc_worddoc_shellcode | malicious |
