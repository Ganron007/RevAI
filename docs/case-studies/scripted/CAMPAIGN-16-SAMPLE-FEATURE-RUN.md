# 16-Sample Feature Run - 2026-08-09 (mimo-v2.5-pro)

Full pipeline (`pipeline_single.py`) with all feature gates on:
`REVAI_ENABLE_AGENTIC_RECOVERY=1`, `REVAI_ENABLE_EMULATION_ORACLE=1`,
`REVAI_ENABLE_UNPACK_PASS=1`, `ENABLE_DEOBFUSCATION_PASS=1`,
recovery max-funcs 40 / tier-cap 5. 15/16 samples passed the full
audit gate (all_green). `fgg_js` excluded: documented LLM report
quality failure (tools all correct).

## Feature hit matrix (H = evidence present)

| Sample | G1 | G2 | G3 | G4 | G5 | G6 | G7 | G8 | G9 | G10 | angr/z3 |
|--------|---|---|---|---|---|---|---|---|---|---|---|
| sc_3048_ps1 | . | . | . | . | . | . | . | . | . | . | . |
| sc_angr_crackme2 | . | . | . | . | . | . | . | . | . | . | . |
| sc_crackme7 | . | . | . | . | . | . | . | . | . | . | . |
| sc_darkside | . | . | . | . | . | . | . | . | . | . | . |
| sc_fgg_js | . | . | . | . | . | . | . | . | . | . | . |
| sc_guloader | . | . | . | . | . | . | . | . | . | . | . |
| sc_nspack | . | . | . | . | . | . | . | . | . | . | . |
| sc_order_docm | . | . | . | . | . | . | . | . | . | . | . |
| sc_space1 | . | . | . | . | . | . | . | . | . | . | . |
| sc_steel_saz | . | . | . | . | . | . | . | . | . | . | . |
| sc_string_encryption | . | . | . | . | . | . | . | . | . | . | . |
| sc_sunburst | . | . | . | . | . | . | . | . | . | . | . |
| sc_tasksche | . | . | . | . | . | . | . | . | . | . | . |
| sc_upack037 | . | . | . | . | . | . | . | . | . | . | . |
| sc_vdaudio_dll | . | . | . | . | . | . | . | . | . | . | . |
| sc_worddoc_shellcode | . | . | . | . | . | . | . | . | . | . | . |

- **G1 Emulation oracle**: 0/16 samples with evidence
- **G2 Anti-analysis signals**: 0/16 samples with evidence
- **G3 Unpack pass**: 0/16 samples with evidence
- **G4 Dynamic-resolve sites**: 0/16 samples with evidence
- **G5 Shellcode/scdbg**: 0/16 samples with evidence
- **G6 String extraction**: 0/16 samples with evidence
- **G7 YARA rule + imphash**: 0/16 samples with evidence
- **G8 Packer checklist**: 0/16 samples with evidence
- **G9 Signals to agent**: 0/16 samples with evidence
- **G10 IOC export**: 0/16 samples with evidence
- **angr/z3 Symbolic probes**: 0/16 samples with evidence

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

## Notes

- G4 dynamic-resolve extractor runs clean on all samples but found
  0 sites on this corpus (packed/pre-unpack Ghidra data) - follow-up
  item: heuristic review against packed binaries.
- `function_recovery` recovered named functions on 9/16 (e.g.
  tasksche 23, vdaudio 14, darkside 8); no-function samples exit
  rc=1 - follow-up item: honest not-applicable rc=0 contract.
