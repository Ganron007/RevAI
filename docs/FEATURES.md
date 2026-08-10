# RevAI — Feature Inventory & Status

Single source of truth for every pipeline feature: what it does, which env gate
controls it, where it runs, what artifact it produces, and its status in the
2026-08-09 16-sample feature run (15/16 green).

## Deterministic extractors (run in quick_scan / deep_dive)

| # | Feature | What it does | Gate (env) | Stage | Artifact |
|---|---------|-------------|-----------|-------|----------|
| G1 | **Emulation oracle** | Bounded Speakeasy emulation; records executed instructions, dynamically resolved imports, executed→function mapping | `REVAI_ENABLE_EMULATION_ORACLE=1` | deep_dive seeds | `deep_dive/03-oracle.json` |
| G2 | **Anti-analysis signals** | Deterministic scan for debugger/VM/timing/TLS anti-analysis patterns | always on (PE/unknown) | quick_scan + deep_dive seeds | `deep_dive/02-signals.json` (`anti_analysis`) |
| G3 | **Unpack pass** | Emulation-assisted unpack/carve when packer checklist flags packed/suspicious | `REVAI_ENABLE_UNPACK_PASS=1` | deep_dive seeds | `deep_dive/02-signals.json` (`unpack`) + `logs/<sha>/unpack/` |
| G4 | **Dynamic-resolve detector** | Finds API-resolve sites (GetProcAddress/LdrGetProcedureAddress patterns) | always on | quick_scan + deep_dive seeds | `deep_dive/02-signals.json` (`dynamic_resolve`) |
| G5 | **Shellcode/scdbg path** | scdbg emulation of raw shellcode; shellcode checklist tool | always on | deep_dive checklist + agent | agent history `deep-dive-agentic-history.json` |
| G6 | **String extraction** | FLOSS (PE) + Malcat strings with ref counts | always on (format-gated) | quick_scan | `quick_scan/00-tools-raw.json` (`floss`/`malcat`) + `evidence/strings.txt` |
| G7 | **YARA rule gen (imphash)** | Auto rule from strings/imphash/hex sigs; validation + goodware FP scan | always on | yara_gen | `rule.yar`, `rule.yara.json`, `rule.yml` |
| G8 | **Packer checklist** | Deterministic packer_intake scoring (entropy/sections/imports) | always on | quick_scan + deep_dive | `packer.txt`, gate context for packed policy |
| G9 | **Signals → agent prompt** | Seeds G1–G4 findings into the agent's evidence so it cites them | always on | deep_dive seeds | findings + agent history |
| G10 | **IOC export** | Structured pack: hashes/domains/ips/urls/files/registry/mutexes | always on | yara_gen | `iocs.json` |
| — | **angr / z3 probes** | Symbolic execution + SMT solving via `extensions/deobfuscation` | `ENABLE_DEOBFUSCATION_PASS=1` | deep_dive checklist (`z3_solve`, `angr_analyze`) | agent history + deep verdict |

## Analysis stages

| Feature | What it does | Gate | Artifact |
|---------|-------------|------|----------|
| Intake (PE/doc/script) | hashing, staging, Ghidra/IDA import (doc formats: doc_triage/olevba/peepdf), engine validation + source decisions | — | `intake-validation.json`, `source-decisions.json`, `doc-triage.json` |
| quick_scan | capa (malcat→capa-rs→Mandiant chain), yara, floss, malcat deep, pe_imports, packer; LLM verdict + v1 fallback + calibration + citation grounding | — | `verdict.json`, `00-tools-raw.json`, `prompt.txt` |
| deep_dive (agentic) | LangGraph ReAct agent; checklist tools + SQL deep (Ghidra/IDA) + signal seeds | `REVAI_AGENTIC_ENGINE=langgraph` | `05-deep-dive.json`, `agentic_deep_dive.json`, `evidence-pack.md` |
| Function recovery | Hybrid oracle/resolve-assisted naming, tiered (max-funcs/tier-cap) | `REVAI_ENABLE_AGENTIC_RECOVERY=1`, `REVAI_AGENTIC_RECOVERY_MAX_FUNCS=40`, `REVAI_AGENTIC_RECOVERY_TIER_CAP=5` | `function-recovery.json` |
| Publish v2 | Master + technical LLM reports with quality gate | — | `REPORT-v2.md`, `REPORT-MASTER-v2.md`, `REPORT-TECHNICAL-v2.md` |
| Publish v3 (sections) | Section-by-section reports with cross-section context | — | `REPORT-MASTER-v3.md`, `REPORT-TECHNICAL-v3.md`, `section-results-v3.json` |
| Audit | Independent re-check: tools_all_ok, citations grounded, engine citations, report completeness, depth coverage, verdict lock | — | `pipeline-audit.json`, `AUDIT-REPORT.md`, showcase packs |

## Reliability & policy features (added in the 2026-08-09 run)

| Feature | What it fixes | Status |
|---------|--------------|--------|
| capa format routing | capa only runs on PE/ELF/Mach-O/.NET; raw/scripts/docs skip+fail-open (was aborting on `format=unknown`) | ✅ live |
| Packed-sample policy | packer-flagged stubs: capa clean-0-rule accepted as `packed_stub`; floss/dotnet incomplete = documented soft-fail (recorded, never hidden) | ✅ live |
| r2 UTF-8 decode | r2 output decoded with `errors=replace` (was crashing on non-UTF8 bytes) | ✅ live |
| mimo abort handling | `llm_judge` validates `finish_reason`; retries with reasoning downgrade then no-thinking fallback (was accepting truncated output) | ✅ live |
| Doc-intake evidence | doc formats now write intake-validation + source-decisions stubs (was failing audit forever) | ✅ live |
| Deep-dive packer context | checklist adds deterministic packer scan so gates share the packed policy | ✅ live |
| Goodware fingerprint | known-good SHA short-circuit → clean verdict, skips LLM | always on |

## External integrations

| Feature | Gate | Status |
|---------|------|--------|
| **TI-enrich (VirusTotal + Hybrid Analysis hash lookup)** | `REVAI_TI_ENRICH=1` + `VT_API_KEY` + `HA_API_KEY` in `/opt/revai/config/cadre.env` | ⚠️ **DISABLED — keys not configured** (lost in env rewrite). Enrichment-only, never clears local gates. |
| LLM (OpenRouter-compatible) | `REVAI_LLM_MODEL` / `REVAI_LLM_API_URL` / `REVAI_LLM_API_KEY` / `REVAI_LLM_REASONING` in `/opt/revai/config/llm.env` | ✅ mimo-v2.5-pro live |

## Run status (2026-08-09, 16 samples, all features on)

15/16 `all_green`. G1 9/16 · G2 2/16 · G3 7/16 · G4 0/16 (extractor runs clean —
follow-up: heuristic review vs packed Ghidra data) · G5 9/16 · G6 11/16 ·
G7/G9/G10 16/16 · G8 11/16 · angr/z3 2/16 · recovery: named functions on 9/16
(tasksche 23, vdaudio 14, darkside 8). `fgg_js` excluded: documented LLM
report-quality failure (all tools correct).
