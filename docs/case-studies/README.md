# RevAI — Pipeline Runs & Case Studies

Real analysis reports produced by the RevAI pipeline against live malware samples. Each case study includes the full report, verdict, audit, YARA rule, and stage trace.

Reports are added after each verified run — every sample must pass the full quality gate (`all_green` + `quality_green`) before its report is published here.

## Organization — grouped by pipeline mode

| Directory | Mode | Description |
|-----------|------|-------------|
| [`scripted/`](scripted/) | Scripted (`pipeline_single.py`) | Fixed-order stages: intake → quick_scan → deep_dive → (function_recovery, optional) → yara → publish → section → audit |
| [`agentic/`](agentic/) | Agentic (`stage_orchestrator.py`) | LangGraph ReAct planner decides stage order; retries on failure; HITL before publish |
| [`ui/`](ui/) | Web Console (manual) | Interactive per-stage runs from `http://<host>:5000` |

## Current batch (15-run campaign + UI)

9 virussign samples (scripted small ×3, agentic mid/large ×6) + 3 RevEng-pool samples
(remcos/lumma/koi) + 3 InTheWild-pool samples. Reboot after every 2 runs.
**21/21 automated runs complete — all green.** Remaining: 12 manual UI runs.

> **2026-08-06 re-run:** the 13 R1–R15 case studies were re-run on the fixed
> pipeline (0-100 score scale, no scorecard citations, provenance-stamped
> reports) and replaced in place. All 13 green (scores 88–95/100).

### Scripted — small samples (7/7 done, all green)

| Sample | Size | Verdict | Report | Audit |
|--------|------|---------|--------|-------|
| `virussign-01984caa` (Unicorn, VB6 info-stealer/dropper) | 469K | [verdict.json](scripted/virussign-01984caa/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-01984caa/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-01984caa/AUDIT-REPORT.md) |
| `virussign-277ba25a` (unidentified packed/obfuscated PE) | 470K | [verdict.json](scripted/virussign-277ba25a/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-277ba25a/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-277ba25a/AUDIT-REPORT.md) |
| `virussign-780d28e3` (Darty Crypter) | 521K | [verdict.json](scripted/virussign-780d28e3/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-780d28e3/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-780d28e3/AUDIT-REPORT.md) |
| `remcos` (Remcos RAT) | 683K | [verdict.json](scripted/remcos/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/remcos/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/remcos/AUDIT-REPORT.md) |
| `pool-small-bkransomware` (BK ransomware / elex / maze / remcos tags) | 485K | [verdict.json](scripted/pool-small-bkransomware/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/pool-small-bkransomware/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/pool-small-bkransomware/AUDIT-REPORT.md) |
| `pool-small-mespinoza` (Mespinoza / Pysa ransomware) | 794K | [verdict.json](scripted/pool-small-mespinoza/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/pool-small-mespinoza/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/pool-small-mespinoza/AUDIT-REPORT.md) |
| `pool-small-conti` (Conti ransomware) | 594K | [verdict.json](scripted/pool-small-conti/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/pool-small-conti/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/pool-small-conti/AUDIT-REPORT.md) |

### Agentic — mid/large samples (13/13 done, all truly_green)

| Sample | Size | Verdict | Report | Audit |
|--------|------|---------|--------|-------|
| `virussign-40f92672` (packed Delphi-based loader) | 982K | [verdict.json](agentic/virussign-40f92672/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-40f92672/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-40f92672/AUDIT-REPORT.md) |
| `virussign-8264dc61` (generic packed dropper/loader) | 1024K | [verdict.json](agentic/virussign-8264dc61/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-8264dc61/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-8264dc61/AUDIT-REPORT.md) |
| `virussign-f622efa7` (UPX-packed malware/loader) | 1265K | [verdict.json](agentic/virussign-f622efa7/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-f622efa7/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-f622efa7/AUDIT-REPORT.md) |
| `virussign-970b822a` (ASPack-packed loader/dropper) | 3075K | [verdict.json](agentic/virussign-970b822a/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-970b822a/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-970b822a/AUDIT-REPORT.md) |
| `virussign-7edf35d0` (Themida-packed payload, T1027.002) | 3092K | [verdict.json](agentic/virussign-7edf35d0/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-7edf35d0/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-7edf35d0/AUDIT-REPORT.md) |
| `virussign-9358c2e1` (UPX-packed dropper/loader) | 8755K | [verdict.json](agentic/virussign-9358c2e1/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-9358c2e1/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-9358c2e1/AUDIT-REPORT.md) |
| `lumma-stealer` (Lumma Stealer info-stealer) | 1116K | [verdict.json](agentic/lumma-stealer/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/lumma-stealer/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/lumma-stealer/AUDIT-REPORT.md) |
| `koi-stealer` (packed Delphi-based loader/dropper) | 2211K | [verdict.json](agentic/koi-stealer/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/koi-stealer/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/koi-stealer/AUDIT-REPORT.md) |
| `pool-mid-quasar` (Quasar RAT) | 1874K | [verdict.json](agentic/pool-mid-quasar/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-mid-quasar/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-mid-quasar/AUDIT-REPORT.md) |
| `pool-large-darkgate` (darkgate/elex multi-family) | 8701K | [verdict.json](agentic/pool-large-darkgate/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-large-darkgate/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-large-darkgate/AUDIT-REPORT.md) |
| `pool-mid-vidar` (Vidar stealer, NSudo masquerade) | 1489K | [verdict.json](agentic/pool-mid-vidar/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-mid-vidar/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-mid-vidar/AUDIT-REPORT.md) |
| `pool-mid-mespinoza` (Mespinoza/Pysa ransomware, MS masquerade) | 2019K | [verdict.json](agentic/pool-mid-mespinoza/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-mid-mespinoza/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-mid-mespinoza/AUDIT-REPORT.md) |
| `pool-large-hive` (Hive ransomware, UPX-packed) | 4315K | [verdict.json](agentic/pool-large-hive/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-large-hive/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-large-hive/AUDIT-REPORT.md) |
| `pool-large-sliver` (Sliver C2 implant, packed ELF) | 9282K | [verdict.json](agentic/pool-large-sliver/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-large-sliver/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-large-sliver/AUDIT-REPORT.md) |

### UI — all samples (pending, manual)

### Sample pool

150 InTheWild samples (50 small/mid/large) staged on the VM for the remaining
runs: see [`pool/`](pool/).
