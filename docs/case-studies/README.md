# CADRE-RevAI — Pipeline Runs & Case Studies

Real analysis reports produced by the CADRE-RevAI pipeline against live malware samples. Each case study includes the full report, verdict, audit, YARA rule, and stage trace.

Reports are added after each verified run — every sample must pass the full quality gate (`all_green` + `quality_green`) before its report is published here.

## Organization — grouped by pipeline mode

| Directory | Mode | Description |
|-----------|------|-------------|
| [`scripted/`](scripted/) | Scripted (`pipeline_single.py`) | Fixed-order stages: intake → quick_scan → deep_dive → yara → publish → section → audit |
| [`agentic/`](agentic/) | Agentic (`stage_orchestrator.py`) | LangGraph ReAct planner decides stage order; retries on failure; HITL before publish |
| [`ui/`](ui/) | Web Console (manual) | Interactive per-stage runs from `http://<host>:5000` |

## Current batch (18-run campaign)

9 unique malware samples × 2 sizes/modes, plus 9 manual UI runs. Reboot after every 2 runs.

### Scripted — small samples (3/3 done)

| Sample | Size | Verdict | Report | Audit |
|--------|------|---------|--------|-------|
| `virussign-01984caa` (Unicorn, VB6 info-stealer/dropper) | 469K | [verdict.json](scripted/virussign-01984caa/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-01984caa/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-01984caa/AUDIT-REPORT.md) |
| `virussign-277ba25a` (unidentified packed/obfuscated PE) | 470K | [verdict.json](scripted/virussign-277ba25a/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-277ba25a/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-277ba25a/AUDIT-REPORT.md) |
| `virussign-780d28e3` (Darty Crypter) | 521K | [verdict.json](scripted/virussign-780d28e3/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-780d28e3/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-780d28e3/AUDIT-REPORT.md) |

### Agentic — mid/large samples (6/6 done, all truly_green)

| Sample | Size | Verdict | Report | Audit |
|--------|------|---------|--------|-------|
| `virussign-40f92672` (packed Delphi-based loader) | 982K | [verdict.json](agentic/virussign-40f92672/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-40f92672/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-40f92672/AUDIT-REPORT.md) |
| `virussign-8264dc61` (generic packed dropper/loader) | 1024K | [verdict.json](agentic/virussign-8264dc61/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-8264dc61/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-8264dc61/AUDIT-REPORT.md) |
| `virussign-f622efa7` (UPX-packed malware/loader) | 1265K | [verdict.json](agentic/virussign-f622efa7/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-f622efa7/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-f622efa7/AUDIT-REPORT.md) |
| `virussign-970b822a` (ASPack-packed loader/dropper) | 3075K | [verdict.json](agentic/virussign-970b822a/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-970b822a/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-970b822a/AUDIT-REPORT.md) |
| `virussign-7edf35d0` (Themida-packed payload, T1027.002) | 3092K | [verdict.json](agentic/virussign-7edf35d0/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-7edf35d0/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-7edf35d0/AUDIT-REPORT.md) |
| `virussign-9358c2e1` (UPX-packed dropper/loader) | 8755K | [verdict.json](agentic/virussign-9358c2e1/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-9358c2e1/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-9358c2e1/AUDIT-REPORT.md) |

### UI — all 9 samples (pending, manual)
