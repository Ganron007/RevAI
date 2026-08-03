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

### Agentic — mid/large samples (pending)

### UI — all 9 samples (pending, manual)
