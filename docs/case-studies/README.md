# CADRE-RevAI — Pipeline Runs & Case Studies

This folder contains real analysis reports produced by the CADRE-RevAI pipeline against live malware samples. Each case study includes the full report, verdict, audit, and stage trace.

## Real Analysis Reports (live samples)

| Sample | Verdict | Full report | Audit |
|--------|---------|-------------|-------|
| **DartyCrypter** — custom VB6 crypter; runtime API resolution, PEB anti-debug | malicious · 90 | [REPORT-TECHNICAL-v3.md](darty-crypter/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](darty-crypter/AUDIT-REPORT.md) |
| **Generic Dropper** (Amadey / CobaltStrike / Satacom / Vidar hits) — packed, embedded PE, XOR, RWX `.text` | malicious · 85 | [REPORT-TECHNICAL-v3.md](amadey-cobaltstrike-satacom-vidar/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](amadey-cobaltstrike-satacom-vidar/AUDIT-REPORT.md) |
| **Trojan — possible Cobalt Strike / IcedID / njRAT** — offline MSI bootstrapper, no hardcoded C2 | malicious · 0.9 | [REPORT-TECHNICAL-v3.md](cobalt-strike-icedid-njrat/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](cobalt-strike-icedid-njrat/AUDIT-REPORT.md) |
| **Delphi RAT** — Delphi-built trojan; packing, XOR/RC4/HC-128, process injection | malicious · 0.9 | [REPORT-TECHNICAL-v3.md](delphi-rat/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](delphi-rat/AUDIT-REPORT.md) |

Each folder also ships `verdict.json` (machine-readable verdict + key evidence) and `stage_trace.json` / `orchestrator_trace.json` (per-stage gate results).

### Virussign batch (9 samples, live runs)

A 9-sample batch of VirusSign-prefixed samples, all analyzed end-to-end with the same pipeline:

| Sample | Verdict | Full report | Audit |
|--------|---------|-------------|-------|
| **01984caa** — Unicorn, VB6 info-stealer/dropper | malicious · 87 | [REPORT-TECHNICAL-v3.md](virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir/AUDIT-REPORT.md) |
| **277ba25a** — unidentified packed/obfuscated PE | malicious · 8 | [REPORT-TECHNICAL-v3.md](virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir/AUDIT-REPORT.md) |
| **40f92672** — packed Delphi-based loader (hard sample) | malicious · 9 | [REPORT-TECHNICAL-v3.md](virussign.com_40f9267218c144475dc0691431825779.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_40f9267218c144475dc0691431825779.vir/AUDIT-REPORT.md) |
| **780d28e3** — Darty Crypter | malicious · 88 | [REPORT-TECHNICAL-v3.md](virussign.com_780d28e33c39a8513613918671ac0b78.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_780d28e33c39a8513613918671ac0b78.vir/AUDIT-REPORT.md) |
| **7edf35d0** — Themida-packed payload (T1027.002) | malicious · 88 | [REPORT-TECHNICAL-v3.md](virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir/AUDIT-REPORT.md) |
| **8264dc61** — generic packed dropper/loader | malicious · 9 | [REPORT-TECHNICAL-v3.md](virussign.com_8264dc61e512149f551c29e1b91b545e.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_8264dc61e512149f551c29e1b91b545e.vir/AUDIT-REPORT.md) |
| **9358c2e1** — UPX-packed dropper/loader (hard sample) | malicious · 9 | [REPORT-TECHNICAL-v3.md](virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir/AUDIT-REPORT.md) |
| **970b822a** — ASPack-packed loader/dropper | malicious · 9 | [REPORT-TECHNICAL-v3.md](virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_970b822a8efe5f1a9e514f3a305e087c.vir/AUDIT-REPORT.md) |
| **f622efa7** — UPX-packed generic malware/loader | malicious · 85 | [REPORT-TECHNICAL-v3.md](virussign.com_f622efa728edc2b6d606315cc6746fa9.vir/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](virussign.com_f622efa728edc2b6d606315cc6746fa9.vir/AUDIT-REPORT.md) |

## Three Pipeline Modes

CADRE-RevAI offers three ways to run the same pipeline, each using the same tool stack (Ghidra, capa, YARA, FLOSS, r2, speakeasy, z3, angr, LIEF, diec, GoReSym, FindCrypt, ilspycmd, RIFT, pycdc, scdbg, etc.) and the same LLM backend:

| Mode | Script | Stages | Deep Dive |
|------|--------|--------|-----------|
| **Scripted** | `pipeline_single.py` | Fixed order (intake -> quick_scan -> deep_dive -> yara_gen -> publish -> audit) | LangGraph agentic (always) |
| **Agentic** | `stage_orchestrator.py` | LLM decides which stage to call; retries on failure; HITL before publish if verdicts disagree | LangGraph agentic |
| **Web Console** | `http://<host>:5000` | User clicks individual stage buttons, or **Run orch** for full agentic | LangGraph agentic |

The deep dive always runs through the LangGraph ReAct agent — only the stage ordering differs between modes.

### 1. Scripted Pipeline (`pipeline_single.py`)

A deterministic spine that runs every stage in fixed order with no LLM planning. Best for batch runs, reproducibility, and CI/CD-style execution.

```bash
python3 /opt/scripts/pipeline_single.py /path/to/sample.exe --mode standard
python3 /opt/scripts/pipeline_single.py /path/to/sample.exe --mode large   # import-only, agentic deep dive
```

Stages: intake -> quick_scan -> deep_dive_agentic -> yara_gen -> publish -> section -> audit

### 2. Agentic Pipeline (`stage_orchestrator.py`)

LangGraph ReAct planner that drives the same stages as tools. The LLM decides which stage to call, retries on failure, and can pause before publish if the quick and deep verdicts disagree (HITL). Best for complex samples, exploratory analysis, and when the LLM can optimize the analysis order.

```bash
python3 /opt/scripts/stage_orchestrator.py /path/to/sample.exe
python3 /opt/scripts/stage_orchestrator.py --sha <sha256>   # resume after intake
```

### 3. Flask Web Console (UI)

A React-based console running at `http://<remnux-ip>:5000`. Upload a sample, click **Run orch** (or stage buttons), and view reports in the built-in report reader. Best for interactive analysis, HITL review, and non-technical users.

## What Changed After Deployment

The deployment test on a fresh Remnux VM revealed and fixed:

| Issue | Fix |
|-------|-----|
| CADRE PE Loader not found | Added to `install/setup-remnux.sh` |
| LibGhidraHost missing external symbols in SQL | Surgical patch: `SymbolsRuntime.java` compiled and replaced in LibGhidraHost JAR |
| `capa` missing signatures | Created empty `/opt/capa-signatures/`, pass `-s` flag to capa calls |
| `z3` solver missing | Added to `requirements.txt`, installed via pip |
| Malcat/IDAPro causing hard failures in quality gates | Soft-fail: `_MALCAT_OPTIONAL_SECTIONS` in `report_quality.py`, `section_publisher.py`, `audit_pipeline.py` |
| Reasoning-model tokens consuming all output tokens | Set `max_tokens=65536` in `llm_judge()` so reasoning + content both fit |
| Smoke test checking wrong path | Fixed: `templates/index.html` → `ui/index.html` |
| Provider-specific API key fallback hardcoded | Removed provider-specific references; scripts read `REVENG_*` env vars only |
