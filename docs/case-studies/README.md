# CADRE-RevAI — Pipeline Runs & Case Studies

This folder contains real analysis reports produced by the CADRE-RevAI pipeline against live malware samples. Each case study includes the full report, verdict, audit, and stage trace.

## Three Pipeline Modes

CADRE-RevAI offers three ways to run the same pipeline, each using the same tool stack (Ghidra, capa, YARA, FLOSS, r2, speakeasy, etc.) and the same LLM backend:

### 1. Scripted Pipeline (`pipeline_single.py`)

A deterministic spine that runs every stage in fixed order with no LLM planning. Best for batch runs, reproducibility, and CI/CD-style execution.

```bash
python3 /opt/scripts/pipeline_single.py /path/to/sample.exe --mode standard
python3 /opt/scripts/pipeline_single.py /path/to/sample.exe --mode large   # import-only, agentic deep dive
```

Stages: intake → quick_scan → deep_dive_agentic → yara_gen → publish → section → audit

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
| CADRE PE Loader not found | Copied extension from RevEng VM, added to `install/setup-remnux.sh` |
| LibGhidraHost missing external symbols in SQL | Surgical patch: `SymbolsRuntime.java` compiled from RevEng source, replaced in LibGhidraHost JAR |
| `capa` missing signatures | Created empty `/opt/capa-signatures/`, pass `-s` flag to capa calls |
| `z3` solver missing | Added to `requirements.txt`, installed via pip |
| Malcat/IDAPro causing hard failures in quality gates | Soft-fail: `_MALCAT_OPTIONAL_SECTIONS` in `report_quality.py`, `section_publisher.py`, `audit_pipeline.py` |
| DeepSeek reasoning tokens consuming all output tokens | Set `max_tokens=65536` in `llm_judge()` so reasoning + content both fit |
| Smoke test checking wrong path | Fixed: `templates/index.html` → `ui/index.html` |
| `DEEPSEEK_API_KEY` fallback hardcoded | Removed all DeepSeek-specific references; scripts read `REVENG_*` env vars only |
