# RevAI System Architecture

RevAI is an LLM-assisted malware reverse-engineering pipeline for REMnux. This document explains the system architecture, component layering, stage sequencing, evidence-grounding model, and quality verification gates.

---

## 1. Architectural Design & Philosophy

### Evidence-Grounded LLM, Not RAG

RevAI is built on an **evidence-grounded LLM architecture**, explicitly avoiding Retrieval-Augmented Generation (RAG):

* **The Problem with RAG in RE**: Empirical research (*Retrieval Contamination in LLM-Assisted Malware Triage*, Zenodo DOI [10.5281/zenodo.21613150](https://doi.org/10.5281/zenodo.21613150)) demonstrated that vector retrieval across external knowledge bases introduces retrieval contamination and false correlations in malware analysis workflows.
* **The Evidence-Grounded Solution**: Reverse-engineering tools (Ghidra, IDA Pro, capa, Malcat, YARA, FLOSS, FindCrypt, etc.) execute directly on the malware sample and output structured technical findings. These outputs are packaged into a signal-prioritized, stage-tagged **Evidence Pack**. An OpenAI-compatible LLM Judge reads this Evidence Pack directly to synthesize verdicts and author analysis reports.

---

## 2. Component & Pipeline Layers

```
Analyst (Browser / CLI)
       │
       ▼
RevAI Console (Flask + React) ────────► LLM Judge & Agentic Planner
       │                                     ▲          │
(drives pipeline)                       (reads pack) (agentic planner)
       │                                     │          │
┌──────▼─────────────────────────────────────│──────────▼────────────────┐
│ REMnux Malware Analysis Pipeline           │                           │
│                                            │                           │
│ 1. Intake ──► 2. Triage ──► 3. Deep Dive ──┤                           │
│  (Ghidra SQL)  (24 tools)    (LangGraph)   │                           │
│       │            │              │        │                           │
│       └────────────┼──────────────┘        │                           │
│                    ▼                       │                           │
│            ┌───────────────┐               │                           │
│            │ Evidence Pack │ ──────────────┘                           │
│            └───────┬───────┘                                           │
│                    │                                                   │
│                    ▼                                                   │
│            ┌───────────────┐                                           │
│            │   HITL Gate   │  (Quick vs Deep Verdict Lock)             │
│            └───────┬───────┘                                           │
│                    │                                                   │
│                    ▼                                                   │
│ 4. Rule Gen ──► 5. Publish ──► 6. Correlate ──► 7. Audit & Quality Gate   │
│  (YARA/Sigma)   (LLM Report)   (Map-Reduce)      (truly_green)         │
└────────────────────────────────────────────────────────────────────────┘
```

The system is organized into three distinct operational layers:

### A. Control & Intelligence Layer
* **Analyst Interface**: React Console UI (`http://<host>:5000`) or CLI entry points (`pipeline_single.py` for deterministic runs, `stage_orchestrator.py` for agentic runs).
* **Flask API Backend (`app.py`)**: Local service running on REMnux that manages session states, executes stage scripts under `/opt/scripts/`, and handles run configurations.
* **LLM Judge & Agentic Planner**: OpenAI-compatible LLM backend. Operates as a LangGraph ReAct planner for autonomous deep-dive tool navigation, and as a grounded synthesizer for report generation.

### B. Evidence Bus & HITL Approval Gate
* **Evidence Pack (`package_stage_evidence`)**: Centralized data structure that collects and ranks output cards from all triage and deep-dive tools. Persisted under `logs/<sha>/<stage>/evidence-pack.md`.
* **HITL Approval Gate (`REVAI_HITL_VERDICT=1`)**: An optional human-in-the-loop checkpoint evaluated between Stage 3 (Deep Dive) and Stage 5 (Publish). It compares the Stage 2 Quick Scan verdict against the Stage 3 Deep Dive verdict. If verdicts conflict (e.g. quick triage flagged malware, but deep dive was fooled by forged binary metadata), execution halts for analyst review before allowing report generation.

### C. 7-Stage Pipeline Spine

| Stage | Script | Role & Functionality |
| :--- | :--- | :--- |
| **1. Intake** | `intake_v2.py` | Normalizes sample, initializes session directory (`logs/<sha>/`), runs Ghidra headless (and optional IDA Pro) to populate `ghidrasql` / `idasql` SQLite database. |
| **2. Triage** | `quick_scan_v2.py` | Executes 24 static and dynamic analysis tools (capa, Malcat, YARA, FLOSS, FindCrypt, radare2, LIEF, etc.) in parallel. Packages findings into Evidence Pack; LLM writes initial quick verdict. |
| **3. Deep Dive** | `deep_dive_agentic.py` | Runs a LangGraph ReAct agent over the RE tool registry. Agent queries Ghidra/IDA SQL database, symbolic/deobfuscation tools (`angr`, `z3`, `cff-deflatten`), and disassemblers to analyze functions and payload logic. Appends findings to Evidence Pack. |
| **4. Rule Gen** | `yara_gen_v2.py` | Generates YARA and Sigma detection signatures derived strictly from Evidence Pack indicators. |
| **5. Publish** | `publish_report_v2.py` | LLM Judge reads the full Evidence Pack and authors source-tagged `REPORT-MASTER-v2.md` and `REPORT-TECHNICAL-v2.md`. |
| **6. Correlate** | `section_publisher.py` | Section Map-Reduce report publisher. Correlates multi-section analysis into `REPORT-MASTER-v3.md` and `REPORT-TECHNICAL-v3.md`. |
| **7. Audit** | `audit_pipeline.py` & `report_quality.py` | Audits per-stage logs (`all_green`), verifies engine citations, checks verdict locking, and enforces the `truly_green` quality gate. |

---

## 3. Quality Verification Gate (`truly_green`)

RevAI enforces an automated quality gate computed by `report_quality.py`:

```text
truly_green = all_green (per-stage audit) AND quality_green (no fallback stubs) AND (failed_tools == 0)
```

* **Audit Verification (`all_green`)**: Every stage must complete with exit code 0 and write a valid stage trace.
* **Quality Gate (`quality_green`)**: Verifies that reports contain no deterministic fallbacks, narrative placeholders, empty tool sections, or mis-attributed engine citations.
* **Source Tagging**: Every report carries explicit machine-readable provenance metadata (`source: llm_judge` vs `source: deterministic_fallback`), preventing stubbed or partial runs from appearing green.

---

## 4. References & Linked Documentation

* [`OPERATE.md`](OPERATE.md) — Daily pipeline operation, staging samples, running CLI / Console.
* [`PREREQUISITES.md`](PREREQUISITES.md) — System requirements, Ghidra, ghidrasql, Malcat, LLM setup.
* [`tool-stack.md`](tool-stack.md) — 24 format-aware manifest tools + 19 agent-callable tools.
* [`agent-loop-discipline.md`](agent-loop-discipline.md) — Loop discipline, budget warnings, hallucination checks, failure taxonomy.
