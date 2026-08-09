# RevAI System Architecture

RevAI is an LLM-assisted malware reverse-engineering pipeline for REMnux. This document explains the system architecture, the three run modes, the two agent loops, control flow, retry & resilience, HITL, and the quality gates.

---

## 1. Architectural Design & Philosophy

### Evidence-Grounded LLM, Not RAG

RevAI is built on an **evidence-grounded LLM architecture**, explicitly avoiding Retrieval-Augmented Generation (RAG):

* **The Problem with RAG in RE**: Empirical research (*Retrieval Contamination in LLM-Assisted Malware Triage*, Zenodo DOI [10.5281/zenodo.21613150](https://doi.org/10.5281/zenodo.21613150)) demonstrated that vector retrieval across external knowledge bases introduces retrieval contamination and false correlations in malware analysis workflows.
* **The Evidence-Grounded Solution**: Reverse-engineering tools (Ghidra, IDA Pro, capa, Malcat, YARA, FLOSS, etc.) execute directly on the malware sample and output structured technical findings. These outputs are packaged into a signal-prioritized, stage-tagged **Evidence Pack**. An OpenAI-compatible LLM Judge reads this Evidence Pack directly to synthesize verdicts and author analysis reports.

### Deterministic Skeleton, Cognitive LLM Union

The pipeline deliberately separates what must be deterministic from what benefits from LLM judgment. Stage order, tool batteries, score scales, gate rules, and retry behavior are code. LLM judgment is reserved for adaptive tool selection (deep dive), verdict synthesis, and report authorship — and even that judgment is bounded by policy and audited by deterministic gates.

---

## 2. Three Run Modes

One shared set of seven stage scripts (plus one optional function-recovery stage); three ways to drive them:

| Mode | Driver | Stage order decided by | Retries | Best for |
|---|---|---|---|---|
| **Scripted** (default) | `pipeline_single.py` | code — fixed order | none (deterministic) | fast, reproducible runs |
| **Agentic** | `stage_orchestrator.py` | LangGraph ReAct planner (policy-pinned order) | 1 stage retry (transient) + 1 tool retry (0-3 configurable) | large/obfuscated samples |
| **Web Console** | `app.py` + React | human clicks (manual) or the same planner (Run orch) | user-configured values | day-to-day work |

All three execute the same stage scripts; only the decision layer differs. The retry/budget values are user-capped in every mode (see §6).

---

## 3. Component & Pipeline Layers

```
Analyst (Browser / CLI)
       │
       ▼
RevAI Console (Flask + React) ────────► LLM Judge & Agentic Planner
       │                                     ▲          │
(scripted / agentic / manual)           (reads pack) (agentic planner)
       │                                     │          │
┌──────▼─────────────────────────────────────│──────────▼────────────────┐
│ REMnux Malware Analysis Pipeline           │                           │
│ 1. Intake ──► 2. Triage ──► 3. Deep Dive ──┤                           │
│  (Ghidra/IDA)  (24 tools)   (LangGraph)    │                           │
│       │            │              │        │                           │
│       └────────────┼──────────────┘        │                           │
│                    ▼                       │                           │
│            ┌───────────────┐               │                           │
│            │ Evidence Pack │ ──────────────┘                           │
│            └───────┬───────┘                                           │
│                    ▼                                                   │
│ 4. Rule Gen ──► 5. Publish ──► 6. Correlate ──► 7. Audit & Quality Gate   │
│  (YARA/Sigma)   (LLM Report)   (Map-Reduce)      (truly_green)         │
└────────────────────────────────────────────────────────────────────────┘
```

### A. Control & Intelligence Layer
* **Analyst Interface**: React Console UI (`http://<host>:5000`) or CLI entry points (`pipeline_single.py` for deterministic runs, `stage_orchestrator.py` for agentic runs).
* **Flask API Backend (`app.py`)**: Local service on REMnux that manages sessions, executes stage scripts under `/opt/scripts/`, and hosts the Run-configuration API.
* **LLM Judge & Agentic Planner**: OpenAI-compatible LLM backend. Operates as a LangGraph ReAct planner for stage sequencing and deep-dive tool navigation, and as a grounded synthesizer for report generation.

### B. The Two Agent Loops

RevAI contains exactly **two LangGraph ReAct loops** (same `create_react_agent` pattern, different granularity):

| Loop | Tools it orchestrates | Decides |
|---|---|---|
| **Deep-dive agent** (`agentic_langgraph.py`) | 12 RE tools: `ghidra_query`, `ida_query`, `ghidra_decompile`, `capa_analyze`, `malcat_analyze`, `yara_scan`, `floss_extract`, `pe_import_signals`, `xor_string_search`, `speakeasy_emulate`, `frida_static_probe`, `signature_match` | which tool to call next, with what arguments, based on previous results |
| **Stage planner** (`stage_orchestrator.py`) | 11 stage tools: `run_intake`, `run_quick_scan`, `run_deep_dive_agentic`, `run_function_recovery`, `run_yara_gen`, `run_publish`, `run_section_publish`, `run_audit`, `check_quality`, `read_verdicts`, `read_evidence` | which stage to execute next, within a policy-pinned order (never skips mandatory stages) |

`run_function_recovery` is an **optional** planner tool — it skips itself when
`REVAI_ENABLE_AGENTIC_RECOVERY` is off and is never required for green.

**LangChain vs LangGraph here**: LangChain supplies the components (message types `AIMessage`/`HumanMessage`/`SystemMessage`/`ToolMessage`, `StructuredTool` adapters, `ChatOpenAI` client). LangGraph supplies the loop that runs the LLM's chosen tool calls and returns results. Everything outside these two loops — quick_scan, publish, section, audit, yara, intake, function recovery, every retry, every gate — is plain Python.

### C. The 7-Stage Pipeline Spine (+ 1 optional)

| Stage | Script | Role & Functionality |
| :--- | :--- | :--- |
| **1. Intake** | `intake_v2.py` | Normalizes sample, initializes session, runs Ghidra headless and (optional, licensed) IDA Pro to populate `ghidrasql` / `idasql` databases. IDA absence is a documented soft-fail, not an error. |
| **2. Triage** | `quick_scan_v2.py` | Executes 24 tools in parallel (capa, Malcat, YARA, FLOSS, radare2, etc.). Packages findings into the Evidence Pack; one LLM judge call writes the quick verdict. |
| **3. Deep Dive** | `deep_dive_agentic.py` | LangGraph ReAct agent over the RE tool registry — SQL-first evidence, adaptive tool selection, agent-loop discipline (see §7). |
| **3.5. Function Recovery** *(optional)* | `agentic_recover_v4.py` (+ `recovery/` package) | Opt-in agentic function-name recovery: relevance-based triage (score = call-in × 2 + string refs + high-value imports × 3, matched by prefix; hybrid pool with guaranteed slots for API callers and largest functions) → call-graph bottom-up tiers → per-function LLM naming with typed signatures → SQL writeback (`ghidra_sql_client`/idasql, confidence ≥ 0.7, never deletes). Gated by `REVAI_ENABLE_AGENTIC_RECOVERY=1` (legacy `ENABLE_AGENTIC_RECOVERY` honored). Produces `function_recovery.json`; recovered names are fed into publish prompts and cited in reports. |
| **4. Rule Gen** | `yara_gen_v2.py` | Generates YARA + Sigma rules from evidence, provenance-stamped, validated in-process. |
| **5. Publish** | `publish_report_v2.py` | LLM Judge authors `REPORT-MASTER-v2.md` (17 sections) and `REPORT-TECHNICAL-v2.md` (13 sections) with the evidence pack appended. |
| **6. Correlate** | `section_publisher.py` | Section map-reduce: per-section LLM passes with cross-section context → `REPORT-MASTER-v3.md` / `REPORT-TECHNICAL-v3.md`. |
| **7. Audit** | `audit_pipeline.py` & `report_quality.py` | Per-stage audit (`all_green`), engine-citation honesty, verdict lock, style gates, depth gate, `truly_green`. |

---

## 4. Control Flow — Who Controls What

Four players: **User** (caps), **LLM** (judgment), **Agent** (the loop), **Code** (enforcement).

| Player | Controls | Never controls |
|---|---|---|
| **User** | limits only: retry counts, budget profile, timeout scale, feature toggles, HITL switch | order, retry execution, tool selection, report content |
| **LLM** | tool order inside the deep dive; stage sequencing as planner (policy-pinned); recovery judgment (re-calling a failed tool); all report prose | retry counts (deterministic layers own them) |
| **Agent** (LangGraph loop) | the harness — executes the LLM's chosen calls, enforces step limits | nothing of its own |
| **Code** | pinned stage order, ALL retries (transient classification + counts), quick_scan tool battery, gates, fallbacks, provenance | LLM judgment |

**Tool-level flow**: quick_scan's tool order = code (fixed battery); deep dive's tool order = the LLM agent. Tool retry = code first (user-capped, before the LLM sees the error), then LLM judgment if still failing.

**Stage-level flow**: scripted = code; agentic = planner (policy-pinned); UI manual = human; UI Run-orch = planner with user values. Stage retry = always code (transient-only, count = user knob) — the planner is never asked to decide retries.

---

## 5. Retry & Resilience

Three layers, each stopping a failure before the next, more expensive layer:

```
L1   tool retry      quick_scan `_timed_retry` + deep-dive transparent wrapper
                    (deterministic, transient-only, count = REVAI_TOOL_RETRIES)
L1.5 stage retry     StageRunner re-runs the whole stage script (transient-only,
                    count = REVAI_STAGE_RETRIES)
L2   LLM judgment    deep-dive agent may re-call a tool differently (uncapped
                    except step budget)
```

* **Transient classification** (`is_transient_failure`): timeout, MCP/server connection loss, OOM → retryable. Permission, rule/artifact errors, LLM quality → never retried.
* **LLM call retry**: the shared `llm_judge` helper has a built-in 3-attempt retry for API timeouts.
* **Visibility**: every retried tool/stage is marked (`retried`, `first_error`, `attempts`) and recorded in traces + audit.

---

## 6. Run Configuration (budgets & retries)

`v2_lib.run_profile()` resolves per-run settings. Profiles: **standard** (40 planner recursion, 16 deep-dive steps, 1 stage retry, 1 tool retry) · **generous** · **unlimited** (lab). Every knob has an env override (`REVAI_RUN_PROFILE`, `REVAI_STAGE_RETRIES`, `REVAI_TOOL_RETRIES`, `REVAI_ORCH_RECURSION_LIMIT`, `REVAI_DEEP_MAX_STEPS`, `REVAI_TOOL_TIMEOUT_SCALE`, `REVAI_RETRY_TRANSIENT_ONLY`).

The **Web Console** exposes a Run-configuration panel (Settings page) that persists these values; they are injected into every stage the console spawns. Scripted CLI mode pins retries to 0 (deterministic contract); user env values still win if explicitly set.

---

## 7. Agent-Loop Discipline (deep-dive features)

Four features implemented in `deep_dive_agentic.py` and active in both engines (env-gated, default ON):

1. **Budget warnings** — convergence nudges at half and near-end of the step budget.
2. **Redundant-call detection** — duplicate `(tool, args)` calls are skipped with a nudge; counted in the result.
3. **Hallucination check** — every `final_answer` claim must be grounded in tool output; ungrounded claims get one correction turn.
4. **Failure taxonomy** — post-run classification (byte-level reasoning / control-flow misinterpretation / API hallucination / tool misuse / early termination / JSON violations).

---

## 8. HITL — Human-in-the-Loop

Four mechanisms, **off by default** (which is why standard runs never pause):

| Mechanism | Location | Trigger |
|---|---|---|
| Stage checkpoints | yara_gen / publish / deep-dive boundaries | `CADRE_HITL_WAIT=1` — stage pauses until a human approves |
| Confidence gate (HITL #2) | post-deep-dive annotation review | annotation `confidence < 50` |
| Critical-impact gate (HITL #3) | same review surface | annotations tagged ransomware/ICS/medical/nuclear/… |
| Verdict-conflict stop | planner, before publish | `REVAI_HITL_VERDICT=1` and quick ≠ deep verdict |

Checkpoints write `/tmp/cadre-hitl/<agent>-<step>.json`; approval flows through `hitl_approve.py` or the console's review page. Approval is fail-safe (timeout) and a checkpoint write failure never kills a stage.

---

## 9. Report Generation & the Explain-Don't-Dump Contract

Reports follow real-world threat-report conventions. Section anatomy (MASTER 17 / TECHNICAL 13) includes a Background & Family Lineage anchor, an Infrastructure/C2 section, detection content and MITRE ATT&CK at the end with IOCs, and structured appendices (Evidence Trail, Module Inventory).

A style contract is enforced at every prompt site:
1. Quote-then-translate — every artifact introduced and interpreted
2. Observation → implication ("we observed X, which indicates Y because Z")
3. Observed-vs-latent capability annotation
4. Hedged inference (likely / possibly / we assess)
5. Evidence traceability — every claim carries `(source: engine)`
6. Explicit unknowns with reasons
7. Module-by-module narrative flow
8. Reader test — no prior context required

Every report/rule/trace carries a **provenance banner** (commit, engine, feature flags, UTC), so any artifact can be traced to the pipeline version that produced it.

---

## 10. Quality Verification Gate (`truly_green`)

```text
truly_green = all_green (per-stage audit) AND quality_green (no fallback stubs)
              AND (failed_tools == 0) AND engine-citation honesty
              AND verdict lock AND confidence sanity AND report style gates
              AND depth gate (capability coverage)
```

* **Audit Verification (`all_green`)**: every stage completes rc=0 with valid artifacts.
* **Quality Gate (`quality_green`)**: no deterministic fallbacks, stubs, or mis-attributed engine citations; SQL-deep honesty (documented infrastructure failures are recorded, not gated); no 0-confidence verdicts on complete dives.
* **Depth Gate (`depth_coverage`, plan #7)**: deterministic completeness gate on the deep-dive summary. Every capability domain — persistence, C2/network, evasion/anti-analysis, exfiltration, defense impairment, credential access, encryption/obfuscation, plus entry point, imports, strings — must be *addressed*: either evidenced or explicitly stated "not observed". An entirely unmentioned domain fails the gate. Implemented by `v2_lib.evaluate_deep_coverage()` in `audit_deep_standard` / `audit_deep_large`. The deep-dive prompts carry the DEPTH PROTOCOL ("a verdict does not end the analysis") so agents know the requirement before final_answer. Pairs with the optional function-recovery stage (#6), which supplies systematic call-graph coverage.
* **Style gates**: provenance byline present, citation coverage in narrative, no dump-style code blocks without interpretation, no orphaned tables, healthy prose ratio. Evaluated on the narrative body only (raw evidence appendices are exempt).
* **Source Tagging**: every report carries explicit provenance (`source: llm_judge` vs `source: deterministic_fallback`), preventing stubbed or partial runs from appearing green.

---

## 11. References & Linked Documentation

* [`OPERATE.md`](OPERATE.md) — Daily pipeline operation, staging samples, running CLI / Console.
* [`PREREQUISITES.md`](PREREQUISITES.md) — System requirements, Ghidra, ghidrasql, Malcat, IDA Pro (optional), LLM setup.
* [`tool-stack.md`](tool-stack.md) — 24 format-aware manifest tools + 19 agent-callable tools.
* [`agent-loop-discipline.md`](agent-loop-discipline.md) — Loop discipline, budget warnings, hallucination checks, failure taxonomy.
* [`cadre-pe-loader.md`](cadre-pe-loader.md) — Custom Ghidra PE loader for packed/binder samples.
* [`malcat-capa-engine.md`](malcat-capa-engine.md) — Malcat-native capa engine integration.
