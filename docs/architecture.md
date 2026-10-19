# RevAI System Architecture

RevAI is an LLM-assisted malware reverse-engineering pipeline for REMnux. This document explains the system architecture, the three run modes, the two agent loops, control flow, retry & resilience, HITL, and the quality gates.

---

## 1. Architectural Design & Philosophy

### Evidence-Grounded Reporting

RevAI does not retrieve from an embedding-indexed threat-intelligence corpus. It supports optional VirusTotal and Hybrid Analysis hash lookups, disabled by default, as an upstream enrichment stage; when enabled, the run-bound `quick_scan/ti-enrich.json` result can be supplied to report writers. This hash-only lookup does not download samples or independently establish family lineage, actor, campaign, or origin. The separate offline SQLite API index contains Windows API reference documentation, not sample-intelligence records. Reports must cite the exact run artifact for any provider result and keep provider labels distinct from reverse-engineering findings.

* **RevAI report inputs**: Reverse-engineering tools (Ghidra, IDA Pro, capa, Malcat, YARA, FLOSS, and others) run against the sample and produce structured findings. RevAI routes relevant, run-bound evidence to report sections and records source artifacts in a report-input manifest. The configured LLM interprets those inputs; quality gates check report claims against the source artifacts.

### Deterministic Skeleton, Cognitive LLM Union

The pipeline deliberately separates what must be deterministic from what benefits from LLM judgment. Stage order, tool batteries, score scales, gate rules, and retry behavior are code. LLM judgment is reserved for adaptive tool selection (deep dive), verdict synthesis, and report authorship — and even that judgment is bounded by policy and audited by deterministic gates.

---

## 2. Three Run Modes

One shared set of stage scripts, five of them optional; three ways to drive them:

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
│  (Ghidra/IDA)  (8-tool pool)  (LangGraph)   │                           │
│       │            │              │        │                           │
│       └────────────┼──────────────┘        │                           │
│                    ▼                       │                           │
│            ┌───────────────┐               │                           │
│            │ Evidence Pack │ ──────────────┘                           │
│            └───────┬───────┘                                           │
│                    ▼                                                   │
│ 4. Rule Gen ──► 5. Publish ──► 6. Sections ──► 7. Audit & Quality Gate  │
│  (YARA/Sigma)   (LLM Report)   (per-section)     (truly_green)         │
└────────────────────────────────────────────────────────────────────────┘
```

The diagram shows the core flow; the numbered table below is the full set,
including the five opt-in stages (Dynamic Analysis, Function Recovery,
Analysis Scripts, Behavioural Model, Depth Mode) that skip themselves when
their flag is off.

### A. Control & Intelligence Layer
* **Analyst Interface**: React Console UI (`http://<host>:5000`) or CLI entry points (`pipeline_single.py` for deterministic runs, `stage_orchestrator.py` for agentic runs).
* **Flask API Backend (`app.py`)**: Local service on REMnux that manages sessions, executes stage scripts under `/opt/scripts/`, and hosts the Run-configuration API.
* **LLM Judge & Agentic Planner**: OpenAI-compatible LLM backend. Operates as a LangGraph ReAct planner for stage sequencing and deep-dive tool navigation, and as a grounded synthesizer for report generation.

### B. The Two Agent Loops

RevAI contains exactly **two LangGraph ReAct loops** (same `create_react_agent` pattern, different granularity):

| Loop | Tools it orchestrates | Decides |
|---|---|---|
| **Deep-dive agent** (`deep_dive_agentic.py`) | 26 RE tools in the registry; **15 bound to the LangGraph graph** (the default engine) — `ghidra_query`, `ida_query`, `ghidra_decompile`, `capa_analyze`, `malcat_analyze`, `yara_scan`, `floss_extract`, `pe_import_signals`, `speakeasy_emulate`, `r2_decompile`, `z3_solve`, `angr_analyze`, `api_lookup`, `compare_files`, `load_skill`. The other 11 (`xor_string_search`, `frida_static_probe`, `signature_match`, `upx_unpack`, `shellcode_extract`, `olevba_analyze`, `peepdf_analyze`, `dotnet_analyze`, `revai_tools_sec`, `revai_tools_sinks`, `revai_tools_audit`) run in the deterministic checklist instead, which already covers the static scanners. `REVAI_AGENTIC_ENGINE=custom` binds the whole registry | which tool to call next, with what arguments, based on previous results |
| **Stage planner** (`stage_orchestrator.py`) | 15 stage tools: `run_intake`, `run_quick_scan`, `run_deep_dive_agentic`, `run_function_recovery`, `run_artifact_gen`, `run_behavioural_model`, `run_yara_gen`, `run_winre_dynamic`, `run_publish`, `run_section_publish`, `run_audit`, `check_quality`, `run_depth`, `read_verdicts`, `read_evidence` | which stage to execute next, within a policy-pinned order (never skips mandatory stages) |

`run_function_recovery`, `run_artifact_gen`, `run_behavioural_model` and
`run_winre_dynamic` are **optional** planner tools — each skips itself when its
`REVAI_ENABLE_*` / `REVAI_WINRE_RUN` flag is off. If WinRE is explicitly
requested, its run ID, status and fresh evidence pack must correlate; a missing,
failed or stale pack is recorded as a failed tool and cannot produce a green run.

**LangChain vs LangGraph here**: LangChain supplies the components (message types `AIMessage`/`HumanMessage`/`SystemMessage`/`ToolMessage`, `StructuredTool` adapters, `ChatOpenAI` client). LangGraph supplies the loop that runs the LLM's chosen tool calls and returns results. Everything outside these two loops — quick_scan, publish, section, audit, yara, intake, function recovery, every retry, every gate — is plain Python.

### C. The Stage Spine (12 stages, 5 optional)

| Stage | Script | Role & Functionality |
| :--- | :--- | :--- |
| **1. Intake** | `intake_v2.py` | Normalizes sample, initializes session, runs Ghidra headless and (optional, licensed) IDA Pro to populate `ghidrasql` / `idasql` databases. IDA absence is a documented soft-fail, not an error. |
| **2. Triage** | `quick_scan_v2.py` | Runs a fixed **8-tool phase-A pool** in parallel — capa (Malcat→capa-rs→Mandiant chain), yara, floss, malcat, pe_imports, packer_intake, revai-tools sec/sinks — plus the Ghidra/IDA SQL queries, then packages findings into the Evidence Pack; one LLM judge call writes the quick verdict (v1 fallback + calibration + citation grounding). The full format-aware battery (`TOOL_MANIFEST`) runs in the standard-mode deep dive, not here. |
| **3. Dynamic Analysis** *(optional)* | `winre_dynamic` / `winre_runner.py` | Opt-in FlareVM detonation (`REVAI_WINRE_RUN=1`), ordered **between triage and the deep dive** so the detonation is evidence the dive can reason over rather than only text in a report. A single execution ID is passed into WinRE and checked against its status and pack, reports, audit and trace. An unrequested run skips; an explicitly requested run with unavailable WinRE, a failed detonation or a stale/missing pack makes the run red. The versioned pack (`load_dynamic_pack()`) is rendered into the deep-dive prompt outside the findings budget and added to `deep_dive/evidence-pack.md`. Without a requested run and pack the deep-dive prompt is unchanged. Dynamic evidence corroborates but never overrides a static finding (`static_yara_wins`). Both scripted and agentic spines use this order; the agentic deep-dive boundary also runs the configured dynamic stage if the planner omits it. Publish supplies component-scoped execution status to the master prompt and adds deterministic WinRE observations to reports when a pack exists. |
| **4. Deep Dive** | `deep_dive_agentic.py` | LangGraph ReAct agent over the RE tool registry — SQL-first evidence, adaptive tool selection, agent-loop discipline (see §7). API behaviour/abuse claims are grounded on demand via `api_lookup` (offline local index) rather than model recall, and RE procedures are loaded on demand via `load_skill` rather than recalled from the model's training data. |
| **5. Function Recovery** *(optional)* | `agentic_recover_v4.py` (+ `recovery/` package + `anti_analysis_signals.py` + `dynamic_resolve_detect.py`) | Opt-in agentic function-name recovery: relevance-based triage (score = call-in × 2 + string refs + high-value imports × 3 + anti-analysis signals; matched by prefix) → hybrid pool with guaranteed slots for API callers, largest functions, and dynamic-import-resolve sites → call-graph bottom-up tiers → per-function LLM naming with typed signatures → SQL writeback (`ghidra_sql_client`/idasql, confidence ≥ 0.7, never deletes). Gated by `REVAI_ENABLE_AGENTIC_RECOVERY=1` (legacy `ENABLE_AGENTIC_RECOVERY` honored). Produces `function_recovery.json`; recovered names are fed into publish prompts and cited in reports. |
| **6. Analysis Scripts** *(optional)* | `artifact_gen.py` | Opt-in verifiable artifact generation: the LLM authors one small, sample-specific extraction script from **structural** evidence (section table, high-entropy regions with offsets, strings with offsets, bounded decompile excerpts — never a decoded answer), the pipeline runs it in a bounded sandbox (isolated interpreter, scrubbed env with no RevAI secrets, address-space/file-size rlimits, timeout, `unshare -n` when available) and then **re-derives every claimed value from the sample bytes** with its own code. Three anti-cheat measurements: the script must read its input argument, hardcoded output literals are flagged, and values already visible in the generation prompt are flagged as not independent. Gated by `REVAI_ENABLE_ARTIFACT_GEN=1`; self-skips with rc=0 otherwise; never gates the verdict. Publish attaches a presence-gated *Appendix: Analysis Scripts* listing only re-derived values. |
| **7. Behavioural Model** *(optional)* | `behavioural_model.py` | Opt-in (`REVAI_ENABLE_BEHAVIOURAL_MODEL=1`): assembles what the sample *does* from the run's own artifacts into `behavioural_model.json` — capabilities with their provenance, the concrete objects they act on (registry keys, URLs, domains, IPs, files, mutexes), the observations backing each, and the gaps. Built deterministically, never authored by the model: a model-authored behavioural model is a plausible story, and a plausible story about a malware sample is the most expensive kind of wrong. Never gates the verdict; off by default, so a run without it is byte-identical. |
| **8. Rule Gen** | `yara_gen_v2.py` | Generates YARA + Sigma rules from evidence, provenance-stamped, validated in-process; `iocs.json` extended with revai-tools wallets + defanged IOC merge. |
| **9. Publish** | `publish_report_v2.py` | LLM Judge authors `REPORT-MASTER-v2.md` (17 sections) and `REPORT-TECHNICAL-v2.md` (13 sections) with the evidence pack appended. |
| **10. Section reports** | `section_publisher.py` | Section map-reduce: per-section LLM passes with cross-section context → `REPORT-MASTER-v3.md` / `REPORT-TECHNICAL-v3.md`. **Both** reports are generated one section per call. Technical evidence is routed to the sections that need it (`TECHNICAL_SECTION_EVIDENCE`) instead of being sent whole to a single call, and each section's evidence is capped. `REVAI_TECHNICAL_SECTIONWISE=0` restores the single-call technical assembly, retained only as a rollback lever. |
| **11. Audit** | `audit_pipeline.py` & `report_quality.py` | Per-stage audit (`all_green`), engine-citation honesty, verdict lock, style gates, depth gate, `truly_green`. |
| **12. Depth Mode** *(optional)* | `depth_agent.py` | Opt-in, **runs after the audit** (`REVAI_DEPTH=1`). Objective is UNDERSTANDING, not a verdict: it produces a function map (`understanding.json`) and never a judgment, and never gates the pipeline. Every region carries a status from a fixed vocabulary with a reason and an evidence citation, and the loop terminates on a declared unknown set. The ceiling consolidates rather than truncates, so a cutoff yields a partial-but-honest map. |

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
truly_green = all_green (per-stage audit, incl. the hollow-success gate)
              AND quality_green (no fallback stubs)
              AND (failed_tools == 0) AND engine-citation honesty
              AND verdict lock AND confidence sanity AND report style gates
              AND depth gate (capability coverage)
              AND publication-quality gates (cross-report consistency, entropy sanity)
```

* **Audit Verification (`all_green`)**: every stage completes rc=0 with valid artifacts, **and** the artifacts contain something. The second half is the hollow-success gate below — "rc=0 with a well-formed artifact" is not sufficient, because five separate defects produced exactly that while the output was worthless.
* **Hollow-success gate (`hollow_success`)**: a deterministic, artifact-based stage measuring whether artifacts carry real content rather than merely existing. It reads each report's *own declared* completeness (`source`, `sections_complete`, `sections_missing`, `sections_stub`), function-recovery name/pseudocode ratios, verdict-panel agreement across reports, exhausted LLM calls, and report degeneration or duplicated sections. Artifacts are discovered by glob rather than enumerated, so a new report version cannot silently escape the checks. Deliberately makes no LLM call: a check that needed a model could be hollow in the same way, and would cost a call per run to report whether the calls worked. Partial function naming is reported as an advisory, never gated — that is a depth signal, not an empty artifact.
* **Quality Gate (`quality_green`)**: no deterministic fallbacks, stubs, missing required Markdown sections, or uncited factual claims; SQL-deep honesty (documented infrastructure failures are recorded, not gated); no 0-confidence verdicts on complete dives.
* **Depth Gate (`depth_coverage`, plan #7)**: deterministic completeness gate on the deep-dive summary. Every capability domain — persistence, C2/network, evasion/anti-analysis, exfiltration, defense impairment, credential access, encryption/obfuscation, plus entry point, imports, strings — must be *addressed*: either evidenced or explicitly stated "not observed". An entirely unmentioned domain fails the gate. Implemented by `v2_lib.evaluate_deep_coverage()` in `audit_deep_standard` / `audit_deep_large`. The deep-dive prompts carry the DEPTH PROTOCOL ("a verdict does not end the analysis") so agents know the requirement before final_answer. Pairs with the optional function-recovery stage (#6), which supplies systematic call-graph coverage.
* **Style, traceability, and claim-support gates**: provenance byline present, a source marker and concrete row/field locator on every factual sentence and evidence-table row, no dump-style code blocks without interpretation, no orphaned tables, healthy prose ratio. Required headings must be actual Markdown headings outside fenced examples. The v3 master is checked alongside the v2 master and technical reports. The claim gate resolves citations to allowlisted primary artifacts and exact rows or fields, then asks the configured LLM to assess each claim against those excerpts; any quote used to support or contradict a claim must match the source excerpt. Missing evidence, malformed review output, and checker/reviewer errors fail closed. The reviewer is the same configured model used by the pipeline, so this is evidence-constrained corroboration rather than independent-model certification; reviewers can inspect the artifact and review metadata.
* **Publication-quality gates (`cross_report_consistency`, 2026-08-12)**: deterministic fact checks across all published report variants — a report must not claim "no dynamic analysis was performed" when run artifacts record execution evidence; verdict panels must agree; and entropy citations are checked against measured whole-file Shannon entropy (section-scoped citations and raw evidence appendices are exempt). These checks preserve contradictory model prose and make the audit fail so the evidence remains reviewable.
* **Source Tagging**: every report carries explicit provenance (`source: llm_judge` vs `source: deterministic_fallback`), preventing stubbed or partial runs from appearing green.
* **Optional dynamic corroboration (WinRE companion)**: master and technical prompts receive component-scoped execution status for Speakeasy, RevAI's static Frida probe, and WinRE. When a WinRE pack exists (`load_dynamic_pack()`), the consumer verifies the WinRE artifact-manifest schema, sample SHA-256, run ID, raw trace SHA-256, byte count, and JSONL record count before using Frida evidence. The complete raw trace and sample-process-tree call/return pairs are stored in the run-attested `deep_dive/02-dynamic-pack.json`, which is itself hashed by the report-input manifest. Master and technical reports receive the validated invocation rows with exact locators; the claim checker resolves those locators back to the same run-bound records. When a trace cannot be validated, the report identifies it as ineligible evidence rather than treating it as absent. Reports also receive sample-launch status, observation window, Frida hook/process/module coverage, unavailable and unobserved hooks, call-limit state, adaptive stop-gate trigger and settle verification, runtime network indicators, captured packet files, sample-process-tree file create/write rows, Frida-decoded runtime path strings, and any agentic-dbg unpack artifact. A gate trigger is runner telemetry, not proof of a malware effect; an installed hook that did not fire is not proof that the behavior is absent. Decoded path strings are not presented as proof of a file drop. A static Frida hook-candidate probe is never treated as execution. Without a pack, runtime observations are omitted and the report says that WinRE execution is unavailable or unverified. Contradictory claims remain visible and fail the audit. Dynamic observations corroborate but never override static verdict gates (`static_yara_wins`). Setup: [`WINRE-REMOTE.md`](WINRE-REMOTE.md).

---

## 11. References & Linked Documentation

* [`OPERATE.md`](OPERATE.md) — Daily pipeline operation, staging samples, running CLI / Console.
* [`PREREQUISITES.md`](PREREQUISITES.md) — System requirements, Ghidra, ghidrasql, Malcat, IDA Pro (optional), LLM setup.
* [`tool-stack.md`](tool-stack.md) — 28 format-aware manifest tools + 26 agent-callable tools (incl. revai-tools, the offline API lookup index and structural binary comparison).
* [`agent-loop-discipline.md`](agent-loop-discipline.md) — Loop discipline, budget warnings, hallucination checks, failure taxonomy.
* [`cadre-pe-loader.md`](cadre-pe-loader.md) — Custom Ghidra PE loader for packed/binder samples.
* [`malcat-capa-engine.md`](malcat-capa-engine.md) — Malcat-native capa engine integration.
* [`WINRE-REMOTE.md`](WINRE-REMOTE.md) — optional Windows dynamic companion: drive WinRE (static, detonation, debugger passes) from the RevAI host, and the presence-gated dynamic-corroboration reporting contract.
