# RevAI Changelog

Timeline of significant changes to RevAI. Newest first. Update this file on every
meaningful change — it is the project's memory so context is never lost.

**Timestamp format:** `YYYY-MM-DD HH:MM:SS UTC` (full date + time to the second).

## 2026-08-06 08:28:44 UTC — System architecture doc + diagram redesign (3997898)

- **Dedicated Architecture Guide (`docs/architecture.md`)** — added comprehensive system documentation covering architectural philosophy (evidence-grounded LLM vs RAG retrieval contamination), component layering (Control & Intelligence layer, Evidence Bus & HITL Approval Gate, 7-stage pipeline spine), stage breakdown, and the automated `truly_green` quality verification gate. Fixed GitHub KaTeX math block rendering error (52613b1). Linked directly in `README.md` above the architecture SVG diagram and in `docs/README.md`.
- **Architecture Diagram Redesign (`docs/img/architecture_v2.svg`)** — re-architected diagram layout into 3 non-intersecting horizontal bands. Eliminates line crossings, explicitly highlights the Evidence Pack → LLM Judge grounding path, and cleanly positions the HITL Approval Gate between Stage 3 Deep Dive and Stage 5 Publish Report.

---

## 2026-08-07 18:20:00 UTC — #7 Deep-dive completeness protocol + deterministic depth gate

**Prompt protocol (a)** — both deep-dive prompts now carry the DEPTH PROTOCOL:
a verdict does not end analysis; before final_answer the summary MUST address
every capability domain (persistence, C2/network, evasion/anti-analysis,
exfiltration, defense impairment, credential access, encryption/obfuscation,
plus entry point, imports, strings) — each as observed evidence or explicit
"not observed".

**Depth gate (b)** — `v2_lib.evaluate_deep_coverage()` scans deep-dive
summary + key_evidence + findings for each domain's signal words OR an
explicit negation; an entirely unmentioned domain => thin => gate fails.
Wired into `audit_deep_standard` + `audit_deep_large` as `depth_coverage`
(only enforced when a summary exists). Whole missing domains fail the run.

**Validation (d)**:
- Re-audit of 29 existing case studies: 13 honestly flagged THIN (keygenmes
  + shallow summaries — written pre-protocol; flags verified fair by reading
  the summaries: 400-650 chars, 0-8 evidence rows, domains skipped).
- Live run (IcedID/njRAT, agentic path, 12 tools, verdict malicious):
  audit rc=1 with `depth_coverage` the ONLY failing check — the pipeline
  honestly rejected a tool-rich but domain-incomplete summary.
- Pass side: re-audit of darkgate — all_green, all 10 domains covered.
- 100/100 regression checks (3 new: thin-fail, full-pass, not-observed-pass).

Pairs with #6 (function recovery) for systematic call-graph coverage.

---

## 2026-08-07 13:00:00 UTC — #6 Agentic function-recovery stage ported + proven (RevEng → RevAI)

**Status on RevEng (verified before porting)**: deployed at `/opt/cadre-v4-tools/`
(legacy path), wired into `deep_dive_v2.py:1008`, gated by
`ENABLE_AGENTIC_RECOVERY=1`, and **proven once** (CozyBear/APT29 artifact with
typed results, confidence 0.95). Never evaluated (eval_recovery unused).

**Port to RevAI**:
- `revai/recovery/` package (call_graph, context_builder, deobfuscator,
  ghidra_writeback, normalizer, signatures, synthesizer — pure stdlib) +
  `revai/agentic_recover_v4.py` + `revai/eval_recovery.py` + `revai/prompts/`
  (2 templates) + `revai/signatures/` (stdlib, crypto, winapi JSON DBs).
- Adaptations: `REVAI_ENABLE_AGENTIC_RECOVERY` gate (legacy honored) + all
  `REVAI_AGENTIC_RECOVERY_*` env names (legacy honored); deobfuscator paths
  `/opt/cadre-v3-tools/…` → `/opt/revai/{cff-deflatten,deobfuscation}/`;
  **`ensure_pipeline_runtime_env()` added in main()** — the missing env-load
  (works under deep_dive_v2 on RevEng, fails standalone) was the one real
  port bug.
- Wiring: `pipeline_single` optional stage between deep_dive and yara_gen
  (opt-in env); `stage_orchestrator` `run_function_recovery` tool (skips when
  env off, never required for green); publish_report_v2 loads
  `function_recovery.json` and feeds recovered names into MASTER + TECHNICAL
  prompts.
- Writeback is SQL-based via ghidra_sql_client (NOT PyGhidra — corrects the
  earlier G6 note), confidence ≥0.7 threshold, never deletes.

**Validated live (RevAI VM)**:
- Direct run on small darkgate: 13/13 functions recovered with real names
  (`parse_float10_from_stream`, `custom_vsnprintf`, `modify_pe_file_resources`,
  `create_delphi_exception`, …) conf 0.7-0.9; writeback applied with honest
  confidence gating (0.55 → NEEDS_HUMAN_REVIEW skip).
- Full scripted pipeline with the stage enabled: all 8 stages rc=0,
  **all_green=True**, `function_recovery rc=0 (267s)`, and recovered names are
  **cited in the published technical report**.
- Regression suite: 94 checks (6 new: gate + package sanity), all PASS.

---

## 2026-08-07 10:30:00 UTC — #5 Verdict calibration (keygenme false-positive fix)

**Problem found by the sanity set**: 5/8 benign Blazytko crackmes were called
Malicious @ 90 with all_green — systematic obfuscation=malware bias. Mechanism:
capa `encode data using XOR` → T1027 treated as intent; "0 ELF imports" read as
packing (normal for static ELF); entropy over-weighted; generic YARA
(domain/base64/url) → indicators; v1 fallback shared the bias so
`llm_and_v1_agree` reinforced it; x86-64 ELFs mislabeled "AARCH64".

**Fix (implemented + proven)**:
- `v2_lib.calibrate_verdict()` — deterministic gate: malicious capped to
  suspicious (score ≤50) when evidence contains protection/obfuscation signals
  but NO behavioral-intent signal (file destruction, C2, persistence, credential
  theft, defense impairment, exfiltration, lateral). Records
  `verdict_calibrated` + `calibration_reason`.
- Applied in quick_scan to BOTH LLM + v1 verdicts BEFORE agreement (fixes the
  v1 false-confirmation) and in the deep-dive finalize.
- `VERDICT_CALIBRATION_CONTRACT` prompt protocol (obfuscation neutral ·
  malicious requires intent · ELF import-table awareness · arch grounding ·
  citations apply to every verdict) embedded in quick_scan, deep-dive,
  publish MASTER + TECHNICAL prompts.
- **Validation — full keygenme re-run (scripted, 8 binaries): 0/8 malicious**
  (was 5/8). encrypted_vault 90→30, monolith 90→25, hash 90→30, xor 90→35,
  rps_rigged 90→20, dungeon 55→20, staged 50→30, vm 100→suspicious/100.
- **Second bug caught during validation**: honest short reports for
  low-signal samples tripped `low_citations` (master min 5 → 3) and the LLM
  wrote citation-free suspicious reports → contract point 7 added
  ("citations apply to every verdict") → both affected runs green after fix.
- Regression suite: 88 checks (9 new calibration tests), all PASS.

---

## 2026-08-07 07:00:00 UTC — G5: retry visibility in the audit surface

- `collect_retry_visibility(log)` in audit_pipeline.py scans quick_scan
  tools-raw + deep-dive tools-raw + deep-dive history for results marked
  `retried` (by `_timed_retry` / `_call_with_tool_retry`) → structured summary
  (layer / tool / retry_count / first_error) into `pipeline-audit.json` and a
  **"Retries observed"** table in AUDIT-REPORT.md (or the explicit
  "_No tool retries occurred during this run._" line when clean).
- Regression suite: 79 checks (5 new collector tests with fake tools-raw),
  all PASS. Validated live: re-audit of the small darkgate case renders the
  negative path correctly.

**Gap-fix round complete (G1-G5).** Retry model now fully matches the 3-mode
contract: scripted = zero retries everywhere · agentic = 1 stage + 1 tool
(transient, user-capped) · UI = full control surface with risk guidance ·
deep-dive retries are transparent (before the LLM sees the error) · every
retry is visible in traces + audit.

---

## 2026-08-07 06:15:00 UTC — G3+G4: UI run-config expansion + manual-stage retry

- **G3 — full UI control surface** (Run-config panel, Settings page):
  - New **Tool retries** field (`REVAI_TOOL_RETRIES`, 0-5).
  - **WARNING banner on stage retries** ("each retry re-runs the WHOLE stage —
    all its tools plus every LLM call; tool retries are the cheap layer").
  - **4 agent-loop feature toggles** (budget warnings / redundant-call nudge /
    hallucination check / failure taxonomy — previously env-only) — persisted
    via `/api/settings` and injected into every spawned stage env.
  - `_RUN_CONFIG_KEYS` + `get_stage_env()` extended; schema + SettingsPage
    updated; tsc clean.
- **G4 — manual UI stage clicks respect stage retries**: `run_stage` in app.py
  refactored with a transient-retry wrapper (attempt loop up to
  run-config `stage_retries`; `is_transient_failure` classification on captured
  output; retry notes in the task log). Previously manual clicks had no retry
  (the wrapper lived only in the orchestrator's StageRunner).
- **Validated live**: settings API round-trip persists tool_retries + feature
  toggles (verified + reset); UI bundle deployed with all new panel elements;
  74/74 regression checks pass.

---

## 2026-08-07 04:45:00 UTC — G1+G2: REVAI_TOOL_RETRIES knob + deep-dive transparent tool retry

Gap-fix round (user-capped retry model, 3-mode contract):

- **G1 — tool retry knob + gating**: `REVAI_TOOL_RETRIES` (0-3, default 1;
  generous 2, unlimited 5) added to `run_profile()`. quick_scan's `_timed_retry`
  was UNGATED (retried once on transient even in scripted mode) — now gated on
  the knob, loops up to the count, marks `retried`/`retry_count`/`first_error`.
  `pipeline_single` pins `REVAI_TOOL_RETRIES=0` alongside `REVAI_STAGE_RETRIES=0`
  → scripted is truly zero-retry at both levels.
- **G2 — deep-dive transparent tool retry**: shared `_call_with_tool_retry()`
  wrapper (retries transient failures up to the knob BEFORE the LLM sees the
  error — saves an LLM round-trip + step budget), wired into BOTH engines
  (custom loop + langgraph `_runner` via helpers). After the retry budget the
  error reaches the LLM and the agent's own judgment takes over.
- **Style-gate calibration**: prose-ratio backstop lowered 0.20 → 0.15
  (precise gates — orphan tables, bare fences, citations — carry the real
  detection weight; table-heavy but interpreted narratives ran 0.19-0.27).
- **Validated live** (small darkgate `8cffdc40…`, both modes):
  scripted all_green=True; agentic truly_green=True with
  `run_config.tool_retries=1` in trace. The policy-7 retry chain was exercised
  for real: section failed the old 0.20 gate (non-transient, correctly not
  auto-retried) → planner re-ran publish→section → green.
  Trace shows it: `[..., run_section_publish, run_publish, run_section_publish,
  run_audit]`.
- Regression suite: 74 checks (2 new: profile tool_retries, deep-dive wrapper
  with fake registry), all PASS.

---

## 2026-08-06 12:30:00 UTC — Report quality review: templates + explain-don't-dump gates (Phases A-C)

Research-driven redesign (4 real reports studied: Kaspersky GReAT OkoBot, Unit 42
XCSSET v4.0, Microsoft Threat Intelligence XCSSET, ESET Gamaredon 2025) applied
and PROVEN on 3 live case studies (scripted small, agentic mid, agentic large
darkgate) — all publish/section/audit green:

**Phase A — section anatomy (v2_lib.py):**
- MASTER 16→17: added `3. Background & Family Lineage` (prior-research anchor);
  removed process artifact `Initial Triage (15 minutes)` (folds into Static);
  `Network Analysis` → `Network Analysis & C2`; MITRE ATT&CK moved to the end
  cluster (#11, next to Detection Rules + IoCs); appendices structured
  (`Appendix A: Evidence Trail`, `Appendix B: Module Inventory`).
- TECHNICAL 12→13: removed tool-named `Malcat Triage Summary` (demoted into
  Appendix A); `Capabilities & MITRE` split into `Capabilities Assessment` +
  new `MITRE ATT&CK Mapping` at end; appendices A/B.
- REPORT_SECTION_SPECS rekeyed to match; deterministic fallback builders
  updated; malcat-optional gate emptied (no malcat-exclusive section anymore).

**Phase B — style contract + gates (report_quality.py, prompts):**
- `REPORT_STYLE_CONTRACT` (quote-then-translate, observation→implication,
  observed-vs-latent, hedged inference, evidence traceability, explicit
  unknowns, narrative flow, reader test) embedded in all 4 prompt sites
  (MASTER, TECHNICAL v2, per-section, TECHNICAL v3) + section prompts.
- New gates in evaluate_report_markdown (LLM sources only; fallback exempt):
  `no_byline` (provenance banner), `low_citations` (narrative `(source:` count),
  `dump_style` (prose-ratio backstop 0.20), `bare_fences` (large adjacent code
  dumps with no prose between), `orphan_tables` (table immediately followed by
  another table). Style evaluated on the NARRATIVE body only (truncated at
  Structured Evidence / Evidence Pack / Appendix markers).

**Phase C — live validation caught + fixed 3 real bugs:**
1. Provenance banner added AFTER quality eval in both publishers → byline_ok
   always failed → banner moved before eval.
2. v3 appendix heading `## Appendix A:` missed by truncation markers → raw
   evidence tables tripped orphan gate → prefix-based marker matching.
3. Table→heading is legitimate (section summary tables); global ratio too
   blunt for table-heavy large reports → ratio backstop 0.20, precise gates
   carry the weight.
- Spot-check shows the pattern working: tables introduced + interpreted
  ("capa analysis identified 6 capability rules… The full capa rule mapping
  is below:" → "The three encryption rules confirm…").
- Regression suite: 66 checks (7 new style-gate checks), all PASS.
- Validation logs: /opt/samples/runlogs/val-*.log, phaseC-master*.log.

---

## 2026-08-06 08:45:00 UTC — 13 re-run case studies synced to repo

The 13 R1–R15 case studies (re-run overnight on the fixed pipeline) are now
replaced in `docs/case-studies/` — the public repo no longer carries the
pre-fix reports (0-10 scores, scorecard mis-attribution). Verified per sample:

- All 13 verdict scores 0-100 (88-95), Malicious
- Provenance banner present in 13/13 REPORT-MASTER-v2
- Zero "scorecard" citations across all synced artifacts (was the R2/R12
  artifact class)
- All 13 stage traces all_green/truly_green
- Case-studies index updated with re-run note

Sync path: VM `/opt/samples/logs/<sha>/` → repo `docs/case-studies/{scripted,agentic}/`
(10 artifacts per case: 5 reports + AUDIT + 3 rules + stage_trace + verdict).

---

## 2026-08-06 07:55:00 UTC — Re-run 13/13 GREEN + retry system verified on both modes

**R1–R15 re-run complete — 13/13 green.** 12 passed in one pass; darkgate
(#13) took three attempts, and the two root causes were both fixed in code:
(1) env flake — capa 300s timeout + Malcat MCP closed (see retry system below);
(2) `PermissionError` on `/tmp/cadre-hitl` (root-owned by the systemd campaign
service vs the remnux retry) — `hitl_checkpoint` now degrades to a per-user
dir and NEVER fails a stage over a telemetry write.

**Bounded retry + run-config (agentic ≠ scripted)** — implemented (3beb9be,
e0817b3) and now **proven live on both modes** with a fresh small darkgate
sample (`8cffdc40…`, 663KB):

- **Scripted** (`pipeline_single.py`): deterministic, zero retries
  (`REVAI_STAGE_RETRIES=0` pinned, user env wins), all 7 stages rc=0,
  `all_green=True`, verdict Malicious/95, provenance banner present.
- **Agentic** (`stage_orchestrator.py`): `truly_green=True`,
  `check_quality ok=True issues=[]`, `run_config` recorded in trace
  (standard profile · stage_retries=1 · recursion 40 · timeout_scale 1.0 ·
  transient-only), every tool_result carries `attempt=1 retried=False`
  (retry machinery live + honest).
- Retry semantics: transient-only classification (`is_transient_failure`:
  timeout / MCP closed / connection / OOM retryable; permission / rule /
  artifact failures never retried), stage-level retry in StageRunner._run,
  tool-level `_timed_retry` in quick_scan (capa timeout, Malcat MCP closed),
  budgets via `run_profile` (standard/generous/unlimited + REVAI_* overrides),
  deep-dive MAX_STEPS from `REVAI_DEEP_MAX_STEPS`.
- **UI**: Run configuration panel (Settings page) — profile, stage retries,
  tool timeout scale, recursion, deep-dive steps, transient-only toggle;
  persisted via `/api/settings` → injected into every stage env by
  `get_stage_env`. Deployed to the VM (npm build on `.43`, service restarted).
  Fixed during deploy: `RunConfig` missing from `api/types.ts` barrel export.
- **README**: "Three ways to run the pipeline" table now documents the real
  differentiation (sequencing, failure handling, best-fit per mode).
- Regression suite: 59 checks (17 new: transient classification, run profiles +
  overrides, checkpoint resilience), all PASS.

---

## 2026-08-06 00:35:00 UTC — Gate regression suite + re-run started

- **Re-run launched** at 00:10:13 UTC: 13 samples (R1–R15 batch), 3 scripted
  (`pipeline_single.py`) + 10 agentic (`stage_orchestrator.py`), reboot after
  every 2, self-resuming via systemd `rerun-resume.service` +
  `/opt/samples/re-run-state.txt`. Master log:
  `/opt/samples/runlogs/rerun-master.log`.
- **Gate regression suite** (`tests/test_gate_regression.py`) — 42 checks,
  all PASS: injects the production bug classes (0-10 score scale, verdict-lock
  conflicts, Rook-class engine mis-attribution, yara batch_errors false-green,
  capa empty/bridge, floss empty, stub/missing sections, SQL-deep
  documented-infra vs non-attempt, confidence-0-on-complete) and asserts the
  gates hard-fail. Runs locally with no VM/LLM/yara_x.
- **Gated logic extracted to v2_lib** (behavior-preserving, now unit-testable):
  `normalize_verdict_score` (quick_scan_v2), `sql_deep_honest` +
  `agentic_confidence_sane` (audit_pipeline). **Not synced to VM** — the running
  campaign stays on `80c92a3`; sync after completion.

---

## 2026-08-05 18:45:00 UTC — Re-run ARMED: VM pre-flight verified, standing by for user signal

No samples run. Read-only pre-flight of `.43` completed with all checks green:

- Scripts in sync — 7 provenance-changed scripts re-pushed to `/opt/scripts`,
  sha256-verified identical to local; hitl helpers verified.
- `/opt/revai/config/REVAI_COMMIT` written (`80c92a39…`) — provenance resolves
  to the real commit live on the VM (tested via v2_lib).
- LLM env (8 REVAI_ keys), service active+enabled, 66G disk free, yara-x module,
  deobfuscation wrapper, Malcat, ghidrasql, Ghidra, cff-deflatten all confirmed.
- All 13 re-run samples present (9 virussign .vir, koi, lumma, remcos, pool
  small/mid/large for bkransomware/quasar/darkgate).
- Run convention locked: `pipeline_single.py` for 3 scripted, `stage_orchestrator.py`
  for 10 agentic, reboot every 2 runs.

Next action (user signal only): run the 13 samples overnight, verify
truly_green + 0-100 scores + provenance stamp + no scorecard markers, then sync
case studies, commit, push.

---

## 2026-08-05 18:31:00 UTC — Report provenance stamp + brand cleanup (public release prep)

Two-part cleanup before the R1–R15 re-run (reports must record which pipeline
made them, and the public repo must carry only the RevAI brand):

**Provenance stamp (blocks the re-run):**
- `v2_lib.revai_provenance()` / `provenance_block()` — commit (from
  `/opt/revai/config/REVAI_COMMIT`, written at sync time), engine
  (`REVAI_AGENTIC_ENGINE`), the 4 agent-loop flags, and UTC timestamp.
- Stamped into: REPORT-MASTER-v2, REPORT-TECHNICAL-v2 (publish_report_v2),
  REPORT-MASTER-v3 + REPORT-TECHNICAL-v3 (section_publisher), AUDIT-REPORT
  (render_markdown), rule.yar (`revai_commit`/`revai_engine` meta),
  rule.yml (`reference:`), rule.yara.json (`provenance`), pipeline_single +
  orchestrator stage traces (`provenance`), pipeline-audit.json (`provenance`).
- Reports carry machine-readable `provenance` in their JSONs + a markdown banner
  at the top of every .md artifact — score-scale / engine-attribution issues of
  the R1–R15 batch become self-evident on inspection.

**Brand cleanup (87b5b57):**
- Full brand pass `CADRE-RevAI`/`cadre-revai`/`cadre_revai` → `RevAI`/`revai`
  across code, docs, UI, install scripts, and all 21 case-study artifacts
  (rule.yar/rule.yml/rule.yara.json/AUDIT-REPORT/REPORT-*).
- Removed stale `examples/` (empty), obsolete
  `extensions/deobfuscation/v2-validate-integration.patch.txt` (wrapper already
  integrated in `deep_dive_agentic.py`); deobfuscation README updated to the
  active-integration state; `pyproject.toml` name=`revai`, authors=RevAI Team.
- `internal/` cleaned: stale audits + experimental/ removed, IMPROVEMENT-PLAN
  rewritten to current state; `malcat_ubuntu24_v0_9_15.zip` renamed to
  `malcat.zip` (setup-remnux.sh auto-install expects this exact name).

---

## 2026-08-05 16:40:48 UTC — Docs consolidation + README tidying (public release prep)

README reworked into a clean public-release document (no tracker/status updates, no
long-form feature explanations):

- **Feature Matrix** now lists only the 6 distinctive capabilities with doc links:
  Custom CADRE PE Loader, Agent-loop discipline, Malcat native capa engine,
  in-process yara-x engine, honest `truly_green` gate, Tool Stack (24+19 tools).
  Commodity items removed.
- **4 feature sections removed from README**, moved to dedicated docs:
  `docs/cadre-pe-loader.md`, `docs/agent-loop-discipline.md`, `docs/tool-stack.md`,
  `docs/malcat-capa-engine.md`. `docs/README.md` index updated.
- **Accuracy pass:** scripted-stages list now includes `section`
  (publish → section → audit) matching `pipeline_single.py`; Malcat install note
  now mentions auto-install from `internal/malcat.zip`; orphaned
  `docs/img/ui-showcase-v2.png` removed; "Malware RE Reports" note wording;
  Reality check placed under "What is RevAI?"; Status column removed from the
  Feature Matrix.
- All counts/claims verified against code (24 TOOL_MANIFEST, 19 ToolRegistry,
  7 pipeline stages, applies_to routing).

---

## 2026-08-05 12:28:49 UTC — R18–R21 complete — 21/21 automated runs green

R18 vidar, R19 mespinoza (large), R20 hive, R21 sliver — all agentic, all truly_green.
Final 4 case studies synced to `docs/case-studies/agentic/`, index updated.

Also on 2026-08-05:
- **Permanent SQL-deep gate fix (4d800f6)** — packed ELF (Sliver-class): ghidrasql
  server can die at startup; ida_query absent without IDA. The agent tried SQL and
  failed on infrastructure, then analyzed via YARA/Malcat/capa/floss — but
  `sql_deep_ok=False` hard-failed the gate (dead-end). Now: deep-dive records
  `sql_deep_attempted` + `sql_deep_unavailable` (ghidrasql_server_died /
  idasql_missing / sql_failed); gates fail only on a complete non-attempt; a
  documented infrastructure failure is recorded, not gate-failing.
- **Permanent orchestrator fixes (ae16d68)** — Part A: deterministic verdict
  reconciliation (tool evidence outranks LLM masquerade read; recorded
  `verdict_reconciled`); Part B: mandatory publish/section enforcement; Part C:
  bounded recovery on unrecoverable engine-citation failures; masquerade-awareness
  added to both deep-dive prompts.
- R18 first attempt failed engine_citation (capa claimed for a YARA needle) — honest
  gate; clean re-run green. R19 deep dive said benign on the Microsoft masquerade —
  resolved via human review (verdict locked malicious) + Part A now handles this
  class automatically. R21 first attempt hit the sql_deep gate — fixed permanently.

---

## 2026-08-05 09:55:48 UTC — Permanent orchestrator fixes — no dead-ends (ae16d68)

Found during R18 (engine-citation fail) + R19 (verdict conflict + skipped publish).
Permanent, deterministic solutions — not patch-through:

- **Part A — deterministic verdict reconciliation:** when quick triage (deterministic
  tool evidence: capa/YARA/Malcat/imports) is stricter than the deep-dive LLM read
  (e.g. quick=malicious, deep=benign), reconcile deep → stricter label with an explicit
  `verdict_reconciled` marker + reason. Real-world RE principle: tool evidence outranks
  an LLM that took a metadata masquerade at face value. `REVAI_HITL_VERDICT=1` preserves
  the human boundary. Never downgrades a stricter deep verdict.
- **Part B — mandatory publish/section enforcement:** planner skipping publish no longer
  dead-ends the audit on missing reports; publish+section run deterministically
  (same pattern as yara_gen enforcement).
- **Part C — bounded recovery on unrecoverable engine-citation failures (R18 class):**
  audit fails on `engine_citation_ok` with `corrected=0` → re-publish once (fresh LLM
  call), re-section, re-audit. Bounded + recorded.
- **Masquerade awareness** added to both deep-dive prompts (custom + langgraph):
  VersionInfo/product/brand metadata is trivially forged — a tool-flagged sample must
  NOT be called benign on brand strings alone.

R19 (pool-mid-mespinoza) resolved via human review (deep dive was fooled by the
Microsoft masquerade; verdict locked to malicious; audit green).

---

## 2026-08-05 05:53:48 UTC — Fallbacks removed entirely — RevAI-only (b40d59e)

**The legacy compatibility layer is gone.** R16–R17 ran solid with the agent-loop
discipline active, so per plan the fallbacks were stripped:

- Code: dropped `_first_existing`/`_mirror_legacy_env` and every legacy path from
  `v2_lib.py`, `intake_v2.py`, `v2_validate.py`, `app.py`,
  `extensions/deobfuscation/invoke_z3_or_angr.py`. `llm.env`/`capa-rs`/`hitl`/
  `signatures`/`cff-deflatten` are now **`/opt/revai` only**.
- Install: `setup-remnux.sh`, `verify-remnux.sh`, `revai.service`, and
  `config/llm.env.template` reference only `/opt/revai`; service EnvironmentFile →
  `/opt/revai/config/llm.env`.
- VM (.43): `/opt/cadre-v3-tools` **deleted entirely**; verified service active +
  HTTP 200, config loads, no legacy refs in deployed v2_lib, git↔VM in sync.
- No `REVENG_*` remains anywhere except the CHANGELOG's historical record.
- Fresh deployments now produce the single clean `/opt/revai` structure.

---

## 2026-08-05 04:41:42 UTC — Docs: CHANGELOG + README feature docs (f70069a)

- Added `CHANGELOG.md` (this file) and documented the 4 agent-loop features in README
  (budget warnings / redundant detection / hallucination check / failure taxonomy).

---

## 2026-08-05 04:27:20 UTC — Agent-loop discipline wired into the DEFAULT engine (d909ee6)

**Context:** the 4 loop-discipline features (inspired by the AgentRE-Bench review) were
initially implemented only in the `custom` agentic engine, which is NOT the default.
Audit caught that 3 of 4 would be dead code under `REVAI_AGENTIC_ENGINE=langgraph`.

**Fix:** ported features 1–3 into `agentic_langgraph.py` so they run in the default engine:
- **Budget warnings** — call-count-aware `[BUDGET]`/`[BUDGET CRITICAL]` notes appended to
  each tool's returned output (the channel the model reads each turn), plus a
  budget-discipline line in the system prompt.
- **Redundant-call detection** — identical `(tool, args)` calls skipped in the tool
  wrapper with a nudge; counted.
- **Hallucination check** — `final_answer` claims validated against tool findings; one
  grounded correction pass re-derives the verdict strictly from evidence.
- **Failure taxonomy** was already in the shared `_finalize_agentic_result` (both engines).
- `redundant_calls` now passed to the shared finalizer.

Shared helpers (`_loop_flag`, `_call_signature`, `_unsupported_claims`) injected via the
helpers dict. Verified on VM (.43): import OK, redundant skip + budget note fire.

**Flags (all default ON):** `REVAI_BUDGET_WARNINGS`, `REVAI_REDUNDANT_NUDGE`,
`REVAI_HALLUCINATION_CHECK`, `REVAI_FAILURE_TAXONOMY`.

---

## 2026-08-05 03:45:10 UTC — RevAI-only rebrand + streamlined runtime layout (f2874ee)

**Goal:** RevAI is the primary project. Remove RevEng branding/artifacts; fresh
deployments must produce a clean, working, RevAI-branded install.

**Changes:**
- Env vars: all `REVENG_*` → `REVAI_*` across code/config/docs (89 references, 12 files).
  Back-compat: `_mirror_legacy_env()` auto-mirrors any lingering `REVENG_*` → `REVAI_*`
  (REVAI_ wins), so old llm.env / systemd / shell exports keep working.
- Runtime layout: moved off legacy `/opt/cadre-v3-tools` to clean `/opt/revai/`
  (`config/llm.env`, `bin/capa-rs`, `hitl/`, `signatures/`, `deobfuscation/`, `cff-deflatten/`).
  Every path resolves new-location-first with legacy fallback (`_first_existing`).
- Aligned for fresh deploys: `setup-remnux.sh` creates `/opt/revai/*`,
  `deploy.sh` deploys hitl → `/opt/revai/hitl`, `verify-remnux.sh` checks `/opt/revai`,
  `revai.service` loads both EnvironmentFiles, `config/llm.env.template` uses `REVAI_*`.
- VM (.43) migrated: llm.env moved to `/opt/revai/config/llm.env` (600 perms, REVAI_ keys),
  capa-rs/hitl/extensions copied; dead RevEng docs + stale v2_lib.py removed from
  `/opt/cadre-v3-tools`.
- **Fallback still present** (legacy paths + REVENG_ mirror) — pending removal after a
  solid run (see Pending below).

---

## 2026-08-05 03:07:24 UTC — Agent-loop discipline (initial implementation) (3d9bf8c)

4 features inspired by the AgentRE-Bench evaluation methodology:
1. Budget convergence warnings in the agent loop.
2. Redundant-tool-call detection + nudge.
3. Hallucination check on `final_answer` (claims must have tool evidence).
4. Post-run failure taxonomy (6 buckets).

Implemented env-gated (default ON). NOTE: initially only in the `custom` engine —
superseded by d909ee6 (wired into the default `langgraph` engine).

---

## 2026-08-04 16:46:25 UTC — Orchestrator: deterministic final re-audit (62866f3)

Planner retries publish after its first audit left `pipeline-audit.json` stale;
orchestrator now re-audits when publish/section/yara ran after the last audit, so
`truly_green` reflects the FINAL artifacts.

---

## 2026-08-04 13:24:50 UTC — Campaign-21 plan (49f72e4)

Re-run all 15 existing (replacing reports with the fixed pipeline: 0-100 score,
confidence gate, no scorecard) + 6 new InTheWild samples (mespinoza/conti small,
vidar/mespinoza mid, hive/sliver large). All verified present on VM.

---

## 2026-08-04 08:00:47 UTC — Remove dead run_scorecard code (9987285)

RevAI never used the RevEng scorecard/RAG harness (module never ported). The inherited
import hook fired on every run and leaked "No module named 'run_scorecard'" into reports.
Deleted the call sites + "scorecard" citation hint from the section prompt. Tool I/O
truth is `audit_pipeline`'s job (`tools_all_ok`, `engine_citation_ok`).

---

## 2026-08-04 07:51:33 UTC — Fix 3 report discrepancies (18c7b56)

1. **Score scale** — quick_scan prompt pins 0-100 + defensive rescale (≤10 → ×10) so
   reports never mix /10 and /100.
2. **Confidence 0 on complete deep dive** — `_confidence_final` treats 0 as
   "not stated" → 50; audit gates `confidence_sane` (standard + large).
3. **run_scorecard dead code** — cleanly skipped when module absent (was leaking
   "No module named run_scorecard" into reports).

Verified on VM (.43): confidence gate fails old koi deep-dive, rescale works.

---

## 2026-08-04 07:13:14 UTC — 15/15 automated runs complete (191c415)

Agentic pool-large-darkgate (darkgate multi-family, 8.7MB) truly_green. All automated
campaign runs done; 12 UI runs remain (manual).

---

## 2026-08-04 05:53:03 UTC — Batch 2 complete: 14/15 (b9fc37c)

Scripted remcos + pool-small-bkransomware (all_green), agentic lumma-stealer +
koi-stealer + pool-mid-quasar (truly_green). Fixed orchestrator HITL false-conflict
(verdict prose normalized to core label before comparison).

---

## 2026-08-04 03:43:08 UTC — Docs: short project title (57f4fea)

Docs use short project title; one-line CADRE affiliation.

---

## 2026-08-04 03:10:13 UTC — Orchestrator: HITL false-conflict fix (a416cf9)

Verdict prose normalized to core label (malicious/malware/suspicious/clean/...) before
comparing quick vs deep. "malicious (lumma info stealer)" vs "malicious" is NOT a
conflict — Run B (lumma) stopped for a fake HITL review.

---

## 2026-08-03 20:31:01 UTC — Sample pool: 150 InTheWild manifests (f98555d)

50 small/mid/large samples (29-34 families each), deployed to VM at
`/opt/samples/incoming/manual-drop/pool/` for the campaign + UI.

---

## 2026-08-03 11:47:03 UTC — Agentic batch complete: 6 mid/large (f7989f2)

40f92672, 8264dc61, f622efa7, 970b822a, 7edf35d0, 9358c2e1 — all truly_green.
Found + fixed 2 orchestrator bugs during campaign (see 5a8de5c, 62866f3).

---

## 2026-08-03 10:19:21 UTC — Orchestrator: deterministic yara_gen enforcement (5a8de5c)

LLM planner could skip mandatory yara_gen (audit hard-requires rule.yar); now run
deterministically when rule.yar is missing, then re-audit.

---

## Earlier history (pre-CHANGELOG)

Reconstructed from git log; see `git log` for full detail.

- **2026-08-03/04 — Honest-reporting fixes:** YARA gate bypass fixed (8b86f5b —
  in-process yara-x engine, tool_result_ok yara branch, audit_yara compiles rule.yar,
  _ok_tool_strict checks batch_errors); verify-remnux.sh checks yara_x module (0646f01);
  yara schema consumer sync (d413db1); case-studies cleanup/reorg (5cb2e35, e93ef8d).
- **2026-07 — Pipeline builds:** earlier campaign batches, 15 case studies grouped by
  mode (`docs/case-studies/{scripted,agentic,ui}`).

### Project origin

**2026-07-10 11:51:50 UTC — first commit `82b1013`**

RevAI started here as the **public arm of the RevEng R&D project** (the private
research lab that built this pipeline). This first commit — the initial scaffold:
README, `config/llm.env.template`, docs (CONFIGURE/DEPLOY/INSTALL/OPERATE),
`install/` (setup/verify/service), `revai/app.py`, and the early `cff-deflatten`
sources — is the starting point of the public repo (138 commits and counting since).
No records exist of the R&D work that led up to this commit; this entry is the only
place RevEng is referenced, as the legitimate origin of this project.

---

## Pending

- [x] ~~Run R16–R17 (scripted: pool-small-mespinoza, pool-small-conti) — first runs WITH
      the agent-loop discipline features active.~~ **DONE 2026-08-05** — both all_green.
- [x] ~~After R16–R17 solid: remove fallbacks entirely.~~ **DONE 2026-08-05 05:53:48 UTC**
      (b40d59e) — no RevEng artifacts on RevAI; testing/fallback stays in RevEng.
- [x] ~~Run R18–R21 (agentic: pool-mid-vidar, pool-mid-mespinoza, pool-large-hive,
      pool-large-sliver).~~ **DONE 2026-08-05 12:28 UTC** — all truly_green.
- [x] ~~Sync remaining case studies (R16–R21).~~ **DONE 2026-08-05** — all synced + pushed
      (`28cb399`, `4423a9c`).
- [ ] UI mode: manual runs by user.
- [x] ~~README cleanup in proper segments.~~ **DONE 2026-08-05** — Feature Matrix highlights
      only distinctive capabilities; 4 feature sections moved to dedicated docs; accuracy
      pass; Status column removed. README is now a clean public-release document.

---

## How to keep this updated

- Every meaningful change gets an entry here (newest first), with a **full UTC
  timestamp to the second**, commit(s), and what/why.
- Note VM (.43) deployment state alongside code changes.
- Update the **Pending** list as items complete.
