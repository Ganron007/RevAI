# RevAI Changelog

Timeline of significant changes to RevAI. Newest first. Update this file on every
meaningful change — it is the project's memory so context is never lost.

## 2026-08-05 — Agent-loop discipline wired into the DEFAULT engine (d909ee6)

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

## 2026-08-05 — RevAI-only rebrand + streamlined runtime layout (f2874ee)

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

## 2026-08-05 — Agent-loop discipline (initial implementation) (3d9bf8c)

4 features inspired by the AgentRE-Bench evaluation methodology:
1. Budget convergence warnings in the agent loop.
2. Redundant-tool-call detection + nudge.
3. Hallucination check on `final_answer` (claims must have tool evidence).
4. Post-run failure taxonomy (6 buckets).

Implemented env-gated (default ON). NOTE: initially only in the `custom` engine —
superseded by d909ee6 (wired into the default `langgraph` engine).

---

## 2026-08-04/05 — 21-sample campaign (first 15 runs)

- 15/15 automated runs complete, all green (`scripted` small ×5 all_green,
  `agentic` mid/large ×10 truly_green). Case studies grouped by mode under
  `docs/case-studies/{scripted,agentic,ui}`.
- Bugs found + fixed during the campaign:
  - **Deterministic final re-audit** (62866f3) — planner retries publish after its first
    audit left `pipeline-audit.json` stale; orchestrator now re-audits when
    publish/section/yara ran after the last audit.
  - **HITL false-conflict** (a416cf9) — verdict prose normalized to core label before
    comparison; "malicious (X)" vs "malicious" is not a conflict.
  - **Deterministic yara_gen enforcement** (5a8de5c) — planner could skip mandatory
    yara_gen; now run deterministically when rule.yar missing.
- Sample pool: 150 InTheWild samples staged on VM (`/opt/samples/incoming/manual-drop/pool/`),
  manifests in `docs/case-studies/pool/`.

---

## 2026-08-04 — Honest-reporting fixes (18c7b56, 0646f01, 9987285)

- **YARA gate bypass fixed** (8b86f5b) — `yara_scan` now uses the in-process yara-x
  engine; `tool_result_ok` gained a yara branch; `audit_yara` compiles rule.yar.
  Root cause of earlier silent gate pass: `yr` CLI binary missing on VM, batch_errors
  never checked.
- **Score scale** (18c7b56) — prompt pins 0–100 + defensive rescale (≤10 → ×10).
- **Confidence 0** (18c7b56) — `_confidence_final` treats 0 on a complete dive as
  "not stated" → 50; audit gates `confidence_sane`.
- **run_scorecard dead code removed** (9987285) — never used in RevAI; deleted call
  sites + citation hint. (Earlier the empty placeholder "skipped" approach was replaced
  by full removal.)

---

## 2026-08-03/04 — 21-sample campaign planning

- `docs/case-studies/pool/campaign-21.md`: re-run all 15 existing + 6 new
  (mespinoza/conti small, vidar/mespinoza mid, hive/sliver large).

---

## Pending

- [ ] Run R16–R17 (scripted: pool-small-mespinoza, pool-small-conti) — first runs WITH
      the agent-loop discipline features active.
- [ ] Run R18–R21 (agentic: pool-mid-vidar, pool-mid-mespinoza, pool-large-hive,
      pool-large-sliver).
- [ ] After R16–R17 solid: **remove fallbacks entirely** — legacy `/opt/cadre-v3-tools`
      paths and the `REVENG_*` mirror from code/setup/verify/service. No RevEng
      artifacts on RevAI. Testing/fallback stays in RevEng.
- [ ] Sync all 21 case studies to repo (replace + new), update index, commit + push.
- [ ] UI mode: manual runs by user.

---

## How to keep this updated

- Every meaningful change gets an entry here (newest first), with date, commit(s), and
  what/why.
- Note VM (.43) deployment state alongside code changes.
- Update the **Pending** list as items complete.
