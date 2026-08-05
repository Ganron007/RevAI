# RevAI Changelog

Timeline of significant changes to RevAI. Newest first. Update this file on every
meaningful change — it is the project's memory so context is never lost.

**Timestamp format:** `YYYY-MM-DD HH:MM:SS UTC` (full date + time to the second).

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
- [ ] Run R18–R21 (agentic: pool-mid-vidar, pool-mid-mespinoza, pool-large-hive,
      pool-large-sliver).
- [ ] Sync all 21 case studies to repo (replace + new), update index, commit + push.
- [ ] UI mode: manual runs by user.
- [ ] README cleanup in proper segments (user will provide suggestions).

---

## How to keep this updated

- Every meaningful change gets an entry here (newest first), with a **full UTC
  timestamp to the second**, commit(s), and what/why.
- Note VM (.43) deployment state alongside code changes.
- Update the **Pending** list as items complete.
