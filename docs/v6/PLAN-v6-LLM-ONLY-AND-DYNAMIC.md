# Plan v6 — LLM-only, Dynamic, Agentic, UI, checklist sweep

> **Status:** Planned (locked 2026-07-22; order refreshed same day).  
> **SSoT home:** `Tools/v6_deploy/` · Tracked in `CHECKLIST.md` (Plan v6).  
> **Why:** RAG benches showed **tool packaging > retrieval** on the current KB. Live default = **LLM + tools**; Flare dynamic next; then a full **agentic RE** revamp for standard/large; then modern Flask UI; then a last pass over pending v2–v6 checklist items. RAG returns under **Plan v7** only.

---

## Locked sequence (S9 may be pending)

```text
S9  Publish RAG article (USER PENDING until confirm)
 │   (V6.1 may proceed in parallel — 2026-07-22)
 ├─► V6.1  LLM-only (RAG off + packaging)  ──► RevAI merge / update & push
 ├─► V6.2  Dynamic analysis (Flare-VM pipeline) ──► RevAI merge / update & push
 ├─► V6.3  Agentic RE framework (Single mode — no std/large size split) ──► RevAI merge / update & push
 ├─► V6.4  Flask UI modern revamp ──► RevAI update & push
 ├─► V6.5  Pending checklist sweep (v2/v3/v4/v5/v6 last revision) ──► RevAI merge / update & push
 └─► LATER  V7  (35K growth + RAG re-eval + commercial APIs)
```

**Rule:** Finish **V6.1 → V6.2 → V6.3 → V6.4** in-repo first. **One CADRE-RevAI** merge/update & push **after V6.4** (not after each block). S9 may stay USER-PENDING in parallel.

---

## Decision (locked)

| Choice | Detail |
|--------|--------|
| **Live default** | **LLM-only** — tools → packaged evidence → LLM. `REVENG_RAG=0` by default. |
| **RAG code / indexes** | Parked (opt-in lab). Not deleted. |
| **Article (S9)** | Honest showcase: measured RAG; did not earn live default on this KB. |
| **v7** | RAG may return after RE-shaped corpus + re-bench vs tools-only. |
| **Agentic RE** | **V6.3** — **Single mode**: goal/state-aware agentic RE across all stages (no size-based standard vs large). Absorbs S11 / V5.15. Not folded into V6.1. |
| **Ship-today** | 2026-07-22 — V6.1→…→V6.5 each with RevAI gate (user lock). |
| **Dynamic** | **V6.2** — Flare-VM detonation pipeline. |
| **Flask UI** | **V6.4** — modern UI (S4 was calibrate-only). |
| **Checklist sweep** | **V6.5** — last revision of open v2–v6 items before v7. |

---

## Main action items

| ID | Item | When | One-liner |
|----|------|------|-----------|
| **V6.1** | LLM-only live path | After S9 | RAG off; ranked stage packaging → LLM |
| **V6.1→RevAI** | RevAI sync | After V6.1 | Merge / update & push public arm |
| **V6.2** | Dynamic (Flare-VM) | After V6.1→RevAI | New optional detonation pipeline → same case logs |
| **V6.2→RevAI** | RevAI sync | After V6.2 | Merge / update & push |
| **V6.3** | Agentic RE framework | After V6.2→RevAI | Industry-standard agent loop for **standard + large** (accommodates V6.1/V6.2 evidence) |
| **V6.3→RevAI** | RevAI sync | After V6.3 | Merge / update & push |
| **V6.4** | Flask UI modern revamp | After V6.3→RevAI | Modern analyst UI |
| **V6.4→RevAI** | RevAI sync | After V6.4 | Update & push |
| **V6.5** | Pending checklist sweep | After V6.4→RevAI | Explore/close open v2/v3/v4/v5/v6 items (last revision) |
| **V6.5→RevAI** | RevAI sync | After V6.5 | Merge / update & push |
| **V7** | RE-primary KB + RAG re-eval | **Later** | 35K growth + commercial APIs |

Detail for Flare architecture: `V6-DYNAMIC-PIPELINE-SKETCH.md`.

---

## V6.1 — LLM-only (RAG off + packaging)

### Goal

Make **tools → LLM** the default triage path: ranked, stage-tagged evidence from Malcat / capa / YARA / FLOSS / Ghidra / IDA — **without** external KB passages. (Major agentic framework work is **V6.3**, not here.)

### Sub-items

| ID | Item | Status |
|----|------|--------|
| **V6.1.1** | Live default **RAG off** (`REVENG_RAG=0`) on Flask + CLI standard/large; opt-in documented | [!] |
| **V6.1.2** | **Evidence packaging** — structured packet per stage; cap size; provenance tags | [!] |
| **V6.1.3** | E2E proof packs: 1 standard + 1 large with RAG off, honest citations | [!] |

### Definition of Done — V6.1

- [ ] Live standard + large run **without** embed/rerank / RAG hits by default.
- [ ] Opt-in RAG still works for lab/article reproduction.
- [ ] Stage-tagged evidence packs feed the LLM (not unbounded dumps).
- [ ] V6.1.3 packs under `Tools/v6_deploy/benchmark/` (or `Tools/v5_deploy/benchmark/v6/`).
- [ ] **V6.1→RevAI** done (public arm updated & pushed).

---

## V6.2 — Dynamic analysis (Flare-VM pipeline)

### Goal

Optional Windows detonation on `.42`; merge into same case logs and LLM evidence pack.

### Sub-items

| ID | Item | Status |
|----|------|--------|
| **V6.2.1** | Dynamic evidence schema `logs/<sha>/dynamic/` | [!] |
| **V6.2.2** | Remnux→Flare job transport (WinRM/SMB/agent) | [!] |
| **V6.2.3** | Non-interactive Frida + procmon from V1.9 scripts | [!] |
| **V6.2.4** | Lab network sink (FakeNet/INetSim) | [!] |
| **V6.2.5** | `dynamic_run_v2.py` + publish/section cards | [!] |
| **V6.2.6** | Accuracy: sandbox cannot clear high-signal YARA | [!] |
| **V6.2.7** | E2E packs: 1 standard PE + 1 large PE | [!] |

### Definition of Done — V6.2

- [ ] Optional stage writes `logs/<sha>/dynamic/` and merges into publish / evidence.
- [ ] Remnux orchestrates; Flare detonates; MVP path without manual GUI babysitting.
- [ ] Lab sink / allowlist — not open internet by default.
- [ ] High-signal YARA + static tools still win; dynamic is corroboration.
- [ ] V6.2.7 packs complete.
- [ ] **V6.2→RevAI** done.

---

## V6.3 — Agentic RE framework (industry-standard)

### Goal

Major revamp so **standard and large** modes use a coherent agentic framework (LangGraph / ToolRegistry / traces / HITL) that consumes **V6.1 packaging** and **V6.2 dynamic** evidence. Absorbs former **S11 / V5.15**.

### Sub-items

| ID | Item | Status |
|----|------|--------|
| **V6.3.1** | Structured final answers (forced JSON / schema) for agent + verdict paths | [!] |
| **V6.3.2** | Shared `ToolRegistry` for custom + LangGraph (timeouts, cost class, skip rules) | [!] |
| **V6.3.3** | Agent budget = SQL/decompile-heavy; checklist stays deterministic pre-loop | [!] |
| **V6.3.4** | HITL / interrupt on final verdict when locks or quick≠deep | [!] |
| **V6.3.5** | Replayable traces (tool calls, tokens, latency) | [!] |
| **V6.3.6** | Wire standard + large to the same framework; consume V6.1 packs + V6.2 dynamic when present | [!] |
| **V6.3.7** | Optional full stage graph (intake→publish) after deep ReAct stable | [!] |
| **V6.3.8** | E2E packs proving agentic path on 1 standard + 1 large | [!] |

### Definition of Done — V6.3

- [ ] Standard and large both run through the documented agentic framework.
- [ ] V6.1 evidence packs (and V6.2 dynamic when enabled) are first-class agent inputs.
- [ ] Traces replayable; HITL path documented.
- [ ] V6.3.8 packs green.
- [ ] **V6.3→RevAI** done.

---

## V6.4 — Flask UI modern revamp

### Goal

Replace calibrate-only S4 UX with a modern analyst UI aligned to V6.1–V6.3 modes (LLM-only default, dynamic stage, agentic large).

### Definition of Done — V6.4

- [ ] Modern UI ships for standard + large (and shows dynamic when present).
- [ ] Settings reflect RAG-off default / opt-in.
- [ ] **V6.4→RevAI** done.

---

## V6.5 — Pending checklist sweep (last revision before v7)

### Goal

Walk open items across Plan **v2 / v3 / v4 / v5 / v6**, close or explicitly defer, so the board is clean before **V7**.

### Definition of Done — V6.5

- [ ] Sweep log in `CHECKLIST.md` / SESSION (what closed, what deferred to v7+).
- [ ] No silent orphans on the active path.
- [ ] **V6.5→RevAI** done.

---

## Out of scope for Plan v6

| Topic | Owner |
|-------|--------|
| Growing / replacing RAG corpora | Plan v7 |
| Commercial vector APIs | V7.10 |
| Deleting RAG implementation | Never — park only |

---

## Relation to earlier IDs

| Old | New |
|-----|-----|
| S11 / V5.15 Agentic RE | **V6.3** |
| V6.1–V6.7 (dynamic-only sketch) | **V6.2.1–V6.2.7** |
| Single S10 RevAI after V6.1 only | **RevAI gate after each of V6.1–V6.5** |
| Agentic polish inside V6.1 | Split — packaging stays **V6.1**; framework = **V6.3** |

---

*Sequence locked 2026-07-22. Next outside this plan: **S9 article publish**.*
