# Plan v4 addendum — Agentic function recovery pipeline (Kong-style concepts)

**Status:** Draft, NOT STARTED  
**Scope:** Borrow design patterns from agentic RE tooling (call-graph-ordered analysis, rich context prompts, signature matching, syntactic normalization, agentic deobfuscation, semantic synthesis) and integrate them into the CADRE-RevAI v2/v3 pipeline. **Do not adopt the external tool or its name.**  
**Prerequisite:** Plan v3 browser verification (V3.22) and stable v2/v3 pipeline.  
**Owned by:** `Tools/v4-deploy/v4-plan.md`  

---

## 1. Why this addendum

The current CADRE-RevAI pipeline produces a verdict and a report, but it does **not** systematically recover symbols, types, structs, or deobfuscated control flow from stripped binaries. The analyst still has to manually rename `FUN_00401a30` to `parse_http_header` when a sample is interesting.

This addendum proposes a **v4 agentic function-recovery stage** that:
- Runs after `deep_dive_v2.py` but before `publish_report_v2.py`.
- Uses Ghidra's program database directly (PyGhidra / `ghidra_sql_client.py`) to build rich context windows.
- Analyzes functions in **call-graph order** (bottom-up) so callers inherit resolved callee names/types.
- Applies a **signature database** for known stdlib / crypto / Windows API wrappers to skip LLM inference.
- Normalizes decompiler output before sending it to the LLM.
- Runs an **agentic deobfuscation pass** before analysis when CFF/bogus-flow/string-encryption is detected.
- Performs a **semantic synthesis pass** to unify names and recover structs globally.
- Writes recovered symbols back into the Ghidra program database.

The result: a new `function_recovery.json` artifact that feeds into the publisher and becomes a searchable part of the CADRE-RevAI corpus.

---

## 2. Where it fits in the pipeline

```
intake_v2.py
    ↓
quick_scan_v2.py  (LLM verdict + v1 second opinion + RAG citations)
    ↓
deep_dive_v2.py   (SQL evidence + all tools + deobfuscation hook)
    ↓
agentic_recover_v4.py   <-- NEW STAGE
    - triage functions
    - signature-match known functions
    - agentic deobfuscation pass
    - call-graph-ordered LLM analysis
    - semantic synthesis
    - write back to Ghidra
    ↓
publish_report_v2.py
```

The stage is **opt-in** via `ENABLE_AGENTIC_RECOVERY=1` and **sample-size-gated** (skip if > 5,000 functions to avoid runaway cost).

---

## 3. New components to add

### 3.1 `Tools/v4-deploy/agentic_recover_v4.py`

Main orchestrator. Implements the five-phase pipeline:

| Phase | What it does | Output |
|-------|--------------|--------|
| **Triage** | Enumerate functions, classify size, build call graph, detect source language, match signatures | `triage.json` |
| **Deobfuscation** | For functions flagged by `cff_deflatten.py` / heuristics, run agentic CFF/bogus-flow/string-encryption pass | `deobfuscated_blocks.json` |
| **Analyze** | Bottom-up call-graph-ordered LLM analysis with rich context prompts | `function_results.json` |
| **Synthesis** | Global name unification + struct recovery from field-access patterns | `synthesis.json` |
| **Export** | Write recovered names/types to Ghidra + emit `function_recovery.json` | `function_recovery.json` |

### 3.2 `Tools/v4-deploy/recovery/` library modules

| Module | Responsibility |
|--------|----------------|
| `call_graph.py` | Build call graph from Ghidra SQL; compute bottom-up work order |
| `signatures.py` | Load `stdlib.json` + `crypto.json` + `winapi.json` and match by byte pattern / import / constant |
| `context_builder.py` | Build per-function prompt context: decompilation + caller/callee signatures + string refs + xrefs |
| `normalizer.py` | Syntactic normalization: modulo recovery, negative-literal reconstruction, dead-assignment removal |
| `deobfuscator.py` | Agentic deobfuscation dispatcher: CFF, bogus control flow, string encryption, VM protection stubs |
| `synthesizer.py` | Semantic synthesis: unify naming conventions, recover structs, resolve inconsistencies |
| `ghidra_writeback.py` | Apply recovered symbols/types to the Ghidra program database via `ghidra_sql_client.py` |

### 3.3 Signature databases

| File | Contents |
|------|----------|
| `Tools/v4-deploy/signatures/stdlib.json` | C standard library functions (`malloc`, `memcpy`, `printf`, etc.) |
| `Tools/v4-deploy/signatures/crypto.json` | Cryptographic functions (`AES_*`, `SHA256_*`, `RC4`, `ChaCha`, etc.) |
| `Tools/v4-deploy/signatures/winapi.json` | Common Windows API wrappers (`VirtualAlloc`, `CreateThread`, `WSAStartup`, etc.) |

These are **additive** to capa rules; they tell the recovery stage "do not waste LLM tokens on this function."

### 3.4 LLM integration

Use the existing `llm_call_metadata()` / `llm_judge()` infrastructure in `v2_lib.py` rather than adding new provider SDKs. Add a new prompt template:

- `prompts/agentic_recovery_system.txt` — system prompt for function recovery.
- `prompts/agentic_recovery_user.txt` — user prompt with the rich context window.

Output schema (JSON):
```json
{
  "function_name": "parse_http_header",
  "confidence": 0.85,
  "parameters": [
    {"name": "request", "type": "const char *"},
    {"name": "out_method", "type": "char **"}
  ],
  "return_type": "int",
  "notes": "Parses HTTP method and path from raw request buffer"
}
```

---

## 4. Rich context window (the Kong concept)

For each function analyzed, the prompt must include:

1. **Target function decompilation** (normalized).
2. **Caller signatures** — names/types of functions that call this one (already resolved if bottom-up).
3. **Callee signatures** — names/types of functions this one calls (already resolved if bottom-up).
4. **String references** — strings referenced by this function (from Ghidra `strings` table).
5. **Cross-references** — data xrefs (global variables, struct fields).
6. **Neighbor functions** — 3 functions before and after in address space (often related logic).
7. **Obfuscation flag** — if CFF/bogus-flow detected, note which pass ran and what changed.

This is richer than the current `quick_scan_v2.py` / `deep_dive_v2.py` prompts, which only send aggregate tables.

---

## 5. Call-graph-ordered analysis

Current pipeline analyzes the binary at the **aggregate level** (counts, top functions, imports). The v4 stage analyzes at the **function level** in dependency order:

```
1. Identify leaf functions (no callees).
2. Resolve leaf functions first (LLM or signature match).
3. Mark resolved functions in the program database.
4. Move up one tier; for each function, include already-resolved callee names/types in context.
5. Repeat until all tiers processed.
```

This propagates naming/context from the bottom up, improving recovery quality for callers.

---

## 6. Deobfuscation integration

Reuse existing v3 tools:

| Existing tool | Role in v4 recovery |
|---------------|---------------------|
| `Tools/v3-deploy/cff-deflatten/cff_deflatten.py` | Flag dispatcher candidates; feed to agentic deobfuscation pass |
| `Tools/v3-deploy/deobfuscation/invoke_z3_or_angr.py` | Prove/disprove MBA identities during deobfuscation |
| `Tools/v3-deploy/deobfuscation/z3_mba_tests.py` | Validation suite for MBA simplification |
| `Tools/v3-deploy/deobfuscation/angr_cff_tests.py` | Validation suite for symbolic CFF recovery |

The agentic pass:
1. Detect obfuscation type per function.
2. Apply the cheapest deterministic transformation first (constant prop, dead assignment removal).
3. If still unreadable, invoke Z3/angr to simplify expressions or recover state transitions.
4. Send normalized decompilation to LLM for final naming.

---

## 7. Semantic synthesis

After per-function analysis, run a global pass:

- **Name unification** — if `func_a` calls `parse_url` and `func_b` calls `url_parse`, unify to one name (or flag inconsistency).
- **Struct recovery** — scan field-access patterns across functions; propose struct definitions (e.g., `struct request { char *method; char *path; int version; }`).
- **Confidence reconciliation** — if two functions claim the same name, downgrade both to `NEEDS_HUMAN_REVIEW`.

This reduces per-function hallucination by adding global consistency checks.

---

## 8. Write-back model

Two write-back paths:

| Path | Mechanism | Use |
|------|-----------|-----|
| **Ghidra program database** | `ghidra_sql_client.py` HTTP endpoints or PyGhidra direct | Persistent, becomes part of the `.gpr`/`.rep` project |
| **`function_recovery.json`** | Flat file in `/opt/reveng-outbox/<sha>/` | Consumed by `publish_report_v2.py` for the report |

Use the existing Ghidra SQL write-back approach rather than introducing PyGhidra as the primary transport unless performance demands it.

---

## 9. Evaluation

Add an eval harness:

- `Tools/v4-deploy/eval_recovery.py` — compare recovered symbols against ground truth for samples where we have source or a known-stripped build.
- Metrics:
  - **Symbol accuracy** — word-based Jaccard between recovered and true function names.
  - **Type accuracy** — signature component scoring for params/return types.
  - **Struct recovery precision/recall** — field names matched.
- Initial ground-truth samples: synthetic C/C++ fixtures compiled with symbols stripped; later use open-source malware with source (e.g., selected `CADRE-Courses` samples).

---

## 10. Safety and cost controls

| Control | Why |
|---------|-----|
| `ENABLE_AGENTIC_RECOVERY=1` gate | Off by default; only run when analyst asks |
| Function-count cap (default 5,000) | Prevents runaway LLM cost on huge binaries |
| Signature DB pre-filter | Skips LLM inference for known functions |
| Token budget per function | Cap prompt size; truncate if too large |
| Cost logging | Per-sample token/cost written to `audit.json` |
| HITL checkpoint | Any function with confidence < 0.7 gets queued for review |

---

## 11. Files to add / modify

**New files:**
- `Tools/v4-deploy/agentic_recover_v4.py`
- `Tools/v4-deploy/recovery/call_graph.py`
- `Tools/v4-deploy/recovery/signatures.py`
- `Tools/v4-deploy/recovery/context_builder.py`
- `Tools/v4-deploy/recovery/normalizer.py`
- `Tools/v4-deploy/recovery/deobfuscator.py`
- `Tools/v4-deploy/recovery/synthesizer.py`
- `Tools/v4-deploy/recovery/ghidra_writeback.py`
- `Tools/v4-deploy/signatures/stdlib.json`
- `Tools/v4-deploy/signatures/crypto.json`
- `Tools/v4-deploy/signatures/winapi.json`
- `Tools/v4-deploy/prompts/agentic_recovery_system.txt`
- `Tools/v4-deploy/prompts/agentic_recovery_user.txt`
- `Tools/v4-deploy/eval_recovery.py`

**Modified files:**
- `Tools/v2-deploy/v2_lib.py` — add `agentic_recover()` helper, `ENABLE_AGENTIC_RECOVERY` env handling.
- `Tools/v2-deploy/deep_dive_v2.py` — add post-tool hook to call `agentic_recover_v4.py`.
- `Tools/v2-deploy/publish_report_v2.py` — include `function_recovery.json` in report sections.
- `Tools/v4-deploy/v4-plan.md` — this addendum becomes §3.
- `Tools/v4-deploy/README.md` — describe the new stage.

---

## 12. Relation to existing plans

- **Plan v1** — SQL-first Ghidra/IDA toolset provides the data layer for rich context.
- **Plan v2** — 5-script pipeline provides the integration point.
- **Plan v3** — Z3/angr/CFF detection provides the deobfuscation primitives.
- **Plan v4** — originally embedding-model upgrade; this addendum expands v4 to also cover **agentic function recovery** while keeping the embedding work.

---

## 13. Success criteria

1. On a stripped synthetic C binary, recover ≥ 60% of function names with Jaccard ≥ 0.7.
2. On a known malware sample, recover the top 10 most-connected function names with confidence ≥ 0.8.
3. No pipeline breakage when `ENABLE_AGENTIC_RECOVERY` is unset/off.
4. Cost per sample ≤ $0.50 (or local LLM equivalent) for binaries under 500 KB.

---

*Drafted 2026-07-05. Does not reference or depend on any external project; design patterns only.*
