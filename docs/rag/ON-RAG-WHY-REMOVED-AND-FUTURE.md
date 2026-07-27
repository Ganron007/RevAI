# On RAG: Why CADRE-RevAI Ships LLM-Only — and How Retrieval Comes Back

*A product position from the CADRE architecture team. This document explains a
deliberate design decision, the evidence behind it, and the roadmap for
re-introducing retrieval the right way. It is the product-facing companion to
our empirical benchmark:*
[*Retrieval Contamination in LLM-Assisted Malware Triage*](ARTICLE-PUBLICATION.md)
*(supporting data: [`BENCHMARK-REPORT-PUBLIC.md`](BENCHMARK-REPORT-PUBLIC.md)).*

---

## TL;DR

We built a malware reverse-engineering pipeline, added Retrieval-Augmented
Generation (RAG) the way the industry recommends, and then **measured whether it
actually helped.** On our benchmarks it did not — and in specific, repeatable
ways it made verdicts *worse*. So we shipped **CADRE-RevAI LLM-only**: the model
reasons over **real tool evidence** (Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA),
not retrieved text. We are not anti-RAG. We are re-introducing it only when a
**curated, RE-primary knowledge base** can *prove* it improves accuracy. This is
that roadmap.

---

## 1. The decision

CADRE-RevAI's production pipeline is **LLM-only by default**:

```
static tools (Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA, r2)
   → stage-tagged evidence pack
   → LLM writes verdict + report
   → quality gate (truly_green) + per-report source tagging
```

There is **no retrieval layer in the default product path.** No embedding
service, no vector index, no corpus to manage. This is not a temporary shortcut
or a missing feature — it is the outcome of an empirical evaluation summarized
below.

---

## 2. Why — the evidence

Our benchmark evaluated RAG inside a **true end-to-end triage loop**, where rich
static disassembler output competes directly with retrieved text, across 16
real-world Windows binaries and four vector configurations (35K→483K chunks,
`bge-m3` ↔ `Qwen3` embeddings). Four findings drove the decision:

### 2.1 Tool evidence packaging dominates retrieval
High-fidelity static packaging drove triage quality more than external
retrieval. **Malcat-first packaging with RAG off (MN)** matched or beat
**Malcat + RAG (MR)** on several hard / out-of-knowledge-base samples, and beat
legacy packaging without RAG (LN) on usefulness. The useful differences came
from *packaging quality*, not retrieval.

### 2.2 The corpus-scaling paradox
Expanding the knowledge base **13.7× (35,302 → 483,800 chunks)** with identical
plumbing did **not** uniformly improve family/theme labels. On niche samples,
the larger corpus *diluted* retrieval density with generic threat-intel and
encyclopedia stubs. **Volume is not quality.**

### 2.3 Retrieval and rule text actively contaminated verdicts
This is the decisive finding. Context injection *degraded* correctness in two
repeatable modes:
- **RAG passage contamination:** a retrieved capa encyclopedia passage mentioning
  *"…common for PlugX, but also used by other families…"* led the judge to emit
  **PlugX** for a sample with **zero** tool evidence for PlugX.
- **Rule-title contamination:** a YARA rule id `CADRE_APT29_CozyBear_Generic`
  led the judge to emit **APT29 / Cozy Bear**; lab rule/tool branding produced a
  fake **"Cadre / CADRE ransomware"** family — *even with RAG turned off.*

The model promoted named entities from **secondary text** (retrieved prose, rule
identifiers) into **primary verdicts** that the binary evidence did not support.

### 2.4 In-KB membership is not generalization
Samples whose hash was *in* the index reached high agreement — but that is
largely **self-hit / membership**, not proof the system generalizes to unseen
threats. A triage system that only recognizes what it has memorized is a
lookup, not an analyst.

> **The honesty problem.** Findings 2.3 and 2.4 are not just accuracy issues —
> they are *integrity* issues. A retrieval layer that can inject a nation-state
> attribution or an invented family from a rule name is a liability in a product
> whose entire value is **trustworthy** triage. We would rather ship a system
> that says *"unknown — here is the evidence"* than one that confidently names a
> family the binary never exhibited.

---

## 3. What we shipped instead

Rather than paper over weak grounding with retrieval, we invested in the things
the benchmark showed actually matter:

1. **Deep, deterministic tool packaging.** SQL-first RE: Ghidra and IDA populate
   SQLite (`ghidrasql`/`idasql`); an agentic LangGraph deep dive queries
   structured evidence (functions, imports, strings, capabilities) instead of
   scraping disassembly text. capa, Malcat, FLOSS, YARA, radare2 feed a
   stage-tagged evidence pack.
2. **An honesty gate (`truly_green`).** A run is `truly_green` only when
   `all_green` (every stage audited) **and** `quality_green` (no deterministic
   fallbacks, no narrative stubs) **and** zero failed tools.
3. **Source tagging.** Every report carries its provenance — `llm_judge`
   (the model wrote it from evidence) vs `deterministic_fallback` (a stub was
   filled in). A stubbed report can **never** look green. This is the direct
   productization of finding 2.3: we make the difference between *grounded* and
   *fabricated* visible.

The result is a pipeline that is **evidence-grounded by construction**, with
fewer moving parts and no corpus-quality surface to defend.

---

## 4. How RAG comes back — the RE-primary roadmap

We are not abandoning retrieval. We are abandoning **undisciplined** retrieval.
The benchmark told us exactly what a useful knowledge base would look like, and
our roadmap (V7) builds precisely that — **quality over volume, measured every
step of the way.**

### 4.1 Gold over bulk
Stop bulk-growing corpora from scraped threat-intel and hash dumps. Build a
**gold knowledge base** from the highest-signal material we have: **our own
verified analysis reports and decompilation notes.** A corpus of *correct,
curated* RE knowledge beats a million generic chunks.

### 4.2 The agentic miner ("golden goose")
An offline agentic miner turns **decompilation → gold chunks**: normalized
pseudo-code, call graphs, and structural control-flow representations of real
malware algorithms (custom RC4, DGAs, process-injection routines), linked to
verified CFGs and symbol tables. The product of the miner is **KB text**, not a
verdict.

### 4.3 Gold schema + measured deltas
- Define a **gold schema**; ingest own reports / decomp notes → JSONL.
- **Delta-embed** into a 35K-lineage tree (`--mode append`) — keep the lineage,
  add gold on top.
- **Measure every delta** against thin official benchmarks (S1–S3, especially
  **HiAsm**, which bulk growth could *not* recover). A gold delta ships only if
  it measurably beats the LLM-only baseline.

### 4.4 Curated public sets; deprecate bulk-grow
Hand-pick public RE sets (ToS-aware), **quality over volume.** Formally
**deprecate bulk-grow-483K as a triage strategy** — it remains a study/archive
artifact, not a production signal source.

### 4.5 Re-introduction is evidence-gated
RAG returns to the product path **only when** the gold corpus demonstrably
improves accuracy on the benchmark — and it returns with the provenance
guardrails from §5 baked in. **Evidence-gated, not assumption-driven.**

---

## 5. The guardrails retrieval must satisfy

When retrieval returns, it returns under strict rules learned from §2.3:

- **Primary vs secondary segregation.** Prompts explicitly separate *primary
  evidence* (facts from the target binary) from *secondary reference text*
  (retrieved passages, rule titles).
- **Negative attribution constraint.** *"Do not output a family or threat-actor
  attribution unless supported by primary static-tool evidence. Treat rule names
  and retrieved document titles as background context, not ground truth."*
- **Property-graded evaluation.** Score behavioral/structural properties
  (process hollowing, RC4, MinGW, packer), not rigid string-matches against
  vendor family names — which fail exactly when the binary is unseen.

---

## 6. The principle

> **Ground the model in what the binary actually shows. Retrieve only what you
> can prove helps. Measure, don't assume.**

CADRE-RevAI ships LLM-only today because the evidence said retrieval wasn't
ready — and because a system that can fabricate a family from a rule name has no
business calling itself an analyst. The roadmap above is how we earn retrieval
back: a curated, RE-primary, **measured** knowledge base, guarded so retrieved
text can never again become an unearned verdict.

---

*CADRE Platform & Security Architecture Research · 2026 · CC BY 4.0*
*Canonical article: [`ARTICLE-PUBLICATION.md`](ARTICLE-PUBLICATION.md) · data appendix: [`BENCHMARK-REPORT-PUBLIC.md`](BENCHMARK-REPORT-PUBLIC.md)*
