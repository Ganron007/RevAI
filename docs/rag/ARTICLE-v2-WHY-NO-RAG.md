# We Added RAG to Our Malware Analysis Pipeline, Then Removed It — Here's the Data

*The industry treats Retrieval-Augmented Generation as mandatory for domain LLMs.
We built it, benchmarked it on real malware, and found it didn't help — and in
specific, repeatable ways made our verdicts worse. This is the story of that
decision, the evidence behind it, and how we plan to earn retrieval back.*

**CADRE Architecture & Security Research · 2026**

> Full empirical benchmark: [*RAG for Automated Malware Triage*](RESEARCH-ARTICLE-RAG-Malware-RE.md) ·
> supporting data: [`BENCHMARK-REPORT-PUBLIC.md`](BENCHMARK-REPORT-PUBLIC.md) ·
> product position: [`ON-RAG-WHY-REMOVED-AND-FUTURE.md`](ON-RAG-WHY-REMOVED-AND-FUTURE.md)

---

## The assumption everyone makes

If you build an LLM that needs to know things — malware families, CVEs, TTPs —
the playbook is written: stand up a vector database, chunk your threat-intel,
embed it, and retrieve at inference time. RAG is the industry's answer to "the
model doesn't know our domain." It's so standard it's rarely questioned.

We didn't question it either — at first. We built **CADRE-RevAI**, an automated
malware reverse-engineering pipeline, and we added RAG exactly by the playbook.
Then we did the thing that's surprisingly rare in security AI: **we measured
whether it actually made the analysis better**, inside a real end-to-end triage
loop where a disassembler's output competes directly with the retrieved text.

The answer changed our product.

---

## The experiment

We ran **16 real-world Windows malware binaries** through a controlled triage
harness across two experimental axes:

- **Axis 1 — model × corpus scale:** four vector configurations scaling the
  knowledge base from **35,302 to 483,800 chunks** (a 13.7× expansion) and
  swapping embedding models (`bge-m3` ↔ `Qwen3-0.6B`).
- **Axis 2 — packaging × retrieval:** a full 2×2 matrix over all 16 binaries,
  crossing **legacy vs. Malcat-first evidence packaging** against **RAG on vs.
  off**.

Crucially, we graded on **behavioral and structural properties** (process
hollowing, RC4, packer, build traits), not string-matches against vendor family
names — because the moment a binary isn't in your index, "what family label did
you print" is a meaningless metric.

---

## What we found

### 1. The tools mattered. The retrieval didn't.

The single strongest driver of triage quality was **how well we packaged the
static tool evidence** — not whether we retrieved anything. Our Malcat-first
packaging **with RAG turned off** matched or beat Malcat **with RAG on** for
several hard, out-of-knowledge-base samples. The model didn't need our document
store; it needed the binary's own structure, handed to it cleanly.

### 2. Bigger corpus, same (or worse) answers.

We grew the knowledge base **13.7×** with identical plumbing. It did not
uniformly improve labels. On niche samples, the larger corpus *diluted* the
good hits with generic threat-intel and encyclopedia stubs. **Volume is not
quality** — and in retrieval, more can genuinely be less.

### 3. Retrieval didn't just fail to help. It lied.

This is the finding that ended the debate. Context injection produced confident,
*wrong* verdicts in two repeatable modes:

- **The "PlugX" effect.** For one sample, hybrid retrieval returned capa
  encyclopedia passages. One mentioned that a certain encoding scheme is
  *"common for PlugX, but also used by other families."* That sentence entered
  the context. The model emitted **PlugX.** The static tools had found zero
  evidence of PlugX. The sample was not PlugX. A retrieved *aside* became a
  verdict.

- **The "APT29" effect.** A YARA rule named `CADRE_APT29_CozyBear_Generic`
  appeared in the prompt. The model emitted **APT29 / Cozy Bear** — a
  nation-state attribution pulled from a *rule identifier*. Worse, our own lab's
  rule and tool branding bled into a fabricated **"Cadre / CADRE ransomware"**
  family — and this happened **with RAG completely turned off.** The
  contamination wasn't only in retrieval; it was in any secondary text the model
  could promote into a primary claim.

### 4. Recognizing your friends isn't intelligence.

Samples whose hash was *already in the index* scored well across the board. But
that's **memorization, not analysis.** A triage system that only recognizes what
it has seen before is a lookup table. The job is the unseen binary — and there,
in-KB membership told us nothing.

---

## The decision

Findings 3 and 4 aren't just accuracy problems. They're **integrity** problems.
A system that can fabricate a nation-state attribution from a rule name, or
invent a family from a retrieved aside, is not an analyst — it's a confident
liability. And in malware triage, a wrong family name isn't a rounding error; it
sends responders down the wrong playbook.

So we made the call: **CADRE-RevAI ships LLM-only.** No retrieval in the default
path. No embedding service, no vector index, no corpus to curate and defend. The
model reasons over **what the binary actually shows** — Ghidra and IDA SQL,
capa capabilities, Malcat structure, FLOSS strings, YARA matches — and nothing
it doesn't.

We'd rather ship a system that says *"unknown — here is the evidence"* than one
that names a family the binary never exhibited.

---

## What we built instead

We took the engineering budget we would have spent on retrieval infrastructure
and put it into the things the benchmark proved actually move the needle:

- **SQL-first reverse engineering.** Ghidra and IDA populate SQLite; an agentic
  LangGraph deep dive *queries structured evidence* — functions, imports,
  strings, capabilities — instead of scraping disassembly text.
- **An honesty gate.** A run only earns `truly_green` when every stage is
  audited (`all_green`), no report fell back to a stub (`quality_green`), and
  zero tools failed.
- **Provenance on every report.** Each report is tagged with its source —
  `llm_judge` (written from evidence) or `deterministic_fallback` (a stub was
  filled in). A fabricated report can never masquerade as a grounded one. This is
  the direct productization of finding 3: we made the line between *grounded*
  and *invented* visible.

The pipeline that emerged is simpler, has fewer moving parts, and is
**evidence-grounded by construction.**

---

## How RAG comes back

Let's be clear: **we are not anti-RAG.** We are anti-*undisciplined*-RAG. The
benchmark didn't say retrieval is useless — it told us exactly what a *useful*
knowledge base would look like. Our roadmap builds precisely that.

**Gold over bulk.** No more bulk-growing corpora from scraped threat-intel and
hash dumps. We're building a **gold knowledge base** from the highest-signal
material we own: **our verified analysis reports and decompilation notes.** A
thousand correct, curated RE entries beat a million generic chunks.

**The agentic miner.** An offline agent turns **decompilation into gold chunks**
— normalized pseudo-code, call graphs, and control-flow representations of real
malware algorithms (custom RC4, DGAs, injection routines), linked to verified
symbol tables. The miner's product is *knowledge-base text*, not a verdict.

**Measured deltas, every step.** Each gold increment is embedded into our
lineage tree and **measured against held-out benchmarks** — including the hard
cases (like HiAsm) that bulk growth *could not* recover. A delta ships only if
it demonstrably beats the LLM-only baseline. **Evidence-gated, not
assumption-driven.**

**Guardrails baked in.** When retrieval returns, it returns under strict rules:
prompts segregate *primary evidence* (from the binary) from *secondary text*
(retrieved passages, rule titles), with an explicit constraint — *no family or
threat-actor attribution unless primary tool evidence supports it.* The PlugX
and APT29 failure modes are designed out, not hoped away.

RAG re-enters CADRE-RevAI the day a curated, RE-primary corpus **proves** it
makes the analysis better — and not a day before.

---

## The takeaway

If you're building LLM tooling for security — RE, detection engineering, threat
intel, DFIR — the lesson generalizes:

1. **Ground the model in primary evidence first.** Deep, structured feature
   extraction from your source systems beats a document lookup.
2. **Curate, don't accumulate.** A domain-shaped knowledge base of verified,
   high-signal content beats raw feeds and hash dumps at any scale.
3. **Enforce provenance.** Treat retrieved text and rule names as *untrusted
   reference*, never as ground truth the model can promote into a verdict.
4. **Measure, don't assume.** Evaluate on the properties that matter, on data
   the system hasn't memorized — and let the data make the architecture
   decisions.

The uncomfortable truth we ran into is that the most popular technique in
domain-LLM engineering can quietly *degrade* the thing you're trying to improve.
You only find out if you measure. We measured. Then we built accordingly.

---

*CADRE Platform & Security Architecture Research · 2026 · MIT / Apache 2.0*

*The complete empirical evaluation, configuration definitions, scoreboards,
latency figures, repeatability audit, and contamination inventory are in
[RESEARCH-ARTICLE-RAG-Malware-RE.md](RESEARCH-ARTICLE-RAG-Malware-RE.md) and
[BENCHMARK-REPORT-PUBLIC.md](BENCHMARK-REPORT-PUBLIC.md).*
