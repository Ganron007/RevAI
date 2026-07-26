# On RAG — why CADRE-RevAI ships LLM-only, and how retrieval comes back

This folder holds the evidence and the narrative behind a deliberate design
decision: CADRE-RevAI ships **LLM-only** (no retrieval in the default path),
and re-introduces RAG only when a curated, **measured** RE-primary knowledge
base proves it improves accuracy.

## Read order

| Doc | What it is |
| :--- | :--- |
| [`ON-RAG-WHY-REMOVED-AND-FUTURE.md`](ON-RAG-WHY-REMOVED-AND-FUTURE.md) | **The product position** — why we ship LLM-only + the RE-primary gold-KB roadmap. Start here. |
| [`ARTICLE-PUBLICATION.md`](ARTICLE-PUBLICATION.md) | **The canonical, citable article (data-rich).** Thin-spine architecture, the Axis-1 / Axis-2 design, the full 16-sample scoreboard, the controlled 2×2 aggregates, latency, the PlugX / APT29 contamination case studies, the repeatability audit, the LLM-only decision, methods, threats-to-validity, ethics, and reproducibility. Cites only its own measured data (no external reference list, by authorial choice). |
| [`RESEARCH-ARTICLE-RAG-Malware-RE.md`](RESEARCH-ARTICLE-RAG-Malware-RE.md) | **Superseded v1 research narrative** (retained for provenance; banner inside). Do not cite; cite `ARTICLE-PUBLICATION.md`. |
| [`BENCHMARK-REPORT-PUBLIC.md`](BENCHMARK-REPORT-PUBLIC.md) | **Supporting data** — scoreboards, latency, repeatability audit, contamination inventory. |

## The short version

We measured RAG inside a real end-to-end malware triage loop. Tool evidence
packaging drove quality more than retrieval; 13.7× corpus growth didn't help
(volume ≠ quality); and retrieved text and rule titles *contaminated* verdicts
(the "PlugX" and "APT29" effects). So the model reasons over **what the binary
actually shows** — Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA — behind a
`truly_green` honesty gate with per-report source tagging. RAG returns only when
a curated gold corpus (built from our own verified analyses) **measurably**
beats the LLM-only baseline. Evidence-gated, not assumed.
