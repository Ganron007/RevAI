# Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline

{{AUTHOR_NAME}}{{AFFILIATION_SUFFIX}} · {{PUB_DATE}}

> Self-archived technical report; not formally peer-reviewed. Reproducibility artifacts and versioned corrections live in the associated Zenodo record ({{ZENODO_URL}}) and source repository ({{CODE_URL}}).

**Abstract.** Retrieval-Augmented Generation (RAG) is a common remedy for domain gaps in LLM systems, but it is rarely evaluated inside a real analysis loop in which primary tool output competes directly with retrieved text. We benchmark RAG within an automated malware reverse-engineering (RE) triage pipeline — a controlled *thin spine* that runs static analysis, packages evidence, optionally retrieves, and passes the result to an LLM judge — across **16 real PE binaries**, **four vector configurations** (35,302–483,800 chunks; `bge-m3` vs `Qwen3-0.6B` embeddings), and a **controlled 2×2 comparison** isolating evidence *packaging* from *retrieval* (legacy vs Malcat-first lead × RAG on vs off; n = 16 per cell). On this benchmark, packaging was the stronger lever: Malcat-first packaging with RAG **off** was the only cell correct on both malicious/benign and supported-family attribution (1.00 / 1.00), with the highest property utility and analyst-usefulness scores and **zero** contamination events; adding RAG under Malcat-first packaging lowered every one of those metrics. We also identify a failure mode we term **secondary-context attribution contamination**, in which the judge promotes a named family or threat actor from untrusted secondary text — a retrieved passage (RAG on) or, notably, a YARA rule identifier with RAG **off** — producing confident, unsupported verdicts (a false *PlugX*, a false *APT29 / Cozy Bear*, and fabricated lab-brand families). A three-run repeatability audit shows retrieval stable while judge family strings vary. On this evidence we ship the pipeline **LLM-only and evidence-grounded**, behind a provenance-aware quality gate, and we specify an evidence-gated, RE-primary knowledge-base roadmap under which retrieval returns only once a curated gold corpus measurably outperforms the retrieval-free baseline.

**Keywords:** retrieval-augmented generation · malware triage · reverse engineering · large language models · grounding · hallucination · retrieval contamination · knowledge-base curation · agentic analysis · provenance · empirical benchmark

---

## 1. Introduction

Off-the-shelf LLMs routinely fail on precise security facts: without grounded evidence they hallucinate malware family names, confuse build signatures, and misattribute techniques with high confidence. A common fix is RAG — stand up a vector store, chunk domain text, retrieve at inference. It is common enough that it is rarely questioned, and rarely measured inside a *true* end-to-end triage loop where a disassembler's structured output competes directly with the retrieved text.

We questioned it. We built **CADRE-RevAI**, an automated malware RE pipeline, added RAG by the conventional playbook, and measured whether it improved the analysis. The result changed the product. This report presents the measurement in full — every cell, every contamination event, every tool version — so that the conclusion (ship LLM-only, ground in tool evidence, gate on provenance) can be checked against the data rather than taken on assertion.

### 1.1 Contributions

1. An empirical evaluation of RAG *inside* a static malware-triage tool loop, with a controlled 2×2 comparison of evidence packaging against retrieval (n = 16 per cell), reported with descriptive per-cell statistics rather than a single headline number.
2. A named and reproduced failure mode, **secondary-context attribution contamination**, with two mechanisms (retrieved passages; rule identifiers) — the second occurring with retrieval disabled.
3. A property-graded evaluation rubric and a full public evidence bundle (CC0) that regenerates every table in this report.
4. An operational consequence: a shipped LLM-only, provenance-gated pipeline, with an evidence-gated roadmap for re-introducing retrieval.

We position the contribution narrowly: evaluation inside a static triage loop; a controlled packaging × retrieval comparison; explicit rule-title contamination with retrieval off; and operational provenance controls. We do not claim a universal verdict on RAG; we report what we measured on this benchmark.

---

## 2. System and threat model

### 2.1 The thin spine

To isolate RAG's effect we evaluate a controlled harness, the *thin spine*: it runs the static tools, packages evidence, *optionally* runs hybrid vector retrieval, and hands the context to an LLM judge — stopping before long-running deep-dive decompilation or report synthesis. This is exactly the decision point where retrieval either helps or harms.

```
   [ Suspicious PE binary ]
              |
   +----------+----------+----------+----------+----------+
   |          |          |          |          |          |
 Malcat      capa       YARA      FLOSS    Ghidra / IDA  (static engine)
   |          |          |          |          |
   +----------+----------+----------+----------+
              |
        [ Lead packaging ]
        legacy (YARA / capa / filename)   OR   Malcat-first (structural anomalies)
              |                                     |
              |   RAG ON  (D / MR)                  |   RAG OFF (LN / MN)
              v                                     |
    [ query synth ] -> [ dense + BM25 + RRF ]       |
         -> [ optional FAISS-HNSW ] -> [ rerank ]   |
         -> top-k (<=5) hits  ----+                 |
                                  v                 v
                           +-----------------------------+
                           |   LLM judge  ->  verdict    |
                           | (verdict, conf, family/     |
                           |  theme, behavioral justif.) |
                           +-----------------------------+
```

When RAG is on, the retrieval path is **dense + BM25 fused with reciprocal rank fusion (RRF)**, top-*k* ≤ 5; FAISS-HNSW ANN and the cross-encoder reranker are optional refinements, not required for every cell. The static engine extracts features from PE headers, section entropy, disassembly, and import tables:

| Tool | Target artifacts | Role in the LLM context |
| :--- | :--- | :--- |
| **Malcat** | Section entropy, anomaly heuristics, compiler id, obfuscation flags | Primary structural signals and execution anomalies |
| **capa** | ATT&CK technique ids, capability rules, API patterns | Behavioral capability taxonomy (injection, crypto, …) |
| **YARA / YARA-X** | Signature matches, heuristic rule names, family triggers | Pattern matching and heuristic classification |
| **FLOSS** | Decoded stack strings, tight-loop obfuscated strings, user-agents | Embedded IOCs and commands |
| **Ghidra** / **IDA Pro** | Function count, import/export tables, CFG complexity | Architecture, linkage, structural complexity (SQL views via ghidrasql / idasql) |

The two lead styles are the packaging lever: *legacy* leads with YARA/capa/filename text (the shape most pipelines ship), *Malcat-first* leads with structural anomalies. Everything downstream is held fixed so the comparison measures packaging and retrieval cleanly.

### 2.2 Threat model and provenance

The integrity threat we study is not "the model is wrong" but "the model is *confidently* wrong in a way that an analyst would trust": a named family or threat actor asserted without binary corroboration. We therefore treat RAG passages and rule identifiers as **untrusted secondary text**, and we tag every report with its provenance (`llm_judge` vs `deterministic_fallback`) so a stubbed or contaminated report cannot masquerade as a grounded one.

---

## 3. Experimental design

### 3.1 Research questions

- **RQ1 (packaging vs retrieval):** does evidence packaging or retrieval dominate triage quality on out-of-knowledge-base samples?
- **RQ2 (corpus scaling):** does a 13.7× corpus expansion improve labels at fixed models/query?
- **RQ3 (model swap):** does swapping embedding/reranking stacks change analyst-facing quality?
- **RQ4 (contamination):** can secondary text drive unsupported attributions, and does this require retrieval?

### 3.2 Samples

Sixteen unique PE binaries in four evaluation roles. *Normal* means *out-of-knowledge-base malware*, not benign; all 16 are malicious.

| Category | Roles | n | Intent | Scoring lens |
| :--- | :--- | :---: | :--- | :--- |
| Smoke | `smoke_{A,B,C}_{1,2}` | 6 | regression / sanity | completion + triage usability |
| Official | `official_S1..S3` | 3 | complex obfuscated real PE (>1 MiB) | behavioral + structural property extraction |
| Normal | `normal_S4..S5` | 2 | real malware **absent** from the index | generalization without self-hits |
| Corpus | `corpus_S6..S10` | 5 | **indexed** in the KB | in-KB lookup fidelity |

Full SHA-256, sizes, in-KB flags, and acquisition notes are in `samples-manifest.json` (binaries are *not* redistributed; SHA-256 is the identifier).

### 3.3 Tools and versions

| Component | Version / identifier |
| :--- | :--- |
| Python | 3.12.3 |
| capa | 9.4.0 |
| FLOSS | 3.1.1 |
| YARA-X | 1.19.0 |
| Ghidra | 12.1.2 (ghidrasql) |
| IDA Pro | 9.3 (idasql; optional cross-engine bridge) |
| Malcat | 0.9.15 (commercial; external dependency, not redistributed) |
| radare2 | 5.9.0 |
| Embedding (stacks A, B) | `BAAI/bge-m3` |
| Reranker (stacks A, B) | `BAAI/bge-reranker-v2-m3` |
| Embedding (stacks C, D) | `Qwen/Qwen3-Embedding-0.6B` |
| Reranker (stacks C, D) | `Qwen/Qwen3-Reranker-0.6B` |
| Sparse / fusion | rank-bm25 (BM25Okapi) / reciprocal rank fusion |
| Dense index | FAISS (HNSW) / numpy |

### 3.4 Judge model and prompts

The judge is `deepseek-v4-pro` (the agentic planner, where used, is `deepseek-v4-flash`); reasoning effort `max`. The chat API used does not expose a deterministic seed; we therefore do not claim deterministic judging, and we characterize judge stochasticity directly with the repeatability audit (§5.5). Each thin-spine run is stateless (fresh process, fresh prompt assembly); per-stage subprocess timeouts apply; an unparseable judge response falls back to a deterministic stub tagged `deterministic_fallback` (the `source` field on every report records which path produced it). The system prompt segregates primary evidence from secondary reference text and forbids family/actor attribution unsupported by primary tool evidence; the user prompt carries the lead-packaged evidence and, when RAG is on, the top-*k* passages. (Exact templates and their hashes are in the reproducibility bundle.)

### 3.5 Corpus and index configurations

| Config | Chunks | Embed / rerank | Index | Isolates |
| :---: | :---: | :--- | :--- | :--- |
| **A** | 35,302 | bge-m3 / bge-reranker-v2-m3 | HNSW + BM25 | small corpus + bge |
| **B** | 483,800 | bge-m3 / bge-reranker-v2-m3 | FAISS-HNSW + BM25 + RRF | 13.7× expansion at fixed models |
| **C** | 483,800 | Qwen3-0.6B / Qwen3-Reranker-0.6B | FAISS-HNSW + BM25 + RRF | model swap at 483K |
| **D** | 35,302 | Qwen3-0.6B / Qwen3-Reranker-0.6B | Qwen3 dense (id-matched 35K) | model swap at 35K (baseline stack) |

The 35,302 figure is the `dense_rows` of the stabilized 35K manifest (corroborated); 483,800 is the published large-corpus figure. Top-*k* = 5; query mode is lead-tag construction (legacy vs Malcat-first).

> **Disclosed confound (corpus scaling).** Axis-1 A→B is presented as a corpus-size contrast at fixed embedding/reranking models and query style; however the index backend differs (A: HNSW+BM25 vs B: FAISS-HNSW+BM25+RRF). We disclose this backend change as a confound: the corpus-size effect is not isolated from the index-backend change, so RQ2 is answered descriptively, not causally.
>
> **Controlled comparison, not factorial ANOVA.** Axis 2 is a controlled 2×2 comparison (lead × retrieval). We report per-cell descriptive statistics; we do not estimate formal main/interaction effects or claim statistical significance at n = 16.

Axis 2 holds the stack at **D** and runs the full 2×2 over all 16 binaries:

```
                              RAG ON              RAG OFF
                       +---------------------+---------------------+
   Legacy lead         |   D   (16/16)       |   LN  (16/16)       |
   (YARA/capa/file)    +---------------------+---------------------+
   Malcat lead         |   MR  (16/16)       |   MN  (16/16)       |
   (structural)        +---------------------+---------------------+
```

### 3.6 Evaluation rubric

We grade behavioral/structural *properties* a human analyst would use, not vendor-family-string F1 (undefined for out-of-KB samples). Per cell, per sample we record: malicious/benign correctness (`mal`, derived from the recorded verdict, not re-judged); supported-family attribution (`sup`); unsupported/invented named family (`unsup`, penalized); secondary-context contamination (`contam`, penalized, severity in §6); property utility (`prop`, 0–3); analyst usefulness (`use`, 1–5). Abstaining from a *name* while reporting the *behavior* is rewarded; abstaining to *benign* on a malicious sample is a `mal` error. The full rubric, worked examples, and the single-author grading disclosure are in `grading-rubric.md`; the 64 graded rows (16 roles × 4 cells) are in `grading-records.csv`.

---

## 4. Results

### 4.1 Axis 1 — corpus scale and model swap (S1–S3)

| Slot | SHA12 | A (bge×35K) | B (bge×483K) | C (Qwen×483K) | D (Qwen×35K) | Property-graded reading |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| S1 | `2df0d15147f7` | Unknown (VMProtect-packed trojan) | **VMProtect-packed** | **VMProtect-packed** | Unknown VMProtect-packed Trojan | Consensus on VMProtect + trojan profile |
| S2 | `39d60466fcbc` | **HiAsm** *(stochastic stub hit)* | Trojan.Win32.Agent | MSUpdaterTrojan | Packed trojan / Neshta-like | GT ≈ Salgorea-class (not indexed); B best property read |
| S3 | `c8c17fe61ee1` | **FuTurAx** | **FuTurAx** | Win32/Futurax | **Futurax** | Full consensus on FuTurAx |

| Slot | A | B | C | D | Reading |
| :---: | :---: | :---: | :---: | :---: | :--- |
| S1 | 263 s | 339 s | 319 s | **258 s** | Wall-clock (2–7 min) dominated by static tools + LLM generation, not vector search |
| S2 | 153 s | 247 s | 222 s | **140 s** | |
| S3 | 126 s | 238 s | 204 s | **103 s** | |

Neither the 13.7× expansion nor the bge↔Qwen swap reliably improved the labels; the smaller id-matched Qwen stack (D) was also fastest. We observed a corpus-scaling *failure* in this corpus (niche labels did not improve and could dilute); we do not claim this as a universal law.

### 4.2 Axis 2 — controlled 2×2, quantitative summary (n = 16 per cell)

| Cell | Lead | RAG | mal | supported | unsupported | contam | prop | use | abst |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **D** | legacy | on | 1.00 | 0.81 | 0.12 | 0 | 2.06 | 3.31 | 0.06 |
| **LN** | legacy | off | 0.94 | 0.75 | 0.19 | **3** | 1.75 | 3.00 | 0.00 |
| **MR** | malcat | on | 0.94 | 0.94 | 0.00 | 0 | 2.12 | 3.38 | 0.00 |
| **MN** | malcat | off | **1.00** | **1.00** | **0.00** | **0** | **2.62** | **4.19** | **0.00** |

Read row-wise: packaging dominates. Malcat-first cells (MR, MN) have **zero** unsupported families versus legacy cells (D 0.12, LN 0.19); supported-family and usefulness rise monotonically from LN → D → MR → MN. Read column-wise within a packaging: under Malcat-first, turning RAG **off** (MN) improves *every* metric over RAG **on** (MR) — retrieval hurt. Under legacy, RAG on (D) slightly raises supported-family and mal-correct but still leaves unsupported families, while RAG off (LN) carries all three contamination events. The contamination events — the headline of this report — are a *legacy-lead / rule-title* phenomenon that occurs **without retrieval**.

### 4.3 Axis 2 — full 16-sample scoreboard (D / LN / MR / MN)

| Cat | id | SHA12 | D (legacy+RAG) | LN (legacy, off) | MR (malcat+RAG) | MN (malcat, off) | Reading |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Smoke | A_1 | `d164c1d5c03a` | Trojan.Dropper (Adobe) | FlashUpdateDropper | FakeAdobeFlashDropper | FakeFlash Dropper | Tie: Flash dropper theme |
| Smoke | A_2 | `d27bc752e43c` | Win32.Neshta variant | Generic process-hollowing trojan/dropper | process_hollower | Unknown Process Hollowing Trojan/Dropper | LN/MR/MN recover hollowing; D invents Neshta |
| Smoke | B_1 | `36c60de86d02` | Trojan.VB.Downloader | Trojan.VB.Generic | VB6 trojan / TJprojMain | **TrojanDownloader.VB** | MN crispest |
| Smoke | B_2 | `dcd93bfb6b29` | unknown | **Cadre ransomware** *(rule bleed)* | Unknown UPX Borland trojan | Delphi trojan (svc + enc) | LN invents lab brand |
| Smoke | C_1 | `fa8b270f1972` | **Kawaii-Unicorn** | *none (benign)* | Kawaii-Unicorn | Unicorn | LN miss; MN works RAG-off |
| Smoke | C_2 | `b73782c34103` | Unknown UPX-packed trojan | **CADRE ransomware** *(rule bleed)* | Generic UPX-packed | UPX-packed trojan/loader | LN invents lab brand |
| Official | S1 | `2df0d15147f7` | VMProtect-packed Trojan | Generic Infostealer (VMProtect) | VMProtect packed malware | VMProtect (poss. Emotet) | Packer consensus |
| Official | S2 | `39d60466fcbc` | Packed trojan / Neshta | **APT29/Cozy Bear** *(rule id)* | Generic trojan | **Remcos Loader** | LN rule-title contamination; MN behavioral |
| Official | S3 | `c8c17fe61ee1` | Futurax | FuTuRaX | FuTurAx | FuTuRaX | Full agreement |
| Normal | S4 | `426511145595` | Generic dropper | Keylogger | None *(dilution)* | **Mailslot / Delphi Trojan** | MN best; MR RAG yields None |
| Normal | S5 | `353ddce78d58` | Go-based crypto miner | Go-based Trojan | Unknown Go dropper | Go-based trojan | Tie: Go runtime |
| Corpus | S6 | `91d57a66876b` | **XWorm** | **XWorm** | **XWorm** | **XWorm** | Tie (in-KB) |
| Corpus | S7 | `7fc9ae64edb1` | HEUR-Trojan-Ransom… | Generic ransomware | Generic Ransomware / BootLocker | Generic ransomware | Tie-ish |
| Corpus | S8 | `980373db2260` | MS17-010 Exploit Loader… | **WannaCry** | MS17-010 / EternalBlue | Exploit.Win32.MS17-010 | Theme tie |
| Corpus | S9 | `1c2e8be7a102` | Trojan.MSIL.Kryplod | **Kryplod** | **Kryplod** | **Kryplod** | Tie (in-KB) |
| Corpus | S10 | `4b9b8edaed36` | **CoreWarrior** | Flooder.Win32.CoreWarrior | **CoreWarrior** | **CoreWarrior** | Tie (in-KB) |

### 4.4 In-KB versus out-of-KB (controlled)

| KB | Cell | n | mal | supported |
| :---: | :---: | :---: | :---: | :---: |
| in-KB | D / LN / MR / MN | 5 each | 1.00 | 1.00 |
| out-of-KB | **MN** | 11 | **1.00** | **1.00** |
| out-of-KB | MR | 11 | 0.91 | 1.00 |
| out-of-KB | D | 11 | 1.00 | 0.91 |
| out-of-KB | LN | 11 | 0.91 | 1.00 |

In-KB agreement is uniform (membership / self-hit, not generalization). Out-of-KB — the real test — only **MN** is correct on *both* dimensions; each RAG cell (MR, D) drops one dimension, and LN drops mal-correct. This is the cleanest single statement of RQ1: on unseen samples, Malcat-first packaging without retrieval was the strongest configuration we measured.

### 4.5 Latency and repeatability

Median wall-clock per cell (controlled): D 156 s, LN 103 s, MR 128 s, MN 124 s — retrieval adds latency without adding quality. Repeatability (Config A, three-plus runs per role): `smoke_A_2` produced **4 distinct** family strings across 4 runs (`HiAsm` / `Process Hollowing Dropper` / `unknown` / `Process hollowing dropper (possibly HiAsm variant)`); `official_S2` produced **3 distinct** across 4 runs (`HiAsm` / `HiAsm (low confidence)` / `None` / `HiAsm`). Retrieval ids/scores were identical across these runs; the judge family strings varied. So retrieval was stable across this tested audit, while judging over thin evidence was not — a "Config A wins HiAsm" reading is a stochastic artifact over an ungrounded encyclopedia stub, not a stable system property.

---

## 5. Contamination case studies

We term the failure mode **secondary-context attribution contamination**: the judge promotes a named entity from untrusted secondary text into a primary family/actor claim. Two mechanisms:

```
   secondary text  ->  enters prompt context  ->  unsupported named entity  ->  verdict
   (retrieved passage | rule identifier | lab-brand tag)        (family / threat actor)
```

Redacted causal excerpts are in `contamination-cases/`.

- **PlugX (config E, RAG on, 5 hits).** Malcat/capa reported generic features (XOR encoding, MurmurHash, stackstrings, service creation); the retrieved/encyclopedia context attached a PlugX association to each ("…a common obfuscation method used in PlugX…", "…a hallmark of PlugX…"), and the judge emitted family = **PlugX** with no binary-specific PlugX signature. *Severity: family.*
- **APT29 / Cozy Bear (config LN, RAG off, 0 hits).** The legacy lead tag set included the rule identifier `CADRE_APT29_CozyBear_Generic`; the judge emitted **APT29 / Cozy Bear** from the rule id. On the same SHA, MN emitted *Remcos Loader* — a behavioral read with no actor promotion. *Severity: threat actor (maximum — a false nation-state attribution is an incident-response hazard, not just a label error).* This case proves contamination does **not** require retrieval.
- **Cadre / CADRE ransomware (config LN, RAG off).** Legacy lead tags included lab rules (`CADRE_Ransomware_Generic_Packer` and a `CADRE_Ransomware_*` tag); the judge emitted fabricated **Cadre / CADRE ransomware** families. MR/MN stayed generic. *Severity: family; instructive because it is the lab's own branding contaminating its own output.*

The pattern across §4.2: Malcat-first packaging (MR, MN) shows **zero** contamination and **zero** unsupported families in the controlled set, while legacy packaging (D, LN) shows both. Packaging is therefore a provenance control as well as a quality lever.

---

## 6. Product implications

The benchmark maps directly to a shipped decision. **CADRE-RevAI ships LLM-only**: no retrieval in the default decision path, no embedding service, no vector index, no corpus to curate and defend. ("LLM-only" means no *external retrieval layer* in the default path — the model still receives Malcat, capa, FLOSS, YARA, and Ghidra/IDA-derived evidence.) We invest the retrieval budget in what the benchmark showed moves the needle:

1. **SQL-first RE.** Ghidra and IDA populate SQLite; an agentic LangGraph deep dive queries structured evidence instead of scraping disassembly text — the packaging lever that §4 shows matters.
2. **A provenance-aware quality gate (`truly_green`).** A run earns `truly_green` only when every stage is audited (`all_green`), no report used a deterministic fallback (`quality_green`), and no tool failed; every report carries its `source`. *Scope note:* in the current release the orchestrator path enforces `truly_green`; the deterministic single-mode spine (`pipeline_single.py`) currently treats success approximately as `all_green`. We scope this report's "evidence-grounded" claim to the orchestrator path; closing that gap product-wide is tracked as a release item (V6.5.3).
3. **Source tagging as a productization of §5.** The line between *grounded* and *invented* is made visible: a stubbed or contaminated report cannot look green.

### 6.1 How retrieval comes back — an evidence-gated roadmap

We are not anti-RAG; we are anti-*undisciplined* RAG. Retrieval returns only when a curated, **RE-primary gold knowledge base** (our own verified reports and decompilation notes, mined offline into normalized pseudo-code / call-graph / control-flow chunks) **measurably** beats the LLM-only baseline on held-out benchmarks — including the hard cases bulk growth could not recover — and only under the provenance guardrails of §2.2, so the §5 failure modes are designed out rather than hoped away. Evidence-gated, not assumption-driven.

---

## 7. Threats to validity

(i) **Scale:** n = 16 binaries and a thin spine (no full deep-dive decompilation in the scored path); Axis 1 has uneven/carry coverage (exact matrix in the appendix), Axis 2 is the controlled core. (ii) **Stochastic judge:** single-run family strings over thin evidence are noisy (§4.5); we report matrices and the repeatability audit, and grade properties rather than labels. (iii) **Pilot cells:** config E is n = 2 and is cited only for the contamination mechanism, not as a peer scoreboard cell; the RAG-off legacy cell LN is the full-16 evidence for rule-title contamination. (iv) **Backend confound:** the corpus-scaling contrast is not isolated from the index-backend change (§3.5). (v) **Property grading is expert-judged**, not an automated F1 — deliberate, but a human-in-the-loop evaluation. (vi) **In-KB agreement is not generalization** (§4.4). (vii) **Single-author grading and author-built system:** the grader also built the system under test; this is an evaluation bias. No second reviewer was available, so per the minimum-acceptable path we publish the rubric, every graded output, and the raw result records, and we avoid absolute wording ("unambiguous", "dominates") in favor of the sample-bounded, descriptive statements above. Inter-rater agreement is therefore not reported (one grader); the reproducibility substitute is full publication of inputs, rubric, and graded outputs so an independent reader can re-grade. None of these limitations change the directional conclusions — packaging over retrieval, the observed corpus-scaling failure, and the contamination modes — but they bound how far those conclusions extend.

---

## 8. Ethics and safety

Analysis in the scored thin spine was **static**; samples were not detonated in the scored path. Malware binaries are **not** redistributed in this publication pack; samples are identified by cryptographic SHA-256 and, where applicable, lawful public references. The study was performed in an isolated lab; no human-subject research was performed and IRB review was not applicable. Malware-analysis automation is dual-use, but the released artifacts contain evaluation data and defensive analysis, not deployable malware. Finally, **false threat-actor attribution is itself a safety and incident-response risk** — the §5 APT29 case is precisely the kind of error that, if trusted, misroutes a response; this is a central motivation for the provenance gate.

---

## 9. Reproducibility and data availability

A sanitized, self-contained public evidence bundle (license **CC0** for the data; the article text **CC BY 4.0**; the pipeline code **MIT**) accompanies this report:

- `benchmark-results.jsonl` / `.csv` — 127 thin-spine runs (every cell of A/B/C/D/LN/MR/MN plus pilots and repeatability reruns).
- `controlled_aggregate.csv` / `controlled_inkb_oob.csv` — the §4.2 / §4.4 tables, regenerated from the JSONL.
- `axis1-scoreboard.csv` / `axis2-scoreboard.csv` / `repeatability.csv` — §4.1 / §4.3 / §4.5, regenerated.
- `grading-records.csv` + `grading-rubric.md` — the 64 graded rows and the rubric.
- `samples-manifest.json` / `config-manifest.json` / `software-environment.json` — roster, retrieval configs (with disclosed confounds), tool/model environment.
- `contamination-cases/` — redacted causal excerpts.
- `scripts/aggregate_results.py` + `scripts/validate_public_pack.py` — regenerate every table and validate row counts, cell coverage, SHA membership, and a secret scan (PASS, 0 warnings).
- `SHA256SUMS` — checksums of every file above.

Three reproduction levels, stated honestly: **(1) evidence verification** — fully available here (run the validator, then the aggregator); **(2) pipeline reproduction** — acquire the 16 samples by SHA-256, install the tools in `software-environment.json`, run the thin spine (CADRE-RevAI, MIT); **(3) exact retrieval reproduction** — rebuild the 35K/483K indexes with the stacks in `config-manifest.json`, constrained by corpus redistribution and proprietary tooling (Malcat, IDA Pro) — constraints documented, not hidden. No malware binary, private vector index, secret, or unsanitized prompt is included.

---

## 10. Conclusions

On this benchmark and triage path: (1) packaging was the stronger lever than retrieval, and Malcat-first with RAG off was the strongest configuration we measured on out-of-KB samples; (2) a 13.7× corpus expansion and a bge↔Qwen swap did not reliably improve labels; (3) secondary text — retrieved passages and, with retrieval off, rule identifiers and lab-brand tags — drove confident, unsupported attributions (PlugX, APT29/Cozy Bear, Cadre/CADRE ransomware); (4) in-KB agreement reflects membership, not generalization; (5) retrieval was stable across the tested repeatability audit while judge family strings varied. The recommended posture — deep static-tool packaging; retrieval opt-in only until a measured, RE-primary corpus exists; provenance guardrails so retrieved text and rule titles cannot become family verdicts without primary binary evidence — is now a shipped pipeline, scoped as noted in §6, not merely a recommendation.

---

## References

*This report cites only its own measured data and supporting record; it does not include an external reference list (an authorial choice for this self-archived technical report). The supporting record:*

- **[S1]** *Supporting Benchmark Report — RAG for Automated Malware Triage* (`BENCHMARK-REPORT-PUBLIC.md`) — the public data appendix; deposited as a **supplement** to this record at {{ZENODO_URL}}, not as an independent source.
- **[S2]** *On RAG: Why CADRE-RevAI Ships LLM-Only — and How Retrieval Comes Back* (`ON-RAG-WHY-REMOVED-AND-FUTURE.md`) — the one-page product-position companion ({{CODE_URL}}).
- **[S3]** *CADRE-RevAI* source release — the evaluated thin-spine pipeline, MIT license ({{CODE_URL}}).

---

## Appendix — data-record map

| Article element | Public record |
| :--- | :--- |
| §3.2 samples | `samples-manifest.json` |
| §3.3 tools/versions, §3.4 judge | `software-environment.json` |
| §3.5 configs + confounds | `config-manifest.json` |
| §3.6 rubric + grading | `grading-rubric.md`, `grading-records.csv` |
| §4.1 Axis-1 scoreboard/latency | `axis1-scoreboard.csv` |
| §4.2 controlled 2×2 | `controlled_aggregate.csv`, `axis2-scoreboard.csv` |
| §4.4 in-KB / out-of-KB | `controlled_inkb_oob.csv` |
| §4.5 repeatability | `repeatability.csv` |
| §5 contamination | `contamination-cases/<id>/{excerpt.md,record.json}` |
| all rows | `benchmark-results.jsonl` / `.csv`; checksums `SHA256SUMS` |
