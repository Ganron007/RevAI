# Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline

{{AUTHOR_NAME}} · {{AFFILIATION}} · {{PUB_DATE}}

**Abstract.** Retrieval-Augmented Generation (RAG) is the default remedy for domain gaps in LLM systems, yet it is rarely evaluated inside a real analysis loop in which primary tool output competes directly with retrieved text. We benchmark RAG within an automated malware reverse-engineering triage pipeline — a controlled *thin spine* that runs static analysis, packages evidence, optionally retrieves, and passes the result to an LLM judge — across **16 real PE binaries**, **four vector configurations** (35,302–483,800 chunks; `bge-m3` vs `Qwen3-0.6B` embeddings), and a complete **2×2 factorial** isolating evidence *packaging* from *retrieval* (legacy vs Malcat-first lead × RAG on vs off). Three results drive the paper: (i) high-fidelity tool packaging matched or beat retrieval on hard, out-of-knowledge-base samples; (ii) a 13.7× corpus expansion did not improve labels (the corpus-scaling paradox); and (iii) retrieved passages and rule identifiers *contaminated* verdicts, emitting a false "PlugX" from a retrieved aside and a false "APT29 / Cozy Bear" from a YARA rule id — a failure that recurred even with retrieval disabled. A repeatability audit shows retrieval is deterministic while the judge over thin evidence is stochastic. On this evidence we ship the pipeline **LLM-only and evidence-grounded**, behind a provenance-aware quality gate (`truly_green`), and we specify an evidence-gated, RE-primary knowledge-base roadmap under which retrieval returns only once a curated gold corpus measurably outperforms the retrieval-free baseline.

**Keywords:** retrieval-augmented generation, malware triage, reverse engineering, large language models, grounding, hallucination, retrieval contamination, knowledge-base curation, agentic analysis, provenance, empirical benchmark

---

## 1. Introduction and motivation

Off-the-shelf LLMs routinely fail on precise security facts: without grounded evidence they hallucinate malware family names, confuse build signatures, and misattribute techniques with high confidence. The industry's standard fix is RAG — stand up a vector store, chunk your threat intelligence, retrieve at inference. It is so standard it is rarely questioned, and almost never measured inside a *true* end-to-end triage loop where a disassembler's structured output competes directly with the retrieved text.

We questioned it. We built **CADRE-RevAI**, an automated malware reverse-engineering pipeline, added RAG by the playbook, and then measured whether it actually improved the analysis. Two independent experimental axes separate *retrieval mechanics* from *prompt packaging*:

- **Axis 1 — model × corpus scale:** four vector configurations (**A, B, C, D**) varying corpus size from **35,302 to 483,800 chunks** and the embedding/reranking stack between `BAAI/bge-m3` and `Qwen3-0.6B`.
- **Axis 2 — packaging × retrieval:** a full **2×2 matrix over all 16 binaries**, crossing **legacy vs Malcat-first** lead packaging against **RAG on vs off** (configs **D, LN, MR, MN**).

```
+---------------------------------------------------------------------+
|                         EXECUTIVE TAKEAWAY                            |
|  High-fidelity static tool packaging (Malcat lead) drives triage    |
|  quality more than external retrieval. Un-shaped corpus expansion   |
|  dilutes signal, and retrieved text plus rule titles pollute the    |
|  LLM's verdicts — including with retrieval switched off.            |
+---------------------------------------------------------------------+
```

The headline findings, in order of consequence:

1. **Tool packaging dominates retrieval.** On the frozen Qwen3 × 35K stack (Axis 2, n=16), Malcat-first *without* RAG (**MN**) matched or beat Malcat *with* RAG (**MR**) on hard / out-of-KB samples (e.g. S2, S4) and beat legacy-without-RAG (**LN**) on property usefulness. In-KB samples (S6–S10) were largely ties. *Packaging quality — not RAG — drove the useful differences.*
2. **The corpus-scaling paradox.** Growing the KB 13.7× (35,302 → 483,800 chunks) with identical `bge-m3` plumbing (**A→B**) did *not* uniformly improve family/theme usefulness; on niche samples the larger corpus diluted retrieval density with generic threat-intel and encyclopedia stubs.
3. **Local embedding models form a peer race.** Swapping `bge-m3` ↔ `Qwen3-0.6B` embedders and rerankers (**A↔D**, **B↔C**) produced no reliable quality win; index *membership and content shape* dominate model brand.
4. **Contamination failure modes.** A retrieved capa passage mentioning PlugX produced a false **PlugX** verdict (pilot **E**); a YARA rule id `CADRE_APT29_CozyBear_Generic` produced a false **APT29 / Cozy Bear** (**LN**); lab rule/tool branding produced a fabricated **"Cadre / CADRE ransomware"** family — *even with RAG off*.
5. **KB membership dominates baseline scores.** Samples whose SHA was *in* the index (S6–S10) agreed across cells — that is self-hit / membership, not generalization to unseen threats.
6. **Property-graded evaluation is mandatory.** Rigid string-matching against vendor family labels fails the moment a binary is absent from the index (S2: VT ≈ Salgorea, not indexed). Grade *behavioral and structural properties* (process hollowing, RC4, MinGW) instead.

---

## 2. System architecture and the thin spine

To isolate RAG's effect we built a controlled harness, the **thin spine**: it runs the static tools, packages evidence, *optionally* runs hybrid vector retrieval, and hands the context to an LLM judge — stopping before long-running deep-dive decompilation or report synthesis. This is exactly the decision point where retrieval either helps or harms.

```
   [ Suspicious PE binary ]
              |
   +----------+----------+----------+----------+----------+
   |          |          |          |          |          |
 Malcat      capa       YARA      FLOSS    Ghidra/IDA   (static engine)
   |          |          |          |          |
   +----------+----------+----------+----------+
              |
        [ Lead packaging ]
        legacy (YARA/capa/filename)   OR   Malcat-first (structural anomalies)
              |                                     |
              |   RAG ON  (D / MR)                  |   RAG OFF (LN / MN)
              v                                     |
   [ query synth ] -> [ dense + BM25 + RRF ]        |
        -> [ optional FAISS-HNSW ] -> [ rerank ]    |
        -> top-k (<=5) hits  ----+                  |
                                 v                  v
                          +-----------------------------+
                          |   LLM judge  ->  verdict    |
                          | (verdict, conf, family/     |
                          |  theme, behavioral justif.) |
                          +-----------------------------+
```

When RAG is on, the core path is **dense + BM25 fused with RRF**, top-*k* ≤ 5; FAISS-HNSW ANN and the cross-encoder reranker are optional refinements, not required for every cell. The static engine extracts ground-truth features directly from PE headers, section entropy, disassembly, and import tables:

| Tool | Target artifacts | Role in the LLM context |
| :--- | :--- | :--- |
| **Malcat** | Section entropy, anomaly heuristics, compiler id, obfuscation flags | Primary structural signals and execution anomalies |
| **capa** | ATT&CK technique ids, capability rules, API patterns | Behavioral capability taxonomy (injection, crypto, …) |
| **YARA** | Signature matches, heuristic rule names, family triggers | Pattern matching and heuristic classification |
| **FLOSS** | Decoded stack strings, tight-loop obfuscated strings, user-agents | Embedded IOCs and commands |
| **Ghidra / IDA** | Function count, import/export tables, CFG complexity | Architecture, linkage, structural complexity |

The two lead styles are the Axis-2 lever: *legacy* leads with YARA/capa/filename text (the shape most pipelines ship), *Malcat-first* leads with structural anomalies. Everything downstream is held fixed so the matrix measures packaging and retrieval cleanly.

---

## 3. Experimental design

### 3.1 Axis 1 — model × corpus scale (legacy query)

Axis 1 fixes the query style (legacy YARA/capa/filename) and varies corpus scale against the embedding/reranking stack:

| Config | Chunks | Dense embedding | Cross-encoder reranker | Index architecture | Isolates |
| :---: | :---: | :--- | :--- | :--- | :--- |
| **A** | 35,302 | `BAAI/bge-m3` | `bge-reranker-v2-m3` | HNSW + BM25 | small corpus + bge (baseline) |
| **B** | 483,800 | `BAAI/bge-m3` | `bge-reranker-v2-m3` | FAISS-HNSW + BM25 + RRF | 13.7× expansion, fixed models |
| **C** | 483,800 | `Qwen3-Embedding-0.6B` | `Qwen3-Reranker-0.6B` | FAISS-HNSW + BM25 + RRF | model swap on 483K |
| **D** | 35,302 | `Qwen3-Embedding-0.6B` | `Qwen3-Reranker-0.6B` | Qwen3 dense, id-matched 35K | model swap on 35K (**baseline stack**) |

### 3.2 Axis 2 — packaging × retrieval (fixed stack = D)

Axis 2 freezes the vector stack at **D (Qwen3 × 35K)** and runs the full 2×2 over all 16 binaries:

```
                              RAG ON                 RAG OFF
                       +---------------------+---------------------+
   Legacy lead         |   D   (16/16)       |   LN  (16/16)       |
   (YARA/capa/file)    +---------------------+---------------------+
   Malcat lead         |   MR  (16/16)       |   MN  (16/16)       |
   (structural)        +---------------------+---------------------+
```

### 3.3 Dataset composition

The suite is **16 unique PE binaries** in four evaluation roles:

| Category | Role ids | n | Intent | Scoring lens |
| :--- | :--- | :---: | :--- | :--- |
| **Smoke** | `smoke_A_1 … smoke_C_2` | 6 | Regression / sanity set | Completion + triage usability |
| **Official** | `official_S1 … S3` | 3 | Complex obfuscated real PE (>1 MiB) | Behavioral + structural property extraction |
| **Normal** | `normal_S4 … S5` | 2 | Real malware **absent** from the index | Generalization without self-hits |
| **Corpus** | `corpus_S6 … S10` | 5 | Malware **indexed** in the KB | In-KB lookup fidelity |

### 3.4 Coverage and honest limits

Config **A** ran S1–S10 plus smoke A1/A2; smoke B1/B2/C1/C2 were carried forward from later letters, not re-run under A. Axis-2 cells **D / LN / MR / MN** are each a full **16/16**. Config **E** (Malcat-first RAG on bge×35K) is a **two-sample pilot (A2/S2 only)** — cited for contamination and property anecdotes, *not* as an n=16 peer cell. The exhaustive per-letter coverage table and the pilot→full-16 replacement map (G→LN, H→MN, F≡MR) are in the supporting data ([`BENCHMARK-REPORT-PUBLIC.md`](BENCHMARK-REPORT-PUBLIC.md)).

---

## 4. Results

### 4.1 Axis 1 — corpus scale and model swap (S1–S3)

Listed Axis-1 RAG runs returned the configured top-*k* of **5** hits.

| Slot | SHA12 | A (`bge`×35K) | B (`bge`×483K) | C (`Qwen`×483K) | D (`Qwen`×35K) | Property-graded ground truth |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S1** | `2df0d15147f7` | Unknown (VMProtect-packed trojan) | **VMProtect-packed** | **VMProtect-packed** | Unknown VMProtect-packed Trojan | **Consensus:** VMProtect packer + trojan profile correct. |
| **S2** | `39d60466fcbc` | **HiAsm** *(stochastic stub hit)* | Trojan.Win32.Agent | MSUpdaterTrojan | Packed trojan / Neshta-like | **GT:** VT ≈ Salgorea-class; *Salgorea not in index.* **B** best property read. |
| **S3** | `c8c17fe61ee1` | **FuTurAx** | **FuTurAx** | Win32/Futurax | **Futurax** | **Tie:** full consensus on FuTurAx. |

| Slot | A latency | B latency | C latency | D latency | Reading |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **S1** | 263 s | 339 s | 319 s | **258 s** | Wall-clock (2–7 min) is dominated by static tools + LLM generation, not vector search. |
| **S2** | 153 s | 247 s | 222 s | **140 s** | |
| **S3** | 126 s | 238 s | 204 s | **103 s** | |

Neither 13.7× growth nor the bge↔Qwen swap reliably improved the labels; the smaller, id-matched Qwen stack (**D**) was also the *fastest*.

### 4.2 Axis 2 — the complete 16-sample scoreboard (D / LN / MR / MN)

| Category | id | SHA12 | D (Legacy+RAG) | LN (Legacy, no RAG) | MR (Malcat+RAG) | MN (Malcat, no RAG) | Comparative utility |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Smoke | `smoke_A_1` | `d164c1d5c03a` | Trojan.Dropper (Adobe) | FlashUpdateDropper | FakeAdobeFlashDropper | FakeFlash Dropper | **Tie:** Flash dropper theme. |
| Smoke | `smoke_A_2` | `d27bc752e43c` | Win32.Neshta variant | Generic process-hollowing trojan/dropper | process_hollower | Unknown Process Hollowing Trojan/Dropper | **LN/MR/MN** recover hollowing; **D** invents Neshta. |
| Smoke | `smoke_B_1` | `36c60de86d02` | Trojan.VB.Downloader | Trojan.VB.Generic | VB6 trojan / TJprojMain | **TrojanDownloader.VB** | **MN win:** crispest downloader attribution. |
| Smoke | `smoke_B_2` | `dcd93bfb6b29` | unknown | **Cadre ransomware** *(lab rule bleed)* | Unknown UPX Borland trojan | Delphi trojan (svc + enc) | **LN fail:** invents lab-branded "Cadre ransomware". |
| Smoke | `smoke_C_1` | `fa8b270f1972` | **Kawaii-Unicorn** | *none* (verdict benign) | Kawaii-Unicorn | Unicorn | **LN miss**; MN also works RAG-off → miss is packaging, not "RAG required". |
| Smoke | `smoke_C_2` | `b73782c34103` | Unknown UPX-packed trojan | **CADRE ransomware** *(lab rule bleed)* | Generic UPX-packed | UPX-packed trojan/loader | **LN fail:** "CADRE ransomware" from lab rule/tool text. |
| Official | `official_S1` | `2df0d15147f7` | VMProtect-packed Trojan | Generic Infostealer (VMProtect) | VMProtect packed malware | VMProtect (poss. Emotet) | Packer consensus; MN adds Emotet guess. |
| Official | `official_S2` | `39d60466fcbc` | Packed trojan / Neshta | **APT29/Cozy Bear** *(rule hallucination)* | Generic trojan | **Remcos Loader** | **MN win:** Remcos loader behavior; LN suffers APT29 rule-title contamination. |
| Official | `official_S3` | `c8c17fe61ee1` | Futurax | FuTuRaX | FuTurAx | FuTuRaX | **Tie:** full family agreement. |
| Normal | `normal_S4` | `426511145595` | Generic dropper | Keylogger | None *(RAG dilution)* | **Mailslot / Delphi Trojan** | **MN win:** Delphi mailslot backdoor; MR RAG yields "None". |
| Normal | `normal_S5` | `353ddce78d58` | Go-based crypto miner | Go-based Trojan | Unknown Go dropper | Go-based trojan | **Tie:** Go runtime environment. |
| Corpus | `corpus_S6` | `91d57a66876b` | **XWorm** | **XWorm** | **XWorm** | **XWorm** | **Tie:** in-KB agreement. |
| Corpus | `corpus_S7` | `7fc9ae64edb1` | HEUR-Trojan-Ransom… | Generic ransomware | Generic Ransomware / BootLocker | Generic ransomware | **Tie-ish:** ransom theme, wording varies. |
| Corpus | `corpus_S8` | `980373db2260` | MS17-010 Exploit Loader… | **WannaCry** | MS17-010 / EternalBlue | Exploit.Win32.MS17-010 | **Theme tie:** LN names campaign, others the exploit id. |
| Corpus | `corpus_S9` | `1c2e8be7a102` | Trojan.MSIL.Kryplod | **Kryplod** | **Kryplod** | **Kryplod** | **Tie:** in-KB Kryplod. |
| Corpus | `corpus_S10` | `4b9b8edaed36` | **CoreWarrior** | Flooder.Win32.CoreWarrior | **CoreWarrior** | **CoreWarrior** | **Tie:** in-KB CoreWarrior. |

Read on the property lens (not a formal F1 ranking):

```
  Stronger ->  MN  Malcat-first, RAG off
               MR  Malcat-first, RAG on     (~ MN on in-KB; MN often better on hard/OOD)
               D   Legacy + RAG             (mixed; can invent Neshta-class names)
  Weaker   ->  LN  Legacy, RAG off          (APT29 / Cadre-ransomware contamination; C1 miss)
```

The pattern is unambiguous: where retrieval *changed* the answer, it was as often wrong as right, and the wrong direction was a confident fabrication. Malcat-first packaging carried the analysis with or without retrieval.

---

## 5. Failure modes — how context corrupts the verdict

### 5.1 Why string accuracy is the wrong metric

Rigid label matching breaks the instant a binary is out of the index. Consider **A2 (`d27bc752e43c`)** and **S2 (`39d60466fcbc`)**:

```
+-----------------------------------------------------------------------------------+
|                     SAMPLE A2 — PROPERTY-GRADED ANALYSIS                          |
+-----------------------------------------------------------------------------------+
|  Useful property target: process hollowing / injector + RC4 (+ MinGW if stated).  |
|  No crisp public family in VT/MB for this SHA.                                    |
+-----------------------------------------------------------------------------------+
|  A (freeze):   HiAsm lottery / unstable                                           |
|  B:            Virut-like                                                         |
|  C:            Generic.ProcessHollowing.Dropper                                   |
|  D (n=16):     Win32.Neshta variant          <- wrong named family                |
|  E (pilot):    Process hollowing + RC4 (MinGW) <- strongest crisp property string |
|  LN (n=16):    Generic process-hollowing trojan/dropper                           |
|  MN (n=16):    Unknown Process Hollowing Trojan/Dropper                           |
|  H (pilot):    Process Hollowing Dropper/Injector (RC4 payload)                   |
+-----------------------------------------------------------------------------------+
|  Reading: Malcat-led packaging recovers hollowing with or without RAG (MN / E/H). |
|  Do not equate MN's Axis-2 string with E's RC4/MinGW wording. D invents Neshta.   |
+-----------------------------------------------------------------------------------+
```

The right question is not "did it print the vendor string" but "did it recover the behavior that matters." On that question, packaging wins and retrieval is at best neutral.

### 5.2 RAG passage contamination — the "PlugX" effect

*Coverage: config **E** only — Malcat-first RAG on live bge×35K, **A2/S2 pilot (n=2)**.* On **S2**, Malcat extracted static anomalies; hybrid retrieval returned five capa encyclopedia passages, one of which stated that an ADD/XOR/SUB encoding scheme is *"common for PlugX, but also utilized by other malware families…"* That sentence entered the context and the judge emitted **PlugX**. The static tools never asserted PlugX; the sample was not PlugX. A retrieved *aside* became a verdict.

### 5.3 Rule-title contamination — the "APT29" / lab-brand effect

*Coverage: config **LN**, full **n=16**, RAG off, legacy lead.* On **official_S2** the prompt carried the YARA rule id `CADRE_APT29_CozyBear_Generic`; the judge emitted **APT29 / Cozy Bear** — a nation-state attribution lifted from a *rule identifier*. On the same SHA, **MN** produced Remcos Loader (still not Salgorea, but not nation-state-from-a-title). Separately, **smoke_B_2 → "Cadre ransomware"** and **smoke_C_2 → "CADRE ransomware"**: our own lab rule/tool branding promoted into a fabricated family, while MR/MN stayed in generic UPX/Delphi/trojan language. This is the crucial detail: **contamination is not only a retrieval problem** — any secondary text the model can promote into a primary claim is a hazard.

> **Prompt-hygiene imperative.** LLM judges must be instructed to treat RAG passage text and YARA rule identifiers as *untrusted reference strings*, prohibited from asserting family or actor attribution unless backed by primary binary evidence.

### 5.4 Repeatability and stochasticity

To check whether headline family strings were deterministic properties of a vector config, we ran **config A** on **A2** and **S2** three times under identical conditions:

```
+----------------------------------------------------------------------+
|                 CONFIG A — REPEATABILITY AUDIT (3 RUNS)              |
+----------------------------------------------------------------------+
|  Run | Sample A2 (Smoke)              | Sample S2 (Official)         |
+------+-------------------------------+------------------------------+
|   1  | Process Hollowing Dropper     | HiAsm (low confidence)       |
|   2  | Unknown                       | (null family)                |
|   3  | Process Hollowing (poss HiAsm)| HiAsm (crisp 0.85 score)     |
+----------------------------------------------------------------------+
|  RETRIEVAL: top-5 chunk ids + similarity scores 100% IDENTICAL x3.   |
|  JUDGE:    fluctuating family strings across the three runs.         |
+----------------------------------------------------------------------+
```

Retrieval is deterministic; judgment over thin evidence is stochastic. "Config A wins HiAsm" was an artifact of stochastic judge sampling over an ungrounded 2014 encyclopedia stub (`W32/HiAsm.A!tr`), not a stable system property. A benchmark that reports a single run of such a cell is reporting noise.

---

## 6. From findings to a product decision

Findings on contamination (§5.2–5.3) and memorization (§1.5) are not accuracy problems — they are **integrity** problems. A triage system that fabricates a nation-state attribution from a rule name, or invents a family from a retrieved aside, is a confident liability; in malware triage a wrong family name sends responders down the wrong playbook. We therefore made the call: **CADRE-RevAI ships LLM-only.** No retrieval in the default path, no embedding service, no vector index, no corpus to curate and defend. The model reasons over what the binary actually shows — Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA — and nothing it does not. We would rather ship a system that says *"unknown — here is the evidence"* than one that names a family the binary never exhibited.

The engineering budget we did *not* spend on retrieval went into what the benchmark proved moves the needle:

- **SQL-first reverse engineering.** Ghidra and IDA populate SQLite; an agentic LangGraph deep dive *queries structured evidence* (functions, imports, strings, capabilities) instead of scraping disassembly text — the packaging lever that Axis 2 showed actually matters.
- **An honesty gate.** A run earns `truly_green` only when every stage is audited (`all_green`), no report fell back to a stub (`quality_green`), and zero tools failed.
- **Provenance on every report.** Each report is tagged with its source — `llm_judge` (written from evidence) vs `deterministic_fallback` (a stub). A fabricated report can never masquerade as a grounded one. This is the direct productization of §5: we made the line between *grounded* and *invented* visible, the same line the contamination failures crossed invisibly.

---

## 7. Cross-domain lessons

The findings generalize to any security-LLM system (detection engineering, threat intel, DFIR, AppSec):

1. **Deep tool packaging beats shallow retrieval.** Invest in extracting high-fidelity structured features from primary systems (disassemblers, SIEM query APIs, cloud audit logs) before standing up a vector store. Here, clean Malcat-first packaging (**MN**) often matched or beat Malcat+RAG (**MR**) on hard/OOD samples *without* any document lookup.
2. **Curate, don't accumulate.** The "bigger vector DB = smarter triage" assumption failed on Axis 1. RE vector stores must move from generic text dumps to **RE-primary corpora** — normalized pseudo-code, verified analyst writeups, symbol-linked CFGs — not raw TI feeds and hash lists.
3. **Enforce provenance.** Segregate *primary evidence* (facts from the target) from *secondary reference text* (retrieved passages, rule titles), with explicit negative constraints against promoting the latter into a verdict.
4. **Evaluate on properties, on unseen data, over repeats.** String-match F1 against vendor labels, on in-KB samples, from a single run, measures the wrong thing three times over.

---

## 8. How retrieval comes back — an evidence-gated roadmap

We are not anti-RAG; we are anti-*undisciplined* RAG. The benchmark told us what a useful knowledge base looks like, and the roadmap (our V7 track) builds exactly that — quality over volume, measured at every step:

- **Gold over bulk.** Stop bulk-growing corpora from scraped TI and hash dumps. Build a **gold KB** from the highest-signal material we own — verified analysis reports and decompilation notes. A thousand correct, curated RE entries beat a million generic chunks.
- **The agentic miner.** An offline agent turns decompilation into gold chunks — normalized pseudo-code, call graphs, control-flow representations of real malware algorithms (custom RC4, DGAs, injection routines) linked to verified symbol tables. The miner's product is *KB text*, not a verdict.
- **Measured deltas.** Each gold increment is embedded into the lineage tree (`--mode append`) and **measured against held-out benchmarks** — including the hard cases (HiAsm) that bulk growth could not recover. A delta ships only if it demonstrably beats the LLM-only baseline. Evidence-gated, not assumption-driven.
- **Guardrails baked in.** When retrieval returns, it returns under the §5 rules: primary/secondary segregation and the no-attribution-without-primary-evidence constraint, so the PlugX and APT29 failure modes are designed out rather than hoped away.

Retrieval re-enters the product the day a curated, RE-primary corpus **proves** it improves the analysis — and not a day before.

---

## 9. Limitations and threats to validity

Credibility requires stating what this study is *not*. (i) **Scale:** n=16 binaries and a thin spine (no full deep-dive decompilation in the scored path); the Axis-2 matrix is the controlled core, Axis-1 is S1–S3 plus carried smoke cells. (ii) **Stochastic judge:** as §5.4 shows, single-run family strings over thin evidence are noisy; we report the matrix and the repeatability audit rather than a single headline number, and we grade properties rather than labels. (iii) **Pilot cells:** config **E** is n=2 (A2/S2) and is cited only for the contamination mechanism, not as a peer scoreboard cell; the RAG-off legacy cell **LN** is the full-16 evidence for rule-title contamination. (iv) **One judge model family and one KB lineage** per axis; we vary embedder/reranker and corpus scale but do not sweep judge models. (v) **Property grading is expert-judged**, not an automated F1; this is deliberate (automated label F1 is the metric we argue against) but it is a human-in-the-loop evaluation, not a fully automatic one. (vi) **In-KB agreement is not generalization** (§1.5); we treat S6–S10 ties as membership evidence, explicitly not as proof the system handles unseen threats. None of these limitations change the directional conclusions — packaging over retrieval, the scaling paradox, and the contamination modes — but they bound how far those conclusions extend.

---

## 10. Conclusions

On this knowledge base and triage path: (1) neither 13.7× corpus growth nor bge↔Qwen swaps reliably improved RE family/theme labels; (2) on the full 16-sample Axis-2 matrix, Malcat-first packaging (**MN / MR**) was more useful than legacy-without-RAG (**LN**) on several hard/OOD cases, and hybrid RAG under Malcat (**MR**) was not a systematic win over tools-only Malcat (**MN**); (3) retrieval prose can inject collateral families (PlugX, pilot E) and YARA/lab titles contaminate even with RAG off (APT29, Cadre/CADRE ransomware, LN); (4) in-KB samples largely agree across cells — membership aids recognition, not out-of-distribution generalization. The recommended posture is therefore: prioritize deep static-tool packaging; keep hybrid RAG opt-in until an RE-shaped, *measured* corpus exists; and enforce provenance so retrieved hits and rule titles can never become family verdicts without primary binary evidence. That posture is now a shipped product, not a recommendation.

---

## Data availability

The exhaustive supporting data — full configuration definitions, the SHA-12 correlation tables, per-letter coverage and the pilot→full-16 replacement map, latency figures, the repeatability audit, and the contamination case inventory (no lab filesystem paths or host identifiers) — accompanies this article as [`BENCHMARK-REPORT-PUBLIC.md`](BENCHMARK-REPORT-PUBLIC.md) and is archived at [{{ZENODO_URL}}]({{ZENODO_URL}}). The rendered tables are at [{{PAGES_URL}}benchmark.html]({{PAGES_URL}}benchmark.html).

## Code

The pipeline evaluated here is released as **CADRE-RevAI** under the MIT license: [{{CODE_URL}}]({{CODE_URL}}).

## How to cite

{{AUTHOR_NAME}} ({{PUB_DATE}}). *Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline.* CADRE Architecture & Security Research. [{{DOI}}]({{DOI}}).

## Note on scope

This is a self-archived technical note, provided as-is for citation and reference. The author is not soliciting peer review, and no comment or feedback channel is attached to this record or its archived copy.

## References

1. CADRE Architecture & Security Research (2026). *RAG for Automated Malware Triage: Empirical Evaluation of Corpus Scaling, Local Embeddings, and Retrieval Contamination* — full research article. Archived: [{{ZENODO_URL}}]({{ZENODO_URL}}).
2. CADRE Architecture & Security Research (2026). *Supporting Benchmark Report — RAG for Automated Malware Triage* (BENCHMARK-REPORT-PUBLIC). Archived: [{{ZENODO_URL}}]({{ZENODO_URL}}).
