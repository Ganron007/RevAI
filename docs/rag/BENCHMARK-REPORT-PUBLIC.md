# Supporting Benchmark Report — RAG for Automated Malware Triage

**Companion (canonical) article:** [`ARTICLE-PUBLICATION.md`](ARTICLE-PUBLICATION.md) — *Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline.* This file is its public data appendix / supplement.
**Study dates:** 2026-07-21 (Axis 1 A–D + Axis 2 MR/MN) · 2026-07-22 (naming lock + LN ×16)  
**Status:** Axis 1 **A/B/C/D complete**. Axis 2 on stack D: **D / LN / MR / MN each 16/16**.

This is the **public supporting data pack**: same experimental results as the lab benchmark record, with hostnames, filesystem paths, deployment scripts, and internal ops notes removed. Narrative interpretation: research article. Numbers and configuration definitions: this file.

---

## 0. Naming convention

Two **independent** study axes. Letters are not ten equal products.

### Axis 1 — Model × corpus size (legacy RAG query)

Fixed query style: YARA / capa / filename. Varies **embedder** and **chunk count**.

| Letter | Chunks | Embed / rerank | Meaning |
|--------|-------:|----------------|---------|
| **A** | 35,302 | bge-m3 + bge-reranker-v2-m3 | Small corpus + bge |
| **B** | 483,800 | bge-m3 pair | Large corpus + bge |
| **C** | 483,800 | Qwen3-Embedding-0.6B + Qwen3-Reranker-0.6B | Large corpus + Qwen |
| **D** | 35,302 | Qwen3-0.6B pair | Small corpus + Qwen (same text/ids as A) |

**Finding (Axis 1):** Growing corpus or swapping bge↔Qwen did **not** reliably improve family/theme usefulness. Index **membership** and **content shape** dominate.

### Axis 2 — Tool lead × RAG on/off (fixed stack = **D**)

| Letter | Lead / query | RAG | Status | Notes |
|--------|--------------|-----|--------|-------|
| **D** | Legacy (YARA/capa/filename) | **ON** | ✓ 16/16 | Also Axis-1 cell |
| **LN** | Legacy | **OFF** | ✓ 16/16 | Full-16 replacement of pilot **G** |
| **MR** | Malcat-first | **ON** | ✓ 16/16 | Canonical Malcat + RAG (**F ≡ MR**) |
| **MN** | Malcat-first | **OFF** | ✓ 16/16 | Full-16 replacement of pilot **H** |

```
                    RAG ON              RAG OFF
Legacy lead         D  ✓16              LN ✓16   ← replaced G (2-sample pilot)
Malcat lead         MR ✓16              MN ✓16   ← replaced H (2-sample pilot)
```

### Replacement map (pilots → full 16 on stack D)

| Old letter | Old coverage | Replaced by | New coverage | Same meaning |
|------------|--------------|-------------|--------------|--------------|
| **G** | A2+S2 only (stack A, bge) | **LN** | full 16 (stack D, Qwen×35K) | Legacy lead + RAG **OFF** |
| **H** | A2+S2 only (stack A, bge) | **MN** | full 16 (stack D, Qwen×35K) | Malcat lead + RAG **OFF** |
| **F** | never a separate 16-run | **MR** | full 16 (stack D) | Malcat lead + RAG **ON** (alias) |

### Pilot / alias letters (not main scoreboard cells)

| Letter | Truth |
|--------|--------|
| **F** | ≡ **MR**. Not a separate study. |
| **E** | Malcat+RAG on stack **A** (bge×35K). **Pilot only: A2+S2.** Optional contamination / property anecdote. |
| **G** | Replaced by **LN**. Historical A2+S2 only. |
| **H** | Replaced by **MN**. Historical A2+S2 only. |

**Article scoreboard cells:** **A/B/C/D** (Axis 1) and **D/LN/MR/MN** (Axis 2).

### Coverage accuracy

| Config | What was run | Honest limit |
|--------|--------------|--------------|
| **A** | S1–S10 + smoke A1/A2; A2/S2 ×3 stability | Smoke B1/B2/C1/C2 **not** under letter A (carry design) |
| **B** | S1–S10 + smoke A1/A2/B1/B2 | Full Axis-1 scoreboard |
| **C** | S1–S10 + full smoke sextet | Full Axis-1 |
| **D** | **16/16** (6 smoke + S1–S10) | Full |
| **LN** | **16/16** on stack D | Replaces G; all RAG off (`hits=0`) |
| **MR** | **16/16** on stack D | Full Axis-2 Malcat+RAG |
| **MN** | **16/16** on stack D | Replaces H |
| **E / G / H** | A2+S2 only | Pilots — not n=16 |
| **F** | Not a separate run | Alias of MR |

---

## 1. Question under test

Does changing **corpus size** and/or **local embed+rerank models** improve reverse-engineering triage quality on a static thin triage path?

```
ingest → static tools → optional hybrid RAG → LLM verdict → STOP
(before deep-dive decompilation / full report publish)
```

Out of scope for this phase: pure IR metrics (nDCG, Recall@k) as primary score; full deep-dive spine; commercial API embedders.

---

## 2. Configurations

| Config | Corpus | Embed | Reranker | Role |
|--------|-------:|-------|----------|------|
| **A** | 35,302 | `BAAI/bge-m3` | `BAAI/bge-reranker-v2-m3` | Axis 1 |
| **B** | 483,800 | bge-m3 pair | same | Axis 1 |
| **C** | 483,800 | `Qwen/Qwen3-Embedding-0.6B` | `Qwen/Qwen3-Reranker-0.6B` | Axis 1 |
| **D** | 35,302 | Qwen3-0.6B pair | same | Axis 1 **and** Axis-2 legacy+RAG |
| **MR** (≡**F**) | stack D | Qwen3 pair | same | Axis 2 Malcat+RAG |
| **MN** | stack D | — (no retrieve) | — | Axis 2 Malcat+no-RAG |
| **LN** | stack D | — (no retrieve) | — | Axis 2 legacy+no-RAG |
| **E** | stack A | bge pair | same | Pilot A2/S2 only |
| **G** | stack A (hist.) | — | — | Pilot → replaced by LN |
| **H** | stack A (hist.) | — | — | Pilot → replaced by MN |

**Isolated contrasts**

| Contrast | Holds fixed | Varies |
|----------|-------------|--------|
| A vs B | bge | corpus 35K → 483K |
| B vs C | 483K text | bge → Qwen3 |
| A vs D | 35K text/ids | bge → Qwen3 |
| C vs D | Qwen3 | 483K → 35K |
| D vs LN | stack D, legacy lead | RAG on vs off |
| MR vs MN | stack D, Malcat lead | RAG on vs off |
| D vs MR | stack D, RAG on | legacy query vs Malcat query |
| LN vs MN | stack D, RAG off | legacy lead vs Malcat lead |

**When RAG is on:** dense + BM25 + RRF hybrid retrieval; optional FAISS HNSW ANN; optional cross-encoder rerank; top-*k* ≤ 5. Served from a local GPU embedding/rerank service. **LN / MN / G / H** do not call the embedder.

---

## 3. Metrics

### 3.1 Primary (RE quality)

| Metric | Definition |
|--------|------------|
| **Family usefulness** | Is the family/theme string actionable (crisp family / packer / exploit vs vague “unknown”)? |
| **Verdict usefulness** | malicious / suspicious / benign + confidence coherence |
| **RAG-backed evidence** | Prompt contains nonempty retrieval hits / context when RAG is on |
| **LLM judge (not fallback)** | Judge source is the LLM path, not a hard-coded fallback |
| **Run validity gate** | Verdict present ∧ (RAG pack OK if RAG on) ∧ LLM judge OK; for RAG-off cells: hits=0 and judge OK |
| **Score** | Model confidence (scale sometimes 0–1 vs 0–100 — treat as ordinal within a pack) |

### 3.2 Supporting

| Metric | Notes |
|--------|-------|
| Hit count | Almost always **5** when RAG on — budget ceiling, weak discriminator alone |
| End-to-end elapsed | Dominated by tools + LLM; not pure embed latency |
| Self-hit on KB samples | For corpus S6–S10: does retrieval surface same-SHA bazaar lineage? (qualitative; strong on large-corpus batches) |

### 3.3 Out of scope

- Pure IR metrics (nDCG, Recall@k) as primary  
- Cost / VRAM beyond “fits 8 GB one model family at a time”  
- Full deep-dive / publish spine  

---

## 4. Sample design

### 4.0 Category meanings

These labels are **benchmark roles**, not malware taxonomy.

| Category | Role IDs | Count | Plain meaning | Scoring lens |
|----------|----------|------:|---------------|--------------|
| **Smoke** | `smoke_A_1`…`smoke_C_2` | 6 | Sanity / regression. Letter in the name = which Axis-1 config *introduced* them (A→B→C carry). Same 6 PE on D/MR/MN/LN. | Pipeline finishes + usable triage; family secondary |
| **Official** | `official_S1`…`S3` | 3 | Hard PE (>1 MiB), same SHA across A/B/C/D. Packed / ambiguous (S2 VT≈Salgorea). | Prefer **behavior/properties**; string match unfair if name ∉ index |
| **Normal** | `normal_S4`…`S5` | 2 | Real samples under folders that *look* like families (Kelihos, Lumma) but SHA **not** in RAG bazaar index | Path name ≠ ground truth; OOD without self-hit |
| **Corpus** | `corpus_S6`…`S10` | 5 | MalwareBazaar samples whose SHA **is** in the indexed KB | In-KB membership / self-hit class |

**Naming traps**

1. **“Corpus” category ≠ corpus size (35K/483K).**  
2. A folder named like a family does **not** make a sample “true corpus” — only index membership does (S4/S5 = normal; S6–S10 = corpus).  
3. **`smoke_A_1` is not “Config A only”** on stack D.  
4. **S1–S10** = 10 scoreboard slots; **full 16** = those + 6 smoke.

| Bucket | Unique PEs | Rule |
|--------|----------:|------|
| Smoke | 6 | A:2 → B:4 (carry A) → C:6 (carry A+B); **D:6** full sextet |
| Official S1–S3 | 3 | Same 3 PE × A/B/C/**D** |
| Normal S4–S5 | 2 | Not in large KB; B/C/**D** |
| True corpus S6–S10 | 5 | SHA in KB bazaar lineage; B/C/**D** |
| **A unique** | **5** | S1–S3 + smoke A1/A2 |
| **B↔C unique** | **10** | S1–S10 same SHA |
| **D unique** | **16** | full 6 smoke + 10 scoreboard |

Trusted result packs: 35 (A/B/C) + **16 (D)** metric summaries (smoke/official/normal/corpus trees; bge vs qwen packs never mixed).

---

## 5. Results tables

Listed runs completed the validity gate unless noted. When RAG was on, hit count was typically **5**.

### 5.1 Official scoreboard (S1–S3) — A / B / C / D (+ E on S2 only)

| Slot | SHA12 | A family | B family | C family | D family (Qwen×35K) | **E (Malcat RAG)** | Better? (property lens) |
|------|-------|----------|----------|----------|---------------------|--------------------|-------------------------|
| S1 | `2df0d15147f7` | unknown (VMProtect-packed trojan) · 0.85 | **VMProtect-packed** · 85 | **VMProtect-packed** · 85 | Unknown, VMProtect-packed Trojan… · 95 | — | B/C/D wording ≈; packer theme OK |
| S2 | `39d60466fcbc` | **HiAsm** · 85 | Trojan.Win32.Agent · 0.95 | MSUpdaterTrojan · high | packed trojan/service installer (possible Neshta) · 0.9 | **PlugX** · 0.92 | Freeze “A wins HiAsm” was **wrong target**. VT≈Salgorea **not in index**. E = RAG capa-prose contamination (§5.5.3). Best fair grade among A–D ≈ **B** (generic trojan/service properties). |
| S3 | `c8c17fe61ee1` | **FuTurAx** · 0.95 | **FuTurAx** · 1.0 | Win32/Futurax · 1.0 | **Futurax** · 10† | — | Tie on name; †D score scale quirk |

| Slot | A elapsed | B elapsed | C elapsed | D elapsed | E elapsed |
|------|----------:|----------:|----------:|----------:|----------:|
| S1 | 263 s | 339 s | 319 s | 258 s | — |
| S2 | 153 s | 247 s | 222 s | 140 s | 197 s |
| S3 | 126 s | 238 s | 204 s | 103 s | — |

**Official learning:** A→B (same embedder, bigger corpus) does **not** uniformly improve RE labels. A→D shows HiAsm on freeze was not “small corpus alone.” Score S2 on **properties**, not HiAsm/Salgorea string match.

### 5.1a A2 / S2 property-graded comparison (A–E + G/H pilots)

Grade = malicious + **behavior/build properties** (not named family absent from index).

| Slot | What “good” looks like | A | B | C | D | **E** | G (no RAG) | H (no RAG) | Winner |
|------|------------------------|---|---|---|---|-------|------------|------------|--------|
| **A2** | Process hollowing / injector + crypto (RC4) + MinGW-ish | HiAsm lottery | Virut-like | ProcessHollowing.Dropper | Neshta | **Hollowing + RC4 (MinGW)** | hollowing (noisier) | **Hollowing + RC4 payload** | **E / H** (tied on properties) |
| **S2** | Packed/obfuscated Win32 trojan/dropper + service (VT: Salgorea; **not in KB**) | HiAsm lottery | Agent + service | MSUpdaterTrojan | Neshta/packed | PlugX (RAG prose) | APT29/CozyBear (YARA name) | Sality (wrong name) | **B** among named A–D; no letter wins Salgorea |

Optional article borrow: **A2 @ E** (and **A2 @ H** without RAG) for analysis-derived property description. Footnote S2@E PlugX / S2@G CozyBear as contamination modes. Remeasure under a future RE-primary index.

### 5.2 Smoke (carry-forward) + Config D (+ E on A2)

| Role | SHA12 | A | B | C | D (Qwen×35K) | **E (Malcat RAG)** |
|------|-------|---|---|---|--------------|--------------------|
| A1 | `d164c1d5c03a` | long Sality-ish dropper · 90 | **Trojan.Dropper** · 0.95 | trojan-dropper (generic) · 0.95 | Trojan.Dropper (Fake Adobe…) · 90 | — |
| A2 | `d27bc752e43c` | **HiAsm** · 1.0 | Virut-like (unconfirmed) · 0.9 | Generic.ProcessHollowing.Dropper · 95 | Win32.Neshta variant · 0.85 | **Process hollowing + RC4 (MinGW)** · 0.95 |
| B1 | `36c60de86d02` | — | VB Trojan Downloader · 0.85 | **MSUpdater** · 0.7 | Trojan.VB.Downloader… · 95 | — |
| B2 | `dcd93bfb6b29` | — | Unknown (ransom/loader?) · 0.95 | Unknown (generic trojan…) · 85 | unknown · 0.95 | — |
| C1 | `fa8b270f1972` | — | — | Unknown · 0.4 · disagree | **Kawaii-Unicorn** (VB Adobe lure) · 0.85 | — |
| C2 | `b73782c34103` | — | — | unknown · 10 | Unknown UPX-packed trojan… · 1.0 | — |

**Smoke learning:** Freeze “A2@A HiAsm” is unstable (§5.5). **A2@E** is the strongest property description across A–E. D recovers crisp C1 (Kawaii-Unicorn) that C missed — model×corpus interaction, not a universal Qwen win.

### 5.5 Config A stability — A2 then S2 ×3

**Setup:** stack A · corpus 35,302 · bge-m3 + bge-reranker-v2-m3. Sequence A2 → S2 three times. All valid; 5 hits each.

| Round | Role | SHA12 | Family | Score | Elapsed |
|------:|------|-------|--------|------:|--------:|
| 1 | smoke_A_2 | `d27bc752e43c` | Process Hollowing Dropper | 0.95 | 124 s |
| 1 | official_S2 | `39d60466fcbc` | **HiAsm (low confidence)** | 0.95 | 183 s |
| 2 | smoke_A_2 | `d27bc752e43c` | unknown | 0.95 | 113 s |
| 2 | official_S2 | `39d60466fcbc` | *null* | 0.95 | 151 s |
| 3 | smoke_A_2 | `d27bc752e43c` | Process hollowing dropper (possibly HiAsm variant) | 95 | 160 s |
| 3 | official_S2 | `39d60466fcbc` | **HiAsm** | 85 | 153 s |

| Sample | HiAsm-ish / 3 | Notes |
|--------|---------------|-------|
| official S2 | **2 / 3** | R1 low-conf; R3 crisp 85; R2 `family=null` |
| smoke A2 | **1 / 3** (weak) | Only R3 “possibly HiAsm”; **0 / 3** pure `HiAsm` |

**Stability learning:** Retrieval/ranking stable (top-5 IDs/scores matched); **LLM family strings churn**. “Config A wins HiAsm” is not a deterministic Config A property.

#### 5.5.1 What 35K contains for HiAsm / A2 / S2

| Item | In Config A 35K index? |
|------|------------------------|
| S2 SHA `39d60466…` | **No** |
| A2 SHA `d27bc752…` | **No** |
| Direct sample writeup / self-hit | **No** |
| HiAsm-related chunks | **1** — FortiGuard encyclopedia name stub `W32/HiAsm.A!tr` (2014-11-30, URL only; no sample hash, no RE detail). Ranked WEAK (~0.007). |

Family “HiAsm” is associative promotion of a thin TI label, not grounded sample evidence.

#### 5.5.2 Query ↔ index source rule

RAG queries should be built from the **same source classes as the indexed chunks**. Prefer confident Malcat (+ deeper analysis) signals; grow the index with RE-shaped text.

#### 5.5.3 Config E — Malcat-query RAG × bge × 35K (A2/S2 pilot); F ≡ MR

**Purpose:** Analysis-derived RAG query on fixed Config A index. Score **malicious + properties** (Salgorea not in index).

| Slot | SHA12 | Valid | Hits | Family @ E | Score | Elapsed |
|------|-------|:-----:|-----:|------------|------:|--------:|
| A2 | `d27bc752e43c` | true | 5 | Process hollowing injector with RC4 encryption (MinGW build) | 0.95 | 158.8 s |
| S2 | `39d60466fcbc` | true | 5 | **PlugX** | 0.92 | 196.7 s |

Both: `verdict=malicious`, LLM judge. Malcat flagged suspicious PE properties; it did **not** emit “PlugX.”

**RAG query (truncated)**

| Slot | Mode | Terms | Query (truncated) |
|------|------|------:|------------------|
| A2 | malcat | 14 | `BigResourceHighEntropy … encrypt data using RC4 PRGA … use process replacement` |
| S2 | malcat | 17 | `CrossSectionJump … CADRE_APT29_CozyBear_Generic … encode data using XOR …` |

vs Config A baseline: filename-only query; top-5 included WEAK FortiGuard HiAsm stub.

**Top-5 @ E — A2** (all capa-rules, WEAK): RC4 encrypt variants (scores ~0.192 → 0.035). No HiAsm. Family ≈ behavior class.

**Top-5 @ E — S2** (all capa-rules, WEAK ~0.008→0.002): XOR / murmur3 / ADD-XOR-SUB / stackstrings / Base64.

**Why S2 @ E said PlugX:** Hit prose states ADD/XOR/SUB encoding is *“common for PlugX but also used by other malware families.”* That text entered RAG context; the LLM promoted PlugX. Contamination failure mode — not “Malcat labeled PlugX.”

| Slot | A (freeze) | B | C | D | **E** |
|------|------------|---|---|---|-------|
| A2 | HiAsm (unstable) | Virut-like | ProcessHollowing.Dropper | Neshta variant | Process hollowing + RC4 (MinGW) |
| S2 | HiAsm (unstable) | Trojan.Win32.Agent | MSUpdaterTrojan | Neshta-ish / packed | **PlugX** (RAG capa prose) |

None of A–E produced Salgorea. **Property grade:** E wins A2; E loses S2 to contamination.

**Config F:** Retired — **F ≡ MR** (already 16/16 on stack D).

#### 5.5.4 Config G/H — no-RAG LLM (A2/S2) — DONE

| Config | Lead | A2 family | S2 family | Hits | Elapsed |
|--------|------|-----------|-----------|------|---------|
| **G** | YARA/capa/filename | virus file infector with process hollowing · 9 | **APT29/CozyBear** · 0.95 | 0 | 67.5 s / 122.4 s |
| **H** | Malcat anomalies | **Process Hollowing Dropper/Injector (RC4-encrypted payload)** | **Sality (packed file infector / trojan)** | 0 | 125.3 s / 146.8 s |

All four: malicious, hits=0, RAG disabled, LLM-only OK.

**Reading:** A2 **H ≈ E** on properties without RAG → E’s A2 win is analysis-driven. S2@G APT29 from YARA rule title (not retrieval). S2@H Sality still wrong named family. Prefer packed/obfuscated trojan as property read.

### 5.3 Normal S4–S5 (not in KB) — A / B / C / D

| Slot | SHA12 | Folder hint | A (bge×35K) | B | C | D |
|------|-------|-------------|-------------|---|---|---|
| S4 | `426511145595` | Kelihos | Possible loader (atom/mailslot) · 65 · 153 s | unknown · 0.2 · disagree · 226 s | none/benign · 0.1 · disagree · 295 s | Generic dropper (mailslots?) · 0.7 · 188 s |
| S5 | `353ddce78d58` | Lumma MTA | Go-based PowerShell loader · 0.85 · 202 s | Go-based malware · 80 · 205 s | Unknown Go-based… · 0.9 · 252 s | Go-based crypto miner · 80 · 414 s |

**Normal learning:** folder names ≠ ground truth. No config invents a strong KB-backed family for S4. S5 lands on “Go-based” across A/B/C/D — useful class, not crisp family.

### 5.4 True corpus S6–S10 (KB bazaar) — A / B / C / D

| Slot | SHA12 | Label | A (bge×35K) | B family | C family | D family | Notes |
|------|-------|-------|-------------|----------|----------|----------|-------|
| S6 | `91d57a66876b` | XWorm | **XWorm** (MSIL…) · 95 | **XWorm** · 0.99 | **XWorm** · 95 | **XWorm** · 0.95 | Tie / self-hit class |
| S7 | `7fc9ae64edb1` | Ransom | Trojan-Ransom.Win32.Generic · 0.85 | HEUR-Trojan-Ransom.Win32.Generic · 95 | same · 100 | same · 90 | Tie |
| S8 | `980373db2260` | MS17-010 | **WannaCry** · 0.98 | MS17-010 Exploit Dropper (long) · 98 | **Exploit.Win32.MS17-010.cb** · 100 | MS17-010 Exploit Loader… · 1.0 | Theme OK; A names campaign, C crispiest exploit ID |
| S9 | `1c2e8be7a102` | Kryplod | MSIL/Kryplod.gen · 0.8 | HEUR-Trojan.MSIL.Kryplod.gen · 95 | same · 95 | **Trojan.MSIL.Kryplod** · 90 | Tie |
| S10 | `4b9b8edaed36` | CoreWarrior | **CoreWarrior** · 0.95 | HEUR-Flooder.Win32.CoreWarrior.a · 1.0 | same · 1.0 | **CoreWarrior** · 95 | Tie |

| Slot | A elapsed | B elapsed | C elapsed | D elapsed |
|------|----------:|----------:|----------:|----------:|
| S6 | 167 s | 206 s | 326 s | 156 s |
| S7 | 167 s | 196 s | 185 s | 157 s |
| S8 | 174 s | 203 s | 204 s | 150 s |
| S9 | 136 s | 200 s | 260 s | 158 s |
| S10 | 107 s | 153 s | 155 s | 181 s |

**Corpus learning:** When SHA is **in** the KB, A/B/C/**D** produce high-quality agreeing families. Embedder×size swap is near-tie on self-hit class. Strongest positive signal = **index membership**.

---

## 5.6 Axis 2 — Malcat ± RAG on stack D (MR / MN)

| Letter | Meaning | RAG | Lead |
|--------|---------|-----|------|
| **MR** | Malcat + RAG | ON (Malcat-derived query) | Analysis-derived hybrid query |
| **MN** | Malcat + no RAG | OFF | Same Malcat signals → LLM only |

**Fixed:** stack D · Qwen3 × 35K · same 16 samples as D.  
**Status:** MR **16/16** valid · MN **16/16** valid · MR typically 5 hits; MN hits=0, RAG disabled.

| Role | MR family | MR valid | MN family | MN valid | Notes |
|------|-----------|----------|-----------|----------|-------|
| smoke_A_1 | FakeAdobeFlashDropper (poss. Roudanx) | ✅ | FakeFlash Dropper | ✅ | Both property-ish dropper |
| smoke_A_2 | process_hollower | ✅ | Unknown Process Hollowing Trojan/Dropper | ✅ | **Both** recover hollowing — RAG not required |
| smoke_B_1 | VB6 trojan / TJprojMain (long) | ✅ | TrojanDownloader.VB | ✅ | MN crisper name |
| smoke_B_2 | unknown UPX Borland C++ trojan | ✅ | Delphi trojan (svc + enc) | ✅ | Neither crisp family |
| smoke_C_1 | Kawaii-Unicorn (poss. BabyShark) | ✅ | Unicorn | ✅ | Similar |
| smoke_C_2 | Generic UPX-packed | ✅ | UPX-packed trojan/loader | ✅ | Vague both |
| official_S1 | VMProtect packed malware | ✅ | VMProtect (poss. Emotet) | ✅ | Packer-level; MN adds Emotet guess |
| official_S2 | generic_trojan | ✅ | Remcos Loader | ✅ | **MN names Remcos**; MR stays generic |
| official_S3 | FuTurAx | ✅ | FuTuRaX | ✅ | Same family (spelling) |
| normal_S4 | none | ✅ | Mailslot Backdoor / Delphi trojan | ✅ | **MN better** without RAG |
| normal_S5 | Unknown Go dropper | ✅ | Go-based trojan | ✅ | Neither Lumma |
| corpus_S6 | XWorm | ✅ | XWorm | ✅ | Tie (in-KB) |
| corpus_S7 | Generic Ransomware / BootLocker | ✅ | Generic ransomware | ✅ | Tie-ish |
| corpus_S8 | MS17-010 / EternalBlue | ✅ | Exploit.Win32.MS17-010 | ✅ | Tie (in-KB) |
| corpus_S9 | Kryplod | ✅ | Kryplod | ✅ | Tie (in-KB) |
| corpus_S10 | CoreWarrior | ✅ | CoreWarrior | ✅ | Tie (in-KB) |

**Conclusions (MR/MN):** In-KB ≈ tie. Out-of-KB / hard: Malcat alone often matches or **beats** Malcat+RAG. No systematic RAG naming win on this KB.

---

## 5.7 Axis 2 — LN (legacy lead + no RAG) on stack D — DONE

**Purpose:** Complete the 2×2. **LN** = full-16 replacement of pilot **G**.

| Pass | Status |
|------|--------|
| Batch | ✅ complete |
| Results | ✅ **16/16** valid · all RAG disabled · hits=0 |

### 5.7.1 LN results

| Role | LN family | LN valid | Elapsed |
|------|-----------|:--------:|--------:|
| smoke_A_1 | FlashUpdateDropper | ✅ | 111 s |
| smoke_A_2 | Generic process-hollowing trojan/dropper | ✅ | 70 s |
| smoke_B_1 | Trojan.VB.Generic | ✅ | 115 s |
| smoke_B_2 | Cadre ransomware | ✅ | 103 s |
| smoke_C_1 | *none* (verdict **benign**/75) | ✅ gate | 87 s |
| smoke_C_2 | CADRE ransomware | ✅ | 100 s |
| official_S1 | Generic Infostealer (packed with VMProtect) | ✅ | 204 s |
| official_S2 | **APT29/Cozy Bear** | ✅ | 120 s |
| official_S3 | FuTuRaX | ✅ | 75 s |
| normal_S4 | keylogger | ✅ | 102 s |
| normal_S5 | Go-based Trojan (dropper/spyware) | ✅ | 191 s |
| corpus_S6 | XWorm | ✅ | 114 s |
| corpus_S7 | Generic ransomware | ✅ | 157 s |
| corpus_S8 | WannaCry | ✅ | 95 s |
| corpus_S9 | Kryplod | ✅ | 104 s |
| corpus_S10 | Flooder.Win32.CoreWarrior | ✅ | 75 s |

### 5.7.2 Axis-2 cross-read (same 16 SHAs on stack D)

| Role | D (legacy+RAG) | LN (legacy+no RAG) | MR (Malcat+RAG) | MN (Malcat+no RAG) | Reading |
|------|----------------|--------------------|-----------------|--------------------|---------|
| smoke_A_2 | Neshta variant | process-hollowing | process_hollower | Process Hollowing… | **LN/MR/MN** recover hollowing; D names Neshta |
| smoke_C_1 | Kawaii-Unicorn | **none / benign** | Kawaii-Unicorn | Unicorn | **LN miss** — packaging, not “RAG required” (MN works with RAG off) |
| official_S2 | Neshta-ish packed | **APT29/Cozy Bear** | generic_trojan | Remcos Loader | **LN = YARA-title contamination** (confirms G pilot at n=16) |
| smoke_B_2 / C_2 | unknown / UPX… | **Cadre/CADRE ransomware** | UPX/generic | Delphi / UPX trojan | LN lab-rule branding bleed |
| normal_S4 | Generic dropper (mailslots) | keylogger | none | Mailslot / Delphi | MN strongest property |
| corpus_S6–S10 | in-KB families | in-KB families | in-KB | in-KB | Tie class (S8: LN→WannaCry; others MS17-010 theme) |

### 5.7.3 LN takeaways

1. Axis-2 complete: D / LN / MR / MN each **16/16**.  
2. Legacy + no RAG is **not** automatically clean (**S2→APT29**, **B2/C2→Cadre ransomware**).  
3. **MN often beats LN** on OOD property usefulness.  
4. Cite **LN** for full-matrix no-RAG legacy claims; G remains the 2-sample discovery note only.

```
Property-lens utility on stack D (not formal F1)

Stronger ──►  MN  Malcat-first, RAG off
              MR  Malcat-first, RAG on
              D   Legacy + RAG
Weaker   ──►  LN  Legacy, RAG off
```

---

## 6. Cross-cutting observations

1. Validity gate is saturated on trusted packs — hygiene, not a ranking metric.  
2. Hit count saturated at 5 when RAG on — budget ceiling.  
3. **Family string** is the real differentiator.  
4. Bigger corpus ≠ better RE labels for every sample (A→B dilution).  
5. Qwen3 does not automatically beat bge-m3 on 483K or 35K.  
6. HiAsm on A is **stochastic** (S2 2/3, A2 ~0–1/3).  
7. **KB membership dominates** (true corpus ≫ normal).  
8. Retrieval deterministic; LLM family strings are not.  
9. Latency ~2–7 min wall-clock thin triage.  
10. Index quality dominates model choice.  
11. E: capa prose can name-drop families (PlugX). **F ≡ MR**.  
12. LN/MN close Axis-2 no-RAG cells (G/H were pilots only).

---

## 7. Verdict summary

| Decision | Recommendation |
|----------|----------------|
| **Primary lever** | Improve the index — decompiled code / functions + verified RE writeups |
| **Study closed for publication?** | **Yes:** Axis 1 A–D + Axis 2 D/LN/MR/MN (each 16/16 where applicable) |
| **Corpus rebuild value** | High for indexed malware (S6–S10); mixed for generalization (official S2) |
| **Malcat RAG (E)** | A2 property win (pilot); S2 PlugX = RAG capa prose. Full Malcat+RAG = **MR** |
| **No-RAG pilots G/H** | A2/S2 only → replaced by **LN / MN** |
| **LN** | ✅ 16/16; S2 APT29 + Cadre/CADRE ransomware risk without Malcat packaging |

**One-line summary:** Index quality + tool packaging matter; Malcat lead (MN) often beats legacy lead (LN) with RAG off; RAG/YARA prose can still contaminate (S2@E PlugX, S2@LN APT29).

---

## 8. Forward work (high level)

1. Publish research article + this supporting pack.  
2. Tools-first packaging as default; hybrid RAG opt-in until remasure.  
3. Build an RE-primary corpus, then remeasure A2/S2 (+ matrix).  
4. Prompt hygiene: do not adopt family names that appear only in RAG hit text or YARA rule titles.  
5. Do not treat E/F/G/H as unfinished full studies.

---

*Public supporting data · CADRE Platform · July 2026 · Companion to the research article*
