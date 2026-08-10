# Pipeline AUDIT-REPORT — `91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:26.665131+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:26 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc`

## Stage scoreboard

| Stage | OK |
|-------|----|
| intake | ok |
| quick_scan | ok |
| deep_dive | ok |
| yara_gen | ok |
| publish | ok |

---

_No tool retries occurred during this run._

## Cross-cutting — LLM / Reports

### LLM stages

#### `triage`

- source=`llm_judge` verdict=`suspicious` confidence=`50`
- key_evidence_count=`5`

```json
{
  "verdict": "suspicious",
  "score": 50,
  "family_guess": "UPX-packed generic malware",
  "cross_engine_notes": "Ghidra and IDA both report 0 functions, consistent with a packed binary where function boundaries are obscured. Malcat provides comprehensive anomalies and strings, while capa and YARA confirm UPX packing. PE imports show memory manipulation APIs, but no explicit behavioral malicious intent is observed across engines.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa (raw JSON, capped)",
      "row_or_rule": "packed with UPX",
      "why": "Detects software packing with UPX, a common obfuscation technique used in both malware and benign software."
    },
    {
      "source": "yara",
      "query_or_table": "yara (raw JSON, capped)",
      "row_or_rule": "UPX rule",
      "why": "Multiple YARA rules match UPX signatures, reinforcing the presence of packing."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat deep profile (raw JSON, capped)",
      "row_or_rule": "Anomalies: Packed\u00d77",
      "why": "Malcat reports seven packing-related anomalies, indicating high levels of obfuscation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports (raw JSON, capped)",
      "row_or_rule": "signals: VirtualProtect, VirtualAlloc",
      "why": "High-signal imports for memory protection and allocation, commonly associated with unpacking or process injection in malicious contexts."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat deep profile (raw JSON, capped)",
      "row_or_rule": "Decompilations: EntryPoint",
      "why": "Decompiled code shows loops and memory operations typical of unpacking routines, but no direct behavioral evidence like C2 or file encryption."
    }
  ],
  "summary": "The sample is a 32-bit PE executable packed with UPX, as confirmed by capa, YARA, and Malcat anomalies. It exhibits multiple indicators of obfuscation, including high entropy, packing anomalies, and suspicious API imports (VirtualProtect, VirtualAlloc). However, no clear behavioral malicious intent such as file destruction, persistence, or credential theft is present in the evidence. The packing and obfuscation alone are neutral signals, placing this sample in the suspicious category pending further analysis for actionable malicious behavior.",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 25 matches",
      "capa: 1 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 25 matches",
      "capa: 1 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "yara",
      "floss",
      "malcat",
      "pe_imports"
    ],
    "tools": {
      "capa": {
        "ok": true,
        "why": "ok"
      },
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "floss": {
        "ok": true,
        "why": "ok"
      },
      "pe_imports": {
        "ok": true,
        "why": "ok"
      }
    },
    "hard_failures": [],
    "soft_failures": [],
    "missing": [],
    "not_applicable": [],
    "large_sample": false
  },
  "yara_family_hits": [
    "PackerUPX_CompresorGratuito_wwwupxsourceforgenet"
  ],
  "engine_citation_corrections": {
    "corrected": 0,
    "corrections": 
… [918 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`13`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "UPX-packed PE32 Windows GUI binary with anti-VM evasion, XOR-encrypted strings containing network indicators (HTTP/1.1, socks, url references), and a large 1MB+ high-entropy overlay. The binary imports memory manipulation APIs (VirtualAlloc, VirtualProtect, VirtualFree) and dynamic resolution functions (LoadLibraryA, GetProcAddress) consistent with a decryptor/unpacker stub. Capa confirms UPX packing (T1027.002). YARA rules detect VirtualPC anti-VM checks. All visible strings in the UPX1 code section are XOR-encrypted, with partial decrypted fragments revealing network protocol strings. Zero functions were recovered by disassemblers due to packing, preventing full behavioral analysis, but the combined indicators are strongly malicious.",
  "key_evidence": [
    "YARA: UPX packing confirmed by 5 rules (UPX, UPXv20, UPXV200V290, UPX290LZMA, upx_3)",
    "YARA: VirtualPC_Detection anti-VM check matched",
    "capa: packed with UPX (T1027.002, F0001.008)",
    "Imports: VirtualAlloc+VirtualProtect+VirtualFree+LoadLibraryA+GetProcAddress \u2014 unpacking/memory injection API set",
    "Import signals: load_library(T1129), get_proc_address(T1129), change_memory_protection(T1055), allocate_memory(T1055)",
    "Segments: UPX0(RWX,172KB)+UPX1(RWX,16KB)+UPX2(RW) \u2014 classic UPX layout, both code sections RWX",
    "Malcat anomalies: ExecutableSectionNoCode (UPX0 and UPX1 have no recognized code), BigBufferNoXrefMediumToHighEntropy (crypto data block)",
    "FLOSS: 2050 strings extracted, 0 decoded/stack \u2014 all static and obfuscated, no readable plaintext",
    "Overlay: 1,097,962 bytes with entropy 226/256 \u2014 large appended payload",
    "Encrypted string fragments: 'f~fsocks\\\\a' (socks proxy ref), 's HTTP/1.1' (HTTP protocol), '-url#c' (URL reference)",
    "WS2_32.DLL imported via ordinal (Ordinal_116 = WSAStartup) \u2014 networking capability",
    "Zero functions recovered by Ghidra/IDA \u2014 code entirely packed/obfuscated",
    "1 exported entry: 'start' at 0x42D710 (UPX1 section) \u2014 UPX unpacking entry stub"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 30,
  "successful_non_bootstrap_tools": 19,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "pe_imports",
      "yara",
      "floss",
      "dotnet",
      "r2_decomp",
      "upx",
      "xor",
      "speakeasy",
      "frida_probe"
    ],
    "tools": {
      "capa": {
        "ok": true,
        "why": "ok"
      },
      "pe_imports": {
        "ok": true,
        "why": "ok"
      },
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "floss": {
        "ok": true,
        "why": "ok"
      },
      "dotnet": {
        "ok": true,
        "why": "ok"
      },
      "r2_decomp": {
        "ok": true,
        "why": "ok"
      },
      "upx": {
        "ok": true,
        "why": "ok"
      },
      "xor": {
        "ok": true,
        "why": "ok"
      },
      "speakeasy": {
        "ok": true,
        "why": "ok"
      },
      "frida_probe": {
        "ok": true,
        "why": "ok"
      }
    },
    "hard_failures": [],
    "soft_failures": [],
    "missing": [],
    "not_applicable": [],
    "large_sample": false
  },
  "depth_coverage": null
}
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Analysis Report: UPX-Packed PE32 Binary with Anti-VM and Network Indicators",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 15:11:58 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: PackerUPX_CompresorGratuito_wwwupxsourceforgenet). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** UPX-packed generic malware\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\n\nThis report details the analysis of a UPX-packed 32-bit Windows executable (SHA256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc). The sample exhibits multiple layers of obfuscation and indicators of potential malicious intent. Static analysis confirmed UPX packing and detected anti-VM evasion via VirtualPC-specific checks. The binary imports APIs associated with memory manipulation (VirtualAlloc, VirtualProtect, VirtualFree) and dynamic resolution (LoadLibraryA, GetProcAddress), consistent with a decryptor/unpacker stub. While no clear behavioral actions (e.g., file destruction, persistence, credential theft) were observed in the provided evidence, the combination of strong obfuscation, anti-VM techniques, and XOR-encrypted network protocol strings (HTTP/1.1, socks, URL references) strongly suggests malicious capability. The upstream triage verdict of \"suspicious\" aligns with the evidence, as no definitive runtime malicious behavior was triggered, but the indicators warrant a high-confidence malicious classification for detection and response purposes.\n\n## 1. Sample Identification\n\nThe sample is a 32-bit PE executable with a GUI subsystem, submitted from the \"incoming\" project corpus. Its file path is provided as `/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir`. The original filename appears to be `virussign.com_f622efa728edc2b6d606315cc6746fa9.vir`, suggesting it was sourced from a virussign.com submission.\n\n## 2. Classification\n\n**Verdict:** Malicious\n**Confidence:** High (90%)\n**Family Guess:** UPX-packed generic malware\n**Rationale:** While the upstream triage initially flagged this as \"suspicious,\" deeper analysis revealed compelling behavioral-intent indicators. The sample employs anti-VM evasion (VirtualPC detection), XOR-encrypted network strings, and a large, high-entropy overlay indicative of a secondary payload. The combination of obfuscation and these active evasion and communication primitives elevates the classification beyond mere obfuscation to malicious. The presence of anti-VM checks is a deliberate attempt to hinder analysis, a common tactic in malicious software.\n\n## 3. Background & Family Lineage\n\nThe binary is packed with UPX (Ultimate Packer for eXecutables), a common and legiti
… [14123 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 15:11:58 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: PackerUPX_CompresorGratuito_wwwupxsourceforgenet). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** UPX-packed generic malware
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

This report details the analysis of a UPX-packed 32-bit Windows executable (SHA256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc). The sample exhibits multiple layers of obfuscation and indicators of potential malicious intent. Static analysis confirmed UPX packing and detected anti-VM evasion via VirtualPC-specific checks. The binary imports APIs associated with memory manipulation (VirtualAlloc, VirtualProtect, VirtualFree) and dynamic resolution (LoadLibraryA, GetProcAddress), consistent with a decryptor/unpacker stub. While no clear behavioral actions (e.g., file destruction, persistence, credential theft) were observed in the provided evidence, the combination of strong obfuscation, anti-VM techniques, and XOR-encrypted network protocol strings (HTTP/1.1, socks, URL references) strongly suggests malicious capability. The upstream triage verdict of "suspicious" aligns with the evidence, as no definitive runtime malicious behavior was triggered, but the indicators warrant a high-confidence malicious classification for detection and response purposes.

## 1. Sample Identification

The sample is a 32-bit PE executable with a GUI subsystem, submitted from the "incoming" project corpus. Its file path is provided as `/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir`. The original filename appears to be `virussign.com_f622efa728edc2b6d606315cc6746fa9.vir`, suggesting it was sourced from a virussign.com 
… [12267 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 15:17:02 UTC

# RE Report — 91b176fb0d65
_Generated 2026-08-08T15:17:02.350631+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=252c | cross_refs=True | llm_ok=True | runtime=15.41s -->

```json
{
  "title": "Executive Summary",
  "markdown": "This malware sample (SHA256: `91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc`) is assessed as **suspicious** with **high confidence (90%)**, likely belonging to the **UPX-packed generic malware** family. Multiple analysis tools indicate this classification, though there is disagreement between analysis passes on the final verdict.\n\nThe analysis pipeline revealed conflicting assessments: an initial deep-dive agentic analysis concluded the sample was malicious with high confidence (source: deep_dive_agentic, deep_confidence: 90), while an alternative LLM-based verdict (v1) scored it as malicious with 290 points based on 25 YARA matches and 1 CAPA rule (source: v1_summary). A subsequent analysis round produced a verdict of \"suspicious\" (source: evidence, verdict: suspicious). This disagreement (`llm_v1_disagree`) suggests the sample exhibits indicators that are ambiguous but collectively point to malicious intent (source: cross-section:agreement). We assess the malicious classification is more probable given the convergent evidence of packing and multiple detection hits.\n\nThe core technical indicators point to a packer-based threat. Static analysis and detection rules consistently identify the use of the **Ultimate Packer for Executables (UPX)**, a tool commonly abused for obfuscation (source: yara, cross-section:malware_family). This packing technique is a primary evasion method, hindering direct analysis and suggesting the authors aimed to avoid detection. The presence of 25 YARA rule matches and 1 capability (CAPA) rule match (source: v1_summary, yara, capa) provides a strong statistical basis for classifying the sample as suspicious, even if its specific payload remains obscured.\n\nIn summary, this is a likely malicious, UPX-packed binary exhibiting strong obfuscation characteristics. The high confidence stems from multiple corroborating detection sources, though t
… [44786 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4418` | `c0adf68e27eefcb8` |
| `prompt.txt` | `True` | `21290` | `64b32383ba304ec8` |
| `pipeline-audit.json` | `True` | `100458` | `3101c369f4bf44cc` |
| `AUDIT-REPORT.md` | `True` | `73640` | `b80e4660abe275e1` |
| `REPORT-MASTER-v2.md` | `True` | `14777` | `dfcd1aecb220ceac` |
| `REPORT-MASTER-v3.md` | `True` | `47302` | `8d6767f567bd870c` |
| `REPORT-v2.md` | `True` | `14777` | `dfcd1aecb220ceac` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `36352` | `4f09929e24aebe39` |
| `rule.yar` | `True` | `1052` | `d959cf38d4c425b2` |
| `intake-validation.json` | `True` | `2303` | `f65479c5f5cd75cd` |
| `source-decisions.json` | `True` | `1463` | `a639e4aa4134fe12` |
| `malcat-triage.json` | `True` | `21277` | `1748a14c9b94eb7d` |
| `deep_dive/01-tools-raw.json` | `True` | `62426` | `7bc5a6d86646fbbe` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3421` | `505aefcfa41bf743` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `60126` | `cf45882d195eb707` |

---

## Stage: intake

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| intake_validation | `True` |
| has_source_decisions | `True` |
| ghidra_mentioned | `True` |

### Artifact paths (verify on disk)

- **intake_validation:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/intake-validation.json` exists=`True` bytes=`2303` mtime=`2026-08-08T15:08:30.318724+00:00`
  - sha256: `f65479c5f5cd75cd2c353124440cb3eed98673c0cc7d8175dba39af068b513a2`
- **malcat_triage:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/malcat-triage.json` exists=`True` bytes=`21277` mtime=`2026-08-08T15:07:22.541884+00:00`
  - sha256: `1748a14c9b94eb7dd76897e6332368f88ec87636311870c0114af3cea661bb1e`
- **source_decisions:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/source-decisions.json` exists=`True` bytes=`1463` mtime=`2026-08-08T15:08:30.318724+00:00`
  - sha256: `a639e4aa4134fe12c181455880b134f5862891327b1d7e7ddbf4b0561f6eca44`
- **ghidra_import_log:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/intake-idasql.log` exists=`True` bytes=`254` mtime=`2026-08-08T15:07:24.012881+00:00`
  - sha256: `4f20a5d52a2df80cae21454318fe85e7cf6c3c546d5b9693ea7f5f4c42813b38`

#### source_decisions_excerpt

```
{
  "sha256": "91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 10 imports, within 20% agreement (Ghidra=10, IDA=10). Malcat also reports 10, but Ghidra is chosen for consistency with rule-based decisions."
  },
  "functions": {
    "source": "none",
    "confidence": "medium",
    "reason": "No functions from Ghidra or IDA (funcs=0), while Malcat reports 1 function, but Ghidra and IDA are more reliable for function analysis; hence, unreliable coverage."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Using both Ghidra (strings=12) and IDA (strings=192) provides comprehensive string extraction; Malcat also reports 100 strings, but
… [686 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "profile": "triage",
  "limits": {
    "strings_max": 100,
    "imports_max": 100,
    "functions_max": 10,
    "anomaly_locations_max": 5,
    "decompile_top_n": 1
  },
  "file_summary": {
    "analysis_id": 1,
    "file_name": "virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
    "file_path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
    "file_size": 1294570,
    "type": "PE",
    "architecture": "X86",
    "entropy": 195,
    "sha256": "91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc
… [20477 more chars]
```


---

## Stage: quick_scan

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| prompt | `True` |
| verdict | `True` |
| has_capa_section | `True` |
| has_yara_section | `True` |
| has_malcat_section | `True` |
| has_floss_section | `True` |
| verdict_has_family | `True` |
| llm_source | `True` |
| tools_all_ok | `True` |
| citations_grounded | `True` |
| capa_salvage_used | `False` |
| evidence_pack_present | `True` |
| benign_blocked_if_incomplete | `True` |
| yara_family_not_cleared | `True` |

### Tools (full evidence excerpts)

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "packed with UPX",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
          "id": "T1027.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Software Packing",
            "UPX"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "UPX",
          "id": "F0001.008"
        }
      ]
    }
  ],
  "timeout_s": 300,
  "sample_size": 1294570,
  "duration_s": 1.55,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 25,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 209129,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 180265,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VirtualPC_Detection",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 182209,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 488,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 528,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 992,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXv20MarkusLaszloReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189244,
          "length": 85,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189291,
          "length": 39,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 188976,
          "length": 63,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "upx_3",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$str1",
          "offset": 188976,
          "length": 45,
          "xor_key": null
        }
      
… [8008 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2050,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "%6w*iA",
    "h8U^L&",
    "cR>#4jX(C",
    "59D;Fw",
    ".SW1zTE",
    "Cb|cn+",
    "`ud2KTcxwc",
    "]pg&*+",
    "/Qmlv%uwjbwdh%fdkkjq%g`%wpk%",
    "AJV%hja`+",
    "9'Wlfm?",
    "w`}nw+",
    "u34v43",
    "asw=((",
    ":cd616rv7Z6",
    "`q\tSfs",
    "RVDV`k",
    "*\t]\\\\8",
    "x5y<{i",
    "g*QQ!U",
    "<!65{+",
    "PN8f<#",
    "BPQ`huUdq",
    "Rwlq`Uwjf`v",
    "V-`uFijv`pj",
    "_x5`Qm",
    "}TW$U+",
    "5Z9op\\",
    "[{Zcalshd",
    "Mjjn@}",
    "N@WK@I",
    "HVSFWQ",
    "/IjdaIl",
    "cftcrk",
    "10,fnn3igpin",
    "RpmaCffpgO",
    "loglvTcpkc`ng",
    "klGzga",
    "Amr{Dk",
    "oIIg{C",
    "8--6]kicY_",
    "vkqGcvmp,",
    "#oclceg",
    "+`ewnlm-f{f",
    "khw*a|",
    "pbf%%8rzzZ",
    "3:\\stop",
    "f~fsocks\\a",
    "miniavprra!#%",
    "ABCDEFGHIJKLMNOPQ",
    "WXYZabcdefgh",
    "qrAuvwxyz01",
    "2345^89+/{",
    "7'ZKoetiu",
    "ZFhbiq",
    "hrPc6oihZT",
    "[QVGO^Aw",
    "\"%1\" %*",
    "~`oj{n",
    "\\zn?ls",
    "<Mrm m",
    "X_^OXDK",
    "3^q{rgo7n",
    "gQGPRPM",
    "smdp_Bss",
    "eX/wru\ts",
    "+x,vorp61s16",
    "#~31324.t",
    "mK[>r~a{k",
    "s HTTP/1.1",
    ")}k4*[",
    "-url#c",
    "VUCPG+",
    "Shefs#",
    "._PSt*C",
    "9819c52",
    "7e-00+:",
    "sidOe;155a",
    "\\BA'aQAgo"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2050
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.13,
  "size_bytes": 1294570,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
    "analysis_id": 1,
    "file_name": "virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
    "file_path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
    "file_size": 1294570,
    "type": "PE",
    "architecture": "X86",
    "entropy": 195,
    "sha256": "91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
    "metadata": {},
    "entrypoint_ea": 188976,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 4096,
        "virtual_size": 0,
        "rights": "",
        "entropy": 180
      },
      {
        "name": "UPX0",
        "effective_address": 4096,
        "physical_size": 172032,
        "virtual_size": 172032,
        "rights": "RWX",
        "entropy": 4
      },
      {
        "name": "UPX1",
        "effective_address": 176128,
        "physical_size": 16384,
        "virtual_size": 16384,
        "rights": "RWX",
        "entropy": 168
      },
      {
        "name": "UPX2",
        "effective_address": 192512,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 9
      },
      {
        "name": "overlay",
        "effective_address": 196608,
        "physical_size": 1097962,
        "virtual_size": 0,
        "rights": "",
        "entropy": 226
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "BigBufferNoXrefMediumToHighEntropy",
        "desc": "a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference inside: most likely a big crypto data block. File must have at least one function for this anomaly to run",
        "category": "entropy",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "DataBetweenHeaderAndFirstSection",
        "desc": "There is non-zero data between the PE header and the first section",
        "category": "headers",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "ExecutableSectionNoCode",
        "desc": "executable section has the flag code not set",
        "category": "sections",
        "level": 4,
        "num_hits": 2
      },
      {
        "name": "GuiSubsystemNoWindowApi",
        "desc": "A GUI windows application does not import any user32 window-related function",
        "category": "headers",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "HugeFunctionGapAtSectionBoundary",
        "desc": "There is a huge gap between start/end of executable section and first/last function of a section with medium-to-high entropy (which is not a know structure). It often means that data is stored there",
        "category": "code",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "InvalidBaseOfCode",
        "desc": "at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section",
        "category": "sections",
        "level": 4,
        "num_hits": 1
      },
    
… [36792 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "packed with UPX capa (raw JSON, capped) Detects software packing with UPX, a common obfuscation technique used in both m",
    "UPX rule yara (raw JSON, capped) Multiple YARA rules match UPX signatures, reinforcing the presence of packing. yara   ",
    "Anomalies: Packed\u00d77 malcat deep profile (raw JSON, capped) Malcat reports seven packing-related anomalies, indicating hi",
    "signals: VirtualProtect, VirtualAlloc pe_imports (raw JSON, capped) High-signal imports for memory protection and alloca",
    "Decompilations: EntryPoint malcat deep profile (raw JSON, capped) Decompiled code shows loops and memory operations typi"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "UPX-packed generic malware",
  "score": 50,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa (raw JSON, capped)",
      "row_or_rule": "packed with UPX",
      "why": "Detects software packing with UPX, a common obfuscation technique used in both malware and benign software."
    },
    {
      "source": "yara",
      "query_or_table": "yara (raw JSON, capped)",
      "row_or_rule": "UPX rule",
      "why": "Multiple YARA rules match UPX signatures, reinforcing the presence of packing."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat deep profile (raw JSON, capped)",
      "row_or_rule": "Anomalies: Packed\u00d77",
      "why": "Malcat reports seven packing-related anomalies, indicating high levels of obfuscation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports (raw JSON, capped)",
      "row_or_rule": "signals: VirtualProtect, VirtualAlloc",
      "why": "High-signal imports for memory protection and allocation, commonly associated with unpacking or process injection in malicious contexts."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat deep profile (raw JSON, capped)",
      "row_or_rule": "Decompilations: EntryPoint",
      "why": "Decompiled code shows loops and memory operations typical of unpacking routines, but no direct behavioral evidence like C2 or file encryption."
    }
  ],
  "summary": "The sample is a 32-bit PE executable packed with UPX, as confirmed by capa, YARA, and Malcat anomalies. It exhibits multiple indicators of obfuscation, including high entropy, packing anomalies, and suspicious API imports (VirtualProtect, VirtualAlloc). However, no clear behavioral malicious intent such as file destruction, persistence, or credential theft is present in the evidence. The packing a"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/prompt.txt` exists=`True` bytes=`21290` mtime=`2026-08-08T15:08:41.337705+00:00`
  - sha256: `64b32383ba304ec8de46147b1c7ed7ffa59c5a03f00b5fe7095c4f193a4e1b50`
- **verdict:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/verdict.json` exists=`True` bytes=`4418` mtime=`2026-08-08T15:09:08.345622+00:00`
  - sha256: `c0adf68e27eefcb8a8947dde6b009cda9071d257b7753f953681664a8bfe438d`

#### prompt_excerpt

```
# Triage evidence
sha256: 91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc
sample_path: /opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir
ghidra_session: ghidra-pe-91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc
ida_session: ida-91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 10 imports, within 20% agreement (Ghidra=10, IDA=10). Malcat also reports 10, but Ghidra is chosen for consistency with rule-based decisions.
- functions: none (confidence=medium) — No functions from Ghidra or IDA (funcs=0), while Malcat reports 1 function, but Ghidra and IDA are more reliable for function analysis; hence, unreliable coverage.
- strings: both (confidence=high) — Using both Ghidra (strings=12) and IDA (strings=192) provides comprehensive string 
… [20256 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 50,
  "family_guess": "UPX-packed generic malware",
  "cross_engine_notes": "Ghidra and IDA both report 0 functions, consistent with a packed binary where function boundaries are obscured. Malcat provides comprehensive anomalies and strings, while capa and YARA confirm UPX packing. PE imports show memory manipulation APIs, but no explicit behavioral malicious intent is observed across engines.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa (raw JSON, capped)",
      "row_or_rule": "packed with UPX",
      "why": "Detects software packing with UPX, a common obfuscation technique used in both malware and benign software."
    },
    {
      "source": "yara",
      "query_or_table": "yara (raw JSON, capped)",
      "row_or_rule": "UPX rule",
      "why": "Multiple YARA rules match UPX signatures, reinforcing the presence of packing."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat deep profil
… [3418 more chars]
```


---

## Stage: deep_dive

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| 01_tools_raw | `True` |
| 00_sql_evidence | `False` |
| 03_prompt | `False` |
| 04_llm | `False` |
| 05_deep | `True` |
| tools_all_ok | `True` |
| llm_source | `False` |
| citations_grounded | `True` |
| engine_citation_ok | `True` |
| upx_second_pass_ok | `True` |
| no_incomplete_tooling | `True` |
| confidence_sane | `True` |
| evidence_pack_present | `True` |
| depth_coverage | `True` |
| agentic_json | `True` |
| sql_deep_re | `True` |
| complete_verdict | `True` |
| not_incomplete | `True` |
| checklist_ok_flag | `True` |
| agentic_confidence_sane | `True` |

### Tools (full evidence excerpts)

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json

```

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "packed with UPX",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
          "id": "T1027.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Software Packing",
            "UPX"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "UPX",
          "id": "F0001.008"
        }
      ]
    }
  ],
  "timeout_s": 60,
  "sample_size": 1294570,
  "duration_s": 1.06,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1294570,
  "duration_s": 0.04,
  "import_count": 10,
  "signal_count": 4,
  "signals": [
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    },
    {
      "label": "get_proc_address",
      "api_match": "GetProcAddress",
      "attack": [
        "T1129"
      ]
    },
    {
      "label": "change_memory_protection",
      "api_match": "VirtualProtect",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "allocate_memory",
      "api_match": "VirtualAlloc",
      "attack": [
        "T1055"
      ]
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 25,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 209129,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 180265,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VirtualPC_Detection",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 182209,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 488,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 528,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 992,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXv20MarkusLaszloReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189244,
          "length": 85,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 189291,
          "length": 39,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 188976,
          "length": 63,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "upx_3",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$str1",
          "offset": 188976,
          "length": 45,
          "xor_key": null
        }
      
… [7986 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2050,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "%6w*iA",
    "h8U^L&",
    "cR>#4jX(C",
    "59D;Fw",
    ".SW1zTE",
    "Cb|cn+",
    "`ud2KTcxwc",
    "]pg&*+",
    "/Qmlv%uwjbwdh%fdkkjq%g`%wpk%",
    "AJV%hja`+",
    "9'Wlfm?",
    "w`}nw+",
    "u34v43",
    "asw=((",
    ":cd616rv7Z6",
    "`q\tSfs",
    "RVDV`k",
    "*\t]\\\\8",
    "x5y<{i",
    "g*QQ!U",
    "<!65{+",
    "PN8f<#",
    "BPQ`huUdq",
    "Rwlq`Uwjf`v",
    "V-`uFijv`pj",
    "_x5`Qm",
    "}TW$U+",
    "5Z9op\\",
    "[{Zcalshd",
    "Mjjn@}",
    "N@WK@I",
    "HVSFWQ",
    "/IjdaIl",
    "cftcrk",
    "10,fnn3igpin",
    "RpmaCffpgO",
    "loglvTcpkc`ng",
    "klGzga",
    "Amr{Dk",
    "oIIg{C",
    "8--6]kicY_",
    "vkqGcvmp,",
    "#oclceg",
    "+`ewnlm-f{f",
    "khw*a|",
    "pbf%%8rzzZ",
    "3:\\stop",
    "f~fsocks\\a",
    "miniavprra!#%",
    "ABCDEFGHIJKLMNOPQ",
    "WXYZabcdefgh",
    "qrAuvwxyz01",
    "2345^89+/{",
    "7'ZKoetiu",
    "ZFhbiq",
    "hrPc6oihZT",
    "[QVGO^Aw",
    "\"%1\" %*",
    "~`oj{n",
    "\\zn?ls",
    "<Mrm m",
    "X_^OXDK",
    "3^q{rgo7n",
    "gQGPRPM",
    "smdp_Bss",
    "eX/wru\ts",
    "+x,vorp61s16",
    "#~31324.t",
    "mK[>r~a{k",
    "s HTTP/1.1",
    ")}k4*[",
    "-url#c",
    "VUCPG+",
    "Shefs#",
    "._PSt*C",
    "9819c52",
    "7e-00+:",
    "sidOe;155a",
    "\\BA'aQAgo"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2050
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.08,
  "size_bytes": 1294570,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `dotnet` — ok=`True` why=`ok`

```json
{
  "is_dotnet": false,
  "runtime_version": null,
  "assembly_name": null,
  "module_name": null,
  "language_hint": null,
  "external_assembly_refs": [],
  "suspicious_native_refs": [],
  "suspicious_methods": [],
  "interesting_pinvoke": [],
  "has_suppress_ildasm": false,
  "shellcode_embed_hint": false,
  "il_total_lines": 0,
  "il_excerpt": ""
}
```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": false,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "disassembly": {},
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x0042e230"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

#### `frida_probe` — ok=`True` why=`ok`

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
    "exists": true
  }
}
```

#### `frida_trace` — ok=`True` why=`not_applicable:pe`

```json

```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 13,
  "hits": 13,
  "misses": [],
  "hit_examples": [
    "YARA: UPX packing confirmed by 5 rules (UPX, UPXv20, UPXV200V290, UPX290LZMA, upx_3)",
    "YARA: VirtualPC_Detection anti-VM check matched",
    "capa: packed with UPX (T1027.002, F0001.008)",
    "Imports: VirtualAlloc+VirtualProtect+VirtualFree+LoadLibraryA+GetProcAddress \u2014 unpacking/memory injection API set",
    "Import signals: load_library(T1129), get_proc_address(T1129), change_memory_protection(T1055), allocate_memory(T1055)"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "UPX-packed PE32 Windows GUI binary with anti-VM evasion, XOR-encrypted strings containing network indicators (HTTP/1.1, socks, url references), and a large 1MB+ high-entropy overlay. The binary imports memory manipulation APIs (VirtualAlloc, VirtualProtect, VirtualFree) and dynamic resolution functi",
  "key_evidence": [
    "YARA: UPX packing confirmed by 5 rules (UPX, UPXv20, UPXV200V290, UPX290LZMA, upx_3)",
    "YARA: VirtualPC_Detection anti-VM check matched",
    "capa: packed with UPX (T1027.002, F0001.008)",
    "Imports: VirtualAlloc+VirtualProtect+VirtualFree+LoadLibraryA+GetProcAddress \u2014 unpacking/memory injection API set",
    "Import signals: load_library(T1129), get_proc_address(T1129), change_memory_protection(T1055), allocate_memory(T1055)",
    "Segments: UPX0(RWX,172KB)+UPX1(RWX,16KB)+UPX2(RW) \u2014 classic UPX layout, both code sections RWX",
    "Malcat anomalies: ExecutableSectionNoCode (UPX0 and UPX1 have no recognized code), BigBufferNoXrefMediumToHighEntropy (crypto data block)",
    "FLOSS: 2050 strings extracted, 0 decoded/stack \u2014 all static and obfuscated, no readable plaintext",
    "Overlay: 1,097,962 bytes with entropy 226/256 \u2014 large appended payload",
    "Encrypted string fragments: 'f~fsocks\\\\a' (socks proxy ref), 's HTTP/1.1' (HTTP protocol), '-url#c' (URL reference)",
    "WS2_32.DLL imported via ordinal (Ordinal_116 = WSAStartup) \u2014 networking capability",
    "Zero functions recovered by Ghidra/IDA \u2014 code entirely packed/obfuscated",
    "1 exported entry: 'start' at 0x42D710 (UPX1 section) \u2014 UPX unpacking entry stub"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 25,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      
… [11086 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
    "analysis_id": 1,
    "fi
… [39871 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "packed with UPX",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
         
… [498 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1294570,
  "duration_s": 0.04,
  "import_count": 10,
  "signal_count": 4,
  "signals": [
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    },
    {
      "label": "get_proc_address",
      "api_match": "GetProcAddress",
      "attack": [
        "T1129"
      ]
    },
    {
      "label"
… [303 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2050,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "%6w*iA",
    "h8U^L&",
    "cR>#4jX(C",
    "59D;Fw",
    ".SW1zTE",
    "Cb|cn+",
    "`ud2KTcxwc",
    "]pg&*+",
    "/Qmlv%uwjbwdh%fdkkjq%g`%wpk%",
    "AJV%hja`+",
    "9'Wlfm?",
    "w`}nw+",
    "u34v43",
    "asw=((",
    ":cd616rv7Z6",
    "`q\tSfs",
  
… [1408 more chars]
```

- **dotnet_analyze** ok=`True` checklist=`True` — Required checklist tool (dotnet)

```json
{
  "is_dotnet": false,
  "runtime_version": null,
  "assembly_name": null,
  "module_name": null,
  "language_hint": null,
  "external_assembly_refs": [],
  "suspicious_native_refs": [],
  "suspicious_methods": [],
  "interesting_pinvoke": [],
  "has_suppress_ildasm": false,
  "shellcode_embed_hint": false,
  "il_total_lines": 0,
  "il_excerpt": ""
}
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": false,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "disassembly": {},
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x0042e230"
  ]
}
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

- **frida_static_probe** ok=`True` checklist=`True` — Required checklist tool (frida_probe)

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
    "exists": true
  }
}
```

- **ghidra_query** ok=`True` checklist=`False` — Auto SQL seed for large-mode deep RE gate

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "audit_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "module"
  ],
  "rows": [
    {
      "address": "6",
      "name": "ExitProcess",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "2",
      "name": "GetProcAddress",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "1",
      "name": "LoadLibraryA",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "10",
      "n
… [924 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "GetProcAddress",
      "address": "4387070",
      "length": "15"
    },
    {
      "content": "VirtualProtect",
      "address": "4387086",
      "length": "15"
    },
    {
      "content": "KERNEL32.DLL",
      "address": "4386996",
      "length": "13"
    },
    {
      "content": "OLEAUT32.d
… [1109 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [
    {
      "name": "ExitProcess",
      "module": "KERNEL32",
      "address": "4386956"
    },
    {
      "name": "GetProcAddress",
      "module": "KERNEL32",
      "address": "4386940"
    },
    {
      "name": "LoadLibraryA",
      "module": "KERNEL32",
      "address": "4386936"
    },
    {
      "name": "VirtualAll
… [912 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "/Qmlv%uwjbwdh%fdkkjq%g`%wpk%",
      "address": "4370592",
      "length": "28"
    },
    {
      "content": "pynZKgiMDrive\"6\u001b#Zs",
      "address": "4382590",
      "length": "19"
    },
    {
      "content": "ABCDEFGHIJKLMNOPQ",
      "address": "4374569",
      "length": "17"
    },
    
… [2909 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "perm"
  ],
  "rows": [
    {
      "start_ea": "4198400",
      "end_ea": "4370432",
      "name": "UPX0",
      "class": "CODE",
      "perm": "7"
    },
    {
      "start_ea": "4370432",
      "end_ea": "4386816",
      "name": "UPX1",
      "class": "CODE",
      "perm": "7"
    },
    {
      "start_ea": "4386816",
 
… [657 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/virussign.com_f622efa728edc2b6d606315cc6746fa9.vir",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
    "analysis_id": 1,
    "fi
… [39871 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "audit_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/audit.jsonl"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 1,
  "top_rules": [
    {
      "name": "packed with UPX",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
         
… [498 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "/Qmlv%uwjbwdh%fdkkjq%g`%wpk%",
      "address": "4370592",
      "length": "28"
    },
    {
      "content": "AJV%hja`+\b\b",
      "address": "4370626",
      "length": "11"
    },
    {
      "content": "9'Wlfm?",
      "address": "4370688",
      "length": "7"
    },
    {
      "content": "w`}
… [2710 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "size"
  ],
  "rows": [
    {
      "start_ea": "4194304",
      "end_ea": "4198399",
      "name": "Headers",
      "class": "DATA",
      "size": "4096"
    },
    {
      "start_ea": "4198400",
      "end_ea": "4370431",
      "name": "UPX0",
      "class": "CODE",
      "size": "172032"
    },
    {
      "start_ea": "
… [550 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "VirtualProtect",
      "address": "4387086",
      "length": "14"
    },
    {
      "content": "VirtualAlloc",
      "address": "4387102",
      "length": "12"
    },
    {
      "content": "VirtualFree",
      "address": "4387116",
      "length": "12"
    }
  ],
  "row_count": 3,
  "total_row_co
… [258 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "GetProcAddress",
      "address": "4387070",
      "length": "15"
    },
    {
      "content": "VirtualProtect",
      "address": "4387086",
      "length": "15"
    },
    {
      "content": "VirtualAlloc",
      "address": "4387102",
      "length": "13"
    },
    {
      "content": "VirtualFre
… [458 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 2050,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "%6w*iA",
    "h8U^L&",
    "cR>#4jX(C",
    "59D;Fw",
    ".SW1zTE",
    "Cb|cn+",
    "`ud2KTcxwc",
    "]pg&*+",
    "/Qmlv%uwjbwdh%fdkkjq%g`%wpk%",
    "AJV%hja`+",
    "9'Wlfm?",
    "w`}nw+",
    "u34v43",
    "asw=((",
    ":cd616rv7Z6",
    "`q\tSfs",
  
… [1408 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 1294570,
  "duration_s": 0.05,
  "import_count": 10,
  "signal_count": 4,
  "signals": [
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    },
    {
      "label": "get_proc_address",
      "api_match": "GetProcAddress",
      "attack": [
        "T1129"
      ]
    },
    {
      "label"
… [303 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "audit_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "f~fsocks\\a",
      "address": "4374532",
      "length": "10"
    },
    {
      "content": "s HTTP/1.1\r",
      "address": "4375121",
      "length": "11"
    },
    {
      "content": "-url#c",
      "address": "4375176",
      "length": "6"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,

… [249 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address"
  ],
  "rows": [
    {
      "name": "start",
      "address": "4383280"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "audit_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90d
… [18 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc",
  "audit_path": "/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/audit.jsonl"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/deep_dive/01-tools-raw.json` exists=`True` bytes=`62426` mtime=`2026-08-08T15:09:20.819592+00:00`
  - sha256: `7bc5a6d86646fbbed504c2c82e311bda300f2bcd1993b1503a631266155c823c`
- **sql_evidence:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/deep_dive/05-deep-dive.json` exists=`True` bytes=`3421` mtime=`2026-08-08T15:11:00.464640+00:00`
  - sha256: `505aefcfa41bf743897699de289386bfa5cf485de120781a8219f2f46f9eefb0`

#### prompt_excerpt

```

```


#### llm_raw_excerpt

```
{}
```


#### deep05_excerpt

```
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "UPX-packed PE32 Windows GUI binary with anti-VM evasion, XOR-encrypted strings containing network indicators (HTTP/1.1, socks, url references), and a large 1MB+ high-entropy overlay. The binary imports memory manipulation APIs (VirtualAlloc, VirtualProtect, VirtualFree) and dynamic resolution functions (LoadLibraryA, GetProcAddress) consistent with a decryptor/unpacker stub. Capa confirms UPX packing (T1027.002). YARA rules detect VirtualPC anti-VM checks. All visible strings in the UPX1 code section are XOR-encrypted, with partial decrypted fragments revealing network protocol strings. Zero functions were recovered by disassemblers due to packing, preventing full behavio
… [2621 more chars]
```

- **agentic:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`310543` mtime=`2026-08-08T15:11:00.463640+00:00`
  - sha256: `df09b83633971d6df4d6a04a19f3b127cdd2af5ee17513eefc45a8a8952cf01e`

---

## Stage: yara_gen

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| rule_yar | `True` |
| non_empty | `True` |
| has_rule_block | `True` |
| rule_compiles | `True` |
| rule_check | `ok` |
| meta_yara_valid | `True` |

### Artifact paths (verify on disk)

- **rule_yar:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/rule.yar` exists=`True` bytes=`1052` mtime=`2026-08-08T15:11:03.651636+00:00`
  - sha256: `d959cf38d4c425b2636cb099ad6d7d00fdf2dffc865d1bd2a60739ae818e0327`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T15:11:03.652004+00:00
rule CADRE_v2_unknown_91b176fb0d65 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "GetProcAddress" ascii wide
        $s1 = "VirtualProtect" ascii wide
        $s2 = "KERNEL32.DLL" ascii wide
        $s3 = "OLEAUT32.dll" ascii wide
        $s4 = "LoadLibraryA" ascii wide
        $s5 = "VirtualAlloc" ascii wide
        $s6 = "VirtualFree" ascii wide
        $s7 = "ExitProcess" ascii wide
        $s8 = "MSVCRT
… [250 more chars]
```


---

## Stage: publish

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| REPORT_MASTER_v2 | `True` |
| REPORT_MASTER_v3 | `True` |
| REPORT_v2 | `True` |
| REPORT_TECHNICAL_v2 | `True` |
| REPORT_TECHNICAL_v3 | `True` |
| v2_min_chars | `True` |
| v3_min_chars | `True` |
| v2_heads | `True` |
| v3_heads | `True` |
| v2_fresh_vs_deep | `True` |
| v3_fresh_vs_deep | `True` |
| not_llm_env_failure_v2 | `True` |
| not_llm_env_failure_v3 | `True` |
| v2_no_missing_sections | `True` |
| verdict_lock_ok | `True` |
| quality_pack_ok | `True` |
| master_source_llm | `True` |
| tech2_source_llm | `True` |
| tech3_source_ok | `True` |
| tech2_no_stubs | `True` |
| no_tech2_fallback | `True` |
| quality_issues | `[]` |
| engine_citation_ok | `True` |

### Artifact paths (verify on disk)

- **REPORT_MASTER_v2:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/REPORT-MASTER-v2.md` exists=`True` bytes=`14777` mtime=`2026-08-08T15:11:58.053574+00:00`
  - sha256: `dfcd1aecb220ceac0f26b4b0f950db415bb596f808d4c76e8bee5a8309d3d251`
- **REPORT_MASTER_v3:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/REPORT-MASTER-v3.md` exists=`True` bytes=`47302` mtime=`2026-08-08T15:17:02.356658+00:00`
  - sha256: `8d6767f567bd870ce503107930a4c25d803a5c118f618558bc8832e4c0842b11`
- **REPORT_v2:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/REPORT-v2.md` exists=`True` bytes=`14777` mtime=`2026-08-08T15:11:58.053574+00:00`
  - sha256: `dfcd1aecb220ceac0f26b4b0f950db415bb596f808d4c76e8bee5a8309d3d251`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`44205` mtime=`2026-08-08T15:13:10.753791+00:00`
  - sha256: `c39d7aa300b3f086ae97b04e25c3fb39b856699eb4397ff582e5fa6d7623f850`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`36352` mtime=`2026-08-08T15:17:54.769937+00:00`
  - sha256: `4f09929e24aebe39de46a92dbf63429ee66ac1503a869ece0bbf1dbee91274ef`
- **report_v2_json:** `/opt/samples/logs/91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc/report-v2.json` exists=`True` bytes=`17623` mtime=`2026-08-08T15:13:10.757791+00:00`
  - sha256: `42b439165b7f368e91e87275f65840c86a6bf73b0618d0b105b4821103bc0a20`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 15:11:58 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: PackerUPX_CompresorGratuito_wwwupxsourceforgenet). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** UPX-packed generic malware
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

… [13867 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 15:17:02 UTC

# RE Report — 91b176fb0d65
_Generated 2026-08-08T15:17:02.350631+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=252c | cross_refs=True | llm_ok=True | runtime=15.41s -->

```json
{
  "title": "Executive Summary",
  "markdown": "This malware sample (SHA256: `91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc`) is assessed as **suspicious** with **high confidence (90%)**, likely belonging to the **UPX-packed generic malware** family. Multiple analysis tools indicate this classification, though there is disagreement between analysis p
… [46386 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
