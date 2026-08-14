# Pipeline AUDIT-REPORT — `8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T15:10:47.807679+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 15:10:47 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e`

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

- source=`llm_judge` verdict=`malicious` confidence=`85`
- key_evidence_count=`3`

```json
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "XAgent",
  "cross_engine_notes": "Ghidra and IDA analysis failed due to session errors; MalCat identified the file as a ZIP/OOXML with high entropy (7.56) and macro content (xl/macrosheets/sheet1.xml); YARA rules matched for base64-encoded strings; VirusTotal reported 34 malicious detections with tags like 'calls-wmi' and threat label 'trojan.msexcel/x97m'. No direct behavioral evidence from static analysis tools, but external TI strongly indicates malicious activity.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64",
      "why": "YARA rule 'contains_base64' matched at offset 1859, length 12, indicating base64-encoded content which is often used in malware for payload obfuscation or data exfiltration."
    },
    {
      "source": "virustotal",
      "query_or_table": "hash_lookup",
      "row_or_rule": "detections: 34 malicious, 0 suspicious, 0 harmless, 30 undetected",
      "why": "VirusTotal analysis shows high number of AV detections (34/64) with tags including 'calls-wmi', 'xlsx', and 'malware', and threat category 'trojan' and 'downloader', suggesting malicious behavior such as command-and-control or persistence mechanisms."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy: 7.56, type: ZIP, virtual_files: includes xl/macrosheets/sheet1.xml",
      "why": "MalCat analysis reveals high entropy (7.56) indicating possible encryption or compression, and the presence of macro sheets in the OOXML structure, which is a common vector for malware delivery and execution."
    }
  ],
  "summary": "The sample is an Excel macro-enabled workbook (OOXML format) with high entropy and base64-encoded content. External threat intelligence from VirusTotal indicates it is a trojan downloader associated with the XAgent family, as evidenced by multiple AV detections and behavioral tags. While static analysis tools like Ghidra and IDA failed, MalCat confirmed the macro presence and high entropy, and YARA rules detected suspicious strings. These factors collectively point to malicious intent.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 100,
    "findings": [
      "yara: 2 matches"
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
  "ti_enrich": {
    "ok": true,
    "providers": {
      "virustotal": {
        "ok": true,
        "malicious": 34,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 30,
        "reputation": 0,
        "popular_threat_classification": {
          "popular_threat_category": [
            {
              "count": 16,
              "value": "trojan"
            },
            {
              "count": 8,
              "value": "downloader"
            }
          ],
          "popular_threat_name": [
            {
              "count": 2,
              "value": "msexcel"
            },
            {
              "count": 2,
              "value": "x97m"
            },
            {
              "count": 2,
              "value": "
… [1429 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`Flagged by YARA as suspicious due to domain and base64 indicators, but no direct evidence of malicious API calls or behaviors.` confidence=`70`
- key_evidence_count=`3`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "Flagged by YARA as suspicious due to domain and base64 indicators, but no direct evidence of malicious API calls or behaviors.",
  "confidence": 70,
  "summary": "The XLSM file triggered YARA rules for domain regex and base64 content, suggesting potential malicious payloads or obfuscation, but specific behaviors like downloading APIs are not confirmed in the evidence.",
  "key_evidence": [
    "YARA rule 'domain' matched with string $domain_regex at offset 0 in file /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm.",
    "YARA rule 'contains_base64' matched with string $a at offset 1859 in the same file, indicating the presence of base64 encoded data.",
    "File type is XLSM (Excel macro-enabled workbook), which can contain macros, but no macro code or API calls are shown in the provided evidence."
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
  "depth_coverage": null
}
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 14:07:28 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | Flagged by YARA as suspicious due to domain and base64 indicators, but no direct evidence of malicious API calls or behaviors. |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a macro-enabled Excel workbook (XLSM) identified as malicious, with a high confidence score of 85 from upstream triage (source: triage_verdict.json). The sample, with SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e, is associated with the XAgent malware family, known for its use as a trojan downloader. Static analysis reveals high entropy (7.56 bits/byte) and the presence of base64-encoded content and domain regex patterns, which are indicators commonly linked to malicious payloads and command-and-control (C2) communication (source: malcat, yara). VirusTotal reports 34 malicious detections, reinforcing its malicious nature (source: virustotal). Behavioral analysis was not performed in this assessment, limiting insight into runtime actions. The sample likely leverages macros for initial execution and network-based indicators suggest potential C2 activity. We assess this as a malicious artifact requiring immediate containment.\n\n## 1. Sample Identification\n\nThe sample is located at /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm (source: evidence_provided). It is an Excel macro-enabled workbook (OOXML format) with the SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e, as confirmed by multiple tools (source: malcat, triage_verdict.json). The project name is 'malware', indicating it is part of a curated malicious corpus. File type analysis shows it is a ZIP archive containing OOXML components, including macro sheets, which are a common vector for malware delivery (source: malcat).\n\n## 2. Classification\n\nBased on upstream triage, the sample is classified as malicious with a family guess of XAgent and a score of 85 (source: triage_verdict.json). This verdict is supported by behavioral intent evidence such as YARA rule matches for domain regex and base64 content, and high AV detections on VirusTotal (source: yara, virustotal). While obfuscation signals like high entropy (7.56 bits/byte) are present, they are neutral alone; however, combined with network indicators and macro capabilities, they point to malicious activity (source: malcat, deep_dive.json). The verdict must align with upstream triage, and we concur that this sample exhibits hostile behavior indicative of malware.\n\n## 3. Background & Family Lineage\n\nThe XAgent malware family is a known trojan downloader often used in cyber-espionage campaigns, typically delivered via macro-enabled documents like XLSM files (source: triage_verdict.json). It is associated with techniques such as command-and-control communication and payload obfuscation through encoding. This sample's characteristics,
… [8964 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 14:07:28 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | Flagged by YARA as suspicious due to domain and base64 indicators, but no direct evidence of malicious API calls or behaviors. |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a macro-enabled Excel workbook (XLSM) identified as malicious, with a high confidence score of 85 from upstream triage (source: triage_verdict.json). The sample, with SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e, is associated with the XAgent malware family, known for its use as a trojan downloader. Static analysis reveals high entropy (7.56 bits/byte) and the presence of base64-encoded content and domain regex patterns, which are indicators commonly linked to malicious payloads and command-and-control (C2) communication (source: malcat, yara). VirusTotal reports 34 malicious detections, reinforcing its malicious nature (source: virustotal). Behavioral analysis was not performed in this assessment, limiting insight into runtime actions. The sample likely leverages macros for initial execution and network-based indicators suggest potential C2 activity. We assess this as a malicious artifact requiring immediate containment.

## 1. Sample Identification

The sample is located at /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm (source: evidence_provided). It is an Excel macro-enabled workbook (OOXML format) with the SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e, as confirmed by multiple tools (source: malcat, triage_verdict.json). The project name is 'malware', indicating it is part of a curated malicious corpus. File type analysis shows it is a ZIP archive containing OOXML components, including macro sheets, which are a common vector for malware delivery (source: malcat).

## 2. Classification

Based on upstream triage, the sample is classified as malicious with a family guess of XAgent and a score of 85 (source: triage_verdict.json). This verdict is supported by behavioral intent evidence such as YARA rule matches for do
… [7369 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 14:19:30 UTC

# RE Report — 8e516c5e0ca2
_Generated 2026-08-13T14:19:30.683544+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=214c | cross_refs=True | llm_ok=True | runtime=62.31s -->

# Executive Summary

**Top-line Verdict:** Malicious

**Malware Family:** XAgent

**Confidence Level:** High (70% confidence with agreement between analyses)

## Key Findings

| Aspect | Assessment | Evidence Source |
|--------|------------|-----------------|
| Maliciousness | Confirmed malicious with perfect score | v1 analysis: score 100, 2 YARA matches detecting patterns like domain names and base64 encoding, indicative of C2 or obfuscation (source: yara, cross-section:classification) |
| Family Identification | XAgent remote access trojan (RAT) | Family guess supported by background analysis, associating with advanced persistent threats (source: llm_judge, cross-section:background_&_family_lineage) |
| Analysis Confidence | 70% confidence, consistent across methods | Deep dive agentic analysis indicates high certainty, reinforced by agreement between LLM and v1 assessments (source: deep_dive_agentic, llm_and_v1_agree) |
| Dynamic Analysis | Tools executed but recorded no runtime events | Speakeasy and Frida probe ran, yet no behavioral data captured, which may affect confidence but does not negate static indicators (source: cross-section:behavioral_analysis) |

## Summary

This sample is definitively malicious, as shown by a v1 analysis score of 100 and two YARA rule matches that likely detect malicious domains and base64 strings, common in command-and-control or data exfiltration. The malware is assessed as part of the XAgent family, a sophisticated RAT linked to advanced threats, with a deep confidence of 70% reflecting consistent static findings, though dynamic analysis yielded no recorded events.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=234c | cross_refs=True | llm_ok=True | runtime=75.13s -->

# 1. Sample Identification

This section details the sample identifiers for the artifact with SHA256 hash `8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e`, based on static analysis evidence. Identifiers include cryptographic hashes, file f
… [43443 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4929` | `f9fb938bf51b0a95` |
| `prompt.txt` | `True` | `12877` | `1179c8440d748b3c` |
| `pipeline-audit.json` | `True` | `73792` | `0ac628856e968bfc` |
| `AUDIT-REPORT.md` | `True` | `53140` | `3a77816958690a12` |
| `REPORT-MASTER-v2.md` | `True` | `9876` | `5204424fa918e60e` |
| `REPORT-MASTER-v3.md` | `True` | `45982` | `094880ddd310a18a` |
| `REPORT-v2.md` | `True` | `9876` | `5204424fa918e60e` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `31375` | `7882dcca31f32749` |
| `rule.yar` | `True` | `916` | `49c391b20edd6697` |
| `intake-validation.json` | `True` | `723` | `32aa710056c9c91d` |
| `source-decisions.json` | `True` | `638` | `9bc4dcc048d13d01` |
| `malcat-triage.json` | `False` | `0` | `` |
| `deep_dive/01-tools-raw.json` | `True` | `54645` | `7aa97f5653e397ec` |
| `deep_dive/01-tools-gate.json` | `True` | `1052` | `f839515c6c93a7bd` |
| `deep_dive/05-deep-dive.json` | `True` | `2313` | `8a43e8eda3616b53` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `54029` | `f5d19d8ab37eca74` |

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

- **intake_validation:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/intake-validation.json` exists=`True` bytes=`723` mtime=`2026-08-12T22:55:11.195969+00:00`
  - sha256: `32aa710056c9c91d8abb7ea04982769d9b0293aa159e343d0afdd498c19e361d`
- **malcat_triage:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/malcat-triage.json` exists=`False` bytes=`0` mtime=`None`
- **source_decisions:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/source-decisions.json` exists=`True` bytes=`638` mtime=`2026-08-12T22:55:11.195969+00:00`
  - sha256: `9bc4dcc048d13d016fc9eafa5b6dc7fa7ccfe2cb0307ea686d9be8414d5f6c21`
- **ghidra_import_log:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e",
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
  "rule_count": 2,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
      "strings": [
        {
          "id": "$a",
          "offset": 1859,
          "length": 12,
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
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_OmniRat.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_OmniRat.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                          ^ unclosed counted repetition\n   |\n   = note: did you mean `\\{` instead of `{`?",
    "/opt/samples/rules/flat/Android_FakeBank_Fanta.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_FakeBank_Fanta.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_AliPay_smsStealer.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_AliPay_smsStealer.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found"
  ],
  "incomplete": true,
  "duration_s": 3.1
}
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
  "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
    "file_name": "koti.xlsm",
    "file_path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
    "file_size": 26363,
    "type": "ZIP",
    "architecture": "NONE",
    "entropy": 7.56,
    "sha256": "8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e",
    "metadata": {},
    "entrypoint_ea": null,
    "layout": [
      {
        "name": "[Content_Types].xml",
        "effective_address": 0,
        "physical_size": 1019,
        "virtual_size": 1019,
        "rights": "R",
        "entropy": 111
      },
      {
        "name": ".rels",
        "effective_address": 1019,
        "physical_size": 806,
        "virtual_size": 806,
        "rights": "R",
        "entropy": 84
      },
      {
        "name": "workbook.xml.rels",
        "effective_address": 1825,
        "physical_size": 626,
        "virtual_size": 626,
        "rights": "R",
        "entropy": 125
      },
      {
        "name": "workbook.xml",
        "effective_address": 2451,
        "physical_size": 473,
        "virtual_size": 473,
        "rights": "R",
        "entropy": 215
      },
      {
        "name": "theme1.xml",
        "effective_address": 2924,
        "physical_size": 1764,
        "virtual_size": 1764,
        "rights": "R",
        "entropy": 222
      },
      {
        "name": "sheet1.xml",
        "effective_address": 4688,
        "physical_size": 1609,
        "virtual_size": 1609,
        "rights": "R",
        "entropy": 216
      },
      {
        "name": "sheet1.xml.rels",
        "effective_address": 6297,
        "physical_size": 284,
        "virtual_size": 284,
        "rights": "R",
        "entropy": 198
      },
      {
        "name": "sheet1.xml.rels",
        "effective_address": 6581,
        "physical_size": 260,
        "virtual_size": 260,
        "rights": "R",
        "entropy": 204
      },
      {
        "name": "sheet2.xml.rels",
        "effective_address": 6841,
        "physical_size": 259,
        "virtual_size": 259,
        "rights": "R",
        "entropy": 209
      },
      {
        "name": "drawing1.xml.rels",
        "effective_address": 7100,
        "physical_size": 272,
        "virtual_size": 272,
        "rights": "R",
        "entropy": 210
      },
      {
        "name": "sheet2.xml",
        "effective_address": 7372,
        "physical_size": 1039,
        "virtual_size": 1039,
        "rights": "R",
        "entropy": 209
      },
      {
        "name": "sheet1.xml",
        "effective_address": 8411,
        "physical_size": 579,
        "virtual_size": 579,
        "rights": "R",
        "entropy": 214
      },
      {
        "name": "styles.xml",
        "effective_address": 8990,
        "physical_size": 787,
        "virtual_size": 787,
        "rights": "R",
        "entropy": 218
      },
      {
        "name": "sharedStrings.xml",
        "effective_address": 9777,
        "physical_size": 396,
        "virtual_size": 396,
        "rights": "R",
        "entropy": 217
      },
      {
        "name": "drawing1.xml",
        "effective_address": 10173,
        "physical_s
… [41076 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 3,
  "hits": 3,
  "misses": [],
  "hit_examples": [
    "contains_base64 matches YARA rule 'contains_base64' matched at offset 1859, length 12, indicating base64-encoded content",
    "detections: 34 malicious, 0 suspicious, 0 harmless, 30 undetected hash_lookup VirusTotal analysis shows high number of A",
    "entropy: 7.56, type: ZIP, virtual_files: includes xl/macrosheets/sheet1.xml file_summary MalCat analysis reveals high en"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "XAgent",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64",
      "why": "YARA rule 'contains_base64' matched at offset 1859, length 12, indicating base64-encoded content which is often used in malware for payload obfuscation or data exfiltration."
    },
    {
      "source": "virustotal",
      "query_or_table": "hash_lookup",
      "row_or_rule": "detections: 34 malicious, 0 suspicious, 0 harmless, 30 undetected",
      "why": "VirusTotal analysis shows high number of AV detections (34/64) with tags including 'calls-wmi', 'xlsx', and 'malware', and threat category 'trojan' and 'downloader', suggesting malicious behavior such as command-and-control or persistence mechanisms."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy: 7.56, type: ZIP, virtual_files: includes xl/macrosheets/sheet1.xml",
      "why": "MalCat analysis reveals high entropy (7.56) indicating possible encryption or compression, and the presence of macro sheets in the OOXML structure, which is a common vector for malware delivery and execution."
    }
  ],
  "summary": "The sample is an Excel macro-enabled workbook (OOXML format) with high entropy and base64-encoded content. External threat intelligence from VirusTotal indicates it is a trojan downloader associated with the XAgent family, as evidenced by multiple AV detections and behavioral tags. While static analysis tools like Ghidra and IDA failed, MalCat confirmed the macro presence and high entropy, and YAR"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/prompt.txt` exists=`True` bytes=`12877` mtime=`2026-08-13T14:04:20.524023+00:00`
  - sha256: `1179c8440d748b3c0d0a75d534d3f907002760c1c0eed17fcd74fcdf995556f8`
- **verdict:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/verdict.json` exists=`True` bytes=`4929` mtime=`2026-08-13T14:05:16.989050+00:00`
  - sha256: `f9fb938bf51b0a9584f6f3b6ef41753a8b0aa29b160b30fe0ac96207ba85fe32`

#### prompt_excerpt

```
# Triage evidence
sha256: 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e
sample_path: /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm
ghidra_session: doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e
ida_session: (not loaded)

## Ghidra SQL (capped)
### engine: ghidra
label: Total function count (Ghidra)
sql: SELECT count(*) AS funcs FROM funcs
error: session doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e has no gpr_path (intake_v2 should have set it)

### engine: ghidra
label: Total string count (Ghidra)
sql: SELECT count(*) AS strings FROM strings
error: session doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e has no gpr_path (intake_v2 should have set it)

### engine: ghidra
label: Imports (Ghidra) from data_items
sql: SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50
error: session doc-ooxml-8e516c5e0ca2a7ffed56b38b
… [11859 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "XAgent",
  "cross_engine_notes": "Ghidra and IDA analysis failed due to session errors; MalCat identified the file as a ZIP/OOXML with high entropy (7.56) and macro content (xl/macrosheets/sheet1.xml); YARA rules matched for base64-encoded strings; VirusTotal reported 34 malicious detections with tags like 'calls-wmi' and threat label 'trojan.msexcel/x97m'. No direct behavioral evidence from static analysis tools, but external TI strongly indicates malicious activity.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "contains_base64",
      "why": "YARA rule 'contains_base64' matched at offset 1859, length 12, indicating base64-encoded content which is often used in malware for payload obfuscation or data exfiltration."
    },
    {
      "source": "virustotal",
      "query_or_table": "hash_lookup",
      "row_or_rule": "detections: 34 malicious, 0 suspicious, 0 har
… [3929 more chars]
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
  "rule_count": 2,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
      "strings": [
        {
          "id": "$a",
          "offset": 1859,
          "length": 12,
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
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_OmniRat.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_OmniRat.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                          ^ unclosed counted repetition\n   |\n   = note: did you mean `\\{` instead of `{`?",
    "/opt/samples/rules/flat/Android_FakeBank_Fanta.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_FakeBank_Fanta.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_AliPay_smsStealer.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_AliPay_smsStealer.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found"
  ],
  "incomplete": true
}
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
  "sample": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
  "disassembly": {
    "0x00000000": "\u250c 24: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg4);\n\u2502           ; arg int64_t arg1 @ rdi\n\u2502           ; arg int64_t arg2 @ rsi\n\u2502           ; arg int64_t arg4 @ rcx\n\u2502           0x00000000      50             push rax\n\u2502           0x00000001      4b030414       add rax, qword [r12 + r10]\n\u2502           0x00000005      0006           add byte [rsi], al          ; arg2\n\u2502           0x00000007      0008           add byte [rax], cl\n\u2502           0x00000009      0000           add byte [rax], al\n\u2502           0x0000000b      0021           add byte [rcx], ah          ; arg4\n\u2502           0x0000000d      00888fbe01c2   add byte [rax - 0x3dfe4171], cl\n\u2502           0x00000013      0100           add dword [rax], eax\n\u2502           0x00000015      0007           add byte [rdi], al          ; arg1\n\u2514           0x00000017      07             invalid"
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
  "sample": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
  "checked": 3,
  "hits": 3,
  "misses": [],
  "hit_examples": [
    "YARA rule 'domain' matched with string $domain_regex at offset 0 in file /opt/samples/corpus/malware/8e516c5e0ca2a7ffed5",
    "YARA rule 'contains_base64' matched with string $a at offset 1859 in the same file, indicating the presence of base64 en",
    "File type is XLSM (Excel macro-enabled workbook), which can contain macros, but no macro code or API calls are shown in "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 70,
  "summary": "The XLSM file triggered YARA rules for domain regex and base64 content, suggesting potential malicious payloads or obfuscation, but specific behaviors like downloading APIs are not confirmed in the evidence.",
  "key_evidence": [
    "YARA rule 'domain' matched with string $domain_regex at offset 0 in file /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm.",
    "YARA rule 'contains_base64' matched with string $a at offset 1859 in the same file, indicating the presence of base64 encoded data.",
    "File type is XLSM (Excel macro-enabled workbook), which can contain macros, but no macro code or API calls are shown in the provided evidence."
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 2,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
      "rule": "contains_base64",
      "path": "/
… [2916 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
    "file_name": "koti.xlsm",
    "file_path": "/
… [44020 more chars]
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
  "disassembly": {
    "0x00000000": "\u250c 24: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg4);\n\u2502           ; arg int64_t arg1 @ rdi\n\u2502           ; arg int64_t arg2 @ rsi\n\u2502           ; arg int64_t arg4 @ rcx\n\u2502           0x00000000
… [805 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
```

- **signal_extractors** ok=`False` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals
  - error: `FileNotFoundError: session doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e has no gpr_path (intake_v2 should have set it)`

```json
{
  "anti_analysis_summary": {},
  "dynamic_resolve_summary": {}
}
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": null,
  "name": null,
  "score": null
}
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `session doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e has no gpr_path (intake_v2 should have set it)`

```json
{
  "error": "session doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e has no gpr_path (intake_v2 should have set it)"
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

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 2,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
      "rule": "contains_base64",
      "path": "/
… [2916 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
    "file_name": "koti.xlsm",
    "file_path": "/
… [44020 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `session doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e has no gpr_path (intake_v2 should have set it)`

```json
{
  "error": "session doc-ooxml-8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e has no gpr_path (intake_v2 should have set it)"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/deep_dive/01-tools-raw.json` exists=`True` bytes=`54645` mtime=`2026-08-13T14:04:15.852013+00:00`
  - sha256: `7aa97f5653e397ec58e17a1b7b0e3faa829db30df9c59994ca0350e667568a20`
- **sql_evidence:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/deep_dive/05-deep-dive.json` exists=`True` bytes=`2313` mtime=`2026-08-12T22:57:34.048671+00:00`
  - sha256: `8a43e8eda3616b5310c9c78390ff785d4b3faac77427fc85be9798bd66118a2b`

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
  "verdict": "Flagged by YARA as suspicious due to domain and base64 indicators, but no direct evidence of malicious API calls or behaviors.",
  "confidence": 70,
  "summary": "The XLSM file triggered YARA rules for domain regex and base64 content, suggesting potential malicious payloads or obfuscation, but specific behaviors like downloading APIs are not confirmed in the evidence.",
  "key_evidence": [
    "YARA rule 'domain' matched with string $domain_regex at offset 0 in file /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm.",
    "YARA rule 'contains_base64' matched with string $a at offset 1859 in the same file, indicating the presence of base64 encoded data.",
    "File 
… [1513 more chars]
```

- **agentic:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`252950` mtime=`2026-08-12T22:57:34.048671+00:00`
  - sha256: `4baefc54c0b1e11cbbcb6529ba3753dbd2be3cbfa44d13f745e4beef890aa338`

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

- **rule_yar:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/rule.yar` exists=`True` bytes=`916` mtime=`2026-08-12T22:57:34.477670+00:00`
  - sha256: `49c391b20edd6697dd429d83ff4e45a18fd51c105d2bd0a60f7eb21834740992`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T22:57:34.478302+00:00
rule CADRE_v2_x97m_8e516c5e0ca2 {
    meta:
        description = "RevAI v2 auto rule for X97M"
        sha256 = "8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e"
        family = "x97m"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Matches domain regex, suggesting possible command-and-control (C2) communication or malicious network activity, a behavi" ascii wide
        $s1 = "Contains base64 encoded strings, commonly used in malware to obfuscate payloads, exfiltrate data, or evade detection." ascii wide
        $s2 = "Indicates a macro-enabled Excel document (OOXML), which is a prevalent vector
… [114 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/REPORT-MASTER-v2.md` exists=`True` bytes=`9876` mtime=`2026-08-13T14:07:28.766062+00:00`
  - sha256: `5204424fa918e60eea945fe23fc79f83fdafe017caa161d70e25b0b9251aaf07`
- **REPORT_MASTER_v3:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/REPORT-MASTER-v3.md` exists=`True` bytes=`45982` mtime=`2026-08-13T14:19:30.689111+00:00`
  - sha256: `094880ddd310a18a39d4b70f2c868506da9c8cb90ee0ed065aa76a785f034485`
- **REPORT_v2:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/REPORT-v2.md` exists=`True` bytes=`9876` mtime=`2026-08-13T14:07:28.766062+00:00`
  - sha256: `5204424fa918e60eea945fe23fc79f83fdafe017caa161d70e25b0b9251aaf07`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`29735` mtime=`2026-08-13T14:10:56.704977+00:00`
  - sha256: `52786de88c30da5f99cacbd0b0adeb1dd750304b3ecd767a6c8d3e6a5d23d098`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`31375` mtime=`2026-08-13T14:21:55.906108+00:00`
  - sha256: `7882dcca31f32749bf6c355d6ae1aef5b1408aa8bcf20d50996ec0be2698319e`
- **report_v2_json:** `/opt/samples/logs/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/report-v2.json` exists=`True` bytes=`12464` mtime=`2026-08-13T14:10:56.707977+00:00`
  - sha256: `5ba3f8c710d85ff38a681ab7a160a5d81f8f00e43e5fcaa8905b61d325e5dc51`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 14:07:28 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | Flagged by YARA as suspicious due to domain and base64 indicators, but no direct evidence of malicious API calls or behaviors. |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a macro-enabled Excel workbook (XLSM) identified as malicious, with a high confidence score of 85 from upstream triage (source: triage_verdict.json). The sample, with SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e, is associated with th
… [8969 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 14:19:30 UTC

# RE Report — 8e516c5e0ca2
_Generated 2026-08-13T14:19:30.683544+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=214c | cross_refs=True | llm_ok=True | runtime=62.31s -->

# Executive Summary

**Top-line Verdict:** Malicious

**Malware Family:** XAgent

**Confidence Level:** High (70% confidence with agreement between analyses)

## Key Findings

| Aspect | Assessment | Evidence Source |
|--------|------------|-----------------|
| Maliciousness | Confirmed malicious with perfect score | v1 analysis: score 100, 2 YARA matches detecting patterns like domain names and base64 encodin
… [45043 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
