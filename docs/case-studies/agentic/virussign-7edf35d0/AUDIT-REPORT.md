# Pipeline AUDIT-REPORT — `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:25.195912+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:25 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`

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

- source=`llm_judge` verdict=`suspicious` confidence=`60`
- key_evidence_count=`3`

```json
{
  "verdict": "suspicious",
  "score": 60,
  "family_guess": "Themida-packed sample with potential token misuse; no specific malware family identified",
  "cross_engine_notes": "Tool divergence is high due to packing: Ghidra detects 23 functions but 0 imports (known limitation for this sample), IDA shows only 2 functions and 3 imports, while Malcat reports 15 functions and mid-signal imports including OpenProcessToken. String extraction varies widely (Ghidra=54, IDA=18756, Malcat=297), with IDA providing extensive strings. Decompilation efforts failed or produced errors, consistent with Themida packing. Behavioral signals are consistent across YARA (win_token) and Malcat (OpenProcessToken import).",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule \"packed with Themida\"",
      "row_or_rule": "ATT&CK T1027.002 (Defense Evasion: Obfuscated Files or Information: Software Packing)",
      "why": "Indicates obfuscation/packing, which is a neutral signal per calibration but contributes to the sample's profile as protected software."
    },
    {
      "source": "yara",
      "query_or_table": "rule \"win_token\"",
      "row_or_rule": "match at offset in the file",
      "why": "Behavioral-intent evidence: YARA rule win_token suggests token manipulation patterns, which could indicate privilege escalation or impersonation capabilities, warranting further analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "imports (mid-signal list)",
      "row_or_rule": "advapi32.OpenProcessToken",
      "why": "API import for token access; OpenProcessToken is commonly used in malicious contexts for privilege escalation, though it can also appear in legitimate software. This is behavioral-intent evidence per calibration."
    }
  ],
  "summary": "This sample is a Themida-packed PE file (X86, high entropy 224) with numerous packing anomalies (e.g., CrossSectionJump, HighEntropy) and obfuscated code. Behavioral signals include the YARA rule win_token and the import of advapi32.OpenProcessToken, indicating potential token manipulation for privilege misuse. However, no definitive malicious behaviors such as C2 communication, file encryption, persistence mechanisms, or credential theft were observed in the provided evidence. Tool divergence due to packing complicates analysis, but the convergence on token-related signals justifies a suspicious classification. Further investigation is needed to determine if the sample exhibits hostile intent beyond protection and potential token abuse.",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 10 matches",
      "capa: 3 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 10 matches",
      "capa: 3 rules"
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
    "la
… [915 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`4`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "The file is a Windows DLL (PE X86) with high entropy and multiple YARA rule matches, including win_token indicating token manipulation, suggesting malicious activity such as privilege escalation or network communication. Persistence: not observed. Exfiltration: not observed. Credential_access: not observed. Encryption_obfuscation: High entropy indicates potential encryption or obfuscation {summary, analysis, high entropy detection, high entropy is commonly associated with encrypted or obfuscated code in malware analysis}. Imports: not observed.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "rule matches",
      "row_or_rule": "win_token",
      "why": "Matches strings at offsets 172606 and 172621, indicating potential token manipulation often used in malware for privilege escalation."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "rule matches",
      "row_or_rule": "IsPE32",
      "why": "Rule matches confirm the file is a Windows PE executable, a common format for malware distribution."
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "file_summary",
      "row_or_rule": "type",
      "why": "Analysis identifies the file as a PE with architecture X86 and high entropy (224), which may indicate obfuscation or packing."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "rule matches",
      "row_or_rule": "domain",
      "why": "Matches domain patterns, suggesting possible network communication capabilities typical in malware."
    }
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 29,
  "successful_non_bootstrap_tools": 18,
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
  "depth_coverage": true
}
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Themida-Packed DLL with Token Manipulation Signals",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 19:01:09 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report presents a technical analysis of a Windows DLL (X86) identified by SHA-256: `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`. The sample exhibits characteristics of commercial software packing (Themida) and contains numerous code anomalies. Crucially, YARA rule `win_token` fired and the import of `advapi32.OpenProcessToken` indicates potential token manipulation capabilities, which could be used for privilege escalation or impersonation. However, no definitive runtime behaviors such as C2 communication, file encryption, persistence, or credential theft were observed in the provided static evidence. The high entropy and packing anomalies complicate analysis, but the convergence on token-related signals leads to a **suspicious** classification. The upstream triage verdict is confirmed as suspicious, pending further behavioral investigation.\n\n## 1. Sample Identification\n\nThe sample under analysis is a Windows Dynamic Link Library (DLL) file. Its SHA-256 hash is `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`. The file was sourced from the project `incoming` and is located at `/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir`. The file type is a PE (Portable Executable) format, specifically an X86 DLL. (Source: malcat, pe_imports).\n\n## 2. Classification\n\n**Verdict: Suspicious** (Upstream Triage Score: 60/100). The sample is classified as suspicious due to the presence of obfuscation/packing and behavioral-intent signals suggesting potential token abuse, but the absence of observed malicious runtime activities. The classification aligns with the upstream triage verdict, which identified the sample as a \"Themida-packed sample with potential token misuse; no specific malware family identified.\" We note the sample is a DLL and exhibits dual-use potential, but without concrete evidence of hostile execution context, a malicious verdict is not fully supported.\n\n| Attribute       | Value                                  |\n|-----------------|----------------------------------------|\n| File Type       | PE DLL (X86)                           |\n| Packing         | Yes (Themida) (Source: capa)           |\n| Entropy         | 224 (High) (Source: malcat)            |\n| Key Behavioral Signals | Token manipulation (win_token, OpenProcessToken) |\n\n## 3. Background & Family Lineage\n\nNo specific malware family has been identified for this sample. The primary indicator of protection is Themida, a commercial software protector, as detected by the capa rule `packed with Themida` (Source: capa). The sample contains numerous strings related to a `CStringLoader` class (e.g., `CreateStringLoader`, `DestroyStringLoader`, `ReadBufferFromFile`, `WriteBuffe
… [14272 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 19:01:09 UTC

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

This report presents a technical analysis of a Windows DLL (X86) identified by SHA-256: `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`. The sample exhibits characteristics of commercial software packing (Themida) and contains numerous code anomalies. Crucially, YARA rule `win_token` fired and the import of `advapi32.OpenProcessToken` indicates potential token manipulation capabilities, which could be used for privilege escalation or impersonation. However, no definitive runtime behaviors such as C2 communication, file encryption, persistence, or credential theft were observed in the provided static evidence. The high entropy and packing anomalies complicate analysis, but the convergence on token-related signals leads to a **suspicious** classification. The upstream triage verdict is confirmed as suspicious, pending further behavioral investigation.

## 1. Sample Identification

The sample under analysis is a Windows Dynamic Link Library (DLL) file. Its SHA-256 hash is `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`. The file was sourced from the project `incoming` and is located at `/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir`. The file type is a PE (Portable Executable) format, specifically an X86 DLL. (Source: malcat, pe_imports).

## 2. Classification

**Verdict: Suspicious** (Upstream Triage Score: 60/100). The sample is classified as suspicious due to the presence of obfuscation/packing and behavioral-intent signals suggesting potential token abuse, but the absence of observed malicious runtime activities. The classification aligns with the upstream triage verdict, which identified the sample as a "Themida-packed sample with potential token misuse; no specific malware family identified." We note the sample is a DLL and exhibits dual-use potential, but without concrete evidence of hostile execution context, a 
… [12732 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 18:58:46 UTC

# RE Report — 3476906b2c72
_Generated 2026-08-08T18:58:46.258075+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=314c | cross_refs=True | llm_ok=True | runtime=32.78s -->

## Executive Summary

The malware sample identified by SHA-256 hash **3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544** is assessed as **suspicious** with a high confidence of 90%, based on aggregated evidence from deep analysis (source: deep_dive_agentic). Discrepancies exist between automated verdicts, with one report indicating malicious intent (score 290 from YARA and CAPA matches) but lacking agreement (source: v1_summary, agreement: llm_v1_disagree). The sample is likely a Themida-packed executable, suggesting use of a commercial protector for obfuscation and evasion (source: yara).

### Key Findings

| Aspect | Evidence | Interpretation |
|--------|----------|----------------|
| **Packing and Evasion** | Themida packing detected via YARA rules and static anomalies (source: yara, cross-section: Static Analysis) | Likely used to hinder analysis and evade defenses, with high confidence from signature matches. |
| **Suspicious Behaviors** | Anomalous runtime behaviors inferred from structural artifacts (source: malcat, cross-section: Behavioral Analysis) | Possibly indicates malicious intent, though specific actions are not detailed; moderate confidence due to indirect evidence. |
| **Capabilities** | Demonstrates MITRE ATT&CK T1027.002 (Obfuscated Files) and potential token misuse (source: capa, cross-section: Capability Assessment) | Suggests capabilities for defense evasion and credential abuse, but no specific malware family is identified. |
| **Network Indicators** | No network or C2 artifacts found (source: cross-section: Network Analysis & C2) | Limits attribution and indicates possible offline or delayed malicious activity. |
| **Detection Potential** | Multiple YARA matches for packing, IP addresses, and obfuscation (source: yara, cross-section: Detection Rules) | Supports detection efforts, with indicators like base64 encoding and IP addresses common in malware. |

Overall, we assess the sample as a Themida-packed ex
… [43104 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4415` | `71e00ae3f3175d2f` |
| `prompt.txt` | `True` | `19731` | `ba5e001a573882c5` |
| `pipeline-audit.json` | `True` | `102469` | `29922f1e403f2ebc` |
| `AUDIT-REPORT.md` | `True` | `76022` | `5cf0dd2a1bd5b65b` |
| `REPORT-MASTER-v2.md` | `True` | `15239` | `8b44d67f7c213fdd` |
| `REPORT-MASTER-v3.md` | `True` | `45619` | `7ed0d2e3d0bab422` |
| `REPORT-v2.md` | `True` | `15239` | `8b44d67f7c213fdd` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `48922` | `9d2049de0db682d5` |
| `rule.yar` | `True` | `1840` | `5474027771ae7095` |
| `intake-validation.json` | `True` | `2449` | `2bf35232770e3d12` |
| `source-decisions.json` | `True` | `1415` | `adf39a5b4b40bc35` |
| `malcat-triage.json` | `True` | `27638` | `2927d3dfaf0f23fc` |
| `deep_dive/01-tools-raw.json` | `True` | `71552` | `524beb4654e07c1c` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2952` | `e65c25f2d5baabc8` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `61297` | `1882eb9df7979965` |

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

- **intake_validation:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/intake-validation.json` exists=`True` bytes=`2449` mtime=`2026-08-08T14:07:41.934650+00:00`
  - sha256: `2bf35232770e3d12caa22834eedcd70a72b6b1e03d76ed0b21a1d7e2e1aff5d4`
- **malcat_triage:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/malcat-triage.json` exists=`True` bytes=`27638` mtime=`2026-08-08T14:06:42.490970+00:00`
  - sha256: `2927d3dfaf0f23fc970730191e3ef7ef08ea8b3afd29f721461a5dad88d6b60e`
- **source_decisions:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/source-decisions.json` exists=`True` bytes=`1415` mtime=`2026-08-08T14:07:41.934650+00:00`
  - sha256: `adf39a5b4b40bc3506d80e39f2c6b26460bdec2e73853787a2f06ccc030443ea`
- **ghidra_import_log:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/intake-idasql.log` exists=`True` bytes=`254` mtime=`2026-08-08T14:06:46.220940+00:00`
  - sha256: `ad24a71bffaedb71a84653e7615274f13bd6eaa796da407cf5036a1d320d9156`

#### source_decisions_excerpt

```
{
  "sha256": "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "imports": {
    "source": "malcat",
    "confidence": "high",
    "reason": "Malcat imports (27) are consistent with Ghidra (26) and provide a comprehensive view, whereas IDA shows low count (3) indicating potential extraction issues."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra detects more functions (23) than IDA (2) or Malcat (10), suggesting better coverage, but divergence exists across tools."
  },
  "strings": {
    "source": "ida",
    "confidence": "high",
    "reason": "IDA extracts a significantly higher number of strings (18756) compared to Malcat (100) and Ghidra (54), offering extensive data for analysis."
  },
  "decompilation": {
    "sourc
… [638 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
    "file_name": "virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
    "file_path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
    "file_size": 3166208,
    "type": "PE",
    "architecture": "X86",
    "entropy": 224,
    "sha256": "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
… [26838 more chars]
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
  "rule_count": 3,
  "top_rules": [
    {
      "name": "packed with Themida",
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
            "Themida"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Themida",
          "id": "F0001.011"
        }
      ]
    },
    {
      "name": "decompress data using aPLib",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decompress Data",
            "aPLib"
          ],
          "objective": "Data",
          "behavior": "Decompress Data",
          "method": "aPLib",
          "id": "C0025.003"
        }
      ]
    },
    {
      "name": "forwarded export",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 3166208,
  "duration_s": 1.55,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 36311,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 169512,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 1328583,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 232,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_token",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 172606,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 172621,
          "length": 16,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rul
… [2335 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 5014,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "@.edata",
    "@.idata",
    ".themida",
    "'1~`nV9F",
    "\\nxswz9C",
    "oh.n~L",
    "Uh~D8C",
    "?=RalLh\tk",
    "'{,.L%J",
    "s\\s`^#j",
    "\"THnOt",
    "w7v:n#",
    "O0,Kd?",
    "|S0|N&",
    "&xK[#[",
    "INb@T%",
    "WWH~|Y",
    "h(&<ul",
    "{'z4(iBpH",
    "wl9T9Hb",
    "D!IBf,OX",
    "rc~]j\"",
    "QH`l+[",
    "qrf4tv",
    "0rMjlUq",
    "cjCH%0",
    "g+Z?x`N",
    "T\\bC8$",
    "g$y[Tc",
    "VrdE#\"",
    "Q3e<KQ",
    "=h*kP?",
    "3eh1vZ",
    "H#+BV5",
    "v'+ST)",
    "[&@\\0Q",
    "5Zw\":!5",
    "#k][$o",
    "*Pt*XY",
    "fG?j99",
    ">bTXwuE",
    "+srL\\Z",
    "bXc=j-",
    "IIz3Ml",
    "1uP@!@",
    "}B;y,?",
    "H\\I{|>",
    "BOU.z]",
    "cMe\\E<",
    "KSY&}\"d",
    "| +LMf",
    "x*rQx-w",
    "{,Z\"{0Z6{4ZB{8ZR{<Zb{@Zr",
    "}A<s\"lrP",
    "',C|T\"v",
    ".1^`Qx_c",
    "^8KT'Ud",
    "Wzh)f4T",
    "Phh[<1",
    "30x(1Y)",
    ")\"IptT&",
    "QGmC2al",
    "pq}%qY",
    "J0K{'3",
    "/[=hpr",
    "COc1Hb",
    "Nv9\\{a",
    "yg^sLW",
    "]=_PWY8",
    "PV\"/jcvx",
    "&~l.sH",
    "y7P,$Il",
    "z%otfL#<",
    "jJS=p7VB",
    "jh+8Q*;",
    "0r%cr|",
    "fnk*nX",
    "gJn|MRx_L[*",
    "qTW,pg"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 5014
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 28.82,
  "size_bytes": 3166208,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
    "file_name": "virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
    "file_path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
    "file_size": 3166208,
    "type": "PE",
    "architecture": "X86",
    "entropy": 224,
    "sha256": "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
    "metadata": {
      "Exports::Module name": "StringLoaderA.dll"
    },
    "entrypoint_ea": 345176,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 205
      },
      {
        "name": "        ",
        "effective_address": 1024,
        "physical_size": 132096,
        "virtual_size": 241664,
        "rights": "RX",
        "entropy": 223
      },
      {
        "name": "        ",
        "effective_address": 242688,
        "physical_size": 26112,
        "virtual_size": 69632,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": "        ",
        "effective_address": 312320,
        "physical_size": 1024,
        "virtual_size": 8192,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": "        ",
        "effective_address": 320512,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": "        ",
        "effective_address": 324608,
        "physical_size": 8704,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".edata",
        "effective_address": 336896,
        "physical_size": 3072,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".idata",
        "effective_address": 340992,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".boot",
        "effective_address": 345088,
        "physical_size": 2993152,
        "virtual_size": 2994176,
        "rights": "RX",
        "entropy": 224
      },
      {
        "name": ".themida",
        "effective_address": 3339264,
        "physical_size": 0,
        "virtual_size": 4710400,
        "rights": "RWX",
        "entropy": 0
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
        "num_hits": 2
      },
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": 
… [43113 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 3,
  "hits": 3,
  "misses": [],
  "hit_examples": [
    "ATT&CK T1027.002 (Defense Evasion: Obfuscated Files or Information: Software Packing) rule \"packed with Themida\" Indicat",
    "match at offset in the file rule \"win_token\" Behavioral-intent evidence: YARA rule win_token suggests token manipulation",
    "advapi32.OpenProcessToken imports (mid-signal list) API import for token access; OpenProcessToken is commonly used in ma"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "Themida-packed sample with potential token misuse; no specific malware family identified",
  "score": 60,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule \"packed with Themida\"",
      "row_or_rule": "ATT&CK T1027.002 (Defense Evasion: Obfuscated Files or Information: Software Packing)",
      "why": "Indicates obfuscation/packing, which is a neutral signal per calibration but contributes to the sample's profile as protected software."
    },
    {
      "source": "yara",
      "query_or_table": "rule \"win_token\"",
      "row_or_rule": "match at offset in the file",
      "why": "Behavioral-intent evidence: YARA rule win_token suggests token manipulation patterns, which could indicate privilege escalation or impersonation capabilities, warranting further analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "imports (mid-signal list)",
      "row_or_rule": "advapi32.OpenProcessToken",
      "why": "API import for token access; OpenProcessToken is commonly used in malicious contexts for privilege escalation, though it can also appear in legitimate software. This is behavioral-intent evidence per calibration."
    }
  ],
  "summary": "This sample is a Themida-packed PE file (X86, high entropy 224) with numerous packing anomalies (e.g., CrossSectionJump, HighEntropy) and obfuscated code. Behavioral signals include the YARA rule win_token and the import of advapi32.OpenProcessToken, indicating potential token manipulation for privilege misuse. However, no definitive malicious behaviors such as C2 communication, file encryption, p"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/prompt.txt` exists=`True` bytes=`19731` mtime=`2026-08-08T18:29:41.450126+00:00`
  - sha256: `ba5e001a573882c53bbc87b089a1b0732cc372030542e37154ac00aafff64c03`
- **verdict:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/verdict.json` exists=`True` bytes=`4415` mtime=`2026-08-08T18:30:21.549135+00:00`
  - sha256: `71e00ae3f3175d2f83363a2acb5de085fc152cc509d025d264c394b81cc9f5da`

#### prompt_excerpt

```
# Triage evidence
sha256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
sample_path: /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir
ghidra_session: ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
ida_session: ida-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544

## Source decisions (from intake validation)
- imports: malcat (confidence=high) — Malcat imports (27) are consistent with Ghidra (26) and provide a comprehensive view, whereas IDA shows low count (3) indicating potential extraction issues.
- functions: ghidra (confidence=medium) — Ghidra detects more functions (23) than IDA (2) or Malcat (10), suggesting better coverage, but divergence exists across tools.
- strings: ida (confidence=high) — IDA extracts a significantly higher number of strings (18756) compared to Malcat (100) and Ghidra (54), offering extensive data for
… [18696 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 60,
  "family_guess": "Themida-packed sample with potential token misuse; no specific malware family identified",
  "cross_engine_notes": "Tool divergence is high due to packing: Ghidra detects 23 functions but 0 imports (known limitation for this sample), IDA shows only 2 functions and 3 imports, while Malcat reports 15 functions and mid-signal imports including OpenProcessToken. String extraction varies widely (Ghidra=54, IDA=18756, Malcat=297), with IDA providing extensive strings. Decompilation efforts failed or produced errors, consistent with Themida packing. Behavioral signals are consistent across YARA (win_token) and Malcat (OpenProcessToken import).",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule \"packed with Themida\"",
      "row_or_rule": "ATT&CK T1027.002 (Defense Evasion: Obfuscated Files or Information: Software Packing)",
      "why": "Indicates obfuscation/packing, which is a neutral signal per
… [3415 more chars]
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
  "rule_count": 3,
  "top_rules": [
    {
      "name": "packed with Themida",
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
            "Themida"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Themida",
          "id": "F0001.011"
        }
      ]
    },
    {
      "name": "decompress data using aPLib",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decompress Data",
            "aPLib"
          ],
          "objective": "Data",
          "behavior": "Decompress Data",
          "method": "aPLib",
          "id": "C0025.003"
        }
      ]
    },
    {
      "name": "forwarded export",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    }
  ],
  "timeout_s": 90,
  "sample_size": 3166208,
  "duration_s": 1.2,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 3166208,
  "duration_s": 0.04,
  "import_count": 3,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 36311,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 169512,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 1328583,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 232,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_token",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 172606,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 172621,
          "length": 16,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rul
… [2314 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 5014,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "@.edata",
    "@.idata",
    ".themida",
    "'1~`nV9F",
    "\\nxswz9C",
    "oh.n~L",
    "Uh~D8C",
    "?=RalLh\tk",
    "'{,.L%J",
    "s\\s`^#j",
    "\"THnOt",
    "w7v:n#",
    "O0,Kd?",
    "|S0|N&",
    "&xK[#[",
    "INb@T%",
    "WWH~|Y",
    "h(&<ul",
    "{'z4(iBpH",
    "wl9T9Hb",
    "D!IBf,OX",
    "rc~]j\"",
    "QH`l+[",
    "qrf4tv",
    "0rMjlUq",
    "cjCH%0",
    "g+Z?x`N",
    "T\\bC8$",
    "g$y[Tc",
    "VrdE#\"",
    "Q3e<KQ",
    "=h*kP?",
    "3eh1vZ",
    "H#+BV5",
    "v'+ST)",
    "[&@\\0Q",
    "5Zw\":!5",
    "#k][$o",
    "*Pt*XY",
    "fG?j99",
    ">bTXwuE",
    "+srL\\Z",
    "bXc=j-",
    "IIz3Ml",
    "1uP@!@",
    "}B;y,?",
    "H\\I{|>",
    "BOU.z]",
    "cMe\\E<",
    "KSY&}\"d",
    "| +LMf",
    "x*rQx-w",
    "{,Z\"{0Z6{4ZB{8ZR{<Zb{@Zr",
    "}A<s\"lrP",
    "',C|T\"v",
    ".1^`Qx_c",
    "^8KT'Ud",
    "Wzh)f4T",
    "Phh[<1",
    "30x(1Y)",
    ")\"IptT&",
    "QGmC2al",
    "pq}%qY",
    "J0K{'3",
    "/[=hpr",
    "COc1Hb",
    "Nv9\\{a",
    "yg^sLW",
    "]=_PWY8",
    "PV\"/jcvx",
    "&~l.sH",
    "y7P,$Il",
    "z%otfL#<",
    "jJS=p7VB",
    "jh+8Q*;",
    "0r%cr|",
    "fnk*nX",
    "gJn|MRx_L[*",
    "qTW,pg"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 5014
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 29.18,
  "size_bytes": 3166208,
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
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "disassembly": {
    "0x104d3058": "\u250c 336: entry0 ();\n\u2502           0x104d3058      e84b010000     call 0x104d31a8\n\u2502           0x104d305d      53             push ebx\n\u2502           0x104d305e      89e3           mov ebx, esp\n\u2502           0x104d3060      53             push ebx\n\u2502           0x104d3061      8b7308         mov esi, dword [ebx + 8]\n\u2502           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]\n\u2502           0x104d3067      fc             cld\n\u2502           0x104d3068      b280           mov dl, 0x80                ; 128\n\u2502       \u250c\u2500> 0x104d306a      8a06           mov al, byte [esi]\n\u2502       \u254e   0x104d306c      46             inc esi\n\u2502       \u254e   0x104d306d      8807           mov byte [edi], al\n\u2502       \u254e   0x104d306f      47             inc edi\n\u2502       \u254e   0x104d3070      bb02000000     mov ebx, 2\n\u2502       \u254e   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)\n\u2502  \u250c\u250c\u250c\u250c\u250c\u2500\u2500> 0x104d3075      00d2           add dl, dl\n\u2502 \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x104d3077      7505           jne 0x104d307e\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u254e   0x104d3079      8a16           mov dl, byte [esi]\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u254e   0x104d307b      46             inc esi\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u254e   0x104d307c      10d2           adc dl, dl\n\u2502 \u2514\u2500\u2500\u2500\u2500\u2500\u2514\u2500< 0x104d307e      73ea           jae 0x104d306a\n\u2502  \u254e\u254e\u254e\u254e\u254e    0x104d3080      00d2           add dl, dl\n\u2502  \u254e\u254e\u254e\u254e\u254e\u250c\u2500< 0x104d3082      7505           jne 0x104d3089\n\u2502  \u254e\u254e\u254e\u254e\u254e\u2502   0x104d3084      8a16           mov dl, byte [esi]\n\u2502  \u254e\u254e\u254e\u254e\u254e\u2502   0x104d3086      46             inc esi\n\u2502  \u254e\u254e\u254e\u254e\u254e\u2502   0x104d3087      10d2           adc dl, dl\n\u2502 \u250c\u2500\u2500\u2500\u2500\u2500\u2514\u2500> 0x104d3089      7351           jae 0x104d30dc\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e    0x104d308b      31c0           xor eax, eax\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e    0x104d308d      00d2           add dl, dl\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u250c\u2500< 0x104d308f      7505           jne 0x104d3096\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d3091      8a16           mov dl, byte [esi]\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d3093      46             inc esi\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d3094      10d2           adc dl, dl\n\u2502 \u2500\u2500\u2500\u2500\u2500\u2500\u2514\u2500> 0x104d3096      0f83e1000000   jae 0x104d317d\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e    0x104d309c      00d2           add dl, dl\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u250c\u2500< 0x104d309e      7505           jne 0x104d30a5\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d30a0      8a16           mov dl, byte [esi]\n\u2502 \u2502\u254e\u254e\u254e\u254e\u254e\u2502   0x104d30a2      46             inc esi\n\u2502 \u2502\u254e\u254e\u254e\u254e\u2
… [4747 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
    "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "win_token rule matches Matches strings at offsets 172606 and 172621, indicating potential token manipulation often used ",
    "IsPE32 rule matches Rule matches confirm the file is a Windows PE executable, a common format for malware distribution. ",
    "type file_summary Analysis identifies the file as a PE with architecture X86 and high entropy (224), which may indicate ",
    "domain rule matches Matches domain patterns, suggesting possible network communication capabilities typical in malware. "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "The file is a Windows DLL (PE X86) with high entropy and multiple YARA rule matches, including win_token indicating token manipulation, suggesting malicious activity such as privilege escalation or network communication. Persistence: not observed. Exfiltration: not observed. Credential_access: not o",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "rule matches",
      "row_or_rule": "win_token",
      "why": "Matches strings at offsets 172606 and 172621, indicating potential token manipulation often used in malware for privilege escalation."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "rule matches",
      "row_or_rule": "IsPE32",
      "why": "Rule matches confirm the file is a Windows PE executable, a common format for malware distribution."
    },
    {
      "source": "checklist_malcat_analyze",
      "query_or_table": "file_summary",
      "row_or_rule": "type",
      "why": "Analysis identifies the file as a PE with architecture X86 and high entropy (224), which may indicate obfuscation or packing."
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "rule matches",
      "row_or_rule": "domain",
      "why": "Matches domain patterns, suggesting possible network communication capabilities typical in malware."
    }
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      
… [5414 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
… [46191 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 3,
  "top_rules": [
    {
      "name": "packed with Themida",
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
     
… [1190 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 3166208,
  "duration_s": 0.04,
  "import_count": 3,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 5014,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "@.edata",
    "@.idata",
    ".themida",
    "'1~`nV9F",
    "\\nxswz9C",
    "oh.n~L",
    "Uh~D8C",
    "?=RalLh\tk",
    "'{,.L%J",
    "s\\s`^#j",
    "\"THnOt",
    "w7v:n#",
    "O0,Kd?",
    "|S0|N&",
    "&xK[#[",
    "INb@T%",
    "WWH~|Y",
    "h(&<ul
… [1318 more chars]
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
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "disassembly": {
    "0x104d3058": "\u250c 336: entry0 ();\n\u2502           0x104d3058      e84b010000     call 0x104d31a8\n\u2502           0x104d305d      53             push ebx\n\u2502           0x104d305e      89e
… [7847 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
    "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
  "rows": [
    {
      "name": "??0CStringLoader@@QAE@PBD@Z",
      "address": "276488192",
      "size": "1"
    },
    {
      "name": "??1CStringLoader@@UAE@XZ",
      "address": "276488196",
      "size": "1"
    },
    {
      "name": "??_7CStringLoader@@6B@",
      "address": "276488200",
      "size": "1"
    },
    {
      "name"
… [2968 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 3166208,
  "duration_s": 0.05,
  "import_count": 3,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [
    {
      "name": "OpenProcessToken",
      "module": "ADVAPI32.DLL",
      "address": "26"
    },
    {
      "name": "GetModuleHandleA",
      "module": "KERNEL32.DLL",
      "address": "24"
    },
    {
      "name": "??0CStringLoader@@QAE@PBD@Z",
      "module": "STRINGLOADERB.DLL",
      "address": "1"
    },
    {
  
… [3515 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "size",
    "instruction_count",
    "block_count",
    "cyclomatic_complexity",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "??0CStringLoader@@QAE@PBD@Z",
      "size": "1",
      "instruction_count": "0",
      "block_count": "1",
      "cyclomatic_complexity": "1",
      "call_out_count": "0",
      "string_ref_cou
… [5233 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "module"
  ],
  "rows": [
    {
      "name": "??0CStringLoader@@QAE@PBD@Z",
      "address": "276488192",
      "module": "Global"
    },
    {
      "name": "??1CStringLoader@@UAE@XZ",
      "address": "276488196",
      "module": "Global"
    },
    {
      "name": "??_7CStringLoader@@6B@",
      "address": "276488200",
      "module": "Global"
  
… [3635 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "size",
    "is_read",
    "is_write",
    "is_exec"
  ],
  "rows": [
    {
      "start_ea": "268435456",
      "end_ea": "268436479",
      "name": "Headers",
      "class": "DATA",
      "size": "1024",
      "is_read": "1",
      "is_write": "0",
      "is_exec": "0"
    },
    {
      "start_ea": "268439552",
      "e
… [2366 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
… [46191 more chars]
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
      "content": "??0CStringLoader@@QAE@PBD@Z",
      "address": "268775482",
      "length": "28"
    },
    {
      "content": "??1CStringLoader@@UAE@XZ",
      "address": "268775510",
      "length": "25"
    },
    {
      "content": "??_7CStringLoader@@6B@",
      "address": "268775535",
      "length": "23"
  
… [6561 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 3,
  "top_rules": [
    {
      "name": "packed with Themida",
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
     
… [1191 more chars]
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
      "content": "{,Z\"{0Z6{4ZB{8ZR{<Zb{@Zr",
      "address": "268473087",
      "length": "24"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "audit_path": "/opt/samples/lo
… [82 more chars]
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
      "content": "StringLoaderA.dll",
      "address": "268775464",
      "length": "18"
    },
    {
      "content": "kernel32.dll",
      "address": "268779520",
      "length": "13"
    },
    {
      "content": "USER32.dll",
      "address": "268779552",
      "length": "11"
    },
    {
      "content": "ADVAP
… [372 more chars]
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
  "session_id": "ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "audit_path": "/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/audit.jsonl"
}
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
      "content": "StringLoaderA.dll",
      "address": "268775464",
      "length": "18"
    },
    {
      "content": "??0CStringLoader@@QAE@PBD@Z",
      "address": "268775482",
      "length": "28"
    },
    {
      "content": "??1CStringLoader@@UAE@XZ",
      "address": "268775510",
      "length": "25"
    },

… [4006 more chars]
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
      "content": "rAU6~",
      "address": "268439595",
      "length": "5"
    },
    {
      "content": "'1~`nV9F",
      "address": "268439694",
      "length": "8"
    },
    {
      "content": "]\\\u001b8+B\u000b",
      "address": "268439733",
      "length": "7"
    },
    {
      "content": "L-Z+y",
      "a
… [2715 more chars]
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
      "content": "StringLoaderA.dll",
      "address": "268775464",
      "length": "18"
    },
    {
      "content": "??0CStringLoader@@QAE@PBD@Z",
      "address": "268775482",
      "length": "28"
    },
    {
      "content": "??1CStringLoader@@UAE@XZ",
      "address": "268775510",
      "length": "25"
    },

… [3979 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544.json"
}
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
      "content": "OpenProcessToken",
      "address": "268779597",
      "length": "17"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "audit_path": "/opt/samples/lo
… [82 more chars]
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
      "content": "{,Z\"{0Z6{4ZB{8ZR{<Zb{@Zr",
      "address": "268473087",
      "length": "24"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "audit_path": "/opt/samples/lo
… [82 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "audit_path": "/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/audit.jsonl"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/01-tools-raw.json` exists=`True` bytes=`71552` mtime=`2026-08-08T18:31:08.082958+00:00`
  - sha256: `524beb4654e07c1c780a58223e0e6d79ba63083f6cc0f5600a448233d8f8061f`
- **sql_evidence:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/05-deep-dive.json` exists=`True` bytes=`2952` mtime=`2026-08-08T18:32:55.847689+00:00`
  - sha256: `e65c25f2d5baabc8dcfa56a91c66562b08adb4927a57ef27425ebeb8068620ba`

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
  "summary": "The file is a Windows DLL (PE X86) with high entropy and multiple YARA rule matches, including win_token indicating token manipulation, suggesting malicious activity such as privilege escalation or network communication. Persistence: not observed. Exfiltration: not observed. Credential_access: not observed. Encryption_obfuscation: High entropy indicates potential encryption or obfuscation {summary, analysis, high entropy detection, high entropy is commonly associated with encrypted or obfuscated code in malware analysis}. Imports: not observed.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "rule matches",
      "row_or_rule": "
… [2152 more chars]
```

- **agentic:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`399504` mtime=`2026-08-08T18:32:55.847689+00:00`
  - sha256: `2a79e61689987bf949534af44dd3948b70eac75af31ae9649bbe1d7de4f0a792`

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

- **rule_yar:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/rule.yar` exists=`True` bytes=`1840` mtime=`2026-08-08T14:12:50.582004+00:00`
  - sha256: `5474027771ae709544a48434aba1bfc440726bcf829c1ed4fa2b7c14dab2da57`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T14:12:50.583191+00:00
rule CADRE_v2_unknown_3476906b2c72 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "StringLoaderB.?ReadBufferFromFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s1 = "StringLoaderB.?ReadBufferFromFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s2 = "StringLoaderB.?WriteBufferToFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
     
… [1038 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-MASTER-v2.md` exists=`True` bytes=`15239` mtime=`2026-08-08T19:01:09.477453+00:00`
  - sha256: `8b44d67f7c213fddf706abb4fc6cf16309e7e4b66f45546ff6f55ae016af9a79`
- **REPORT_MASTER_v3:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-MASTER-v3.md` exists=`True` bytes=`45619` mtime=`2026-08-08T18:58:46.263754+00:00`
  - sha256: `7ed0d2e3d0bab422a9136b59c751eb3f687d52e708ac20fa1b3d2db593310c54`
- **REPORT_v2:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-v2.md` exists=`True` bytes=`15239` mtime=`2026-08-08T19:01:09.477453+00:00`
  - sha256: `8b44d67f7c213fddf706abb4fc6cf16309e7e4b66f45546ff6f55ae016af9a79`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`46850` mtime=`2026-08-08T19:02:20.657397+00:00`
  - sha256: `22066fe736d93f29f8f1a6aace07362330547936429cd827ae63f5b19e06ad1e`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`48922` mtime=`2026-08-08T18:59:53.112508+00:00`
  - sha256: `9d2049de0db682d518e88d786842ac6a6f6a177b6b3db8a43ededaa95ad114ae`
- **report_v2_json:** `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/report-v2.json` exists=`True` bytes=`17772` mtime=`2026-08-08T19:02:20.661397+00:00`
  - sha256: `6fd87e0524ce36dea196d80b820b67be3d56e7b63a3db9b239d6b5c27a2b1c7c`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 19:01:09 UTC

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

This report presents a technical analysis of a Windows DLL (X86) identified by SHA-256: `3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544`. The sample exhibits characteristics of commercial software packing (Themida) and contains numerous code anomalies. Crucially, YARA rule `win_token` fired and the import of `advapi32.OpenProcessToken` indicates potential token man
… [14332 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 18:58:46 UTC

# RE Report — 3476906b2c72
_Generated 2026-08-08T18:58:46.258075+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=314c | cross_refs=True | llm_ok=True | runtime=32.78s -->

## Executive Summary

The malware sample identified by SHA-256 hash **3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544** is assessed as **suspicious** with a high confidence of 90%, based on aggregated evidence from deep analysis (source: deep_dive_agentic). Discrepancies exist between automated verdicts, with one report indicating malicious intent (score 290 fr
… [44704 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
