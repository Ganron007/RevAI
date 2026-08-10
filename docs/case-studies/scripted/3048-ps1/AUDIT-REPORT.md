# Pipeline AUDIT-REPORT — `14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.096633+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2`

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

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`malicious` confidence=`40`
- key_evidence_count=`6`

```json
{
  "verdict": "malicious",
  "score": 40.0,
  "family_guess": "PowerShell-based malware",
  "cross_engine_notes": "Ghidra analysis failed due to server errors; IDA provided minimal data with zero functions and one string; MalCat and YARA supplied comprehensive evidence of behavioral signals and obfuscation, indicating malicious intent.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "views.yara_hits",
      "row_or_rule": "RunShell",
      "why": "YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or command execution, which is commonly associated with malicious activity."
    },
    {
      "source": "malcat",
      "query_or_table": "views.yara_hits",
      "row_or_rule": "Powershell",
      "why": "YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious campaigns for payload delivery or evasion."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "powershell",
      "why": "YARA rule matched for PowerShell content, corroborating the script's nature and potential for malicious use."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "contains_base64",
      "why": "Base64 strings suggest obfuscation, a neutral but suspicious technique often used in malicious scripts to evade detection."
    },
    {
      "source": "malcat",
      "query_or_table": "strings/apis",
      "row_or_rule": "ProcessStartInfo, RedirectStandardOutput, etc.",
      "why": "APIs related to process execution (e.g., ProcessStartInfo, RedirectStandardOutput) indicate the script can launch and control processes, a capability used for malicious activities like downloading payloads or executing commands."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.entropy",
      "row_or_rule": "148",
      "why": "High entropy for a text file (2800 bytes) may indicate encoded or obfuscated content, supporting suspicion of malicious intent and evasion techniques."
    }
  ],
  "summary": "A PowerShell script with high entropy and base64 obfuscation, exhibiting behavioral signals such as YARA rules for shell execution and process control APIs. These findings strongly suggest malicious intent, likely used for lateral movement, payload delivery, or command-and-control operations.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 250,
    "findings": [
      "yara: 5 matches"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "text",
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
    "powershell",
    "Antivirus"
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
      "RunShell views.yara_hits YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or comm",
      "Powershell views.yara_hits YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious ca",
      "powershell yara matches YARA rule matched for 
… [863 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`9`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "PowerShell dropper/loader script that uses architecture-aware execution, hidden window launch (-nop -w hidden), and a double-encoded (Base64 + GZip) payload delivered via [scriptblock]::create(). The encoded payload (2800 bytes of dense Base64) is a classic technique used by PowerShell Empire, Cobalt Strike stagers, and document-embedded macro payloads. YARA rules matched for RunShell (lateral movement), Powershell execution, Base64 encoding, domain regex, and IPv6 patterns.",
  "key_evidence": [
    "Malcat YARA hit: 'RunShell' rule (category: lateral movement, reliability 70) \u2014 starts a shell",
    "Malcat YARA hit: 'Powershell' rule (category: lateral movement, reliability 30) \u2014 runs a powershell script",
    "YARA checklist: contains_base64 rule matched (16 pattern hits at offset 52)",
    "YARA checklist: domain_regex matched, powershell matched at offset 59, ipv6 matched at offset 11",
    "IDA strings: full script reveals '-nop -w hidden -c' flags for hidden execution with no PowerShell profile",
    "IDA strings: architecture check '[IntPtr]::Size -eq 4' with sysnative path workaround for 32/64-bit compatibility",
    "IDA strings: dynamic code execution via [scriptblock]::create() with GZip+Base64 decoded payload (H4sI GZip magic header)",
    "Malcat strings: 12+ long Base64-encoded strings identified, indicating heavily obfuscated payload",
    "Malcat: file type text/utf8, 2800 bytes, entropy 148 \u2014 consistent with encoded PowerShell payload"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 8,
  "successful_non_bootstrap_tools": 4,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "text",
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
        "why": "not_applicable:text"
      },
      "pe_imports": {
        "ok": true,
        "why": "not_applicable:text"
      },
      "floss": {
        "ok": true,
        "why": "not_applicable:text"
      },
      "dotnet": {
        "ok": true,
        "why": "not_applicable:text"
      },
      "upx": {
        "ok": true,
        "why": "not_applicable:text"
      },
      "speakeasy": {
        "ok": true,
        "why": "not_applicable:text"
      },
      "frida_probe": {
        "ok": true,
        "why": "not_applicable:text"
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

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: PowerShell Dropper/Loader (SHA256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 19:22:26 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a PowerShell script (SHA256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2) identified as malicious. The script functions as a dropper/loader, employing architecture-aware execution, hidden window launch, and a double-encoded (Base64 + GZip) payload delivered via dynamic code execution. The payload is consistent with techniques used by PowerShell Empire, Cobalt Strike stagers, and document-embedded macro payloads. Key behavioral indicators include YARA rule matches for shell execution, PowerShell abuse, Base64 obfuscation, and process control APIs. The script's high entropy and obfuscation are neutral signals, but the combination of hidden execution, dynamic code creation, and process manipulation constitutes clear behavioral intent for malicious activity, likely for lateral movement, payload delivery, or command-and-control operations. The sample is classified as malicious with high confidence.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| SHA256 | 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 |\n| File Path | /opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1 |\n| Project | day6 |\n| File Type | text/utf8 (PowerShell script) |\n| Size | 2800 bytes |\n| Entropy | 148 (high for a text file, indicating encoded/obfuscated content) |\n| Architecture | NONE (script, not a native binary) |\n| .NET Analysis | Not a .NET assembly |\n\nThe sample is a UTF-8 encoded PowerShell script. The high entropy value of 148 for a 2800-byte text file is a strong indicator of encoded or obfuscated content, which is a common evasion technique in malicious scripts (source: malcat, file_summary.entropy).\n\n## 2. Classification\n\n| Field | Value |\n|---|---|\n| Verdict | Malicious |\n| Confidence | 90 |\n| Family | PowerShell-based malware |\n| Score | 40.0 (Triage) / 90 (Deep-dive) |\n| Key Behavioral Signals | Hidden execution, dynamic code creation, process control APIs, Base64/GZip encoding |\n\nThe classification is based on behavioral intent evidence, not obfuscation alone. The script exhibits multiple hostile behaviors: it launches a hidden PowerShell window (`-nop -w hidden`), performs architecture checks for 32/64-bit compatibility, and dynamically creates and executes a double-encoded payload using `[scriptblock]::create()` (source: deep-dive.json). These are classic techniques for evading detection and executing arbitrary code, which are hallmarks of malicious droppers and loaders. The upstream triage verdict of \"malicious\" is confirmed and calibrated with high confidence.\n\n## 3. Background & Family Lineage\n\nThe script's techniques are consistent with several well-known PowerShell-based attack frameworks:\n\n- **PowerShell Empire**: 
… [17360 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 19:22:26 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a PowerShell script (SHA256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2) identified as malicious. The script functions as a dropper/loader, employing architecture-aware execution, hidden window launch, and a double-encoded (Base64 + GZip) payload delivered via dynamic code execution. The payload is consistent with techniques used by PowerShell Empire, Cobalt Strike stagers, and document-embedded macro payloads. Key behavioral indicators include YARA rule matches for shell execution, PowerShell abuse, Base64 obfuscation, and process control APIs. The script's high entropy and obfuscation are neutral signals, but the combination of hidden execution, dynamic code creation, and process manipulation constitutes clear behavioral intent for malicious activity, likely for lateral movement, payload delivery, or command-and-control operations. The sample is classified as malicious with high confidence.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 |
| File Path | /opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1 |
| Project | day6 |
| File Type | text/utf8 (PowerShell script) |
| Size | 2800 bytes |
| Entropy | 148 (high for a text file, indicating encoded/obfuscated content) |
| Architecture | NONE (script, not a native binary) |
| .NET Analysis | Not a .NET assembly |

The sample is a UTF-8 encoded PowerShell script. The high entropy value of 148 for a 2800-byte text file is a strong indicator of encoded or obfuscated content, which is a common evasion technique in malicious scripts (source: malcat, file_summary.entropy).

## 2. Classification

| Field | Value |
|---|---|
| Verdict | Malicious |
| Confidence | 90 |
| Family | PowerShell-based malware |
| Score | 40.0 (Triage) / 90 (Deep-dive) |
| Key Behavioral Signals | Hidden execution, dynamic code creation, process control APIs, Base64/GZip en
… [15682 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 19:31:54 UTC

# RE Report — 14a42d6418b3
_Generated 2026-08-09T19:31:54.113748+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=58.07s -->

# Executive Summary

The sample identified by SHA256 hash `14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2` is assessed as **malicious PowerShell-based malware** with high confidence. This top-line verdict is based on converging evidence from automated detections and deep analysis, though specific runtime behaviors are not fully confirmed.

| Aspect | Assessment | Confidence | Evidence & Interpretation |
|--------|------------|------------|---------------------------|
| Verdict | Malicious | High | (source: yara) – Five YARA rule matches were detected, indicating likely malicious patterns; this aligns with V1 summary findings. |
| Family | PowerShell-based malware | Medium | (source: deep_dive_agentic) – Code structure and patterns suggest PowerShell usage, inferred from static analysis without behavioral logs. |
| Agreement | LLM and V1 concur | High | (source: cross-section:classification) – Multiple independent methods agree on the verdict, strengthening reliability. |
| Deep Confidence | 90% | High | (source: deep_dive_agentic) – Comprehensive code examination reduces uncertainty, though limited behavioral data is available. |

The malicious verdict is strongly supported by YARA detections, which identified five rule matches that help pinpoint specific malware traits. (source: yara) The classification as PowerShell-based malware is likely based on static code analysis, such as disassembly and capability assessment, but we hedge this due to absent runtime monitoring. (source: deep_dive_agentic) Agreement between the LLM judge and V1 analysis, as noted in the classification section, reinforces the assessment's consistency. (source: cross-section:classification) The high confidence score of 90% stems from deep dive analysis that examined code and potential behaviors, though actual execution data remains limited. (source: deep_dive_agentic)

In summary, this sample is highly likely to be malicious PowerShell malware, with robust consensus from detection rules an
… [43005 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4363` | `44249b077ceeeac2` |
| `prompt.txt` | `True` | `18954` | `a3d3f9684e3c5151` |
| `pipeline-audit.json` | `True` | `85602` | `1daf596c795478d5` |
| `AUDIT-REPORT.md` | `True` | `63802` | `704966f8294e0094` |
| `REPORT-MASTER-v2.md` | `True` | `18189` | `a096ed8cef501ee7` |
| `REPORT-MASTER-v3.md` | `True` | `45534` | `a1f65b55209b920b` |
| `REPORT-v2.md` | `True` | `18189` | `a096ed8cef501ee7` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `26743` | `4fe6a6eb1d6469e8` |
| `rule.yar` | `True` | `1411` | `52aec5749a25c9a5` |
| `intake-validation.json` | `True` | `3668` | `7350fb3d58a2550f` |
| `source-decisions.json` | `True` | `1727` | `ad5915abc05e97f1` |
| `malcat-triage.json` | `True` | `9658` | `5a9d199b4c2bd027` |
| `deep_dive/01-tools-raw.json` | `True` | `20594` | `074bd38e0523eeef` |
| `deep_dive/01-tools-gate.json` | `True` | `1044` | `e71d8e3a0f7d8580` |
| `deep_dive/05-deep-dive.json` | `True` | `2978` | `9da7091ba8b0c96d` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `16613` | `e807d9136896f430` |

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

- **intake_validation:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/intake-validation.json` exists=`True` bytes=`3668` mtime=`2026-08-09T13:43:28.325836+00:00`
  - sha256: `7350fb3d58a2550f2a5758b68891f1c4be45fff7fd78989cced96ef032c831cf`
- **malcat_triage:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/malcat-triage.json` exists=`True` bytes=`9658` mtime=`2026-08-09T13:42:27.891850+00:00`
  - sha256: `5a9d199b4c2bd027fac51488c587952d3ec6df5e332c0c1498b0f77188da5749`
- **source_decisions:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/source-decisions.json` exists=`True` bytes=`1727` mtime=`2026-08-09T13:43:28.326837+00:00`
  - sha256: `ad5915abc05e97f10675729ab6bfa4d445737f53c8ae48cf1954c6c15ff6a781`
- **ghidra_import_log:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/intake-analyzeHeadless.log` exists=`True` bytes=`4138` mtime=`2026-08-09T13:01:04.421851+00:00`
  - sha256: `667451f6c4de9e65539132b7e3d57cdff94c3a9d9fc3ca4655cb1aeb97e164e1`
- **ida_bootstrap_log:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/intake-idasql.log` exists=`True` bytes=`208` mtime=`2026-08-09T13:42:28.934847+00:00`
  - sha256: `87e9963dae475f438de62a690a7a1c49a7adafdba3ab58851e735c5f48747678`

#### source_decisions_excerpt

```
{
  "sha256": "14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2",
  "imports": {
    "source": "none",
    "confidence": "high",
    "reason": "Evidence: {malcat, summary, imports_count: 0, indicates no imports}; {ida, summary, imports: 0, confirms zero imports}; {ghidra, failure warning, server died, no data available}."
  },
  "functions": {
    "source": "none",
    "confidence": "high",
    "reason": "Evidence: {malcat, summary, functions_count: 0, shows no functions}; {ida, summary, funcs: 0, confirms zero functions}; {ghidra, failure warning, server died, no data available}."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Evidence: {malcat, summary, strings_count: 100, provides extensive string list}; {ida, summary, strings: 1, adds
… [950 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
    "file_name": "3048.ps1",
    "file_path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
    "file_size": 2800,
    "type": "text/utf8",
    "architecture": "NONE",
    "entropy": 148,
    "sha256": "14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2",
    "metadata": {},
    "entrypoint_ea": null,
    "layout": [
      {
        "name": "",
        "effective_address": 0,
   
… [8858 more chars]
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

#### `capa` — ok=`True` why=`not_applicable:text`

```json
{
  "skipped": true,
  "fail_open": true,
  "reason": "not_applicable:text",
  "error": "CAPA supports PE/ELF/Mach-O only (got text)",
  "rule_count": 0,
  "matched_rule_count": 0,
  "top_rules": []
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 5,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
      "rule": "powershell",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$a",
          "offset": 59,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 11,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$a",
          "offset": 52,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": []
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
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                          ^ unclosed counted repetition\n   |\n   = 
… [598 more chars]
```

#### `floss` — ok=`True` why=`not_applicable:text`

```json
{
  "skipped": true,
  "fail_open": true,
  "reason": "not_applicable:text",
  "error": "FLOSS supports PE only (got text)",
  "string_count": 0,
  "strings": []
}
```

#### `malcat` — ok=`True` why=`not_applicable:text`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
    "file_name": "3048.ps1",
    "file_path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
    "file_size": 2800,
    "type": "text/utf8",
    "architecture": "NONE",
    "entropy": 148,
    "sha256": "14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2",
    "metadata": {},
    "entrypoint_ea": null,
    "layout": [
      {
        "name": "",
        "effective_address": 0,
        "physical_size": 2800,
        "virtual_size": 2800,
        "rights": "",
        "entropy": 148
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [],
    "anomaly_locations": {},
    "yara_hits": [
      {
        "id": "RunShell",
        "category": "lateral movement",
        "reliability": 70,
        "type": "UNCOMMON",
        "description": "starts a shell",
        "num_patterns": 1
      },
      {
        "id": "Powershell",
        "category": "lateral movement",
        "reliability": 30,
        "type": "SUSPICIOUS",
        "description": "runs a powershell script",
        "num_patterns": 1
      }
    ],
    "strings": [
      {
        "ea": 75,
        "summary": "powershell"
      },
      {
        "ea": 100,
        "summary": "powershell"
      },
      {
        "ea": 1575,
        "summary": "o7pr3d3E1k5jz02X..GAV521nIJ17x5ls7"
      },
      {
        "ea": 1846,
        "summary": "Gpbr0XQ3VYSTpa6N..K7RjgOTuuIzjddpQ"
      },
      {
        "ea": 922,
        "summary": "T3JylvqFE5qcDlZQ..8BxX0ldul5V1Ngah"
      },
      {
        "ea": 1173,
        "summary": "2hkmcF9neg5RB7Ja..gNN9JfmZNyjAfv3v"
      },
      {
        "ea": 775,
        "summary": "P3VqrGPCxLhlhYXO..vUr8SyWQmhdZowlJ"
      },
      {
        "ea": 2159,
        "summary": "7F96i2Gg0GWOMwld..QKGJS8cXU5oqmLUV"
      },
      {
        "ea": 2364,
        "summary": "sX3hKXG549OGzo9r..I49gUI8fvDGiZpyZ"
      },
      {
        "ea": 1436,
        "summary": "JIzORjuBW1XFNGUr..9XwoM3DpQaGhpNAC"
      },
      {
        "ea": 1379,
        "summary": "WYuJycRmqIaC0cyb..HFpK8G8ENJPljUam"
      },
      {
        "ea": 1500,
        "summary": "AraaEnCWshkAR1OD..yqRk6mZ4sh9tvdsR"
      },
      {
        "ea": 1973,
        "summary": "WZ4ZLhY3guI7s7G0..k2HoVJV9N3SWvZUI"
      },
      {
        "ea": 1777,
        "summary": "2RwaVKLc7mCSsNxE..HH6NuKI6Oev8Z3at"
      },
      {
        "ea": 2027,
        "summary": "Eo2s3vBUtuLYploi..fAfYge4eCdAvfIwo"
      },
      {
        "ea": 1327,
        "summary": "JoEvjoV91JZMDbXv..IXc2SSEI5HvQvpYH"
      },
      {
        "ea": 607,
        "summary": "611R5MNolexcoi8E..PEQ8yVlplSUvD1X3"
      },
      {
        "ea": 2679,
        "summary": "RedirectStandardOutput"
      },
      {
        "ea": 409,
        "summary": "ayBL9nEj5D9YKCaN..yGnURa6drYHkwwDz"
      },
      {
        "ea": 2320,
        "summary": "VXTTL1eqvOE8I0eJ..wy8c6oqJlKaeOxGh"
      },
      {
        "ea": 1279,
        "summary": "lU0vnCWIVFB8MI7S..VDfCvzH9olicnRhm"
      },
      {
        "ea": 696,
        "summary": "JkW7RcEve6LTvO0R..MiTPy83oAY4JfhYp"
      },
      {
        "ea": 511,
        "summary"
… [6831 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "RunShell views.yara_hits YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or comm",
    "Powershell views.yara_hits YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious ca",
    "powershell yara matches YARA rule matched for PowerShell content, corroborating the script's nature and potential for ma",
    "contains_base64 yara matches Base64 strings suggest obfuscation, a neutral but suspicious technique often used in malici",
    "ProcessStartInfo, RedirectStandardOutput, etc. strings/apis APIs related to process execution (e.g., ProcessStartInfo, R"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "PowerShell-based malware",
  "score": 40.0,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "views.yara_hits",
      "row_or_rule": "RunShell",
      "why": "YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or command execution, which is commonly associated with malicious activity."
    },
    {
      "source": "malcat",
      "query_or_table": "views.yara_hits",
      "row_or_rule": "Powershell",
      "why": "YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious campaigns for payload delivery or evasion."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "powershell",
      "why": "YARA rule matched for PowerShell content, corroborating the script's nature and potential for malicious use."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "contains_base64",
      "why": "Base64 strings suggest obfuscation, a neutral but suspicious technique often used in malicious scripts to evade detection."
    },
    {
      "source": "malcat",
      "query_or_table": "strings/apis",
      "row_or_rule": "ProcessStartInfo, RedirectStandardOutput, etc.",
      "why": "APIs related to process execution (e.g., ProcessStartInfo, RedirectStandardOutput) indicate the script can launch and control processes, a capability used for malicious activities like downloading payloads or executing commands."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.entropy",
      "row_or_rule": "148",
      "why": "High entropy for a text file (2800 bytes) may indicate encoded or obfuscated content, supporting suspicion of malicious intent and evasion techniques."
    }
  ],
  "summary": "A PowerShell script with high entropy and base64 obfuscation, exhibiting behavioral signals such as YARA rules for shell execution and process control APIs. These findings strongly suggest malicious intent, likely used for lateral movement, payload delivery, or command-and-control operations."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/prompt.txt` exists=`True` bytes=`18954` mtime=`2026-08-09T13:44:04.801762+00:00`
  - sha256: `a3d3f9684e3c5151cdd00b049abefef90d74ee03cbc9fa507931ab2559cdb53e`
- **verdict:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/verdict.json` exists=`True` bytes=`4363` mtime=`2026-08-09T13:45:11.206535+00:00`
  - sha256: `44249b077ceeeac2c7c665e88b920fa8844962b2c5aa8a11089a6fa2c5e2ae0c`

#### prompt_excerpt

```
# Triage evidence
sha256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2
sample_path: /opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1
ghidra_session: ghidra-pe-14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2
ida_session: ida-14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2

## Source decisions (from intake validation)
- imports: none (confidence=high) — Evidence: {malcat, summary, imports_count: 0, indicates no imports}; {ida, summary, imports: 0, confirms zero imports}; {ghidra, failure warning, server died, no data available}.
- functions: none (confidence=high) — Evidence: {malcat, summary, functions_count: 0, shows no functions}; {ida, summary, funcs: 0, confirms zero functions}; {ghidra, failure warning, server died, no data available}.
- strings: both (confidence=high) — Evidence: {malcat, summary, strings_count: 100, provides extensive string list}; {ida, summary, strings: 1, ad
… [17924 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 40.0,
  "family_guess": "PowerShell-based malware",
  "cross_engine_notes": "Ghidra analysis failed due to server errors; IDA provided minimal data with zero functions and one string; MalCat and YARA supplied comprehensive evidence of behavioral signals and obfuscation, indicating malicious intent.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "views.yara_hits",
      "row_or_rule": "RunShell",
      "why": "YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or command execution, which is commonly associated with malicious activity."
    },
    {
      "source": "malcat",
      "query_or_table": "views.yara_hits",
      "row_or_rule": "Powershell",
      "why": "YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious campaigns for payload delivery or evasion."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "ro
… [3363 more chars]
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

#### `malcat` — ok=`True` why=`not_applicable:text`

```json

```

#### `capa` — ok=`True` why=`not_applicable:text`

```json

```

#### `pe_imports` — ok=`True` why=`not_applicable:text`

```json

```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 5,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
      "rule": "powershell",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$a",
          "offset": 59,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 11,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$a",
          "offset": 52,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": []
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
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                          ^ unclosed counted repetition\n   |\n   = 
… [576 more chars]
```

#### `floss` — ok=`True` why=`not_applicable:text`

```json

```

#### `dotnet` — ok=`True` why=`not_applicable:text`

```json

```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
  "disassembly": {
    "0x00000000": "\u250c 1906: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_31h, int64_t arg_32h, int64_t arg_36h, int64_t arg_41h, int64_t arg_49h, int64_t arg_4ah, int64_t arg_56h, int64_t arg_63h, int64_t arg_6ah, int64_t arg_79h);\n\u2502           ; arg int64_t arg1 @ rdi\n\u2502           ; arg int64_t arg2 @ rsi\n\u2502           ; arg int64_t arg3 @ rdx\n\u2502           ; arg int64_t arg4 @ rcx\n\u2502           ; arg int64_t arg5 @ r8\n\u2502           ; arg int64_t arg6 @ r9\n\u2502           ; arg int64_t arg_31h @ rbp+0x31\n\u2502           ; arg int64_t arg_32h @ rbp+0x32\n\u2502           ; arg int64_t arg_36h @ rbp+0x36\n\u2502           ; arg int64_t arg_41h @ rbp+0x41\n\u2502           ; arg int64_t arg_49h @ rbp+0x49\n\u2502           ; arg int64_t arg_4ah @ rbp+0x4a\n\u2502           ; arg int64_t arg_56h @ rbp+0x56\n\u2502           ; arg int64_t arg_63h @ rbp+0x63\n\u2502           ; arg int64_t arg_6ah @ rbp+0x6a\n\u2502           ; arg int64_t arg_79h @ rbp+0x79\n\u2502           0x00000000      6966285b49..   imul esp, dword [rsi + 0x28], 0x746e495b\n\u2502           0x00000007      50             push rax\n\u2502       \u250c\u2500< 0x00000008      7472           je 0x7c\n\u2502       \u2502   0x0000000a      5d             pop rbp\n\u2502       \u2502   0x0000000b      3a3a           cmp bh, byte [arg_49h]      ; arg3\n\u2502       \u2502   0x0000000d      53             push rbx\n\u2502       \u2502   0x0000000e      697a65202d..   imul edi, dword [rdx + 0x65], 0x71652d20\n\u2502       \u2502   0x00000015      203429         and byte [rcx + rbp], dh    ; arg4\n\u2502      \u250c\u2500\u2500< 0x00000018      7b24           jnp 0x3e\n\u2502      \u2502\u2502   0x0000001a      62             invalid\n..\n    \u2502\u2502\u2502\u2502\u2502   ; DATA XREF from fcn.00000000 @ 0x1a0(w)\n\u2502  \u2502\u2502\u2502\u2502\u2514\u2500\u2500> 0x0000003e      657253         jb 0x94\n\u2502  \u2502\u2502\u2502\u2502\u2502\u2502   ; DATA XREF from fcn.00000000 @ 0x70e(w)\n\u2502  \u2502\u2502\u2502\u2502\u2502\u2502   0x00000041      68656c6c5c     push 0x5c6c6c65             ; 'ell\\\\'\n\u2502 \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x00000046      7631           jbe 0x79\n\u2502 \u2502\u2502\u2502\u2502\u2502\u2502\u2502   0x00000048      2e305c706f     xor byte cs:[rax + rsi*2 + 0x6f], bl\n\u2502 \u2502\u2502\u2502\u2502\u2502\u2502\u2502   ; DATA XREF from fcn.00000000 @ 0x6aa(r)\n\u2502 \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x0000004d      7765           ja 0xb4\n\u2502 \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x0000004f      7273           jb 0xc4\n\u2502 \u2502\u2502\u2502\u2502\u2502\u2502\u2502   0x00000051      68656c6c2e     push 0x2e6c6c65             ; 'ell.'\n\u2502 \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x00000056      657865         js 0xbe\n\u2502 \u2502\u2502\u2502\u2502\u2502\u2502\u2502   0x00000059      27             invalid\n  \u2502\u2502\u2502\u2502\u2502\u2502\u2502   ; DATA XREFS from fcn.00000000 @ 0x72c(r), 0x7b7(r)\n..\n  \u2502\u2502\u2502\u2502\u2502\u2502\u2502   ; DATA XREF from fcn.00000000 @ 0xb3(r)\n  \u2502\u2502\u2502\u2502\u2502\u2502\u2502   ; DATA XREF from fcn.00000000 @ 0x3e4(w)\n  \u2502\u2502\u2502\u2502\u2502\u2502\u2502  
… [986 more chars]
```

#### `upx` — ok=`True` why=`not_applicable:text`

```json

```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
```

#### `speakeasy` — ok=`True` why=`not_applicable:text`

```json

```

#### `frida_probe` — ok=`True` why=`not_applicable:text`

```json

```

#### `frida_trace` — ok=`True` why=`not_applicable:text`

```json

```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 9,
  "hits": 9,
  "misses": [],
  "hit_examples": [
    "Malcat YARA hit: 'RunShell' rule (category: lateral movement, reliability 70) \u2014 starts a shell",
    "Malcat YARA hit: 'Powershell' rule (category: lateral movement, reliability 30) \u2014 runs a powershell script",
    "YARA checklist: contains_base64 rule matched (16 pattern hits at offset 52)",
    "YARA checklist: domain_regex matched, powershell matched at offset 59, ipv6 matched at offset 11",
    "IDA strings: full script reveals '-nop -w hidden -c' flags for hidden execution with no PowerShell profile"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "PowerShell dropper/loader script that uses architecture-aware execution, hidden window launch (-nop -w hidden), and a double-encoded (Base64 + GZip) payload delivered via [scriptblock]::create(). The encoded payload (2800 bytes of dense Base64) is a classic technique used by PowerShell Empire, Cobal",
  "key_evidence": [
    "Malcat YARA hit: 'RunShell' rule (category: lateral movement, reliability 70) \u2014 starts a shell",
    "Malcat YARA hit: 'Powershell' rule (category: lateral movement, reliability 30) \u2014 runs a powershell script",
    "YARA checklist: contains_base64 rule matched (16 pattern hits at offset 52)",
    "YARA checklist: domain_regex matched, powershell matched at offset 59, ipv6 matched at offset 11",
    "IDA strings: full script reveals '-nop -w hidden -c' flags for hidden execution with no PowerShell profile",
    "IDA strings: architecture check '[IntPtr]::Size -eq 4' with sysnative path workaround for 32/64-bit compatibility",
    "IDA strings: dynamic code execution via [scriptblock]::create() with GZip+Base64 decoded payload (H4sI GZip magic header)",
    "Malcat strings: 12+ long Base64-encoded strings identified, indicating heavily obfuscated payload",
    "Malcat: file type text/utf8, 2800 bytes, entropy 148 \u2014 consistent with encoded PowerShell payload"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 5,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
      "rule": "powershell",
      "path": "/opt/sampl
… [3676 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
    "file_name": "3048.ps1",
    "file_path": "/opt/s
… [9909 more chars]
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
  "disassembly": {
    "0x00000000": "\u250c 1906: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_31h, int64_t arg_32h, int64_t arg_36h, int64_t arg_41h, int64_t arg_49h, int64_t arg_4ah, int64_t arg_56h,
… [4086 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
```

- **signal_extractors** ok=`False` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals + emulation oracle
  - error: `RuntimeError: ghidrasql server died during startup for ghidra-pe-14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (rc=1); tail of log:
ening existing project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessAnalyzer)  
INFO  Opening project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessProject)  
ERROR Abort due to Headless analyzer error: Requested project program file(s) not found: 3048.ps1 (HeadlessAnalyzer) java.io.IOException: Requested project program file(s) not found: 3048.ps1
	at ghidra.app.util.headless.HeadlessAnalyzer.processNoImport(HeadlessAnalyzer.java:1404)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:461)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
 
Ghidra exited before becoming ready (exit code 1)
`

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
  - error: `ghidrasql server died during startup for ghidra-pe-14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (rc=1); tail of log:
ening existing project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessAnalyzer)  
INFO  Opening project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessProject)  
ERROR Abort due to Headless analyzer error: Requested project program file(s) not found: 3048.ps1 (HeadlessAnalyzer) java.io.IOException: Requested project program file(s) not found: 3048.ps1
	at ghidra.app.util.headless.HeadlessAnalyzer.processNoImport(HeadlessAnalyzer.java:1404)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:461)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
 
Ghidra exited before becoming ready (exit code 1)
`

```json
{
  "error": "ghidrasql server died during startup for ghidra-pe-14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (rc=1); tail of log:\nening existing project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessAnalyzer)  \nINFO  Opening project: /home/remnux/ghidra-
… [770 more chars]
```

- **floss_extract** ok=`False` checklist=`False` — langgraph tool call
  - error: `FLOSS supports PE only (got text)`

```json
{
  "skipped": true,
  "fail_open": true,
  "reason": "not_applicable:text",
  "error": "FLOSS supports PE only (got text)",
  "string_count": 0,
  "strings": [],
  "floss_profile": "skipped",
  "duration_s": 0.0
}
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
    "file_name": "3048.ps1",
    "file_path": "/opt/s
… [9909 more chars]
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
      "content": "if([IntPtr]::Size -eq 4){$b=$env:windir+'\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe'}else{$b='powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.C
… [2856 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (rc=1); tail of log:
ening existing project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessAnalyzer)  
INFO  Opening project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessProject)  
ERROR Abort due to Headless analyzer error: Requested project program file(s) not found: 3048.ps1 (HeadlessAnalyzer) java.io.IOException: Requested project program file(s) not found: 3048.ps1
	at ghidra.app.util.headless.HeadlessAnalyzer.processNoImport(HeadlessAnalyzer.java:1404)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:461)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
 
Ghidra exited before becoming ready (exit code 1)
`

```json
{
  "error": "ghidrasql server died during startup for ghidra-pe-14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (rc=1); tail of log:\nening existing project: /home/remnux/ghidra-projects/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 (HeadlessAnalyzer)  \nINFO  Opening project: /home/remnux/ghidra-
… [770 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content"
  ],
  "rows": [
    {
      "content": "if([IntPtr]::Size -eq 4){$b=$env:windir+'\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe'}else{$b='powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;$s.FileName=$b;$s.Arguments='-nop -w hidden -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Ob
… [2781 more chars]
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 5,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
      "rule": "powershell",
      "path": "/opt/sampl
… [3676 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/deep_dive/01-tools-raw.json` exists=`True` bytes=`20594` mtime=`2026-08-09T13:45:27.415606+00:00`
  - sha256: `074bd38e0523eeefe56649582e0dcb2adaf21056a78fca974472b4a33ef610af`
- **sql_evidence:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/deep_dive/05-deep-dive.json` exists=`True` bytes=`2978` mtime=`2026-08-09T13:46:34.143688+00:00`
  - sha256: `9da7091ba8b0c96d887f54864af68929ead98b2c5264235e7b01ab96d9dfb2fc`

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
  "summary": "PowerShell dropper/loader script that uses architecture-aware execution, hidden window launch (-nop -w hidden), and a double-encoded (Base64 + GZip) payload delivered via [scriptblock]::create(). The encoded payload (2800 bytes of dense Base64) is a classic technique used by PowerShell Empire, Cobalt Strike stagers, and document-embedded macro payloads. YARA rules matched for RunShell (lateral movement), Powershell execution, Base64 encoding, domain regex, and IPv6 patterns.",
  "key_evidence": [
    "Malcat YARA hit: 'RunShell' rule (category: lateral movement, reliability 70) \u2014 starts a shell",
    "Malcat YARA hit: 'Powershell' rule (category: lateral movement, re
… [2178 more chars]
```

- **agentic:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`116184` mtime=`2026-08-09T13:46:34.143688+00:00`
  - sha256: `442c910d852b8dbfbae46eb442b981e56b88ef1ce0b5d30cb3b28d2b17b28321`

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

- **rule_yar:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/rule.yar` exists=`True` bytes=`1411` mtime=`2026-08-09T13:46:47.781687+00:00`
  - sha256: `52aec5749a25c9a5f32b152c4e196a080dd2f17090f71409b8cf0086f969a121`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T13:46:47.782117+00:00
rule CADRE_v2_powershell_based_malware_14a42d6418b3 {
    meta:
        description = "RevAI v2 auto rule for PowerShell-based malware"
        sha256 = "14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2"
        family = "powershell_based_malware"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or command execution, which is c" ascii wide
        $s1 = "YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious campaigns for payload deliver" ascii wide
        $s2 = "YARA rule matc
… [609 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/REPORT-MASTER-v2.md` exists=`True` bytes=`18189` mtime=`2026-08-09T19:22:26.081194+00:00`
  - sha256: `a096ed8cef501ee757d5d991201a462ae4eceb2014f4959a7bb272567e19de63`
- **REPORT_MASTER_v3:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/REPORT-MASTER-v3.md` exists=`True` bytes=`45534` mtime=`2026-08-09T19:31:54.115567+00:00`
  - sha256: `a1f65b55209b920bf0ad1e3b48950adab69dd061405ee28f0eb3a1cdbdb17684`
- **REPORT_v2:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/REPORT-v2.md` exists=`True` bytes=`18189` mtime=`2026-08-09T19:22:26.081194+00:00`
  - sha256: `a096ed8cef501ee757d5d991201a462ae4eceb2014f4959a7bb272567e19de63`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`25161` mtime=`2026-08-09T19:23:53.758137+00:00`
  - sha256: `c5d829c8fa010cb2d9cbf2041ef172b8a8b498734df8f30fb05bbf0fc20fc3d0`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`26743` mtime=`2026-08-09T19:33:47.845711+00:00`
  - sha256: `4fe6a6eb1d6469e8b9f0775a743dd4a2d692589241b963fc57da4c0c78568e83`
- **report_v2_json:** `/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/report-v2.json` exists=`True` bytes=`20860` mtime=`2026-08-09T19:23:53.762138+00:00`
  - sha256: `418cc0e4611025332668c14435b0ef2384718da279e1f9fd885f84ff9a9bf08a`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 19:22:26 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a PowerShell script (SHA256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2) identified as malicious. The script functions as a dropper/loader, employing architecture-aware execution, hidden window launch, and a double-encoded (Base64 + GZip) payload delivered via dynamic code execution. The payload is consistent with techniques used by PowerShell Empire, Cobalt 
… [17282 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 19:31:54 UTC

# RE Report — 14a42d6418b3
_Generated 2026-08-09T19:31:54.113748+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=58.07s -->

# Executive Summary

The sample identified by SHA256 hash `14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2` is assessed as **malicious PowerShell-based malware** with high confidence. This top-line verdict is based on converging evidence from automated detections and deep analysis, though specific runtime behaviors are not fully confirmed.

| Aspect | Assessment | Confidence | Evidence & Inter
… [44605 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
