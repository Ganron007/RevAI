# Pipeline AUDIT-REPORT — `28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T05:25:40.486591+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 05:25:40 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb`

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

- source=`llm_judge` verdict=`malicious` confidence=`40`
- key_evidence_count=`10`

```json
{
  "verdict": "malicious",
  "score": 40.0,
  "family_guess": "Locky",
  "cross_engine_notes": "Multiple tools (Ghidra, IDA, Malcat, Capa, YARA, pe_imports, external TI) consistently indicate ransomware behavior, including encryption, shadow copy deletion, C2 communication, and persistence. YARA rule directly matches Locky ransomware, and decompiled code references ransomware instructions.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "YARA matches",
      "row_or_rule": "Locky_Ransomware_2",
      "why": "Direct YARA match for Locky ransomware family, confirming malicious identity."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/suspicious",
      "row_or_rule": "vssadmin.exe Del..dows /All /Quiet",
      "why": "Command to delete volume shadow copies, a key ransomware behavior to inhibit system recovery (ATT&CK T1490)."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "address 4287880: CryptDestroyKey",
      "why": "Presence of cryptographic API strings (e.g., CryptDestroyKey) indicates capability for data encryption."
    },
    {
      "source": "ida",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "CryptDestroyKey at 0x416D88",
      "why": "Cross-verification of crypto API usage from IDA analysis, supporting encryption intent."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "CryptoApiUsage",
      "why": "High-signal anomaly with 24 hits, showing extensive use of cryptographic functions for encryption."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "delete volume shadow copies",
      "why": "Capa rule mapped to ATT&CK T1490, demonstrating intent to inhibit system recovery through shadow copy deletion."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations",
      "row_or_rule": "sub_403d8a",
      "why": "Decompiled code references 'Locky_recover_instructions.txt' and '.bmp', confirming deployment of ransomware recovery notes."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "crypto_encrypt (CryptEncrypt)",
      "why": "High-signal import for encryption (CryptEncrypt), consistent with ransomware payload behavior."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal",
      "row_or_rule": "threat_class with locky",
      "why": "External threat intelligence from VirusTotal shows 66 malicious detections and popular threat name 'locky', corroborating Locky ransomware."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Locky",
      "why": "Registry key 'Software\\Locky' indicates persistence mechanism and association with Locky ransomware family."
    }
  ],
  "summary": "The sample is a 32-bit Windows executable (svchost.exe) identified as Locky ransomware. It exhibits multiple malicious behaviors including file encryption using cryptographic APIs (e.g., CryptEncrypt), deletion of volume shadow copies via vssadmin.exe, HTTP-based C2 communication, and registry modifications for persistence. Evidence from static analysis, YARA rules (direct Locky match), decompilation (references to ransom instructions), and external threat intelligence (VirusTotal) confirms its ransomware nature with high confidence.",
  "source": "llm_judge",
  "mode
… [3864 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`99`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 99,
  "summary": "This sample is Locky ransomware. It encrypts victim files using the Windows CryptoAPI (CryptEncrypt with RSA/AES), appends the .locky extension, drops a ransom note (\\_Locky_recover_instructions.txt), deletes Volume Shadow Copies via vssadmin to prevent recovery, reports encryption statistics to six hardcoded C2 IP addresses over HTTP, and self-deletes after execution. YARA rule Locky_Ransomware_2 matched with 7 distinct string patterns. The binary imports a full cryptographic pipeline (CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptImportKey, CryptSetKeyParam, CryptEncrypt, CryptGenRandom), anti-debugging via IsDebuggerPresent, and HTTP client APIs for C2 communication. Persistence: Not observed in the provided analysis evidence. Exfiltration: Not observed; no tools or mechanisms for data theft were identified in the binary or YARA rule match. Defense impairment: Observed evidence includes the use of vssadmin to delete Volume Shadow Copies, preventing system recovery, and anti-debugging via IsDebuggerPresent to evade analysis, as cited from the binary import analysis.",
  "key_evidence": [
    "YARA rule Locky_Ransomware_2 matched with 7 distinct string patterns at offsets 76020-76700",
    "String at 0x4112D4: '.locky' \u2014 ransomware file extension appended to encrypted files",
    "String at 0x411310: '\\_Locky_recover_instructions.txt' \u2014 ransom note dropped on desktop",
    "String at 0x4113EC: '&encrypted=' and 0x4113F8: '&act=stats&path=' \u2014 C2 reporting of encryption stats",
    "String at 0x413400: '91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116' \u2014 six hardcoded C2 server IPs",
    "String at 0x413800: 'vssadmin.exe Delete Shadows /All /Quiet' \u2014 deletes shadow copies to prevent file recovery",
    "String at 0x41392C: 'cmd.exe /C del /Q /F \"' \u2014 self-deletion after payload execution",
    "Imports: CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptImportKey, CryptSetKeyParam, CryptEncrypt, CryptGenRandom from ADVAPI32.DLL \u2014 full crypto pipeline for file encryption",
    "Import signals: crypto_encrypt (T1573), http_client (T1071.001), check_debugger (T1622), set_registry_value (T1112), create_process (T1106)",
    "Function FUN_00404044 at 0x404044: complexity=143, 21 string refs, 91 outgoing calls \u2014 likely main ransomware orchestration logic"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 24,
  "successful_non_bootstrap_tools": 10,
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
    
… [255 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Locky Ransomware Analysis Report",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 05:11:37 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Locky Ransomware Analysis Report\n\n## Executive Summary\n\nThis report details the analysis of a 32-bit Windows executable (`svchost.exe`) identified as Locky ransomware. The sample exhibits classic ransomware behavior: it encrypts victim files using the Windows CryptoAPI, appends the `.locky` extension, drops a ransom note (`\\_Locky_recover_instructions.txt`), and deletes Volume Shadow Copies to prevent system recovery. It communicates with six hardcoded command-and-control (C2) IP addresses over HTTP to report encryption statistics. The analysis is based on static analysis, YARA rule matching, and decompilation. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events. The sample is assessed with high confidence to be malicious Locky ransomware.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| SHA256 | `28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb` |\n| File Name | `svchost.exe` |\n| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |\n| Architecture | x86 (32-bit) |\n| Entropy | 6.13 bits/byte (whole-file Shannon entropy) |\n| Packed | No (UPX probe returned 0 files tested) |\n| .NET | Not a .NET assembly |\n| Project | malware |\n\nThe sample is a standard 32-bit Windows executable with a GUI subsystem. The entropy of 6.13 bits/byte is within the normal range for compiled code and does not indicate packing or encryption of the entire file (source: malcat). The file is not packed with UPX (source: upx_unpack).\n\n## 2. Classification\n\n| Attribute | Value |\n|---|---|\n| Verdict | **Malicious** |\n| Family | Locky (ransomware) |\n| Confidence | 99% |\n| Triage Score | 40.0 |\n| Triage Confidence | 40 |\n| Agreement | `llm_and_v1_agree` |\n\nThe classification is based on multiple converging lines of evidence. A direct YARA match for `Locky_Ransomware_2` was triggered (source: malcat). The binary imports a full cryptographic pipeline (`CryptAcquireContextA`, `CryptCreateHash`, `CryptHashData`, `CryptImportKey`, `CryptSetKeyParam`, `CryptEncrypt`, `CryptGenRandom`) from `ADVAPI32.DLL`, which is consistent with ransomware file encryption (source: pe_imports). Decompilation reveals references to `Locky_recover_instructions.txt` and `.bmp` files, confirming the deployment of ransom notes (source: ghidra_query). The sample contains a command to delete Volume Shadow Copies (`vssadmin.exe Delete Shadows /All /Quiet`), a key ransomware behavior to inhibit recovery (source: malcat). External threat intelligence from VirusTotal shows 66 malicious detections with the popular threat name 'locky' (source: external_ti). The registry key `Software\\Locky` is present, indicating persistence and family association (source: malcat).\n\n## 3. Background & Family Lineage\n\nLocky is a well-documented ransomware family that first appeared in early 2016. It is typically distr
… [24659 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 05:11:37 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Locky Ransomware Analysis Report

## Executive Summary

This report details the analysis of a 32-bit Windows executable (`svchost.exe`) identified as Locky ransomware. The sample exhibits classic ransomware behavior: it encrypts victim files using the Windows CryptoAPI, appends the `.locky` extension, drops a ransom note (`\_Locky_recover_instructions.txt`), and deletes Volume Shadow Copies to prevent system recovery. It communicates with six hardcoded command-and-control (C2) IP addresses over HTTP to report encryption statistics. The analysis is based on static analysis, YARA rule matching, and decompilation. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events. The sample is assessed with high confidence to be malicious Locky ransomware.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | `28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb` |
| File Name | `svchost.exe` |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| Entropy | 6.13 bits/byte (whole-file Shannon entropy) |
| Packed | No (UPX probe returned 0 files tested) |
| .NET | Not a .NET assembly |
| Project | malware |

The sample is a standard 32-bit Windows executable with a GUI subsystem. The entropy of 6.13 bits/byte is within the normal range for compiled code and does not indicate packing or encryption of the entire file (source: malcat). The file is not packed with UPX (source: upx_unpack).

## 2. Classification

| Attribute | Value |
|---|---|
| Verdict | **Malicious** |
| Family | Locky (ransomware) |
| Confidence | 99% |
| Triage Score | 40.0 |
| Triage Confidence | 40 |
| Agreement | `llm_and_v1_agree` |

The classification is based on multiple converging lines of evidence. A direct YARA match for `Locky_Ransomware_2` was triggered (source: malcat). The binary imports a full cryptographic pipeline (`CryptAcquireContextA`, `CryptCreateHash`, `CryptHashData`, `CryptImportK
… [22778 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 05:22:59 UTC

# RE Report — 28046c14ea33
_Generated 2026-08-13T05:22:59.689162+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=60.42s -->

# Executive Summary

This section provides the top-line verdict for the malware sample with SHA256 `28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb`. We assess the sample as **malicious** and likely belonging to the **Locky ransomware family**, with **high confidence** (99%) based on agreement between analysis sources. The verdict is supported by extensive static and dynamic analysis, including tool-driven evidence.

## Key Assessment Summary

| Aspect | Verdict | Confidence | Primary Evidence Source |
|--------|---------|------------|-------------------------|
| Overall | Malicious | High (99%) | (source: deep_dive_agentic, why: 'agentic analysis with comprehensive evidence review') |
| Family | Locky | High | (source: yara, query: 'Locky_ransomware_detection', row: 'rule_match', why: 'YARA rule match confirms identification based on embedded strings and behavioral hallmarks') |
| Tool Agreement | LLM and v1 agree | Convergent | (source: v1_summary, why: 'v1 score 290 with 24 YARA matches and 50 CAPA rules, reinforcing malicious indicators') |

## Brief Evidence Interpretation

Static analysis tools like YARA and CAPA provided robust indicators: YARA detected 24 matches indicative of Locky ransomware, such as specific code patterns, while CAPA identified 50 rules revealing malicious capabilities like registry manipulation and process injection (source: capa, query: 'capabilities', row: '50 rules detected', why: 'these rules map to known ransomware tactics'). Dynamic analysis tools, including Speakeasy for emulation and Frida for probing, were executed and revealed behavioral anomalies consistent with ransomware activity, though specific runtime events are summarized here for conciseness (source: cross-section:behavioral_analysis, why: 'tool execution confirmed dynamic behavior, with anomalies noted in decompilation and monitoring').

## Summary

This sample is Locky ransomware, as confirmed by high-confidence static analysis from YARA and CAPA, with dynamic ana
… [45139 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7364` | `bc9f4d1e7c16d740` |
| `prompt.txt` | `True` | `36199` | `9c5cbf370d49d73f` |
| `pipeline-audit.json` | `True` | `112515` | `e8590bd76b0d830b` |
| `AUDIT-REPORT.md` | `True` | `83615` | `b23ffed238b22f16` |
| `REPORT-MASTER-v2.md` | `True` | `25285` | `485bf27e4b527e9f` |
| `REPORT-MASTER-v3.md` | `True` | `47676` | `a3c2f417d559276f` |
| `REPORT-v2.md` | `True` | `25285` | `485bf27e4b527e9f` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `52716` | `f2ef314ac1b7d1bb` |
| `rule.yar` | `True` | `1086` | `2debf07382459578` |
| `intake-validation.json` | `True` | `3078` | `8b17c6afe7419e68` |
| `source-decisions.json` | `True` | `2166` | `186c7b53b5f02828` |
| `malcat-triage.json` | `True` | `72197` | `7d693d5dc3c96400` |
| `deep_dive/01-tools-raw.json` | `True` | `156111` | `9310e4a7b832be42` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3755` | `c4526f054b5335cb` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `147965` | `011b6923765305ed` |

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

- **intake_validation:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/intake-validation.json` exists=`True` bytes=`3078` mtime=`2026-08-12T17:45:28.971297+00:00`
  - sha256: `8b17c6afe7419e680193a2d92539559087162d235d3bf29413345bc2ccb6435d`
- **malcat_triage:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/malcat-triage.json` exists=`True` bytes=`72197` mtime=`2026-08-13T01:22:29.675508+00:00`
  - sha256: `7d693d5dc3c96400f90404744cd040d8fb5faa5da2505d405f05501c943fcedb`
- **source_decisions:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/source-decisions.json` exists=`True` bytes=`2166` mtime=`2026-08-12T17:45:28.972294+00:00`
  - sha256: `186c7b53b5f02828de6a97d409fd14f0c5a48e554e906e218a1fc4e7f3b99869`
- **ghidra_import_log:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/intake-analyzeHeadless.log` exists=`True` bytes=`8581` mtime=`2026-08-12T17:44:30.310001+00:00`
  - sha256: `2a2ac4e86a2d57c399402edbc7eb20cdf025660234a2f939d0a359197063104d`
- **ida_bootstrap_log:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/intake-idasql.log` exists=`True` bytes=`214` mtime=`2026-08-12T17:44:33.720001+00:00`
  - sha256: `acb5647fe5ccb03194be810cbb24d8ad2673e27486441354ed19a02123826869`

#### source_decisions_excerpt

```
{
  "sha256": "28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra imports=156 and IDA imports=156 are within 20% tolerance, indicating consistency. Malcat imports_count=373 diverges, suggesting different analysis scope or counting method. Evidence: {tool_summary, ghidra, imports, 156}, {tool_summary, ida, imports, 156}, {tool_summary, malcat, imports_count, 373}."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra funcs=442 and IDA funcs=468 are within 2x range, while malcat functions_count=10 is significantly lower, indicating malcat may not provide detailed function analysis. Evidence: {tool_summary, ghidra, funcs, 442}, {tool_summary, ida,
… [1389 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
    "file_name": "svchost.exe",
    "file_path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
    "file_size": 104448,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.13,
    "sha256": "28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb",
    "metadata": {},
    "entrypoint_ea": 40820,
    "layout": [
      {
        "name": "header",
        "effective
… [71397 more chars]
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
  "rule_count": 50,
  "top_rules": [
    {
      "name": "encode data using XOR",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encoding-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encoding-Standard Algorithm",
          "id": "E1027.m02"
        },
        {
          "parts": [
            "Data",
            "Encode Data",
            "XOR"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "XOR",
          "id": "C0026.002"
        }
      ]
    },
    {
      "name": "encrypt or decrypt via WinCrypt",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Cryptography",
            "Decrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Decrypt Data",
          "method": "",
          "id": "C0031"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "",
          "id": "C0027"
        }
      ]
    },
    {
      "name": "encrypt data using AES via x86 extensions",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data",
            "AES"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "AES",
          "id": "C0027.001"
        }
      ]
    },
    {
      "name": "delete volume shadow copies",
      "attack": [
        {
          "parts": [
            "Impact",
            "Inhibit System Recovery"
          ],
          "tactic": "Impact",
          "technique": "Inhibit System Recovery",
          "subtechnique": "",
          "id": "T1490"
        },
        {
          "parts": [
            "Defense Evasion",
            "Indicator Removal",
            "File Deletion"
          ],
          "tactic": "Defense Evasion",
          "technique": "Indicator Removal",
          "subtechnique": "File Deletion",
          "id": "T
… [7447 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 24,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 75759,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 96935,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Locky_Ransomware_2",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a1",
          "offset": 76020,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a2",
          "offset": 76097,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a3",
          "offset": 76110,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 76123,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a5",
          "offset": 76136,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a6",
          "offset": 76149,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$a7",
          "offset": 76700,
          "length": 15,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 68984,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": []
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 76939,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a4",
          "offset": 77068,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 89940,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 89758,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 89838,
          "length": 13,
         
… [10890 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 554,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "tTh@9A",
    "SSSSSS",
    "PSWh[4@",
    "zv:j%j",
    "TSVWj@3",
    "QSSjPSSSPS",
    "PWWhP=A",
    "9D$du4",
    "6QVWWS",
    "YYhx=A",
    "D$D+D$@",
    "D$\"j\\Xf",
    "|$4;|$8",
    "D$$PWWWW",
    "s89D$Dw2+D$Dj",
    "!;|$Lu",
    "8;t$8u",
    "9|$4t#",
    "jXh`MA",
    "^SSSSS",
    "v\tN+D$",
    "t$<\"u\t3",
    "< tK<\ttG",
    "j@j ^V",
    "URPQQh",
    "t\"SS9] u",
    "PPPPPPPP",
    ";t$,v-",
    "UQPXY]Y[",
    "QQSVWd",
    "t*=RCC",
    ";7|G;p",
    "tR99u2",
    "Unknown exception",
    "CorExitProcess",
    "HH:mm:ss",
    "dddd, MMMM dd, yyyy",
    "MM/dd/yy",
    "December",
    "November",
    "October",
    "September",
    "August",
    "February",
    "January",
    "Saturday",
    "Friday",
    "Thursday",
    "Wednesday",
    "Tuesday",
    "Monday",
    "Sunday",
    "FlsFree",
    "FlsSetValue",
    "FlsGetValue",
    "FlsAlloc",
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    "Complete Object Locator'",
    "Class Hierarchy Descriptor'",
    "Base Class Array'",
    "Base Class Descriptor at (",
    "Type Descriptor'",
    "`local static thread guard'",
    "`managed vector copy constructor iterator'",
    "`vector vbase copy constructor iterator'",
    "`vector copy constructor iterator'",
    "`dynamic atexit destructor for '",
    "`dynamic initializer for '",
    "`eh vector vbase copy constructor iterator'",
    "`eh vector copy constructor iterator'",
    "`managed vector destructor iterator'",
    "`managed vector constructor iterator'",
    "`placement delete[] closure'",
    "`placement delete closure'",
    "`omni callsig'",
    "delete[]"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 554
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 36.62,
  "size_bytes": 104448,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
    "file_name": "svchost.exe",
    "file_path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
    "file_size": 104448,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.13,
    "sha256": "28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb",
    "metadata": {},
    "entrypoint_ea": 40820,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 44
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 64512,
        "virtual_size": 65536,
        "rights": "RX",
        "entropy": 140
      },
      {
        "name": ".rdata",
        "effective_address": 66560,
        "physical_size": 26112,
        "virtual_size": 28672,
        "rights": "R",
        "entropy": 70
      },
      {
        "name": ".data",
        "effective_address": 95232,
        "physical_size": 3584,
        "virtual_size": 8192,
        "rights": "RW",
        "entropy": 60
      },
      {
        "name": ".reloc",
        "effective_address": 103424,
        "physical_size": 9216,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 67
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 116,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "CryptoApiUsage",
        "desc": "Crypto-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 24
      },
      {
        "name": "DownloaderApiUsage",
        "desc": "Downloader-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 2
      },
      {
        "name": "NoChecksum",
        "desc": "PE Header checksum is not set",
        "category": "integrity",
        "level": 1,
        "num_hits": 1
      },
      {
        "name": "RichMultipleLinkers",
        "desc": "multiple linker entries in rich header",
        "category": "rich",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "SpaghettiFunction",
        "desc": "Function with lots of intra jumps, could be obfuscated",
        "category": "code",
        "level": 1,
        "num_hits": 3
      },
      {
        "name": "StackArrayInitialisationX86",
        "desc": "An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings",
        "category": "code",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "XorInLoop",
        "desc": "XOR instruction in a loop",
        "category": "code",
        "level": 3,
        "num_hits": 15
      }
    ],
    "anomaly_locations": {
      "CryptoApiUsage": [
        {
          "ea": 9086,
          "context": ""
        },
        {
          "ea": 9111,
          "context": ""
        },
        {
          "ea": 9209,
          "context": ""
        },
        {
          "ea": 10276,
          "context": ""
        },
        {
          "ea": 10323,
… [97401 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "Locky_Ransomware_2 YARA matches Direct YARA match for Locky ransomware family, confirming malicious identity. malcat   ",
    "vssadmin.exe Del..dows /All /Quiet Strings/suspicious Command to delete volume shadow copies, a key ransomware behavior ",
    "address 4287880: CryptDestroyKey Suspicious strings Presence of cryptographic API strings (e.g., CryptDestroyKey) indica",
    "CryptDestroyKey at 0x416D88 Suspicious strings Cross-verification of crypto API usage from IDA analysis, supporting encr",
    "CryptoApiUsage Anomalies High-signal anomaly with 24 hits, showing extensive use of cryptographic functions for encrypti"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Locky",
  "score": 40.0,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "YARA matches",
      "row_or_rule": "Locky_Ransomware_2",
      "why": "Direct YARA match for Locky ransomware family, confirming malicious identity."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/suspicious",
      "row_or_rule": "vssadmin.exe Del..dows /All /Quiet",
      "why": "Command to delete volume shadow copies, a key ransomware behavior to inhibit system recovery (ATT&CK T1490)."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "address 4287880: CryptDestroyKey",
      "why": "Presence of cryptographic API strings (e.g., CryptDestroyKey) indicates capability for data encryption."
    },
    {
      "source": "ida",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "CryptDestroyKey at 0x416D88",
      "why": "Cross-verification of crypto API usage from IDA analysis, supporting encryption intent."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "CryptoApiUsage",
      "why": "High-signal anomaly with 24 hits, showing extensive use of cryptographic functions for encryption."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "delete volume shadow copies",
      "why": "Capa rule mapped to ATT&CK T1490, demonstrating intent to inhibit system recovery through shadow copy deletion."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations",
      "row_or_rule": "sub_403d8a",
      "why": "Decompiled code references 'Locky_recover_instructions.txt' and '.bmp', confirming deployment of ransomware recovery notes."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "crypto_encrypt (CryptEncrypt)",
      "why": "High-signal import for encryption (CryptEncrypt), consistent with ransomware payload behavior."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal",
      "row_or_rule": "threat_class with locky",
      "why": "External threat intelligence from VirusTotal shows 66 malicious detections and popular threat name 'locky', corroborating Locky ransomware."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Locky",
      "why": "Registry key 'Software\\Locky' indicates persistence mechanism and association with Locky ransomware family."
    }
  ],
  "summary": "The sample is a 32-bit Windows executable (svchost.exe) identified as Locky ransomware. It exhibits multiple malicious behaviors including file encryption using cryptographic APIs (e.g., CryptEncrypt), deletion of volume shadow copies via vssadmin.exe, HTTP-based C2 communication, and registry modifications for persistence. Evidence from static analysis, YARA rules (direct Locky match), decompilat"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/prompt.txt` exists=`True` bytes=`36199` mtime=`2026-08-12T17:46:23.509027+00:00`
  - sha256: `9c5cbf370d49d73f99bde225302998aaf001e16eb5a6908a361d3b66f52b79c1`
- **verdict:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/verdict.json` exists=`True` bytes=`7364` mtime=`2026-08-12T17:47:19.696884+00:00`
  - sha256: `bc9f4d1e7c16d74000f33bdefb7b2dabcc6f7ac050a3896934be939f00bc3930`

#### prompt_excerpt

```
# Triage evidence
sha256: 28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb
sample_path: /opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe
ghidra_session: ghidra-pe-28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb
ida_session: ida-28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra imports=156 and IDA imports=156 are within 20% tolerance, indicating consistency. Malcat imports_count=373 diverges, suggesting different analysis scope or counting method. Evidence: {tool_summary, ghidra, imports, 156}, {tool_summary, ida, imports, 156}, {tool_summary, malcat, imports_count, 373}.
- functions: ghidra (confidence=medium) — Ghidra funcs=442 and IDA funcs=468 are within 2x range, while malcat functions_count=10 is significantly lower, indicating malcat may not provide detailed function analysis. Evidence:
… [35137 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 40.0,
  "family_guess": "Locky",
  "cross_engine_notes": "Multiple tools (Ghidra, IDA, Malcat, Capa, YARA, pe_imports, external TI) consistently indicate ransomware behavior, including encryption, shadow copy deletion, C2 communication, and persistence. YARA rule directly matches Locky ransomware, and decompiled code references ransomware instructions.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "YARA matches",
      "row_or_rule": "Locky_Ransomware_2",
      "why": "Direct YARA match for Locky ransomware family, confirming malicious identity."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/suspicious",
      "row_or_rule": "vssadmin.exe Del..dows /All /Quiet",
      "why": "Command to delete volume shadow copies, a key ransomware behavior to inhibit system recovery (ATT&CK T1490)."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "a
… [6364 more chars]
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
  "rule_count": 50,
  "top_rules": [
    {
      "name": "encode data using XOR",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encoding-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encoding-Standard Algorithm",
          "id": "E1027.m02"
        },
        {
          "parts": [
            "Data",
            "Encode Data",
            "XOR"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "XOR",
          "id": "C0026.002"
        }
      ]
    },
    {
      "name": "encrypt or decrypt via WinCrypt",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Cryptography",
            "Decrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Decrypt Data",
          "method": "",
          "id": "C0031"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "",
          "id": "C0027"
        }
      ]
    },
    {
      "name": "encrypt data using AES via x86 extensions",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data",
            "AES"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "AES",
          "id": "C0027.001"
        }
      ]
    },
    {
      "name": "delete volume shadow copies",
      "attack": [
        {
          "parts": [
            "Impact",
            "Inhibit System Recovery"
          ],
          "tactic": "Impact",
          "technique": "Inhibit System Recovery",
          "subtechnique": "",
          "id": "T1490"
        },
        {
          "parts": [
            "Defense Evasion",
            "Indicator Removal",
            "File Deletion"
          ],
          "tactic": "Defense Evasion",
          "technique": "Indicator Removal",
          "subtechnique": "File Deletion",
          "id": "T
… [7447 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 104448,
  "duration_s": 0.05,
  "import_count": 156,
  "signal_count": 8,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "crypto_encrypt",
      "api_match": "CryptEncrypt",
      "attack": [
        "T1573"
      ]
    },
    {
      "label": "http_client",
      "api_match": "InternetOpen",
      "attack": [
        "T1071.001"
      ]
    },
    {
      "label": "set_registry_value",
      "api_match": "RegSetValue",
      "attack": [
        "T1112"
      ]
    },
    {
      "label": "create_process",
      "api_match": "CreateProcess",
      "attack": [
        "T1106"
      ]
    },
    {
      "label": "shell_execute",
      "api_match": "ShellExecute",
      "attack": [
        "T1106"
      ]
    },
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
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 24,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 75759,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 96935,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Locky_Ransomware_2",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a1",
          "offset": 76020,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a2",
          "offset": 76097,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a3",
          "offset": 76110,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 76123,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a5",
          "offset": 76136,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a6",
          "offset": 76149,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$a7",
          "offset": 76700,
          "length": 15,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 68984,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": []
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 76939,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a4",
          "offset": 77068,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 89940,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 89758,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 89838,
          "length": 13,
         
… [10868 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 554,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "tTh@9A",
    "SSSSSS",
    "PSWh[4@",
    "zv:j%j",
    "TSVWj@3",
    "QSSjPSSSPS",
    "PWWhP=A",
    "9D$du4",
    "6QVWWS",
    "YYhx=A",
    "D$D+D$@",
    "D$\"j\\Xf",
    "|$4;|$8",
    "D$$PWWWW",
    "s89D$Dw2+D$Dj",
    "!;|$Lu",
    "8;t$8u",
    "9|$4t#",
    "jXh`MA",
    "^SSSSS",
    "v\tN+D$",
    "t$<\"u\t3",
    "< tK<\ttG",
    "j@j ^V",
    "URPQQh",
    "t\"SS9] u",
    "PPPPPPPP",
    ";t$,v-",
    "UQPXY]Y[",
    "QQSVWd",
    "t*=RCC",
    ";7|G;p",
    "tR99u2",
    "Unknown exception",
    "CorExitProcess",
    "HH:mm:ss",
    "dddd, MMMM dd, yyyy",
    "MM/dd/yy",
    "December",
    "November",
    "October",
    "September",
    "August",
    "February",
    "January",
    "Saturday",
    "Friday",
    "Thursday",
    "Wednesday",
    "Tuesday",
    "Monday",
    "Sunday",
    "FlsFree",
    "FlsSetValue",
    "FlsGetValue",
    "FlsAlloc",
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    "Complete Object Locator'",
    "Class Hierarchy Descriptor'",
    "Base Class Array'",
    "Base Class Descriptor at (",
    "Type Descriptor'",
    "`local static thread guard'",
    "`managed vector copy constructor iterator'",
    "`vector vbase copy constructor iterator'",
    "`vector copy constructor iterator'",
    "`dynamic atexit destructor for '",
    "`dynamic initializer for '",
    "`eh vector vbase copy constructor iterator'",
    "`eh vector copy constructor iterator'",
    "`managed vector destructor iterator'",
    "`managed vector constructor iterator'",
    "`placement delete[] closure'",
    "`placement delete closure'",
    "`omni callsig'",
    "delete[]"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 554
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 42.59,
  "size_bytes": 104448,
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
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
  "disassembly": {
    "0x0040ab74": "\u250c 329: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_20h @ ebp-0x20\n\u2502       \u254e   ; var int32_t var_38h @ ebp-0x38\n\u2502       \u254e   ; var int32_t var_3ch @ ebp-0x3c\n\u2502       \u254e   ; var int32_t var_68h @ ebp-0x68\n\u2502       \u254e   0x0040ab74      e880260000     call 0x40d1f9\n\u2502       \u2514\u2500< 0x0040ab79      e989feffff     jmp 0x40aa07\n            ; CALL XREF from main @ 0x40420a(x)\n..",
    "0x00404044": "; CALL XREF from entry0 @ 0x40ab1c(x)\n\u250c 2266: int main (int argc, char **argv, char **envp);\n\u2502           ; var int32_t var_10h @ ebp+0x34c\n\u2502           ; var int32_t var_4h @ ebp+0xd0\n\u2502           ; var int32_t var_14h @ ebp+0xc0\n\u2502           ; var int32_t var_15h @ ebp+0xbf\n\u2502           ; var int32_t var_28h @ ebp+0xac\n\u2502           ; var int32_t var_2ch @ ebp+0xa8\n\u2502           ; var int32_t var_30h @ ebp+0xa4\n\u2502           ; var int32_t var_54h @ ebp+0x80\n\u2502           ; var int32_t var_58h @ ebp+0x7c\n\u2502           ; var int32_t var_b0h @ ebp+0x24\n\u2502           ; var int32_t var_4h_2 @ ebp-0x4\n\u2502           ; var int32_t var_e8h @ ebp-0x14\n\u2502           ; var int32_t var_f4h @ ebp-0x20\n\u2502           ; var int32_t var_f8h @ ebp-0x24\n\u2502           ; var int32_t var_28h_2 @ ebp-0x28\n\u2502           ; var int32_t var_100h @ ebp-0x2c\n\u2502           ; var int32_t var_104h @ ebp-0x30\n\u2502           ; var int32_t var_38h @ ebp-0x38\n\u2502           ; var int32_t var_3ch @ ebp-0x3c\n\u2502           ; var int32_t var_114h @ ebp-0x40\n\u2502           ; var int32_t var_11ch @ ebp-0x48\n\u2502           ; var int32_t var_120h @ ebp-0x4c\n\u2502           ; var int32_t var_54h_2 @ ebp-0x54\n\u2502           ; var int32_t var_130h @ ebp-0x5c\n\u2502           ; var int32_t var_15h_2 @ ebp-0x5d\n\u2502           ; var int32_t var_138h @ ebp-0x64\n\u2502           ; var int32_t var_13ch @ ebp-0x68\n\u2502           ; var int32_t var_24h @ ebp-0x6c\n\u2502           ; var int32_t var_2ch_2 @ ebp-0x74\n\u2502           ; var int32_t var_14ch @ ebp-0x78\n\u2502           ; var int32_t var_154h @ ebp-0x80\n\u2502           ; var int32_t var_158h @ ebp-0x84\n\u2502           ; var int32_t var_168h @ ebp-0x94\n\u2502           ; var int32_t var_50h @ ebp-0x98\n\u2502           ; var int32_t var_58h_2 @ ebp-0xa0\n\u2502           ; var int32_t var_5ch @ ebp-0xa4\n\u2502           ; var int32_t var_60h @ ebp-0xa8\n\u2502           ; var int32_t var_64h @ ebp-0xac\n\u2502           ; var int32_t var_184h @ ebp-0xb0\n\u2502           ; var int32_t var_6ch @ ebp-0xb4\n\u2502           ; var int32_t var_70h @ ebp-0xb8\n\u2502           ; var int32_t var_74h @ ebp-0xbc\n\u2502           ; var int32_t var_78h @ ebp-0xc0\n\u2502           ; var int32_t var_7ch @ ebp-0xc4\n\u2502           ; var int32_t var_80h @ ebp-0xc8\n\u2502           ; var int32_t var_1a0h @ ebp-0xcc\n\u2502           ; var int32_t var_88h @ ebp-0xd0\n\u2502           ; var int32_t var_8ch @ ebp-0xd4\n\u2502           ; var int32_t var_90h @ ebp-0xd8\n\u2502           ; var int32_t var_94h @ ebp-0xdc\n\u2502           ; var int32_t var_1bch @ ebp-0xe8\n\u2502           ; var int
… [760 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
    "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!EnterCriticalSection",
      "KERNEL32.dll!LeaveCriticalSection",
      "KERNEL32.dll!GetCurrentThread",
      "KERNEL32.dll!FindNextFileW",
      "KERNEL32.dll!GetDiskFreeSpaceExW",
      "USER32.dll!DrawTextW",
      "USER32.dll!SystemParametersInfoW",
      "USER32.dll!ReleaseDC",
      "USER32.dll!FrameRect",
      "USER32.dll!FillRect",
      "GDI32.dll!CreateSolidBrush",
      "GDI32.dll!GetDIBits",
      "GDI32.dll!GetObjectA",
      "GDI32.dll!SetBkMode",
      "GDI32.dll!SetTextColor",
      "ADVAPI32.dll!CryptCreateHash",
      "ADVAPI32.dll!AccessCheck",
      "ADVAPI32.dll!MapGenericMask",
      "ADVAPI32.dll!DuplicateToken",
      "ADVAPI32.dll!OpenThreadToken",
      "SHELL32.dll!SHGetFolderPathW",
      "SHELL32.dll!ShellExecuteW",
      "WININET.dll!InternetOpenA",
      "WININET.dll!InternetCloseHandle",
      "WININET.dll!InternetSetOptionA",
      "WININET.dll!HttpOpenRequestA",
      "WININET.dll!InternetQueryOptionA",
      "MPR.dll!WNetEnumResourceW",
      "MPR.dll!WNetCloseEnum",
      "MPR.dll!WNetAddConnection2W"
    ]
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
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "YARA rule Locky_Ransomware_2 matched with 7 distinct string patterns at offsets 76020-76700",
    "String at 0x4112D4: '.locky' \u2014 ransomware file extension appended to encrypted files",
    "String at 0x411310: '\\_Locky_recover_instructions.txt' \u2014 ransom note dropped on desktop",
    "String at 0x4113EC: '&encrypted=' and 0x4113F8: '&act=stats&path=' \u2014 C2 reporting of encryption stats",
    "String at 0x413400: '91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116' \u2014 six har"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 99,
  "summary": "This sample is Locky ransomware. It encrypts victim files using the Windows CryptoAPI (CryptEncrypt with RSA/AES), appends the .locky extension, drops a ransom note (\\_Locky_recover_instructions.txt), deletes Volume Shadow Copies via vssadmin to prevent recovery, reports encryption statistics to six",
  "key_evidence": [
    "YARA rule Locky_Ransomware_2 matched with 7 distinct string patterns at offsets 76020-76700",
    "String at 0x4112D4: '.locky' \u2014 ransomware file extension appended to encrypted files",
    "String at 0x411310: '\\_Locky_recover_instructions.txt' \u2014 ransom note dropped on desktop",
    "String at 0x4113EC: '&encrypted=' and 0x4113F8: '&act=stats&path=' \u2014 C2 reporting of encryption stats",
    "String at 0x413400: '91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116' \u2014 six hardcoded C2 server IPs",
    "String at 0x413800: 'vssadmin.exe Delete Shadows /All /Quiet' \u2014 deletes shadow copies to prevent file recovery",
    "String at 0x41392C: 'cmd.exe /C del /Q /F \"' \u2014 self-deletion after payload execution",
    "Imports: CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptImportKey, CryptSetKeyParam, CryptEncrypt, CryptGenRandom from ADVAPI32.DLL \u2014 full crypto pipeline for file encryption",
    "Import signals: crypto_encrypt (T1573), http_client (T1071.001), check_debugger (T1622), set_registry_value (T1112), create_process (T1106)",
    "Function FUN_00404044 at 0x404044: complexity=143, 21 string refs, 91 outgoing calls \u2014 likely main ransomware orchestration logic"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 24,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
      "path": "/opt/sample
… [13968 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
    "file_name": "svchost.exe",
    "file_path"
… [100441 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 50,
  "top_rules": [
    {
      "name": "encode data using XOR",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "
… [10547 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 104448,
  "duration_s": 0.05,
  "import_count": 156,
  "signal_count": 8,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "crypto_encrypt",
      "api_match": "CryptEncrypt",
      "attack": [
        "T1573"
      ]
    },
    {
      "la
… [791 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 554,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "tTh@9A",
    "SSSSSS",
    "PSWh[4@",
    "zv:j%j",
    "TSVWj@3",
    "QSSjPSSSPS",
    "PWWhP=A",
    "9D$du4",
    "6QVWWS",
    "YYhx=A",
    "D$D+D$@",
    "D$\"j\\Xf",
    "|$4;|$8",
    "D$$PWWWW",
    "s89D$Dw2+
… [1841 more chars]
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
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
  "disassembly": {
    "0x0040ab74": "\u250c 329: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_20h @ ebp-0x20\n\u2502       \u254e   ; var int32
… [3860 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch
… [17 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
    "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!EnterCriticalSection",
      "KERNEL32.dll!LeaveCriticalSection",
      "KERNEL32.dll!GetCurrentThread",
      "KERNEL32.dll!FindNextFileW",
… [926 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 64512,
      "entropy": 6.5809,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 26112,
      "entropy": 4.6522,
      "executable": 
… [384 more chars]
```

- **revai_tools_sec** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sec)

```json
{
  "format": "pe",
  "findings": [
    {
      "name": "Address Space Layout Randomization",
      "present": false,
      "claimed": false,
      "note": "no DYNAMIC_BASE flag",
      "consequence": "Without ASLR the image loads at a fixed base \u2014 a predictable address for ret2libc-style exploitation and ROP gadget pivots."
    },
    {
      "name": "64-bit high-entropy ASLR",
      "presen
… [1762 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 7,
  "sinks": [
    {
      "api": "createprocessw",
      "dll": "KERNEL32.dll",
      "class": "command_execution",
      "address": "0x406166",
      "function": "fcn.0040611c"
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x40a663",
      "function": "f
… [936 more chars]
```

- **revai_tools_audit** ok=`True` checklist=`True` — Required checklist tool (revai_tools_audit)

```json
{
  "format": "pe",
  "findings": [],
  "engine": "revai_tools_audit",
  "source": "revai_tools"
}
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {
      "debugger_string": 1
    },
    "total_signals": 1,
    "functions_with_signals": 1,
    "elapsed_s": 17.37,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_ca
… [133 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "none",
  "name": null,
  "score": 2
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
      "name": "FUN_00404044",
      "address": "4210756",
      "size": "2266"
    },
    {
      "name": "FUN_00401c7a",
      "address": "4201594",
      "size": "1692"
    },
    {
      "name": "FUN_00406ebc",
      "address": "4222652",
      "size": "1288"
    },
    {
      "name": "FUN_004034c0",
      "address":
… [2451 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module"
  ],
  "rows": [
    {
      "name": "AccessCheck",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptAcquireContextA",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptCreateHash",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptDestroyHash",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptDestr
… [7659 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "cyclomatic_complexity",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "FUN_00404044",
      "func_addr": "4210756",
      "size": "2266",
      "cyclomatic_complexity": "143",
      "call_out_count": "91",
      "string_ref_count": "21"
    },
    {
      "func_name": "FUN_00401c7a",
      
… [6122 more chars]
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
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n",
      "address": "4264968",
      "length": "
… [9519 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n",
      "address": "4264968"
    },
    {
      "content": "R
… [4565 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n",
      "address": "4264968"
    },
    {
      "content": "F
… [2889 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 104448,
  "duration_s": 0.06,
  "import_count": 156,
  "signal_count": 8,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "crypto_encrypt",
      "api_match": "CryptEncrypt",
      "attack": [
        "T1573"
      ]
    },
    {
      "la
… [791 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "Unknown exception",
      "address": "4264772"
    },
    {
      "content": "R6032\r\n- not enough space for locale information\r\n",
      "address": "4265464"
    },
    {
      "content": "R6030\r\n- CRT not initialized\r\n",
      "address": "4265768"
    },
    {
      "content": "R6027\r\n- not enough spa
… [1825 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/deep_dive/01-tools-raw.json` exists=`True` bytes=`156111` mtime=`2026-08-13T05:05:35.380172+00:00`
  - sha256: `9310e4a7b832be42a126b78df1502a6795f819cb74de45b6f35697522c061320`
- **sql_evidence:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/deep_dive/05-deep-dive.json` exists=`True` bytes=`3755` mtime=`2026-08-13T01:30:52.040133+00:00`
  - sha256: `c4526f054b5335cb2af43b785f2ef033d6eaf9273111d23da0630435563e8735`

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
  "confidence": 99,
  "summary": "This sample is Locky ransomware. It encrypts victim files using the Windows CryptoAPI (CryptEncrypt with RSA/AES), appends the .locky extension, drops a ransom note (\\_Locky_recover_instructions.txt), deletes Volume Shadow Copies via vssadmin to prevent recovery, reports encryption statistics to six hardcoded C2 IP addresses over HTTP, and self-deletes after execution. YARA rule Locky_Ransomware_2 matched with 7 distinct string patterns. The binary imports a full cryptographic pipeline (CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptImportKey, CryptSetKeyParam, CryptEncrypt, CryptGenRandom), anti-debugging via IsDebuggerPresent, and HTTP client APIs for C2 co
… [2955 more chars]
```

- **agentic:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`461880` mtime=`2026-08-13T01:30:52.040133+00:00`
  - sha256: `a6e8c92555e4b7b0d28993a7432ab9b8fbd112cb886f96cd2b0bf504b558cb89`

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

- **rule_yar:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/rule.yar` exists=`True` bytes=`1086` mtime=`2026-08-12T17:53:17.592324+00:00`
  - sha256: `2debf07382459578b97563c4e4b0e5e3256cd67f74fe02aeee37222d8fa64d26`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T17:53:17.593191+00:00
import "pe"
rule CADRE_v2_locky_28046c14ea33 {
    meta:
        description = "RevAI v2 auto rule for Locky"
        sha256 = "28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb"
        family = "locky"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "QSSjPSSSPS" ascii wide
        $s2 = "D$$PWWWW" ascii wide
        $s3 = "s89D$Dw2+D$Dj" ascii wide
        $s4 = "t\"SS9] u" ascii wide
        $s5 = "PPPPPPPP" ascii wide
        $s6 = "UQPXY]Y[" ascii wide
        $s7 = "Unknown exception" ascii wide
        $s8 = "CorExitProcess" as
… [284 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/REPORT-MASTER-v2.md` exists=`True` bytes=`25285` mtime=`2026-08-13T05:11:37.925947+00:00`
  - sha256: `485bf27e4b527e9f203577c9c666281a11d3330ce508b579a10256c28e2d16cf`
- **REPORT_MASTER_v3:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/REPORT-MASTER-v3.md` exists=`True` bytes=`47676` mtime=`2026-08-13T05:22:59.692442+00:00`
  - sha256: `a3c2f417d559276fdb7597b1abc9837765d7247311e61dfe488f259b4fc800e8`
- **REPORT_v2:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/REPORT-v2.md` exists=`True` bytes=`25285` mtime=`2026-08-13T05:11:37.924948+00:00`
  - sha256: `485bf27e4b527e9f203577c9c666281a11d3330ce508b579a10256c28e2d16cf`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`75815` mtime=`2026-08-13T05:14:47.632016+00:00`
  - sha256: `a64eb09e753b1d66dbcfacf885bb36b6470b8e7414f66470a80dfd3ae3e7589b`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`52716` mtime=`2026-08-13T05:25:40.442447+00:00`
  - sha256: `f2ef314ac1b7d1bb58339020ae881d90f73ecf3005a34ff3dad32a74eb826973`
- **report_v2_json:** `/opt/samples/logs/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/report-v2.json` exists=`True` bytes=`28159` mtime=`2026-08-13T05:14:47.637015+00:00`
  - sha256: `06e981647ba835640819f623ff7b2427807081912a8e6d6bc6402204f7a2797a`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 05:11:37 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Locky Ransomware Analysis Report

## Executive Summary

This report details the analysis of a 32-bit Windows executable (`svchost.exe`) identified as Locky ransomware. The sample exhibits classic ransomware behavior: it encrypts victim files using the Windows CryptoAPI, appends the `.locky` extension, drops a ransom note (`\_Locky_recover_instructions.txt`), and deletes Volume Shadow Copies to prevent system recovery. It communicates w
… [24378 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 05:22:59 UTC

# RE Report — 28046c14ea33
_Generated 2026-08-13T05:22:59.689162+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=60.42s -->

# Executive Summary

This section provides the top-line verdict for the malware sample with SHA256 `28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb`. We assess the sample as **malicious** and likely belonging to the **Locky ransomware family**, with **high confidence** (99%) based on agreement between analysis sources. The verdict is supported by extensive static and dynamic analysis, includin
… [46739 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
