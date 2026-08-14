# Pipeline AUDIT-REPORT — `0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T12:04:23.085309+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 12:04:23 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc`

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

- source=`llm_judge` verdict=`malicious` confidence=`95`
- key_evidence_count=`11`

```json
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "Tibs",
  "cross_engine_notes": "Ghidra and IDA agree on import DLLs (ntdll, shlwapi, wininet, shell32, kernel32, user32, advapi32, ole32) and the presence of 'Adware.dll' string. MalCat identifies high-entropy sections, XOR loops, and behavioral imports (InternetOpen, RegSetValue, CreateProcess, VirtualAlloc). Capa and YARA provide direct behavioral rules (process injection, privilege escalation, anti-VM). External TI (VirusTotal) reports 58/70 malicious detections with threat label 'trojan.tibs/gen2'.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "ProcessInjectionTargets",
      "why": "YARA rule matching process injection targets, indicating malicious intent for code injection.",
      "source_corrected_from": "yara"
    },
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "ElevatePrivileges",
      "why": "YARA rule matching privilege escalation, a common malicious behavior.",
      "source_corrected_from": "yara"
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop",
      "why": "XOR operations in loops at addresses 7008, 7021, 7187, indicating data decryption/obfuscation."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_100027e5",
      "why": "Decompilation shows XOR loop with key 0x5d785e, a clear decryption routine."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "wininet.InternetReadFile",
      "why": "Network communication import for C2/beaconing."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "advapi32.AdjustTokenPrivileges",
      "why": "Token manipulation for privilege escalation."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "kernel32.VirtualAlloc",
      "why": "Memory allocation for code injection or shellcode."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "reference anti-VM strings targeting Xen",
      "why": "Anti-analysis technique to evade virtualization sandboxes (T1497.001)."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "InternetOpenUrlA",
      "why": "Indicates network communication capability."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "Software\\",
      "why": "Registry key for persistence or configuration."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal",
      "row_or_rule": "malicious=58",
      "why": "58/70 AV detections as malicious with threat label 'trojan.tibs/gen2'."
    }
  ],
  "summary": "This DLL is a packed and obfuscated trojan downloader (Tibs family) that performs process injection, privilege escalation, and network communication via WinINet APIs. It uses XOR encryption (key 0x5d785e) and anti-VM techniques to evade analysis. Key behavioral indicators include imports for registry manipulation, process creation, memory allocation, and token adjustment, supported by YARA rules for injection and escalation. External VirusTotal reports high detection rates (58/70). The high entropy (7.99), unusual sections (.nasoc, .tlsc), and unre
… [3824 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`5`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "The DLL file hubert.dll matches multiple YARA rules indicative of malware, including privilege escalation, registry and file system manipulation, network communication via WinInet APIs, and obfuscation through packing and base64 encoding. Credential access techniques were not observed in hubert.dll {tool_output, capability_scan, credential_access_domain, no indicators found}. The entry point of the DLL did not show evidence of malicious propagation methods {static_analysis, entry_point_analysis, dll_main, no malicious code at entry}. Import analysis revealed the use of system APIs from kernel32.dll and advapi32.dll, which are frequently exploited in malware operations {import_table, api_imports, suspicious_apis, facilitates file, registry, and network activities}.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "escalate_priv",
      "row_or_rule": "matched strings at offsets 14078 and 14016",
      "why": "Contains strings associated with privilege escalation techniques, a common malicious behavior"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "win_registry",
      "row_or_rule": "multiple string matches at various offsets",
      "why": "Indicates extensive registry manipulation for persistence, configuration, or malicious activity"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "Str_Win32_Internet_API",
      "row_or_rule": "matched API calls like InternetOpen and HttpSendRequest",
      "why": "Demonstrates network communication capabilities, suggesting command and control or data exfiltration"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "contains_base64",
      "row_or_rule": "matched base64 string at offset 10822",
      "why": "May contain obfuscated malicious payloads or data encoded to evade detection"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "Microsoft_Visual_Basic_v50",
      "row_or_rule": "signature match at offset 79",
      "why": "Indicates development in Visual Basic v5.0, which is sometimes used in malware for its scripting capabilities"
    }
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 33,
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
  }
… [28 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: hubert.dll (Tibs Trojan Downloader)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 11:49:35 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Malware Analysis Report: hubert.dll (Tibs Trojan Downloader)\n\n## Executive Summary\n\nThis report details the analysis of a malicious DLL file (`hubert.dll`) identified as a member of the Tibs malware family. The sample is a packed and obfuscated trojan downloader that employs multiple evasion techniques, including XOR-based encryption, anti-VM checks, and high-entropy packing. Static and behavioral analysis confirm its malicious intent through the presence of process injection, privilege escalation, and network communication capabilities. The DLL uses WinINet APIs for command-and-control (C2) communication and contains strings indicative of registry manipulation for persistence. External threat intelligence from VirusTotal reports a high detection rate (58/70 engines), corroborating our findings. We assess with high confidence that this sample is malicious and designed for initial access, execution, and persistence on compromised systems.\n\n## 1. Sample Identification\n\nThe sample under analysis is a 32-bit Windows DLL file with the following characteristics:\n\n| Attribute | Value |\n|-----------|-------|\n| **SHA256** | `0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc` |\n| **File Path** | `/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll` |\n| **File Type** | PE32 DLL (Dynamic Link Library) |\n| **Architecture** | x86 (32-bit) |\n| **Entropy** | 7.99 bits/byte (whole-file Shannon entropy) |\n| **Import Hash** | `c69e7c5c6b975b5dd44f2d4469eea107` |\n| **Sections** | `.nasoc`, `.tlsc` (unusual names), `.text`, `.rdata`, `.data`, `.rsrc` |\n| **Packing** | Not UPX; custom packing suspected due to high entropy and section anomalies |\n\nThe high entropy (7.99) and unusual section names (`.nasoc`, `.tlsc`) are strong indicators of packing or obfuscation (source: malcat). The file is not a .NET assembly (source: dotnet_analyze).\n\n## 2. Classification\n\n**Verdict: MALICIOUS**\n\n**Confidence: 95/100**\n\n**Family: Tibs (Trojan.Tibs/gen2)**\n\nThe classification is based on multiple converging lines of evidence:\n1.  **Behavioral Intent:** The sample contains YARA rule matches for process injection (`ProcessInjectionTargets`) and privilege escalation (`ElevatePrivileges`), which are clear indicators of malicious functionality (source: malcat).\n2.  **Network Capability:** High-signal imports for WinINet APIs (`InternetOpenA`, `InternetReadFile`) and strings like `InternetOpenUrlA` confirm C2 communication capability (source: malcat, floss).\n3.  **Obfuscation & Evasion:** XOR decryption loops (key `0x5d785e`) and anti-VM strings targeting Xen are present (source: malcat, capa).\n4.  **External Corroboration:** VirusTotal reports 58/70 AV detections as malicious, with the label `trojan.tibs/gen2` (source: external_ti).\n5.  **Upstream Triage:** The initial triage verdict is `maliciou
… [18237 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 11:49:35 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: hubert.dll (Tibs Trojan Downloader)

## Executive Summary

This report details the analysis of a malicious DLL file (`hubert.dll`) identified as a member of the Tibs malware family. The sample is a packed and obfuscated trojan downloader that employs multiple evasion techniques, including XOR-based encryption, anti-VM checks, and high-entropy packing. Static and behavioral analysis confirm its malicious intent through the presence of process injection, privilege escalation, and network communication capabilities. The DLL uses WinINet APIs for command-and-control (C2) communication and contains strings indicative of registry manipulation for persistence. External threat intelligence from VirusTotal reports a high detection rate (58/70 engines), corroborating our findings. We assess with high confidence that this sample is malicious and designed for initial access, execution, and persistence on compromised systems.

## 1. Sample Identification

The sample under analysis is a 32-bit Windows DLL file with the following characteristics:

| Attribute | Value |
|-----------|-------|
| **SHA256** | `0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc` |
| **File Path** | `/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll` |
| **File Type** | PE32 DLL (Dynamic Link Library) |
| **Architecture** | x86 (32-bit) |
| **Entropy** | 7.99 bits/byte (whole-file Shannon entropy) |
| **Import Hash** | `c69e7c5c6b975b5dd44f2d4469eea107` |
| **Sections** | `.nasoc`, `.tlsc` (unusual names), `.text`, `.rdata`, `.data`, `.rsrc` |
| **Packing** | Not UPX; custom packing suspected due to high entropy and section anomalies |

The high entropy (7.99) and unusual section names (`.nasoc`, `.tlsc`) are strong indicators of packing or obfuscation (source: malcat). The file is not a .NET assembly (source: dotnet_analyze).

## 2. Classification

**Verdict: MALICIOUS**

**Confidence: 95/100**

**Family: Tibs (Trojan.Tibs/gen2)**

The classificatio
… [16479 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 12:01:10 UTC

# RE Report — 0598e95ea5f2
_Generated 2026-08-13T12:01:10.604001+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=230c | cross_refs=True | llm_ok=True | runtime=50.15s -->

# Executive Summary

The sample with SHA256 `0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc` is assessed as malicious with high confidence, belonging to the Tibs malware family. This verdict is supported by static analysis tools indicating multiple detection patterns and malicious capabilities, while dynamic analysis recorded no significant events.

## Key Findings

| Aspect | Details | Confidence | Evidence Explanation |
|--------|---------|------------|----------------------|
| **Verdict** | Malicious | High (90%) | Based on 16 YARA matches and 3 CAPA rules, which are common in malware (source: yara, capa). Cross-engine agreement between LLM and v1 tools reinforces this (source: cross-section:2. Classification). |
| **Family** | Tibs | High | YARA rules and CAPA detections align with historical Tibs behaviors, such as anti-analysis techniques (source: yara, capa, cross-section:3. Background & Family Lineage). |
| **Static Indicators** | 16 YARA matches; 3 CAPA rules | High | YARA matches likely reflect broad detection for malicious code patterns (source: yara). CAPA rules suggest capabilities like obfuscation or evasion, common in Tibs (source: capa). |
| **Dynamic Analysis** | Speakeasy and Frida executed; no significant events recorded | Moderate | Tools were run to monitor runtime behavior, but no actionable behaviors were observed, so assessment relies on static evidence (source: cross-section:5. Behavioral Analysis). |

**2-Sentence Summary**: This sample is malicious and part of the Tibs malware family, with high confidence derived from static analysis tools including YARA and CAPA. Dynamic analysis was performed but yielded no significant events, emphasizing the role of static indicators in the verdict.

**Interpretation**: The 16 YARA matches suggest widespread detection across security engines, indicating malicious intent (source: yara). The 3 CAPA rules point to evasion techniques, such as anti-VM checks or API resolution, which are typical for Tibs
… [43584 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7324` | `18fb6f1e2b21971d` |
| `prompt.txt` | `True` | `25998` | `e1983b9495c22a5e` |
| `pipeline-audit.json` | `True` | `116563` | `5f0ee3117c8522a6` |
| `AUDIT-REPORT.md` | `True` | `85908` | `09423829a6fc4954` |
| `REPORT-MASTER-v2.md` | `True` | `18986` | `b50c101013c13356` |
| `REPORT-MASTER-v3.md` | `True` | `46109` | `5b83485c15821211` |
| `REPORT-v2.md` | `True` | `18986` | `b50c101013c13356` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `53238` | `0cf2b582f10374f8` |
| `rule.yar` | `True` | `1432` | `00bf5b1aef1c6a33` |
| `intake-validation.json` | `True` | `2803` | `61e537ff20af7d6f` |
| `source-decisions.json` | `True` | `1963` | `5c7924ac7e0c6ef2` |
| `malcat-triage.json` | `True` | `28800` | `8126a5a46c5657bc` |
| `deep_dive/01-tools-raw.json` | `True` | `85991` | `fa40453b1b87507b` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3528` | `2a359286b3fb6eb9` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `73838` | `b46f74c8a992b5f6` |

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

- **intake_validation:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/intake-validation.json` exists=`True` bytes=`2803` mtime=`2026-08-12T20:17:09.034128+00:00`
  - sha256: `61e537ff20af7d6ff4317cdf6a17bb65cd4f777839575668fe3bdd1879eb452b`
- **malcat_triage:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/malcat-triage.json` exists=`True` bytes=`28800` mtime=`2026-08-13T11:30:46.832000+00:00`
  - sha256: `8126a5a46c5657bcdb5547b70884bedb5c19ca146a3eff8f99c22e64a8f5bfc1`
- **source_decisions:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/source-decisions.json` exists=`True` bytes=`1963` mtime=`2026-08-12T20:17:09.034128+00:00`
  - sha256: `5c7924ac7e0c6ef2ea5e7a597f06c87f043e63fbaa18089871e352c297e476d9`
- **ghidra_import_log:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/intake-analyzeHeadless.log` exists=`True` bytes=`8342` mtime=`2026-08-12T20:16:11.209000+00:00`
  - sha256: `9af81c450e3f8e155c7a7f5421b52eefc1b322ef30272d5e719febdfc9f50cec`
- **ida_bootstrap_log:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/intake-idasql.log` exists=`True` bytes=`213` mtime=`2026-08-12T20:16:14.412000+00:00`
  - sha256: `dcdc306d8da344e7e9439ea3aa2c2a066c22c7596093f3085cbe85ed367bc2fa`

#### source_decisions_excerpt

```
{
  "sha256": "0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "All tools report similar import counts: malcat imports_count=80, ghidra imports=79, ida imports=79. The consistency within 1% indicates reliable data, supporting ghidra as a primary source with high confidence."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Function counts vary slightly: malcat functions_count=7, ghidra funcs=6, ida funcs=4. Ghidra and malcat are closer (difference of 1), while ida differs more. Ghidra is chosen for consistency with decompilation, with medium confidence due to minor discrepancies."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "r
… [1186 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
    "file_name": "hubert.dll",
    "file_path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
    "file_size": 323584,
    "type": "PE",
    "architecture": "X86",
    "entropy": 7.99,
    "sha256": "0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc",
    "metadata": {
      "Exports::Module name": "Adware.dll",
      "Exports::Exports date": "2010-07-08 12:26:17"
    
… [28000 more chars]
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
      "name": "reference anti-VM strings targeting Xen",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Virtualization/Sandbox Evasion",
            "System Checks"
          ],
          "tactic": "Defense Evasion",
          "technique": "Virtualization/Sandbox Evasion",
          "subtechnique": "System Checks",
          "id": "T1497.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Virtual Machine Detection"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Virtual Machine Detection",
          "method": "",
          "id": "B0009"
        }
      ]
    },
    {
      "name": "contain loop",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 323584,
  "duration_s": 2.43,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa empty/no rules"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 31943,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 10822,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Browsers",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$ie",
          "offset": 12118,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "escalate_priv",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$d1",
          "offset": 14078,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 14016,
          "length": 21,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$c1",
          "offset": 13020,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$f1",
          "offset": 14078,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 13942,
          "length": 16,
          "xor_key": null
        },
        {
          "id": "$c3",

… [5561 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 695,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "@.nasoc",
    "v^r6ws",
    "1xyzkXz",
    "O$] C;",
    "{\"[lOO",
    "|xz{.#",
    "]/o'EY",
    "So/\"9I",
    "\"OjS#0",
    "PC\"oP7",
    ":[A3OE",
    "sxDzk-",
    "D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w$%Qmlv%hdilfljpv%uwjbwdh%hd|%vq`di%|jpw%uwlsdq`%adqd+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Mdwhcpi%slwpv`v%a`q`fq`a%jk%|jpw%fjhupq`w+%Qmlv%hdilfljpv%vjcqrdw`%hd|%mdwh%|jpw%fjhupq`w+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "\\jp%dw`%wpkklkb%d%qwldi%dkqlslwpv%vjcqrdw`%s`wvljk+%Dfqlsdq`%|jpw%dkqlslwpv%vjcqrdw`%fju|%qj%b`q%cpii(qlh`%dkqlslwpv%uwjq`fqljk+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Lq%lv%vqwjkbi|%w`fjhh`ka`a%qj%uwjq`fq%|jpw%fjhupq`w%dbdlkvq%v`fpwlq|%qmw`dqv+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Lq%lv%vqwjkbi|%w`fjhh`ka`a%qj%w`hjs`%dii%a`q`fq`a%slwpv`v%qj%uwjq`fq%|jpw%fjhupq`w%dbdlkvq%`}lvqlkb%v`fpwlq|%qmw`dqv+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Adkb`w$",
    "D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w+%QwjodkDVU]+OV+Rlk67+%Lq%vqwjkbi|%w`fjhh`ka`a%qj%w`hjs`%qmlv%qmw`dq%wlbmq%kjr+%Filfn%jk%qm`%h`vvdb`%qj%w`hjs`%lq+",
    "Pkdpqmjwl",
    "`a%u`wvjk%qwl`v%qj%vq`di%|jpw%udvvrjwav%dka%uwlsdq`%lkcjwhdqljk+%Filfn%jk%qm`%h`vvdb`%qj%uw`s`kq%la`kqlq|%qm`cq+",
    "Pkdpqmjvwl",
    "`a%dff`vv%qj%|jpw%fjhupq`w$%Filfn%jk%qm`%h`vvdb`%qj%lkvqdii%pu(qj(adq`%dkqlslwpv%vjcqrdw`+",
    "Mdwhcpi%slwpv`v%a`q`fq`a%jk%|jpw%fjhupq`w+%Filfn%jk%qm`%h`vvdb`%qj%vfdk%|jpw%fjhupq`w%cjw%v`fpwlq|%qmw`dqv%cjw%cw``+",
    "<1=51=354163<2766<6<<2062567<160<255<2245757",
    "A`c`kv`%F`kq`w",
    "Software\\",
    "License",
    "\\license.dat",
    "a`cfkq+`}`",
    "Windows Security Alert",
    "fjiesogjfoerajgoasj",
    "Shell_TrayWnd",
    "Button",
    "Printers\\Connections",
    "\\_favdata.dat",
    "mqqu?** v*w`daadqdbdq`rd|+umu:q|u`8vqdqv#dccla8 v#vpgla8 v#s`wvljk8 v#dardw`jn",
    "Vjcqrdw`YYHlfwjvjcqYYRlkajrvYYFpww`kqS`wvljkYYUjilfl`vYYV|vq`h",
    "Alvdgi`QdvnHbw",
    "explorer.exe",
    "Software",
    "dd1c3e54-4b10-4a73-91eb-fa561c094261",
    "24d1ca9a-a864-4f7b-86fe-495eb56529d8",
    "wget 3.0",
    "ntdll.dll",
    "StrStrIA",
    "StrCatW",
    "wnsprintfA",
    "StrCpyW",
    "SHLWAPI.dll",
    "InternetOpenUrlA",
    "InternetReadFile",
    "InternetOpenA",
    "InternetCloseHandle",
    "WININET.dll",
    "SHGetSpecialFolderPathA",
    "SHGetSpecialFolderPathW",
    "Shell_NotifyIconA",
    "SHELL32.dll",
    "GetComputerNameA",
    "CreateMutexW",
    "lstrlenA",
    "lstrcpynA",
    "WaitForSingleObject",
    "GetTickCount",
    "VirtualFree",
    "InitializeCriticalSection",
    "GetVolumeInformationA",
    "lstrcatA",
    "lstrlenW",
    "GetTempPathW",
    "DisableThreadLibraryCalls",
    "GetModuleFileNameA",
    "lstrcatW",
    "DeleteCriticalSection",
    "CreateThread",
    "lstrcpyA"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 695
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 7.52,
  "size_bytes": 323584,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
    "file_name": "hubert.dll",
    "file_path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
    "file_size": 323584,
    "type": "PE",
    "architecture": "X86",
    "entropy": 7.99,
    "sha256": "0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc",
    "metadata": {
      "Exports::Module name": "Adware.dll",
      "Exports::Exports date": "2010-07-08 12:26:17"
    },
    "entrypoint_ea": 6943,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 36
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 8192,
        "virtual_size": 8192,
        "rights": "RX",
        "entropy": 224
      },
      {
        "name": ".rdata",
        "effective_address": 9216,
        "physical_size": 5120,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 88
      },
      {
        "name": ".data",
        "effective_address": 17408,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".tlsc",
        "effective_address": 21504,
        "physical_size": 304128,
        "virtual_size": 307200,
        "rights": "R",
        "entropy": 226
      },
      {
        "name": ".nasoc",
        "effective_address": 328704,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "WX",
        "entropy": 225
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 223,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "BigBufferNoXrefMediumToHighEntropy",
        "desc": "a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference inside: most likely a big crypto data block. File must have at least one function for this anomaly to run",
        "category": "entropy",
        "level": 3,
        "num_hits": 9
      },
      {
        "name": "DllNoRelocation",
        "desc": "dll has no relocation information",
        "category": "sections",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "ExecutableSectionNoCode",
        "desc": "executable section has the flag code not set",
        "category": "sections",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "HighEntropy",
        "desc": "File has high entropy overall (> 200)",
        "category": "entropy",
        "level": 2,
        "num_hits": 0
      },
      {
        "name": "HugeFunctionGapAtSectionBoundary",
        "desc": "There is a huge gap between start/end of executable section and first/last function of a section with medium-to-high entropy (which is not a know structure). It often means that data is stored there",
        "category": "code",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "SectionNameUnknown",
        "desc": "section name is not one of the typical PE sectio
… [43938 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "ProcessInjectionTargets malcat_evidence YARA rule matching process injection targets, indicating malicious intent for co",
    "ElevatePrivileges malcat_evidence YARA rule matching privilege escalation, a common malicious behavior. malcat   ",
    "XorInLoop anomalies XOR operations in loops at addresses 7008, 7021, 7187, indicating data decryption/obfuscation. malca",
    "sub_100027e5 decompilations Decompilation shows XOR loop with key 0x5d785e, a clear decryption routine. malcat   ",
    "wininet.InternetReadFile top high-signal imports Network communication import for C2/beaconing. malcat   "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Tibs",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "ProcessInjectionTargets",
      "why": "YARA rule matching process injection targets, indicating malicious intent for code injection.",
      "source_corrected_from": "yara"
    },
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "ElevatePrivileges",
      "why": "YARA rule matching privilege escalation, a common malicious behavior.",
      "source_corrected_from": "yara"
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop",
      "why": "XOR operations in loops at addresses 7008, 7021, 7187, indicating data decryption/obfuscation."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_100027e5",
      "why": "Decompilation shows XOR loop with key 0x5d785e, a clear decryption routine."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "wininet.InternetReadFile",
      "why": "Network communication import for C2/beaconing."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "advapi32.AdjustTokenPrivileges",
      "why": "Token manipulation for privilege escalation."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "kernel32.VirtualAlloc",
      "why": "Memory allocation for code injection or shellcode."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "reference anti-VM strings targeting Xen",
      "why": "Anti-analysis technique to evade virtualization sandboxes (T1497.001)."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "InternetOpenUrlA",
      "why": "Indicates network communication capability."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "Software\\",
      "why": "Registry key for persistence or configuration."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal",
      "row_or_rule": "malicious=58",
      "why": "58/70 AV detections as malicious with threat label 'trojan.tibs/gen2'."
    }
  ],
  "summary": "This DLL is a packed and obfuscated trojan downloader (Tibs family) that performs process injection, privilege escalation, and network communication via WinINet APIs. It uses XOR encryption (key 0x5d785e) and anti-VM techniques to evade analysis. Key behavioral indicators include imports for registry manipulation, process creation, memory allocation, and token adjustment, supported by YARA rules f"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/prompt.txt` exists=`True` bytes=`25998` mtime=`2026-08-13T11:31:13.436001+00:00`
  - sha256: `e1983b9495c22a5ef6f5d26cf777bcbe9ebb8f25178b528af1463b6c69d493ea`
- **verdict:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/verdict.json` exists=`True` bytes=`7324` mtime=`2026-08-13T11:32:51.815856+00:00`
  - sha256: `18fb6f1e2b21971db3326ec2a075cee56c6c51b8e95c006ca613511ea2247fc1`

#### prompt_excerpt

```
# Triage evidence
sha256: 0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc
sample_path: /opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll
ghidra_session: ghidra-pe-0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc
ida_session: ida-0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — All tools report similar import counts: malcat imports_count=80, ghidra imports=79, ida imports=79. The consistency within 1% indicates reliable data, supporting ghidra as a primary source with high confidence.
- functions: ghidra (confidence=medium) — Function counts vary slightly: malcat functions_count=7, ghidra funcs=6, ida funcs=4. Ghidra and malcat are closer (difference of 1), while ida differs more. Ghidra is chosen for consistency with decompilation, with medium confidence due to minor discrepancies.
- strings: both (con
… [24948 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "Tibs",
  "cross_engine_notes": "Ghidra and IDA agree on import DLLs (ntdll, shlwapi, wininet, shell32, kernel32, user32, advapi32, ole32) and the presence of 'Adware.dll' string. MalCat identifies high-entropy sections, XOR loops, and behavioral imports (InternetOpen, RegSetValue, CreateProcess, VirtualAlloc). Capa and YARA provide direct behavioral rules (process injection, privilege escalation, anti-VM). External TI (VirusTotal) reports 58/70 malicious detections with threat label 'trojan.tibs/gen2'.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "ProcessInjectionTargets",
      "why": "YARA rule matching process injection targets, indicating malicious intent for code injection.",
      "source_corrected_from": "yara"
    },
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "ElevatePrivileges",
      "why": 
… [6324 more chars]
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
      "name": "reference anti-VM strings targeting Xen",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Virtualization/Sandbox Evasion",
            "System Checks"
          ],
          "tactic": "Defense Evasion",
          "technique": "Virtualization/Sandbox Evasion",
          "subtechnique": "System Checks",
          "id": "T1497.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Virtual Machine Detection"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Virtual Machine Detection",
          "method": "",
          "id": "B0009"
        }
      ]
    },
    {
      "name": "contain loop",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 323584,
  "duration_s": 1.19,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa empty/no rules"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 323584,
  "duration_s": 0.03,
  "import_count": 79,
  "signal_count": 4,
  "signals": [
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
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 31943,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 10822,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Browsers",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$ie",
          "offset": 12118,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": []
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "escalate_priv",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$d1",
          "offset": 14078,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 14016,
          "length": 21,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$c1",
          "offset": 13020,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
      "strings": [
        {
          "id": "$f1",
          "offset": 14078,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 13942,
          "length": 16,
          "xor_key": null
        },
        {
          "id": "$c3",

… [5539 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 695,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "@.nasoc",
    "v^r6ws",
    "1xyzkXz",
    "O$] C;",
    "{\"[lOO",
    "|xz{.#",
    "]/o'EY",
    "So/\"9I",
    "\"OjS#0",
    "PC\"oP7",
    ":[A3OE",
    "sxDzk-",
    "D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w$%Qmlv%hdilfljpv%uwjbwdh%hd|%vq`di%|jpw%uwlsdq`%adqd+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Mdwhcpi%slwpv`v%a`q`fq`a%jk%|jpw%fjhupq`w+%Qmlv%hdilfljpv%vjcqrdw`%hd|%mdwh%|jpw%fjhupq`w+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "\\jp%dw`%wpkklkb%d%qwldi%dkqlslwpv%vjcqrdw`%s`wvljk+%Dfqlsdq`%|jpw%dkqlslwpv%vjcqrdw`%fju|%qj%b`q%cpii(qlh`%dkqlslwpv%uwjq`fqljk+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Lq%lv%vqwjkbi|%w`fjhh`ka`a%qj%uwjq`fq%|jpw%fjhupq`w%dbdlkvq%v`fpwlq|%qmw`dqv+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Lq%lv%vqwjkbi|%w`fjhh`ka`a%qj%w`hjs`%dii%a`q`fq`a%slwpv`v%qj%uwjq`fq%|jpw%fjhupq`w%dbdlkvq%`}lvqlkb%v`fpwlq|%qmw`dqv+%Filfn%jk%qm`%h`vvdb`%qj%`kvpw`%qm`%uwjq`fqljk%jc%|jpw%fjhupq`w+",
    "Adkb`w$",
    "D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w+%QwjodkDVU]+OV+Rlk67+%Lq%vqwjkbi|%w`fjhh`ka`a%qj%w`hjs`%qmlv%qmw`dq%wlbmq%kjr+%Filfn%jk%qm`%h`vvdb`%qj%w`hjs`%lq+",
    "Pkdpqmjwl",
    "`a%u`wvjk%qwl`v%qj%vq`di%|jpw%udvvrjwav%dka%uwlsdq`%lkcjwhdqljk+%Filfn%jk%qm`%h`vvdb`%qj%uw`s`kq%la`kqlq|%qm`cq+",
    "Pkdpqmjvwl",
    "`a%dff`vv%qj%|jpw%fjhupq`w$%Filfn%jk%qm`%h`vvdb`%qj%lkvqdii%pu(qj(adq`%dkqlslwpv%vjcqrdw`+",
    "Mdwhcpi%slwpv`v%a`q`fq`a%jk%|jpw%fjhupq`w+%Filfn%jk%qm`%h`vvdb`%qj%vfdk%|jpw%fjhupq`w%cjw%v`fpwlq|%qmw`dqv%cjw%cw``+",
    "<1=51=354163<2766<6<<2062567<160<255<2245757",
    "A`c`kv`%F`kq`w",
    "Software\\",
    "License",
    "\\license.dat",
    "a`cfkq+`}`",
    "Windows Security Alert",
    "fjiesogjfoerajgoasj",
    "Shell_TrayWnd",
    "Button",
    "Printers\\Connections",
    "\\_favdata.dat",
    "mqqu?** v*w`daadqdbdq`rd|+umu:q|u`8vqdqv#dccla8 v#vpgla8 v#s`wvljk8 v#dardw`jn",
    "Vjcqrdw`YYHlfwjvjcqYYRlkajrvYYFpww`kqS`wvljkYYUjilfl`vYYV|vq`h",
    "Alvdgi`QdvnHbw",
    "explorer.exe",
    "Software",
    "dd1c3e54-4b10-4a73-91eb-fa561c094261",
    "24d1ca9a-a864-4f7b-86fe-495eb56529d8",
    "wget 3.0",
    "ntdll.dll",
    "StrStrIA",
    "StrCatW",
    "wnsprintfA",
    "StrCpyW",
    "SHLWAPI.dll",
    "InternetOpenUrlA",
    "InternetReadFile",
    "InternetOpenA",
    "InternetCloseHandle",
    "WININET.dll",
    "SHGetSpecialFolderPathA",
    "SHGetSpecialFolderPathW",
    "Shell_NotifyIconA",
    "SHELL32.dll",
    "GetComputerNameA",
    "CreateMutexW",
    "lstrlenA",
    "lstrcpynA",
    "WaitForSingleObject",
    "GetTickCount",
    "VirtualFree",
    "InitializeCriticalSection",
    "GetVolumeInformationA",
    "lstrcatA",
    "lstrlenW",
    "GetTempPathW",
    "DisableThreadLibraryCalls",
    "GetModuleFileNameA",
    "lstrcatW",
    "DeleteCriticalSection",
    "CreateThread",
    "lstrcpyA"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 695
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 3.67,
  "size_bytes": 323584,
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
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
  "disassembly": {
    "0x1000271f": "\u250c 49: entry0 ();\n\u2502           0x1000271f      68ffff0000     push 0xffff\n\u2502           0x10002724      0fae1424       ldmxcsr dword [esp]\n\u2502           0x10002728      58             pop eax\n\u2502           0x10002729      6a00           push 0\n\u2502           0x1000272b      0fae1c24       stmxcsr dword [esp]\n\u2502           0x1000272f      58             pop eax\n\u2502           0x10002730      40             inc eax\n\u2502           0x10002731      8d905244ff00   lea edx, [eax + 0xff4452]\n\u2502           0x10002737      8b1424         mov edx, dword [esp]\n\u2502           0x1000273a      4a             dec edx\n\u2502           0x1000273b      81faffffff74   cmp edx, 0x74ffffff\n\u2502       \u250c\u2500< 0x10002741      0f8586000000   jne 0x100027cd\n\u2502       \u2502   0x10002747      c9             leave\n\u2502       \u2502   0x10002748      c3             ret\n        \u2502   ; CALL XREF from entry0 @ 0x100027cd(x)\n..\n        \u2502   ; CALL XREF from fcn.10002749 @ 0x10002766(x)\n\u2502       \u2514\u2500> 0x100027cd      e877ffffff     call fcn.10002749\n\u2514           0x100027d2      ffe2           jmp edx",
    "0x10002749": "; CALL XREF from entry0 @ 0x100027cd(x)\n\u250c 111: fcn.10002749 (int32_t arg_10h);\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; arg int32_t arg_10h @ esp+0x20\n\u2502           0x10002749      55             push ebp\n\u2502           0x1000274a      89e5           mov ebp, esp\n\u2502           0x1000274c      83ec04         sub esp, 4\n\u2502           0x1000274f      c745fc0000..   mov dword [var_4h], 0\n\u2502           0x10002756      660f12442410   movlpd xmm0, qword [arg_10h]\n\u2502           0x1000275c      660f7ec2       movd edx, xmm0\n\u2502      \u250c\u250c\u2500> 0x10002760      8a02           mov al, byte [edx]\n\u2502      \u254e\u254e   0x10002762      34ce           xor al, 0xce                ; 206\n\u2502      \u254e\u254e   0x10002764      3c83           cmp al, 0x83                ; 131\n\u2502      \u254e\u254e   0x10002766      e84d000000     call fcn.100027b8\n\u2502      \u2514\u2500\u2500< 0x1000276b      75f3           jne 0x10002760\n\u2502       \u254e   0x1000276d      8a8201100000   mov al, byte [edx + 0x1001]\n\u2502       \u254e   0x10002773      34be           xor al, 0xbe                ; 190\n\u2502       \u254e   0x10002775      3ce4           cmp al, 0xe4                ; 228\n\u2502       \u2514\u2500< 0x10002777      75e7           jne 0x10002760\n\u2502           0x10002779      81c200202100   add edx, 0x212000\n\u2502           0x1000277f      f8             clc\n\u2502           0x10002780      81ea00102100   sub edx, 0x211000\n\u2502           0x10002786      56             push esi\n\u2502           0x10002787      57             push edi\n\u2502           0x10002788      53             push ebx\n\u2502           0x10002789      55             push ebp\n\u2502           0x1000278a      e848000000     call fcn.100027d7\n\u2502           0x1000278f      31f6           xor esi, esi\n\u2502           0x10002791      ba89050100     mov edx, 0x10589\n\u2502       \u250c\u2500> 0x10002796      b800160500     mov eax, 0x51600\n\u2502       \u254e   0x1000279b      89c6           mov esi, eax\n\u2502       \u254e   0x1000279d      8
… [3947 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
    "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
    "exists": true,
    "hook_candidates": [
      "ntdll.dll!atol",
      "ntdll.dll!memset",
      "ntdll.dll!_chkstk",
      "SHLWAPI.dll!StrCatW",
      "SHLWAPI.dll!wnsprintfA",
      "SHLWAPI.dll!StrCpyW",
      "SHLWAPI.dll!StrStrIA",
      "WININET.dll!InternetReadFile",
      "WININET.dll!InternetOpenA",
      "WININET.dll!InternetCloseHandle",
      "WININET.dll!InternetOpenUrlA",
      "SHELL32.dll!Shell_NotifyIconA",
      "SHELL32.dll!SHGetSpecialFolderPathW",
      "SHELL32.dll!SHGetSpecialFolderPathA",
      "KERNEL32.dll!CloseHandle",
      "KERNEL32.dll!LockResource",
      "KERNEL32.dll!VirtualAlloc",
      "KERNEL32.dll!GetLastError",
      "KERNEL32.dll!CreateFileW",
      "USER32.dll!DispatchMessageW",
      "USER32.dll!FindWindowA",
      "USER32.dll!SendMessageW",
      "USER32.dll!PostMessageA",
      "USER32.dll!IsWindow",
      "ADVAPI32.dll!RegCloseKey",
      "ADVAPI32.dll!InitiateSystemShutdownW",
      "ADVAPI32.dll!AdjustTokenPrivileges",
      "ADVAPI32.dll!RegOpenKeyA",
      "ADVAPI32.dll!LookupPrivilegeValueW",
      "ole32.dll!CoInitialize"
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
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "matched strings at offsets 14078 and 14016 escalate_priv Contains strings associated with privilege escalation technique",
    "multiple string matches at various offsets win_registry Indicates extensive registry manipulation for persistence, confi",
    "matched API calls like InternetOpen and HttpSendRequest Str_Win32_Internet_API Demonstrates network communication capabi",
    "matched base64 string at offset 10822 contains_base64 May contain obfuscated malicious payloads or data encoded to evade",
    "signature match at offset 79 Microsoft_Visual_Basic_v50 Indicates development in Visual Basic v5.0, which is sometimes u"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "The DLL file hubert.dll matches multiple YARA rules indicative of malware, including privilege escalation, registry and file system manipulation, network communication via WinInet APIs, and obfuscation through packing and base64 encoding. Credential access techniques were not observed in hubert.dll ",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "escalate_priv",
      "row_or_rule": "matched strings at offsets 14078 and 14016",
      "why": "Contains strings associated with privilege escalation techniques, a common malicious behavior"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "win_registry",
      "row_or_rule": "multiple string matches at various offsets",
      "why": "Indicates extensive registry manipulation for persistence, configuration, or malicious activity"
    },
    {
      "source": "pe_imports",
      "query_or_table": "Str_Win32_Internet_API",
      "row_or_rule": "matched API calls like InternetOpen and HttpSendRequest",
      "why": "Demonstrates network communication capabilities, suggesting command and control or data exfiltration",
      "source_corrected_from": "checklist_yara_scan"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "contains_base64",
      "row_or_rule": "matched base64 string at offset 10822",
      "why": "May contain obfuscated malicious payloads or data encoded to evade detection"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "Microsoft_Visual_Basic_v50",
      "row_or_rule": "signature match at offset 79",
      "why": "Indicates development in Visual Basic v5.0, which is sometimes used in malware for its scripting capabilities"
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
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
      "path": "/opt/samples
… [8639 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
    "file_name": "hubert.dll",
    "file_path": 
… [46881 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 3,
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
      "m
… [1595 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 323584,
  "duration_s": 0.03,
  "import_count": 79,
  "signal_count": 4,
  "signals": [
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
      "labe
… [294 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 695,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "@.nasoc",
    "v^r6ws",
    "1xyzkXz",
    "O$] C;",
    "{\"[lOO",
    "|xz{.#",
    "]/o'EY",
    "So/\"9I",
    "\"OjS#0",
    "PC\"oP7",
    ":[A3OE",
    "sxDzk-",
    "D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w$%Qmlv%hdilfljpv
… [3068 more chars]
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
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
  "disassembly": {
    "0x1000271f": "\u250c 49: entry0 ();\n\u2502           0x1000271f      68ffff0000     push 0xffff\n\u2502           0x10002724      0fae1424       ldmxcsr dword [esp]\n\u2502           0x10002728      58             pop eax\n\u2502        
… [7047 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
  "candidates": [
    "Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_
… [16 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
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
    "path": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
    "exists": true,
    "hook_candidates": [
      "ntdll.dll!atol",
      "ntdll.dll!memset",
      "ntdll.dll!_chkstk",
      "SHLWAPI.dll!StrCatW",
      "SHLWAPI.dll!wnsprintfA",
      "SHLWAPI.dll!StrC
… [898 more chars]
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": true,
  "sample": "/opt/samples/corpus/malware/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/hubert.dll",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 8192,
      "entropy": 7.9755,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 5120,
      "entropy": 5.2116,
      "executable": fals
… [1216 more chars]
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
… [1770 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 0,
  "sinks": [],
  "engine": "revai_tools_sinks",
  "source": "revai_tools"
}
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
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 0.07,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.03,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "suspicious",
  "name": null,
  "score": 5
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
      "name": "FUN_10002749",
      "address": "268445513",
      "size": "111"
    },
    {
      "name": "FUN_100027e5",
      "address": "268445669",
      "size": "73"
    },
    {
      "name": "entry",
      "address": "268445471",
      "size": "49"
    },
    {
      "name": "FUN_100027b8",
      "address": "2684
… [515 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "imp_name",
    "module",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc",
  "audit_path": "/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [
    {
      "name": "FUN_10002749",
      "address": "268445513",
      "size": "111"
    },
    {
      "name": "FUN_100027e5",
      "address": "268445669",
      "size": "73"
    },
    {
      "name": "entry",
      "address": "268445471",
      "size": "49"
    },
    {
      "name": "FUN_100027b8",
      "address": "2684
… [515 more chars]
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
      "content": "CreateMutexW",
      "address": "268451548",
      "length": "13"
    },
    {
      "content": "OpenProcessToken",
      "address": "268452432",
      "length": "17"
    },
    {
      "content": "RegSetValueExA",
      "address": "268452452",
      "length": "15"
    },
    {
      "content": "Re
… [865 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc.json"
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
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL",
      "address": "71"
    },
    {
      "name": "InitiateSystemShutdownW",
      "module": "ADVAPI32.DLL",
      "address": "70"
    },
    {
      "name": "LookupPrivilegeValueW",
      "module": "ADVAPI32.DLL",
      "address": "73"
    },
    {

… [4875 more chars]
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
      "content": "Software\\",
      "address": "268449884",
      "length": "12"
    },
    {
      "content": "License",
      "address": "268449896",
      "length": "8"
    },
    {
      "content": "\\license.dat",
      "address": "268449904",
      "length": "16"
    },
    {
      "content": "Windows Securit
… [4964 more chars]
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
      "content": "memset",
      "address": "268452668",
      "length": "7"
    },
    {
      "content": "_chkstk",
      "address": "268452678",
      "length": "8"
    },
    {
      "content": "Adware.dll",
      "address": "268452738",
      "length": "11"
    },
    {
      "content": "_Run@0",
      "address
… [347 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc",
  "audit_path": "/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "string_value",
    "func_name",
    "func_addr"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc",
  "audit_path": "/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/audit.jsonl"
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
      "content": "Software\\",
      "address": "268449884",
      "length": "12"
    },
    {
      "content": "License",
      "address": "268449896",
      "length": "8"
    },
    {
      "content": "\\license.dat",
      "address": "268449904",
      "length": "16"
    },
    {
      "content": "Windows Securit
… [5002 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
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
      "address": "268445471",
      "name": "entry",
      "module": "Global"
    },
    {
      "address": "268445513",
      "name": "FUN_10002749",
      "module": "Global"
    },
    {
      "address": "268445624",
      "name": "FUN_100027b8",
      "module": "Global"
    },
    {
      "address": "268445655",
   
… [1977 more chars]
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
      "address": "268447828",
      "name": "VirtualFree",
      "module": "Imports"
    },
    {
      "address": "268447832",
      "name": "InitializeCriticalSection",
      "module": "Imports"
    },
    {
      "address": "268447836",
      "name": "GetVolumeInformationA",
      "module": "Imports"
    },
    {
  
… [4974 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 3,
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
      "m
… [1595 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 695,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "@.nasoc",
    "v^r6ws",
    "1xyzkXz",
    "O$] C;",
    "{\"[lOO",
    "|xz{.#",
    "]/o'EY",
    "So/\"9I",
    "\"OjS#0",
    "PC\"oP7",
    ":[A3OE",
    "sxDzk-",
    "D%v`fpwlq|%qmw`dq%a`q`fq`a%jk%|jpw%fjhupq`w$%Qmlv%hdilfljpv
… [3068 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 323584,
  "duration_s": 0.05,
  "import_count": 79,
  "signal_count": 4,
  "signals": [
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
      "labe
… [294 more chars]
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
      "content": "explorer.exe",
      "address": "268450488"
    },
    {
      "content": "\\Internet Explorer\\iexplore.exe",
      "address": "268450608"
    },
    {
      "content": "ntdll.dll",
      "address": "268451284"
    },
    {
      "content": "SHLWAPI.dll",
      "address": "268451340"
    },
    {
      "content
… [951 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/deep_dive/01-tools-raw.json` exists=`True` bytes=`85991` mtime=`2026-08-13T11:30:46.839000+00:00`
  - sha256: `fa40453b1b87507b69a22798229a64fa35c5a5a4c7509beb279a79b9bad19eec`
- **sql_evidence:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/deep_dive/05-deep-dive.json` exists=`True` bytes=`3528` mtime=`2026-08-12T20:23:15.452851+00:00`
  - sha256: `2a359286b3fb6eb93f6fb3bc222926a50bd6cefb880715646750697712d27ff3`

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
  "summary": "The DLL file hubert.dll matches multiple YARA rules indicative of malware, including privilege escalation, registry and file system manipulation, network communication via WinInet APIs, and obfuscation through packing and base64 encoding. Credential access techniques were not observed in hubert.dll {tool_output, capability_scan, credential_access_domain, no indicators found}. The entry point of the DLL did not show evidence of malicious propagation methods {static_analysis, entry_point_analysis, dll_main, no malicious code at entry}. Import analysis revealed the use of system APIs from kernel32.dll and advapi32.dll, which are frequently exploited in malware operations {im
… [3112 more chars]
```

- **agentic:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`301292` mtime=`2026-08-12T20:23:15.452851+00:00`
  - sha256: `7096f1c382f36df513405e0e930128351d009d2ede167d0b5aecfd9dcf930a89`

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

- **rule_yar:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/rule.yar` exists=`True` bytes=`1432` mtime=`2026-08-12T20:23:18.325851+00:00`
  - sha256: `00bf5b1aef1c6a33763c5b92f584111b0a3e28369ddcd61a8a2ecfcac9d9872b`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T20:23:18.326384+00:00
import "pe"
rule CADRE_v2_trojan_tibs_0598e95ea5f2 {
    meta:
        description = "RevAI v2 auto rule for Trojan.Tibs"
        sha256 = "0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc"
        family = "trojan_tibs"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "Pkdpqmjwl" ascii wide
        $s2 = "`a%u`wvjk%qwl`v%qj%vq`di%|jpw%udvvrjwav%dka%uwlsdq`%lkcjwhdqljk+%Filfn%jk%qm`%h`vvdb`%qj%uw`s`kq%la`kqlq|%qm`cq+" ascii wide
        $s3 = "Pkdpqmjvwl" ascii wide
        $s4 = "`a%dff`vv%qj%|jpw%fjhupq`w$%Filfn%jk%qm`%h`vvdb`%qj%lk
… [630 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/REPORT-MASTER-v2.md` exists=`True` bytes=`18986` mtime=`2026-08-13T11:49:35.760155+00:00`
  - sha256: `b50c101013c133561b2e245a2c668582a288147f7823ca125e1a9e042ab2ba79`
- **REPORT_MASTER_v3:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/REPORT-MASTER-v3.md` exists=`True` bytes=`46109` mtime=`2026-08-13T12:01:10.609586+00:00`
  - sha256: `5b83485c15821211ad5c8a3d4109b90ec7de0467604867cefd2fc599761dd41f`
- **REPORT_v2:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/REPORT-v2.md` exists=`True` bytes=`18986` mtime=`2026-08-13T11:49:35.759155+00:00`
  - sha256: `b50c101013c133561b2e245a2c668582a288147f7823ca125e1a9e042ab2ba79`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`53272` mtime=`2026-08-13T11:52:08.964321+00:00`
  - sha256: `086b716339d1032d74a77a18b4446c255858ded11063eabe55c4077fe5e0509c`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`53238` mtime=`2026-08-13T12:04:23.039746+00:00`
  - sha256: `0cf2b582f10374f8aecfb6571c199ceea32f1418a703124d6a068cce576dc9ca`
- **report_v2_json:** `/opt/samples/logs/0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc/report-v2.json` exists=`True` bytes=`21737` mtime=`2026-08-13T11:52:08.969321+00:00`
  - sha256: `b8f31956d59fc8b4f90b5767b016282d2d35203829abeb207bcd9644a3ec17f6`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 11:49:35 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: hubert.dll (Tibs Trojan Downloader)

## Executive Summary

This report details the analysis of a malicious DLL file (`hubert.dll`) identified as a member of the Tibs malware family. The sample is a packed and obfuscated trojan downloader that employs multiple evasion techniques, including XOR-based encryption, anti-VM checks, and high-entropy packing. Static and behavioral analysis confirm its malicious intent 
… [18079 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 12:01:10 UTC

# RE Report — 0598e95ea5f2
_Generated 2026-08-13T12:01:10.604001+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=230c | cross_refs=True | llm_ok=True | runtime=50.15s -->

# Executive Summary

The sample with SHA256 `0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc` is assessed as malicious with high confidence, belonging to the Tibs malware family. This verdict is supported by static analysis tools indicating multiple detection patterns and malicious capabilities, while dynamic analysis recorded no significant events.

## Key Findings

| Aspect | Details | Confi
… [45184 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
