# Pipeline AUDIT-REPORT — `65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T12:25:52.529802+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 12:25:52 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b`

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
- key_evidence_count=`10`

```json
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Poison/Symmi",
  "cross_engine_notes": "MalCat anomalies align with capa and YARA detections for hooking and obfuscation. Ghidra and IDA report consistent function and string counts, while MalCat provides detailed behavioral evidence through decompilations and high-signal imports. External VirusTotal detections corroborate local findings with high confidence.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_401000",
      "why": "Decompiled code shows calls to SetWindowsHookExA and GetMessageA, indicating potential keylogging or UI hooking, which is behavioral-intent evidence for monitoring or data interception."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "set application hook",
      "why": "Capa rule detects hooking behavior, corroborating MalCat decompilation and suggesting malicious intent for system monitoring or input capture."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "win_hook",
      "why": "YARA rule matches for Windows hook setup, confirming hooking capability and aligning with other tool detections."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d78",
      "why": "Indicates use of XOR obfuscation for data encoding, commonly associated with malware for payload encryption or evasion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR",
      "why": "Capa rule maps to ATT&CK T1027, confirming obfuscation techniques that are neutral but supportive of evasion strategies when combined with behavioral evidence."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library",
      "why": "LoadLibrary API used for dynamic library loading, a common technique in malware to resolve APIs at runtime and evade static analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "allocate_memory",
      "why": "VirtualAlloc for memory allocation, often used in process injection or shellcode execution, indicating potential malicious memory manipulation."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "SpaghettiFunction\u00d77",
      "why": "Spaghetti code patterns suggest obfuscated control flow, which can hinder analysis and is often seen in malware."
    },
    {
      "source": "malcat",
      "query_or_table": "high-signal imports",
      "row_or_rule": "kernel32.VirtualAlloc \u00d74",
      "why": "High-signal import indicating repeated memory allocation, potentially for staging malicious payloads or shellcode."
    },
    {
      "source": "external TI",
      "query_or_table": "hash_lookup",
      "row_or_rule": "VirusTotal detections",
      "why": "56 malicious detections with threat labels like 'trojan.poison/symmi', supporting local evidence of malicious intent and known malware families."
    }
  ],
  "summary": "The sample exhibits clear behavioral-intent evidence through hooking APIs (SetWindowsHookExA) and obfuscation (XOR loops, spaghetti functions). Combined with dynamic API resolution (LoadLibrary, VirtualAlloc) and strong external VirusTotal detections, it is identified as malicious malware, likely belonging t
… [3776 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`20`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "PE DLL (vbprop.exe) masquerading as Trend Micro Internet Security while implementing Windows hooking (SetWindowsHookExA/CallNextHookEx/UnhookWindowsHookEx) consistent with keylogger/spyware functionality. Protected by Armadillo v4.x packer with XOR-based obfuscation. The .data section is marked executable (RWX), and the binary uses VirtualAlloc for runtime memory allocation alongside dynamic API resolution via LoadLibraryA/GetProcAddress. Multiple functions exhibit extreme cyclomatic complexity (up to 139 in FUN_0040166e with 223 blocks), indicative of heavy obfuscation or control-flow flattening. Contains network indicators (IP address at offset 0xF500) and base64-encoded data. Persistence mechanisms are not observed in the provided tool or SQL sources.",
  "key_evidence": [
    "YARA: Armadillo_v4x rule matched - known software protector/packer used for anti-analysis",
    "YARA: IP address pattern detected at file offset 62720 (0xF500)",
    "YARA: Base64-encoded content detected at offset 25104",
    "YARA: SEH_Save detected - Structured Exception Handling for anti-debugging",
    "CAPA: 'encode data using XOR' (T1027) - Defense Evasion via obfuscated files/information",
    "CAPA: 'set application hook' - Windows hooking capability detected",
    "CAPA: 'terminate process' - Process termination capability",
    "FLOSS: Imports SetWindowsHookExA, CallNextHookEx, UnhookWindowsHookEx from USER32.dll - classic keylogger/spyware hooking APIs",
    "FLOSS: Imports VirtualAlloc, VirtualFree for dynamic memory allocation (shellcode/runtime code injection)",
    "FLOSS: Imports WriteFile, SetFilePointer for data exfiltration to disk",
    "FLOSS: Imports GetActiveWindow, GetLastActivePopup, DispatchMessageA, TranslateMessage, GetMessageA - message loop processing for hook callbacks",
    "Ghidra: .data section (0x404800-0x4097FF) marked as executable (is_read=1, is_write=1, is_exec=1) - anomalous RWX memory",
    "Ghidra: FUN_0040166e has cyclomatic_complexity=139, 223 blocks, 622 instructions, 30 call-outs - extreme complexity indicating obfuscation",
    "Ghidra: FUN_00404920 and FUN_00405300 each have cyclomatic_complexity=62 with 63 blocks and identical sizes (664 bytes) - likely obfuscation-duplicated code",
    "Ghidra: FUN_00401000 (first export) references repetitive strings 'us7jsus7j...', 'q5y8q5y8...', 'v9i02ks3k7a8...' - XOR keys or obfuscation padding",
    "Ghidra: Exports include hook-related APIs (SetWindowsHookExA, CallNextHookEx, UnhookWindowsHookEx) and process control (ExitProcess, TerminateProcess, GetCurrentProcess)",
    "Ghidra: Entry point calls FUN_00401000 along with multiple indirect calls (sub_0) suggesting dynamic resolution",
    "Masquerade: VersionInfo claims 'Trend Micro Internet Security' / 'Trend Micro Inc.' / 'Copyright (C) 1995-2009 Trend Micro Incorporated' - forged metadata impersonating legitimate security software",
    "Masquerade: References 'Build 1366 - 7/29/2009' as private build info to appear legitimate",
    "YARA: Microsoft_Visual_Cpp_v60 and Armadillo signatures both match at overlapping offsets, confirming VC6 binary wrapped in Armadillo protector"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 42,
  "successful_non_bootstrap_tools": 28,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
 
… [1016 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: vbprop.exe (Poison/Symmi Trojan)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 12:08:41 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Malware Analysis Report: vbprop.exe (Poison/Symmi Trojan)\n\n## Executive Summary\n\nThis report details the analysis of a malicious Windows executable (SHA256: 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b) identified as a variant of the Poison/Symmi trojan family. The sample exhibits clear behavioral-intent evidence through Windows API hooking (SetWindowsHookExA) consistent with keylogger/spyware functionality, combined with significant obfuscation techniques including XOR encoding and spaghetti code patterns. The binary masquerades as Trend Micro Internet Security software through forged version information, a common social engineering tactic. Dynamic analysis tools executed but recorded no runtime events, suggesting the sample may require specific environmental triggers or employs anti-analysis techniques. The sample is classified as **malicious** with high confidence based on multiple converging evidence streams from static analysis, behavioral indicators, and external threat intelligence.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b |\n| File Path | /opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe |\n| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |\n| Architecture | x86 (32-bit) |\n| Compiler | Microsoft Visual C++ 6.0 (source: malcat) |\n| Packer/Protector | Armadillo v4.x (source: yara) |\n| Entropy | 5.18 bits/byte (source: malcat) |\n| Size | 66,048 bytes |\n| Imphash | e39378c4fb2416ba4fcdfda97cdd80df (source: rule.yara.json) |\n| First Submission | 2009-07-29 (based on version info) |\n| Project Context | malware analysis project |\n\nThe sample is a 32-bit Windows GUI executable compiled with Visual C++ 6.0 and protected by the Armadillo software protection system. The relatively low entropy (5.18) suggests the Armadillo packer may not be applying heavy compression, or the sample contains significant plaintext resources. The file contains 15 identified functions and 49 imported APIs (source: malcat).\n\n## 2. Classification\n\n**Verdict: MALICIOUS**\n\n**Confidence: 90%**\n\n**Family: Poison/Symmi Trojan**\n\nThe classification is based on multiple converging evidence streams:\n\n1. **Behavioral-Intent Evidence**: The sample implements Windows hooking via SetWindowsHookExA with a WH_KEYBOARD hook (idHook=14), which is a classic keylogger/spyware technique (source: malcat, capa).\n2. **Obfuscation Techniques**: XOR encoding loops and spaghetti code patterns indicate deliberate evasion (source: malcat).\n3. **Dynamic API Resolution**: Use of LoadLibraryA and GetProcAddress for runtime API resolution (source: pe_imports).\n4. **Memory Manipulation**: VirtualAlloc for dynamic memory allocation, potentially for shellcode execution (source: pe_imports).\
… [16726 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 12:08:41 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: vbprop.exe (Poison/Symmi Trojan)

## Executive Summary

This report details the analysis of a malicious Windows executable (SHA256: 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b) identified as a variant of the Poison/Symmi trojan family. The sample exhibits clear behavioral-intent evidence through Windows API hooking (SetWindowsHookExA) consistent with keylogger/spyware functionality, combined with significant obfuscation techniques including XOR encoding and spaghetti code patterns. The binary masquerades as Trend Micro Internet Security software through forged version information, a common social engineering tactic. Dynamic analysis tools executed but recorded no runtime events, suggesting the sample may require specific environmental triggers or employs anti-analysis techniques. The sample is classified as **malicious** with high confidence based on multiple converging evidence streams from static analysis, behavioral indicators, and external threat intelligence.

## 1. Sample Identification

| Attribute | Value |
|-----------|-------|
| SHA256 | 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b |
| File Path | /opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| Compiler | Microsoft Visual C++ 6.0 (source: malcat) |
| Packer/Protector | Armadillo v4.x (source: yara) |
| Entropy | 5.18 bits/byte (source: malcat) |
| Size | 66,048 bytes |
| Imphash | e39378c4fb2416ba4fcdfda97cdd80df (source: rule.yara.json) |
| First Submission | 2009-07-29 (based on version info) |
| Project Context | malware analysis project |

The sample is a 32-bit Windows GUI executable compiled with Visual C++ 6.0 and protected by the Armadillo software protection system. The relatively low entropy (5.18) suggests the Armadillo packer may not be applying heavy compression, or the sample contains significant plaintext reso
… [14876 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 12:21:49 UTC

# RE Report — 65fdb5d460b0
_Generated 2026-08-13T12:21:49.022340+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=238c | cross_refs=True | llm_ok=True | runtime=65.08s -->

# Executive Summary

The sample with SHA256 `65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b` is analyzed as **malicious** and likely belongs to the **Poison/Symmi** malware family. This verdict is based on high-confidence static analysis and tool agreement, with dynamic analysis tools executed but no significant runtime events observed.

## Key Findings

| Aspect               | Finding                              | Confidence | Evidence Source                               |
|----------------------|--------------------------------------|------------|-----------------------------------------------|
| Top-line Verdict     | Malicious                            | High       | yara, capa, deep_dive_agentic (source: cross-section:2) |
| Malware Family       | Poison/Symmi                         | High       | yara (source: cross-section:3)                |
| Analysis Confidence  | 90%                                  | High       | deep_dive_agentic (source: deep_dive_agentic) |
| Dynamic Analysis     | Tools executed, no significant events| N/A        | speakeasy, frida (source: cross-section:5)    |

**Explanation:**
- The malicious verdict is supported by 19 YARA rule matches and 3 capa capability rules from static analysis, with agreement between LLM and v1 analysis methods, indicating robust detection (source: cross-section:2, yara, capa).
- The family association to Poison/Symmi comes from YARA detections, which is a known malware family often linked to spyware or trojan activities, though attribution inferences are hedged (source: cross-section:3, yara).
- A deep confidence score of 90% suggests high reliability, derived from an agentic deep dive analysis that corroborated static findings (source: deep_dive_agentic).
- Dynamic analysis using Speakeasy emulator and Frida probe was conducted, but no significant runtime behavior was recorded, which may indicate anti-analysis techniques or latent capabilities (source: cross-section:5, speakeasy, frida).

**Sum
… [38819 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7276` | `012185bbdd1a3a99` |
| `prompt.txt` | `True` | `27419` | `54b21d5c81f45e19` |
| `pipeline-audit.json` | `True` | `121640` | `89a896dd5b9d65c4` |
| `AUDIT-REPORT.md` | `True` | `89073` | `b2756ffeb9c25128` |
| `REPORT-MASTER-v2.md` | `True` | `17383` | `e8ac352d1de74b23` |
| `REPORT-MASTER-v3.md` | `True` | `41338` | `312b632877d16b2c` |
| `REPORT-v2.md` | `True` | `17383` | `e8ac352d1de74b23` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `52160` | `50a38b1bb8388409` |
| `rule.yar` | `True` | `1155` | `786957bb5675e1f0` |
| `intake-validation.json` | `True` | `2453` | `4c80c0fb5891a919` |
| `source-decisions.json` | `True` | `1547` | `1184fa64349188b9` |
| `malcat-triage.json` | `True` | `37746` | `028a12813ca6e22d` |
| `deep_dive/01-tools-raw.json` | `True` | `92681` | `e73e73446db071d9` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4516` | `ca1f42ad0bb9b362` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `82616` | `bf003310b19a1448` |

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

- **intake_validation:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/intake-validation.json` exists=`True` bytes=`2453` mtime=`2026-08-12T20:49:54.942888+00:00`
  - sha256: `4c80c0fb5891a9195cfeb6dfcc3582d52a1b45d48ddb3209c1c5a520795851f9`
- **malcat_triage:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/malcat-triage.json` exists=`True` bytes=`37746` mtime=`2026-08-13T12:04:23.236746+00:00`
  - sha256: `028a12813ca6e22db4dcd88ea2489e8cd06272737d794185027090ab0054b757`
- **source_decisions:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/source-decisions.json` exists=`True` bytes=`1547` mtime=`2026-08-12T20:49:54.942888+00:00`
  - sha256: `1184fa64349188b974b9f1691f93be702a2838aa7a8fd7b004341d1e6d805cac`
- **ghidra_import_log:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/intake-analyzeHeadless.log` exists=`True` bytes=`7648` mtime=`2026-08-12T20:49:03.963628+00:00`
  - sha256: `c733d19b35b49849370720b9d40faf71b6d8a07f8eaf7e34214644890f256153`
- **ida_bootstrap_log:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/intake-idasql.log` exists=`True` bytes=`213` mtime=`2026-08-12T20:49:05.697640+00:00`
  - sha256: `d5ca8b3fda08c423cadb45e2ffc6bf842f427d02b298efcd3b55a130f244ba1d`

#### source_decisions_excerpt

```
{
  "sha256": "65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 49 imports, showing consistency, while Malcat reports 130, indicating potential discrepancy in counting methodology."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra (102) and IDA (106) report closely aligned function counts, suggesting accuracy, whereas Malcat reports only 10, likely under-counting or using different criteria."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "All tools report similar string counts (Malcat: 100, Ghidra: 110, IDA: 106), so using both engines ensures comprehensive and verified string extracti
… [770 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
    "file_name": "vbprop.exe",
    "file_path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
    "file_size": 65729,
    "type": "PE",
    "architecture": "X86",
    "entropy": 5.18,
    "sha256": "65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
    "metadata": {
      "VersionInfo::Comments": "",
      "VersionInfo::CompanyName": "Trend Micro Inc.",
      "Versio
… [36946 more chars]
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
      "name": "terminate process",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Terminate Process"
          ],
          "objective": "Process",
          "behavior": "Terminate Process",
          "method": "",
          "id": "C0018"
        }
      ]
    },
    {
      "name": "set application hook",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 65729,
  "duration_s": 2.19,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 62720,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 25104,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 200,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v60",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4182,
          "length": 1,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 5146,
          "length": 79,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 5146,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Installer_VISE_Custom_additional",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC_additional",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_50",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2
… [5896 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 132,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "\"~Richj",
    ".rdata",
    "@.data",
    "HHtpHHtl",
    "SS@SSPVSS",
    "t#SSUP",
    "t$$VSS",
    "_^][YY",
    "DSUVWh",
    "t.;t$$t(",
    "VC20XC00U",
    "`h````",
    "ppxxxx",
    "(null)",
    "__GLOBAL_HEAP_SELECTED",
    "__MSVCRT_HEAP_SELECT",
    "runtime error",
    "TLOSS error",
    "SING error",
    "DOMAIN error",
    "- unable to initialize heap",
    "- not enough space for lowio initialization",
    "- not enough space for stdio initialization",
    "- pure virtual function call",
    "- not enough space for _onexit/atexit table",
    "- unable to open console device",
    "- unexpected heap error",
    "- unexpected multithread lock error",
    "- not enough space for thread data",
    "abnormal program termination",
    "- not enough space for environment",
    "- not enough space for arguments",
    "- floating point not loaded",
    "Microsoft Visual C++ Runtime Library",
    "Runtime Error!",
    "Program:",
    "<program name unknown>",
    "GetLastActivePopup",
    "GetActiveWindow",
    "MessageBoxA",
    "user32.dll",
    "GetModuleHandleA",
    "KERNEL32.dll",
    "UnhookWindowsHookEx",
    "DispatchMessageA",
    "TranslateMessage",
    "GetMessageA",
    "SetWindowsHookExA",
    "CallNextHookEx",
    "USER32.dll",
    "ExitProcess",
    "TerminateProcess",
    "GetCurrentProcess",
    "GetStartupInfoA",
    "GetCommandLineA",
    "GetVersion",
    "HeapFree",
    "GetLastError",
    "CloseHandle",
    "UnhandledExceptionFilter",
    "GetModuleFileNameA",
    "FreeEnvironmentStringsA",
    "FreeEnvironmentStringsW",
    "WideCharToMultiByte",
    "GetEnvironmentStrings",
    "GetEnvironmentStringsW",
    "SetHandleCount",
    "GetStdHandle",
    "GetFileType",
    "GetEnvironmentVariableA",
    "GetVersionExA",
    "HeapDestroy",
    "HeapCreate",
    "VirtualFree",
    "RtlUnwind",
    "WriteFile",
    "SetFilePointer",
    "HeapAlloc",
    "VirtualAlloc"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 132
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 9.87,
  "size_bytes": 65729,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
    "file_name": "vbprop.exe",
    "file_path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
    "file_size": 65729,
    "type": "PE",
    "architecture": "X86",
    "entropy": 5.18,
    "sha256": "65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
    "metadata": {
      "VersionInfo::Comments": "",
      "VersionInfo::CompanyName": "Trend Micro Inc.",
      "VersionInfo::FileDescription": "VBProp Dynamic Link Library",
      "VersionInfo::FileVersion": "17.50.0.1366",
      "VersionInfo::InternalName": "VBProp",
      "VersionInfo::LegalCopyright": "Copyright (C) 1995-2009 Trend Micro Incorporated. All rights reserved.",
      "VersionInfo::LegalTrademarks": "Copyright (C) Trend Micro Inc.",
      "VersionInfo::OriginalFilename": "VBProp.dll",
      "VersionInfo::PrivateBuild": "Build 1366 - 7/29/2009",
      "VersionInfo::ProductName": "Trend Micro Internet Security",
      "VersionInfo::ProductVersion": "17.50",
      "VersionInfo::SpecialBuild": "1366"
    },
    "entrypoint_ea": 5146,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 4096,
        "virtual_size": 0,
        "rights": "",
        "entropy": 13
      },
      {
        "name": ".text",
        "effective_address": 4096,
        "physical_size": 20480,
        "virtual_size": 20480,
        "rights": "RX",
        "entropy": 136
      },
      {
        "name": ".rdata",
        "effective_address": 24576,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 60
      },
      {
        "name": ".data",
        "effective_address": 28672,
        "physical_size": 20480,
        "virtual_size": 20480,
        "rights": "RWX",
        "entropy": 61
      },
      {
        "name": ".rsrc",
        "effective_address": 49152,
        "physical_size": 16384,
        "virtual_size": 16384,
        "rights": "R",
        "entropy": 90
      },
      {
        "name": "overlay",
        "effective_address": 65536,
        "physical_size": 193,
        "virtual_size": 0,
        "rights": "",
        "entropy": 4
      },
      {
        "name": ".bss",
        "effective_address": 65729,
        "physical_size": 0,
        "virtual_size": 20480,
        "rights": "RW",
        "entropy": 0
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 89,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
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
        "name": "GuiSubsystemNoWindowApi",
        "desc": "A GUI windows application does not import any user32 window-related function",
        "category": "headers",
   
… [51902 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 9,
  "misses": [
    "VirusTotal detections hash_lookup 56 malicious detections with threat labels like 'trojan.poison/symmi', supporting loca"
  ],
  "hit_examples": [
    "sub_401000 decompilations Decompiled code shows calls to SetWindowsHookExA and GetMessageA, indicating potential keylogg",
    "set application hook top_rules Capa rule detects hooking behavior, corroborating MalCat decompilation and suggesting mal",
    "win_hook matches YARA rule matches for Windows hook setup, confirming hooking capability and aligning with other tool de",
    "XorInLoop\u00d78 anomalies Indicates use of XOR obfuscation for data encoding, commonly associated with malware for payload e",
    "encode data using XOR top_rules Capa rule maps to ATT&CK T1027, confirming obfuscation techniques that are neutral but s"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Poison/Symmi",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_401000",
      "why": "Decompiled code shows calls to SetWindowsHookExA and GetMessageA, indicating potential keylogging or UI hooking, which is behavioral-intent evidence for monitoring or data interception."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "set application hook",
      "why": "Capa rule detects hooking behavior, corroborating MalCat decompilation and suggesting malicious intent for system monitoring or input capture."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "win_hook",
      "why": "YARA rule matches for Windows hook setup, confirming hooking capability and aligning with other tool detections."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d78",
      "why": "Indicates use of XOR obfuscation for data encoding, commonly associated with malware for payload encryption or evasion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR",
      "why": "Capa rule maps to ATT&CK T1027, confirming obfuscation techniques that are neutral but supportive of evasion strategies when combined with behavioral evidence."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library",
      "why": "LoadLibrary API used for dynamic library loading, a common technique in malware to resolve APIs at runtime and evade static analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "allocate_memory",
      "why": "VirtualAlloc for memory allocation, often used in process injection or shellcode execution, indicating potential malicious memory manipulation."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "SpaghettiFunction\u00d77",
      "why": "Spaghetti code patterns suggest obfuscated control flow, which can hinder analysis and is often seen in malware."
    },
    {
      "source": "malcat",
      "query_or_table": "high-signal imports",
      "row_or_rule": "kernel32.VirtualAlloc \u00d74",
      "why": "High-signal import indicating repeated memory allocation, potentially for staging malicious payloads or shellcode."
    },
    {
      "source": "external TI",
      "query_or_table": "hash_lookup",
      "row_or_rule": "VirusTotal detections",
      "why": "56 malicious detections with threat labels like 'trojan.poison/symmi', supporting local evidence of malicious intent and known malware families."
    }
  ],
  "summary": "The sample exhibits clear behavioral-intent evidence through hooking APIs (SetWindowsHookExA) and obfuscation (XOR loops, spaghetti functions). Combined with dynamic API resolution (LoadLibrary, VirtualAlloc) and strong external VirusTotal detections, it is identified as malicious malware, likely belonging to the Poison or Symmi trojan families. Obfuscation alone is neutral, but the presence of ho"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/prompt.txt` exists=`True` bytes=`27419` mtime=`2026-08-13T12:04:50.300716+00:00`
  - sha256: `54b21d5c81f45e1982b64069d902ce604fb97745f90f807cf955262ebe5690b6`
- **verdict:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/verdict.json` exists=`True` bytes=`7276` mtime=`2026-08-13T12:06:08.983355+00:00`
  - sha256: `012185bbdd1a3a990fbad8d165c6482e9184e9888dc28c311bd401b47acf6a23`

#### prompt_excerpt

```
# Triage evidence
sha256: 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b
sample_path: /opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe
ghidra_session: ghidra-pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b
ida_session: ida-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 49 imports, showing consistency, while Malcat reports 130, indicating potential discrepancy in counting methodology.
- functions: ghidra (confidence=high) — Ghidra (102) and IDA (106) report closely aligned function counts, suggesting accuracy, whereas Malcat reports only 10, likely under-counting or using different criteria.
- strings: both (confidence=high) — All tools report similar string counts (Malcat: 100, Ghidra: 110, IDA: 106), so using both engines ensures comprehensive and verified string e
… [26370 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Poison/Symmi",
  "cross_engine_notes": "MalCat anomalies align with capa and YARA detections for hooking and obfuscation. Ghidra and IDA report consistent function and string counts, while MalCat provides detailed behavioral evidence through decompilations and high-signal imports. External VirusTotal detections corroborate local findings with high confidence.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_401000",
      "why": "Decompiled code shows calls to SetWindowsHookExA and GetMessageA, indicating potential keylogging or UI hooking, which is behavioral-intent evidence for monitoring or data interception."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "set application hook",
      "why": "Capa rule detects hooking behavior, corroborating MalCat decompilation and suggesting malicious intent for syst
… [6276 more chars]
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
      "name": "terminate process",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Terminate Process"
          ],
          "objective": "Process",
          "behavior": "Terminate Process",
          "method": "",
          "id": "C0018"
        }
      ]
    },
    {
      "name": "set application hook",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 65729,
  "duration_s": 0.88,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 65729,
  "duration_s": 0.03,
  "import_count": 49,
  "signal_count": 3,
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
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 62720,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 25104,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 200,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v60",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4182,
          "length": 1,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 5146,
          "length": 79,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 5146,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Installer_VISE_Custom_additional",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC_additional",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_50",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2
… [5874 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 132,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "\"~Richj",
    ".rdata",
    "@.data",
    "HHtpHHtl",
    "SS@SSPVSS",
    "t#SSUP",
    "t$$VSS",
    "_^][YY",
    "DSUVWh",
    "t.;t$$t(",
    "VC20XC00U",
    "`h````",
    "ppxxxx",
    "(null)",
    "__GLOBAL_HEAP_SELECTED",
    "__MSVCRT_HEAP_SELECT",
    "runtime error",
    "TLOSS error",
    "SING error",
    "DOMAIN error",
    "- unable to initialize heap",
    "- not enough space for lowio initialization",
    "- not enough space for stdio initialization",
    "- pure virtual function call",
    "- not enough space for _onexit/atexit table",
    "- unable to open console device",
    "- unexpected heap error",
    "- unexpected multithread lock error",
    "- not enough space for thread data",
    "abnormal program termination",
    "- not enough space for environment",
    "- not enough space for arguments",
    "- floating point not loaded",
    "Microsoft Visual C++ Runtime Library",
    "Runtime Error!",
    "Program:",
    "<program name unknown>",
    "GetLastActivePopup",
    "GetActiveWindow",
    "MessageBoxA",
    "user32.dll",
    "GetModuleHandleA",
    "KERNEL32.dll",
    "UnhookWindowsHookEx",
    "DispatchMessageA",
    "TranslateMessage",
    "GetMessageA",
    "SetWindowsHookExA",
    "CallNextHookEx",
    "USER32.dll",
    "ExitProcess",
    "TerminateProcess",
    "GetCurrentProcess",
    "GetStartupInfoA",
    "GetCommandLineA",
    "GetVersion",
    "HeapFree",
    "GetLastError",
    "CloseHandle",
    "UnhandledExceptionFilter",
    "GetModuleFileNameA",
    "FreeEnvironmentStringsA",
    "FreeEnvironmentStringsW",
    "WideCharToMultiByte",
    "GetEnvironmentStrings",
    "GetEnvironmentStringsW",
    "SetHandleCount",
    "GetStdHandle",
    "GetFileType",
    "GetEnvironmentVariableA",
    "GetVersionExA",
    "HeapDestroy",
    "HeapCreate",
    "VirtualFree",
    "RtlUnwind",
    "WriteFile",
    "SetFilePointer",
    "HeapAlloc",
    "VirtualAlloc"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 132
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 7.19,
  "size_bytes": 65729,
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
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
  "disassembly": {
    "0x0040141a": "\u250c 235: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n\u2502           ; var int32_t var_30h @ ebp-0x30\n\u2502           ; var int32_t var_5ch @ ebp-0x5c\n\u2502           ; var int32_t var_60h @ ebp-0x60\n\u2502           ; var int32_t var_64h @ ebp-0x64\n\u2502           ; var int32_t var_68h @ ebp-0x68\n\u2502           0x0040141a      55             push ebp\n\u2502           0x0040141b      8bec           mov ebp, esp\n\u2502           0x0040141d      6aff           push 0xffffffffffffffff\n\u2502           0x0040141f      68d0b04000     push 0x40b0d0\n\u2502           0x00401424      68b42b4000     push 0x402bb4\n\u2502           0x00401429      64a100000000   mov eax, dword fs:[0]\n\u2502           0x0040142f      50             push eax\n\u2502           0x00401430      6489250000..   mov dword fs:[0], esp\n\u2502           0x00401437      83ec58         sub esp, 0x58\n\u2502           0x0040143a      53             push ebx\n\u2502           0x0040143b      56             push esi\n\u2502           0x0040143c      57             push edi\n\u2502           0x0040143d      8965e8         mov dword [var_18h], esp\n\u2502           0x00401440      ff152cb04000   call dword [sym.imp.KERNEL32.dll_GetVersion] ; 0x40b02c ; DWORD GetVersion(void)\n\u2502           0x00401446      33d2           xor edx, edx\n\u2502           0x00401448      8ad4           mov dl, ah\n\u2502           0x0040144a      891540974000   mov dword [0x409740], edx   ; [0x409740:4]=0\n\u2502           0x00401450      8bc8           mov ecx, eax\n\u2502           0x00401452      81e1ff000000   and ecx, 0xff               ; 255\n\u2502           0x00401458      890d3c974000   mov dword [0x40973c], ecx   ; [0x40973c:4]=0\n\u2502           0x0040145e      c1e108         shl ecx, 8\n\u2502           0x00401461      03ca           add ecx, edx\n\u2502           0x00401463      890d38974000   mov dword [0x409738], ecx   ; [0x409738:4]=0\n\u2502           0x00401469      c1e810         shr eax, 0x10\n\u2502           0x0040146c      a334974000     mov dword [0x409734], eax   ; [0x409734:4]=0\n\u2502           0x00401471      33f6           xor esi, esi\n\u2502           0x00401473      56             push esi\n\u2502           0x00401474      e8e4150000     call 0x402a5d\n\u2502           0x00401479      59             pop ecx\n\u2502           0x0040147a      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x0040147c      7508           jne 0x401486\n\u2502       \u2502   0x0040147e      6a1c           push 0x1c                   ; 28\n\u2502       \u2502   0x00401480      e8b0000000     call 0x401535\n\u2502       \u2502   0x00401485      59             pop ecx\n\u2502       \u2514\u2500> 0x00401486      8975fc         mov dword [var_4h], esi\n\u2502           0x00401489      e8af120000     call 0x40273d\n\u2502           0x0040148e      ff1528b04000   call dword [sym.imp.KERNEL32.dll_GetCommandLineA] ; 0x40b028 ; LPSTR GetCommandLineA(void)\n\u2502           0x00401494      a364ac4000     mov dword [0x40ac64], eax   ; [0x40ac64:4]=0\n\u2502           0x00401499      e86d110000     call 0x40260b\n\u2502           0x0
… [3448 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
    "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!GetModuleHandleA",
      "KERNEL32.dll!GetStringTypeA",
      "KERNEL32.dll!LCMapStringW",
      "KERNEL32.dll!LCMapStringA",
      "KERNEL32.dll!MultiByteToWideChar",
      "USER32.dll!SetWindowsHookExA",
      "USER32.dll!GetMessageA",
      "USER32.dll!TranslateMessage",
      "USER32.dll!DispatchMessageA",
      "USER32.dll!UnhookWindowsHookEx"
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
  "checked": 20,
  "hits": 19,
  "misses": [
    "Ghidra: FUN_0040166e has cyclomatic_complexity=139, 223 blocks, 622 instructions, 30 call-outs - extreme complexity indi"
  ],
  "hit_examples": [
    "YARA: Armadillo_v4x rule matched - known software protector/packer used for anti-analysis",
    "YARA: IP address pattern detected at file offset 62720 (0xF500)",
    "YARA: Base64-encoded content detected at offset 25104",
    "YARA: SEH_Save detected - Structured Exception Handling for anti-debugging",
    "CAPA: 'encode data using XOR' (T1027) - Defense Evasion via obfuscated files/information"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "PE DLL (vbprop.exe) masquerading as Trend Micro Internet Security while implementing Windows hooking (SetWindowsHookExA/CallNextHookEx/UnhookWindowsHookEx) consistent with keylogger/spyware functionality. Protected by Armadillo v4.x packer with XOR-based obfuscation. The .data section is marked exec",
  "key_evidence": [
    "YARA: Armadillo_v4x rule matched - known software protector/packer used for anti-analysis",
    "YARA: IP address pattern detected at file offset 62720 (0xF500)",
    "YARA: Base64-encoded content detected at offset 25104",
    "YARA: SEH_Save detected - Structured Exception Handling for anti-debugging",
    "CAPA: 'encode data using XOR' (T1027) - Defense Evasion via obfuscated files/information",
    "CAPA: 'set application hook' - Windows hooking capability detected",
    "CAPA: 'terminate process' - Process termination capability",
    "FLOSS: Imports SetWindowsHookExA, CallNextHookEx, UnhookWindowsHookEx from USER32.dll - classic keylogger/spyware hooking APIs",
    "FLOSS: Imports VirtualAlloc, VirtualFree for dynamic memory allocation (shellcode/runtime code injection)",
    "FLOSS: Imports WriteFile, SetFilePointer for data exfiltration to disk",
    "FLOSS: Imports GetActiveWindow, GetLastActivePopup, DispatchMessageA, TranslateMessage, GetMessageA - message loop processing for hook callbacks",
    "Ghidra: .data section (0x404800-0x4097FF) marked as executable (is_read=1, is_write=1, is_exec=1) - anomalous RWX memory",
    "Ghidra: FUN_0040166e has cyclomatic_complexity=139, 223 blocks, 622 instructions, 30 call-outs - extreme complexity indicating obfuscation",
    "Ghidra: FUN_00404920 and FUN_00405300 each have cyclomatic_complexity=62 with 63 blocks and identical sizes (664 bytes) - likely obfuscation-duplicated code",
    "Ghidra: FUN_00401000 (first export) references repetitive strings 'us7jsus7j...', 'q5y8q5y8...', 'v9i02ks3k7a8...' - XOR keys or obfuscation padding",
    "Ghidra: Exports include hook-related APIs (SetWindowsHookExA, CallNextHookEx, UnhookWindowsHookEx) and process control (ExitProcess, TerminateProcess, GetCurrentProcess)",
    "Ghidra: Entry point calls FUN_00401000 along with multiple indirect calls (sub_0) suggesting dynamic resolution",
    "Masquerade: VersionInfo claims 'Trend Micro Internet Security' / 'Trend Micro Inc.' / 'Copyright (C) 1995-2009 Trend Micro Incorporated' - forged metadata impersonating legitimate security software",
    "Masquerade: References 'Build 1366 - 7/29/2009' as private build info to appear legitimate",
    "YARA: Microsoft_Visual_Cpp_v60 and Armadillo signatures both match at overlapping offsets, confirming VC6 binary wrapped in Armadillo protector"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
… [8974 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
    "file_name": "vbprop.exe",
    "file_path": 
… [54846 more chars]
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
… [1173 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 65729,
  "duration_s": 0.03,
  "import_count": 49,
  "signal_count": 3,
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
      "label": 
… [166 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 132,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "\"~Richj",
    ".rdata",
    "@.data",
    "HHtpHHtl",
    "SS@SSPVSS",
    "t#SSUP",
    "t$$VSS",
    "_^][YY",
    "DSUVWh",
    "t.;t$$t(",
    "VC20XC00U",
    "`h````",
    "ppxxxx",
    "(null)",
    "__GLOBAL_HEAP_SELECTED",
    "__MSVCRT_HEAP_SELECT",
 
… [2045 more chars]
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
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
  "disassembly": {
    "0x0040141a": "\u250c 235: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_2ch @ ebp-0x2c
… [6548 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
    "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!GetModuleHandleA",
      "KERNEL32.dll!GetStringTypeA",
      "KERNEL32.dll!LCMapStringW",
      "KERNEL32.dll!LCMapStringA",
      "KERNEL32
… [221 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 20480,
      "entropy": 6.6604,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 4096,
      "entropy": 5.4264,
      "executable": fa
… [382 more chars]
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
… [1768 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 9,
  "sinks": [
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x4032b5",
      "function": "fcn.00403249"
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x403422",
      "function": "fc
… [1285 more chars]
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
    "elapsed_s": 0.79,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.4,
  
… [100 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "packed",
  "name": null,
  "score": 6
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
      "name": "FUN_0040166e",
      "address": "4200046",
      "size": "1918"
    },
    {
      "name": "FUN_00403488",
      "address": "4207752",
      "size": "809"
    },
    {
      "name": "FUN_004037b1",
      "address": "4208561",
      "size": "777"
    },
    {
      "name": "FUN_00404920",
      "address": "
… [2250 more chars]
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
      "content": "Copyright (C) 1995-2009 Trend Micro Incorporated. All rights reserved.",
      "address": "4277616"
    },
    {
      "content": "Copyright (C) Trend Micro Inc.",
      "address": "4277800"
    },
    {
      "content": "v9i02ks3k7a8v9i02ks3k7a8v9i02ks3k7a8v9i02ks3k7a8v9i02ks3k7a8",
      "address": "4250620"
 
… [5215 more chars]
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
      "name": "CloseHandle",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "ExitProcess",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "FlushFileBuffers",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "FreeEnvironmentStringsA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "FreeEnviron
… [3682 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: name`

```json
{
  "error": "ghidrasql SQL error: no such column: name"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "cyclomatic_complexity",
    "instruction_count",
    "block_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "FUN_0040166e",
      "func_addr": "4200046",
      "size": "1918",
      "cyclomatic_complexity": "139",
      "instruction_count": "622",
      "block_count": "223",
      "ca
… [5227 more chars]
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
      "content": "user32.dll",
      "address": "4240544"
    },
    {
      "content": "KERNEL32.dll",
      "address": "4240888"
    },
    {
      "content": "USER32.dll",
      "address": "4241016"
    },
    {
      "content": "WriteFile",
      "address": "4241494"
    },
    {
      "content": "VirtualAlloc",
      "addres
… [472 more chars]
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
  "session_id": "ghidra-pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
  "audit_path": "/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/audit.jsonl"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_0040166e",
      "func_addr": "4200046",
      "string_value": "null)"
    },
    {
      "func_name": "FUN_0040166e",
      "func_addr": "4200046",
      "string_value": "null)"
    },
    {
      "func_name": "FUN_0040166e",
      "func_addr": "4200046",
      "string_value": "nul
… [315 more chars]
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
      "content": "Microsoft Visual C++ Runtime Library",
      "address": "4240396",
      "length": "37"
    },
    {
      "content": "us7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7j",
      "address": "4250564",
      "length": "55"
    },
    {
      "content": "v9i02ks3k7a8v9i02ks3k7a8v9i02ks3k7a8v9i02ks
… [1383 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: c.from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: c.from_func_name"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value",
    "string_addr"
  ],
  "rows": [
    {
      "func_name": "FUN_00401000",
      "func_addr": "4198400",
      "string_value": "us7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7j",
      "string_addr": "4250564"
    },
    {
      "func_name": "FUN_00401000",
      "func_addr": "4198400",
      "string_value": "q5y8q5y8q5y
… [2521 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: c.from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: c.from_func_name"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "cyclomatic_complexity",
    "block_count",
    "call_out_count"
  ],
  "rows": [
    {
      "func_name": "FUN_0040166e",
      "func_addr": "4200046",
      "size": "1918",
      "cyclomatic_complexity": "139",
      "block_count": "223",
      "call_out_count": "30"
    },
    {
      "func_name": "entry",
      "func_addr": "41
… [2922 more chars]
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
  "session_id": "ghidra-pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
  "audit_path": "/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/audit.jsonl"
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
  "audit_path": "/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/audit.jsonl"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_addr"
}
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
… [1173 more chars]
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
    "content",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
  "audit_path": "/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "ref_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_00401000",
      "func_addr": "4198400",
      "ref_addr": "4198432",
      "string_value": "us7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7j"
    },
    {
      "func_name": "FUN_00401000",
      "func_addr": "4198400",
      "ref_addr": "4198635",
      "stri
… [565 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_addr",
    "src_func_name",
    "dst_func_addr",
    "dst_func_name",
    "call_site"
  ],
  "rows": [
    {
      "src_func_addr": "4198400",
      "src_func_name": "FUN_00401000",
      "dst_func_addr": "4199282",
      "dst_func_name": "FUN_00401372",
      "call_site": "4198438"
    },
    {
      "src_func_addr": "4198400",
      "src_func_name": "FUN_00401000",
… [926 more chars]
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
  "session_id": "ghidra-pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
  "audit_path": "/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/audit.jsonl"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: func_name"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_name",
    "dst_func_name"
  ],
  "rows": [
    {
      "src_func_name": "FUN_0040166e",
      "dst_func_name": "FUN_00401eaa"
    },
    {
      "src_func_name": "FUN_0040166e",
      "dst_func_name": "FUN_00401eaa"
    },
    {
      "src_func_name": "FUN_0040166e",
      "dst_func_name": "FUN_00401e0c"
    },
    {
      "src_func_name": "FUN_0040166e",
      "dst
… [2665 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address"
  ],
  "rows": [
    {
      "name": "FUN_00401000",
      "address": "4198400"
    },
    {
      "name": "FUN_00401170",
      "address": "4198768"
    },
    {
      "name": "FUN_00401270",
      "address": "4199024"
    },
    {
      "name": "FUN_0040129d",
      "address": "4199069"
    },
    {
      "name": "__exit",
      "address": "4199086"
   
… [653 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 132,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "\"~Richj",
    ".rdata",
    "@.data",
    "HHtpHHtl",
    "SS@SSPVSS",
    "t#SSUP",
    "t$$VSS",
    "_^][YY",
    "DSUVWh",
    "t.;t$$t(",
    "VC20XC00U",
    "`h````",
    "ppxxxx",
    "(null)",
    "__GLOBAL_HEAP_SELECTED",
    "__MSVCRT_HEAP_SELECT",
 
… [2045 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address"
  ],
  "rows": [
    {
      "name": "ExitProcess",
      "address": "4239384"
    },
    {
      "name": "TerminateProcess",
      "address": "4239388"
    },
    {
      "name": "GetCurrentProcess",
      "address": "4239392"
    },
    {
      "name": "GetProcAddress",
      "address": "4239524"
    },
    {
      "name": "SetWindowsHookExA",
      "ad
… [478 more chars]
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
      "name": "FUN_00401000",
      "address": "4198400",
      "size": "368"
    },
    {
      "name": "entry",
      "address": "4199450",
      "size": "235"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-65fdb5d460b079279a4afcb45671b4
… [151 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_0040503f",
      "string_value": "MessageBoxA"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b",
  "audit_path": "/opt/samples/logs/65fdb5d460b079279a4af
… [58 more chars]
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
      "start_ea": "4198400",
      "end_ea": "4218879",
      "name": ".text",
      "class": "CODE",
      "size": "20480",
      "is_read": "1",
      "is_write": "0",
      "is_exec": "1"
    },
    {
      "start_ea": "4243456",
      "end_ea":
… [458 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_name",
    "dst_func_name"
  ],
  "rows": [
    {
      "src_func_name": "entry",
      "dst_func_name": "sub_0"
    },
    {
      "src_func_name": "entry",
      "dst_func_name": "FUN_00402a5d"
    },
    {
      "src_func_name": "entry",
      "dst_func_name": "FUN_00401535"
    },
    {
      "src_func_name": "entry",
      "dst_func_name": "FUN_0040273d"
    },

… [1198 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "cyclomatic_complexity",
    "block_count"
  ],
  "rows": [
    {
      "func_name": "FUN_00404920",
      "func_addr": "4213024",
      "size": "664",
      "cyclomatic_complexity": "62",
      "block_count": "63"
    },
    {
      "func_name": "FUN_00405300",
      "func_addr": "4215552",
      "size": "664",
      "cyclomatic_c
… [2457 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/deep_dive/01-tools-raw.json` exists=`True` bytes=`92681` mtime=`2026-08-13T12:04:23.241746+00:00`
  - sha256: `e73e73446db071d971e325ce9a2de5b5e03ca3fe0b1a6f7f84c303eb3a8aca50`
- **sql_evidence:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/deep_dive/05-deep-dive.json` exists=`True` bytes=`4516` mtime=`2026-08-12T20:54:01.236632+00:00`
  - sha256: `ca1f42ad0bb9b362cec2a005eccfbceabb5f078918fadfec66920435fff7c8cc`

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
  "summary": "PE DLL (vbprop.exe) masquerading as Trend Micro Internet Security while implementing Windows hooking (SetWindowsHookExA/CallNextHookEx/UnhookWindowsHookEx) consistent with keylogger/spyware functionality. Protected by Armadillo v4.x packer with XOR-based obfuscation. The .data section is marked executable (RWX), and the binary uses VirtualAlloc for runtime memory allocation alongside dynamic API resolution via LoadLibraryA/GetProcAddress. Multiple functions exhibit extreme cyclomatic complexity (up to 139 in FUN_0040166e with 223 blocks), indicative of heavy obfuscation or control-flow flattening. Contains network indicators (IP address at offset 0xF500) and base64-encode
… [3716 more chars]
```

- **agentic:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`354363` mtime=`2026-08-12T20:54:01.236632+00:00`
  - sha256: `9560005a7dccf3b751df2b6b3bf661ceb37b94afc842abf1c4867d72a4ba1350`

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

- **rule_yar:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/rule.yar` exists=`True` bytes=`1155` mtime=`2026-08-12T20:54:04.084637+00:00`
  - sha256: `786957bb5675e1f004d319df6a51039fbef948b145eadf70675b2b2b61458eb9`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T20:54:04.085168+00:00
import "pe"
rule CADRE_v2_trojan_poison_symmi_65fdb5d460b0 {
    meta:
        description = "RevAI v2 auto rule for trojan.poison/symmi"
        sha256 = "65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b"
        family = "trojan_poison_symmi"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "HHtpHHtl" ascii wide
        $s2 = "SS@SSPVSS" ascii wide
        $s3 = "t.;t$$t(" ascii wide
        $s4 = "VC20XC00U" ascii wide
        $s5 = "__GLOBAL_HEAP_SELECTED" ascii wide
        $s6 = "__MSVCRT_HEAP_SELECT" ascii wide
        $s7 = "r
… [353 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/REPORT-MASTER-v2.md` exists=`True` bytes=`17383` mtime=`2026-08-13T12:08:41.577177+00:00`
  - sha256: `e8ac352d1de74b237baccdcb3ec7732ed5cf8a5fd53a0aba112bf994487c2058`
- **REPORT_MASTER_v3:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/REPORT-MASTER-v3.md` exists=`True` bytes=`41338` mtime=`2026-08-13T12:21:49.028181+00:00`
  - sha256: `312b632877d16b2c1c3438d7abf29d3b47c70fedc1b45ea7ab038b1afb94d6f8`
- **REPORT_v2:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/REPORT-v2.md` exists=`True` bytes=`17383` mtime=`2026-08-13T12:08:41.577177+00:00`
  - sha256: `e8ac352d1de74b237baccdcb3ec7732ed5cf8a5fd53a0aba112bf994487c2058`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`59569` mtime=`2026-08-13T12:12:55.791268+00:00`
  - sha256: `11a64a3c87ee7077455d5c1a63ca6a6178cc5262e9f0a5f8d7e0e4b2d552e601`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`52160` mtime=`2026-08-13T12:25:52.482769+00:00`
  - sha256: `50a38b1bb8388409d1726b7049c1723afe701fcad69152422c55bd02ac6e8d35`
- **report_v2_json:** `/opt/samples/logs/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/report-v2.json` exists=`True` bytes=`20226` mtime=`2026-08-13T12:12:55.795269+00:00`
  - sha256: `431831bb6e0c120e61c027b75b8eefc5aff77e8b85274e02bc715f13598f27fa`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 12:08:41 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: vbprop.exe (Poison/Symmi Trojan)

## Executive Summary

This report details the analysis of a malicious Windows executable (SHA256: 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b) identified as a variant of the Poison/Symmi trojan family. The sample exhibits clear behavioral-intent evidence through Windows API hooking (SetWindowsHookExA) consistent with keylogger/spyware functionality, combine
… [16476 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 12:21:49 UTC

# RE Report — 65fdb5d460b0
_Generated 2026-08-13T12:21:49.022340+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=238c | cross_refs=True | llm_ok=True | runtime=65.08s -->

# Executive Summary

The sample with SHA256 `65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b` is analyzed as **malicious** and likely belongs to the **Poison/Symmi** malware family. This verdict is based on high-confidence static analysis and tool agreement, with dynamic analysis tools executed but no significant runtime events observed.

## Key Findings

| Aspect               | Finding      
… [40419 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
