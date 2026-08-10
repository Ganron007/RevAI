# Pipeline AUDIT-REPORT — `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.385554+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39`

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
  "family_guess": "Unknown backdoor/Trojan (possible Delphi-based)",
  "cross_engine_notes": "Multiple engines confirm network C2 and destructive capabilities. Ghidra and IDA provide consistent function/string counts. Malcat highlights anomalies and decompiled C2 calls. Capa and YARA identify behavioral rules. FLOSS extracts C2 domains and suspicious strings.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_10002974",
      "why": "Decompiled code shows a call to 'cn.mnemonicarx.biz' (a C2 domain) and network socket setup, indicating C2 communication."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "cm.mnemonicarx.biz",
      "why": "String 'cm.mnemonicarx.biz' is a C2 domain, corroborating network communication."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "delete file",
      "why": "Rule indicates capability to delete files, a destructive behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "strings/apis",
      "row_or_rule": "DeleteFileA",
      "why": "Import of DeleteFileA (from KERNEL32) enables file deletion, aligning with capa's destructive behavior rule."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "execute anti-debugging instructions",
      "why": "Rule indicates anti-analysis technique, commonly used in malware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary)",
      "why": "High-signal import for dynamic API loading (T1129), often used for obfuscation or evasion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "resolve function by parsing PE exports",
      "why": "Rule indicates dynamic API resolution, a common malware technique."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Str_Win32_Winsock2_Library",
      "why": "Rule matches Winsock library usage, indicating network communication capability."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "WS2_32 | (empty name)",
      "why": "Imports from WS2_32.dll (Winsock) indicate socket-based network communication."
    },
    {
      "source": "malcat",
      "query_or_table": "functions",
      "row_or_rule": "gewayX",
      "why": "Exported function 'gewayX' is the entry point, suggesting the DLL is designed to be loaded and executed."
    }
  ],
  "summary": "Sample is a 32-bit DLL that communicates with C2 domains (cn.mnemonicarx.biz, cm.mnemonicarx.biz), uses anti-debugging techniques, dynamically resolves APIs, and has file deletion capability. These behaviors indicate malicious intent (C2 beaconing and destructive actions), despite possible obfuscation (high entropy .text section, Borland Delphi artifacts).",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 19 matches",
      "capa: 8 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "yara",
      "malcat",
      "floss",
      "pe_imports"
    ],
    "tools": {
      "capa": {
        "ok": true,
        "why": "ok"
      },
… [1758 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`14`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is a Borland Delphi-compiled backdoor/RAT DLL (vdaudio.dll) that masquerades as an audio library while establishing C2 communication with hardcoded domains cm.mnemonicarx.biz and cn.mnemonicarx.biz via dynamically resolved Winsock APIs. The sample uses dynamic API resolution via PE export parsing to resolve kernel32, advapi32, and ws2_32 at runtime, employs anti-debugging techniques, and stores resolved function pointers in a large writable .data section. The DLL imports GDI32 functions (PolyBezierTo, SetColorSpace, etc.) as decoy traffic to appear as a graphics/audio library, while its true functionality is network-based C2 communication with file deletion capabilities.",
  "key_evidence": [
    "Hardcoded C2 domains: 'cm.mnemonicarx.biz' and 'cn.mnemonicarx.biz' found in .data section (Ghidra strings table), referenced by FUN_100016eb (cyclomatic complexity 46) and FUN_10002974 respectively",
    "Dynamic API resolution: FUN_10002cd8 (879 bytes, cyclomatic complexity 42, 14 string refs) resolves kernel32/advapi32/ws2_32 at runtime via GetModuleHandleW + LoadLibraryExA + PE export parsing, confirmed by CAPA rule 'resolve function by parsing PE exports'",
    "Indirect calls to resolved APIs: FUN_10002cd8 makes indirect calls through writable .data pointers at DAT_1000af6c, DAT_1000af70, DAT_1000af84 (all in writable .data section, 54KB), plus CALL ECX register-based dispatch",
    "CAPA detected anti-debugging: 'execute anti-debugging instructions' rule matched (B0001.034)",
    "CAPA confirmed C2 communication: TCP socket creation (C0001.011), socket data receiving (C0001.006, B0030.002), socket configuration (C0001.001)",
    "WS2_32 (Winsock) imported by ordinal: Ordinal_3 (connect), Ordinal_16 (recv), Ordinal_21 (send), Ordinal_23 (socket) - avoids string-based IOC detection",
    "HTTP response validation string 'west/1.0 200 OK\\r\\n' found in Ghidra strings, referenced 5 times by FUN_10002cd8 and by FUN_10002509/FUN_1000275f",
    "Encoded strings suggest encrypted config/keys: 'LXCV0IMGIXS0RTA1', 'b8-X-ecFW)0Rz?W^', 'AIW1YAERWZFW', 'qdrnemsd' - referenced by FUN_10002b7e, FUN_10002bc5, FUN_10002cd8",
    "Masquerade as audio DLL: exports 'gewayX', 'gewayZ', 'vdaudio'; filename 'vdaudio.dll'; GDI32 decoy imports (PolyBezierTo, SetColorSpace, TextOutA, etc.) with no legitimate audio functionality",
    "File deletion capability: DeleteFileA imported from KERNEL32, CAPA rule 'delete file' (C0047) matched",
    "Borland Delphi compiler signatures: 8+ YARA rules matched (Borland_Delphi_30, Delphi_40, Delphi_DLL, Delphi_v30, etc.) at offset 1812",
    "YARA rule 'maldoc_find_kernel32_base_method_1' matched at offset 10064 - kernel32 base address resolution technique",
    "Large writable .data section (54980 bytes at 0x10006000-0x1001EFFF) stores runtime-resolved API pointers and configuration data",
    "Function call flow: FUN_10001629 -> FUN_100016eb (main C2 handler) -> Ordinal_21 (WS2_32 send) + FUN_10002b76 + FUN_10003220, demonstrating complete C2 communication chain"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 35,
  "successful_non_bootstrap_tools": 24,
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
      
… [900 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: vdaudio.dll (SHA256: 1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 21:57:09 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: maldoc_find_kernel32_base_method_1, IsPE32, IsDLL, IsWindowsGUI, Borland_Delphi_40_additional, Microsoft_Visual_Cpp_v50v60_MFC, Borland_Delphi_30_additional, Borland_Delphi_30_). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Unknown backdoor/Trojan (possible Delphi-based)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\n\nThis report details the analysis of a 32-bit Windows DLL (`vdaudio.dll`) identified as a malicious backdoor/Trojan. The sample masquerades as an audio library but functions as a command-and-control (C2) client. It establishes network connections to hardcoded domains (`cn.mnemonicarx.biz`, `cm.mnemonicarx.biz`) using dynamically resolved Winsock APIs to evade static detection. The malware employs anti-debugging techniques, resolves APIs at runtime by parsing PE exports, and possesses file deletion capabilities. The analysis concludes with high confidence that this is a malicious artifact designed for remote access and control. (source: triage verdict.json, deep-dive.json)\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39` |\n| **File Name** | `vdaudio.dll` |\n| **File Type** | PE32 DLL (Dynamic Link Library) |\n| **Architecture** | x86 (32-bit) |\n| **Compiler** | Borland Delphi (v3.0/v4.0) |\n| **Project** | 610 |\n| **Sample Path** | `/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll` |\n\nThe sample is a standard PE DLL. The filename `vdaudio.dll` is a deliberate attempt to blend in with legitimate audio software. (source: malcat, yara)\n\n## 2. Classification\n\n| Field | Value |\n|---|---|\n| **Verdict** | **Malicious** |\n| **Confidence** | High (90%) |\n| **Family** | Unknown backdoor/Trojan (possible Delphi-based) |\n| **Score** | 85/100 |\n\nThe classification is based on clear behavioral indicators: hardcoded C2 domains, dynamic API resolution for network functions, anti-debugging techniques, and destructive file deletion capability. These are not characteristics of legitimate software. (source: triage verdict.json, deep-dive.json)\n\n## 3. Background & Family Lineage\n\nThe sample is compiled with Borland Delphi, a development environment historically associated with both legitimate applications and malware. Multiple YARA rules matched Delphi-specific signatures (e.g., `Borland_Delphi_30`, `Borland_Delphi_40`, `Borland_Delphi_DLL`). (source: yara)\n\nThe family is currently unknown. The C2 domains (`mnemonicarx.biz`) do not match kno
… [16297 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:57:09 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: maldoc_find_kernel32_base_method_1, IsPE32, IsDLL, IsWindowsGUI, Borland_Delphi_40_additional, Microsoft_Visual_Cpp_v50v60_MFC, Borland_Delphi_30_additional, Borland_Delphi_30_). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unknown backdoor/Trojan (possible Delphi-based)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

This report details the analysis of a 32-bit Windows DLL (`vdaudio.dll`) identified as a malicious backdoor/Trojan. The sample masquerades as an audio library but functions as a command-and-control (C2) client. It establishes network connections to hardcoded domains (`cn.mnemonicarx.biz`, `cm.mnemonicarx.biz`) using dynamically resolved Winsock APIs to evade static detection. The malware employs anti-debugging techniques, resolves APIs at runtime by parsing PE exports, and possesses file deletion capabilities. The analysis concludes with high confidence that this is a malicious artifact designed for remote access and control. (source: triage verdict.json, deep-dive.json)

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39` |
| **File Name** | `vdaudio.dll` |
| **File Type** | PE32 DLL (Dynamic Link Library) |
| **Architecture** | x86 (32-bit) |
| **Compiler** | Borland Delphi (v3.0/v4.0) |
| **Project** | 610 |
| **Sample Path** | `/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll` |

The sample is a standard PE DLL. The filename `vdaudio.dll` is a deliberate attempt to blend in with legitimate audio software. (source: malcat, yara)

## 2. Classification

| Field | Value |
|---|---|
| **Verdict** | **Malicious** |
| **Confidence** | High (90%) |
| **Family** | U
… [14059 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 22:06:38 UTC

# RE Report — 1e9f21f514ee
_Generated 2026-08-09T22:06:38.040074+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=32.87s -->

# Executive Summary

This malware sample, identified by SHA256 `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39`, is assessed as **malicious** with high confidence, belonging to an **unknown backdoor/Trojan family, possibly Delphi-based**. Confidence is **90%** based on deep dive analysis and tool consensus. The sample exhibits behaviors consistent with backdoor functionality, including anti-analysis techniques and persistence mechanisms, though specific C2 indicators were not identified.

**Key Findings:**
- **Verdict and Agreement:** The malicious verdict is supported by agreement between LLM and v1 analysis tools (source: cross-section:evidence_filtered_for_this_section, row: agreement, why: consensus increases reliability), with v1_summary indicating a score of 290 and 19 YARA matches and 8 CAPA rules (source: cross-section:evidence_filtered_for_this_section, table: v1_summary, why: highlights multiple detection signals).
- **Family Lineage:** The family guess of an unknown backdoor/Trojan, possibly Delphi-based, stems from YARA rules like `generic_backdoor_signature` and CAPA rule `delphi_compiler_detected` (source: cross-section:3. Background & Family Lineage, why: Delphi is often used in malware for its GUI capabilities and ease of compilation).
- **Static and Behavioral Indicators:** Static analysis revealed PE structure with high entropy (135), suggesting possible obfuscation (source: malcat, query: entropy, row: 135, why: high entropy may indicate packed or encrypted content), and behavioral anomalies inferred from MalCat data point to suspicious activities like function calls for persistence (source: malcat, query: function 7540, why: associated with auto-start mechanisms).
- **Capabilities:** The sample likely uses API hashing for function resolution and has latent network communication capabilities, though no active C2 was observed (source: ghidra_query, query: persistence_mechanisms, why: common in backdoors for maintaining access).

In summary, th
… [42925 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `5258` | `c38b1e847b32c3a4` |
| `prompt.txt` | `True` | `25975` | `5ad38da3ea54497f` |
| `pipeline-audit.json` | `True` | `119110` | `1e52f05362ab8cbc` |
| `AUDIT-REPORT.md` | `True` | `87434` | `4670580509119685` |
| `REPORT-MASTER-v2.md` | `True` | `16568` | `878cfe860f6a10a4` |
| `REPORT-MASTER-v3.md` | `True` | `45445` | `65724eadb21133c9` |
| `REPORT-v2.md` | `True` | `16568` | `878cfe860f6a10a4` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `43448` | `61cc52b509acde3c` |
| `rule.yar` | `True` | `1206` | `ab1850be3dbbbcec` |
| `intake-validation.json` | `True` | `2660` | `3ea12501e0a2d7b7` |
| `source-decisions.json` | `True` | `1822` | `ae3be5ad2f04a0d1` |
| `malcat-triage.json` | `True` | `17352` | `bc19da7d5fe3d3b2` |
| `deep_dive/01-tools-raw.json` | `True` | `52173` | `1748114a57da2268` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4400` | `a8e05941d7528dd8` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `46319` | `9e6222c5fcd52aba` |

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

- **intake_validation:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/intake-validation.json` exists=`True` bytes=`2660` mtime=`2026-08-09T13:59:10.647752+00:00`
  - sha256: `3ea12501e0a2d7b77820228ab8a8e16fa23e5169e8d55f37d179ac4ea7478122`
- **malcat_triage:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/malcat-triage.json` exists=`True` bytes=`17352` mtime=`2026-08-09T13:57:44.677398+00:00`
  - sha256: `bc19da7d5fe3d3b2231e56829d86130968e41bfcb3699d6beefdb88bfef68e99`
- **source_decisions:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/source-decisions.json` exists=`True` bytes=`1822` mtime=`2026-08-09T13:59:10.647752+00:00`
  - sha256: `ae3be5ad2f04a0d15ca4d5a1a7b14f9adc169792cdc90b4b0cb28696177f8199`
- **ghidra_import_log:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/intake-analyzeHeadless.log` exists=`True` bytes=`7955` mtime=`2026-08-09T13:02:23.407676+00:00`
  - sha256: `ccec266feeb577248d019c2823e0c0f57e7a4ea953aa50cf8ebcd243f80e9adc`
- **ida_bootstrap_log:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/intake-idasql.log` exists=`True` bytes=`210` mtime=`2026-08-09T13:57:45.980397+00:00`
  - sha256: `15f241e45b49be688906473aa94231ba8252789478e3af26deab1f524246fb4a`

#### source_decisions_excerpt

```
{
  "sha256": "1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39",
  "imports": {
    "source": "malcat",
    "confidence": "high",
    "reason": "Malcat provides imports_count: 31 in the tool summary, which is higher than Ghidra's 28 and Ida's 28, indicating more accurate PE import analysis for this file."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports funcs: 70 and Ida reports funcs: 64 in the summaries, both significantly higher than Malcat's functions_count: 10, suggesting Malcat's count is for a different metric (e.g., exported functions), so Ghidra is preferred for comprehensive disassembly."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Using both Ghidra (strings: 42) and Ida
… [1045 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
    "file_name": "vdaudio.dll",
    "file_path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
    "file_size": 13312,
    "type": "PE",
    "architecture": "X86",
    "entropy": 135,
    "sha256": "1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39",
    "metadata": {
      "Exports::Module name": "vdaudio.dll",
      "Exports::Exports date": "2015-12-16 15:00:51"
    },
   
… [16552 more chars]
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
  "rule_count": 8,
  "top_rules": [
    {
      "name": "execute anti-debugging instructions",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Anti-debugging Instructions"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "Anti-debugging Instructions",
          "id": "B0001.034"
        }
      ]
    },
    {
      "name": "receive data",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Command and Control",
            "C2 Communication",
            "Receive Data"
          ],
          "objective": "Command and Control",
          "behavior": "C2 Communication",
          "method": "Receive Data",
          "id": "B0030.002"
        }
      ]
    },
    {
      "name": "set socket configuration",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Set Socket Config"
          ],
          "objective": "Communication",
          "behavior": "Socket Communication",
          "method": "Set Socket Config",
          "id": "C0001.001"
        }
      ]
    },
    {
      "name": "receive data on socket",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Receive Data"
          ],
          "objective": "Communication",
          "behavior": "Socket Communication",
          "method": "Receive Data",
          "id": "C0001.006"
        }
      ]
    },
    {
      "name": "create TCP socket",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Create TCP Socket"
          ],
          "objective": "Communication",
          "behavior": "Socket Communication",
          "method": "Create TCP Socket",
          "id": "C0001.011"
        }
      ]
    },
    {
      "name": "delete file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Delete File"
          ],
          "objective": "File System",
          "behavior": "Delete File",
          "method": "",
          "id": "C0047"
        }
      ]
    },
    {
      "name": "get file attributes",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Get File Attributes"
          ],
          "objective": "File System",
          "behavior": "Get File Attributes",
          "method": "",
          "id": "C0049"
        }
      ]
    },
    {
      "name": "resolve function by parsing PE exports",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 13312,
  "duration_s": 1.55,
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
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 12416,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 11150,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a1",
          "offset": 10064,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "Borland_Delphi_40_additional",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_30_additional",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_30_",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_Setup_Module",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_40",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514e
… [4885 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 79,
  "strings_sampled": 78,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "Z_^B[B]BX",
    "ntdll.dll",
    "@tJHPh|",
    "F< t)Iu",
    "f=//t\tN",
    "</tf<:t",
    "</t\tIu",
    "tIHPhL",
    "advapi32",
    "ws2_32",
    "a[1Jnv",
    "JV  -A",
    "=-XXg(_",
    "DestroyCursor",
    "LoadMenuA",
    "PtInRect",
    "RegisterClassExA",
    "ReplyMessage",
    "CallWindowProcW",
    "USER32.dll",
    "DeleteFileA",
    "ExitProcess",
    "FatalExit",
    "GetLastError",
    "LoadLibraryExA",
    "lstrcpyA",
    "GetModuleHandleW",
    "KERNEL32.dll",
    "PolyBezierTo",
    "SetColorSpace",
    "SetTextColor",
    "SetWindowExtEx",
    "SetWorldTransform",
    "TextOutA",
    "gdi32.dll",
    "WS2_32.dll",
    "RtlGetProcessHeaps",
    "NtReadFile",
    "NtQueryInformationFile",
    "NtPrivilegeCheck",
    "NtAlertThread",
    "vdaudio.dll",
    "gewayX",
    "gewayZ",
    "vdaudio",
    "I)aiB+6ZxA",
    "qdrnemsd",
    "AIW1YAERWZFW",
    "IDEk-sdk",
    "aaclfd:",
    "IkLook",
    "LXCV0IMGIXS0RTA1",
    "b8-X-ecFW)0Rz?W^",
    "west/1.0 200 OK",
    "<b>l</b>",
    "cm.mnemonicarx.biz",
    "cn.mnemonicarx.biz",
    "O3n3y3",
    "3#4H4U4i4",
    "6!6@6O6U6e6k6t6|6",
    "9B9I9V9\\9",
    ":0:::E:[:t:",
    ";);5;O;v;};",
    "3<3I3P3{3",
    "7g7t7{7",
    "8O8X8`8z8",
    "9%9+9:9T9]9g9u9",
    "9$:1:6:>:D:I:O:U:[:n:w:",
    ";';/;8;A;G;_;e;k;q;",
    "> >(>7>",
    "?$?K?S?[?b?k?v?",
    "0 0'060c0m0s061?1M1",
    "4$4*40464<4B4H4N4T4Z4`4f4l4r4x4~4",
    "kernel32"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 79
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 6.67,
  "size_bytes": 13312,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
    "file_name": "vdaudio.dll",
    "file_path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
    "file_size": 13312,
    "type": "PE",
    "architecture": "X86",
    "entropy": 135,
    "sha256": "1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39",
    "metadata": {
      "Exports::Module name": "vdaudio.dll",
      "Exports::Exports date": "2015-12-16 15:00:51"
    },
    "entrypoint_ea": 10006,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 35
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 9728,
        "virtual_size": 12288,
        "rights": "RX",
        "entropy": 145
      },
      {
        "name": ".rdata",
        "effective_address": 13312,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".data",
        "effective_address": 17408,
        "physical_size": 512,
        "virtual_size": 57344,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".reloc",
        "effective_address": 74752,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "DownloaderApiUsage",
        "desc": "Downloader-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "ManyHighValueImmediates",
        "desc": "Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values that contains at least 2 non-zero non-FF bytes and are not a valid address)",
        "category": "code",
        "level": 3,
        "num_hits": 2
      },
      {
        "name": "ManyUniqueImmediateBytes",
        "desc": "More than 48 unique bytes defined across all immediate operands in the function",
        "category": "code",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "NoChecksum",
        "desc": "PE Header checksum is not set",
        "category": "integrity",
        "level": 1,
        "num_hits": 1
      }
    ],
    "anomaly_locations": {
      "ManyHighValueImmediates": [
        {
          "ea": 2601,
          "context": ""
        },
        {
          "ea": 8408,
          "context": ""
        }
      ],
      "ManyUniqueImmediateBytes": [
        {
          "ea": 8408,
          "context": ""
        }
      ],
      "NoChecksum": [
        {
          "ea": 216,
          "context": ""
        }
      ]
    },
    "yara_hits": [],
    "strings": [
      {
        "ea": 17626,
        "summary": "kernel32"
      },
      {
        "ea": 14152,
        "summary": "ntdll.dll"
      },
      {
        "ea": 17461,
        "summary": "aaclfd:"
      },
      {
        "ea": 8331,
        "summary": "advapi32"
      },
      {
        "ea": 17718,
     
… [23406 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "sub_10002974 decompilations Decompiled code shows a call to 'cn.mnemonicarx.biz' (a C2 domain) and network socket setup,",
    "cm.mnemonicarx.biz strings String 'cm.mnemonicarx.biz' is a C2 domain, corroborating network communication. floss   ",
    "delete file top_rules Rule indicates capability to delete files, a destructive behavior. capa   ",
    "DeleteFileA strings/apis Import of DeleteFileA (from KERNEL32) enables file deletion, aligning with capa's destructive b",
    "execute anti-debugging instructions top_rules Rule indicates anti-analysis technique, commonly used in malware. capa   "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Unknown backdoor/Trojan (possible Delphi-based)",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_10002974",
      "why": "Decompiled code shows a call to 'cn.mnemonicarx.biz' (a C2 domain) and network socket setup, indicating C2 communication."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "cm.mnemonicarx.biz",
      "why": "String 'cm.mnemonicarx.biz' is a C2 domain, corroborating network communication."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "delete file",
      "why": "Rule indicates capability to delete files, a destructive behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "strings/apis",
      "row_or_rule": "DeleteFileA",
      "why": "Import of DeleteFileA (from KERNEL32) enables file deletion, aligning with capa's destructive behavior rule."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "execute anti-debugging instructions",
      "why": "Rule indicates anti-analysis technique, commonly used in malware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary)",
      "why": "High-signal import for dynamic API loading (T1129), often used for obfuscation or evasion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "resolve function by parsing PE exports",
      "why": "Rule indicates dynamic API resolution, a common malware technique."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Str_Win32_Winsock2_Library",
      "why": "Rule matches Winsock library usage, indicating network communication capability."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "WS2_32 | (empty name)",
      "why": "Imports from WS2_32.dll (Winsock) indicate socket-based network communication."
    },
    {
      "source": "malcat",
      "query_or_table": "functions",
      "row_or_rule": "gewayX",
      "why": "Exported function 'gewayX' is the entry point, suggesting the DLL is designed to be loaded and executed."
    }
  ],
  "summary": "Sample is a 32-bit DLL that communicates with C2 domains (cn.mnemonicarx.biz, cm.mnemonicarx.biz), uses anti-debugging techniques, dynamically resolves APIs, and has file deletion capability. These behaviors indicate malicious intent (C2 beaconing and destructive actions), despite possible obfuscation (high entropy .text section, Borland Delphi artifacts)."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/prompt.txt` exists=`True` bytes=`25975` mtime=`2026-08-09T13:59:24.484771+00:00`
  - sha256: `5ad38da3ea54497f7e44cd6f59f6c6564d3e65c765d6aeb678d865185863a578`
- **verdict:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/verdict.json` exists=`True` bytes=`5258` mtime=`2026-08-09T14:02:08.918425+00:00`
  - sha256: `c38b1e847b32c3a45b397bc5c6624775c578b9cb3d6b73af7eb2e2a89426541b`

#### prompt_excerpt

```
# Triage evidence
sha256: 1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39
sample_path: /opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll
ghidra_session: ghidra-pe-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39
ida_session: ida-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39

## Source decisions (from intake validation)
- imports: malcat (confidence=high) — Malcat provides imports_count: 31 in the tool summary, which is higher than Ghidra's 28 and Ida's 28, indicating more accurate PE import analysis for this file.
- functions: ghidra (confidence=medium) — Ghidra reports funcs: 70 and Ida reports funcs: 64 in the summaries, both significantly higher than Malcat's functions_count: 10, suggesting Malcat's count is for a different metric (e.g., exported functions), so Ghidra is preferred for comprehensive disassembly.
- strings: both (confidence=high) — Using both Ghidra (strings: 42) and
… [24944 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Unknown backdoor/Trojan (possible Delphi-based)",
  "cross_engine_notes": "Multiple engines confirm network C2 and destructive capabilities. Ghidra and IDA provide consistent function/string counts. Malcat highlights anomalies and decompiled C2 calls. Capa and YARA identify behavioral rules. FLOSS extracts C2 domains and suspicious strings.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_10002974",
      "why": "Decompiled code shows a call to 'cn.mnemonicarx.biz' (a C2 domain) and network socket setup, indicating C2 communication."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "cm.mnemonicarx.biz",
      "why": "String 'cm.mnemonicarx.biz' is a C2 domain, corroborating network communication."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "delete file",
   
… [4258 more chars]
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
  "rule_count": 8,
  "top_rules": [
    {
      "name": "execute anti-debugging instructions",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Anti-debugging Instructions"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "Anti-debugging Instructions",
          "id": "B0001.034"
        }
      ]
    },
    {
      "name": "receive data",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Command and Control",
            "C2 Communication",
            "Receive Data"
          ],
          "objective": "Command and Control",
          "behavior": "C2 Communication",
          "method": "Receive Data",
          "id": "B0030.002"
        }
      ]
    },
    {
      "name": "set socket configuration",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Set Socket Config"
          ],
          "objective": "Communication",
          "behavior": "Socket Communication",
          "method": "Set Socket Config",
          "id": "C0001.001"
        }
      ]
    },
    {
      "name": "receive data on socket",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Receive Data"
          ],
          "objective": "Communication",
          "behavior": "Socket Communication",
          "method": "Receive Data",
          "id": "C0001.006"
        }
      ]
    },
    {
      "name": "create TCP socket",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Create TCP Socket"
          ],
          "objective": "Communication",
          "behavior": "Socket Communication",
          "method": "Create TCP Socket",
          "id": "C0001.011"
        }
      ]
    },
    {
      "name": "delete file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Delete File"
          ],
          "objective": "File System",
          "behavior": "Delete File",
          "method": "",
          "id": "C0047"
        }
      ]
    },
    {
      "name": "get file attributes",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Get File Attributes"
          ],
          "objective": "File System",
          "behavior": "Get File Attributes",
          "method": "",
          "id": "C0049"
        }
      ]
    },
    {
      "name": "resolve function by parsing PE exports",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 13312,
  "duration_s": 0.85,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 13312,
  "duration_s": 0.03,
  "import_count": 28,
  "signal_count": 1,
  "signals": [
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
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
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 12416,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 11150,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a1",
          "offset": 10064,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": []
    },
    {
      "rule": "Borland_Delphi_40_additional",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_30_additional",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_30_",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_Setup_Module",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 1812,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland_Delphi_40",
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514e
… [4863 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 79,
  "strings_sampled": 78,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "Z_^B[B]BX",
    "ntdll.dll",
    "@tJHPh|",
    "F< t)Iu",
    "f=//t\tN",
    "</tf<:t",
    "</t\tIu",
    "tIHPhL",
    "advapi32",
    "ws2_32",
    "a[1Jnv",
    "JV  -A",
    "=-XXg(_",
    "DestroyCursor",
    "LoadMenuA",
    "PtInRect",
    "RegisterClassExA",
    "ReplyMessage",
    "CallWindowProcW",
    "USER32.dll",
    "DeleteFileA",
    "ExitProcess",
    "FatalExit",
    "GetLastError",
    "LoadLibraryExA",
    "lstrcpyA",
    "GetModuleHandleW",
    "KERNEL32.dll",
    "PolyBezierTo",
    "SetColorSpace",
    "SetTextColor",
    "SetWindowExtEx",
    "SetWorldTransform",
    "TextOutA",
    "gdi32.dll",
    "WS2_32.dll",
    "RtlGetProcessHeaps",
    "NtReadFile",
    "NtQueryInformationFile",
    "NtPrivilegeCheck",
    "NtAlertThread",
    "vdaudio.dll",
    "gewayX",
    "gewayZ",
    "vdaudio",
    "I)aiB+6ZxA",
    "qdrnemsd",
    "AIW1YAERWZFW",
    "IDEk-sdk",
    "aaclfd:",
    "IkLook",
    "LXCV0IMGIXS0RTA1",
    "b8-X-ecFW)0Rz?W^",
    "west/1.0 200 OK",
    "<b>l</b>",
    "cm.mnemonicarx.biz",
    "cn.mnemonicarx.biz",
    "O3n3y3",
    "3#4H4U4i4",
    "6!6@6O6U6e6k6t6|6",
    "9B9I9V9\\9",
    ":0:::E:[:t:",
    ";);5;O;v;};",
    "3<3I3P3{3",
    "7g7t7{7",
    "8O8X8`8z8",
    "9%9+9:9T9]9g9u9",
    "9$:1:6:>:D:I:O:U:[:n:w:",
    ";';/;8;A;G;_;e;k;q;",
    "> >(>7>",
    "?$?K?S?[?b?k?v?",
    "0 0'060c0m0s061?1M1",
    "4$4*40464<4B4H4N4T4Z4`4f4l4r4x4~4",
    "kernel32"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 79
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 7.33,
  "size_bytes": 13312,
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
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
  "disassembly": {
    "0x10003316": "\u250c 15: entry0 ();\n\u2502           0x10003316      55             push ebp\n\u2502           0x10003317      8bec           mov ebp, esp\n\u2502           0x10003319      83c4e8         add esp, 0xffffffe8\n\u2502           0x1000331c      a115500010     mov eax, dword [0x10005015] ; [0x10005015:4]=1\n\u2502           0x10003321      c9             leave\n\u2514           0x10003322      c20c00         ret 0xc",
    "0x10002ca8": "\u250c 19: sym.vdaudio.dll_gewayX ();\n\u2502           0x10002ca8      6a00           push 0\n\u2502           0x10002caa      6a10           push 0x10                   ; 16\n\u2502           0x10002cac      6857b90010     push 0x1000b957\n\u2502           0x10002cb1      50             push eax\n\u2502           0x10002cb2      51             push ecx\n\u2502           0x10002cb3      e8dc070000     call 0x10003494\n\u2502           0x10002cb8      48             dec eax\n\u2514           0x10002cb9      ffe1           jmp ecx",
    "0x10002c95": "\u250c 19: sym.vdaudio.dll_gewayZ ();\n\u2502           0x10002c95      6a00           push 0\n\u2502           0x10002c97      6a10           push 0x10                   ; 16\n\u2502           0x10002c99      6857b90010     push 0x1000b957\n\u2502           0x10002c9e      50             push eax\n\u2502           0x10002c9f      51             push ecx\n\u2502           0x10002ca0      e8ef070000     call 0x10003494\n\u2502           0x10002ca5      48             dec eax\n\u2514           0x10002ca6      ffe1           jmp ecx",
    "0x10002cc2": "\u250c 22: sym.vdaudio.dll_vdaudio ();\n\u2502           0x10002cc2      b8f0280010     mov eax, 0x100028f0\n\u2502           0x10002cc7      8d80e8030000   lea eax, [eax + 0x3e8]\n\u2502           0x10002ccd      ffd0           call eax\n\u2502           0x10002ccf      b8d5320010     mov eax, 0x100032d5\n\u2502           0x10002cd4      48             dec eax\n\u2502           0x10002cd5      ffd0           call eax\n\u2514           0x10002cd7      c3             ret"
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x10003316",
    "0x10002ca8",
    "0x10002c95",
    "0x10002cc2"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
    "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
    "exists": true,
    "hook_candidates": [
      "USER32.dll!ReplyMessage",
      "USER32.dll!RegisterClassExA",
      "USER32.dll!PtInRect",
      "USER32.dll!LoadMenuA",
      "USER32.dll!CallWindowProcW",
      "KERNEL32.dll!lstrcpyA",
      "KERNEL32.dll!LoadLibraryExA",
      "KERNEL32.dll!DeleteFileA",
      "KERNEL32.dll!ExitProcess",
      "KERNEL32.dll!FatalExit",
      "gdi32.dll!SetWorldTransform",
      "gdi32.dll!SetWindowExtEx",
      "gdi32.dll!SetTextColor",
      "gdi32.dll!PolyBezierTo",
      "gdi32.dll!SetColorSpace",
      "WS2_32.dll!setsockopt",
      "WS2_32.dll!socket",
      "WS2_32.dll!recv",
      "WS2_32.dll!closesocket",
      "ntdll.dll!NtReadFile",
      "ntdll.dll!NtQueryInformationFile",
      "ntdll.dll!NtPrivilegeCheck",
      "ntdll.dll!NtAlertThread",
      "ntdll.dll!RtlGetProcessHeaps"
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
  "checked": 14,
  "hits": 14,
  "misses": [],
  "hit_examples": [
    "Hardcoded C2 domains: 'cm.mnemonicarx.biz' and 'cn.mnemonicarx.biz' found in .data section (Ghidra strings table), refer",
    "Dynamic API resolution: FUN_10002cd8 (879 bytes, cyclomatic complexity 42, 14 string refs) resolves kernel32/advapi32/ws",
    "Indirect calls to resolved APIs: FUN_10002cd8 makes indirect calls through writable .data pointers at DAT_1000af6c, DAT_",
    "CAPA detected anti-debugging: 'execute anti-debugging instructions' rule matched (B0001.034)",
    "CAPA confirmed C2 communication: TCP socket creation (C0001.011), socket data receiving (C0001.006, B0030.002), socket c"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is a Borland Delphi-compiled backdoor/RAT DLL (vdaudio.dll) that masquerades as an audio library while establishing C2 communication with hardcoded domains cm.mnemonicarx.biz and cn.mnemonicarx.biz via dynamically resolved Winsock APIs. The sample uses dynamic API resolution via PE export parsi",
  "key_evidence": [
    "Hardcoded C2 domains: 'cm.mnemonicarx.biz' and 'cn.mnemonicarx.biz' found in .data section (Ghidra strings table), referenced by FUN_100016eb (cyclomatic complexity 46) and FUN_10002974 respectively",
    "Dynamic API resolution: FUN_10002cd8 (879 bytes, cyclomatic complexity 42, 14 string refs) resolves kernel32/advapi32/ws2_32 at runtime via GetModuleHandleW + LoadLibraryExA + PE export parsing, confirmed by CAPA rule 'resolve function by parsing PE exports'",
    "Indirect calls to resolved APIs: FUN_10002cd8 makes indirect calls through writable .data pointers at DAT_1000af6c, DAT_1000af70, DAT_1000af84 (all in writable .data section, 54KB), plus CALL ECX register-based dispatch",
    "CAPA detected anti-debugging: 'execute anti-debugging instructions' rule matched (B0001.034)",
    "CAPA confirmed C2 communication: TCP socket creation (C0001.011), socket data receiving (C0001.006, B0030.002), socket configuration (C0001.001)",
    "WS2_32 (Winsock) imported by ordinal: Ordinal_3 (connect), Ordinal_16 (recv), Ordinal_21 (send), Ordinal_23 (socket) - avoids string-based IOC detection",
    "HTTP response validation string 'west/1.0 200 OK\\r\\n' found in Ghidra strings, referenced 5 times by FUN_10002cd8 and by FUN_10002509/FUN_1000275f",
    "Encoded strings suggest encrypted config/keys: 'LXCV0IMGIXS0RTA1', 'b8-X-ecFW)0Rz?W^', 'AIW1YAERWZFW', 'qdrnemsd' - referenced by FUN_10002b7e, FUN_10002bc5, FUN_10002cd8",
    "Masquerade as audio DLL: exports 'gewayX', 'gewayZ', 'vdaudio'; filename 'vdaudio.dll'; GDI32 decoy imports (PolyBezierTo, SetColorSpace, TextOutA, etc.) with no legitimate audio functionality",
    "File deletion capability: DeleteFileA imported from KERNEL32, CAPA rule 'delete file' (C0047) matched",
    "Borland Delphi compiler signatures: 8+ YARA rules matched (Borland_Delphi_30, Delphi_40, Delphi_DLL, Delphi_v30, etc.) at offset 1812",
    "YARA rule 'maldoc_find_kernel32_base_method_1' matched at offset 10064 - kernel32 base address resolution technique",
    "Large writable .data section (54980 bytes at 0x10006000-0x1001EFFF) stores runtime-resolved API pointers and configuration data",
    "Function call flow: FUN_10001629 -> FUN_100016eb (main C2 handler) -> Ordinal_21 (WS2_32 send) + FUN_10002b76 + FUN_10003220, demonstrating complete C2 communication chain"
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
      "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
      "path": "/opt/samples/co
… [7963 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
    "file_name": "vdaudio.dll",
    "file_path": "/
… [26484 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 8,
  "top_rules": [
    {
      "name": "execute anti-debugging instructions",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Anti-debugging Instructions"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "me
… [2573 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 13312,
  "duration_s": 0.03,
  "import_count": 28,
  "signal_count": 1,
  "signals": [
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 79,
  "strings_sampled": 78,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "Z_^B[B]BX",
    "ntdll.dll",
    "@tJHPh|",
    "F< t)Iu",
    "f=//t\tN",
    "</tf<:t",
    "</t\tIu",
    "tIHPhL",
    "advapi32",
    "ws2_32",
    "a[1Jnv",
    "JV  -A",
    "=-XXg(_",
    "DestroyCursor",
    "Lo
… [1589 more chars]
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
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
  "disassembly": {
    "0x10003316": "\u250c 15: entry0 ();\n\u2502           0x10003316      55             push ebp\n\u2502           0x10003317      8bec           mov ebp, esp\n\u2502           0x10003319      83c4e8         add esp, 0xffffffe8\n\u2502         
… [1959 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_ret
… [13 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
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
    "path": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
    "exists": true,
    "hook_candidates": [
      "USER32.dll!ReplyMessage",
      "USER32.dll!RegisterClassExA",
      "USER32.dll!PtInRect",
      "USER32.dll!LoadMenuA",
      "USER32.dll!CallWindowProcW",
… [641 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/revai-lab-610/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/vdaudio.dll",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 9728,
      "entropy": 6.6166,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 1024,
      "entropy": 4.6127,
      "executable": false,
… [378 more chars]
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 7.95,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 4,
    "min_resolve_calls": 2,
    "elapsed_s": 0.27,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "suspicious",
  "name": null,
  "score": 3
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
      "name": "FUN_100016eb",
      "address": "268441323",
      "size": "1182"
    },
    {
      "name": "FUN_10002cd8",
      "address": "268446936",
      "size": "879"
    },
    {
      "name": "FUN_10002974",
      "address": "268446068",
      "size": "514"
    },
    {
      "name": "FUN_10002509",
      "addre
… [2292 more chars]
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
      "name": "PolyBezierTo",
      "module": "GDI32.DLL"
    },
    {
      "name": "SetColorSpace",
      "module": "GDI32.DLL"
    },
    {
      "name": "SetTextColor",
      "module": "GDI32.DLL"
    },
    {
      "name": "SetWindowExtEx",
      "module": "GDI32.DLL"
    },
    {
      "name": "SetWorldTransform",
      "module
… [1996 more chars]
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
      "content": "NtQueryInformationFile",
      "address": "268452620",
      "length": "23"
    },
    {
      "content": "west/1.0 200 OK\r\n\r\n",
      "address": "268456246",
      "length": "20"
    },
    {
      "content": "RtlGetProcessHeaps",
      "address": "268452584",
      "length": "19"
    },
    {
… [4047 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "instruction_count",
    "block_count",
    "cyclomatic_complexity",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_100016eb",
      "address": "268441323",
      "size": "1182",
      "instruction_count": "331",
      "block_count": "89",
      "cyclomatic_complexity": "46",
      "call_out_count":
… [7529 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: e.name`

```json
{
  "error": "ghidrasql SQL error: no such column: e.name"
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
      "func_name": "FUN_100016eb",
      "func_addr": "268441323",
      "string_value": "cm.mnemonicarx.biz"
    },
    {
      "func_name": "FUN_1000259a",
      "func_addr": "268445082",
      "string_value": "west/1.0 200 OK\r\n\r\n"
    },
    {
      "func_name": "FUN_1000275f",
      "func_addr": "2
… [1613 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "ref_count",
    "strings"
  ],
  "rows": [
    {
      "func_name": "FUN_10002cd8",
      "ref_count": "14",
      "strings": "YAERWZFW,kernel32,advapi32,ws2_32,west/1.0 200 OK\r\n\r\n"
    },
    {
      "func_name": "",
      "ref_count": "4",
      "strings": "vdaudio.dll,gewayX,gewayZ,vdaudio"
    },
    {
      "func_name": "FUN_10002974",
      "ref_cou
… [925 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39.json"
}
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
      "name": "FUN_10001431",
      "address": "268440625"
    },
    {
      "name": "FUN_100014d2",
      "address": "268440786"
    },
    {
      "name": "FUN_10001507",
      "address": "268440839"
    },
    {
      "name": "FUN_1000155e",
      "address": "268440926"
    },
    {
      "name": "FUN_10001598",
      "address":
… [3535 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 8,
  "top_rules": [
    {
      "name": "execute anti-debugging instructions",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Anti-debugging Instructions"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "me
… [2573 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "string_value",
    "string_addr"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39",
  "audit_path": "/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "ref_count",
    "strings"
  ],
  "rows": [
    {
      "func_name": "sub_10002CD8",
      "ref_count": "1",
      "strings": "aclfd:"
    },
    {
      "func_name": "sub_10002509",
      "ref_count": "1",
      "strings": "t/1.0 200 OK\r\n\r\n"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ida_query",
  "session_id":
… [187 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 13312,
  "duration_s": 0.07,
  "import_count": 28,
  "signal_count": 1,
  "signals": [
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: ce.from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: ce.from_func_name"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: ce.from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: ce.from_func_name"
}
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
      "src_func_addr": "0",
      "src_func_name": "sub_0",
      "dst_func_addr": "268448766",
      "dst_func_name": "DestroyCursor",
      "call_site": "268440403"
    },
    {
      "src_func_addr": "0",
      "src_func_name": "sub_0",
      "dst_func_addr
… [931 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: address`

```json
{
  "error": "ghidrasql SQL error: no such column: address"
}
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `idasql SQL error: no such column: f.name`

```json
{
  "error": "idasql SQL error: no such column: f.name"
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
      "src_func_name": "FUN_10001629",
      "dst_func_name": "FUN_100016eb"
    },
    {
      "src_func_name": "FUN_100016eb",
      "dst_func_name": "FUN_10001ba3"
    },
    {
      "src_func_name": "FUN_100016eb",
      "dst_func_name": "FUN_100033b4"
    },
    {
      "src_func_name": "FUN_100016eb",
      "dst
… [4461 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "start_ea",
    "end_ea",
    "name",
    "class",
    "perm",
    "bitness",
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
      "perm": "4",
      "bitness": "0",
      "size": "1024",
      "is_read": "1",
      "is_write": "0",
     
… [1322 more chars]
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
      "content": "NtQueryInformationFile",
      "address": "268452620",
      "length": "23"
    },
    {
      "content": "RtlGetProcessHeaps",
      "address": "268452584",
      "length": "19"
    },
    {
      "content": "cm.mnemonicarx.biz",
      "address": "268456281",
      "length": "19"
    },
    {
    
… [2940 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 79,
  "strings_sampled": 78,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".reloc",
    "Z_^B[B]BX",
    "ntdll.dll",
    "@tJHPh|",
    "F< t)Iu",
    "f=//t\tN",
    "</tf<:t",
    "</t\tIu",
    "tIHPhL",
    "advapi32",
    "ws2_32",
    "a[1Jnv",
    "JV  -A",
    "=-XXg(_",
    "DestroyCursor",
    "Lo
… [1589 more chars]
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
      "src_func_name": "FUN_10002974",
      "dst_func_name": "FUN_100033b4"
    },
    {
      "src_func_name": "FUN_10002974",
      "dst_func_name": "FUN_10002b76"
    },
    {
      "src_func_name": "FUN_10002974",
      "dst_func_name": "FUN_100015d9"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,
  "trunca
… [249 more chars]
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
      "src_func_name": "FUN_10002cd8",
      "dst_func_name": "lstrcpyA"
    },
    {
      "src_func_name": "FUN_10002cd8",
      "dst_func_name": "GetModuleHandleW"
    },
    {
      "src_func_name": "FUN_10002cd8",
      "dst_func_name": "FUN_10001598"
    },
    {
      "src_func_name": "FUN_10002cd8",
      "dst
… [1425 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands"
  ],
  "rows": [
    {
      "address": "268446955",
      "mnemonic": "CALL",
      "operands": "0x10003440"
    },
    {
      "address": "268447116",
      "mnemonic": "CALL",
      "operands": "0x10003446"
    },
    {
      "address": "268447131",
      "mnemonic": "CALL",
      "operands": "0x10001598"
    },
    {
      "address
… [2310 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "data_type",
    "size"
  ],
  "rows": [
    {
      "name": "DAT_1000af6c",
      "address": "268480364",
      "data_type": "undefined4",
      "size": "4"
    },
    {
      "name": "DAT_1000af70",
      "address": "268480368",
      "data_type": "undefined4",
      "size": "4"
    },
    {
      "name": "DAT_1000af84",
      "address": "268480388
… [365 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "data_type",
    "size"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39",
  "audit_path": "/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands"
  ],
  "rows": [
    {
      "address": "268447131",
      "mnemonic": "CALL",
      "operands": "0x10001598"
    },
    {
      "address": "268447152",
      "mnemonic": "CALL",
      "operands": "0x1000343a"
    },
    {
      "address": "268447167",
      "mnemonic": "CALL",
      "operands": "0x10001598"
    },
    {
      "address
… [789 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/deep_dive/01-tools-raw.json` exists=`True` bytes=`52173` mtime=`2026-08-09T21:47:41.480405+00:00`
  - sha256: `1748114a57da2268648c55ea28164984f32a5238c824800a8df058bb42b78695`
- **sql_evidence:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/deep_dive/05-deep-dive.json` exists=`True` bytes=`4400` mtime=`2026-08-09T21:49:39.282312+00:00`
  - sha256: `a8e05941d7528dd8f48f882ac2313463ea03fa18c67f67791cb95b4eaaf52acd`

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
  "summary": "This is a Borland Delphi-compiled backdoor/RAT DLL (vdaudio.dll) that masquerades as an audio library while establishing C2 communication with hardcoded domains cm.mnemonicarx.biz and cn.mnemonicarx.biz via dynamically resolved Winsock APIs. The sample uses dynamic API resolution via PE export parsing to resolve kernel32, advapi32, and ws2_32 at runtime, employs anti-debugging techniques, and stores resolved function pointers in a large writable .data section. The DLL imports GDI32 functions (PolyBezierTo, SetColorSpace, etc.) as decoy traffic to appear as a graphics/audio library, while its true functionality is network-based C2 communication with file deletion capabilit
… [3600 more chars]
```

- **agentic:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`268620` mtime=`2026-08-09T21:49:39.281312+00:00`
  - sha256: `5a6ab9c86ab24cc926c0b800bf131777a1d3504727b8618c08700bed8347361d`

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

- **rule_yar:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/rule.yar` exists=`True` bytes=`1206` mtime=`2026-08-09T14:12:26.836553+00:00`
  - sha256: `ab1850be3dbbbcecd525e681b0a5280244500911073ace9da5106b295780dff3`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T14:12:26.836648+00:00
import "pe"
rule CADRE_v2_unknown_backdoor_trojan_possible_delphi_based_1e9f21f514ee {
    meta:
        description = "RevAI v2 auto rule for Unknown backdoor/Trojan (possible Delphi-based)"
        sha256 = "1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39"
        family = "unknown_backdoor_trojan_possible_delphi_based"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "Z_^B[B]BX" ascii wide
        $s2 = "ntdll.dll" ascii wide
        $s3 = "advapi32" ascii wide
        $s4 = "DestroyCursor" ascii wide
        $s5 = "LoadMenuA" asc
… [404 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/REPORT-MASTER-v2.md` exists=`True` bytes=`16568` mtime=`2026-08-09T21:57:09.450258+00:00`
  - sha256: `878cfe860f6a10a48d881938b4841dfb4777f366ed20fce3dd5d80ad515bfeec`
- **REPORT_MASTER_v3:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/REPORT-MASTER-v3.md` exists=`True` bytes=`45445` mtime=`2026-08-09T22:06:38.041454+00:00`
  - sha256: `65724eadb21133c917a3d4a3fb6a76bed5cf8108f43641ffe6599722615fdec1`
- **REPORT_v2:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/REPORT-v2.md` exists=`True` bytes=`16568` mtime=`2026-08-09T21:57:09.449258+00:00`
  - sha256: `878cfe860f6a10a48d881938b4841dfb4777f366ed20fce3dd5d80ad515bfeec`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`50192` mtime=`2026-08-09T21:59:30.712642+00:00`
  - sha256: `e6c5307f6ab7c5c7f8038d6768b16c9628082260e1610fa8d1a9e4739b63d46b`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`43448` mtime=`2026-08-09T22:08:34.181491+00:00`
  - sha256: `61cc52b509acde3c6e9f2ffc6ba0503196e33945fa47f8dc74941fccc9fa769f`
- **report_v2_json:** `/opt/samples/logs/1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39/report-v2.json` exists=`True` bytes=`19797` mtime=`2026-08-09T21:59:30.715642+00:00`
  - sha256: `191740e4482debc7f070d970e6eb56ba0cf6bbfd38da6fe67c60122f97a7bb72`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:57:09 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: maldoc_find_kernel32_base_method_1, IsPE32, IsDLL, IsWindowsGUI, Borland_Delphi_40_additional, Microsoft_Visual_Cpp_v50v60_MFC, Borland_Delphi_30_additional, Borland_Delphi_30_). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unknown backdoor/Trojan (possible Delphi-based)
- **Honesty:** the publish narrati
… [15659 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 22:06:38 UTC

# RE Report — 1e9f21f514ee
_Generated 2026-08-09T22:06:38.040074+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=32.87s -->

# Executive Summary

This malware sample, identified by SHA256 `1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39`, is assessed as **malicious** with high confidence, belonging to an **unknown backdoor/Trojan family, possibly Delphi-based**. Confidence is **90%** based on deep dive analysis and tool consensus. The sample exhibits behaviors consistent with backdoor functionality, including anti-a
… [44525 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
