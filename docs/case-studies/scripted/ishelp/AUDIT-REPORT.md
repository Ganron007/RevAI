# Pipeline AUDIT-REPORT — `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T09:51:23.364631+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 09:51:23 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`

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
- key_evidence_count=`8`

```json
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "Lotus Blossom",
  "cross_engine_notes": "Ghidra and IDA agree on 74 functions and 88 imports, indicating reliable disassembly. MalCat identifies 11 anomalies including EmbeddedProgram and high-signal imports like CreateRemoteThread. Capa and YARA rules detect process injection, privilege escalation, and persistence behaviors. External VirusTotal shows 49 malicious detections with threat names like 'lotusblossom' and 'explorerhijack'.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "kernel32.CreateRemoteThread",
      "why": "API for creating remote threads in other processes, a key technique for process injection and malicious code execution."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1055.003",
      "why": "Rule for Thread Execution Hijacking, indicating process injection for defense evasion, a clear malicious behavior."
    },
    {
      "source": "ghidra",
      "query_or_table": "Anti Analysis Signals",
      "row_or_rule": "FUN_100019a0",
      "why": "Function enumerates processes using CreateToolhelp32Snapshot, used for discovery and targeting in malicious activities."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "inject_thread",
      "why": "YARA rule match for thread injection, confirming malicious injection capabilities from behavioral patterns."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "EmbeddedProgram",
      "why": "Anomaly indicates an embedded program, suggesting dropper or payload delivery functionality for malware distribution."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "why": "Registry key for autostart persistence, commonly modified by malware to ensure survival across reboots."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "cmd.exe /c %s > %s",
      "why": "String for command execution and output redirection, indicating potential command-and-control or payload execution."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "change_memory_protection",
      "why": "VirtualProtect API used to alter memory permissions, enabling executable code in non-executable regions for injection."
    }
  ],
  "summary": "The DLL 'ishelp.dll' exhibits malicious behavior including process injection via CreateRemoteThread, registry-based persistence, privilege escalation, and an embedded payload. It uses anti-analysis techniques and matches known malware patterns, with strong consensus from multiple analysis engines and external threat intelligence.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 26 matches",
      "capa: 30 rules"
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
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "floss": {
        "ok": true,
… [2917 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`98`
- key_evidence_count=`12`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 98,
  "summary": "This is a DLL dropper/loader component of the Emissary APT malware family. YARA rule 'Emissary_APT_Malware_1' matched with 8 distinct strings. The DLL exports a 'Setting' function designed to be invoked via rundll32.exe. Its behavioral chain: (1) creates mutex '_MICROSOFT_LOADER_MUTEX_' for single-instance enforcement, (2) enables SeDebugPrivilege via AdjustTokenPrivileges for elevated process access, (3) extracts an embedded payload from PE resources to disk as 'A08E81B411.DAT' in a \\LocalData\\ directory (FindResourceW/LockResource/CreateFileA), (4) enumerates running processes using CreateToolhelp32Snapshot to locate IE (iexplore.exe) as injection target, (5) performs classic process injection via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread into the target process, (6) establishes registry persistence under Software\\Microsoft\\Windows\\CurrentVersion\\Run with 'rundll32.exe \"%s\",Setting', (7) reads proxy configuration from Internet Settings registry keys (ProxyEnable/ProxyServer) likely for C2 configuration. CAPA confirms stack string obfuscation (T1027.005), Base64 encoding (T1027), and file discovery (T1083). The 151-cyclomatic-complexity main function (FUN_10003853, 2771 bytes) suggests heavy obfuscation or control-flow flattening. VersionInfo metadata claiming 'Loader Dynamic Link Library' and 'Copyright (C) 2015' is irrelevant \u2014 all functional indicators are unambiguously malicious. Exfiltration: Not observed based on YARA rule 'Emissary_APT_Malware_1' and CAPA analysis, as no data exfiltration techniques (e.g., network transmission, file transfer) were identified in the behavioral chain or tool outputs. Defense impairment: Not observed based on YARA rule 'Emissary_APT_Malware_1' and CAPA analysis, as no techniques to disable security tools, clear logs, or evade defenses were identified in the behavioral chain or tool outputs.",
  "key_evidence": [
    "YARA rule 'Emissary_APT_Malware_1' matched with 8 strings at offsets 61976, 61996, 17696, 61864, 60320, 61412, 70960, 61896",
    "Imports: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtectEx, OpenProcess (classic DLL injection chain)",
    "Imports: AdjustTokenPrivileges, LookupPrivilegeValueA, OpenProcessToken (privilege escalation)",
    "String refs in FUN_10002300: 'IE Process is running.' and '_MICROSOFT_LOADER_MUTEX_' (IE injection targeting + mutex)",
    "String refs in FUN_100019a0: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'A08E81B411.DAT', 'SeDebugPrivilege', '\\LocalData\\' (persistence + payload drop + priv esc)",
    "Export 'Setting' with string 'rundll32.exe \"%s\",Setting' (autorun persistence via rundll32)",
    "Strings: 'ProxyEnable', 'ProxyServer', 'Internet Settings' registry path (proxy credential theft)",
    "FUN_10001820 references 'ReleaseFile Error->FindResource Failed', 'LoadLibrary Failed', 'GetProcAddress Failed', 'CreateFile Failed' (resource-based dropper with debug strings)",
    "CAPA: obfuscated stackstrings (T1027.005), Base64 encoding (T1027), file/directory discovery (T1083)",
    "FUN_10003853: size=2771, cyclomatic_complexity=151, 240 basic blocks (heavily obfuscated main payload logic)",
    "Imports: CreateToolhelp32Snapshot, Process32First, Process32Next, Module32First, Module32Next (process/module enumeration for injection target)",
    "SHA512 constants and BASE6
… [1335 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: ishelp.dll (Lotus Blossom / Emissary APT Loader)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 09:32:35 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Malware Analysis Report: ishelp.dll (Lotus Blossom / Emissary APT Loader)\n\n## Executive Summary\n\nThe DLL sample `ishelp.dll` (SHA256: `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`) is a malicious dropper/loader component associated with the Emissary APT (also tracked as Lotus Blossom). The sample exhibits a clear behavioral chain: it creates a mutex for single-instance enforcement, escalates privileges via `SeDebugPrivilege`, extracts an embedded PE payload from its resources to disk, enumerates running processes to locate Internet Explorer (`iexplore.exe`) as an injection target, performs classic DLL injection via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, and establishes persistence through a `Run` registry key invoking `rundll32.exe`. The sample also reads proxy configuration from the registry, likely for C2 communication setup. Multiple YARA rules matched, including `Emissary_APT_Malware_1` with 8 distinct strings, and CAPA identified thread injection, obfuscated stack strings, and Base64 encoding. The verdict is **malicious** with high confidence (98%). (source: deep-dive.json, triage verdict.json)\n\n## 1. Sample Identification\n\n| Field | Value |\n|---|---|\n| SHA256 | `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76` |\n| File Path | `/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll` |\n| File Type | PE32 DLL (x86) |\n| Architecture | x86 (32-bit) |\n| Entropy | 6.35 bits/byte (whole-file Shannon entropy) |\n| Imphash | `aee2f8f6aa200110e796682791bc8758` |\n| Packed | No (UPX probe returned 0 files tested; not packed) |\n| .NET | Not a .NET assembly |\n| Export | `Setting` (invoked via `rundll32.exe \"%s\",Setting`) |\n| Compiler | Visual C++ 2008 (MSVC_2008_linker, MSVC_2008_rich YARA matches) |\n| VersionInfo | Claims \"Loader Dynamic Link Library\", Copyright (C) 2015 -- irrelevant metadata (source: deep-dive.json) |\n\nThe file is a standard PE32 DLL with a single exported function named `Setting`. The entropy of 6.35 bits/byte is moderately elevated but not indicative of packing; the UPX probe confirmed no UPX packing. The import hash `aee2f8f6aa200110e796682791bc8758` can be used for cross-referencing with threat intelligence databases. (source: malcat, rule.yara.json)\n\n## 2. Classification\n\n| Field | Value |\n|---|---|\n| Verdict | **Malicious** |\n| Confidence | 98% |\n| Family | Emissary APT / Lotus Blossom (trojan.lotusblossom/explorerhijack) |\n| Type | DLL Dropper/Loader |\n| Triage Score | 95/100 |\n| Agreement | LLM and v1 triage agree |\n\nThe classification is unambiguous. The sample exhibits multiple behavioral-intent indicators: process injection (T1055.003), privilege escalation via `SeDebugPrivilege`, registry-based persistence (T1547.001), embedded payload extraction, and mutex creation. These are 
… [21505 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:32:35 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: ishelp.dll (Lotus Blossom / Emissary APT Loader)

## Executive Summary

The DLL sample `ishelp.dll` (SHA256: `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`) is a malicious dropper/loader component associated with the Emissary APT (also tracked as Lotus Blossom). The sample exhibits a clear behavioral chain: it creates a mutex for single-instance enforcement, escalates privileges via `SeDebugPrivilege`, extracts an embedded PE payload from its resources to disk, enumerates running processes to locate Internet Explorer (`iexplore.exe`) as an injection target, performs classic DLL injection via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, and establishes persistence through a `Run` registry key invoking `rundll32.exe`. The sample also reads proxy configuration from the registry, likely for C2 communication setup. Multiple YARA rules matched, including `Emissary_APT_Malware_1` with 8 distinct strings, and CAPA identified thread injection, obfuscated stack strings, and Base64 encoding. The verdict is **malicious** with high confidence (98%). (source: deep-dive.json, triage verdict.json)

## 1. Sample Identification

| Field | Value |
|---|---|
| SHA256 | `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76` |
| File Path | `/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll` |
| File Type | PE32 DLL (x86) |
| Architecture | x86 (32-bit) |
| Entropy | 6.35 bits/byte (whole-file Shannon entropy) |
| Imphash | `aee2f8f6aa200110e796682791bc8758` |
| Packed | No (UPX probe returned 0 files tested; not packed) |
| .NET | Not a .NET assembly |
| Export | `Setting` (invoked via `rundll32.exe "%s",Setting`) |
| Compiler | Visual C++ 2008 (MSVC_2008_linker, MSVC_2008_rich YARA matches) |
| VersionInfo | Claims "Loader Dynamic Link Library", Copyright (C) 2015 -- irrelevant metadata (source: deep-dive.json) |

The file is a standard PE32 DLL with a single exported function named `Setting`. The en
… [19573 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:48:05 UTC

# RE Report — bf0d6cc20fa7
_Generated 2026-08-13T09:48:05.328005+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=240c | cross_refs=True | llm_ok=True | runtime=67.45s -->

# Executive Summary

This section presents a top-line verdict for the malware sample with SHA256 `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`, summarizing its malicious nature, family association, confidence level, and key evidence.

| Aspect       | Value                | Source (Citation) |
|--------------|----------------------|--------------------|
| Verdict      | Malicious            | (source: cross-section:classification, row_or_rule: verdict assessment) |
| Family       | Likely Lotus Blossom | (source: deep_dive_agentic, row_or_rule: family guess) |
| Confidence   | 98%                  | (source: deep_dive_agentic, row_or_rule: confidence score) |
| Agreement    | LLM and V1 agree     | (source: cross-section:classification, row_or_rule: agreement) |

We assess the sample as **malicious** with high confidence, supported by 26 YARA rule matches that identify malicious signatures and 30 CAPA rules mapping to capabilities like persistence and evasion, which are typical in malware (source: yara, row_or_rule: 26 matches; capa, row_or_rule: 30 rules). The family guess of Lotus Blossom is likely, based on cross-engine analysis and historical data from sources like VirusTotal, though further correlation is recommended for certainty (source: cross-section:background_and_family_lineage, evidence: VirusTotal detections). Dynamic analysis tools such as Speakeasy and Frida were executed during behavioral assessment, contributing to the overall evaluation, but static analysis provided the primary evidence for this summary (source: cross-section:behavioral_analysis, evidence: dynamic tool execution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=71.43s -->

## 1. Sample Identification

This section outlines the fundamental identifiers for the malware sample, providing a basis for further analysis. The evidence is derived from static analysis, and each identifier is explained to ensure clarity for
… [45129 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6417` | `8e3500dcc48b7214` |
| `prompt.txt` | `True` | `33514` | `9e5ebb85c9aabce6` |
| `pipeline-audit.json` | `True` | `120770` | `5e112fb55f1d8865` |
| `AUDIT-REPORT.md` | `True` | `89681` | `98d15908d91c001d` |
| `REPORT-MASTER-v2.md` | `True` | `22080` | `42c579d9aed7eb06` |
| `REPORT-MASTER-v3.md` | `True` | `47646` | `3dc124e07e737ba1` |
| `REPORT-v2.md` | `True` | `22080` | `42c579d9aed7eb06` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `56451` | `e310fb6d864571c3` |
| `rule.yar` | `True` | `1330` | `8e55b8a981e0999d` |
| `intake-validation.json` | `True` | `2637` | `534c224a97976875` |
| `source-decisions.json` | `True` | `1794` | `b41b7aade1f2143f` |
| `malcat-triage.json` | `True` | `36732` | `a0399a135b1d9008` |
| `deep_dive/01-tools-raw.json` | `True` | `119947` | `833fc1a37c7449cc` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4835` | `c08e509c8307b3aa` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `109948` | `68aadea749ec9466` |

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

- **intake_validation:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/intake-validation.json` exists=`True` bytes=`2637` mtime=`2026-08-12T19:16:58.388908+00:00`
  - sha256: `534c224a97976875bbd4deca77b93d46c5ea74b27351daff322715304b1f58fa`
- **malcat_triage:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/malcat-triage.json` exists=`True` bytes=`36732` mtime=`2026-08-13T05:04:15.257143+00:00`
  - sha256: `a0399a135b1d9008f684969591e17a75eacb5ef96233147e79ba48848d1079d2`
- **source_decisions:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/source-decisions.json` exists=`True` bytes=`1794` mtime=`2026-08-12T19:16:58.389909+00:00`
  - sha256: `b41b7aade1f2143f614a58cae63f465efff67143a8aa442371f7182ad1084bef`
- **ghidra_import_log:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/intake-analyzeHeadless.log` exists=`True` bytes=`8380` mtime=`2026-08-12T19:15:44.497000+00:00`
  - sha256: `9de0cf612cacbd1bda6219bb90252e2d931f7f4c3643736d847fed9a4293aee5`
- **ida_bootstrap_log:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/intake-idasql.log` exists=`True` bytes=`213` mtime=`2026-08-12T19:15:47.529001+00:00`
  - sha256: `e87d917d2c81c5a0629fece1c549ce27260ba8f4cce7a8b73838d46f4eb719fd`

#### source_decisions_excerpt

```
{
  "sha256": "bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "From tool summaries, ghidra and ida both report 88 imports, while malcat reports 113; agreement between disassemblers indicates reliability. Evidence: {ghidra, imports, 88} and {ida, imports, 88}."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra and ida both identify 74 functions, whereas malcat only has 10; consistency between disassemblers suggests high accuracy. Evidence: {ghidra, funcs, 74} and {ida, funcs, 74}."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Using both engines covers more strings: ghidra has 178, ida has 253, malcat has 100; thi
… [1017 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
    "file_name": "ishelp.dll",
    "file_path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
    "file_size": 78848,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.35,
    "sha256": "bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76",
    "metadata": {
      "VersionInfo::FileDescription": "Loader Dynamic Link Library",
      "VersionInfo::FileVersion":
… [35932 more chars]
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
  "rule_count": 30,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Indicator Removal from Tools",
          "id": "T1027.005"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Argument Obfuscation"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Argument Obfuscation",
          "id": "B0032.020"
        },
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Stack Strings"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Stack Strings",
          "id": "B0032.017"
        }
      ]
    },
    {
      "name": "reference Base64 string",
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
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        },
        {
          "parts": [
            "Data",
            "Check String"
          ],
          "objective": "Data",
          "behavior": "Check String",
          "method": "",
          "id": "C0019"
        }
      ]
    },
    {
      "name": "get common file path",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "get file size",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "inject thread",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Process Injection",
            "Thread Execution Hijacking"
          ],
          "tactic": "Def
… [5140 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 60279,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 16611,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": []
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$a0",
          "offset": 16899,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$a4",
          "offset": 61976,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA512_Constants",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$c1",
          "offset": 58812,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 58820,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 58828,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 58836,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "BASE64_table",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$c0",
          "offset": 58736,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Emissary_APT_Malware_1",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$s1",
          "offset": 61976,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$s2",
          "offset": 61996,
          "length": 20,
          "xor_key": null
        },
        {
          "id": "$s3",
          "offset": 17696,
          "length": 25,
          "xor_key": null
        },
        {
          "id": "$s4",
          "offset": 61864,
          "length": 28,
          "xor_key": null
        },
        {
          "id": "$s5",
          "offset": 60320,
    
… [10592 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 619,
  "strings_sampled": 80,
  "strings": [
    "\\Internet Explorer\\iexplore.exe",
    "000A758C8FEAE5F.TMP",
    "-3$1-$3",
    "7/+.1$1",
    "($7/+.1$",
    "!This program cannot be run in DOS mode.",
    "3 !23;",
    "!23Rich",
    "`.rdata",
    "@.data",
    "@.reloc",
    "Qj&hTs",
    "0SSSSS",
    "0WWWWW",
    "AAFFf;",
    "URPQQh",
    "v\tN+D$",
    "YSSSSS",
    "HHtXHHt",
    ">If90t",
    "UQPXY]Y[",
    "Invalid parameter passed to C runtime function.",
    "(null)",
    "```hhh",
    "xppwpp",
    "%d/%02d/%02d %02d:%02d:%02d -",
    "ReleaseFile Error->FindResource Failed[%d].",
    "ReleaseFile Error->Size=0.",
    "Kernel32.dll",
    "ReleaseFile Error->LoadLibrary Failed[%d].",
    "LoadResource",
    "ReleaseFile->GetProcAddress Failed[%d].",
    "ReleaseFile->ProLdRsc Failed.",
    "ReleaseFile->CreateFile Failed[%d].",
    "Removing...",
    "\\LocalData\\",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SystemDrive",
    "SeDebugPrivilege",
    "FreeLibrary",
    "kernel32.dll",
    "A08E81B411.DAT",
    "Windows Internet Explorer",
    "LoadLibraryA",
    "ishelp.dll",
    "IE Process is running.",
    "ReF(D)F.",
    "_MICROSOFT_LOADER_MUTEX_",
    "create snapshot failed: 0x%x.",
    "process32first failed: 0x%x.",
    "TID list head is NULL.",
    "create tid snapshot failed: 0x%x.",
    "thread32first failed: 0x%x.",
    "ZwMapViewOfSection",
    "XXXX.dat",
    "insert.",
    "get pid failed.",
    "error pid.",
    "create tid list failed.",
    "get tid list failed.",
    "open process failed: 0x%x.",
    "75BD50EC.DAT",
    "*SLAR_GFD Error:%d.",
    "rundll32.exe \"%s\",Setting",
    "*SLAR_RO Error:%d.",
    "*SLAR_RS Error:%d.",
    "S-1-5-21",
    "Classes",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    "ProxyEnable",
    "ProxyServer",
    "_errno",
    "??2@YAPAXI@Z",
    "??3@YAXPAX@Z",
    "malloc",
    "msvcrt.dll",
    "memset",
    "memcpy",
    "_XcptFilter",
    "_initterm"
  ],
  "per_category": {
    "decoded_strings": 2,
    "stack_strings": 3,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 614
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 11.29,
  "size_bytes": 78848,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
    "file_name": "ishelp.dll",
    "file_path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
    "file_size": 78848,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.35,
    "sha256": "bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76",
    "metadata": {
      "VersionInfo::FileDescription": "Loader Dynamic Link Library",
      "VersionInfo::FileVersion": "1, 0, 0, 1",
      "VersionInfo::InternalName": "Loader",
      "VersionInfo::LegalCopyright": "Copyright (C) 2015",
      "VersionInfo::OriginalFilename": "Loader.dll",
      "VersionInfo::ProductName": "Loader Dynamic Link Library",
      "VersionInfo::ProductVersion": "1, 0, 0, 1",
      "Exports::Module name": "Loader.dll",
      "Exports::Exports date": "2015-11-07 00:22:24"
    },
    "entrypoint_ea": 10359,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 51
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 14848,
        "virtual_size": 16384,
        "rights": "RX",
        "entropy": 126
      },
      {
        "name": ".rdata",
        "effective_address": 17408,
        "physical_size": 4608,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 88
      },
      {
        "name": ".data",
        "effective_address": 25600,
        "physical_size": 2048,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 100
      },
      {
        "name": ".rsrc",
        "effective_address": 29696,
        "physical_size": 54272,
        "virtual_size": 57344,
        "rights": "R",
        "entropy": 125
      },
      {
        "name": ".reloc",
        "effective_address": 87040,
        "physical_size": 2048,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 90
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 121,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "BigStringHiScore",
        "desc": "string has more than 256 characters and high interest score",
        "category": "strings",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynamically",
        "category": "strings",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "EmbeddedProgram",
        "desc": "File embeds a program",
        "category": "embedding",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "HugeStringBinary",
        "desc": "string has more than 1024 characters and binary encoding",
        "category": "strings",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "InvalidChecksum",
        "desc": "PE Header checksum is wrong",
        "category": "integrity",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "ManyUniqueImmediateBytes",
        "desc": "More than 48 
… [64537 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "kernel32.CreateRemoteThread Top high-signal imports API for creating remote threads in other processes, a key technique ",
    "T1055.003 ATT&CK Rule for Thread Execution Hijacking, indicating process injection for defense evasion, a clear maliciou",
    "FUN_100019a0 Anti Analysis Signals Function enumerates processes using CreateToolhelp32Snapshot, used for discovery and ",
    "inject_thread matches YARA rule match for thread injection, confirming malicious injection capabilities from behavioral ",
    "EmbeddedProgram Anomalies Anomaly indicates an embedded program, suggesting dropper or payload delivery functionality fo"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Lotus Blossom",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "kernel32.CreateRemoteThread",
      "why": "API for creating remote threads in other processes, a key technique for process injection and malicious code execution."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1055.003",
      "why": "Rule for Thread Execution Hijacking, indicating process injection for defense evasion, a clear malicious behavior."
    },
    {
      "source": "ghidra",
      "query_or_table": "Anti Analysis Signals",
      "row_or_rule": "FUN_100019a0",
      "why": "Function enumerates processes using CreateToolhelp32Snapshot, used for discovery and targeting in malicious activities."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "inject_thread",
      "why": "YARA rule match for thread injection, confirming malicious injection capabilities from behavioral patterns."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "EmbeddedProgram",
      "why": "Anomaly indicates an embedded program, suggesting dropper or payload delivery functionality for malware distribution."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "why": "Registry key for autostart persistence, commonly modified by malware to ensure survival across reboots."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "cmd.exe /c %s > %s",
      "why": "String for command execution and output redirection, indicating potential command-and-control or payload execution."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "change_memory_protection",
      "why": "VirtualProtect API used to alter memory permissions, enabling executable code in non-executable regions for injection."
    }
  ],
  "summary": "The DLL 'ishelp.dll' exhibits malicious behavior including process injection via CreateRemoteThread, registry-based persistence, privilege escalation, and an embedded payload. It uses anti-analysis techniques and matches known malware patterns, with strong consensus from multiple analysis engines and external threat intelligence."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/prompt.txt` exists=`True` bytes=`33514` mtime=`2026-08-13T09:27:06.674001+00:00`
  - sha256: `9e5ebb85c9aabce6d61725494d8bc775859c0840a4093987612d9f1cbaf6594b`
- **verdict:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/verdict.json` exists=`True` bytes=`6417` mtime=`2026-08-13T09:29:10.630171+00:00`
  - sha256: `8e3500dcc48b72147f5e7fbcaeb0afd4d7f9341f875768cf82d0045dfc16cbee`

#### prompt_excerpt

```
# Triage evidence
sha256: bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76
sample_path: /opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll
ghidra_session: ghidra-pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76
ida_session: ida-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — From tool summaries, ghidra and ida both report 88 imports, while malcat reports 113; agreement between disassemblers indicates reliability. Evidence: {ghidra, imports, 88} and {ida, imports, 88}.
- functions: ghidra (confidence=high) — Ghidra and ida both identify 74 functions, whereas malcat only has 10; consistency between disassemblers suggests high accuracy. Evidence: {ghidra, funcs, 74} and {ida, funcs, 74}.
- strings: both (confidence=high) — Using both engines covers more strings: ghidra has 178, ida has 253, malcat has 1
… [32461 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "Lotus Blossom",
  "cross_engine_notes": "Ghidra and IDA agree on 74 functions and 88 imports, indicating reliable disassembly. MalCat identifies 11 anomalies including EmbeddedProgram and high-signal imports like CreateRemoteThread. Capa and YARA rules detect process injection, privilege escalation, and persistence behaviors. External VirusTotal shows 49 malicious detections with threat names like 'lotusblossom' and 'explorerhijack'.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "kernel32.CreateRemoteThread",
      "why": "API for creating remote threads in other processes, a key technique for process injection and malicious code execution."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1055.003",
      "why": "Rule for Thread Execution Hijacking, indicating process injection for defense evasion, a 
… [5417 more chars]
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
  "rule_count": 30,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Indicator Removal from Tools",
          "id": "T1027.005"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Argument Obfuscation"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Argument Obfuscation",
          "id": "B0032.020"
        },
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Stack Strings"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Stack Strings",
          "id": "B0032.017"
        }
      ]
    },
    {
      "name": "reference Base64 string",
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
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        },
        {
          "parts": [
            "Data",
            "Check String"
          ],
          "objective": "Data",
          "behavior": "Check String",
          "method": "",
          "id": "C0019"
        }
      ]
    },
    {
      "name": "get common file path",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "get file size",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "objective": "Discovery",
          "behavior": "File and Directory Discovery",
          "method": "",
          "id": "E1083"
        }
      ]
    },
    {
      "name": "inject thread",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Process Injection",
            "Thread Execution Hijacking"
          ],
          "tactic": "Def
… [5139 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 78848,
  "duration_s": 0.03,
  "import_count": 88,
  "signal_count": 7,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "create_remote_thread",
      "api_match": "CreateRemoteThread",
      "attack": [
        "T1055"
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
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 60279,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 16611,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": []
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$a0",
          "offset": 16899,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$a4",
          "offset": 61976,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA512_Constants",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$c1",
          "offset": 58812,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 58820,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 58828,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 58836,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "BASE64_table",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$c0",
          "offset": 58736,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Emissary_APT_Malware_1",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
      "strings": [
        {
          "id": "$s1",
          "offset": 61976,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$s2",
          "offset": 61996,
          "length": 20,
          "xor_key": null
        },
        {
          "id": "$s3",
          "offset": 17696,
          "length": 25,
          "xor_key": null
        },
        {
          "id": "$s4",
          "offset": 61864,
          "length": 28,
          "xor_key": null
        },
        {
          "id": "$s5",
          "offset": 60320,
    
… [10570 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 619,
  "strings_sampled": 80,
  "strings": [
    "\\Internet Explorer\\iexplore.exe",
    "000A758C8FEAE5F.TMP",
    "-3$1-$3",
    "7/+.1$1",
    "($7/+.1$",
    "!This program cannot be run in DOS mode.",
    "3 !23;",
    "!23Rich",
    "`.rdata",
    "@.data",
    "@.reloc",
    "Qj&hTs",
    "0SSSSS",
    "0WWWWW",
    "AAFFf;",
    "URPQQh",
    "v\tN+D$",
    "YSSSSS",
    "HHtXHHt",
    ">If90t",
    "UQPXY]Y[",
    "Invalid parameter passed to C runtime function.",
    "(null)",
    "```hhh",
    "xppwpp",
    "%d/%02d/%02d %02d:%02d:%02d -",
    "ReleaseFile Error->FindResource Failed[%d].",
    "ReleaseFile Error->Size=0.",
    "Kernel32.dll",
    "ReleaseFile Error->LoadLibrary Failed[%d].",
    "LoadResource",
    "ReleaseFile->GetProcAddress Failed[%d].",
    "ReleaseFile->ProLdRsc Failed.",
    "ReleaseFile->CreateFile Failed[%d].",
    "Removing...",
    "\\LocalData\\",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SystemDrive",
    "SeDebugPrivilege",
    "FreeLibrary",
    "kernel32.dll",
    "A08E81B411.DAT",
    "Windows Internet Explorer",
    "LoadLibraryA",
    "ishelp.dll",
    "IE Process is running.",
    "ReF(D)F.",
    "_MICROSOFT_LOADER_MUTEX_",
    "create snapshot failed: 0x%x.",
    "process32first failed: 0x%x.",
    "TID list head is NULL.",
    "create tid snapshot failed: 0x%x.",
    "thread32first failed: 0x%x.",
    "ZwMapViewOfSection",
    "XXXX.dat",
    "insert.",
    "get pid failed.",
    "error pid.",
    "create tid list failed.",
    "get tid list failed.",
    "open process failed: 0x%x.",
    "75BD50EC.DAT",
    "*SLAR_GFD Error:%d.",
    "rundll32.exe \"%s\",Setting",
    "*SLAR_RO Error:%d.",
    "*SLAR_RS Error:%d.",
    "S-1-5-21",
    "Classes",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
    "ProxyEnable",
    "ProxyServer",
    "_errno",
    "??2@YAPAXI@Z",
    "??3@YAXPAX@Z",
    "malloc",
    "msvcrt.dll",
    "memset",
    "memcpy",
    "_XcptFilter",
    "_initterm"
  ],
  "per_category": {
    "decoded_strings": 2,
    "stack_strings": 3,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 614
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 8.4,
  "size_bytes": 78848,
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
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
  "disassembly": {
    "0x10003477": "\u250c 400: entry0 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);\n\u2502       \u254e   ; arg int32_t arg_8h @ ebp+0x8\n\u2502       \u254e   ; arg int32_t arg_ch @ ebp+0xc\n\u2502       \u254e   ; arg int32_t arg_10h @ ebp+0x10\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   0x10003477      8bff           mov edi, edi\n\u2502       \u254e   0x10003479      55             push ebp\n\u2502       \u254e   0x1000347a      8bec           mov ebp, esp\n\u2502       \u254e   0x1000347c      837d0c01       cmp dword [arg_ch], 1\n\u2502      \u250c\u2500\u2500< 0x10003480      7505           jne 0x10003487\n\u2502      \u2502\u254e   0x10003482      e82b110000     call 0x100045b2\n\u2502      \u2514\u2500\u2500> 0x10003487      5d             pop ebp\n\u2502       \u2514\u2500< 0x10003488      e98efdffff     jmp 0x1000321b\n..\n            ; XREFS: CALL 0x10002328  CALL 0x10002345  CALL 0x1000235f  \n            ; XREFS: CALL 0x1000237c  CALL 0x10002399  CALL 0x100023b8  \n            ; XREFS: CALL 0x100023d5  CALL 0x100025d2  ",
    "0x10002660": "\u250c 10: sym.Loader.dll_Setting ();\n\u2502           0x10002660      55             push ebp\n\u2502           0x10002661      8bec           mov ebp, esp\n\u2502           0x10002663      e898fcffff     call fcn.10002300\n\u2502           0x10002668      5d             pop ebp\n\u2514           0x10002669      c3             ret",
    "0x10002300": "; CALL XREF from sym.Loader.dll_Setting @ 0x10002663(x)\n\u250c 852: fcn.10002300 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_20eh @ ebp-0x20e\n\u2502           ; var int32_t var_210h @ ebp-0x210\n\u2502           ; var int32_t var_317h @ ebp-0x317\n\u2502           ; var int32_t var_318h @ ebp-0x318\n\u2502           ; var int32_t var_31ch @ ebp-0x31c\n\u2502           ; var int32_t var_427h @ ebp-0x427\n\u2502           ; var int32_t var_428h @ ebp-0x428\n\u2502           ; var int32_t var_52fh @ ebp-0x52f\n\u2502           ; var int32_t var_530h @ ebp-0x530\n\u2502           ; var int32_t var_637h @ ebp-0x637\n\u2502           ; var int32_t var_638h @ ebp-0x638\n\u2502           ; var int32_t var_72eh @ ebp-0x72e\n\u2502           ; var int32_t var_730h @ ebp-0x730\n\u2502           ; var int32_t var_734h @ ebp-0x734\n\u2502           ; var int32_t var_738h @ ebp-0x738\n\u2502           ; var int32_t var_73ch @ ebp-0x73c\n\u2502           ; var int32_t var_73fh @ ebp-0x73f\n\u2502           ; var int32_t var_740h @ ebp-0x740\n\u2502           ; var int32_t var_773h @ ebp-0x773\n\u2502           ; var int32_t var_774h @ ebp-0x774\n\u2502           ; var int32_t var_7fch @ ebp-0x7fc\n\u2502           ; var int32_t var_800h @ ebp-0x800\n\u2502           ; var int32_t var_810h @ ebp-0x810\n\u2502           ; var int32_t var_814h @ ebp-0x814\n\u2502           0x10002300      55             push ebp\n\u2502           0x10002301      8bec           mov ebp, esp\n\u2502           0x10002303      81ec14080000   sub esp, 0x814\n\u2502           0x10002309      a100700010     mov eax, dword [section..data] ; [0x10007000:4]=0xbb40e64e ; \"N\\xe6@\\xbb\\xb1\\x19\\xbfD\"\n\u2502           0x1000230e      33c5           xor eax, ebp\n\u2502           0x10002
… [1650 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
  "candidates": [
    "Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00005908: 00000110 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r\nFound XOR 00 position 00005908: 00000110 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
    "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
    "exists": true,
    "hook_candidates": [
      "msvcrt.dll!__badioinfo",
      "msvcrt.dll!wctomb",
      "msvcrt.dll!_itoa",
      "msvcrt.dll!_snprintf",
      "msvcrt.dll!_iob",
      "KERNEL32.dll!GetProcAddress",
      "KERNEL32.dll!GetSystemTimeAsFileTime",
      "KERNEL32.dll!GetCurrentProcessId",
      "KERNEL32.dll!GetCurrentThreadId",
      "KERNEL32.dll!GetTickCount",
      "ADVAPI32.dll!OpenProcessToken",
      "ADVAPI32.dll!RegCloseKey",
      "ADVAPI32.dll!AdjustTokenPrivileges",
      "ADVAPI32.dll!LookupPrivilegeValueA",
      "ADVAPI32.dll!RegOpenKeyExA",
      "SHELL32.dll!SHGetSpecialFolderPathA",
      "ole32.dll!CoCreateGuid",
      "RPCRT4.dll!RpcStringFreeA",
      "RPCRT4.dll!UuidToStringA"
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
  "checked": 12,
  "hits": 12,
  "misses": [],
  "hit_examples": [
    "YARA rule 'Emissary_APT_Malware_1' matched with 8 strings at offsets 61976, 61996, 17696, 61864, 60320, 61412, 70960, 61",
    "Imports: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtectEx, OpenProcess (classic DLL injection ch",
    "Imports: AdjustTokenPrivileges, LookupPrivilegeValueA, OpenProcessToken (privilege escalation)",
    "String refs in FUN_10002300: 'IE Process is running.' and '_MICROSOFT_LOADER_MUTEX_' (IE injection targeting + mutex)",
    "String refs in FUN_100019a0: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'A08E81B411.DAT', 'SeDebugPrivilege', '\\Lo"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 98,
  "summary": "This is a DLL dropper/loader component of the Emissary APT malware family. YARA rule 'Emissary_APT_Malware_1' matched with 8 distinct strings. The DLL exports a 'Setting' function designed to be invoked via rundll32.exe. Its behavioral chain: (1) creates mutex '_MICROSOFT_LOADER_MUTEX_' for single-i",
  "key_evidence": [
    "YARA rule 'Emissary_APT_Malware_1' matched with 8 strings at offsets 61976, 61996, 17696, 61864, 60320, 61412, 70960, 61896",
    "Imports: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtectEx, OpenProcess (classic DLL injection chain)",
    "Imports: AdjustTokenPrivileges, LookupPrivilegeValueA, OpenProcessToken (privilege escalation)",
    "String refs in FUN_10002300: 'IE Process is running.' and '_MICROSOFT_LOADER_MUTEX_' (IE injection targeting + mutex)",
    "String refs in FUN_100019a0: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'A08E81B411.DAT', 'SeDebugPrivilege', '\\LocalData\\' (persistence + payload drop + priv esc)",
    "Export 'Setting' with string 'rundll32.exe \"%s\",Setting' (autorun persistence via rundll32)",
    "Strings: 'ProxyEnable', 'ProxyServer', 'Internet Settings' registry path (proxy credential theft)",
    "FUN_10001820 references 'ReleaseFile Error->FindResource Failed', 'LoadLibrary Failed', 'GetProcAddress Failed', 'CreateFile Failed' (resource-based dropper with debug strings)",
    "CAPA: obfuscated stackstrings (T1027.005), Base64 encoding (T1027), file/directory discovery (T1083)",
    "FUN_10003853: size=2771, cyclomatic_complexity=151, 240 basic blocks (heavily obfuscated main payload logic)",
    "Imports: CreateToolhelp32Snapshot, Process32First, Process32Next, Module32First, Module32Next (process/module enumeration for injection target)",
    "SHA512 constants and BASE64 alphabet table detected at offsets 58812-58836 and 58736 (crypto encoding infrastructure)"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
… [13670 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
    "file_name": "ishelp.dll",
    "file_path": 
… [67480 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 30,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": 
… [8239 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 78848,
  "duration_s": 0.03,
  "import_count": 88,
  "signal_count": 7,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
    {
 
… [697 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 619,
  "strings_sampled": 80,
  "strings": [
    "\\Internet Explorer\\iexplore.exe",
    "000A758C8FEAE5F.TMP",
    "-3$1-$3",
    "7/+.1$1",
    "($7/+.1$",
    "!This program cannot be run in DOS mode.",
    "3 !23;",
    "!23Rich",
    "`.rdata",
    "@.data",
    "@.reloc",
    "Qj&hTs",
    "0SSSSS",
    "0WWWWW",
    "AAFFf;",
    "URPQQh",
    "v\tN+
… [2023 more chars]
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
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
  "disassembly": {
    "0x10003477": "\u250c 400: entry0 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);\n\u2502       \u254e   ; arg int32_t arg_8h @ ebp+0x8\n\u2502       \u254e   ; arg int32_t arg_ch @ ebp+0xc\n\u2502       \u254e   ; arg int32_t arg_10h @
… [4750 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
  "candidates": [
    "Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00005908: 00000110 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 0000
… [184 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
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
    "path": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
    "exists": true,
    "hook_candidates": [
      "msvcrt.dll!__badioinfo",
      "msvcrt.dll!wctomb",
      "msvcrt.dll!_itoa",
      "msvcrt.dll!_snprintf",
      "msvcrt.dll!_iob",
      "KERNEL32.dll!G
… [533 more chars]
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": true,
  "sample": "/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 14848,
      "entropy": 6.2174,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 4608,
      "entropy": 5.3481,
      "executable": fal
… [1240 more chars]
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
  "sink_count": 12,
  "sinks": [
    {
      "api": "memcpy",
      "dll": "msvcrt.dll",
      "class": "unbounded_copy",
      "address": "0x1000360c",
      "function": "sub.msvcrt.dll_memcpy"
    },
    {
      "api": "malloc",
      "dll": "msvcrt.dll",
      "class": "integer_overflow_size",
      "address": "0x10003077",
      "function": ""
   
… [1684 more chars]
```

- **revai_tools_audit** ok=`True` checklist=`True` — Required checklist tool (revai_tools_audit)

```json
{
  "format": "pe",
  "findings": [
    {
      "api": "createprocessa",
      "class": "command_execution",
      "address": "0x10001feb",
      "function": "fcn.10001e80",
      "patterns": [
        "concat_built"
      ],
      "provenance": {
        "arg1": "0x104                  ; 260",
        "arg2": "ecx <- lea [var_110h]"
      }
    }
  ],
  "engine": "revai_tools_audit",
  "source": 
… [15 more chars]
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {
      "process_scan": 4
    },
    "total_signals": 4,
    "functions_with_signals": 1,
    "elapsed_s": 0.84,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls"
… [130 more chars]
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
      "name": "FUN_10003853",
      "address": "268449875",
      "size": "2771"
    },
    {
      "name": "FUN_100019a0",
      "address": "268442016",
      "size": "1243"
    },
    {
      "name": "FUN_10002300",
      "address": "268444416",
      "size": "852"
    },
    {
      "name": "FUN_10001e80",
      "addr
… [2316 more chars]
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
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "LookupPrivilegeValueA",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "OpenProcessToken",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "Reg
… [6512 more chars]
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
      "name": "FUN_10003853",
      "address": "268449875",
      "size": "2771"
    },
    {
      "name": "FUN_100019a0",
      "address": "268442016",
      "size": "1243"
    },
    {
      "name": "FUN_10002300",
      "address": "268444416",
      "size": "852"
    },
    {
      "name": "FUN_10001e80",
      "addr
… [2772 more chars]
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
      "content": "%d/%02d/%02d %02d:%02d:%02d - ",
      "address": "268456552",
      "length": "64"
    },
    {
      "content": "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
      "address": "268457912",
      "length": "60"
    },
    {
      "content": "Loader Dynamic Link Library",
      
… [4478 more chars]
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
      "name": "_write",
      "module": "MSVCRT.DLL"
    },
    {
      "name": "GetCurrentProcessId",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetCurrentThreadId",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "TerminateProcess",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetExitCodeThre
… [1486 more chars]
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
    "call_in_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_100010f0",
      "address": "268439792",
      "size": "740",
      "instruction_count": "203",
      "block_count": "46",
      "cyclomatic_complexity": "28",
   
… [1521 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "content",
    "str_addr"
  ],
  "rows": [
    {
      "func_name": "",
      "func_addr": "",
      "content": "Invalid parameter passed to C runtime function.\n",
      "str_addr": "268456336"
    },
    {
      "func_name": "FUN_10001820",
      "func_addr": "268441632",
      "content": "ReleaseFile Error->FindResource Failed[%d].",
      
… [1831 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "content",
    "str_addr"
  ],
  "rows": [
    {
      "func_name": "FUN_10001820",
      "func_addr": "268441632",
      "content": "asdasdasdasdsad",
      "str_addr": "268456624"
    },
    {
      "func_name": "FUN_10002300",
      "func_addr": "268444416",
      "content": "IE Process is running.",
      "str_addr": "268457300"
    },
   
… [456 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 30,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": 
… [8238 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "sub_1000292A",
      "func_addr": "268445994",
      "string_value": "Invalid parameter passed to C runtime function.\n"
    },
    {
      "func_name": "sub_10001820",
      "func_addr": "268441632",
      "string_value": "asdasdasdasdsad"
    },
    {
      "func_name": "sub_10001820"
… [1512 more chars]
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
      "content": "ReleaseFile->GetProcAddress Failed[%d].",
      "address": "268456804",
      "length": "40"
    },
    {
      "content": "get pid failed.",
      "address": "268457580",
      "length": "16"
    },
    {
      "content": "get tid list failed.",
      "address": "268457632",
      "length": "24"
 
… [1918 more chars]
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
      "content": "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
      "address": "268457912"
    },
    {
      "content": "ProxyEnable",
      "address": "268457972"
    },
    {
      "content": "ProxyServer",
      "address": "268457984"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,
  "truncated": fa
… [241 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76",
  "audit_path": "/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/audit.jsonl"
}
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
      "name": "FUN_10001000",
      "address": "268439552",
      "module": "Global"
    },
    {
      "name": "FUN_10001070",
      "address": "268439664",
      "module": "Global"
    },
    {
      "name": "FUN_100010a0",
      "address": "268439712",
      "module": "Global"
    },
    {
      "name": "FUN_100010f
… [1933 more chars]
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
      "content": "Kernel32.dll",
      "address": "268456728",
      "length": "13"
    },
    {
      "content": "kernel32.dll",
      "address": "268457028",
      "length": "13"
    },
    {
      "content": "kernel32.dll",
      "address": "268457200",
      "length": "13"
    },
    {
      "content": "ishelp.d
… [1245 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "content"
  ],
  "rows": [
    {
      "func_name": "FUN_100019a0",
      "func_addr": "268442016",
      "content": "Removing..."
    },
    {
      "func_name": "FUN_100019a0",
      "func_addr": "268442016",
      "content": "\\LocalData\\"
    },
    {
      "func_name": "FUN_100019a0",
      "func_addr": "268442016",
      "content": "Sof
… [1644 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_addr"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "content"
  ],
  "rows": [
    {
      "func_name": "FUN_10002300",
      "func_addr": "268444416",
      "content": "IE Process is running."
    },
    {
      "func_name": "FUN_10002300",
      "func_addr": "268444416",
      "content": "ReF(D)F."
    },
    {
      "func_name": "FUN_10002300",
      "func_addr": "268444416",
      "content"
… [340 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "content"
  ],
  "rows": [
    {
      "func_name": "FUN_10001e80",
      "func_addr": "268443264",
      "content": "kernel32.dll"
    },
    {
      "func_name": "FUN_10001e80",
      "func_addr": "268443264",
      "content": "LoadLibraryA"
    },
    {
      "func_name": "FUN_100026a0",
      "func_addr": "268445344",
      "content": "%d/
… [762 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/deep_dive/01-tools-raw.json` exists=`True` bytes=`119947` mtime=`2026-08-13T05:04:15.263143+00:00`
  - sha256: `833fc1a37c7449cc951e3831e14cc0ec059d907382bbd8c30ebb6e2f6ae5bca1`
- **sql_evidence:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/deep_dive/05-deep-dive.json` exists=`True` bytes=`4835` mtime=`2026-08-12T19:20:56.544092+00:00`
  - sha256: `c08e509c8307b3aa675514dd249a5a901bd5ef0950bce97a3a36579f2a0ed980`

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
  "confidence": 98,
  "summary": "This is a DLL dropper/loader component of the Emissary APT malware family. YARA rule 'Emissary_APT_Malware_1' matched with 8 distinct strings. The DLL exports a 'Setting' function designed to be invoked via rundll32.exe. Its behavioral chain: (1) creates mutex '_MICROSOFT_LOADER_MUTEX_' for single-instance enforcement, (2) enables SeDebugPrivilege via AdjustTokenPrivileges for elevated process access, (3) extracts an embedded payload from PE resources to disk as 'A08E81B411.DAT' in a \\LocalData\\ directory (FindResourceW/LockResource/CreateFileA), (4) enumerates running processes using CreateToolhelp32Snapshot to locate IE (iexplore.exe) as injection target, (5) performs
… [4035 more chars]
```

- **agentic:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`411882` mtime=`2026-08-12T19:20:56.543092+00:00`
  - sha256: `39ba058a35eab987120dd2785df9743e7b6c42bc628e2654c12fd8664593d1c0`

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

- **rule_yar:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/rule.yar` exists=`True` bytes=`1330` mtime=`2026-08-12T19:20:59.426380+00:00`
  - sha256: `8e55b8a981e0999da9280dfb42bd41003434427f5e301c75e952dd6344581e89`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T19:20:59.426679+00:00
import "pe"
rule CADRE_v2_trojan_lotusblossom_explorerhijack_bf0d6cc20fa7 {
    meta:
        description = "RevAI v2 auto rule for trojan.lotusblossom/explorerhijack"
        sha256 = "bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76"
        family = "trojan_lotusblossom_explorerhijack"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "\\Internet Explorer\\iexplore.exe" ascii wide
        $s1 = "000A758C8FEAE5F.TMP" ascii wide
        $s2 = "($7/+.1$" ascii wide
        $s3 = "!This program cannot be run in DOS mode." ascii wide
        $s4 = "UQPXY]Y[" ascii wide
        $s5 = "Invalid parameter pa
… [528 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/REPORT-MASTER-v2.md` exists=`True` bytes=`22080` mtime=`2026-08-13T09:32:35.752402+00:00`
  - sha256: `42c579d9aed7eb061802e7f36e706748d59498d63ece4f9e68f59abb99d34666`
- **REPORT_MASTER_v3:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/REPORT-MASTER-v3.md` exists=`True` bytes=`47646` mtime=`2026-08-13T09:48:05.331274+00:00`
  - sha256: `3dc124e07e737ba11e6b86e9c940941c9b4b4637ac1e28abbba8a24e3cf7667a`
- **REPORT_v2:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/REPORT-v2.md` exists=`True` bytes=`22080` mtime=`2026-08-13T09:32:35.751401+00:00`
  - sha256: `42c579d9aed7eb061802e7f36e706748d59498d63ece4f9e68f59abb99d34666`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`73303` mtime=`2026-08-13T09:37:45.400313+00:00`
  - sha256: `a89fb62eeeba351f9de8b4f376d8c2a870d421c424c575b516d093945eb78a86`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`56451` mtime=`2026-08-13T09:51:23.313953+00:00`
  - sha256: `e310fb6d864571c37f3e11980b9e19046a215c0d3e700bc2c27365cb27cecc9e`
- **report_v2_json:** `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/report-v2.json` exists=`True` bytes=`25005` mtime=`2026-08-13T09:37:45.405313+00:00`
  - sha256: `3b609049b4cba4a45f23ae9967da28fa2533c82413b5b140aea9cda2efb92514`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:32:35 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: ishelp.dll (Lotus Blossom / Emissary APT Loader)

## Executive Summary

The DLL sample `ishelp.dll` (SHA256: `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`) is a malicious dropper/loader component associated with the Emissary APT (also tracked as Lotus Blossom). The sample exhibits a clear behavioral chain: it creates a mutex for single-instance enforcement, escalates privileges via `SeDebug
… [21173 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:48:05 UTC

# RE Report — bf0d6cc20fa7
_Generated 2026-08-13T09:48:05.328005+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=240c | cross_refs=True | llm_ok=True | runtime=67.45s -->

# Executive Summary

This section presents a top-line verdict for the malware sample with SHA256 `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`, summarizing its malicious nature, family association, confidence level, and key evidence.

| Aspect       | Value                | Source (Citation) |
|--------------|----------------------|--------------------|
| Verdict      | Malicious          
… [46729 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
