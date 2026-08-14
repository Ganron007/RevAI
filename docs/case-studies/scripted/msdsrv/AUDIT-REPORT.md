# Pipeline AUDIT-REPORT — `ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T09:04:02.888858+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 09:04:02 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98`

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
- key_evidence_count=`6`

```json
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "trojan.graftor/skeeyah",
  "cross_engine_notes": "Ghidra and IDA reveal HTTP-related strings (e.g., 'http://', 'WININET.DLL') and DLL imports, indicating network capabilities. Malcat identifies obfuscation anomalies like DownloaderApiUsage and XorInLoop, alongside YARA matches for keylogger and network rules. Capa confirms behavioral-intent evidence: keylogging and clipboard data theft. pe_imports highlights high-signal imports such as IsDebuggerPresent and InternetOpen for anti-debugging and C2. External TI from VirusTotal shows 56 malicious detections, classifying it as a trojan with tags like persistence and runtime-modules.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "log keystrokes via application hook",
      "why": "Detects keystroke capture capability via application hooks, a clear data theft behavior indicating malicious intent (ATT&CK T1056.001)."
    },
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "read clipboard data",
      "why": "Identifies clipboard data theft, another data collection technique for credential or sensitive information theft (ATT&CK T1115)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "InternetOpen",
      "why": "HTTP client API import suggests capability for command-and-control communication or data exfiltration (ATT&CK T1071.001)."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "DownloaderApiUsage",
      "why": "Indicates downloader-related API usage, often associated with malware for fetching payloads or additional components."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "keylogger",
      "why": "YARA rule detects keylogging patterns, corroborating capa findings and confirming data theft functionality."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal",
      "row_or_rule": "malicious=56",
      "why": "High detection rate by antivirus vendors, with popular threat names 'graftor' and 'skeeyah', classifying it as malicious trojan."
    }
  ],
  "summary": "This PE executable, disguised as 'System Search Indexer', exhibits malicious behaviors including keylogging, clipboard data theft, network communication via WinINet APIs (e.g., InternetOpen, HttpOpenRequestA), and anti-analysis techniques (e.g., IsDebuggerPresent, obfuscation anomalies). Multiple analysis engines corroborate these findings, and external threat intelligence confirms it belongs to the graftor/skeeyah trojan family, indicating clear hostile intent beyond mere obfuscation.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 19 matches",
      "capa: 22 rules"
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
        "why": "ok"
      },
      "pe_imports": {
        "ok": true,
        "why": "ok"
      }
    },
    "hard_failures": [],
    "soft_failures": [],
    "missing
… [2833 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`13`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This PE executable (msdsrv.exe) is a keylogger with HTTP-based C2 exfiltration capability. CAPA confirms two keylogging techniques: application hooking (SetWindowsHookExA) and polling (GetAsyncKeyState/GetKeyState), both mapped to MITRE ATT&CK T1056.001. The sample uses WININET.DLL HTTP APIs (InternetOpenA, InternetConnectA, HttpSendRequestExA, InternetWriteFile) to exfiltrate captured keystrokes to a remote server. Keystrokes are also written locally to 'temp.txt'. Base64 encoding (T1027) is used for defense evasion. The executable tracks the active foreground window (GetForegroundWindow) to associate keystrokes with specific applications. The filename 'msdsrv.exe' masquerades as a Microsoft service. YARA rules matched anti-debug strings, window hooking, HTTP networking, and IP address patterns. The function at 0x004024d0 has extremely high complexity (cyclomatic complexity 336, 148 call-outs, 9 string references) consistent with the main malware payload orchestrating keylogging and network communication.",
  "key_evidence": [
    "CAPA: 'log keystrokes via application hook' (T1056.001 / F0002.001) - SetWindowsHookExA keyboard hook",
    "CAPA: 'log keystrokes via polling' (T1056.001 / F0002.002) - GetAsyncKeyState/GetKeyState polling",
    "Imports: SetWindowsHookExA (USER32.DLL), GetAsyncKeyState (USER32.DLL), GetKeyState (USER32.DLL), GetForegroundWindow (USER32.DLL)",
    "Imports: InternetOpenA, InternetConnectA, HttpSendRequestExA, InternetWriteFile, InternetReadFile (WININET.DLL) - full HTTP C2 stack",
    "String refs: 'temp.txt' referenced in FUN_00403610 (0x00403610) - local keystroke log file",
    "Strings: 'CHttpConnection', 'CHttpFile', 'http://', 'HTTP/1.0', 'WININET.DLL' - MFC HTTP client classes for C2",
    "CAPA: 'encode data using Base64' (T1027 / E1027.m02 / C0026.001) - defense evasion via encoding",
    "YARA: anti_dbg matched at offsets 191098 and 193100 - anti-debugging strings present",
    "YARA: win_hook matched at offsets 175752, 191366, 191278, 191260 - window hooking infrastructure",
    "YARA: network_http matched at offsets 163812, 163429, 191716, 191806, 191786, 191886 - HTTP networking strings",
    "YARA: contains_base64 matched at offset 162639 - Base64 encoded data present",
    "Ghidra funcs: FUN_004024d0 at 0x004024d0 has cyclomatic_complexity=336, call_out_count=148, string_ref_count=9 - main payload orchestrator",
    "Filename 'msdsrv.exe' masquerades as Microsoft service (MSD/Microsoft naming convention)"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 25,
  "successful_non_bootstrap_tools": 12,
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
      "x
… [356 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: msdsrv.exe (ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 08:43:37 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a 32-bit Windows executable (`msdsrv.exe`) identified as a member of the **trojan.graftor/skeeyah** malware family. The sample exhibits clear malicious intent, functioning as a keylogger with HTTP-based command-and-control (C2) capabilities. It captures user keystrokes via two distinct methods\u2014application hooking and polling\u2014and exfiltrates the captured data to a remote server using the Windows Internet (WinINet) API suite. The malware also performs clipboard data theft and employs basic defense evasion techniques, including anti-debugging checks and Base64 encoding.\n\nStatic analysis reveals a complex, non-packed executable with a high cyclomatic complexity in its main payload function, indicative of a sophisticated orchestrator. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events in this environment. The sample's behavior aligns with a data-stealing trojan designed for persistent surveillance. All findings are corroborated by multiple analysis engines and external threat intelligence.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n| :--- | :--- |\n| **SHA256** | `ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98` |\n| **File Name** | `msdsrv.exe` |\n| **File Path** | `/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe` |\n| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |\n| **Architecture** | x86 (32-bit) |\n| **Compiler/Linker** | Microsoft Visual C++ 8 (2005/2008) |\n| **Packed** | No (UPX probe returned 0 files tested) (source: upx_unpack) |\n| **Entropy** | 5.88 bits/byte (whole file) (source: malcat) |\n| **Import Hash** | `fbed62d6575587ffd7907c1f823fa846` (source: rule.yara.json) |\n| **Project** | malware |\n\nThe filename `msdsrv.exe` is a masquerade, likely mimicking a Microsoft service (e.g., MSDTC, MSD). The file is a standard PE32 GUI executable, not packed with a known packer like UPX. The entropy of 5.88 is within the normal range for compiled code, suggesting no heavy encryption or packing. (source: malcat)\n\n## 2. Classification\n\n| Field | Value |\n| :--- | :--- |\n| **Verdict** | **Malicious** |\n| **Confidence** | High (95/100) |\n| **Family** | `trojan.graftor/skeeyah` |\n| **Type** | Keylogger, Data Stealer, Trojan |\n| **Primary Tactic** | Collection (TA0009) |\n\nThe classification is based on direct behavioral evidence of data theft (keylogging, clipboard theft) and C2 communication, not merely on obfuscation or packing. The upstream triage verdict is `malicious` with a score of 95, and the deep-dive analysis confirms this with a confidence of 90. (source: triage verdict.json, deep-dive.json)\n\n## 3. Background & Family Lineage\n\nThe `graftor`
… [16359 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 08:43:37 UTC

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

This report details the analysis of a 32-bit Windows executable (`msdsrv.exe`) identified as a member of the **trojan.graftor/skeeyah** malware family. The sample exhibits clear malicious intent, functioning as a keylogger with HTTP-based command-and-control (C2) capabilities. It captures user keystrokes via two distinct methods—application hooking and polling—and exfiltrates the captured data to a remote server using the Windows Internet (WinINet) API suite. The malware also performs clipboard data theft and employs basic defense evasion techniques, including anti-debugging checks and Base64 encoding.

Static analysis reveals a complex, non-packed executable with a high cyclomatic complexity in its main payload function, indicative of a sophisticated orchestrator. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events in this environment. The sample's behavior aligns with a data-stealing trojan designed for persistent surveillance. All findings are corroborated by multiple analysis engines and external threat intelligence.

## 1. Sample Identification

| Attribute | Value |
| :--- | :--- |
| **SHA256** | `ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98` |
| **File Name** | `msdsrv.exe` |
| **File Path** | `/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe` |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **Compiler/Linker** | Microsoft Visual C++ 8 (2005/2008) |
| **Packed** | No (UPX probe returned 0 files tested) (source: upx_unpack) |
| **Entropy** | 5.88 bits/byte (whole file) (source: malcat) |
| **Import Hash** | `fbed62d6575587ffd7907c1f823fa846` (source: rule.yara.json) |
| **Project** | malware |

The filename `msdsrv.exe` is a masquerade, likely mimicking a Microsoft service (e.g., MSDTC, MSD). The file is a standard PE32 GUI executable, not packed with a known packer l
… [14381 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 08:57:50 UTC

# RE Report — ef2d290a0b2c
_Generated 2026-08-13T08:57:50.622268+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=249c | cross_refs=True | llm_ok=True | runtime=84.18s -->

# Executive Summary

The malware sample with SHA256 hash `ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98` is assessed as **malicious** with high confidence, classified under the **trojan.graftor/skeeyah** family. This top-line verdict is derived from static analysis tools and cross-engine agreement, indicating a broad threat profile.

| Aspect          | Value                  | Confidence | Source Evidence                                                                 |
|-----------------|------------------------|------------|---------------------------------------------------------------------------------|
| Verdict         | Malicious              | High       | Deep static analysis (source: deep_dive_agentic) and tool agreement             |
| Family Guess    | Trojan.Graftor/Skeeyah | High       | YARA rule matches (source: yara) and CAPA rule detections (source: capa)        |
| Deep Confidence | 90%                    | High       | Deep static analysis assessment (source: deep_dive_agentic)                     |

The malicious verdict is supported by agreement between the LLM judge and the v1 summary, which reported 19 YARA matches and 22 CAPA rules indicative of malicious behavior (source: v1_summary, citing yara and capa). Deep static analysis from deep_dive_agentic reinforces this with a high confidence score of 90, assessing the sample's intent based on structural and behavioral patterns (source: deep_dive_agentic). The family guess of trojan.graftor/skeeyah aligns with known trojan characteristics, such as data theft and remote access capabilities, as highlighted in background analyses (source: cross-section:background_&_family_lineage).

In summary, this sample is a likely variant of the Trojan.Graftor/Skeeyah family, demonstrating capabilities for information gathering, persistence, and HTTP-based command-and-control communication, which pose risks for data exfiltration and unauthorized access. No dynamic analysis tools (e.g., Speakeasy, Frida) 
… [42098 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6333` | `b666ca3fd9ffe810` |
| `prompt.txt` | `True` | `33125` | `fb6b9e583cda7295` |
| `pipeline-audit.json` | `True` | `111122` | `93a801bac8a9175f` |
| `AUDIT-REPORT.md` | `True` | `83124` | `c8b28e047776e6d2` |
| `REPORT-MASTER-v2.md` | `True` | `16896` | `f96edc32df2ec55a` |
| `REPORT-MASTER-v3.md` | `True` | `44614` | `0819ac2e0d48d4c5` |
| `REPORT-v2.md` | `True` | `16896` | `f96edc32df2ec55a` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `50732` | `9ef0797b25d82502` |
| `rule.yar` | `True` | `1130` | `289ccb0f04fa9aba` |
| `intake-validation.json` | `True` | `2478` | `51a9d0d858b098f7` |
| `source-decisions.json` | `True` | `1563` | `6434260334d8a2da` |
| `malcat-triage.json` | `True` | `224442` | `06a20175afaf0e46` |
| `deep_dive/01-tools-raw.json` | `True` | `322668` | `80ede2dfa76e13e6` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3856` | `41c70aa66864b3a4` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `314569` | `e2cc025b3564b0dd` |

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

- **intake_validation:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/intake-validation.json` exists=`True` bytes=`2478` mtime=`2026-08-12T18:42:49.762780+00:00`
  - sha256: `51a9d0d858b098f713dfeed9cd7038e193b56f172e71745a0467473b946c7b90`
- **malcat_triage:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/malcat-triage.json` exists=`True` bytes=`224442` mtime=`2026-08-13T04:41:40.110344+00:00`
  - sha256: `06a20175afaf0e461812c2d152a5386df3d61e1af373f25d53e766904179851e`
- **source_decisions:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/source-decisions.json` exists=`True` bytes=`1563` mtime=`2026-08-12T18:42:49.762780+00:00`
  - sha256: `6434260334d8a2daad6a618d0472400f77116f99847f4379d25efd8c5e898500`
- **ghidra_import_log:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/intake-analyzeHeadless.log` exists=`True` bytes=`9314` mtime=`2026-08-12T18:40:39.794739+00:00`
  - sha256: `df8687682d5e7bb38bb2e0623655f771793669d5929d837c93054fd37c07d344`
- **ida_bootstrap_log:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/intake-idasql.log` exists=`True` bytes=`213` mtime=`2026-08-12T18:40:42.037741+00:00`
  - sha256: `aa6e97077268a08f1a58bb7d1e1c4549a1c7cf22770dab126b7e982e11290af4`

#### source_decisions_excerpt

```
{
  "sha256": "ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 264 imports, indicating consistency. Malcat's 1573 imports likely include duplicates or indirect references, making it less reliable for direct import analysis."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 1107 functions, IDA reports 923, within a 2x range. Ghidra's higher count may include more thorough analysis, but both are credible."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Using both engines provides comprehensive coverage: Ghidra (654 strings), IDA (677 strings), and Malcat (100 strings). Combini
… [786 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
    "file_name": "msdsrv.exe",
    "file_path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
    "file_size": 328704,
    "type": "PE",
    "architecture": "X86",
    "entropy": 5.88,
    "sha256": "ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98",
    "metadata": {
      "VersionInfo::FileDescription": "System Search Indexer",
      "VersionInfo::FileVersion": "14.
… [223642 more chars]
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
  "rule_count": 22,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "log keystrokes via application hook",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Application Hook"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Application Hook",
          "id": "F0002.001"
        }
      ]
    },
    {
      "name": "log keystrokes via polling",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Polling"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Polling",
          "id": "F0002.002"
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
      "name": "get hostname",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Information Discovery",
          "subtechnique": "",
          "id": "T1082"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "objective": "Discovery",
          "behavior": "System Information Dis
… [3910 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 295772,
          "length": 16,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 176064,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 162639,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 216,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VC8_Microsoft_Corporation",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 22742,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_8",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 671,
          "length": 82,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 61476,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 76034,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1244,
          "length": 6,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 104575,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 191098,
          "leng
… [8417 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1166,
  "strings_sampled": 80,
  "strings": [
    "DataABackup.lnk",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "@.reloc",
    "D$DSUVW",
    "D$@9|$Ts",
    "D$tPQPVU",
    "\\$@9|$8r",
    "L$ _^3",
    "?????????????",
    "??????????????????",
    "!\"#$%&?????'()*+,-./0??????????????????????????????????????????????????????112233????????????????????456789:??????????????????????????;<=>",
    "L$0QjnP",
    "SSjPSP",
    "SSOWVQ",
    "HtpHHt",
    "u6hgo@",
    "td9~<u_",
    "9~<u;h",
    "N8;N@r(",
    "8\\t\tj/",
    "+F(_^[;E",
    "F(@@;F,v",
    "F(;^ r",
    "F(;F0u",
    "^(_^[]",
    "<A|0<Z",
    "<A|S<Z",
    "u*h`FC",
    "S\\_^[]",
    "t39w u&",
    "_ 9w$u",
    "9~Pu\tP",
    "t\t9p(u",
    "Ht;O u",
    "u:j0^V",
    "SVWj(3",
    "tj9~8u@j",
    "9~8ucj",
    "F4_^[]",
    "0WWWWW",
    "YSSSSS",
    "YWWWWW",
    "QQSVWd",
    "0SSSSS",
    "^SSSSS",
    "8VVVVV",
    "0A@@Ju",
    "<at9<rt,<wt",
    "URPQQh",
    "j@j ^V",
    "HHtXHHt",
    ">If90t",
    "HHtYHHt",
    "t$<\"u\t3",
    ">=Yt1j",
    "< tK<\ttG",
    "j\"^SSSSS",
    "s[S;7|G;w",
    "tR99u2",
    "PPPPPPPP",
    "^WWWWW",
    "0WhLkC",
    ">:u8FV",
    "VVVVVQRSSj",
    "v\tN+D$",
    "_VVVVV",
    "uL9= jC",
    "t\"SS9]",
    "tGHt.Ht&",
    ";t$,v-",
    "UQPXY]Y[",
    "t+WWVPV",
    "<+t(<-t$:",
    "+t HHt",
    "FCOleException",
    "DISPLAY",
    "CInvalidArgException",
    "CNotSupportedException"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1165
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 60.31,
  "size_bytes": 328704,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
    "file_name": "msdsrv.exe",
    "file_path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
    "file_size": 328704,
    "type": "PE",
    "architecture": "X86",
    "entropy": 5.88,
    "sha256": "ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98",
    "metadata": {
      "VersionInfo::FileDescription": "System Search Indexer",
      "VersionInfo::FileVersion": "14.8.1.6",
      "VersionInfo::InternalName": "System Search Indexer",
      "VersionInfo::LegalCopyright": "Copyright \u00a9  2014",
      "VersionInfo::OriginalFilename": "System Search Indexer",
      "VersionInfo::ProductName": "System Search Indexer",
      "VersionInfo::ProductVersion": "13.9.6.11"
    },
    "entrypoint_ea": 74850,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 49
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 160256,
        "virtual_size": 163840,
        "rights": "RX",
        "entropy": 139
      },
      {
        "name": ".rdata",
        "effective_address": 164864,
        "physical_size": 34304,
        "virtual_size": 36864,
        "rights": "R",
        "entropy": 75
      },
      {
        "name": ".data",
        "effective_address": 201728,
        "physical_size": 9216,
        "virtual_size": 28672,
        "rights": "RW",
        "entropy": 99
      },
      {
        "name": ".rsrc",
        "effective_address": 230400,
        "physical_size": 92160,
        "virtual_size": 94208,
        "rights": "R",
        "entropy": 84
      },
      {
        "name": ".reloc",
        "effective_address": 324608,
        "physical_size": 31744,
        "virtual_size": 32768,
        "rights": "R",
        "entropy": 77
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 112,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "DownloaderApiUsage",
        "desc": "Downloader-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 6
      },
      {
        "name": "HighXrefLoopingFunction",
        "desc": "Function contains a loop and has a lot of incoming references (string decryption candidate)",
        "category": "code",
        "level": 1,
        "num_hits": 3
      },
      {
        "name": "InvalidChecksum",
        "desc": "PE Header checksum is wrong",
        "category": "integrity",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "ManyHighValueImmediates",
        "desc": "Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values that contains at least 2 non-zero non-FF bytes and are not a valid address)",
        "category": "code",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "ManyUniqueImmediateBytes",
        "desc": "More than 48 unique bytes defined across all immediate operands in the function",
      
… [255623 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "log keystrokes via application hook rule Detects keystroke capture capability via application hooks, a clear data theft ",
    "read clipboard data rule Identifies clipboard data theft, another data collection technique for credential or sensitive ",
    "InternetOpen imports HTTP client API import suggests capability for command-and-control communication or data exfiltrati",
    "DownloaderApiUsage anomalies Indicates downloader-related API usage, often associated with malware for fetching payloads",
    "keylogger matches YARA rule detects keylogging patterns, corroborating capa findings and confirming data theft functiona"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "trojan.graftor/skeeyah",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "log keystrokes via application hook",
      "why": "Detects keystroke capture capability via application hooks, a clear data theft behavior indicating malicious intent (ATT&CK T1056.001)."
    },
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "read clipboard data",
      "why": "Identifies clipboard data theft, another data collection technique for credential or sensitive information theft (ATT&CK T1115)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "InternetOpen",
      "why": "HTTP client API import suggests capability for command-and-control communication or data exfiltration (ATT&CK T1071.001)."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "DownloaderApiUsage",
      "why": "Indicates downloader-related API usage, often associated with malware for fetching payloads or additional components."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "keylogger",
      "why": "YARA rule detects keylogging patterns, corroborating capa findings and confirming data theft functionality."
    },
    {
      "source": "external_ti",
      "query_or_table": "VirusTotal",
      "row_or_rule": "malicious=56",
      "why": "High detection rate by antivirus vendors, with popular threat names 'graftor' and 'skeeyah', classifying it as malicious trojan."
    }
  ],
  "summary": "This PE executable, disguised as 'System Search Indexer', exhibits malicious behaviors including keylogging, clipboard data theft, network communication via WinINet APIs (e.g., InternetOpen, HttpOpenRequestA), and anti-analysis techniques (e.g., IsDebuggerPresent, obfuscation anomalies). Multiple analysis engines corroborate these findings, and external threat intelligence confirms it belongs to t"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/prompt.txt` exists=`True` bytes=`33125` mtime=`2026-08-12T18:44:13.856632+00:00`
  - sha256: `fb6b9e583cda7295e56735baf1020a3c3b3851352a4fb56c55e295f1492e0832`
- **verdict:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/verdict.json` exists=`True` bytes=`6333` mtime=`2026-08-12T18:44:57.102618+00:00`
  - sha256: `b666ca3fd9ffe810fd8251a24af9053948cbab57c2dac3e29872690882e58550`

#### prompt_excerpt

```
# Triage evidence
sha256: ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98
sample_path: /opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe
ghidra_session: ghidra-pe-ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98
ida_session: ida-ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 264 imports, indicating consistency. Malcat's 1573 imports likely include duplicates or indirect references, making it less reliable for direct import analysis.
- functions: ghidra (confidence=medium) — Ghidra reports 1107 functions, IDA reports 923, within a 2x range. Ghidra's higher count may include more thorough analysis, but both are credible.
- strings: both (confidence=high) — Using both engines provides comprehensive coverage: Ghidra (654 strings), IDA (677 strings), and Malcat (100 strings). 
… [32067 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "trojan.graftor/skeeyah",
  "cross_engine_notes": "Ghidra and IDA reveal HTTP-related strings (e.g., 'http://', 'WININET.DLL') and DLL imports, indicating network capabilities. Malcat identifies obfuscation anomalies like DownloaderApiUsage and XorInLoop, alongside YARA matches for keylogger and network rules. Capa confirms behavioral-intent evidence: keylogging and clipboard data theft. pe_imports highlights high-signal imports such as IsDebuggerPresent and InternetOpen for anti-debugging and C2. External TI from VirusTotal shows 56 malicious detections, classifying it as a trojan with tags like persistence and runtime-modules.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "log keystrokes via application hook",
      "why": "Detects keystroke capture capability via application hooks, a clear data theft behavior indicating malicious intent (ATT&CK T1056.001)."
    },

… [5333 more chars]
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
  "rule_count": 22,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "log keystrokes via application hook",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Application Hook"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Application Hook",
          "id": "F0002.001"
        }
      ]
    },
    {
      "name": "log keystrokes via polling",
      "attack": [
        {
          "parts": [
            "Collection",
            "Input Capture",
            "Keylogging"
          ],
          "tactic": "Collection",
          "technique": "Input Capture",
          "subtechnique": "Keylogging",
          "id": "T1056.001"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Collection",
            "Keylogging",
            "Polling"
          ],
          "objective": "Collection",
          "behavior": "Keylogging",
          "method": "Polling",
          "id": "F0002.002"
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
      "name": "get hostname",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Information Discovery",
          "subtechnique": "",
          "id": "T1082"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "objective": "Discovery",
          "behavior": "System Information Dis
… [3909 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 328704,
  "duration_s": 0.03,
  "import_count": 264,
  "signal_count": 5,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 295772,
          "length": 16,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 176064,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 162639,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 216,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VC8_Microsoft_Corporation",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 22742,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_8",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 671,
          "length": 82,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 61476,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 76034,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1244,
          "length": 6,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 104575,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 191098,
          "leng
… [8395 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1166,
  "strings_sampled": 80,
  "strings": [
    "DataABackup.lnk",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "@.reloc",
    "D$DSUVW",
    "D$@9|$Ts",
    "D$tPQPVU",
    "\\$@9|$8r",
    "L$ _^3",
    "?????????????",
    "??????????????????",
    "!\"#$%&?????'()*+,-./0??????????????????????????????????????????????????????112233????????????????????456789:??????????????????????????;<=>",
    "L$0QjnP",
    "SSjPSP",
    "SSOWVQ",
    "HtpHHt",
    "u6hgo@",
    "td9~<u_",
    "9~<u;h",
    "N8;N@r(",
    "8\\t\tj/",
    "+F(_^[;E",
    "F(@@;F,v",
    "F(;^ r",
    "F(;F0u",
    "^(_^[]",
    "<A|0<Z",
    "<A|S<Z",
    "u*h`FC",
    "S\\_^[]",
    "t39w u&",
    "_ 9w$u",
    "9~Pu\tP",
    "t\t9p(u",
    "Ht;O u",
    "u:j0^V",
    "SVWj(3",
    "tj9~8u@j",
    "9~8ucj",
    "F4_^[]",
    "0WWWWW",
    "YSSSSS",
    "YWWWWW",
    "QQSVWd",
    "0SSSSS",
    "^SSSSS",
    "8VVVVV",
    "0A@@Ju",
    "<at9<rt,<wt",
    "URPQQh",
    "j@j ^V",
    "HHtXHHt",
    ">If90t",
    "HHtYHHt",
    "t$<\"u\t3",
    ">=Yt1j",
    "< tK<\ttG",
    "j\"^SSSSS",
    "s[S;7|G;w",
    "tR99u2",
    "PPPPPPPP",
    "^WWWWW",
    "0WhLkC",
    ">:u8FV",
    "VVVVVQRSSj",
    "v\tN+D$",
    "_VVVVV",
    "uL9= jC",
    "t\"SS9]",
    "tGHt.Ht&",
    ";t$,v-",
    "UQPXY]Y[",
    "t+WWVPV",
    "<+t(<-t$:",
    "+t HHt",
    "FCOleException",
    "DISPLAY",
    "CInvalidArgException",
    "CNotSupportedException"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1165
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 60.53,
  "size_bytes": 328704,
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
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
  "disassembly": {
    "0x00413062": "\u250c 320: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_20h @ ebp-0x20\n\u2502       \u254e   ; var int32_t var_38h @ ebp-0x38\n\u2502       \u254e   ; var int32_t var_3ch @ ebp-0x3c\n\u2502       \u254e   ; var int32_t var_68h @ ebp-0x68\n\u2502       \u254e   0x00413062      e8509c0000     call 0x41ccb7\n\u2502       \u2514\u2500< 0x00413067      e978feffff     jmp 0x412ee4\n..",
    "0x004042e0": "; CALL XREF from entry0 @ 0x412ff2(x)\n\u250c 343: int main (int argc, char **argv, char **envp);\n\u2502           ; var int32_t var_ch_2 @ esp+0x24\n\u2502           ; var int32_t var_10h @ esp+0x28\n\u2502           ; var int32_t var_ch @ esp+0x34\n\u2502           ; var int32_t var_20h_2 @ esp+0x38\n\u2502           ; var int32_t var_1ch @ esp+0x44\n\u2502           ; var int32_t var_20h @ esp+0x48\n\u2502           ; var int32_t var_24h @ esp+0x4c\n\u2502           ; var int32_t var_2ch_2 @ esp+0x54\n\u2502           ; var int32_t var_30h @ esp+0x58\n\u2502           ; var int32_t var_28h @ esp+0x68\n\u2502           ; var int32_t var_2ch @ esp+0x6c\n\u2502           ; var int32_t var_38h_2 @ esp+0x70\n\u2502           ; var int32_t var_3ch @ esp+0x74\n\u2502           ; var int32_t var_38h @ esp+0x78\n\u2502           ; var int32_t var_128h @ esp+0x148\n\u2502           ; var int32_t var_12ch @ esp+0x150\n\u2502           ; var int32_t var_130h @ esp+0x160\n\u2502           ; var int32_t var_22ch @ esp+0x254\n\u2502           ; var int32_t var_230h @ esp+0x270\n\u2502           ; var int32_t var_328h @ esp+0x378\n\u2502           0x004042e0      81ec2c030000   sub esp, 0x32c\n\u2502           0x004042e6      a1e02b4300     mov eax, dword [0x432be0]   ; [0x432be0:4]=0xbb40e64e\n\u2502           0x004042eb      33c4           xor eax, esp\n\u2502           0x004042ed      8984242803..   mov dword [var_328h], eax\n\u2502           0x004042f4      56             push esi\n\u2502           0x004042f5      57             push edi\n\u2502           0x004042f6      e845fdffff     call 0x404040\n\u2502           0x004042fb      e870dcffff     call 0x401f70\n\u2502           0x00404300      e87bf2ffff     call 0x403580\n\u2502           0x00404305      e806f3ffff     call 0x403610\n\u2502           0x0040430a      8b352c924200   mov esi, dword [sym.imp.KERNEL32.dll_Sleep] ; [0x42922c:4]=0x303da reloc.KERNEL32.dll_Sleep\n\u2502           0x00404310      68d0070000     push 0x7d0                  ; 2000\n\u2502           0x00404315      ffd6           call esi\n\u2502           0x00404317      e834f5ffff     call 0x403850\n\u2502           0x0040431c      8b0db0cc4200   mov ecx, dword [0x42ccb0]   ; [0x42ccb0:4]=0x615e433f ; \"?C^alrn/ill\"\n\u2502           0x00404322      a1accc4200     mov eax, dword [str.A_u_Calrn_ill] ; [0x42ccac:4]=0x5e755f41 ; \"A_u^?C^alrn/ill\"\n\u2502           0x00404327      8b15b4cc4200   mov edx, dword [0x42ccb4]   ; [0x42ccb4:4]=0x2f6e726c ; \"lrn/ill\"\n\u2502           0x0040432d      68f4000000     push 0xf4                   ; 244\n\u2502           0x00404332      894c242c       mov dword [var_2ch], ecx\n\u2502           0x00404336      89442428       mov dword [var_28h], eax\n\u2502           0x0040433a      a1b8cc4200   
… [622 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
    "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!LoadLibraryA",
      "KERNEL32.dll!ReadFile",
      "KERNEL32.dll!WriteFile",
      "KERNEL32.dll!SetFilePointer",
      "KERNEL32.dll!FlushFileBuffers",
      "USER32.dll!GetClientRect",
      "USER32.dll!SetForegroundWindow",
      "USER32.dll!SetMenu",
      "USER32.dll!MapWindowPoints",
      "USER32.dll!GetMessagePos",
      "ADVAPI32.dll!GetUserNameA",
      "SHELL32.dll!SHGetSpecialFolderPathA",
      "ole32.dll!CoCreateInstance",
      "ole32.dll!CoInitialize",
      "SHLWAPI.dll!PathFindFileNameA",
      "SHLWAPI.dll!PathIsUNCA",
      "SHLWAPI.dll!PathStripToRootA",
      "SHLWAPI.dll!PathAppendA",
      "WININET.dll!HttpOpenRequestA",
      "WININET.dll!InternetConnectA",
      "WININET.dll!HttpSendRequestExA",
      "WININET.dll!HttpEndRequestA",
      "WININET.dll!InternetReadFile",
      "OLEACC.dll!LresultFromObject",
      "OLEACC.dll!CreateStdAccessibleObject",
      "GDI32.dll!CreateBitmap",
      "GDI32.dll!DeleteObject",
      "GDI32.dll!SaveDC",
      "GDI32.dll!RestoreDC",
      "GDI32.dll!SetBkColor"
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
  "checked": 13,
  "hits": 13,
  "misses": [],
  "hit_examples": [
    "CAPA: 'log keystrokes via application hook' (T1056.001 / F0002.001) - SetWindowsHookExA keyboard hook",
    "CAPA: 'log keystrokes via polling' (T1056.001 / F0002.002) - GetAsyncKeyState/GetKeyState polling",
    "Imports: SetWindowsHookExA (USER32.DLL), GetAsyncKeyState (USER32.DLL), GetKeyState (USER32.DLL), GetForegroundWindow (U",
    "Imports: InternetOpenA, InternetConnectA, HttpSendRequestExA, InternetWriteFile, InternetReadFile (WININET.DLL) - full H",
    "String refs: 'temp.txt' referenced in FUN_00403610 (0x00403610) - local keystroke log file"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This PE executable (msdsrv.exe) is a keylogger with HTTP-based C2 exfiltration capability. CAPA confirms two keylogging techniques: application hooking (SetWindowsHookExA) and polling (GetAsyncKeyState/GetKeyState), both mapped to MITRE ATT&CK T1056.001. The sample uses WININET.DLL HTTP APIs (Intern",
  "key_evidence": [
    "CAPA: 'log keystrokes via application hook' (T1056.001 / F0002.001) - SetWindowsHookExA keyboard hook",
    "CAPA: 'log keystrokes via polling' (T1056.001 / F0002.002) - GetAsyncKeyState/GetKeyState polling",
    "Imports: SetWindowsHookExA (USER32.DLL), GetAsyncKeyState (USER32.DLL), GetKeyState (USER32.DLL), GetForegroundWindow (USER32.DLL)",
    "Imports: InternetOpenA, InternetConnectA, HttpSendRequestExA, InternetWriteFile, InternetReadFile (WININET.DLL) - full HTTP C2 stack",
    "String refs: 'temp.txt' referenced in FUN_00403610 (0x00403610) - local keystroke log file",
    "Strings: 'CHttpConnection', 'CHttpFile', 'http://', 'HTTP/1.0', 'WININET.DLL' - MFC HTTP client classes for C2",
    "CAPA: 'encode data using Base64' (T1027 / E1027.m02 / C0026.001) - defense evasion via encoding",
    "YARA: anti_dbg matched at offsets 191098 and 193100 - anti-debugging strings present",
    "YARA: win_hook matched at offsets 175752, 191366, 191278, 191260 - window hooking infrastructure",
    "YARA: network_http matched at offsets 163812, 163429, 191716, 191806, 191786, 191886 - HTTP networking strings",
    "YARA: contains_base64 matched at offset 162639 - Base64 encoded data present",
    "Ghidra funcs: FUN_004024d0 at 0x004024d0 has cyclomatic_complexity=336, call_out_count=148, string_ref_count=9 - main payload orchestrator",
    "Filename 'msdsrv.exe' masquerades as Microsoft service (MSD/Microsoft naming convention)"
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
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
… [11495 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
    "file_name": "msdsrv.exe",
    "file_path": 
… [258528 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 22,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
    
… [7009 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 328704,
  "duration_s": 0.03,
  "import_count": 264,
  "signal_count": 5,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      "l
… [420 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 1166,
  "strings_sampled": 80,
  "strings": [
    "DataABackup.lnk",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "@.reloc",
    "D$DSUVW",
    "D$@9|$Ts",
    "D$tPQPVU",
    "\\$@9|$8r",
    "L$ _^3",
    "?????????????",
    "??????????????????",
    "!\"#$%&?????'()*+,-./0???????????????????????????????????????????????
… [1484 more chars]
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
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
  "disassembly": {
    "0x00413062": "\u250c 320: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_20h @ ebp-0x20\n\u2502       \u254e   ; var int32_
… [3722 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_
… [16 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
    "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!LoadLibraryA",
      "KERNEL32.dll!ReadFile",
      "KERNEL32.dll!WriteFile",
      "KERNEL32.dll!SetFilePointer",
      "KERNEL32.dll!FlushF
… [909 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 160256,
      "entropy": 6.6547,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 34304,
      "entropy": 5.0072,
      "executable": 
… [517 more chars]
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
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x412c21",
      "function": "fcn.00412c0d"
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x413aee",
      "function": "fc
… [939 more chars]
```

- **revai_tools_audit** ok=`False` checklist=`True` — Required checklist tool (revai_tools_audit)
  - error: `revai_tools_audit: timeout`

```json
{
  "error": "revai_tools_audit: timeout",
  "fail_open": true,
  "skipped": true,
  "reason": "not_applicable:timeout"
}
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 8.03,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 3,
    "min_resolve_calls": 2,
    "elapsed_s": 4.42,
 
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
      "name": "_memcmp",
      "address": "4276295",
      "size": "5632"
    },
    {
      "name": "FUN_004024d0",
      "address": "4203728",
      "size": "3759"
    },
    {
      "name": "__output_s_l",
      "address": "4307490",
      "size": "2990"
    },
    {
      "name": "__output_l",
      "address": "43039
… [2634 more chars]
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
      "content": "CHttpConnection",
      "address": "4364372",
      "length": "16"
    },
    {
      "content": "CHttpFile",
      "address": "4364428",
      "length": "10"
    },
    {
      "content": "http://",
      "address": "4364524",
      "length": "8"
    },
    {
      "content": "WININET.DLL",
      
… [4692 more chars]
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
      "name": "CreateBitmap",
      "module": "GDI32.DLL",
      "address": "235"
    },
    {
      "name": "CreateDirectoryA",
      "module": "KERNEL32.DLL",
      "address": "115"
    },
    {
      "name": "CreateFileA",
      "module": "KERNEL32.DLL",
      "address": "17"
    },
    {
      "name": "HeapCreate",
… [2429 more chars]
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
      "name": "___tmainCRTStartup",
      "address": "4271844",
      "size": "310"
    },
    {
      "name": "?SendMessageToDescendants@CWnd@@SGXPAUHWND__@@IIJHH@Z",
      "address": "4252668",
      "size": "127"
    },
    {
      "name": "?AfxHookWindowCreate@@YGXPAVCWnd@@@Z",
      "address": "4257144",
      "size
… [1231 more chars]
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
      "content": "accKeyboardShortcut",
      "address": "4367680"
    },
    {
      "content": "Microsoft Visual C++ Runtime Library",
      "address": "4372008"
    },
    {
      "content": "GetProcessWindowStation",
      "address": "4376612"
    },
    {
      "content": "GetKeyState",
      "address": "4392074"
    },
    
… [688 more chars]
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
      "func_name": "",
      "func_addr": "",
      "string_value": "http://",
      "string_addr": "4364524"
    },
    {
      "func_name": "",
      "func_addr": "",
      "string_value": "CHttpFile",
      "string_addr": "4364428"
    },
    {
      "func_name": "",
      "func_addr"
… [1128 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "cyclomatic_complexity",
    "size",
    "instruction_count",
    "block_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "_memcmp",
      "address": "4276295",
      "cyclomatic_complexity": "382",
      "size": "5632",
      "instruction_count": "1934",
      "block_count": "439",
      "call_out_count": "0"
… [5469 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98.json"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 22,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
    
… [7009 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands",
    "disasm"
  ],
  "rows": [
    {
      "address": "4203728",
      "mnemonic": "PUSH",
      "operands": "-0x1",
      "disasm": "PUSH -0x1"
    },
    {
      "address": "4203730",
      "mnemonic": "PUSH",
      "operands": "0x427913",
      "disasm": "PUSH 0x427913"
    },
    {
      "address": "4203741",
      "mnemonic": "PUS
… [10082 more chars]
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
      "func_name": "",
      "func_addr": "",
      "string_value": "http://"
    },
    {
      "func_name": "",
      "func_addr": "",
      "string_value": "CHttpFile"
    },
    {
      "func_name": "",
      "func_addr": "",
      "string_value": "CHttpConnection"
    },
    {
      "func_name": "FUN_
… [2508 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/deep_dive/01-tools-raw.json` exists=`True` bytes=`322668` mtime=`2026-08-13T04:41:40.124344+00:00`
  - sha256: `80ede2dfa76e13e6d574a9ea62ab95d6133e622d15ab1b5a2d4503ad122fe8de`
- **sql_evidence:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/deep_dive/05-deep-dive.json` exists=`True` bytes=`3856` mtime=`2026-08-12T18:57:45.699135+00:00`
  - sha256: `41c70aa66864b3a4e6e753fbcd0a66e96f8b6497fbacaf5c882fc537e35816ae`

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
  "summary": "This PE executable (msdsrv.exe) is a keylogger with HTTP-based C2 exfiltration capability. CAPA confirms two keylogging techniques: application hooking (SetWindowsHookExA) and polling (GetAsyncKeyState/GetKeyState), both mapped to MITRE ATT&CK T1056.001. The sample uses WININET.DLL HTTP APIs (InternetOpenA, InternetConnectA, HttpSendRequestExA, InternetWriteFile) to exfiltrate captured keystrokes to a remote server. Keystrokes are also written locally to 'temp.txt'. Base64 encoding (T1027) is used for defense evasion. The executable tracks the active foreground window (GetForegroundWindow) to associate keystrokes with specific applications. The filename 'msdsrv.exe' masqu
… [3056 more chars]
```

- **agentic:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`850375` mtime=`2026-08-12T18:57:45.699135+00:00`
  - sha256: `8dc42993a9e525dc51747bee46624c581f9d4207b316f60f07b3d1746104dae6`

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

- **rule_yar:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/rule.yar` exists=`True` bytes=`1130` mtime=`2026-08-12T18:57:48.588131+00:00`
  - sha256: `289ccb0f04fa9aba75ceb0a394a9a97d17df31121c4f505b564d1aededaf21d8`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T18:57:48.589329+00:00
import "pe"
rule CADRE_v2_trojan_graftor_skeeyah_ef2d290a0b2c {
    meta:
        description = "RevAI v2 auto rule for trojan.graftor/skeeyah"
        sha256 = "ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98"
        family = "trojan_graftor_skeeyah"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "DataABackup.lnk" ascii wide
        $s1 = "!This program cannot be run in DOS mode." ascii wide
        $s2 = "D$@9|$Ts" ascii wide
        $s3 = "D$tPQPVU" ascii wide
        $s4 = "\\$@9|$8r" ascii wide
        $s5 = "?????????????" ascii wide
        $s6 = "??????????????????" ascii wide
        $s7 
… [328 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/REPORT-MASTER-v2.md` exists=`True` bytes=`16896` mtime=`2026-08-13T08:43:37.502223+00:00`
  - sha256: `f96edc32df2ec55aff702dddcf61bd72ea2220af4c3d387b9589207417d6ca6b`
- **REPORT_MASTER_v3:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/REPORT-MASTER-v3.md` exists=`True` bytes=`44614` mtime=`2026-08-13T08:57:50.629208+00:00`
  - sha256: `0819ac2e0d48d4c58d5378c6a294db3c9ace2e86a77d01a74016dc4ed4ee12ba`
- **REPORT_v2:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/REPORT-v2.md` exists=`True` bytes=`16896` mtime=`2026-08-13T08:43:37.502223+00:00`
  - sha256: `f96edc32df2ec55aff702dddcf61bd72ea2220af4c3d387b9589207417d6ca6b`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`58629` mtime=`2026-08-13T08:47:03.042297+00:00`
  - sha256: `e6c72977ede6413a7f3e091a67b916284fbc5434446c36064df8d8ca2fa41c90`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`50732` mtime=`2026-08-13T09:04:02.844080+00:00`
  - sha256: `9ef0797b25d82502093ad677eb08551122407295aedb565be2cc6e65f66829db`
- **report_v2_json:** `/opt/samples/logs/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/report-v2.json` exists=`True` bytes=`19859` mtime=`2026-08-13T08:47:03.046297+00:00`
  - sha256: `82cf66d85324a5f5483043533b1d2fcf040095f65fbfbd4d71c4a394bed28400`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 08:43:37 UTC

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

This report details the analysis of a 32-bit Windows executable (`msdsrv.exe`) identified as a member of the **trojan.graftor/skeeyah** malware family. The sample exhibits clear malicious intent, functioning as a keylogger with HTTP-based command-and-control (C2) capabilities. It captures user keystrokes via two distinct methods—application hooking and polling—and exfiltrates the captured data to a remote server usi
… [15981 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 08:57:50 UTC

# RE Report — ef2d290a0b2c
_Generated 2026-08-13T08:57:50.622268+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=249c | cross_refs=True | llm_ok=True | runtime=84.18s -->

# Executive Summary

The malware sample with SHA256 hash `ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98` is assessed as **malicious** with high confidence, classified under the **trojan.graftor/skeeyah** family. This top-line verdict is derived from static analysis tools and cross-engine agreement, indicating a broad threat profile.

| Aspect          | Value                  | Confidence | 
… [43698 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
