# Pipeline AUDIT-REPORT — `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-09T20:38:54.037436+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-09 20:38:54 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`

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

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`malicious` confidence=`75`
- key_evidence_count=`5`

```json
{
  "verdict": "malicious",
  "score": 75,
  "family_guess": "unknown service-based trojan",
  "cross_engine_notes": "Ghidra and IDA both identify process enumeration functions (e.g., CreateToolhelp32Snapshot, Process32FirstW). Malcat anomalies (e.g., BigResourceHighEntropy, CrossSectionJump) and pe_imports high-signal imports (e.g., CreateServiceA, IsDebuggerPresent) align with capa rules for anti-debug, shellcode execution, and persistence. YARA matches include service creation and anti-debug rules. FLOSS strings show API calls consistent with these behaviors.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "create_service",
      "why": "API for creating services (CreateServiceA), indicating potential persistence via service installation (T1543.003)."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "execute shellcode via indirect call",
      "why": "Rule detects capability for indirect shellcode execution, a direct malicious behavior for code execution."
    },
    {
      "source": "ghidra",
      "query_or_table": "Anti Analysis Signals",
      "row_or_rule": "FUN_00402640 calls CreateToolhelp32Snapshot, Process32FirstW, Process32NextW",
      "why": "Process enumeration functions used for discovery (T1057), a common reconnaissance technique in malware."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "IsDebuggerPresent",
      "why": "Anti-debugging API import, indicating evasion techniques to hinder analysis (T1622)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports_evidence",
      "row_or_rule": "CreateService",
      "why": "YARA rule matched for service creation API, supporting evidence of persistence behavior.",
      "source_corrected_from": "yara"
    }
  ],
  "summary": "The PE file space1.ex exhibits clear malicious intent through behavioral signals: anti-debugging (IsDebuggerPresent), process enumeration (CreateToolhelp32Snapshot), service creation for persistence (CreateServiceA), and shellcode execution capabilities (capa rule). Obfuscation techniques (e.g., high entropy, dynamic strings) are present but secondary. Cross-engine analysis confirms consistent findings, with high-signal imports and anomalies pointing to hostile activity beyond mere protection.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 12 matches",
      "capa: 11 rules"
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
    "missing": [],
    "not_applicable": [],
    "large_sample": false
  },
  "yara_family_hits": [
    "Antivirus",
    "IsPE32",
    "IsWindowsGUI",
    "IsPacked",
    "HasRichSignature",
    "Microsoft_Visual_Basic_v50",
    "SEH_Save",
    "SEH_Init",
    "anti_dbg"
  ],
  "engine_citation_corrections": {
    "corrected": 1,
    "corrections": [
 
… [1176 more chars]
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
  "summary": "Dropper/loader targeting Windows. The entry function systematically enumerates 13 security product processes (360 Security suite, Comodo, AhnLab V3, Dr.Web, ESET) via CreateToolhelp32Snapshot and terminates or evades if detected. After AV evasion, it resolves APIs dynamically (GetProcAddress+LoadLibraryA) using an obfuscated API name table, allocates RWX memory via VirtualAlloc, decrypts embedded payload data (garbled strings like '&*^@QDSJGIO', 'V><MDNbyfui6y2iuow'), and uses QueueUserAPC for code injection. It establishes persistence via CreateServiceA/OpenSCManagerA and registry (RegOpenKeyA), and has network capabilities via WININET and WSOCK32 DLLs. Built with MSVC and uses stack-string obfuscation to hinder static analysis. Exfiltration: Network capabilities are indicated by WININET and WSOCK32 DLLs, but specific exfiltration methods are not observed in the provided analysis, citing evidence from the network DLL references in the summary. Credential access: Not observed in the provided details.",
  "key_evidence": [
    "YARA 'anti_dbg' rule matched at offsets 7456 and 9106 with strings $d1 (12 bytes) and $c2 (17 bytes)",
    "CAPA: 'enumerate processes' (T1057/T1518), 'check for trap flag exception' (B0001), 'contain obfuscated stackstrings' (T1027.005), 'allocate or change RWX memory'",
    "Entry function (0x402720) calls FUN_00402640 13 times with AV process names: QHACTIVEDEFENSE.EXE, QHSAFETRAY.EXE, QHWATCHDOG.EXE, CMDAGENT.EXE, CIS.EXE, V3LITE.EXE, V3MAIN.EXE, V3SP.EXE, SPIDERAGENT.EXE, DWENGINE.EXE, DWARKDAEMON.EXE, EGUI.EXE, EKRN.EXE \u2014 each followed by conditional jump to 0x402948 (exit if found)",
    "Imports include CreateServiceA+OpenSCManagerA (ADVAPI32, service persistence), QueueUserAPC (code injection), VirtualAlloc (RWX allocation), DebugSetProcessKillOnExit+IsDebuggerPresent (anti-debug), GetProcAddress+LoadLibraryA (dynamic API resolution), RegOpenKeyA (registry manipulation)",
    "Network-capable imports: InternetOpenA, InternetConnectA, HttpSendRequestA (WININET), WSAStartup, connect, send, recv (WSOCK32)",
    "Obfuscated/garbled strings in data section: '&*^@QDSJGIO', '&JTEH$WHD', 'V><MDNbyfui6y2iuow', 'fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6'",
    "FLOSS decoded 3 stack strings from the binary; entry function has cyclomatic complexity 56 with 62 basic blocks and 19 string references",
    "GDI32 imports (CreateDCW, GetTextMetricsW, SetDIBits) suggest screen capture capability"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 32,
  "successful_non_bootstrap_tools": 20,
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
   
… [390 more chars]
```

#### `publish`

- source=`llm_judge` model=`mimo-v2.5-pro` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: space1.ex (5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 20:22:51 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a malicious Windows PE executable (`space1.ex`, SHA256: `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`). The sample is a dropper/loader with a primary objective of evading security software, establishing persistence, and executing a secondary payload. It is not a known, named malware family but exhibits characteristics of a service-based trojan.\n\nThe malware's execution flow begins with a comprehensive anti-analysis phase. It enumerates running processes to detect 13 specific security products from vendors including 360 Security, Comodo, AhnLab, Dr.Web, and ESET. If any of these processes are found, the malware terminates itself to avoid detection in sandboxed or protected environments (source: r2_disassembly, ghidra_query). It also employs anti-debugging techniques by checking for the presence of a debugger (source: ida_query, capa).\n\nUpon successful evasion, the malware dynamically resolves API functions to hinder static analysis, allocates memory with read-write-execute (RWX) permissions, and decrypts an embedded payload. It then injects this payload into a process using Asynchronous Procedure Calls (APCs) (source: capa, pe_imports). To ensure it runs automatically, it creates a Windows service for persistence (source: pe_imports, yara). The binary contains network-capable imports (WININET, WSOCK32), indicating latent command-and-control (C2) or data exfiltration capabilities, though specific C2 servers or exfiltration methods were not observed in the static analysis (source: deep-dive.json).\n\nThe verdict is **malicious** with high confidence (90%). The behavioral intent is clear: defense evasion, persistence, and code execution are core malicious activities, not neutral protection mechanisms. Recommendations include immediate containment, eradication of the service, and network monitoring for related indicators.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n| :--- | :--- |\n| **File Name** | space1.ex |\n| **SHA256** | 5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da |\n| **MD5** | (Not provided in evidence) |\n| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |\n| **Architecture** | x86 (32-bit) |\n| **Compiler/Linker** | Microsoft Visual C++ 2008 (source: malcat) |\n| **File Size** | (Not provided in evidence) |\n| **First Submission** | (Not provided in evidence) |\n| **Project** | Malware Analyst Professional - Level 2 |\n| **Sample Path** | /opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex |\n\nThe sample is a standard 32-bit Windows GUI executable. The import hash (imphash) is `1905143b6a38c11e2b30615cb955fd08` (source: rule.yara.json). Analysis confirms it is not a .NET assembly (source: dotnet_a
… [16895 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:22:51 UTC

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

This report details the analysis of a malicious Windows PE executable (`space1.ex`, SHA256: `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`). The sample is a dropper/loader with a primary objective of evading security software, establishing persistence, and executing a secondary payload. It is not a known, named malware family but exhibits characteristics of a service-based trojan.

The malware's execution flow begins with a comprehensive anti-analysis phase. It enumerates running processes to detect 13 specific security products from vendors including 360 Security, Comodo, AhnLab, Dr.Web, and ESET. If any of these processes are found, the malware terminates itself to avoid detection in sandboxed or protected environments (source: r2_disassembly, ghidra_query). It also employs anti-debugging techniques by checking for the presence of a debugger (source: ida_query, capa).

Upon successful evasion, the malware dynamically resolves API functions to hinder static analysis, allocates memory with read-write-execute (RWX) permissions, and decrypts an embedded payload. It then injects this payload into a process using Asynchronous Procedure Calls (APCs) (source: capa, pe_imports). To ensure it runs automatically, it creates a Windows service for persistence (source: pe_imports, yara). The binary contains network-capable imports (WININET, WSOCK32), indicating latent command-and-control (C2) or data exfiltration capabilities, though specific C2 servers or exfiltration methods were not observed in the static analysis (source: deep-dive.json).

The verdict is **malicious** with high confidence (90%). The behavioral intent is clear: defense evasion, persistence, and code execution are core malicious activities, not neutral protection mechanisms. Recommendations include immediate containment, eradication of the service, and network monitoring for related indicators.

## 1. Sample Identification

| Attribute | Value |
| :--- | :--- |
| **File Name** | space1.ex |
| **SHA256** | 5f
… [15225 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:35:25 UTC

# RE Report — 5f251ed33fb1
_Generated 2026-08-09T20:35:25.337166+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=255c | cross_refs=True | llm_ok=True | runtime=47.86s -->

# Executive Summary

## Top-line Verdict
- **Verdict**: Malicious
- **Family**: Unknown service-based trojan
- **Confidence**: 90%
- **Summary**: This sample is assessed as malicious with high confidence, based on consistent indicators from multiple analyses. It likely operates as a service-based trojan, focusing on persistence and stealth through Windows service mechanisms.

## Key Findings and Evidence
The following table summarizes critical aspects, with evidence cited to support the assessment. Each finding is interpreted to explain its implications for malware behavior.

| Aspect | Detail | Evidence | Interpretation (What + Why + Confidence) |
|--------|--------|----------|------------------------------------------|
| Verdict | Malicious | (source: deep_dive_agentic) | The deep dive analysis, using behavioral heuristics, consistently flags this sample as malicious. This is supported by a confidence score of 90, indicating high reliability from detailed examination. |
| Family Guess | Unknown service-based trojan | (source: deep_dive_agentic) | Behavioral indicators, such as service-related actions, suggest the malware installs or manipulates Windows services for persistence. We assess this as a likely classification, though specific variants are not identified. |
| Agreement | LLM and v1 agree | (source: cross-section:2) | Independent analyses from LLM and v1 both reach malicious verdicts, enhancing confidence through consensus. This agreement reduces false positive risk. |
| YARA Matches | 12 matches | (source: yara) | YARA rules detect static patterns associated with malicious behavior, such as obfuscation or service manipulation. These matches likely indicate known malware techniques, contributing to the verdict. |
| CAPA Rules | 11 rules | (source: capa) | CAPA identifies executable capabilities like service creation or anti-analysis, aligning with the service-based trojan family. This evidence is crucial for understanding the malware's functional scope. |

## Overall A
… [44310 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4676` | `bc46166afdc74678` |
| `prompt.txt` | `True` | `29069` | `27c87d8bc3245d78` |
| `pipeline-audit.json` | `True` | `115661` | `6a5324dd4f09768c` |
| `AUDIT-REPORT.md` | `True` | `86700` | `b682a2821fcef412` |
| `REPORT-MASTER-v2.md` | `True` | `17736` | `61aaecb9a1027eaa` |
| `REPORT-MASTER-v3.md` | `True` | `46828` | `9c5c6cd319e2fd94` |
| `REPORT-v2.md` | `True` | `17736` | `61aaecb9a1027eaa` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `53287` | `042a5de59cadea9f` |
| `rule.yar` | `True` | `1220` | `0af0c83d35a9e028` |
| `intake-validation.json` | `True` | `2265` | `d837840ab0f50ecc` |
| `source-decisions.json` | `True` | `1424` | `df206ec091de9685` |
| `malcat-triage.json` | `True` | `27958` | `acbc063685828466` |
| `deep_dive/01-tools-raw.json` | `True` | `107418` | `960e17cbe85f6a2a` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3890` | `f4c29603906f6c6d` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `101749` | `08919c0ef6004e86` |

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

- **intake_validation:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/intake-validation.json` exists=`True` bytes=`2265` mtime=`2026-08-09T16:28:50.620753+00:00`
  - sha256: `d837840ab0f50eccd24a146cae5cb20ffd2bc5750f0b62da6b23a57777cc01ae`
- **malcat_triage:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/malcat-triage.json` exists=`True` bytes=`27958` mtime=`2026-08-09T16:27:40.914433+00:00`
  - sha256: `acbc0636858284666c948ae6895c5231695a27d5da494695243605836e1211a7`
- **source_decisions:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/source-decisions.json` exists=`True` bytes=`1424` mtime=`2026-08-09T16:28:50.620753+00:00`
  - sha256: `df206ec091de9685c3bce46a0556d52f43d8ef0849ee8218d01836f962c549bf`
- **ghidra_import_log:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/intake-analyzeHeadless.log` exists=`True` bytes=`8118` mtime=`2026-08-09T13:09:09.447806+00:00`
  - sha256: `341d452c09726a0fe59f26464c1bc4220aefadc8cded685c3c5ce1b8a940fe42`
- **ida_bootstrap_log:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/intake-idasql.log` exists=`True` bytes=`243` mtime=`2026-08-09T16:27:42.166433+00:00`
  - sha256: `4002911776faccc3bb5801338c4fbb519aa30c39a22c3e91f9e5dfba0ab3c5d7`

#### source_decisions_excerpt

```
{
  "sha256": "5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra=63 and IDA=63 imports, identical counts indicating reliable extraction; malcat=67 is slightly higher but inconsistent with disassemblers."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra=33 and IDA=34 functions, very close; malcat=10 is significantly lower, suggesting malcat may not capture all functions accurately."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Use both engines for comprehensive string extraction; Ghidra=341, IDA=91, Malcat=100 vary, so combining provides better coverage."
  },
  "decompilation": {
    "source": "ghidra",
  
… [647 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
    "file_name": "space1.ex",
    "file_path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
    "file_size": 160256,
    "type": "PE",
    "architecture": "X86",
    "entropy": 176,
    "sha256": "5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da",
    "metadata": {},
    "entrypoint_ea": 6944,
    "layout": 
… [27158 more chars]
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
  "rule_count": 11,
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
      "name": "enumerate processes",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Process Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Process Discovery",
          "subtechnique": "",
          "id": "T1057"
        },
        {
          "parts": [
            "Discovery",
            "Software Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Software Discovery",
          "subtechnique": "",
          "id": "T1518"
        }
      ],
      "mbc": []
    },
    {
      "name": "check for trap flag exception",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "",
          "id": "B0001"
        }
      ]
    },
    {
      "name": "find graphical window",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Application Window Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Application Window Discovery",
          "subtechnique": "",
          "id": "T1010"
        }
      ],
      "mbc": []
    },
    {
      "name": "allocate or change RWX memory",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Memory",
            "Allocate Memory"
          ],
          "objective": "Memory",
          "behavior": "Allocate Memory",
          "method": "",
          "id": "C0007"
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
      "name": "link function at runtime on Windows",
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
    },
    {
     
… [1292 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 96608,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 7871,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1521,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1540,
          "length": 6,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 3823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d56
… [3011 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2471,
  "strings_sampled": 80,
  "strings": [
    "QueryPerformanceFrequency",
    "QueryPerformanceCounter",
    "IsBadCodePtr",
    "!This program cannot be run in DOS mode.",
    "/uRich",
    "`.rdata",
    "@.data",
    "VC20XC00U",
    ";t$,v-",
    "UQPXY]Y[",
    "URPQQhT",
    "1F;5T@@",
    "bad allocation",
    "kernel32.dll",
    "user32",
    "&*^@QDSJGIO",
    "&JTEH$WHD",
    "fdsfsd,",
    "fdsfds",
    "V><MDNbyfui6y2iuow",
    "fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6",
    "ExitProcess",
    "HeapReAlloc",
    "CreateFileA",
    "FindResourceW",
    "LoadResource",
    "GetCurrentActCtx",
    "GetModuleHandleW",
    "GetCurrentThread",
    "VirtualFree",
    "GetProcessHeap",
    "TlsSetValue",
    "GetConsoleCP",
    "SizeofResource",
    "GetSystemDirectoryA",
    "GetACP",
    "lstrcmpW",
    "lstrlenW",
    "RtlMoveMemory",
    "GetLastError",
    "SetLastError",
    "GetProcAddress",
    "VirtualAlloc",
    "QueueUserAPC",
    "DisableThreadLibraryCalls",
    "LoadLibraryA",
    "Process32FirstW",
    "LockResource",
    "CreateEventW",
    "Process32NextW",
    "DebugSetProcessKillOnExit",
    "GetModuleHandleA",
    "EraseTape",
    "IsDebuggerPresent",
    "CreateToolhelp32Snapshot",
    "CloseHandle",
    "GetCurrentProcessId",
    "TlsFree",
    "lstrcpyW",
    "KERNEL32.dll",
    "SetWindowTextW",
    "FindWindowA",
    "CheckRadioButton",
    "EndDialog",
    "SetWinEventHook",
    "LoadAcceleratorsW",
    "MessageBeep",
    "AttachThreadInput",
    "SendDlgItemMessageA",
    "CharUpperBuffW",
    "SetCursor",
    "USER32.dll",
    "SetDIBits",
    "CreateDCW",
    "GetTextMetricsW",
    "GDI32.dll",
    "OpenPrinter2A",
    "OpenPrinterW",
    "WINSPOOL.DRV",
    "CreateServiceA"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 3,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2468
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 12.22,
  "size_bytes": 160256,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
    "file_name": "space1.ex",
    "file_path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
    "file_size": 160256,
    "type": "PE",
    "architecture": "X86",
    "entropy": 176,
    "sha256": "5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da",
    "metadata": {},
    "entrypoint_ea": 6944,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 45
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 3584,
        "virtual_size": 4096,
        "rights": "RX",
        "entropy": 124
      },
      {
        "name": ".rdata",
        "effective_address": 5120,
        "physical_size": 2560,
        "virtual_size": 4096,
        "rights": "RX",
        "entropy": 129
      },
      {
        "name": ".rdata",
        "effective_address": 9216,
        "physical_size": 2560,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 82
      },
      {
        "name": ".data",
        "effective_address": 13312,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 78
      },
      {
        "name": ".rsrc",
        "effective_address": 17408,
        "physical_size": 150016,
        "virtual_size": 151552,
        "rights": "R",
        "entropy": 179
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "BigResourceHighEntropy",
        "desc": "File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture",
        "category": "resources",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
        "num_hits": 3
      },
      {
        "name": "DuplicatedSectionName",
        "desc": "section name has already been used before in section table",
        "category": "sections",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynamically",
        "category": "strings",
        "level": 3,
        "num_hits": 3
      },
      {
        "name": "GuiSubsystemNoWindowApi",
        "desc": "A GUI windows application does not import any user32 window-related function",
        "category": "headers",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "RcdataNoDelphi",
        "desc": "File contains a rcdata resource and is not a delphi application",
        "category": "resources",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "SectionWeirdRights",
        "desc": "sections has a standard name but the sections rights are not the usual ones (like .text not having +X\")",
        "category": "sections",
        "le
… [72864 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "create_service pe_imports signals API for creating services (CreateServiceA), indicating potential persistence via servi",
    "execute shellcode via indirect call capa rules Rule detects capability for indirect shellcode execution, a direct malici",
    "FUN_00402640 calls CreateToolhelp32Snapshot, Process32FirstW, Process32NextW Anti Analysis Signals Process enumeration f",
    "IsDebuggerPresent Imports (IDA) Anti-debugging API import, indicating evasion techniques to hinder analysis (T1622). ida",
    "CreateService pe_imports_evidence YARA rule matched for service creation API, supporting evidence of persistence behavio"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "unknown service-based trojan",
  "score": 75,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "create_service",
      "why": "API for creating services (CreateServiceA), indicating potential persistence via service installation (T1543.003)."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "execute shellcode via indirect call",
      "why": "Rule detects capability for indirect shellcode execution, a direct malicious behavior for code execution."
    },
    {
      "source": "ghidra",
      "query_or_table": "Anti Analysis Signals",
      "row_or_rule": "FUN_00402640 calls CreateToolhelp32Snapshot, Process32FirstW, Process32NextW",
      "why": "Process enumeration functions used for discovery (T1057), a common reconnaissance technique in malware."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "IsDebuggerPresent",
      "why": "Anti-debugging API import, indicating evasion techniques to hinder analysis (T1622)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports_evidence",
      "row_or_rule": "CreateService",
      "why": "YARA rule matched for service creation API, supporting evidence of persistence behavior.",
      "source_corrected_from": "yara"
    }
  ],
  "summary": "The PE file space1.ex exhibits clear malicious intent through behavioral signals: anti-debugging (IsDebuggerPresent), process enumeration (CreateToolhelp32Snapshot), service creation for persistence (CreateServiceA), and shellcode execution capabilities (capa rule). Obfuscation techniques (e.g., high entropy, dynamic strings) are present but secondary. Cross-engine analysis confirms consistent fin"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/prompt.txt` exists=`True` bytes=`29069` mtime=`2026-08-09T20:19:36.319470+00:00`
  - sha256: `27c87d8bc3245d787250e177a5b2cbf7c830b8d2d2df53319f5336807dddfaa1`
- **verdict:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/verdict.json` exists=`True` bytes=`4676` mtime=`2026-08-09T20:20:43.153240+00:00`
  - sha256: `bc46166afdc74678a5cfad535654bc6d70791c20c1ca9f624d0567f3195a026d`

#### prompt_excerpt

```
# Triage evidence
sha256: 5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da
sample_path: /opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex
ghidra_session: ghidra-pe-5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da
ida_session: ida-5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — Ghidra=63 and IDA=63 imports, identical counts indicating reliable extraction; malcat=67 is slightly higher but inconsistent with disassemblers.
- functions: ghidra (confidence=high) — Ghidra=33 and IDA=34 functions, very close; malcat=10 is significantly lower, suggesting malcat may not capture all functions accurately.
- strings: both (confidence=high) — Use both engines for comprehensive string extraction; Ghidra=341, IDA=91, Malcat=100 vary, so combining provides better coverage.
- decompilation:
… [28038 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 75,
  "family_guess": "unknown service-based trojan",
  "cross_engine_notes": "Ghidra and IDA both identify process enumeration functions (e.g., CreateToolhelp32Snapshot, Process32FirstW). Malcat anomalies (e.g., BigResourceHighEntropy, CrossSectionJump) and pe_imports high-signal imports (e.g., CreateServiceA, IsDebuggerPresent) align with capa rules for anti-debug, shellcode execution, and persistence. YARA matches include service creation and anti-debug rules. FLOSS strings show API calls consistent with these behaviors.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "create_service",
      "why": "API for creating services (CreateServiceA), indicating potential persistence via service installation (T1543.003)."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "execute shellcode via indirect call",
      "why": "Rule dete
… [3676 more chars]
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
  "rule_count": 11,
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
      "name": "enumerate processes",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Process Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Process Discovery",
          "subtechnique": "",
          "id": "T1057"
        },
        {
          "parts": [
            "Discovery",
            "Software Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Software Discovery",
          "subtechnique": "",
          "id": "T1518"
        }
      ],
      "mbc": []
    },
    {
      "name": "check for trap flag exception",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "",
          "id": "B0001"
        }
      ]
    },
    {
      "name": "find graphical window",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Application Window Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Application Window Discovery",
          "subtechnique": "",
          "id": "T1010"
        }
      ],
      "mbc": []
    },
    {
      "name": "allocate or change RWX memory",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Memory",
            "Allocate Memory"
          ],
          "objective": "Memory",
          "behavior": "Allocate Memory",
          "method": "",
          "id": "C0007"
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
      "name": "link function at runtime on Windows",
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
    },
    {
     
… [1291 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 160256,
  "duration_s": 0.04,
  "import_count": 63,
  "signal_count": 6,
  "signals": [
    {
      "label": "queue_apc",
      "api_match": "QueueUserAPC",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "create_service",
      "api_match": "CreateService",
      "attack": [
        "T1543.003"
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
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 96608,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 7871,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1521,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1540,
          "length": 6,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 3823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d56
… [2988 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2471,
  "strings_sampled": 80,
  "strings": [
    "QueryPerformanceFrequency",
    "QueryPerformanceCounter",
    "IsBadCodePtr",
    "!This program cannot be run in DOS mode.",
    "/uRich",
    "`.rdata",
    "@.data",
    "VC20XC00U",
    ";t$,v-",
    "UQPXY]Y[",
    "URPQQhT",
    "1F;5T@@",
    "bad allocation",
    "kernel32.dll",
    "user32",
    "&*^@QDSJGIO",
    "&JTEH$WHD",
    "fdsfsd,",
    "fdsfds",
    "V><MDNbyfui6y2iuow",
    "fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6",
    "ExitProcess",
    "HeapReAlloc",
    "CreateFileA",
    "FindResourceW",
    "LoadResource",
    "GetCurrentActCtx",
    "GetModuleHandleW",
    "GetCurrentThread",
    "VirtualFree",
    "GetProcessHeap",
    "TlsSetValue",
    "GetConsoleCP",
    "SizeofResource",
    "GetSystemDirectoryA",
    "GetACP",
    "lstrcmpW",
    "lstrlenW",
    "RtlMoveMemory",
    "GetLastError",
    "SetLastError",
    "GetProcAddress",
    "VirtualAlloc",
    "QueueUserAPC",
    "DisableThreadLibraryCalls",
    "LoadLibraryA",
    "Process32FirstW",
    "LockResource",
    "CreateEventW",
    "Process32NextW",
    "DebugSetProcessKillOnExit",
    "GetModuleHandleA",
    "EraseTape",
    "IsDebuggerPresent",
    "CreateToolhelp32Snapshot",
    "CloseHandle",
    "GetCurrentProcessId",
    "TlsFree",
    "lstrcpyW",
    "KERNEL32.dll",
    "SetWindowTextW",
    "FindWindowA",
    "CheckRadioButton",
    "EndDialog",
    "SetWinEventHook",
    "LoadAcceleratorsW",
    "MessageBeep",
    "AttachThreadInput",
    "SendDlgItemMessageA",
    "CharUpperBuffW",
    "SetCursor",
    "USER32.dll",
    "SetDIBits",
    "CreateDCW",
    "GetTextMetricsW",
    "GDI32.dll",
    "OpenPrinter2A",
    "OpenPrinterW",
    "WINSPOOL.DRV",
    "CreateServiceA"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 3,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2468
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.41,
  "size_bytes": 160256,
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
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "disassembly": {
    "0x00402720": "\u250c 556: entry0 ();\n\u2502           0x00402720      6838314000     push str.QHACTIVEDEFENSE.EXE ; 0x403138 ; u\"QHACTIVEDEFENSE.EXE\"\n\u2502           0x00402725      e816ffffff     call 0x402640\n\u2502           0x0040272a      83c404         add esp, 4\n\u2502           0x0040272d      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x0040272f      0f8513020000   jne 0x402948\n\u2502       \u2502   0x00402735      6860314000     push str.QHSAFETRAY.EXE     ; 0x403160 ; u\"QHSAFETRAY.EXE\"\n\u2502       \u2502   0x0040273a      e801ffffff     call 0x402640\n\u2502       \u2502   0x0040273f      83c404         add esp, 4\n\u2502       \u2502   0x00402742      85c0           test eax, eax\n\u2502      \u250c\u2500\u2500< 0x00402744      0f85fe010000   jne 0x402948\n\u2502      \u2502\u2502   0x0040274a      6880314000     push str.QHWATCHDOG.EXE     ; 0x403180 ; u\"QHWATCHDOG.EXE\"\n\u2502      \u2502\u2502   0x0040274f      e8ecfeffff     call 0x402640\n\u2502      \u2502\u2502   0x00402754      83c404         add esp, 4\n\u2502      \u2502\u2502   0x00402757      85c0           test eax, eax\n\u2502     \u250c\u2500\u2500\u2500< 0x00402759      0f85e9010000   jne 0x402948\n\u2502     \u2502\u2502\u2502   0x0040275f      68a0314000     push str.CMDAGENT.EXE       ; 0x4031a0 ; u\"CMDAGENT.EXE\"\n\u2502     \u2502\u2502\u2502   0x00402764      e8d7feffff     call 0x402640\n\u2502     \u2502\u2502\u2502   0x00402769      83c404         add esp, 4\n\u2502     \u2502\u2502\u2502   0x0040276c      85c0           test eax, eax\n\u2502    \u250c\u2500\u2500\u2500\u2500< 0x0040276e      0f85d4010000   jne 0x402948\n\u2502    \u2502\u2502\u2502\u2502   0x00402774      68bc314000     push str.CIS.EXE            ; 0x4031bc ; u\"CIS.EXE\"\n\u2502    \u2502\u2502\u2502\u2502   0x00402779      e8c2feffff     call 0x402640\n\u2502    \u2502\u2502\u2502\u2502   0x0040277e      83c404         add esp, 4\n\u2502    \u2502\u2502\u2502\u2502   0x00402781      85c0           test eax, eax\n\u2502   \u250c\u2500\u2500\u2500\u2500\u2500< 0x00402783      0f85bf010000   jne 0x402948\n\u2502   \u2502\u2502\u2502\u2502\u2502   0x00402789      68cc314000     push str.V3LITE.EXE         ; 0x4031cc ; u\"V3LITE.EXE\"\n\u2502   \u2502\u2502\u2502\u2502\u2502   0x0040278e      e8adfeffff     call 0x402640\n\u2502   \u2502\u2502\u2502\u2502\u2502   0x00402793      83c404         add esp, 4\n\u2502   \u2502\u2502\u2502\u2502\u2502   0x00402796      85c0           test eax, eax\n\u2502  \u250c\u2500\u2500\u2500\u2500\u2500\u2500< 0x00402798      0f85aa010000   jne 0x402948\n\u2502  \u2502\u2502\u2502\u2502\u2502\u2502   0x0040279e      68e4314000     push str.V3MAIN.EXE         ; 0x4031e4 ; u\"V3MAIN.EXE\"\n\u2502  \u2502\u2502\u2502\u2502\u2502\u2502   0x004027a3      e898feffff     call 0x402640\n\u2502  \u2502\u2502\u2502\u2502\u2502\u2502   0x004027a8      83c404         add esp, 4\n\u2502  \u2502\u2502\u2502\u2502\u2502\u2502   0x004027ab      85c0           test eax, eax\n\u2502 \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500< 0x004027ad      0f8595010000   jne 0x402948\n\u2502 \u2502\u2502\u2502\u2502\u2502\u2502\u2502   0x004027b3      68fc314000     push str.V3SP.EXE           ; 0x4031fc ; u\"V3SP.EXE\"\n\u2502 \u2502\u2502\u2502\u2502\u2502\u25
… [1099 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
    "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "YARA 'anti_dbg' rule matched at offsets 7456 and 9106 with strings $d1 (12 bytes) and $c2 (17 bytes)",
    "CAPA: 'enumerate processes' (T1057/T1518), 'check for trap flag exception' (B0001), 'contain obfuscated stackstrings' (T",
    "Entry function (0x402720) calls FUN_00402640 13 times with AV process names: QHACTIVEDEFENSE.EXE, QHSAFETRAY.EXE, QHWATC",
    "Imports include CreateServiceA+OpenSCManagerA (ADVAPI32, service persistence), QueueUserAPC (code injection), VirtualAll",
    "Network-capable imports: InternetOpenA, InternetConnectA, HttpSendRequestA (WININET), WSAStartup, connect, send, recv (W"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Dropper/loader targeting Windows. The entry function systematically enumerates 13 security product processes (360 Security suite, Comodo, AhnLab V3, Dr.Web, ESET) via CreateToolhelp32Snapshot and terminates or evades if detected. After AV evasion, it resolves APIs dynamically (GetProcAddress+LoadLib",
  "key_evidence": [
    "YARA 'anti_dbg' rule matched at offsets 7456 and 9106 with strings $d1 (12 bytes) and $c2 (17 bytes)",
    "CAPA: 'enumerate processes' (T1057/T1518), 'check for trap flag exception' (B0001), 'contain obfuscated stackstrings' (T1027.005), 'allocate or change RWX memory'",
    "Entry function (0x402720) calls FUN_00402640 13 times with AV process names: QHACTIVEDEFENSE.EXE, QHSAFETRAY.EXE, QHWATCHDOG.EXE, CMDAGENT.EXE, CIS.EXE, V3LITE.EXE, V3MAIN.EXE, V3SP.EXE, SPIDERAGENT.EXE, DWENGINE.EXE, DWARKDAEMON.EXE, EGUI.EXE, EKRN.EXE \u2014 each followed by conditional jump to 0x402948 (exit if found)",
    "Imports include CreateServiceA+OpenSCManagerA (ADVAPI32, service persistence), QueueUserAPC (code injection), VirtualAlloc (RWX allocation), DebugSetProcessKillOnExit+IsDebuggerPresent (anti-debug), GetProcAddress+LoadLibraryA (dynamic API resolution), RegOpenKeyA (registry manipulation)",
    "Network-capable imports: InternetOpenA, InternetConnectA, HttpSendRequestA (WININET), WSAStartup, connect, send, recv (WSOCK32)",
    "Obfuscated/garbled strings in data section: '&*^@QDSJGIO', '&JTEH$WHD', 'V><MDNbyfui6y2iuow', 'fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6'",
    "FLOSS decoded 3 stack strings from the binary; entry function has cyclomatic complexity 56 with 62 basic blocks and 19 string references",
    "GDI32 imports (CreateDCW, GetTextMetricsW, SetDIBits) suggest screen capture capability"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "rule": "IP
… [6088 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
    "file_name": "
… [75941 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 11,
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
… [4391 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 160256,
  "duration_s": 0.04,
  "import_count": 63,
  "signal_count": 6,
  "signals": [
    {
      "label": "queue_apc",
      "api_match": "QueueUserAPC",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": 
… [541 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2471,
  "strings_sampled": 80,
  "strings": [
    "QueryPerformanceFrequency",
    "QueryPerformanceCounter",
    "IsBadCodePtr",
    "!This program cannot be run in DOS mode.",
    "/uRich",
    "`.rdata",
    "@.data",
    "VC20XC00U",
    ";t$,v-",
    "UQPXY]Y[",
    "URPQQhT",
    "1F;5T@@",
    "bad allocation",
    "kernel32.dll",
    "user32",
    "&
… [1833 more chars]
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
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "disassembly": {
    "0x00402720": "\u250c 556: entry0 ();\n\u2502           0x00402720      6838314000     push str.QHACTIVEDEFENSE.EXE ; 0x403138 ; u\"QHACTIVEDEFENSE.EXE\"\n\u2502           0x00402725      e816ffffff     call 0
… [4199 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 202
… [23 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r\n",
  "xorsea
… [46 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
    "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
    "exists": true
  }
}
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 3584,
      "entropy": 6.2772,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 2560,
      "entropy": 6.
… [1293 more chars]
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals + emulation oracle + unpack pass

```json
{
  "anti_analysis_summary": {
    "categories": {
      "process_scan": 3
    },
    "total_signals": 3,
    "functions_with_signals": 1,
    "elapsed_s": 0.4,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls":
… [378 more chars]
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
      "name": "__ValidateEH3RN",
      "address": "4199296",
      "size": "818"
    },
    {
      "name": "entry",
      "address": "4204320",
      "size": "561"
    },
    {
      "name": "FUN_00402180",
      "address": "4202880",
      "size": "460"
    },
    {
      "name": "__except_handler4",
      "address": "
… [2349 more chars]
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
      "content": "nPVYYFDZSEDv,SMtSxOdZqe,XzTZwwdG,RRnys,nHIZgAmPu,uwvANxUxMg",
      "address": "4224534",
      "length": "120"
    },
    {
      "content": "fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6",
      "address": "4207312",
      "length": 
… [6362 more chars]
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
      "name": "CreateServiceA",
      "module": "ADVAPI32.DLL",
      "address": "63"
    },
    {
      "name": "OpenSCManagerA",
      "module": "ADVAPI32.DLL",
      "address": "62"
    },
    {
      "name": "RegOpenKeyA",
      "module": "ADVAPI32.DLL",
      "address": "61"
    },
    {
      "name": "CreateDCW",
… [6159 more chars]
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
      "name": "__ValidateEH3RN",
      "address": "4199296",
      "size": "818"
    },
    {
      "name": "entry",
      "address": "4204320",
      "size": "561"
    },
    {
      "name": "FUN_00402180",
      "address": "4202880",
      "size": "460"
    },
    {
      "name": "__except_handler4",
      "address": "
… [1868 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "ref_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_00402180",
      "ref_addr": "4202905",
      "string_value": "kernel32.dll"
    },
    {
      "func_name": "entry",
      "ref_addr": "4204320",
      "string_value": "QHACTIVEDEFENSE.EXE"
    },
    {
      "func_name": "entry",
      "ref_addr": "4204341",
      "string_value": "
… [1493 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "ref_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "entry",
      "ref_addr": "4204837",
      "string_value": "fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id"
… [194 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
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
      "func_name": "__ValidateEH3RN",
      "func_addr": "4199296",
      "size": "818",
      "instruction_count": "261",
      "block_count": "74",
      "cyclomatic_complex
… [9537 more chars]
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
    "func_name",
    "ref_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "entry",
      "ref_addr": "4204320",
      "string_value": "QHACTIVEDEFENSE.EXE"
    },
    {
      "func_name": "entry",
      "ref_addr": "4204341",
      "string_value": "QHSAFETRAY.EXE"
    },
    {
      "func_name": "entry",
      "ref_addr": "4204362",
      "string_value": "QHWAT
… [2109 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
}
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
    "ref_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_00402180",
      "ref_addr": "4202905",
      "string_value": "kernel32.dll"
    },
    {
      "func_name": "FUN_00402180",
      "ref_addr": "4203447",
      "string_value": "user32"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_quer
… [212 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "from_ea",
    "to_ea",
    "kind"
  ],
  "rows": [
    {
      "from_ea": "4204320",
      "to_ea": "4206904",
      "kind": "DATA"
    },
    {
      "from_ea": "4204325",
      "to_ea": "4204096",
      "kind": "UNCONDITIONAL_CALL"
    },
    {
      "from_ea": "4204335",
      "to_ea": "4204872",
      "kind": "CONDITIONAL_JUMP"
    },
    {
      "from_ea": "4204341",
   
… [2879 more chars]
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
      "dst_func_addr": "4199296",
      "dst_func_name": "__ValidateEH3RN",
      "call_site": "4198492"
    },
    {
      "src_func_addr": "0",
      "src_func_name": "sub_0",
      "dst_func_addr":
… [939 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_name",
    "dst_func_name",
    "call_site"
  ],
  "rows": [
    {
      "src_func_name": "entry",
      "dst_func_name": "FUN_00402640",
      "call_site": "4204325"
    },
    {
      "src_func_name": "entry",
      "dst_func_name": "FUN_00402640",
      "call_site": "4204346"
    },
    {
      "src_func_name": "entry",
      "dst_func_name": "FUN_00402640",
     
… [3509 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "from_ea",
    "to_ea",
    "kind"
  ],
  "rows": [
    {
      "from_ea": "4204602",
      "to_ea": "4206716",
      "kind": "READ"
    },
    {
      "from_ea": "4204608",
      "to_ea": "4206664",
      "kind": "READ"
    },
    {
      "from_ea": "4204614",
      "to_ea": "4206768",
      "kind": "READ"
    },
    {
      "from_ea": "4204629",
      "to_ea": "24",
      "k
… [2747 more chars]
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
      "name": "VirtualFree",
      "module": "KERNEL32.DLL",
      "address": "1"
    },
    {
      "name": "GetProcessHeap",
      "module": "KERNEL32.DLL",
      "address": "2"
    },
    {
      "name": "TlsSetValue",
      "module": "KERNEL32.DLL",
      "address": "3"
    },
    {
      "name": "GetConsoleCP",
  
… [6159 more chars]
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
      "content": "CMDAGENT.EXE",
      "address": "4207008"
    },
    {
      "content": "RegOpenKeyA",
      "address": "4208984"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da",
  
… [112 more chars]
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
      "content": "bad allocation",
      "address": "4206864",
      "length": "15"
    },
    {
      "content": "kernel32.dll",
      "address": "4206880",
      "length": "13"
    },
    {
      "content": "user32",
      "address": "4206896",
      "length": "7"
    },
    {
      "content": "QHACTIVEDEFENSE.EXE
… [5809 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 11,
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
… [4390 more chars]
```

- **r2_decompile** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
  "disassembly": {
    "0x00402720": "\u250c 556: entry0 ();\n\u2502           0x00402720      6838314000     push str.QHACTIVEDEFENSE.EXE ; 0x403138 ; u\"QHACTIVEDEFENSE.EXE\"\n\u2502           0x00402725      e816ffffff     call 0
… [4199 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 2471,
  "strings_sampled": 80,
  "strings": [
    "QueryPerformanceFrequency",
    "QueryPerformanceCounter",
    "IsBadCodePtr",
    "!This program cannot be run in DOS mode.",
    "/uRich",
    "`.rdata",
    "@.data",
    "VC20XC00U",
    ";t$,v-",
    "UQPXY]Y[",
    "URPQQhT",
    "1F;5T@@",
    "bad allocation",
    "kernel32.dll",
    "user32",
    "&
… [1833 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/deep_dive/01-tools-raw.json` exists=`True` bytes=`107418` mtime=`2026-08-09T16:31:17.180360+00:00`
  - sha256: `960e17cbe85f6a2ad867aa57dae682962fee8892b4b9c9d122726dc244565a1c`
- **sql_evidence:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/deep_dive/05-deep-dive.json` exists=`True` bytes=`3890` mtime=`2026-08-09T16:34:15.203682+00:00`
  - sha256: `f4c29603906f6c6d797f5bfc05a1a501249fbf08c951ac243eab8f07d0572b58`

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
  "summary": "Dropper/loader targeting Windows. The entry function systematically enumerates 13 security product processes (360 Security suite, Comodo, AhnLab V3, Dr.Web, ESET) via CreateToolhelp32Snapshot and terminates or evades if detected. After AV evasion, it resolves APIs dynamically (GetProcAddress+LoadLibraryA) using an obfuscated API name table, allocates RWX memory via VirtualAlloc, decrypts embedded payload data (garbled strings like '&*^@QDSJGIO', 'V><MDNbyfui6y2iuow'), and uses QueueUserAPC for code injection. It establishes persistence via CreateServiceA/OpenSCManagerA and registry (RegOpenKeyA), and has network capabilities via WININET and WSOCK32 DLLs. Built with MSVC a
… [3090 more chars]
```

- **agentic:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`443822` mtime=`2026-08-09T16:34:15.203682+00:00`
  - sha256: `7e90aeaa989c4b7e85dc76d8799d682b2c89c1d5aa7d346e6be34a67da89feda`

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

- **rule_yar:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/rule.yar` exists=`True` bytes=`1220` mtime=`2026-08-09T16:37:08.302579+00:00`
  - sha256: `0af0c83d35a9e028d009f58e7744df61559aa84bb6e2ed45bb54366237280364`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T16:37:08.302644+00:00
import "pe"
rule CADRE_v2_unknown_5f251ed33fb1 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da"
        family = "unknown"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "QueryPerformanceFrequency" ascii wide
        $s1 = "QueryPerformanceCounter" ascii wide
        $s2 = "IsBadCodePtr" ascii wide
        $s3 = "!This program cannot be run in DOS mode." ascii wide
        $s4 = "VC20XC00U" ascii wide
        $s5 = "UQPXY]Y[" ascii wide
        $s6 = "bad allocation" ascii wide
        $s7 = "kernel32.dll" ascii wi
… [418 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/REPORT-MASTER-v2.md` exists=`True` bytes=`17736` mtime=`2026-08-09T20:22:51.944177+00:00`
  - sha256: `61aaecb9a1027eaa2566bd8c5701148f5a5954c895b4a090bcd1ae2f449cc30c`
- **REPORT_MASTER_v3:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/REPORT-MASTER-v3.md` exists=`True` bytes=`46828` mtime=`2026-08-09T20:35:25.340607+00:00`
  - sha256: `9c5c6cd319e2fd94c1a8cd5a83ff9e1f9b20be2b62f63785ccd8783b2f4493a5`
- **REPORT_v2:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/REPORT-v2.md` exists=`True` bytes=`17736` mtime=`2026-08-09T20:22:51.944177+00:00`
  - sha256: `61aaecb9a1027eaa2566bd8c5701148f5a5954c895b4a090bcd1ae2f449cc30c`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`61569` mtime=`2026-08-09T20:28:30.676337+00:00`
  - sha256: `9c75fde21c96c5beca686bc44bf05088b59a12ecef08d98aebdc8617c811946b`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`53287` mtime=`2026-08-09T20:38:53.986380+00:00`
  - sha256: `042a5de59cadea9f41879874a7a324495eec07f28438601e6274fe7400fa49c4`
- **report_v2_json:** `/opt/samples/logs/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/report-v2.json` exists=`True` bytes=`20395` mtime=`2026-08-09T20:28:30.679338+00:00`
  - sha256: `b05929c92568dc9ead8a9aeb93235cb774fa76aafd617e07aacb76d933cf1aa9`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:22:51 UTC

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

This report details the analysis of a malicious Windows PE executable (`space1.ex`, SHA256: `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`). The sample is a dropper/loader with a primary objective of evading security software, establishing persistence, and executing a secondary payload. It is not a known, named malware family but exhibits characteristics of a service-based trojan.

The malware's 
… [16825 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:35:25 UTC

# RE Report — 5f251ed33fb1
_Generated 2026-08-09T20:35:25.337166+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=255c | cross_refs=True | llm_ok=True | runtime=47.86s -->

# Executive Summary

## Top-line Verdict
- **Verdict**: Malicious
- **Family**: Unknown service-based trojan
- **Confidence**: 90%
- **Summary**: This sample is assessed as malicious with high confidence, based on consistent indicators from multiple analyses. It likely operates as a service-based trojan, focusing on persistence and stealth through Windows service mechanisms.

## Key Findings and Evidence
The f
… [45910 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
