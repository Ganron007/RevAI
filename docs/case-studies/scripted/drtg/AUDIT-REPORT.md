# Pipeline AUDIT-REPORT — `683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T11:28:59.674988+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 11:28:59 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96`

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

- source=`llm_judge` verdict=`malicious` confidence=`90`
- key_evidence_count=`6`

```json
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "Satana ransomware",
  "cross_engine_notes": "Ghidra and IDA both report 28 functions, indicating consistent analysis. MalCat provides static anomalies like XorInLoop and BigBufferNoXrefMediumToHighEntropy, suggesting obfuscation and crypto data. Capa detects anti-VM strings for sandbox evasion, and YARA matches a ransomware dropper rule. VirusTotal corroborates with 67 malicious detections and ransomware threat category. FLOSS strings include base64-encoded data and sensitive APIs for memory manipulation.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "Ransom_Satana_Dropper",
      "row_or_rule": "Ransom_Satana_Dropper",
      "why": "Direct YARA match for known ransomware dropper signature, indicating malicious intent to deliver ransomware payload."
    },
    {
      "source": "capa",
      "query_or_table": "reference anti-VM strings targeting Qemu",
      "row_or_rule": "reference anti-VM strings targeting Qemu",
      "why": "Shows sandbox evasion behavior, a behavioral-intent tactic to avoid detection in analysis environments."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop",
      "why": "XOR instructions in loops suggest encryption or obfuscation routines, commonly used in malware for hiding payloads or data."
    },
    {
      "source": "virustotal",
      "query_or_table": "threat_class",
      "row_or_rule": "popular_threat_category ransomware",
      "why": "VirusTotal identifies high malicious detections (67) with ransomware as a top category, supporting malicious classification based on community intelligence."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "ZwProtectVirtualMemory, NtAllocateVirtualMemory",
      "why": "APIs for virtual memory manipulation, often used in process injection or shellcode execution, indicating potential malicious behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_401e60",
      "why": "Function accesses PEB via PEBx86, a common technique for environment detection and anti-analysis in malware."
    }
  ],
  "summary": "The sample is malicious with high confidence. Key indicators include YARA rule match for ransomware dropper, capa detection of anti-VM evasion, and VirusTotal's widespread malicious detections. Anomalies like XOR loops and base64 strings point to obfuscation and encryption routines, while FLOSS-revealed APIs suggest memory manipulation for malicious purposes. Behavioral signals such as sandbox evasion and environment detection confirm hostile intent beyond mere obfuscation.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 15 matches",
      "capa: 7 rules"
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
    "not_appl
… [3303 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`16`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Satana ransomware dropper with extensive anti-analysis capabilities. The sample matches the Ransom_Satana_Dropper YARA rule with 3 string signatures, contains anti-debugging (ZwGetContextThread, OutputDebugStringA, NtYieldExecution, 4 TLS callbacks executing before entry point), anti-VM/Qemu detection, a massive encoded payload blob with embedded URLs and IPv6 addresses, a Base64 encoding table, and highly obfuscated control flow (cyclomatic complexity 91 in main function). OpenGL API imports (11 functions) serve as anti-sandbox evasion. The dropper contains obfuscated configuration and C2 infrastructure. Persistence mechanisms: not observed. Exfiltration mechanisms: not observed.",
  "key_evidence": [
    "YARA rule 'Ransom_Satana_Dropper' matched with 3 strings at offsets 1264, 1628, 1196 \u2014 direct family identification",
    "YARA rule 'anti_dbg' matched with 2 strings at offsets 690 and 9350 \u2014 anti-debugging techniques present",
    "YARA rule 'Qemu_Detection' matched at offset 44611 \u2014 anti-VM/sandbox evasion",
    "YARA rule 'url' matched at offset 49141 (53 chars) \u2014 embedded URL for C2 or ransom payment",
    "YARA rule 'IP' (IPv6) matched at offset 22282 \u2014 embedded network indicators",
    "YARA rules 'contains_base64' and 'BASE64_table' matched \u2014 encoded payload detected",
    "Ghidra string_refs: 4 TLS callbacks (First_tls, on_tls_callback1, on_tls_callback2, on_tls_callback3) \u2014 code executes before entry point, anti-debugging technique",
    "Ghidra imports: ZwGetContextThread from NTDLL.DLL \u2014 anti-debugging (checks debug context registers)",
    "Ghidra imports: OutputDebugStringA from KERNEL32.DLL \u2014 known anti-debugging technique",
    "Ghidra imports: NtYieldExecution from NTDLL.DLL \u2014 anti-debugging/anti-analysis",
    "Ghidra imports: 11 OpenGL functions (glBegin, glClear, glColor3d, glVertex3d, etc.) from OPENGL32.DLL \u2014 unusual for non-GUI PE, anti-sandbox technique",
    "Ghidra function_metrics: FUN_00401310 has cyclomatic_complexity=91, block_count=91, instruction_count=486, size=2349 \u2014 highly complex obfuscated logic",
    "Ghidra strings: obfuscated string 'qfntvthb' referenced by FUN_00402030 \u2014 likely encoded key or config",
    "Ghidra strings: massive encoded blob (thousands of chars, non-ASCII) at address 0x401B00+ \u2014 encrypted/obfuscated payload or configuration",
    "Malcat static profile: entropy 135, anomalies count 7, file size 50861 \u2014 high entropy consistent with packed/encrypted content",
    "YARA rule 'Safeguard_103_Simonzh' matched at offset 6416 \u2014 additional malware family signature"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 35,
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
  
… [505 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Satana Ransomware Dropper Analysis Report",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 10:25:09 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Satana Ransomware Dropper Analysis Report\n\n## Executive Summary\n\nThis report details the analysis of a malicious Windows PE executable (SHA256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96) identified as a dropper for the Satana ransomware family. The sample exhibits a high degree of sophistication, employing multiple layers of anti-analysis and anti-sandbox evasion techniques to hinder detection and reverse engineering. Key findings include a direct YARA rule match for the Satana ransomware dropper, extensive use of anti-debugging and anti-VM checks, and the presence of a large, obfuscated payload likely containing the ransomware component and C2 infrastructure. The sample's primary function appears to be to deliver and execute the ransomware payload while evading security analysis environments. The verdict is **malicious** with high confidence (90/100). (source: triage_verdict.json)\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96 |\n| **File Path** | /opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe |\n| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |\n| **Architecture** | x86 (32-bit) |\n| **File Size** | 50,861 bytes |\n| **Entropy** | 6.46 bits/byte (Shannon, whole file) |\n| **Compiler/Linker** | MSVC 2010 (Rich Header) |\n| **Import Hash (imphash)** | a3bc0305643e7601d6deca72652f4ab5 |\n| **Packed** | No (UPX probe negative) |\n| **.NET Assembly** | No |\n\nThe file is a standard 32-bit Windows GUI executable. The entropy of 6.46 is elevated but not extreme, suggesting a mix of code and potentially compressed or encrypted data sections, consistent with a dropper containing an obfuscated payload. (source: malcat)\n\n## 2. Classification\n\n**Verdict: MALICIOUS**\n**Family: Satana Ransomware (Dropper)**\n**Confidence: 90/100**\n\nThe classification is based on a convergence of high-confidence signals from multiple analysis engines. The primary indicator is a direct YARA rule match for `Ransom_Satana_Dropper`, which is a specific signature for this malware family's delivery component. This is corroborated by behavioral-intent evidence including anti-VM evasion (targeting Qemu), anti-debugging techniques (TLS callbacks, API hooks), and the presence of a large encoded payload blob. VirusTotal community intelligence also classifies the sample as ransomware with 67 malicious detections. (source: triage_verdict.json, deep-dive.json)\n\n## 3. Background & Family Lineage\n\nThe Satana ransomware family is known for its destructive capabilities, often encrypting user files and demanding ransom payment in cryptocurrency. This sample is identified as a **dropper**, a component whose sole purpose is to deliver and execute the main ransomware payload. Droppers are typically the first stage 
… [15763 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:25:09 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Satana Ransomware Dropper Analysis Report

## Executive Summary

This report details the analysis of a malicious Windows PE executable (SHA256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96) identified as a dropper for the Satana ransomware family. The sample exhibits a high degree of sophistication, employing multiple layers of anti-analysis and anti-sandbox evasion techniques to hinder detection and reverse engineering. Key findings include a direct YARA rule match for the Satana ransomware dropper, extensive use of anti-debugging and anti-VM checks, and the presence of a large, obfuscated payload likely containing the ransomware component and C2 infrastructure. The sample's primary function appears to be to deliver and execute the ransomware payload while evading security analysis environments. The verdict is **malicious** with high confidence (90/100). (source: triage_verdict.json)

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96 |
| **File Path** | /opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **File Size** | 50,861 bytes |
| **Entropy** | 6.46 bits/byte (Shannon, whole file) |
| **Compiler/Linker** | MSVC 2010 (Rich Header) |
| **Import Hash (imphash)** | a3bc0305643e7601d6deca72652f4ab5 |
| **Packed** | No (UPX probe negative) |
| **.NET Assembly** | No |

The file is a standard 32-bit Windows GUI executable. The entropy of 6.46 is elevated but not extreme, suggesting a mix of code and potentially compressed or encrypted data sections, consistent with a dropper containing an obfuscated payload. (source: malcat)

## 2. Classification

**Verdict: MALICIOUS**
**Family: Satana Ransomware (Dropper)**
**Confidence: 90/100**

The classification is based on a convergence of high-confidence signals from multiple analysis engines. The
… [13962 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:38:59 UTC

# RE Report — 683a09da2199
_Generated 2026-08-13T10:38:59.013941+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=243c | cross_refs=True | llm_ok=True | runtime=75.75s -->

## Executive Summary

This section presents the top-line assessment for the malware sample with SHA256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.

**Top-line Verdict:** Malicious  
**Family:** Satana ransomware  
**Confidence:** High (90%)  
**Summary:** The sample is a variant of the Satana ransomware family, identified through static analysis with high confidence based on consistent indicators. It likely engages in destructive behaviors such as file encryption, though dynamic analysis revealed no runtime events, suggesting possible anti-analysis techniques.

### Key Findings

The malicious verdict is supported by agreement between multiple analytical sources (source: cross-section:classification, agreement: llm_and_v1_agree), indicating robust detection.

- **Static Analysis Evidence:** YARA rules matched 15 times, including patterns for ransomware droppers and Satana family signatures (source: yara, why: these matches detect elements like base64 encoding and PE structures common in malicious executables, enhancing detection reliability). Capa identified 7 rules related to capabilities such as encryption, network operations, and anti-analysis (source: capa, why: these rules highlight behaviors like encoding mechanisms and virtualization detection, which are typical of ransomware for data protection and evasion).

- **Dynamic Analysis Honesty:** The sample was executed in the Speakeasy emulation environment and instrumented with Frida probes, as detailed in the behavioral analysis section (source: cross-section:behavioral_analysis). However, no system calls, API invocations, or runtime events were recorded (source: malcat, why: this null result may indicate anti-VM techniques or an inert payload, complicating behavioral assessment but not negating static findings).

- **Family Lineage:** Background analysis confirms the Satana ransomware affiliation, with evidence including base64-encoded data and sensitive APIs in strings, along with anomalies like XOR 
… [44912 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6803` | `784bfa4a933763d1` |
| `prompt.txt` | `True` | `25322` | `05416bd239b0d90d` |
| `pipeline-audit.json` | `True` | `115236` | `79e163fb646cbc98` |
| `AUDIT-REPORT.md` | `True` | `85146` | `bf022d113deed173` |
| `REPORT-MASTER-v2.md` | `True` | `16469` | `f4aab37738e00f13` |
| `REPORT-MASTER-v3.md` | `True` | `47425` | `c6a25b72fc518a29` |
| `REPORT-v2.md` | `True` | `16469` | `f4aab37738e00f13` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `50290` | `81cfd922e7c2a1ef` |
| `rule.yar` | `True` | `1210` | `e63661a180782533` |
| `intake-validation.json` | `True` | `2175` | `412856f4b91b23bb` |
| `source-decisions.json` | `True` | `1336` | `d23f3f0d18410124` |
| `malcat-triage.json` | `True` | `19400` | `427b89b820ac847e` |
| `deep_dive/01-tools-raw.json` | `True` | `59495` | `5b8581356e973afe` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4005` | `11dc6ac6f8781d8c` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `51520` | `3915fcc9bd9a8f00` |

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

- **intake_validation:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/intake-validation.json` exists=`True` bytes=`2175` mtime=`2026-08-12T19:58:23.691207+00:00`
  - sha256: `412856f4b91b23bb4905b32fad073f58848a602b7b68e4bcfd7ec35c42d6fc94`
- **malcat_triage:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/malcat-triage.json` exists=`True` bytes=`19400` mtime=`2026-08-13T10:13:56.301293+00:00`
  - sha256: `427b89b820ac847e7957d0f0a8f6dabd7d6eeda525b26f96ae0cb613869d9a14`
- **source_decisions:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/source-decisions.json` exists=`True` bytes=`1336` mtime=`2026-08-12T19:58:23.691207+00:00`
  - sha256: `d23f3f0d18410124e2144db9fd208006e76cd929e35bd3780c2d6acfe99e5b70`
- **ghidra_import_log:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/intake-analyzeHeadless.log` exists=`True` bytes=`6098` mtime=`2026-08-12T19:57:23.397290+00:00`
  - sha256: `c63ebffa4f96826ff4738c9abd4083e3b922b30cbc9e1724a5616c0002a1e34c`
- **ida_bootstrap_log:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/intake-idasql.log` exists=`True` bytes=`211` mtime=`2026-08-12T19:57:24.730289+00:00`
  - sha256: `500dcef9e5ce0f3521acd11a38d129e8ccd630c785b84aeb21a9f98acadecc0e`

#### source_decisions_excerpt

```
{
  "sha256": "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra reports 21 imports, matching IDA's 21 and malcat's imports_count of 21, indicating consistent data for import analysis."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra and IDA both report 28 functions, while malcat reports 10; ghidra provides reliable detailed function disassembly."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Malcat reports 100 strings, IDA reports 94, and Ghidra reports 44; combining both malcat and IDA ensures comprehensive string coverage."
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "medium",
  
… [559 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
    "file_name": "drtg.exe",
    "file_path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
    "file_size": 50861,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.46,
    "sha256": "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96",
    "metadata": {
      "Debug::Date.Debug.Fixup": "2009-11-10 10:17:40"
    },
    "entrypoint_ea": 6416,
    "layout": [
   
… [18600 more chars]
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
  "rule_count": 7,
  "top_rules": [
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
      "name": "reference anti-VM strings targeting Qemu",
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
      "name": "inspect section memory permissions",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "Code Discovery",
            "Inspect Section Memory Permissions"
          ],
          "objective": "Discovery",
          "behavior": "Code Discovery",
          "method": "Inspect Section Memory Permissions",
          "id": "B0046.002"
        }
      ]
    },
    {
      "name": "parse PE header",
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
      "name": "contains PDB path",
      "attack": [],
      "mbc": []
    },
    {
      "name": "print debug messages",
      "attack": [],
      "mbc": []
    },
    {
      "name": "resolve function by parsing PE exports",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 300,
  "sample_size": 50861,
  "duration_s": 1.69,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 22282,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1216,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Qemu_Detection",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 44611,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "BASE64_table",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 47688,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 49141,
          "length": 53,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
      "rule": "Safeguard_103_Simonzh",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 6416,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Check_OutputDebugStringA_iat",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/6
… [3582 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 145,
  "strings_sampled": 80,
  "strings": [
    "ZwProtectVirtualMemory",
    "ZwWriteVirtualMemory",
    "GetModuleFileNameW",
    "FlushInstructionCache",
    "ZwUnmapViewOfSection",
    "4siPKFd;`U7v`U0VcPGjirHv`fWPIVuSGQ2TISePjPGf[1KP30Lv0UQeVLWP`AEeVFiD@@6PVP2dCemdFCCPVS6OCuOAEW2PFujLJzeFVSSPC22rKh7LCCIPASjF[E@lQPUZ",
    "NtAllocateVirtualMemory",
    "?456789:;<=",
    "!\"#$%&'()*+,-./0123",
    "SetUnhandledExceptionFilter",
    "RtlDecompressBuffer",
    "!This program cannot be run in DOS mode.",
    "`.data",
    "@.reloc",
    "ntdll.dll",
    "KERNEL32.dll",
    "USER32.dll",
    "OPENGL32.dll",
    "kaxkytpp",
    "qfntvthb",
    "ZwGetContextThread",
    "MyUnhandledExceptionFilter",
    "%s-TryExcept",
    "EntryPoint",
    "First_tls",
    "on_tls_callback1",
    "on_tls_callback2",
    "on_tls_callback3",
    "@ffffff",
    "?333333",
    "333333",
    "d:\\lbetwmwy\\uijeuqplfwub.pdb",
    "YUSW_[]",
    "^SP@X[Q=",
    "QSVWh(",
    "Rj@ZZQ}",
    "Ilz`_R",
    "UWRjyZZ_]PP|",
    "_P@XUf",
    "UjS]]f",
    "t.VGWP",
    "Vjt^^v",
    "WjI__Uw",
    "Sj*[[]",
    "WRWO_Z_s",
    "_stricmp",
    "vsprintf",
    "memmove",
    "NtYieldExecution",
    "strchr",
    "strncpy",
    "GetLocalTime",
    "OutputDebugStringA",
    "MessageBoxA",
    "glClear",
    "glPointSize",
    "glVertex3d",
    "glLineStipple",
    "glDisable",
    "glBegin",
    "glColor3d",
    "glPolygonMode",
    "glLineWidth",
    "glEnable",
    "memset",
    "DfGmmxhAmp",
    "qwvywvszdcvle",
    "Veu[qljtotrrP",
    "tydqcgfwwka",
    "ythlbnzpc",
    "ewsyeor",
    "panamkve",
    "5rhQJGe:aT6waT1WbQFkhsIwagVQHWtRFP3UHRdQkQFgZ0JQ21Mw1TPdWMVQa@DdWGhEAA7QWQ3eBdleGBBQWR7NBtN@DV3QGtkMK{dGWRRQB33sJi6MBBHQ@RkGZDAmPQT[FQTV3SsQ:a5sVARPTJ3wrU3QEi7A5qrsV{NTwHoRBAFT3vntF{YQ:a;UrP3QEruTs5oP",
    "jmenfrhmjebkjhainycnyvrdfclb",
    "Bg~Tyfm`j~J`~Kobm",
    "asdzfk",
    "@bMrbRmmft",
    "aijrjgxt",
    "vannql",
    "!)#);'"
  ],
  "per_category": {
    "decoded_strings": 15,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 130
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 7.21,
  "size_bytes": 50861,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
    "file_name": "drtg.exe",
    "file_path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
    "file_size": 50861,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.46,
    "sha256": "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96",
    "metadata": {
      "Debug::Date.Debug.Fixup": "2009-11-10 10:17:40"
    },
    "entrypoint_ea": 6416,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 52
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 8704,
        "virtual_size": 12288,
        "rights": "RX",
        "entropy": 124
      },
      {
        "name": ".data",
        "effective_address": 13312,
        "physical_size": 38912,
        "virtual_size": 40960,
        "rights": "RW",
        "entropy": 144
      },
      {
        "name": ".rsrc",
        "effective_address": 54272,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 89
      },
      {
        "name": ".reloc",
        "effective_address": 58368,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 19
      },
      {
        "name": "overlay",
        "effective_address": 62464,
        "physical_size": 173,
        "virtual_size": 0,
        "rights": "",
        "entropy": 170
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 135,
    "entropy_source": "whole_file_shannon_revai"
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
        "name": "BoundImports",
        "desc": "Bound imports are present",
        "category": "imports",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "ManyUniqueImmediateBytes",
        "desc": "More than 48 unique bytes defined across all immediate operands in the function",
        "category": "code",
        "level": 3,
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
        "name": "StringBase64",
        "desc": "string has more than 16 characters is encoded using base64",
        "category": "strings",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "WeirdDebugInfoType",
        "desc": "the Debug infos are not in the usual format",
        "category": "headers",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "XorInLoop",
        "desc": "XOR instruction in a loop",
        "category": "co
… [26624 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "Ransom_Satana_Dropper Ransom_Satana_Dropper Direct YARA match for known ransomware dropper signature, indicating malicio",
    "reference anti-VM strings targeting Qemu reference anti-VM strings targeting Qemu Shows sandbox evasion behavior, a beha",
    "XorInLoop anomalies XOR instructions in loops suggest encryption or obfuscation routines, commonly used in malware for h",
    "popular_threat_category ransomware threat_class VirusTotal identifies high malicious detections (67) with ransomware as ",
    "ZwProtectVirtualMemory, NtAllocateVirtualMemory strings APIs for virtual memory manipulation, often used in process inje"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Satana ransomware",
  "score": 90,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "Ransom_Satana_Dropper",
      "row_or_rule": "Ransom_Satana_Dropper",
      "why": "Direct YARA match for known ransomware dropper signature, indicating malicious intent to deliver ransomware payload."
    },
    {
      "source": "capa",
      "query_or_table": "reference anti-VM strings targeting Qemu",
      "row_or_rule": "reference anti-VM strings targeting Qemu",
      "why": "Shows sandbox evasion behavior, a behavioral-intent tactic to avoid detection in analysis environments."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop",
      "why": "XOR instructions in loops suggest encryption or obfuscation routines, commonly used in malware for hiding payloads or data."
    },
    {
      "source": "virustotal",
      "query_or_table": "threat_class",
      "row_or_rule": "popular_threat_category ransomware",
      "why": "VirusTotal identifies high malicious detections (67) with ransomware as a top category, supporting malicious classification based on community intelligence."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "ZwProtectVirtualMemory, NtAllocateVirtualMemory",
      "why": "APIs for virtual memory manipulation, often used in process injection or shellcode execution, indicating potential malicious behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_401e60",
      "why": "Function accesses PEB via PEBx86, a common technique for environment detection and anti-analysis in malware."
    }
  ],
  "summary": "The sample is malicious with high confidence. Key indicators include YARA rule match for ransomware dropper, capa detection of anti-VM evasion, and VirusTotal's widespread malicious detections. Anomalies like XOR loops and base64 strings point to obfuscation and encryption routines, while FLOSS-revealed APIs suggest memory manipulation for malicious purposes. Behavioral signals such as sandbox eva"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/prompt.txt` exists=`True` bytes=`25322` mtime=`2026-08-13T10:14:19.857332+00:00`
  - sha256: `05416bd239b0d90d1660d6b4f3b833995f96cda0a0a577918fd561122e5b7fd1`
- **verdict:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/verdict.json` exists=`True` bytes=`6803` mtime=`2026-08-13T10:16:00.940811+00:00`
  - sha256: `784bfa4a933763d1343becb93a232a97e829bfb7b352b7bcc58ed0cc1751135e`

#### prompt_excerpt

```
# Triage evidence
sha256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96
sample_path: /opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe
ghidra_session: ghidra-pe-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96
ida_session: ida-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — Ghidra reports 21 imports, matching IDA's 21 and malcat's imports_count of 21, indicating consistent data for import analysis.
- functions: ghidra (confidence=high) — Ghidra and IDA both report 28 functions, while malcat reports 10; ghidra provides reliable detailed function disassembly.
- strings: both (confidence=high) — Malcat reports 100 strings, IDA reports 94, and Ghidra reports 44; combining both malcat and IDA ensures comprehensive string coverage.
- decompilation: ghidra (confidence=medium) — Ghidra is a default choice for
… [24276 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "Satana ransomware",
  "cross_engine_notes": "Ghidra and IDA both report 28 functions, indicating consistent analysis. MalCat provides static anomalies like XorInLoop and BigBufferNoXrefMediumToHighEntropy, suggesting obfuscation and crypto data. Capa detects anti-VM strings for sandbox evasion, and YARA matches a ransomware dropper rule. VirusTotal corroborates with 67 malicious detections and ransomware threat category. FLOSS strings include base64-encoded data and sensitive APIs for memory manipulation.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "Ransom_Satana_Dropper",
      "row_or_rule": "Ransom_Satana_Dropper",
      "why": "Direct YARA match for known ransomware dropper signature, indicating malicious intent to deliver ransomware payload."
    },
    {
      "source": "capa",
      "query_or_table": "reference anti-VM strings targeting Qemu",
      "row_or_rule": "reference anti-VM str
… [5803 more chars]
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
  "rule_count": 7,
  "top_rules": [
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
      "name": "reference anti-VM strings targeting Qemu",
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
      "name": "inspect section memory permissions",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "Code Discovery",
            "Inspect Section Memory Permissions"
          ],
          "objective": "Discovery",
          "behavior": "Code Discovery",
          "method": "Inspect Section Memory Permissions",
          "id": "B0046.002"
        }
      ]
    },
    {
      "name": "parse PE header",
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
      "name": "contains PDB path",
      "attack": [],
      "mbc": []
    },
    {
      "name": "print debug messages",
      "attack": [],
      "mbc": []
    },
    {
      "name": "resolve function by parsing PE exports",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 60,
  "sample_size": 50861,
  "duration_s": 0.89,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 50861,
  "duration_s": 0.03,
  "import_count": 21,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 22282,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1216,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Qemu_Detection",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 44611,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "BASE64_table",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 47688,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 49141,
          "length": 53,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
      "rule": "Safeguard_103_Simonzh",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 6416,
          "length": 5,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Check_OutputDebugStringA_iat",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
      "strings": []
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/6
… [3560 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 145,
  "strings_sampled": 80,
  "strings": [
    "ZwProtectVirtualMemory",
    "ZwWriteVirtualMemory",
    "GetModuleFileNameW",
    "FlushInstructionCache",
    "ZwUnmapViewOfSection",
    "4siPKFd;`U7v`U0VcPGjirHv`fWPIVuSGQ2TISePjPGf[1KP30Lv0UQeVLWP`AEeVFiD@@6PVP2dCemdFCCPVS6OCuOAEW2PFujLJzeFVSSPC22rKh7LCCIPASjF[E@lQPUZ",
    "NtAllocateVirtualMemory",
    "?456789:;<=",
    "!\"#$%&'()*+,-./0123",
    "SetUnhandledExceptionFilter",
    "RtlDecompressBuffer",
    "!This program cannot be run in DOS mode.",
    "`.data",
    "@.reloc",
    "ntdll.dll",
    "KERNEL32.dll",
    "USER32.dll",
    "OPENGL32.dll",
    "kaxkytpp",
    "qfntvthb",
    "ZwGetContextThread",
    "MyUnhandledExceptionFilter",
    "%s-TryExcept",
    "EntryPoint",
    "First_tls",
    "on_tls_callback1",
    "on_tls_callback2",
    "on_tls_callback3",
    "@ffffff",
    "?333333",
    "333333",
    "d:\\lbetwmwy\\uijeuqplfwub.pdb",
    "YUSW_[]",
    "^SP@X[Q=",
    "QSVWh(",
    "Rj@ZZQ}",
    "Ilz`_R",
    "UWRjyZZ_]PP|",
    "_P@XUf",
    "UjS]]f",
    "t.VGWP",
    "Vjt^^v",
    "WjI__Uw",
    "Sj*[[]",
    "WRWO_Z_s",
    "_stricmp",
    "vsprintf",
    "memmove",
    "NtYieldExecution",
    "strchr",
    "strncpy",
    "GetLocalTime",
    "OutputDebugStringA",
    "MessageBoxA",
    "glClear",
    "glPointSize",
    "glVertex3d",
    "glLineStipple",
    "glDisable",
    "glBegin",
    "glColor3d",
    "glPolygonMode",
    "glLineWidth",
    "glEnable",
    "memset",
    "DfGmmxhAmp",
    "qwvywvszdcvle",
    "Veu[qljtotrrP",
    "tydqcgfwwka",
    "ythlbnzpc",
    "ewsyeor",
    "panamkve",
    "5rhQJGe:aT6waT1WbQFkhsIwagVQHWtRFP3UHRdQkQFgZ0JQ21Mw1TPdWMVQa@DdWGhEAA7QWQ3eBdleGBBQWR7NBtN@DV3QGtkMK{dGWRRQB33sJi6MBBHQ@RkGZDAmPQT[FQTV3SsQ:a5sVARPTJ3wrU3QEi7A5qrsV{NTwHoRBAFT3vntF{YQ:a;UrP3QEruTs5oP",
    "jmenfrhmjebkjhainycnyvrdfclb",
    "Bg~Tyfm`j~J`~Kobm",
    "asdzfk",
    "@bMrbRmmft",
    "aijrjgxt",
    "vannql",
    "!)#);'"
  ],
  "per_category": {
    "decoded_strings": 15,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 130
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 6.7,
  "size_bytes": 50861,
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
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
  "disassembly": {
    "0x00402510": "\u250c 11: entry0 ();\n\u2502           0x00402510      e8fb000000     call fcn.00402610\n\u2502           0x00402515      a164104000     mov eax, dword [0x401064]   ; [0x401064:4]=0x5de7afeb\n\u2514           0x0040251a      c3             ret",
    "0x00402610": "; CALL XREF from entry0 @ 0x402510(x)\n\u250c 549: fcn.00402610 ();\n\u2502           ; var int32_t var_4h @ esp+0xc\n\u2502           ; var int32_t var_8h @ esp+0x24\n\u2502           ; var int32_t var_10h @ esp+0x28\n\u2502           0x00402610      8bff           mov edi, edi\n\u2502           0x00402612      55             push ebp\n\u2502           0x00402613      8bec           mov ebp, esp\n\u2502           0x00402615      83e4f8         and esp, 0xfffffff8\n\u2502           0x00402618      83ec14         sub esp, 0x14\n\u2502           0x0040261b      56             push esi\n\u2502           0x0040261c      6800114000     push 0x401100               ; \"EntryPoint\"\n\u2502           0x00402621      680c114000     push 0x40110c               ; '\\f\\x11@' ; \"%s\"\n\u2502           0x00402626      e8a5ecffff     call 0x4012d0\n\u2502           0x0040262b      83c408         add esp, 8\n\u2502           0x0040262e      e84decffff     call 0x401280\n\u2502           0x00402633      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x00402635      7416           je 0x40264d\n\u2502       \u2502   0x00402637      8d442408       lea eax, [var_8h]\n\u2502       \u2502   0x0040263b      50             push eax\n\u2502       \u2502   0x0040263c      ff1500104000   call dword [sym.imp.KERNEL32.dll_GetLocalTime] ; 0x401000 ; \"1H\\x02\" ; VOID GetLocalTime(LPSYSTEMTIME lpSystemTime)\n\u2502       \u2502   0x00402642      0fb74c2410     movzx ecx, word [var_10h]\n\u2502       \u2502   0x00402647      890d94d54000   mov dword [0x40d594], ecx   ; [0x40d594:4]=0\n\u2502       \u2514\u2500> 0x0040264d      6800114000     push 0x401100               ; \"EntryPoint\"\n\u2502           0x00402652      6810114000     push 0x401110               ; '\\x10\\x11@' ; \"%s-2\"\n\u2502           0x00402657      e874ecffff     call 0x4012d0\n\u2502           0x0040265c      83c408         add esp, 8\n\u2502           0x0040265f      e8acecffff     call 0x401310\n\u2502           0x00402664      6a72           push 0x72                   ; 'r' ; 114\n\u2502           0x00402666      e8d5010000     call 0x402840\n\u2502           0x0040266b      b838ebf906     mov eax, 0x6f9eb38\n\u2502       \u250c\u2500> 0x00402670      52             push edx\n\u2502       \u254e   0x00402671      51             push ecx\n\u2502      \u250c\u2500\u2500< 0x00402672      7c03           jl 0x402677\n\u2502      \u2502\u254e   0x00402674      660bc0         or ax, ax\n\u2502      \u2514\u2500\u2500> 0x00402677      59             pop ecx\n\u2502       \u254e   0x00402678      5a             pop edx\n\u2502       \u254e   0x00402679      45             inc ebp\n\u2502       \u254e   0x0040267a      4d             dec ebp\n\u2502       \u254e   0x0040267b      80c000         add al, 0\n\u2502       \u254e   0x0040267e      81fb46c98d5b   cmp ebx, 0x5b8dc946\n\u2502       \u254e   0x00402684      55             push ebp\n\u2502       \u254e   0x00402685      83c600         add esi, 0\n\u2502       \u254e   0x00402688      5d             p
… [567 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
    "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
    "exists": true,
    "hook_candidates": [
      "ntdll.dll!vsprintf",
      "ntdll.dll!memmove",
      "ntdll.dll!NtYieldExecution",
      "ntdll.dll!strchr",
      "ntdll.dll!strncpy",
      "KERNEL32.dll!GetLocalTime",
      "KERNEL32.dll!OutputDebugStringA",
      "USER32.dll!MessageBoxA",
      "OPENGL32.dll!glEnd",
      "OPENGL32.dll!glEnable",
      "OPENGL32.dll!glLineWidth",
      "OPENGL32.dll!glPolygonMode",
      "OPENGL32.dll!glColor3d"
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
  "checked": 16,
  "hits": 16,
  "misses": [],
  "hit_examples": [
    "YARA rule 'Ransom_Satana_Dropper' matched with 3 strings at offsets 1264, 1628, 1196 \u2014 direct family identification",
    "YARA rule 'anti_dbg' matched with 2 strings at offsets 690 and 9350 \u2014 anti-debugging techniques present",
    "YARA rule 'Qemu_Detection' matched at offset 44611 \u2014 anti-VM/sandbox evasion",
    "YARA rule 'url' matched at offset 49141 (53 chars) \u2014 embedded URL for C2 or ransom payment",
    "YARA rule 'IP' (IPv6) matched at offset 22282 \u2014 embedded network indicators"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Satana ransomware dropper with extensive anti-analysis capabilities. The sample matches the Ransom_Satana_Dropper YARA rule with 3 string signatures, contains anti-debugging (ZwGetContextThread, OutputDebugStringA, NtYieldExecution, 4 TLS callbacks executing before entry point), anti-VM/Qemu detecti",
  "key_evidence": [
    "YARA rule 'Ransom_Satana_Dropper' matched with 3 strings at offsets 1264, 1628, 1196 \u2014 direct family identification",
    "YARA rule 'anti_dbg' matched with 2 strings at offsets 690 and 9350 \u2014 anti-debugging techniques present",
    "YARA rule 'Qemu_Detection' matched at offset 44611 \u2014 anti-VM/sandbox evasion",
    "YARA rule 'url' matched at offset 49141 (53 chars) \u2014 embedded URL for C2 or ransom payment",
    "YARA rule 'IP' (IPv6) matched at offset 22282 \u2014 embedded network indicators",
    "YARA rules 'contains_base64' and 'BASE64_table' matched \u2014 encoded payload detected",
    "Ghidra string_refs: 4 TLS callbacks (First_tls, on_tls_callback1, on_tls_callback2, on_tls_callback3) \u2014 code executes before entry point, anti-debugging technique",
    "Ghidra imports: ZwGetContextThread from NTDLL.DLL \u2014 anti-debugging (checks debug context registers)",
    "Ghidra imports: OutputDebugStringA from KERNEL32.DLL \u2014 known anti-debugging technique",
    "Ghidra imports: NtYieldExecution from NTDLL.DLL \u2014 anti-debugging/anti-analysis",
    "Ghidra imports: 11 OpenGL functions (glBegin, glClear, glColor3d, glVertex3d, etc.) from OPENGL32.DLL \u2014 unusual for non-GUI PE, anti-sandbox technique",
    "Ghidra function_metrics: FUN_00401310 has cyclomatic_complexity=91, block_count=91, instruction_count=486, size=2349 \u2014 highly complex obfuscated logic",
    "Ghidra strings: obfuscated string 'qfntvthb' referenced by FUN_00402030 \u2014 likely encoded key or config",
    "Ghidra strings: massive encoded blob (thousands of chars, non-ASCII) at address 0x401B00+ \u2014 encrypted/obfuscated payload or configuration",
    "Malcat static profile: entropy 135, anomalies count 7, file size 50861 \u2014 high entropy consistent with packed/encrypted content",
    "YARA rule 'Safeguard_103_Simonzh' matched at offset 6416 \u2014 additional malware family signature"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
      "path": "/opt/samples/c
… [6660 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
    "file_name": "drtg.exe",
    "file_path": "/op
… [29567 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 7,
  "top_rules": [
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
      
… [2395 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 50861,
  "duration_s": 0.03,
  "import_count": 21,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 145,
  "strings_sampled": 80,
  "strings": [
    "ZwProtectVirtualMemory",
    "ZwWriteVirtualMemory",
    "GetModuleFileNameW",
    "FlushInstructionCache",
    "ZwUnmapViewOfSection",
    "4siPKFd;`U7v`U0VcPGjirHv`fWPIVuSGQ2TISePjPGf[1KP30Lv0UQeVLWP`AEeVFiD@@6PVP2dCemdFCCPVS6OCuOAEW2PFujLJzeFVSSPC22rKh7LCCIPASjF[E@lQPUZ",
    "NtAllocateVirtualMemory",
   
… [1963 more chars]
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
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
  "disassembly": {
    "0x00402510": "\u250c 11: entry0 ();\n\u2502           0x00402510      e8fb000000     call fcn.00402610\n\u2502           0x00402515      a164104000     mov eax, dword [0x401064]   ; [0x401064:4]=0x5de7afeb\n\u2514           0x0040251a      
… [3667 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_re
… [14 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
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
    "path": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
    "exists": true,
    "hook_candidates": [
      "ntdll.dll!vsprintf",
      "ntdll.dll!memmove",
      "ntdll.dll!NtYieldExecution",
      "ntdll.dll!strchr",
      "ntdll.dll!strncpy",
      "KERNEL32.dll
… [260 more chars]
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": true,
  "sample": "/opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 8704,
      "entropy": 6.3566,
      "executable": true,
      "writable": false
    },
    {
      "name": ".data",
      "size": 38912,
      "entropy": 5.9859,
      "executable": false,
… [1120 more chars]
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
  "sink_count": 2,
  "sinks": [
    {
      "api": "vsprintf",
      "dll": "ntdll.dll",
      "class": "format_string",
      "address": "0x4012ea",
      "function": "fcn.004012d0"
    },
    {
      "api": "memmove",
      "dll": "ntdll.dll",
      "class": "unbounded_copy",
      "address": "0x401e50",
      "function": "fcn.00401c50"
    }
  ],
 
… [59 more chars]
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
    "elapsed_s": 0.45,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.21,
 
… [101 more chars]
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
      "name": "FUN_00401310",
      "address": "4199184",
      "size": "2349"
    },
    {
      "name": "FUN_00402030",
      "address": "4202544",
      "size": "1032"
    },
    {
      "name": "FUN_00402610",
      "address": "4204048",
      "size": "549"
    },
    {
      "name": "FUN_00401c50",
      "address": 
… [2236 more chars]
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
      "name": "GetLocalTime",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "OutputDebugStringA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "NtYieldExecution",
      "module": "NTDLL.DLL"
    },
    {
      "name": "_stricmp",
      "module": "NTDLL.DLL"
    },
    {
      "name": "memmove",
      "module"
… [1446 more chars]
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
      "content": "ntdll.dll",
      "address": "4194984",
      "length": "10"
    },
    {
      "content": "KERNEL32.dll",
      "address": "4194994",
      "length": "13"
    },
    {
      "content": "USER32.dll",
      "address": "4195007",
      "length": "11"
    },
    {
      "content": "OPENGL32.dll",
    
… [5095 more chars]
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
      "name": "FUN_00401280",
      "address": "4199040",
      "size": "25"
    },
    {
      "name": "FUN_004012a0",
      "address": "4199072",
      "size": "13"
    },
    {
      "name": "FUN_004012b0",
      "address": "4199088",
      "size": "7"
    },
    {
      "name": "FUN_004012c0",
      "address": "41991
… [2497 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.json"
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
      "content": "ntdll.dll",
      "address": "4194984",
      "length": "10"
    },
    {
      "content": "KERNEL32.dll",
      "address": "4194994",
      "length": "13"
    },
    {
      "content": "USER32.dll",
      "address": "4195007",
      "length": "11"
    },
    {
      "content": "OPENGL32.dll",
    
… [5095 more chars]
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
      "content": "NtYieldExecution",
      "address": "4206660",
      "length": "17"
    },
    {
      "content": "5rhQJGe:aT6waT1WbQFkhsIwagVQHWtRFP3UHRdQkQFgZ0JQ21Mw1TPdWMVQa@DdWGhEAA7QWQ3eBdleGBBQWR7NBtN@DV3QGtkMK{dGWRRQB33sJi6MBBHQ@RkGZDAmPQT[FQTV3SsQ:a5sVARPTJ3wrU3QEi7A5qrsV{NTwHoRBAFT3vntF{YQ:a;UrP3QEruTs5oP
… [37193 more chars]
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
      "content": "OutputDebugStringA",
      "address": "4206726",
      "length": "19"
    },
    {
      "content": "5rhQJGe:aT6waT1WbQFkhsIwagVQHWtRFP3UHRdQkQFgZ0JQ21Mw1TPdWMVQa@DdWGhEAA7QWQ3eBdleGBBQWR7NBtN@DV3QGtkMK{dGWRRQB33sJi6MBBHQ@RkGZDAmPQT[FQTV3SsQ:a5sVARPTJ3wrU3QEi7A5qrsV{NTwHoRBAFT3vntF{YQ:a;UrP3QEruTs5
… [37195 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name",
    "ref_addr"
  ],
  "rows": [
    {
      "content": "First_tls",
      "func_name": "sub_401E60",
      "ref_addr": "4202089"
    },
    {
      "content": "ZwGetContextThread",
      "func_name": "sub_402030",
      "ref_addr": "4202845"
    },
    {
      "content": "on_tls_callback1",
      "func_name": "sub_402520",
      "ref_addr": "4203808
… [75872 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

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
  "source": "ida_query",
  "session_id": "ida-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96",
  "audit_path": "/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

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
  "source": "ida_query",
  "session_id": "ida-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96",
  "audit_path": "/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

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
  "source": "ida_query",
  "session_id": "ida-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96",
  "audit_path": "/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/audit.jsonl"
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
      "content": "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application xml
… [980 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "5rhQJGe:aT6waT1WbQFkhsIwagVQHWtRFP3UHRdQkQFgZ0JQ21Mw1TPdWMVQa@DdWGhEAA7QWQ3eBdleGBBQWR7NBtN@DV3QGtkMK{dGWRRQB33sJi6MBBHQ@RkGZDAmPQT[FQTV3SsQ:a5sVARPTJ3wrU3QEi7A5qrsV{NTwHoRBAFT3vntF{YQ:a;UrP3QEruTs5oPpkVjFGYHbAFUEjNWMjF,AB7EFBlVvi3lFT2wJT{saWN7ERN5EBHMaV:pYiEpY12wMQF[QTz7h{kMLQFWeYFRKYTW3IBVa12wbD1PKsRP[T0ghQJQj
… [37055 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

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
  "source": "ida_query",
  "session_id": "ida-683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96",
  "audit_path": "/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_addr",
    "func_name",
    "size",
    "instruction_count",
    "block_count",
    "edge_count",
    "cyclomatic_complexity",
    "call_in_count",
    "call_out_count",
    "string_ref_count",
    "token_count"
  ],
  "rows": [
    {
      "func_addr": "4199184",
      "func_name": "FUN_00401310",
      "size": "2349",
      "instruction_count": "486",
      "block_coun
… [9478 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "string_addr",
    "string_value",
    "string_length",
    "ref_addr",
    "func_addr",
    "func_name"
  ],
  "rows": [
    {
      "string_addr": "4198696",
      "string_value": "First_tls",
      "string_length": "10",
      "ref_addr": "4202089",
      "func_addr": "4202080",
      "func_name": "FUN_00401e60"
    },
    {
      "string_addr": "4198592",
      "string_val
… [3351 more chars]
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
      "src_func_addr": "4199072",
      "src_func_name": "FUN_004012a0",
      "dst_func_addr": "0",
      "dst_func_name": "sub_0",
      "call_site": "4199075"
    },
    {
      "src_func_addr": "4199120",
      "src_func_name": "FUN_004012d0",
      "dst_f
… [8790 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 50861,
  "duration_s": 0.05,
  "import_count": 21,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/deep_dive/01-tools-raw.json` exists=`True` bytes=`59495` mtime=`2026-08-13T10:13:56.305293+00:00`
  - sha256: `5b8581356e973afea4b5795063f0faf0338ccb7770dd4647e0b2116a14ffa0be`
- **sql_evidence:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/deep_dive/05-deep-dive.json` exists=`True` bytes=`4005` mtime=`2026-08-12T20:01:55.815470+00:00`
  - sha256: `11dc6ac6f8781d8c48f7bdf4c72e086be863164ee26c8beaa0e69deb3ab2dd72`

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
  "summary": "Satana ransomware dropper with extensive anti-analysis capabilities. The sample matches the Ransom_Satana_Dropper YARA rule with 3 string signatures, contains anti-debugging (ZwGetContextThread, OutputDebugStringA, NtYieldExecution, 4 TLS callbacks executing before entry point), anti-VM/Qemu detection, a massive encoded payload blob with embedded URLs and IPv6 addresses, a Base64 encoding table, and highly obfuscated control flow (cyclomatic complexity 91 in main function). OpenGL API imports (11 functions) serve as anti-sandbox evasion. The dropper contains obfuscated configuration and C2 infrastructure. Persistence mechanisms: not observed. Exfiltration mechanisms: not 
… [3205 more chars]
```

- **agentic:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`642296` mtime=`2026-08-12T20:01:55.815470+00:00`
  - sha256: `dbdc8e6c0a4bb730c113ee5ff5715981cb3c2e37fd31b63052521293a6fbd4ba`

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

- **rule_yar:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/rule.yar` exists=`True` bytes=`1210` mtime=`2026-08-12T20:01:58.688475+00:00`
  - sha256: `e63661a18078253301df29c5c8d625fdb1f0b2d4d6e14971fcc06f18d2ed7e52`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T20:01:58.690028+00:00
import "pe"
rule CADRE_v2_satana_ransomware_683a09da2199 {
    meta:
        description = "RevAI v2 auto rule for Satana ransomware"
        sha256 = "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96"
        family = "satana_ransomware"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "ZwProtectVirtualMemory" ascii wide
        $s1 = "ZwWriteVirtualMemory" ascii wide
        $s2 = "GetModuleFileNameW" ascii wide
        $s3 = "FlushInstructionCache" ascii wide
        $s4 = "ZwUnmapViewOfSection" ascii wide
        $s5 = "NtAllocateVirtualMemory" ascii wide
        $s6 = "?456789:;<=" ascii wide
   
… [408 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/REPORT-MASTER-v2.md` exists=`True` bytes=`16469` mtime=`2026-08-13T10:25:09.257859+00:00`
  - sha256: `f4aab37738e00f13181026c32707453ab5b983e461072aaec1e05ac954dc1a59`
- **REPORT_MASTER_v3:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/REPORT-MASTER-v3.md` exists=`True` bytes=`47425` mtime=`2026-08-13T10:38:59.020349+00:00`
  - sha256: `c6a25b72fc518a29c27575ebd509e2bd6c413c19b56a94707713f56ac20fced6`
- **REPORT_v2:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/REPORT-v2.md` exists=`True` bytes=`16469` mtime=`2026-08-13T10:25:09.257859+00:00`
  - sha256: `f4aab37738e00f13181026c32707453ab5b983e461072aaec1e05ac954dc1a59`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`56635` mtime=`2026-08-13T10:30:16.722641+00:00`
  - sha256: `1b29ad9b1e7dc53035c48a53c47e3e2f905b604a66750032b69327acb6ebe159`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`50290` mtime=`2026-08-13T10:47:31.140598+00:00`
  - sha256: `81cfd922e7c2a1ef953c69e1c85fdb753a30f1d5446cdf7029f0b3e5a602e170`
- **report_v2_json:** `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/report-v2.json` exists=`True` bytes=`19263` mtime=`2026-08-13T10:30:16.725641+00:00`
  - sha256: `faac36a67fe65db4b81995a9791c3e7c9d9bbb75eb080fdeaf0062204451f27e`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:25:09 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Satana Ransomware Dropper Analysis Report

## Executive Summary

This report details the analysis of a malicious Windows PE executable (SHA256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96) identified as a dropper for the Satana ransomware family. The sample exhibits a high degree of sophistication, employing multiple layers of anti-analysis and anti-sandbox evasion techniques to hinder detection and reverse enginee
… [15562 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:38:59 UTC

# RE Report — 683a09da2199
_Generated 2026-08-13T10:38:59.013941+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=243c | cross_refs=True | llm_ok=True | runtime=75.75s -->

## Executive Summary

This section presents the top-line assessment for the malware sample with SHA256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96.

**Top-line Verdict:** Malicious  
**Family:** Satana ransomware  
**Confidence:** High (90%)  
**Summary:** The sample is a variant of the Satana ransomware family, identified through static analysis with high confidence based on consistent i
… [46512 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
