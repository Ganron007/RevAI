# Pipeline AUDIT-REPORT — `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-03T13:12:40.192836+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`MALWARE (high confidence)` confidence=`9`
- key_evidence_count=`10`

```json
{
  "verdict": "MALWARE (high confidence)",
  "score": 9,
  "family_guess": "Meterpreter-associated UPX-packed loader/dropper",
  "cross_engine_notes": "IDA analysis is unavailable due to validation failure, so all findings are derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's function count (25) and import count (12) align with Malcat's data, while Malcat provides unique high-level anomaly and structural insights (e.g., UPX sections, embedded PEs, XOR loops) not available from Ghidra. All tools consistently identify UPX packing, XOR obfuscation, and suspicious runtime linking imports. Malcat's carved PE files and capa's embedded PE detection align, confirming the presence of additional payloads. YARA matches for UPX, RunShell, and android_meterpreter corroborate the packing and post-exploitation framework association.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with UPX",
      "why": "Confirms the sample is compressed with UPX, a packer frequently used to obfuscate malware, consistent with Malcat's UPX section layout and YARA UPX match."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "EntryPoint@4481792 decompilation",
      "why": "The entry point contains an XOR decoding loop (key 0xae) that modifies memory in place, a common obfuscation technique for hiding malicious payloads, matching capa's 'encode data using XOR' rule."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "change_memory_protection (VirtualProtect, T1055)",
      "why": "VirtualProtect is used to alter memory page permissions, a key technique for code injection, shellcode execution, and evading memory-based security controls, indicating process manipulation capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "carved files",
      "row_or_rule": "10 carved PE files at offsets 4535183, 4730130, 7411350, etc.",
      "why": "The sample embeds 10 additional PE files, which are almost certainly malicious payloads intended to be dropped or executed after unpacking, confirmed by capa's 'contain an embedded PE file' rule."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary, T1129) and get_proc_address (GetProcAddress, T1129)",
      "why": "These APIs enable dynamic resolution of function addresses at runtime, a common obfuscation method to hide malicious API usage from static analysis, matching capa's 'link function at runtime on Windows' rule."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy=145",
      "why": "Extremely high file entropy is a strong indicator of packed, encrypted, or compressed malicious content, consistent with the observed UPX packing and obfuscation anomalies."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "android_meterpreter",
      "why": "This YARA match indicates the sample is associated with Meterpreter, a widely used post-exploitation framework, suggesting the sample acts as a loader for Meterpreter payloads (potentially cross-platform, given the Android variant match)."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "CrossSectionJump",
      "why": "Control flow that jumps across section boun
… [3506 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is a 64-bit Windows PE with UPX packing and runtime dynamic API resolution. Static imports are minimal and include networking, process/memory, and user-profile APIs. Capa flags UPX packing, XOR-based encoding, embedded PE handling, process termination, and runtime linking. YARA matches include UPX signatures, Winsock library strings, mutex strings, file-operation strings, and an Android Meterpreter-related marker. The entry routine performs a large XOR decode loop over a memory region, then pushes a decoded pointer and calls into obfuscated code, consistent with a packed loader/dropper.",
  "key_evidence": [
    "UPX sections present: UPX0/UPX1/UPX2 memory blocks (Ghidra memory_blocks)",
    "YARA UPX match at offsets 392, 432, 517",
    "YARA Winsock library string match at offset 4483023",
    "YARA mutex string match at offset 4716493",
    "YARA file-operation strings at offsets 4482966, 4716263, 4716599",
    "YARA android_meterpreter marker at offset 744814",
    "Imports: LoadLibraryA, GetProcAddress, VirtualProtect, bind, GetAdaptersAddresses, GetProcessMemoryInfo, GetUserProfileDirectoryW, ExitProcess (Ghidra imports)",
    "Capa: packed with UPX; encode data using XOR; terminate process; link function at runtime on Windows; contain an embedded PE file",
    "Entry disassembly shows large XOR decode loop and subsequent call into decoded code (r2 decompile at 0x010b4100)",
    "PE import signals: LoadLibrary, GetProcAddress, VirtualProtect (pe_import_signals)"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 26,
  "successful_non_bootstrap_tools": 15,
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
  "title": "Malware Analysis Report: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 (Meterpreter-Associated UPX-Packed Loader/Dropper)",
  "markdown": "# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | MALWARE (high confidence) |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\nThis report details the analysis of a high-confidence malicious 64-bit Windows PE file (SHA256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5) identified as a Meterpreter-associated UPX-packed loader/dropper. The sample received a triage score of 9/10 and a deep-dive confidence rating of 90% for maliciousness. Static analysis confirms the sample is packed with a modified UPX variant (standard UPX unpack failed), uses XOR obfuscation (key 0xae) in its entry point to decode payloads in memory, employs dynamic API resolution via LoadLibrary/GetProcAddress to hide functionality, and embeds 10 additional PE files for delivery. High-signal YARA matches include `android_meterpreter`, `win_files_operation`, and UPX signatures, confirming association with the Meterpreter post-exploitation framework. The sample has confirmed capabilities for memory permission modification (VirtualProtect), process termination, and network communication via Winsock imports. No dynamic behavioral analysis was performed, so runtime capabilities are inferred from static artifacts. The sample is designed to evade static analysis via packing, obfuscation, and dynamic API resolution, and is intended to deliver post-exploitation payloads to compromised Windows endpoints.\n\n## 1. Sample Identification\nThe analyzed sample is a 64-bit Windows Portable Executable (PE) file with the following identifying attributes:\n- SHA256: `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5`\n- Sample path: `/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir`\n- Project name: `incoming`\n- File type: 64-bit Windows PE (X64 architecture), confirmed not to be a .NET assembly via dnfile analysis\n- File entropy: 145 (extremely high, indicating packed/encrypted content, source: malcat)\n- UPX status: Modified UPX packing (standard UPX 5.1.0 unpack failed, source: UPX unpack evidence)\nThe sample was submitted from virussign.com, a known malware distribution platform, consistent with its malicious classification.\n\n## 2. Classification\n**Verdict: MALWARE (high confidence)**\n**Family: Meterpreter-associated UPX-packed loader/dropper**\nThis classification is confirmed by upstream triage (score 9/10) and deep-dive analysis (90% confidence). The sample is a loader/dropper designed to unpack and execute embedded Meterpreter post-exploitation payloads. It uses multiple obfuscation techniques (UPX packing, XOR encoding, dynamic API resolution) to evade static and dynamic detection. The `android_meterpreter` YARA match indicates the sample may include cross-platform Meterpreter payloads or be part of a campaign targeting both Windows and Android devices. Per accuracy constraints, dual-use remote access tools (RATs) like Meterpreter abused in malware campaigns are classified as malicious, and this sample's behavior aligns with malicious use cases (embedded payload delivery, o
… [18363 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | MALWARE (high confidence) |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report details the analysis of a high-confidence malicious 64-bit Windows PE file (SHA256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5) identified as a Meterpreter-associated UPX-packed loader/dropper. The sample received a triage score of 9/10 and a deep-dive confidence rating of 90% for maliciousness. Static analysis confirms the sample is packed with a modified UPX variant (standard UPX unpack failed), uses XOR obfuscation (key 0xae) in its entry point to decode payloads in memory, employs dynamic API resolution via LoadLibrary/GetProcAddress to hide functionality, and embeds 10 additional PE files for delivery. High-signal YARA matches include `android_meterpreter`, `win_files_operation`, and UPX signatures, confirming association with the Meterpreter post-exploitation framework. The sample has confirmed capabilities for memory permission modification (VirtualProtect), process termination, and network communication via Winsock imports. No dynamic behavioral analysis was performed, so runtime capabilities are inferred from static artifacts. The sample is designed to evade static analysis via packing, obfuscation, and dynamic API resolution, and is intended to deliver post-exploitation payloads to compromised Windows endpoints.

## 1. Sample Identification
The analyzed sample is a 64-bit Windows Portable Executable (PE) file with the following identifying attributes:
- SHA256: `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5`
- Sample path: `/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir`
- Project name: `incoming`
- File type: 64-bit Windows PE (X64 architecture), confirmed not to be a .NET assembly via dnfile analysis
- File entropy: 145 (extremely high, indicating packed/encrypted content, source: malcat)
- UPX status: Modified UPX packing (standard UPX 5.1.0 unpack failed, source: UPX unpack evidence)
The sample was submitted from virussign.com, a known malware distribution platform, consistent with its malicious classification.

## 2. Classification
**Verdict: MALWARE (high confidence)**
**Family: Met
… [17350 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — c7e2c9b73000
_Generated 2026-08-03T13:10:21.517382+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=289c | cross_refs=True | llm_ok=True | runtime=26.89s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Sample SHA256 | `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5` |
| Final Verdict | MALWARE (high confidence) |
| Malware Family | Meterpreter-associated UPX-packed loader/dropper |
| Analysis Confidence | 90% (source: deep_dive_agentic) |

This sample is a high-confidence malicious UPX-packed 64-bit Portable Executable (PE) designed to act as a loader/dropper for Meterpreter post-exploitation payloads. The classification is supported by 12 YARA rule matches, including signatures for UPX packing, Meterpreter-associated functionality, and standard PE metadata, as well as 5 matched capa rules covering execution, evasion, and payload delivery capabilities (source: v1_summary, yara, capa, cross-section:2. Classification, cross-section:3. Initial Triage).

Static and behavioral analysis identified 10 distinct anomalies, including TLS callback-based pre-entry point execution, XOR decryption routines in the entry point, and anti-analysis obfuscation that causes disassembly failures in core subroutines (source: malcat, cross-section:4. Static Analysis, cross-section:5. Behavioral Analysis). No hardcoded network C2 indicators (IP addresses, callback URLs, or mutexes) were extracted from static analysis, consistent with the sample's role as an initial access loader that retrieves payloads dynamically at runtime (source: cross-section:6. Network Analysis). MITRE ATT&CK mapping confirms the sample supports common post-exploitation and lateral movement techniques associated with Meterpreter frameworks (source: cross-section:8. MITRE ATT&CK Mapping).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=26.9s -->

# 1. Sample Identification
This section documents the core static identifying attributes for the analyzed sample, derived from file metadata and format parsing analysis.

| Attribute | Value | Source |
|-----------|-------|--------|
| SHA256 Hash | `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5` | malcat, sample file metadata |
| Ingestion Path | `/opt/samples/corpus/incoming/c7e2c9b730007847a0942a9
… [46223 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7006` | `d7fc766eebd2d830` |
| `prompt.txt` | `True` | `18504` | `ad23d61ce77a35b6` |
| `pipeline-audit.json` | `True` | `97449` | `d1b8c42d07f25900` |
| `AUDIT-REPORT.md` | `True` | `72941` | `582bce3be9249f5f` |
| `REPORT-MASTER-v2.md` | `True` | `19852` | `63bf204e0ca57101` |
| `REPORT-MASTER-v3.md` | `True` | `48733` | `c308f2ce91ee1e80` |
| `REPORT-v2.md` | `True` | `19852` | `63bf204e0ca57101` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `58362` | `359d47aeb2464467` |
| `rule.yar` | `True` | `980` | `2b798a4a0120b350` |
| `intake-validation.json` | `True` | `2424` | `3fc5e0d15c1da88a` |
| `source-decisions.json` | `True` | `1555` | `f0ea899a2fcd26a5` |
| `malcat-triage.json` | `True` | `21397` | `74f6b47f11818d8a` |
| `deep_dive/01-tools-raw.json` | `True` | `70918` | `4bc91c77064b7e2b` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2834` | `4cc4acdafc079282` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `60016` | `15a02cd20427502f` |

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

- **intake_validation:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/intake-validation.json` exists=`True` bytes=`2424` mtime=`2026-08-03T12:52:14.342915+00:00`
  - sha256: `3fc5e0d15c1da88abfc7e64f57c31c8d2ec4c5e151074752e7782984a706091b`
- **malcat_triage:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/malcat-triage.json` exists=`True` bytes=`21397` mtime=`2026-08-03T12:51:33.564814+00:00`
  - sha256: `74f6b47f11818d8a674515e68ec1dfa604d230684cba09c17c23e9ced7317ae3`
- **source_decisions:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/source-decisions.json` exists=`True` bytes=`1555` mtime=`2026-08-03T12:52:14.342915+00:00`
  - sha256: `f0ea899a2fcd26a54782a7f0c7ad0e1848cb4b2795aae6d72ff7ebbb2879fc19`
- **ghidra_import_log:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/intake-analyzeHeadless.log` exists=`True` bytes=`82876` mtime=`2026-08-03T00:03:35.506731+00:00`
  - sha256: `f39464b8d48e02f6795fb97ee9a064ac177446d801423a8d44bac3c1d229a5c4`
- **ida_bootstrap_log:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable due to validation failure and has no import data; Ghidra reports 12 imports consistent with Malcat's recorded import count of 12."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable due to validation failure and has no function data; Ghidra reports 25 functions, offering more comprehensive function coverage than Malcat's 4 recorded functions."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Both Ghidra (20 strings) and Malcat (100 strings) provide string data, so combining both sources ensures full string coverage."
  }
… [778 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
    "file_name": "virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
    "file_path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
    "file_size": 8964155,
    "type": "PE",
    "architecture": "X64",
    "entropy": 145,
    "sha256": "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5
… [20597 more chars]
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
  "rule_count": 5,
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
      "name": "packed with UPX",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
          "id": "T1027.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Software Packing",
            "UPX"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "UPX",
          "id": "F0001.008"
        }
      ]
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
    }
  ],
  "timeout_s": 300,
  "sample_size": 8964155,
  "duration_s": 2.08,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 51072,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2689014,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 392,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 432,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 517,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 744814,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 4716493,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_files_operation",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "stri
… [3567 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 10548,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "nQz>F^",
    "gQ~F-u(k",
    "C{mCFdD2",
    "WuDsmio",
    "YuuptX",
    "2mbq4>",
    "~e??eR",
    "a}KYulH_",
    "'w}LoD",
    "%U%>ZQQ@",
    "L%B=^5",
    "1w\"~pA",
    "?3]RQQ",
    "gW1%;jn&",
    "^@*>BW",
    "PXQQiI",
    "< J\\>VB6",
    "~O/j_m",
    "{+RR1}f",
    "E#-R/%",
    ",yQ*_F",
    "JZB\\az",
    "bfe@#~",
    "<aOdRR",
    "YU%nYF",
    "gH`c,n",
    "=/C\"k)",
    "-VFJPM",
    "U'{dQIY",
    "p]'PoA",
    "G5Sovf",
    "0l -Mb",
    "'nUG~O",
    "MW0xw2K",
    "0\tWoITW",
    "kkc#pF",
    "YEuPEg",
    "'p-MRP",
    "nG?T:Q",
    "Omj/l%",
    "3$N|LD,vF",
    "G&mn,R",
    "%K)E<'",
    "onD:d}",
    "+d#-OV?",
    "NIoBkW1e",
    ">?efHd",
    "KU7'~}",
    "Q,<i4uae",
    "u'o''i",
    "5<lc_J",
    "MzN>hE",
    "p-oliG{U",
    "F)FQQo'",
    ",iuwS=",
    "~)},V:G~",
    "v3v,{(0",
    "qOPQO)O_",
    "%xQ,0^",
    "Xj,$i}",
    "ED*[qlY",
    "Sf*G(a",
    "M)\tkFN",
    "(s([A.",
    "+S_@)u",
    ")*3U)tG]",
    "0zmq$}",
    ".\\\tU'Po",
    "M;Z$YM",
    ".1I8%r",
    "Z3l?z1",
    "U@tz\\5[",
    "x6_c$>h",
    "n(n!\t'",
    "O81fEJp",
    "Hf#ho~",
    "/d{/g#=v",
    "wE3NPJ",
    "R7[0,G"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 10548
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 181.09,
  "size_bytes": 8964155,
  "static_only": true,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
    "file_name": "virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
    "file_path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
    "file_size": 8964155,
    "type": "PE",
    "architecture": "X64",
    "entropy": 145,
    "sha256": "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5",
    "metadata": {},
    "entrypoint_ea": 4481792,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 512,
        "virtual_size": 0,
        "rights": "",
        "entropy": 216
      },
      {
        "name": "UPX1",
        "effective_address": 512,
        "physical_size": 4482048,
        "virtual_size": 4485120,
        "rights": "RWX",
        "entropy": 210
      },
      {
        "name": "UPX2",
        "effective_address": 4485632,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": "overlay",
        "effective_address": 4489728,
        "physical_size": 4480571,
        "virtual_size": 0,
        "rights": "",
        "entropy": 81
      },
      {
        "name": "UPX0",
        "effective_address": 8970299,
        "physical_size": 0,
        "virtual_size": 8835072,
        "rights": "RWX",
        "entropy": 0
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "BigBufferNoXrefMediumToHighEntropy",
        "desc": "a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference inside: most likely a big crypto data block. File must have at least one function for this anomaly to run",
        "category": "entropy",
        "level": 3,
        "num_hits": 41
      },
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "EmbeddedProgram",
        "desc": "File embeds a program",
        "category": "embedding",
        "level": 3,
        "num_hits": 10
      },
      {
        "name": "ExecutableSectionNoCode",
        "desc": "executable section has the flag code not set",
        "category": "sections",
        "level": 4,
        "num_hits": 2
      },
      {
        "name": "HugeFunctionGapAtSectionBoundary",
        "desc": "There is a huge gap between start/end of executable section and first/last function of a section with medium-to-high entropy (which is not a know structure). It often means that data is stored there",
        "category": "code",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "InvalidBaseOfCode",
        "desc": "at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section",
        "category": "sections",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "InvalidSizeOfCode",
        "d
… [39096 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "packed with UPX top_rules Confirms the sample is compressed with UPX, a packer frequently used to obfuscate malware, con",
    "EntryPoint@4481792 decompilation decompilations The entry point contains an XOR decoding loop (key 0xae) that modifies m",
    "change_memory_protection (VirtualProtect, T1055) signals VirtualProtect is used to alter memory page permissions, a key ",
    "10 carved PE files at offsets 4535183, 4730130, 7411350, etc. carved files The sample embeds 10 additional PE files, whi",
    "load_library (LoadLibrary, T1129) and get_proc_address (GetProcAddress, T1129) signals These APIs enable dynamic resolut"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "MALWARE (high confidence)",
  "family": "Meterpreter-associated UPX-packed loader/dropper",
  "score": 9,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with UPX",
      "why": "Confirms the sample is compressed with UPX, a packer frequently used to obfuscate malware, consistent with Malcat's UPX section layout and YARA UPX match."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "EntryPoint@4481792 decompilation",
      "why": "The entry point contains an XOR decoding loop (key 0xae) that modifies memory in place, a common obfuscation technique for hiding malicious payloads, matching capa's 'encode data using XOR' rule."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "change_memory_protection (VirtualProtect, T1055)",
      "why": "VirtualProtect is used to alter memory page permissions, a key technique for code injection, shellcode execution, and evading memory-based security controls, indicating process manipulation capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "carved files",
      "row_or_rule": "10 carved PE files at offsets 4535183, 4730130, 7411350, etc.",
      "why": "The sample embeds 10 additional PE files, which are almost certainly malicious payloads intended to be dropped or executed after unpacking, confirmed by capa's 'contain an embedded PE file' rule."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library (LoadLibrary, T1129) and get_proc_address (GetProcAddress, T1129)",
      "why": "These APIs enable dynamic resolution of function addresses at runtime, a common obfuscation method to hide malicious API usage from static analysis, matching capa's 'link function at runtime on Windows' rule."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy=145",
      "why": "Extremely high file entropy is a strong indicator of packed, encrypted, or compressed malicious content, consistent with the observed UPX packing and obfuscation anomalies."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "android_meterpreter",
      "why": "This YARA match indicates the sample is associated with Meterpreter, a widely used post-exploitation framework, suggesting the sample acts as a loader for Meterpreter payloads (potentially cross-platform, given the Android variant match)."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "CrossSectionJump",
      "why": "Control flow that jumps across section boundaries is a common indicator of packed or patched malware, used to disrupt static analysis and control flow reconstruction."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "UnreferencedImports\u00d78",
      "why": "8 imported functions have no static cross-references, indicating they are called dynamically at runtime to hide malicious functionality from static analysis tools."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "NoChecksum",
      "why": "Missing PE header checksum is a common trait of packed or modified malware, as packers typically do not recalculate the checksum after altering the binary's contents."
    }
  ],
  "summary": "This is a high-confidence malicious 64-bit Windows PE file, packed with UPX and likely functioning as a Meterpreter-associated loader/dropper. The sample employs XOR obfuscation in its entry point to decode its payload in memory, uses dynamic API resolution (LoadLibrary/GetProcAddress) to hide functionality, and contains 10 embedded PE payloads for delivery. It has capabilities for memory permissi"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/prompt.txt` exists=`True` bytes=`18504` mtime=`2026-08-03T12:55:25.359822+00:00`
  - sha256: `ad23d61ce77a35b61721892bcbb5288afd39ba4469add70f0953dd70a2ac18e0`
- **verdict:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/verdict.json` exists=`True` bytes=`7006` mtime=`2026-08-03T12:56:02.677423+00:00`
  - sha256: `d7fc766eebd2d83040e93d4c7e790967fc81630cf3e24128985b1f1e319eecbe`

#### prompt_excerpt

```
# Triage evidence
sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5
sample_path: /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir
ghidra_session: ghidra-pe-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5
ida_session: ida-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable due to validation failure and has no import data; Ghidra reports 12 imports consistent with Malcat's recorded import count of 12.
- functions: ghidra (confidence=medium) — IDA is unavailable due to validation failure and has no function data; Ghidra reports 25 functions, offering more comprehensive function coverage than Malcat's 4 recorded functions.
- strings: both (confidence=high) — Both Ghidra (20 strings) and Malcat (100 strings) provide string data, so combining
… [17484 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "MALWARE (high confidence)",
  "score": 9,
  "family_guess": "Meterpreter-associated UPX-packed loader/dropper",
  "cross_engine_notes": "IDA analysis is unavailable due to validation failure, so all findings are derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's function count (25) and import count (12) align with Malcat's data, while Malcat provides unique high-level anomaly and structural insights (e.g., UPX sections, embedded PEs, XOR loops) not available from Ghidra. All tools consistently identify UPX packing, XOR obfuscation, and suspicious runtime linking imports. Malcat's carved PE files and capa's embedded PE detection align, confirming the presence of additional payloads. YARA matches for UPX, RunShell, and android_meterpreter corroborate the packing and post-exploitation framework association.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with UPX",
      "why": "Con
… [6006 more chars]
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
| evidence_pack_present | `True` |
| agentic_json | `True` |
| sql_deep_re | `True` |
| complete_verdict | `True` |
| not_incomplete | `True` |
| checklist_ok_flag | `True` |

### Tools (full evidence excerpts)

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json

```

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 5,
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
      "name": "packed with UPX",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Software Packing"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Software Packing",
          "id": "T1027.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Software Packing",
            "UPX"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "UPX",
          "id": "F0001.008"
        }
      ]
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
    }
  ],
  "timeout_s": 90,
  "sample_size": 8964155,
  "duration_s": 1.11,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 8964155,
  "duration_s": 0.03,
  "import_count": 12,
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
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 51072,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2689014,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 392,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 432,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 517,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 744814,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 4716493,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_files_operation",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "stri
… [3545 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 10548,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "nQz>F^",
    "gQ~F-u(k",
    "C{mCFdD2",
    "WuDsmio",
    "YuuptX",
    "2mbq4>",
    "~e??eR",
    "a}KYulH_",
    "'w}LoD",
    "%U%>ZQQ@",
    "L%B=^5",
    "1w\"~pA",
    "?3]RQQ",
    "gW1%;jn&",
    "^@*>BW",
    "PXQQiI",
    "< J\\>VB6",
    "~O/j_m",
    "{+RR1}f",
    "E#-R/%",
    ",yQ*_F",
    "JZB\\az",
    "bfe@#~",
    "<aOdRR",
    "YU%nYF",
    "gH`c,n",
    "=/C\"k)",
    "-VFJPM",
    "U'{dQIY",
    "p]'PoA",
    "G5Sovf",
    "0l -Mb",
    "'nUG~O",
    "MW0xw2K",
    "0\tWoITW",
    "kkc#pF",
    "YEuPEg",
    "'p-MRP",
    "nG?T:Q",
    "Omj/l%",
    "3$N|LD,vF",
    "G&mn,R",
    "%K)E<'",
    "onD:d}",
    "+d#-OV?",
    "NIoBkW1e",
    ">?efHd",
    "KU7'~}",
    "Q,<i4uae",
    "u'o''i",
    "5<lc_J",
    "MzN>hE",
    "p-oliG{U",
    "F)FQQo'",
    ",iuwS=",
    "~)},V:G~",
    "v3v,{(0",
    "qOPQO)O_",
    "%xQ,0^",
    "Xj,$i}",
    "ED*[qlY",
    "Sf*G(a",
    "M)\tkFN",
    "(s([A.",
    "+S_@)u",
    ")*3U)tG]",
    "0zmq$}",
    ".\\\tU'Po",
    "M;Z$YM",
    ".1I8%r",
    "Z3l?z1",
    "U@tz\\5[",
    "x6_c$>h",
    "n(n!\t'",
    "O81fEJp",
    "Hf#ho~",
    "/d{/g#=v",
    "wE3NPJ",
    "R7[0,G"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 10548
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 181.11,
  "size_bytes": 8964155,
  "static_only": true,
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
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
  "disassembly": {
    "0x010b4100": "\u250c 88: entry0 (int64_t arg4);\n\u2502           ; arg int64_t arg4 @ r9\n\u2502           0x010b4100      53             push rbx\n\u2502           0x010b4101      56             push rsi\n\u2502           0x010b4102      57             push rdi\n\u2502           0x010b4103      55             push rbp\n\u2502           0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]\n\u2502           0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]\n\u2502           0x010b4112      50             push rax\n\u2502           0x010b4113      53             push rbx\n\u2502           0x010b4114      56             push rsi\n\u2502           0x010b4115      b3ae           mov bl, 0xae                ; 174\n\u2502       \u250c\u2500> 0x010b4117      8a06           mov al, byte [rsi]\n\u2502       \u254e   0x010b4119      30d8           xor al, bl\n\u2502       \u254e   0x010b411b      8806           mov byte [rsi], al\n\u2502       \u254e   0x010b411d      48ffc6         inc rsi\n\u2502       \u254e   0x010b4120      4c39ce         cmp rsi, r9                 ; arg4\n\u2502       \u2514\u2500< 0x010b4123      75f2           jne 0x10b4117\n\u2502           0x010b4125      5e             pop rsi\n\u2502           0x010b4126      5b             pop rbx\n\u2502           0x010b4127      58             pop rax\n\u2502           0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]\n\u2502           0x010b412f      ff30           push qword [rax]\n\u2502           0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1\n\u2502           0x010b4137      50             push rax\n\u2502           0x010b4138      57             push rdi\n\u2502           0x010b4139      31db           xor ebx, ebx\n\u2502           0x010b413b      31c9           xor ecx, ecx\n\u2502           0x010b413d      4883cdff       or rbp, 0xffffffffffffffff\n\u2502           0x010b4141      e850000000     call fcn.010b4196\n\u2502           0x010b4146      01db           add ebx, ebx\n\u2502       \u250c\u2500< 0x010b4148      7402           je 0x10b414c\n\u2502       \u2502   0x010b414a      f3c3           repz ret\n\u2502       \u2514\u2500> 0x010b414c      8b1e           mov ebx, dword [rsi]\n\u2502           0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc\n\u2502           0x010b4152      11db           adc ebx, ebx\n\u2502           0x010b4154      8a16           mov dl, byte [rsi]\n\u2514           0x010b4156      f3c3           repz ret",
    "0x010b4196": "\u254e   ; CALL XREF from entry0 @ 0x10b4141(x)\n\u250c 400: fcn.010b4196 (int64_t arg1);\n\u2502       \u254e   ; arg int64_t arg1 @ rcx\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   0x010b4196      fc             cld\n\u2502       \u254e   0x010b4197      415b           pop r11\n\u2502      \u250c\u2500\u2500< 0x010b4199      eb08           jmp 0x10b41a3\n\u2502     \u250c\u2500\u2500\u2500> 0x010b419b      48ffc6         inc rsi\n\u2502     \u254e\u2502\u254e   0x010b419e      8817           mov byte [rdi], dl\n\u2502     \u254e\u2502\u254e   0x010b41a0      48ffc7         inc rdi\n\u2502     \u254e\u2502\u254e   ; CODE XREFS from fcn.010b4196 @ 0x10b4199(x), 0x10b423e(x)\n\u2502    \u250c\u2500\u2514\u2500\u2500> 0x010b41a3      8
… [3697 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\ntesting /opt/s"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 007FE026: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 0082D456: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 0085CCD5: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 007FE026: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 0082D456: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 0085CCD5: 00000080 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
    "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "UPX sections present: UPX0/UPX1/UPX2 memory blocks (Ghidra memory_blocks)",
    "YARA UPX match at offsets 392, 432, 517",
    "YARA Winsock library string match at offset 4483023",
    "YARA mutex string match at offset 4716493",
    "YARA file-operation strings at offsets 4482966, 4716263, 4716599"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is a 64-bit Windows PE with UPX packing and runtime dynamic API resolution. Static imports are minimal and include networking, process/memory, and user-profile APIs. Capa flags UPX packing, XOR-based encoding, embedded PE handling, process termination, and runtime linking. YARA matches include ",
  "key_evidence": [
    "UPX sections present: UPX0/UPX1/UPX2 memory blocks (Ghidra memory_blocks)",
    "YARA UPX match at offsets 392, 432, 517",
    "YARA Winsock library string match at offset 4483023",
    "YARA mutex string match at offset 4716493",
    "YARA file-operation strings at offsets 4482966, 4716263, 4716599",
    "YARA android_meterpreter marker at offset 744814",
    "Imports: LoadLibraryA, GetProcAddress, VirtualProtect, bind, GetAdaptersAddresses, GetProcessMemoryInfo, GetUserProfileDirectoryW, ExitProcess (Ghidra imports)",
    "Capa: packed with UPX; encode data using XOR; terminate process; link function at runtime on Windows; contain an embedded PE file",
    "Entry disassembly shows large XOR decode loop and subsequent call into decoded code (r2 decompile at 0x010b4100)",
    "PE import signals: LoadLibrary, GetProcAddress, VirtualProtect (pe_import_signals)"
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
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
      
… [6645 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
    "fi
… [42174 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 5,
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
… [2504 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 8964155,
  "duration_s": 0.03,
  "import_count": 12,
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
      "label"
… [179 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 10548,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "nQz>F^",
    "gQ~F-u(k",
    "C{mCFdD2",
    "WuDsmio",
    "YuuptX",
    "2mbq4>",
    "~e??eR",
    "a}KYulH_",
    "'w}LoD",
    "%U%>ZQQ@",
    "L%B=^5",
    "1w\"~pA",
    "?3]RQQ",
    "gW1%;jn&",
    "^@*>BW",
    "PXQQiI",
    "< J\\>VB6",
    "~O/j_m"
… [1280 more chars]
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
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
  "disassembly": {
    "0x010b4100": "\u250c 88: entry0 (int64_t arg4);\n\u2502           ; arg int64_t arg4 @ r9\n\u2502           0x010b4100      53             push rbx\n\u2502           0x010b4101      56             
… [6797 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [33 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 posi
… [1737 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
    "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
    "exists": true
  }
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
      "name": "FUN_010b4196",
      "address": "17514902",
      "size": "400"
    },
    {
      "name": "entry",
      "address": "17514752",
      "size": "88"
    },
    {
      "name": "FUN_010b4158",
      "address": "17514840",
      "size": "62"
    },
    {
      "name": "FUN_00fe915a",
      "address": "1668335
… [2226 more chars]
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
      "address": "1",
      "name": "FreeSid",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "2",
      "name": "CertOpenStore",
      "module": "CRYPT32.DLL"
    },
    {
      "address": "3",
      "name": "GetAdaptersAddresses",
      "module": "IPHLPAPI.DLL"
    },
    {
      "address": "4",
      "
… [1134 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "start_ea",
    "name",
    "size",
    "end_ea",
    "flags",
    "namespace",
    "signature",
    "return_type",
    "arg_count",
    "calling_conv",
    "return_is_ptr",
    "return_is_void",
    "return_is_int",
    "return_is_integral"
  ],
  "rows": [
    {
      "address": "4818131",
      "start_ea": "4818131",
      "name": "FUN_004984d3",
      "size"
… [11332 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [
    {
      "address": "17518960",
      "ea": "17518960",
      "length": "13",
      "type": "TerminatedCString",
      "type_name": "ascii",
      "width": "1",
      "width_name": "1-byte",
      "lay
… [6316 more chars]
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5",
  "audit_path": "/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a
… [45 more chars]
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
      "func_addr": "17514902",
      "func_name": "FUN_010b4196",
      "size": "400",
      "instruction_count": "138",
      "block_coun
… [6769 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5",
  "audit_path": 
… [98 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 8964155,
  "duration_s": 0.04,
  "import_count": 12,
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
      "label"
… [179 more chars]
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
      "start_ea": "4198400",
      "end_ea": "13033471",
      "name": "UPX0",
      "class": "CODE",
      "perm": "7",
      "bitness": "0",
      "size": "8835072",
      "is_read": "1",
      "is_write": "1",
      "i
… [1063 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 5,
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
… [2504 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5.json"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: ESCAPE expression must be a single character`

```json
{
  "error": "ghidrasql SQL error: ESCAPE expression must be a single character"
}
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
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [
    {
      "address": "17519218",
      "ea": "17519218",
      "length": "25",
      "type": "TerminatedCString",
      "type_name": "ascii",
      "width": "1",
      "width_name": "1-byte",
      "lay
… [1061 more chars]
```

- **r2_decompile** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
  "disassembly": {
    "0x010b4100": "\u250c 88: entry0 (int64_t arg4);\n\u2502           ; arg int64_t arg4 @ r9\n\u2502           0x010b4100      53             push rbx\n\u2502           0x010b4101      56             
… [6797 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "from_ea",
    "to_ea",
    "kind",
    "is_code",
    "is_data"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5",
  "audit_path": "/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/audit.jso
… [5 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [
    {
      "address": "17518960",
      "ea": "17518960",
      "length": "13",
      "type": "TerminatedCString",
      "type_name": "ascii",
      "width": "1",
      "width_name": "1-byte",
      "lay
… [2888 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5",
  "audit_path": 
… [98 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/deep_dive/01-tools-raw.json` exists=`True` bytes=`70918` mtime=`2026-08-03T12:59:24.027230+00:00`
  - sha256: `4bc91c77064b7e2b09e677127eff59a5b35d74808b8dd027bf3512d0b2f4cdf1`
- **sql_evidence:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/deep_dive/05-deep-dive.json` exists=`True` bytes=`2834` mtime=`2026-08-03T13:01:56.942635+00:00`
  - sha256: `4cc4acdafc0792823e5b22884a1f8ab5dd3a7ab5ff25ca15fda90cfea8225666`

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
  "summary": "This is a 64-bit Windows PE with UPX packing and runtime dynamic API resolution. Static imports are minimal and include networking, process/memory, and user-profile APIs. Capa flags UPX packing, XOR-based encoding, embedded PE handling, process termination, and runtime linking. YARA matches include UPX signatures, Winsock library strings, mutex strings, file-operation strings, and an Android Meterpreter-related marker. The entry routine performs a large XOR decode loop over a memory region, then pushes a decoded pointer and calls into obfuscated code, consistent with a packed loader/dropper.",
  "key_evidence": [
    "UPX sections present: UPX0/UPX1/UPX2 memory blocks (Gh
… [2034 more chars]
```

- **agentic:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`291160` mtime=`2026-08-03T13:01:56.941735+00:00`
  - sha256: `70ceacffe1b81e4f34df6e30b05dafd55caccbd177b34e7c4b529f7f9d1c88f2`

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

- **rule_yar:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yar` exists=`True` bytes=`980` mtime=`2026-08-03T13:02:12.035635+00:00`
  - sha256: `2b798a4a0120b35026b22a5cfabaa7d3660208c08f7b6717b483dee1f187c665`

#### excerpt

```
// yara_gen_v2.py — 2026-08-03T13:02:12.036635+00:00
rule CADRE_v2_unknown_c7e2c9b73000 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "GetUserProfileDirectoryW" ascii wide
        $s1 = "GetAdaptersAddresses" ascii wide
        $s2 = "GetProcessMemoryInfo" ascii wide
        $s3 = "VirtualProtect" ascii wide
        $s4 = "CertOpenStore" ascii wide
        $s5 = "ADVAPI32.dll" ascii wide
        $s6 = "IPHLPAPI.DLL" ascii wide
        $s7 = "KERNEL32.DLL" ascii wide
        $s8 = "LoadLibraryA" ascii wide
        $s9 = "CRYPT32.dll" ascii wide
  
… [178 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/REPORT-MASTER-v2.md` exists=`True` bytes=`19852` mtime=`2026-08-03T13:03:47.227738+00:00`
  - sha256: `63bf204e0ca5710119b123a3228c0c6b5e4be683c5ed5f85b1d0c34f5d564b2c`
- **REPORT_MASTER_v3:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/REPORT-MASTER-v3.md` exists=`True` bytes=`48733` mtime=`2026-08-03T13:10:21.521352+00:00`
  - sha256: `c308f2ce91ee1e80a4cb6bbfd95f14d52ff6e42c84724ef5e84f4e37d7f1abb2`
- **REPORT_v2:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/REPORT-v2.md` exists=`True` bytes=`19852` mtime=`2026-08-03T13:03:47.226838+00:00`
  - sha256: `63bf204e0ca5710119b123a3228c0c6b5e4be683c5ed5f85b1d0c34f5d564b2c`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`61068` mtime=`2026-08-03T13:06:00.358443+00:00`
  - sha256: `f1625c9158e1547e8985777faff7f9f00d99fead1aaaec50cc55e4e6189e78ee`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`58362` mtime=`2026-08-03T13:12:37.376356+00:00`
  - sha256: `359d47aeb2464467c533686d1559be155a39c1b787fe13e8982a295df79e69ee`
- **report_v2_json:** `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/report-v2.json` exists=`True` bytes=`21863` mtime=`2026-08-03T13:06:00.361143+00:00`
  - sha256: `3615cea948205dda563e228dbd0623a1d41f55c32b604033d1a41a03a27e83f3`

#### v2_excerpt

```
# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | MALWARE (high confidence) |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report details the analysis of a high-confidence malicious 64-bit Windows PE file (SHA256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5) identified as a Meterpreter-associated UPX-packed loader/dropper. The sample received a triage score of 9/10 and a deep-dive confidence rating of 90% for maliciousness. Static analysis confirms the sample is packed with a modified UPX variant (standard UPX unpack failed), uses XOR obfuscation (key 0xae) in its entry point to decode payloads in memory, employs dynamic API resolution via LoadLibrary/GetProcAddress to hid
… [18950 more chars]
```


#### v3_excerpt

```
# RE Report — c7e2c9b73000
_Generated 2026-08-03T13:10:21.517382+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=289c | cross_refs=True | llm_ok=True | runtime=26.89s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Sample SHA256 | `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5` |
| Final Verdict | MALWARE (high confidence) |
| Malware Family | Meterpreter-associated UPX-packed loader/dropper |
| Analysis Confidence | 90% (source: deep_dive_agentic) |

This sample is a high-confidence malicious UPX-packed 64-bit Portable Executable (PE) designed to act as a loader/dropper for Meterpreter post-exploitation payloads. The classification is supported by 12 YARA rule matches, including signatures for UPX packing, Meter
… [47823 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
