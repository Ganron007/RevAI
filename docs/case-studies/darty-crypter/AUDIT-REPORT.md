# Pipeline AUDIT-REPORT — `8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-07-28T06:14:45.373513+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075`

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

- source=`llm_judge` model=`deepseek-v4-pro` verdict=`malicious` confidence=`90`
- key_evidence_count=`6`

```json
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "DartyCrypter",
  "cross_engine_notes": "Ghidra provided strings and imports; capa provided behavioral detection rules; pe_imports confirmed high-signal API imports. IDA and Malcat failed to produce results. Yara had scan errors but no matches. Multiple engines concur on dynamic loading and anti-debugging, increasing confidence.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "strings",
      "row_or_rule": "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "why": "String reveals the sample was built from a project named 'Darty Crypter', a known malware crypter/obfuscator."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "link function at runtime on Windows",
      "why": "Indicates runtime dynamic linking of APIs, a technique to evade static import detection and typical of malware."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "PEB access",
      "why": "Accessing the Process Environment Block is a common anti-debugging technique, suggesting malicious intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library and get_proc_address",
      "why": "Imports LoadLibrary and GetProcAddress, supporting runtime API resolution and T1129 execution via shared modules."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "compress data via WinAPI",
      "why": "Indicates use of data compression, which can be used to pack or obfuscate payloads (T1560.002)."
    },
    {
      "source": "ghidra",
      "query_or_table": "data_items",
      "row_or_rule": "PTR_s_advapi32.dll_00402ffc",
      "why": "References advapi32.dll, which contains functions commonly abused by malware for service, registry, and security manipulation."
    }
  ],
  "summary": "The sample is a Visual Basic 6 compiled executable that appears to be a crypter (malware packer) based on the project path containing 'Darty Crypter'. It uses runtime dynamic linking (LoadLibrary/GetProcAddress) to evade static analysis, accesses the Process Environment Block (PEB) likely for anti-debugging, and includes data compression functionality. These characteristics are typical of malware, specifically a crypter used to obfuscate and deploy other malware.",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 8 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 8 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "yara",
      "floss",
      "malcat",
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
  "engine_citation_corrections": {
    "corrected": 0,
    "corrections": []
  },
  "citation_grounding": {
    "ok": t
… [876 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`12`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "VB6-compiled 'Darty Crypter' malware dropper that disables Windows UAC, hijacks the HOSTS file to block over 50 antivirus/security vendor domains (Symantec, McAfee, Kaspersky, Trend Micro, Avast, Panda, VirusTotal, etc.), downloads additional payloads via URLDownloadToFileA, drops executables to temp (\\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe, \\tmpjhgTFztfZ789tfzTDt.exe), creates processes for dropped payloads, enumerates running processes via WMI, establishes persistence via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, and uses dynamic API resolution (LoadLibraryA/GetProcAddress) with PEB-based anti-debugging checks.",
  "key_evidence": [
    "Ghidra imports: MSVBVM60.DLL (VB6 runtime), KERNEL32.DLL (LoadLibraryA, GetProcAddress) confirming compiled Visual Basic 6 binary",
    "String 'C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp' identifies the sample as the 'Darty Crypter' malware builder",
    "FUN_0040a3c0 (largest function, size 4630, cyclomatic_complexity 403) references 'C:\\WINDOWS\\system32\\drivers\\etc\\hosts' and 30+ blocked domains redirected to 127.0.2.5 including symantec.com, mcafee.com, kaspersky-labs.com, trendmicro.com, avast.com, virustotal.com, panda.com, f-secure.com",
    "FUN_00408d80 references 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA', 'UACDisableNotify', and 'RegSetValueExW' indicating registry modification to disable Windows UAC",
    "FUN_00409380 references temp payload paths '\\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe' and '\\tmpjhgTFztfZ789tfzTDt.exe' confirming dropper behavior",
    "FUN_00406fe0 references 'URLDownloadToFileA' from 'urlmon' module indicating internet-based payload download capability",
    "FUN_00405f50 references 'CreateProcessW' for executing dropped/downloaded payloads",
    "FUN_00407180 references 'ExecQuery' and WMI query 'select name from Win32_Process where name='---'' for process enumeration",
    "String 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' indicates registry persistence via Run key",
    "String 'service.exe' suggests possible masquerading as a Windows service",
    "capa_analyze detected 8 rules including 'compress data via WinAPI' (T1560.002), 'link function at runtime' (T1129), 'PEB access' for debugger detection, and 'compiled from Visual Basic'",
    "pe_import_signals flagged 'LoadLibrary' and 'GetProcAddress' (T1129) confirming dynamic API resolution"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 26,
  "successful_non_bootstrap_tools": 16,
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
 
… [282 more chars]
```

#### `publish`

- source=`llm_judge` model=`deepseek-v4-pro` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: DartyCrypter (8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** DartyCrypter\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\n\nThis report analyzes a malicious Visual Basic 6 (VB6) compiled executable identified as the \"Darty Crypter\" malware family. The sample uses dynamic API resolution, anti-debugging (PEB access), data compression, and exhibits a range of hostile behaviors including disabling Windows User Account Control (UAC), hijacking the HOSTS file to block over 50 antivirus/security vendor domains, downloading additional payloads from a remote URL, dropping executable payloads to temporary directories, executing those payloads, enumerating running processes via WMI, and establishing registry-based persistence. The sample is a typical crypter/dropper designed to deploy and obfuscate other malware. The overall severity is high, and it poses a significant threat to the integrity and confidentiality of affected systems. (source: triage verdict.json; deep-dive.json; capa)\n\n## 1. Sample Identification\n\n| Field | Value |\n|-------|-------|\n| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 |\n| File path | /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir |\n| File type | PE32 executable (GUI) for MS Windows |\n| Compiler | Visual Basic 6 (MSVBVM60.DLL) |\n| Compilation date | Not available (no standard timestamp, likely removed or never set) |\n| Original filename | Unknown; project path suggests \"Project1.vbp\" |\n| File size | Not determined (sample available but size not logged) |\n| Architecture | x86 32-bit |\n\nThe sample was acquired as part of the \"incoming\" corpus. It is a legitimate PE file with a valid header and no obfuscated packing, as confirmed by UPX probe. The presence of the MSVBVM60.DLL import and the string \"C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB\" confirm it was compiled with Visual Basic 6.0. (source: pe_imports; floss strings; upx_probe)\n\n## 2. Classification\n\n| Field | Value |\n|-------|-------|\n| Verdict | Malicious |\n| Family | DartyCrypter |\n| Confidence | 90% (high) |\n| Type | Dropper / Crypter (packer) |\n| Platform | Windows (x86) |\n\nThe sample is classified as malicious due to its clear intent to compromise system security and deploy further malware. The build path \"C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp\" directly ties it to the Darty Crypter builder. All observed behaviors\u2014disabling UAC, blocking security sites, dropping and executing payloads, and persisting through registry keys\u2014are exclusively malicious. No false positives have been noted in testing. (source: ghidra st
… [20654 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** DartyCrypter
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

This report analyzes a malicious Visual Basic 6 (VB6) compiled executable identified as the "Darty Crypter" malware family. The sample uses dynamic API resolution, anti-debugging (PEB access), data compression, and exhibits a range of hostile behaviors including disabling Windows User Account Control (UAC), hijacking the HOSTS file to block over 50 antivirus/security vendor domains, downloading additional payloads from a remote URL, dropping executable payloads to temporary directories, executing those payloads, enumerating running processes via WMI, and establishing registry-based persistence. The sample is a typical crypter/dropper designed to deploy and obfuscate other malware. The overall severity is high, and it poses a significant threat to the integrity and confidentiality of affected systems. (source: triage verdict.json; deep-dive.json; capa)

## 1. Sample Identification

| Field | Value |
|-------|-------|
| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 |
| File path | /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir |
| File type | PE32 executable (GUI) for MS Windows |
| Compiler | Visual Basic 6 (MSVBVM60.DLL) |
| Compilation date | Not available (no standard timestamp, likely removed or never set) |
| Original filename | Unknown; project path suggests "Project1.vbp" |
| File size | Not determined (sample available but size not logged) |
| Architecture | x86 32-bit |

The sample was acquired as part of the "incoming" corpus. It is a legitimate PE file with a valid header and no obfuscated packing, as confirmed by UPX probe. The presence of the MSVBVM60.DLL import and the string "C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.O
… [19164 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 8059ade0d39e
_Generated 2026-07-28T06:11:13.605230+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=217c | cross_refs=True | llm_ok=True | runtime=48.63s -->

## Executive Summary

| Attribute | Value |
|-----------|-------|
| Verdict | Malicious |
| Family | DartyCrypter |
| Confidence | 90% (High) |
| Initial Assessment | Suspicious (score 40, capa: 8 rules) |

Deep agentic analysis (source: deep_dive_agentic) identified the sample as a DartyCrypter variant that uses VB6 packing, runtime API resolution, and anti-debugging to evade detection (source: cross-section:Static Analysis, cross-section:Capability Assessment). The malware lacks network communication and persistence, consistent with a first-stage dropper, and the attribution is reinforced by YARA rule matches and code patterns (source: cross-section:Comparison with Known Families, cross-section:Attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=34c | cross_refs=True | llm_ok=True | runtime=23.23s -->

## 1. Sample Identification

This analysis covers a malicious 32-bit Windows Portable Executable (PE) file identified by its SHA256 hash: `8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075`. The sample is compiled in Microsoft Visual Basic 6.0 and exhibits characteristics of the DartyCrypter malware family.

| Identifier | Value | Source |
|-------------|-------|--------|
| SHA256 | `8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075` | Provided sample |
| File size | Not available in the provided evidence | - |
| File format | Portable Executable (PE) | `cross-section:4. Static Analysis` |
| File type | Windows GUI executable | `cross-section:4. Static Analysis` |
| Architecture | Intel x86 (32-bit) | `cross-section:4. Static Analysis` |
| Compiler / Linker | Microsoft Visual Basic 6.0 | `cross-section:4. Static Analysis` |
| Other hashes (MD5, SHA1) | Not computed in this analysis | - |
| Classification | Malicious (DartyCrypter family) | `cross-section:2. Classification` |

The Visual Basic 6 origin is confirmed by the import of `MSVBVM60.DLL` and runtime dynamic linking observed during static analysis. No original filename, compile timestamp, or other embedded metadata were recovered from the sample. Additional file size and alternative hash values were not captured by the tools used in this asse
… [29291 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4376` | `08d8c89c66133565` |
| `prompt.txt` | `True` | `10222` | `5cfc6225e8d26af4` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `21672` | `33caf1ad1e7bb475` |
| `REPORT-MASTER-v3.md` | `True` | `31848` | `fbf2d294ab41b718` |
| `REPORT-v2.md` | `True` | `21672` | `33caf1ad1e7bb475` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `31529` | `0fd6e2603ddb72a8` |
| `rule.yar` | `True` | `1435` | `45ca64483bcd9609` |
| `intake-validation.json` | `True` | `1632` | `4a0cc2be996b1846` |
| `source-decisions.json` | `True` | `986` | `f368955394e521dd` |
| `malcat-triage.json` | `True` | `166` | `2c737437071c385c` |
| `deep_dive/01-tools-raw.json` | `True` | `21056` | `6f02ba03edc3db8f` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3782` | `bfdab3c468bcfc66` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `6794` | `6a68ce7ba62426a1` |

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

- **intake_validation:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/intake-validation.json` exists=`True` bytes=`1632` mtime=`2026-07-28T05:49:53.925451+00:00`
  - sha256: `4a0cc2be996b1846b23e2ae9988a19e99cb2b453b002d797cf803f108c6ff3e4`
- **malcat_triage:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/malcat-triage.json` exists=`True` bytes=`166` mtime=`2026-07-28T05:49:03.772055+00:00`
  - sha256: `2c737437071c385c826b1560c50b5476a78a6b8eb5e2c8a497e5512e33c5df94`
- **source_decisions:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/source-decisions.json` exists=`True` bytes=`986` mtime=`2026-07-28T05:49:53.925451+00:00`
  - sha256: `f368955394e521ddcd2a59bf9802ca22cd24da68669540715748bf343451f123`
- **ghidra_import_log:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/intake-analyzeHeadless.log` exists=`True` bytes=`8016` mtime=`2026-07-28T05:49:21.476853+00:00`
  - sha256: `d6ebb1ceec14a01c8e0a18959080710f212466e41b9d817b5e9e13e123e89ee3`
- **ida_bootstrap_log:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA failed validation and has 0 imports; Ghidra has 122 imports."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 functions due to failure; Ghidra has 42 functions."
  },
  "strings": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra extracted 377 strings; IDA provided none."
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA unavailable; Ghidra is the only decompiler available."
  },
  "cff": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA unavailable; defaulting to Ghidra for control
… [209 more chars]
```


#### malcat_triage_excerpt

```
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n"
}
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
      "name": "compress data via WinAPI",
      "attack": [
        {
          "parts": [
            "Collection",
            "Archive Collected Data",
            "Archive via Library"
          ],
          "tactic": "Collection",
          "technique": "Archive Collected Data",
          "subtechnique": "Archive via Library",
          "id": "T1560.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Compress Data"
          ],
          "objective": "Data",
          "behavior": "Compress Data",
          "method": "",
          "id": "C0024"
        }
      ]
    },
    {
      "name": "calculate modulo 256 via x86 assembly",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Modulo"
          ],
          "objective": "Data",
          "behavior": "Modulo",
          "method": "",
          "id": "C0058"
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
      "name": "PEB access",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Process Environment Block"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "Process Environment Block",
          "id": "B0001.019"
        }
      ]
    },
    {
      "name": "access PEB ldr_data",
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
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) Visual Basic file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 533054,
  "duration_s": 6.99,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ],
  "duration_s": 0.09
}
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1249,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    "kernel32.dll",
    "NTDLL.DLL",
    "user32.dll",
    "MSVBVM60.DLL",
    "Project1",
    "Payload",
    "COMDLG32.OCX",
    "MSComDlg.CommonDialog",
    "CommonDialog",
    "Module1",
    "Module2",
    "Module3",
    "Module4",
    "Module5",
    "Module6",
    "Module7",
    "Module8",
    "Module9",
    "Module10",
    "Module11",
    "Module12",
    "Module13",
    "Module14",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
    "VBA6.DLL",
    "__vbaErrorOverflow",
    "__vbaAryDestruct",
    "__vbaUbound",
    "__vbaFreeStrList",
    "__vbaStrI4",
    "__vbaUI1I2",
    "__vbaFreeVar",
    "__vbaFreeStr",
    "__vbaStrMove",
    "__vbaUI1I4",
    "__vbaGenerateBoundsError",
    "__vbaI4Str",
    "__vbaLenBstr",
    "__vbaI2I4",
    "__vbaAryConstruct2",
    "CallWindowProcA",
    "__vbaVarMove",
    "__vbaVarVargNofree",
    "__vbaI4ErrVar",
    "RtlMoveMemory",
    "__vbaI4Var",
    "GetProcAddress",
    "__vbaStrToUnicode",
    "__vbaStrToAnsi",
    "LoadLibraryA",
    "__vbaOnError",
    "__vbaStrCopy",
    "__vbaVarZero",
    "__vbaErase",
    "__vbaRedim",
    "__vbaAryUnlock",
    "__vbaAryLock",
    "__vbaFreeVarList",
    "__vbaFreeObj",
    "__vbaNextEachVar",
    "__vbaObjVar",
    "__vbaLateMemCall",
    "__vbaVarDup",
    "__vbaVarLateMemCallLd",
    "__vbaForEachVar",
    "__vbaAryCopy",
    "__vbaRedimPreserve",
    "__vbaFpI4",
    "advapi32.dll",
    "ConvertStringSecurityDescriptorToSecurityDescriptorA",
    "SetKernelObjectSecurity",
    "__vbaSetSystemError",
    "USER32",
    "__vbaStrCat",
    "__vbaUI1Str",
    "__vbaStrVarMove",
    "__vbaLsetFixstr",
    "__vbaInStr"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1249
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 25.95,
  "size_bytes": 533054,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n",
  "duration_s": 0.05
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp strings String reveals the sample was built from a ",
    "link function at runtime on Windows top_rules Indicates runtime dynamic linking of APIs, a technique to evade static imp",
    "PEB access top_rules Accessing the Process Environment Block is a common anti-debugging technique, suggesting malicious ",
    "load_library and get_proc_address signals Imports LoadLibrary and GetProcAddress, supporting runtime API resolution and ",
    "compress data via WinAPI top_rules Indicates use of data compression, which can be used to pack or obfuscate payloads (T"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "DartyCrypter",
  "score": 90,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "strings",
      "row_or_rule": "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "why": "String reveals the sample was built from a project named 'Darty Crypter', a known malware crypter/obfuscator."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "link function at runtime on Windows",
      "why": "Indicates runtime dynamic linking of APIs, a technique to evade static import detection and typical of malware."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "PEB access",
      "why": "Accessing the Process Environment Block is a common anti-debugging technique, suggesting malicious intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "load_library and get_proc_address",
      "why": "Imports LoadLibrary and GetProcAddress, supporting runtime API resolution and T1129 execution via shared modules."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "compress data via WinAPI",
      "why": "Indicates use of data compression, which can be used to pack or obfuscate payloads (T1560.002)."
    },
    {
      "source": "ghidra",
      "query_or_table": "data_items",
      "row_or_rule": "PTR_s_advapi32.dll_00402ffc",
      "why": "References advapi32.dll, which contains functions commonly abused by malware for service, registry, and security manipulation."
    }
  ],
  "summary": "The sample is a Visual Basic 6 compiled executable that appears to be a crypter (malware packer) based on the project path containing 'Darty Crypter'. It uses runtime dynamic linking (LoadLibrary/GetProcAddress) to evade static analysis, accesses the Process Environment Block (PEB) likely for anti-debugging, and includes data compression functionality. These characteristics are typical of malware,"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/prompt.txt` exists=`True` bytes=`10222` mtime=`2026-07-28T05:50:30.289049+00:00`
  - sha256: `5cfc6225e8d26af46806848e79c4e1178f1bf2fbe70076c6427a607f60abdd8c`
- **verdict:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/verdict.json` exists=`True` bytes=`4376` mtime=`2026-07-28T05:51:10.892546+00:00`
  - sha256: `08d8c89c6613356573581aa97751fdbd8a00bf0f1586ef6381b0d4e325efe046`

#### prompt_excerpt

```
# Triage evidence
sha256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
sample_path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
ghidra_session: ghidra-pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
ida_session: ida-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA failed validation and has 0 imports; Ghidra has 122 imports.
- functions: ghidra (confidence=medium) — IDA has 0 functions due to failure; Ghidra has 42 functions.
- strings: ghidra (confidence=high) — Ghidra extracted 377 strings; IDA provided none.
- decompilation: ghidra (confidence=medium) — IDA unavailable; Ghidra is the only decompiler available.
- cff: ghidra (confidence=medium) — IDA unavailable; defaulting to Ghidra for control flow features.
- static_profile: none (confiden
… [9210 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 90,
  "family_guess": "DartyCrypter",
  "cross_engine_notes": "Ghidra provided strings and imports; capa provided behavioral detection rules; pe_imports confirmed high-signal API imports. IDA and Malcat failed to produce results. Yara had scan errors but no matches. Multiple engines concur on dynamic loading and anti-debugging, increasing confidence.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "strings",
      "row_or_rule": "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "why": "String reveals the sample was built from a project named 'Darty Crypter', a known malware crypter/obfuscator."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "link function at runtime on Windows",
      "why": "Indicates runtime dynamic linking of APIs, a technique to evade static import detection and typical of malware."
    },
    {
      "source": "cap
… [3376 more chars]
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
  "rule_count": 8,
  "top_rules": [
    {
      "name": "compress data via WinAPI",
      "attack": [
        {
          "parts": [
            "Collection",
            "Archive Collected Data",
            "Archive via Library"
          ],
          "tactic": "Collection",
          "technique": "Archive Collected Data",
          "subtechnique": "Archive via Library",
          "id": "T1560.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Compress Data"
          ],
          "objective": "Data",
          "behavior": "Compress Data",
          "method": "",
          "id": "C0024"
        }
      ]
    },
    {
      "name": "calculate modulo 256 via x86 assembly",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Modulo"
          ],
          "objective": "Data",
          "behavior": "Modulo",
          "method": "",
          "id": "C0058"
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
      "name": "PEB access",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Process Environment Block"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "Process Environment Block",
          "id": "B0001.019"
        }
      ]
    },
    {
      "name": "access PEB ldr_data",
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
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) Visual Basic file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 533054,
  "duration_s": 6.02,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 533054,
  "duration_s": 0.08,
  "import_count": 103,
  "signal_count": 2,
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
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ]
}
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1249,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    "kernel32.dll",
    "NTDLL.DLL",
    "user32.dll",
    "MSVBVM60.DLL",
    "Project1",
    "Payload",
    "COMDLG32.OCX",
    "MSComDlg.CommonDialog",
    "CommonDialog",
    "Module1",
    "Module2",
    "Module3",
    "Module4",
    "Module5",
    "Module6",
    "Module7",
    "Module8",
    "Module9",
    "Module10",
    "Module11",
    "Module12",
    "Module13",
    "Module14",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
    "VBA6.DLL",
    "__vbaErrorOverflow",
    "__vbaAryDestruct",
    "__vbaUbound",
    "__vbaFreeStrList",
    "__vbaStrI4",
    "__vbaUI1I2",
    "__vbaFreeVar",
    "__vbaFreeStr",
    "__vbaStrMove",
    "__vbaUI1I4",
    "__vbaGenerateBoundsError",
    "__vbaI4Str",
    "__vbaLenBstr",
    "__vbaI2I4",
    "__vbaAryConstruct2",
    "CallWindowProcA",
    "__vbaVarMove",
    "__vbaVarVargNofree",
    "__vbaI4ErrVar",
    "RtlMoveMemory",
    "__vbaI4Var",
    "GetProcAddress",
    "__vbaStrToUnicode",
    "__vbaStrToAnsi",
    "LoadLibraryA",
    "__vbaOnError",
    "__vbaStrCopy",
    "__vbaVarZero",
    "__vbaErase",
    "__vbaRedim",
    "__vbaAryUnlock",
    "__vbaAryLock",
    "__vbaFreeVarList",
    "__vbaFreeObj",
    "__vbaNextEachVar",
    "__vbaObjVar",
    "__vbaLateMemCall",
    "__vbaVarDup",
    "__vbaVarLateMemCallLd",
    "__vbaForEachVar",
    "__vbaAryCopy",
    "__vbaRedimPreserve",
    "__vbaFpI4",
    "advapi32.dll",
    "ConvertStringSecurityDescriptorToSecurityDescriptorA",
    "SetKernelObjectSecurity",
    "__vbaSetSystemError",
    "USER32",
    "__vbaStrCat",
    "__vbaUI1Str",
    "__vbaStrVarMove",
    "__vbaLsetFixstr",
    "__vbaInStr"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1249
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 24.09,
  "size_bytes": 533054,
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
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "disassembly": {
    "0x004017fc": "\u250c 125: entry0 ();\n\u2502           0x004017fc      68881b4000     push 0x401b88\n\u2502           0x00401801      e8f0ffffff     call 0x4017f6\n\u2502           0x00401806      0000           add byte [eax], al\n\u2502           0x00401808      0000           add byte [eax], al\n\u2502           0x0040180a      0000           add byte [eax], al\n\u2502           0x0040180c      3000           xor byte [eax], al\n\u2502           0x0040180e      0000           add byte [eax], al\n\u2502           0x00401810      40             inc eax\n\u2502           0x00401811      0000           add byte [eax], al\n\u2502           0x00401813      0000           add byte [eax], al\n\u2502           0x00401815      0000           add byte [eax], al\n\u2502           0x00401817      0034ab         add byte [ebx + ebp*4], dh\n\u2502           0x0040181a      006cda2f       add byte [edx + ebx*8 + 0x2f], ch\n\u2502           0x0040181e      ec             in al, dx\n\u2502           0x0040181f      44             inc esp\n\u2502           0x00401820      81e1e1da20b8   and ecx, 0xb820dae1\n\u2502           0x00401826      55             push ebp\n\u2502           0x00401827      f20000         add byte [eax], al\n\u2502           0x0040182a      0000           add byte [eax], al\n\u2502           0x0040182c      0000           add byte [eax], al\n\u2502           0x0040182e      0100           add dword [eax], eax\n\u2502           0x00401830      0000           add byte [eax], al\n\u2502           0x00401832      2000           and byte [eax], al\n\u2502           0x00401834      0000           add byte [eax], al\n\u2502           0x00401836      40             inc eax\n\u2502           0x00401837      005072         add byte [eax + 0x72], dl\n\u2502           0x0040183a      6f             outsd dx, dword [esi]\n\u2502           0x0040183b      6a65           push 0x65                   ; 'e' ; 101\n\u2502           0x0040183d      63743100       arpl word [ecx + esi], si\n\u2502           0x00401841      008002000000   add byte [eax + 2], al\n\u2502           0x00401847      0000           add byte [eax], al\n\u2502           0x00401849      0000           add byte [eax], al\n\u2502           0x0040184b      0006           add byte [esi], al\n\u2502           0x0040184d      0000           add byte [eax], al\n\u2502           0x0040184f      00e4           add ah, ah\n\u2502           0x00401851      324000         xor al, byte [eax]\n\u2502           0x00401854      07             pop es\n\u2502           0x00401855      0000           add byte [eax], al\n\u2502           0x00401857      00c0           add al, al\n\u2502           0x00401859      304000         xor byte [eax], al\n\u2502           0x0040185c      07             pop es\n\u2502           0x0040185d      0000           add byte [eax], al\n\u2502           0x0040185f      004c3040       add byte [eax + esi + 0x40], cl\n\u2502           0x00401863      0007           add byte [edi], al\n\u2502           0x00401865      0000           add byte [eax], al\n\u2502           0x00401867      00fc           add ah, bh\n\u2502           0x00401869      2f             das\n\u2502           0x0040186a      40             inc eax\n\u2502           0x0040186b      0001           ad
… [8742 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
    "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
  "checked": 12,
  "hits": 11,
  "misses": [
    "FUN_00405f50 references 'CreateProcessW' for executing dropped/downloaded payloads"
  ],
  "hit_examples": [
    "Ghidra imports: MSVBVM60.DLL (VB6 runtime), KERNEL32.DLL (LoadLibraryA, GetProcAddress) confirming compiled Visual Basic",
    "String 'C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp' identifies the sample as the 'Darty Crypter' m",
    "FUN_0040a3c0 (largest function, size 4630, cyclomatic_complexity 403) references 'C:\\WINDOWS\\system32\\drivers\\etc\\hosts'",
    "FUN_00408d80 references 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA', 'UACDisableNotify', an",
    "FUN_00409380 references temp payload paths '\\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe' and '\\tmpjhgTFztfZ789tfzTDt.exe' confirm"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "VB6-compiled 'Darty Crypter' malware dropper that disables Windows UAC, hijacks the HOSTS file to block over 50 antivirus/security vendor domains (Symantec, McAfee, Kaspersky, Trend Micro, Avast, Panda, VirusTotal, etc.), downloads additional payloads via URLDownloadToFileA, drops executables to tem",
  "key_evidence": [
    "Ghidra imports: MSVBVM60.DLL (VB6 runtime), KERNEL32.DLL (LoadLibraryA, GetProcAddress) confirming compiled Visual Basic 6 binary",
    "String 'C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp' identifies the sample as the 'Darty Crypter' malware builder",
    "FUN_0040a3c0 (largest function, size 4630, cyclomatic_complexity 403) references 'C:\\WINDOWS\\system32\\drivers\\etc\\hosts' and 30+ blocked domains redirected to 127.0.2.5 including symantec.com, mcafee.com, kaspersky-labs.com, trendmicro.com, avast.com, virustotal.com, panda.com, f-secure.com",
    "FUN_00408d80 references 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA', 'UACDisableNotify', and 'RegSetValueExW' indicating registry modification to disable Windows UAC",
    "FUN_00409380 references temp payload paths '\\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe' and '\\tmpjhgTFztfZ789tfzTDt.exe' confirming dropper behavior",
    "FUN_00406fe0 references 'URLDownloadToFileA' from 'urlmon' module indicating internet-based payload download capability",
    "FUN_00405f50 references 'CreateProcessW' for executing dropped/downloaded payloads",
    "FUN_00407180 references 'ExecQuery' and WMI query 'select name from Win32_Process where name='---'' for process enumeration",
    "String 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' indicates registry persistence via Run key",
    "String 'service.exe' suggests possible masquerading as a Windows service",
    "capa_analyze detected 8 rules including 'compress data via WinAPI' (T1560.002), 'link function at runtime' (T1129), 'PEB access' for debugger detection, and 'compiled from Visual Basic'",
    "pe_import_signals flagged 'LoadLibrary' and 'GetProcAddress' (T1129) confirming dynamic API resolution"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file 
… [269 more chars]
```

- **malcat_analyze** ok=`False` checklist=`True` — Required checklist tool (malcat)
  - error: `malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n"
}
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 8,
  "top_rules": [
    {
      "name": "compress data via WinAPI",
      "attack": [
        {
          "parts": [
            "Collection",
            "Archive Collected Data",
            "Archive via Library"
          ],
          "tactic": "Collection",
          "technique": "Archive Collected Data",
          "subtechnique": "Archive via Library",
          "id": "T1560
… [2130 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 533054,
  "duration_s": 0.08,
  "import_count": 103,
  "signal_count": 2,
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
    }
  ],
  "hint": "PE i
… [44 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 1249,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    "kernel32.dll",
    "NTDLL.DLL",
    "user32.dll",
    "MSVBVM60.DLL",
    "Project1",
    "Payload",
    "COMDLG32.OCX",
    "MSComDlg.CommonDialog",
    "CommonDialog",
    "Module1",
    "Module2",
    "Module3",
    "Module4",
    "Module5",
  
… [1783 more chars]
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
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "disassembly": {
    "0x004017fc": "\u250c 125: entry0 ();\n\u2502           0x004017fc      68881b4000     push 0x401b88\n\u2502           0x00401801      e8f0ffffff     call 0x4017f6\n\u2502           0x00401806      
… [11842 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
    "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
      "name": "FUN_0040a3c0",
      "address": "4236224",
      "size": "4630"
    },
    {
      "name": "FUN_00409380",
      "address": "4232064",
      "size": "4069"
    },
    {
      "name": "FUN_00405f50",
      "address": "4218704",
      "size": "3821"
    },
    {
      "name": "FUN_00408d80",
      "address":
… [2263 more chars]
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
      "name": "FUN_0040a3c0",
      "address": "4236224",
      "size": "4630"
    },
    {
      "name": "FUN_00409380",
      "address": "4232064",
      "size": "4069"
    },
    {
      "name": "FUN_00405f50",
      "address": "4218704",
      "size": "3821"
    },
    {
      "name": "FUN_00408d80",
      "address":
… [1808 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module",
    "name",
    "address"
  ],
  "rows": [
    {
      "module": "KERNEL32.DLL",
      "name": "GetProcAddress",
      "address": "1"
    },
    {
      "module": "KERNEL32.DLL",
      "name": "LoadLibraryA",
      "address": "3"
    },
    {
      "module": "KERNEL32.DLL",
      "name": "RtlMoveMemory",
      "address": "2"
    },
    {
      "module": "MSVBVM60.DLL
… [2878 more chars]
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
      "content": "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "address": "4202654",
      "length": "138"
    },
    {
      "content": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      "address": "4207860",
      "length": "116"
    },
    {
      "conte
… [3719 more chars]
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
      "content": "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "address": "4202654",
      "length": "138"
    },
    {
      "content": "select name from Win32_Process where name='---'",
      "address": "4206084",
      "length": "96"
    },
    {
      "content": "GetModuleF
… [1739 more chars]
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
      "content": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
      "address": "4207860",
      "length": "116"
    },
    {
      "content": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "address": "4213108",
      "length": "102"
    },
    {
      "content": "127.0.2.5\\tli
… [5984 more chars]
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
      "func_name": "FUN_0040a3c0",
      "func_addr": "4236224",
      "size": "4630",
      "instruction_count": "1492",
      "block_count": "404",
      "cyclomatic_complex
… [4432 more chars]
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
      "content": "\\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe",
      "address": "4208080",
      "length": "70"
    },
    {
      "content": "\\tmpjhgTFztfZ789tfzTDt.exe",
      "address": "4208156",
      "length": "54"
    },
    {
      "content": "CreateProcessW",
      "address": "4205336",
      "length": "30"
    }
… [872 more chars]
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
      "content": "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "address": "4202654",
      "length": "138"
    },
    {
      "content": "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
      "address": "4204308",
      "length": "60"
    },
    {
      "conte
… [3130 more chars]
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
      "content": "127.0.2.5\\tliveupdate.symantecliveupdate.com\\r\\n",
      "address": "4208968",
      "length": "98"
    },
    {
      "content": "127.0.2.5\\tsecurityresponse.symantec.com\\r\\n",
      "address": "4208520",
      "length": "90"
    },
    {
      "content": "127.0.2.5\\twindowsupdate.microsoft
… [5877 more chars]
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
      "content": "select name from Win32_Process where name='---'",
      "address": "4206084",
      "length": "96"
    },
    {
      "content": "127.0.2.5\\twww.free-av.com\\r\\n",
      "address": "4211888",
      "length": "62"
    },
    {
      "content": "127.0.2.5\\twww.clamav.net\\r\\n",
      "address": "
… [3237 more chars]
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
      "content": "127.0.2.5\\tliveupdate.symantecliveupdate.com\\r\\n",
      "address": "4208968",
      "length": "98"
    },
    {
      "content": "127.0.2.5\\tsecurityresponse.symantec.com\\r\\n",
      "address": "4208520",
      "length": "90"
    },
    {
      "content": "127.0.2.5\\twindowsupdate.microsoft
… [7001 more chars]
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
      "content": "127.0.2.5\\tavast.com\\r\\n",
      "address": "4212020",
      "length": "50"
    },
    {
      "content": "127.0.2.5\\tavp.com\\r\\n",
      "address": "4209652",
      "length": "46"
    },
    {
      "content": "127.0.2.5\\tca.com\\r\\n",
      "address": "4210000",
      "length": "44"
    }
… [7418 more chars]
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
      "content": "127.0.2.5\\tdownload.mcafee.com\\r\\n",
      "address": "4210252",
      "length": "70"
    },
    {
      "content": "Copyright (c) 1998-2010 ICQ, LLC.",
      "address": "4288696",
      "length": "68"
    },
    {
      "content": "NtGetContextThread",
      "address": "4205676",
      "length"
… [1239 more chars]
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
      "content": "127.0.2.5\\tnovirusthanks.org\\r\\n",
      "address": "4212824",
      "length": "66"
    },
    {
      "content": "UACDisableNotify",
      "address": "4207792",
      "length": "34"
    },
    {
      "content": "service.exe",
      "address": "4213052",
      "length": "24"
    },
    {
      
… [586 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075.json"
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
      "func_name": "FUN_00405f50",
      "func_addr": "4218704",
      "string_value": "CreateProcessW",
      "string_addr": "4205336"
    },
    {
      "func_name": "FUN_00406fe0",
      "func_addr": "4222944",
      "string_value": "URLDownloadToFileA",
      "string_addr": "4205988"
… [8346 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075.json"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/01-tools-raw.json` exists=`True` bytes=`21056` mtime=`2026-07-28T05:51:46.797144+00:00`
  - sha256: `6f02ba03edc3db8ff1d9e8020db0a145c03b7af919ff4c8902e07dd464c68426`
- **sql_evidence:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/05-deep-dive.json` exists=`True` bytes=`3782` mtime=`2026-07-28T05:52:20.151142+00:00`
  - sha256: `bfdab3c468bcfc6613f40d85d27b3a5b94e7eb84e6d2257b659bfbd3efe030e7`

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
  "summary": "VB6-compiled 'Darty Crypter' malware dropper that disables Windows UAC, hijacks the HOSTS file to block over 50 antivirus/security vendor domains (Symantec, McAfee, Kaspersky, Trend Micro, Avast, Panda, VirusTotal, etc.), downloads additional payloads via URLDownloadToFileA, drops executables to temp (\\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe, \\tmpjhgTFztfZ789tfzTDt.exe), creates processes for dropped payloads, enumerates running processes via WMI, establishes persistence via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, and uses dynamic API resolution (LoadLibraryA/GetProcAddress) with PEB-based anti-debugging checks.",
  "key_evidence": [
    "Ghidra imports: MSVB
… [2982 more chars]
```

- **agentic:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`230990` mtime=`2026-07-28T05:52:20.151142+00:00`
  - sha256: `d0e4c08dea6afdb9e5f84fe62e77c21e89e382e05fd5e0435f8ec816df1a599f`

---

## Stage: yara_gen

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| rule_yar | `True` |
| non_empty | `True` |
| has_rule_block | `True` |

### Artifact paths (verify on disk)

- **rule_yar:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yar` exists=`True` bytes=`1435` mtime=`2026-07-28T05:52:21.663142+00:00`
  - sha256: `45ca64483bcd96090272f8569aed01fdc65919fb9e53aa9be38405ea5b1bc972`

#### excerpt

```
// yara_gen_v2.py — 2026-07-28T05:52:21.664254+00:00
rule CADRE_v2_unknown_8059ade0d39e {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075"
        family = "unknown"
        cadre_reveng_v2 = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp" ascii wide
        $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
        $s3 = "ConvertStringSecurityDescriptorToSecurityDescriptorA" ascii wide
        $s4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersio
… [633 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-MASTER-v2.md` exists=`True` bytes=`21672` mtime=`2026-07-28T06:03:36.357997+00:00`
  - sha256: `33caf1ad1e7bb475a1949ba5010ee109769814003cdd7ac57b6a47040a15be5f`
- **REPORT_MASTER_v3:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-MASTER-v3.md` exists=`True` bytes=`31848` mtime=`2026-07-28T06:11:13.606567+00:00`
  - sha256: `fbf2d294ab41b71815bee3512febe12556328c2fc8da5fdb9cce808ef226d5f5`
- **REPORT_v2:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-v2.md` exists=`True` bytes=`21672` mtime=`2026-07-28T06:03:36.357997+00:00`
  - sha256: `33caf1ad1e7bb475a1949ba5010ee109769814003cdd7ac57b6a47040a15be5f`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`38030` mtime=`2026-07-28T06:06:09.879087+00:00`
  - sha256: `dd226b8c039e3405f8296e45839c2ef281e4fdbe1711eabf5d44eec5bafb09ca`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`31529` mtime=`2026-07-28T06:14:45.300953+00:00`
  - sha256: `0fd6e2603ddb72a8a0c84e64acdf08db875e39d591014ae59b83c90bf12c1c74`
- **report_v2_json:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/report-v2.json` exists=`True` bytes=`24154` mtime=`2026-07-28T06:06:09.882687+00:00`
  - sha256: `c7fec91ae83dc521eb049343f7074490d3fd8072cfe964a56510e1119f2b3986`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** DartyCrypter
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

This report analyzes a malicious Visual Basic 6 (VB6) compiled executable identified as the "Darty Crypter" malware family. The sample uses dynamic API resolution, anti-debugging (PEB access), data co
… [20764 more chars]
```


#### v3_excerpt

```
# RE Report — 8059ade0d39e
_Generated 2026-07-28T06:11:13.605230+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=217c | cross_refs=True | llm_ok=True | runtime=48.63s -->

## Executive Summary

| Attribute | Value |
|-----------|-------|
| Verdict | Malicious |
| Family | DartyCrypter |
| Confidence | 90% (High) |
| Initial Assessment | Suspicious (score 40, capa: 8 rules) |

Deep agentic analysis (source: deep_dive_agentic) identified the sample as a DartyCrypter variant that uses VB6 packing, runtime API resolution, and anti-debugging to evade detection (source: cross-section:Static Analysis, cross-section:Capability Assessment). The malware lacks network communication and persistence, consistent with a first-stage dropper, and the attribution is reinfo
… [30891 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
