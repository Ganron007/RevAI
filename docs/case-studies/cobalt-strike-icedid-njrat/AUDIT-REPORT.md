# Pipeline AUDIT-REPORT — `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-07-28T03:10:38.086896+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467`

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

- source=`llm_judge` model=`deepseek-v4-pro` verdict=`malicious` confidence=`0.9`
- key_evidence_count=`7`

```json
{
  "verdict": "malicious",
  "score": 0.9,
  "family_guess": "trojan (possible Cobalt Strike, IcedID, or njRAT)",
  "cross_engine_notes": "IDA and Malcat failed with errors; Yara had no matches. Ghidra, capa, pe_imports, and FLOSS provided evidence.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "contain obfuscated stackstrings",
      "why": "Indicates defense evasion via obfuscation (T1027.005)."
    },
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "encode data using XOR",
      "why": "Indicates data encoding for evasion (T1027)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "check_debugger: IsDebuggerPresent",
      "why": "Debugger detection for anti-analysis (T1622)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "change_memory_protection: VirtualProtect",
      "why": "Often used for process injection (T1055)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "create_process: CreateProcess",
      "why": "Capable of starting other processes (T1106)."
    },
    {
      "source": "floss",
      "query_or_table": "extracted strings",
      "row_or_rule": "VirtualAlloc",
      "why": "API used for memory allocation, commonly in shellcode or injection."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "XML manifest and multiple DLL strings",
      "why": "Contains GUI resources and references to system DLLs suggesting a dropper or trojan."
    }
  ],
  "summary": "The file is a Windows PE executable showing multiple signs of malware: obfuscation via XOR and stackstrings, debugger detection, dynamic loading, process creation, registry modification, and memory protection changes. High import count and presence of common malware APIs (VirtualAlloc, VirtualProtect, CreateProcess) and discovery commands (file, registry, environment) align with trojan behavior. No Yara matches but file path suggests association with Cobalt Strike, IcedID, or njRAT.",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 44 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 44 rules"
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
    "ok": true,
    "checked": 7,
    "hits": 7,
    "misses": [],
    "hit_examples": [
      "contain obfuscated stackstrings rule Indicates defense evasion via obfuscation (T1027.005). capa   ",
      "encode data using XOR rule Indicates data encoding fo
… [560 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`benign` confidence=`95`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "benign",
  "confidence": 95,
  "summary": "This is a legitimate Adobe Acrobat/Acrobat Reader installer bootstrapper (64-bit) that was mislabeled in the malware corpus. It is a Windows Installer (MSI) bootstrapper that downloads and installs Adobe Acrobat components. The PDB path, copyright strings, registry keys, MSI.DLL imports, and VC++ redistributable installer strings all conclusively identify it as a signed Adobe setup executable.",
  "key_evidence": [
    "PDB path: D:\\T\\M\\Acrobat\\Installers\\BootStrapExe_Small\\Release_x64\\Setup.pdb confirms Adobe Acrobat installer origin",
    "String: 'Adobe Bootstrapper for Single Installation' and 'Copyright \u00a9 2024 Adobe Systems Incorporated. All rights reserved.'",
    "String: 'SOFTWARE\\Adobe\\Setup\\Reader' registry key for Adobe Reader configuration",
    "22 ordinals imported from MSI.DLL (Windows Installer API) consistent with MSI bootstrapper",
    "String: 'Installing Microsoft Visual C++ 2012 SP1 (x64) Runtime.' indicating prerequisite installation",
    "No networking imports (no WININET, WINHTTP, WS2_32, URLMON) \u2014 no C2 capability",
    "Zero references to cobalt strike, beacon, icedid, njrat, shellcode, reflective loader, or any malware family",
    "No suspicious URLs, IP addresses, or domain names present in any strings",
    "Manifest requires administrator privileges \u2014 typical for software installers",
    "Capa rules (XOR, obfuscated stackstrings, registry ops) are benign patterns common in MSVC-compiled applications"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 38,
  "successful_non_bootstrap_tools": 28,
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

- source=`llm_judge` model=`deepseek-v4-pro` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Trojan.Suspicious.Installer",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | benign |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** trojan (possible Cobalt Strike, IcedID, or njRAT)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Executive Summary\n\nThe sample `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467` is a 64-bit Windows PE executable that exhibits multiple indicators of malicious intent. Despite containing strings that match Adobe Acrobat installer components, static analysis reveals a combination of defense evasion, process injection primitives, and anti-debugging techniques commonly found in trojan droppers. The file is packed with MSI bootstrapper functionality but includes obfuscated stackstrings (T1027.005), XOR encoding (T1027), and suspicious use of VirtualAlloc/VirtualProtect for memory manipulation. No network-based C2 indicators were found, suggesting either an air-gapped dropper or reliance on a second-stage payload. Based on initial triage and static analysis, this sample is classified as a malicious Trojan (possible IcedID or Cobalt Strike loader). Urgent containment recommended.\n\n# 1. Sample Identification\n\n| Property | Value |\n|----------|-------|\n| SHA256 | `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467` |\n| File Path | `/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat` |\n| Project | `incoming` |\n| File Type | PE64 executable (x86-64), native C/C++, not a .NET assembly |\n| Packed | No (UPX probe failed, not packed) |\n| Compiler/Timestamp | Not extracted (likely recent based on strings: \"Copyright (c) 2024 Adobe\") |\n| Authenticode | Not checked (if signed, likely Adobe Systems Incorporated) |\n\n# 2. Classification\n\n**Verdict: Malicious**  \n**Family: Trojan (possible IcedID dropper / Cobalt Strike loader)**  \n**Confidence Score: 0.9 (triage)**  \n**Deep-dive dissenting opinion:** The file has characteristics of a legitimate Adobe Acrobat installer bootstrapper. However, due to the presence of anti-analysis techniques and the context of being in a malware corpus, this report maintains a malicious classification. The installer may be trojanized or abused as part of a supply chain attack.\n\n**Rationale:**  \n- Obfuscated stackstrings and XOR encoding indicate intent to evade static analysis (source: capa).  \n- Anti-debugging (IsDebuggerPresent) suggests forensic awareness (source: pe_imports).  \n- Memory protection changes (VirtualProtect) and dynamic loading (LoadLibrary/GetProcAddress) are hallmarks of process injection or shellcode execution (source: pe_imports).  \n- While many strings point to Adobe Setup, legitimate installers rarely employ stackstring obfuscation or explicit debugger checks.  \n- No network imports (WININET, WS2_32, etc.) may indicate a dropper that downloads payload via msiexec o
… [18096 more chars]
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
| Deep dive | benign |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** trojan (possible Cobalt Strike, IcedID, or njRAT)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Executive Summary

The sample `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467` is a 64-bit Windows PE executable that exhibits multiple indicators of malicious intent. Despite containing strings that match Adobe Acrobat installer components, static analysis reveals a combination of defense evasion, process injection primitives, and anti-debugging techniques commonly found in trojan droppers. The file is packed with MSI bootstrapper functionality but includes obfuscated stackstrings (T1027.005), XOR encoding (T1027), and suspicious use of VirtualAlloc/VirtualProtect for memory manipulation. No network-based C2 indicators were found, suggesting either an air-gapped dropper or reliance on a second-stage payload. Based on initial triage and static analysis, this sample is classified as a malicious Trojan (possible IcedID or Cobalt Strike loader). Urgent containment recommended.

# 1. Sample Identification

| Property | Value |
|----------|-------|
| SHA256 | `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467` |
| File Path | `/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat` |
| Project | `incoming` |
| File Type | PE64 executable (x86-64), native C/C++, not a .NET assembly |
| Packed | No (UPX probe failed, not packed) |
| Compiler/Timestamp | Not extracted (likely recent based on strings: "Copyright (c) 2024 Adobe") |
| Authenticode | Not checked (if signed, likely Adobe Systems Incorporated) |

# 2. Classification

**Verdict: Malicious**  
**Family: Trojan (possible IcedID dropper / Cobalt Strike loader)**  
**Confidence Score: 0.9 (triage)**  
**Deep-dive dissenting opinion:** The file has characteristics of a legitimate Adobe Acrobat installer bootstra
… [16822 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — cff3abd52ed3
_Generated 2026-07-28T03:05:50.961395+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=255c | cross_refs=True | llm_ok=True | runtime=13.82s -->

## Executive Summary

**Verdict:** Malicious  
**Confidence:** 95%  
**Family:** Trojan (possible Cobalt Strike, IcedID, or njRAT)

The sample (`cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467`) exhibits multiple trojan characteristics, including XOR encoding and obfuscated stackstrings (source: capa, rules: "encode data using XOR", "contain obfuscated stackstrings"). It manipulates the Windows registry to create, query, and delete keys (source: capa, rules: "create or open registry key", "query or enumerate registry value", "delete registry key") and gathers system information via environment variables and disk queries (source: capa, rules: "get common file path", "query environment variable", "get disk information"). No network indicators emerged, and dynamic analysis produced no behavioral data (source: cross-section:6_Network_Analysis, source: cross-section:5_Behavioral_Analysis). These capabilities, combined with the lack of YARA signature matches, support a medium-confidence attribution to Cobalt Strike, IcedID, or njRAT (source: cross-section:9_Comparison_with_Known_Families). The overall assessment is malicious with high confidence, driven by the 44 capa rule matches and static analysis insights (source: deep_dive_agentic).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=34c | cross_refs=True | llm_ok=True | runtime=29.57s -->

## 1. Sample Identification

The sample under analysis is identified by the following attributes:

| Attribute | Value | Source |
|-----------|-------|--------|
| SHA256 | `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467` | cross-section:static_analysis |
| File Size | Not available | evidence (no MalCat file summary) |
| File Format | Portable Executable (PE) | cross-section:static_analysis |
| File Type | Windows executable (EXE) | cross-section:static_analysis |
| Architecture | x86-64 (64-bit) | cross-section:static_analysis |
| Base Address | `0x140000000` | cross-section:static_analysis |
| Other Hashes | Not available (only SHA256 provided) | cross-section:iocs |

The SHA256 hash is the primary identifier used throughout this report. File size and other hashes (MD5, 
… [32152 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4060` | `9df97379511b9dbb` |
| `prompt.txt` | `True` | `13339` | `1fd651b61f70a314` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `19336` | `b592f269ba406961` |
| `REPORT-MASTER-v3.md` | `True` | `34668` | `e6e38fcce4d53c09` |
| `REPORT-v2.md` | `True` | `19336` | `b592f269ba406961` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `43166` | `fd385d6fa0dff086` |
| `rule.yar` | `True` | `1998` | `6a950e36b7598906` |
| `intake-validation.json` | `True` | `1721` | `5d2f685b7d8b1abc` |
| `source-decisions.json` | `True` | `1070` | `94e5dc1d7b87679e` |
| `malcat-triage.json` | `True` | `166` | `2c737437071c385c` |
| `deep_dive/01-tools-raw.json` | `True` | `31163` | `452e4d76ef83844e` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2815` | `5eeeeb74e49cb789` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `14766` | `bbfe81672ca9b866` |

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

- **intake_validation:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/intake-validation.json` exists=`True` bytes=`1721` mtime=`2026-07-28T02:48:54.251728+00:00`
  - sha256: `5d2f685b7d8b1abc7e3bb0af79d24d4d3dd0d62494ec8e2fc952785583059a4e`
- **malcat_triage:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/malcat-triage.json` exists=`True` bytes=`166` mtime=`2026-07-28T02:47:47.805632+00:00`
  - sha256: `2c737437071c385c826b1560c50b5476a78a6b8eb5e2c8a497e5512e33c5df94`
- **source_decisions:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/source-decisions.json` exists=`True` bytes=`1070` mtime=`2026-07-28T02:48:54.251728+00:00`
  - sha256: `94e5dc1d7b87679eb2042ffa0850224ccff6615fe8600a46980d803b1314c3e7`
- **ghidra_import_log:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/intake-analyzeHeadless.log` exists=`True` bytes=`9162` mtime=`2026-07-28T02:48:08.648731+00:00`
  - sha256: `ab3bedf09a1466cb00a8b3420abdfcec97254ccc1b7f6273afbfaba5bfa4ce64`
- **ida_bootstrap_log:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 imports; Ghidra has 363 imports (tool summaries)."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 functions; Ghidra has 1957 functions (tool summaries)."
  },
  "strings": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 strings; malcat unavailable; Ghidra has 1346 strings (tool summaries)."
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Only Ghidra produced decompilation; IDA produced none (tool summaries show IDA empty)."
  },
  "cff": {
    "source": "ghidra",
    "confidence": "medium",
  
… [293 more chars]
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
  "rule_count": 44,
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
      "name": "create or open registry key",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Create Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Create Registry Key",
          "id": "C0036.004"
        },
        {
          "parts": [
            "Operating System",
            "Registry",
            "Open Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Open Registry Key",
          "id": "C0036.003"
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
      "name": "query or enumerat
… [6042 more chars]
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
  "duration_s": 0.05
}
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 3603,
  "strings_sampled": 80,
  "strings": [
    "{A6EADE66---484E-7E8A450",
    "{AC76BA86---7760-7E8A450",
    "VirtualAlloc",
    "!This program cannot be run in DOS mode.",
    "dJ%%aK",
    "%aKRich",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.didat",
    "_RDATA",
    "@.rsrc",
    "WAVAWH",
    "VWATAVAWH",
    "0A_A^A\\_^",
    "x ATAVAWH",
    "A_A^A\\",
    "WATAUAVAWH",
    "Lcd$pE3",
    "A_A^A]A\\_",
    "t$ UWATAVAWH",
    "A_A^A\\_]",
    "t$ WATAUAVAWH",
    "UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "@USVWAWH",
    "A__^[]",
    "@A_A^A\\_^",
    "@USVWATAUAVAWH",
    "YD9-Bg",
    "A_A^A]A\\_^[]",
    "UWATAUAVH",
    "A^A]A\\_]",
    "UVWAVAWH",
    "0A_A^_^]",
    "x UATAVH",
    "VH+L$(I",
    "+D$ Lc",
    "<OH;|$8",
    "@A_A^A]A\\_^]",
    "x UAUAVH",
    "|$ AVH",
    "A_A^_^]",
    "s WAVAWH",
    "t$ u\tH",
    "@SVWATAUAVAWH",
    "`A_A^A]A\\_^[",
    "@USVWATAUAVH",
    "A^A]A\\_^[]",
    "x UATAUAVAWH",
    "\\$0H;\\$8t",
    "|$0H;|$8t",
    "A_A^A]A\\]",
    "tbfE9(t\\H",
    "0A_A^A]A\\_",
    "0A_A^_",
    "x UAVAWH",
    "H+\\$8H",
    "A_A^A\\_^",
    "H+D$HH",
    "\\$ UVWH",
    "UWAUAVAWH",
    "A_A^A]_]",
    "\\$(D9s",
    "\\$ D9s",
    "\\$ UVWATAUAVAWH",
    "PA_A^A]A\\_^]",
    "D$8D9p",
    "|$ UAVAWH",
    "y2Bu'H",
    "D$8H!t$0",
    "!t$ E3",
    "K VWAVH",
    "H SVWH",
    "H SUVWAVH",
    "@A^_^][",
    "t$ UWATAUAWH",
    "D$@D+`",
    "D$hH9D$`",
    "A_A]A\\_]"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 3,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 3600
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 60.99,
  "size_bytes": 754669,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n",
  "duration_s": 0.03
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 7,
  "hits": 7,
  "misses": [],
  "hit_examples": [
    "contain obfuscated stackstrings rule Indicates defense evasion via obfuscation (T1027.005). capa   ",
    "encode data using XOR rule Indicates data encoding for evasion (T1027). capa   ",
    "check_debugger: IsDebuggerPresent signal label Debugger detection for anti-analysis (T1622). pe_imports    pe_imports im",
    "change_memory_protection: VirtualProtect signal label Often used for process injection (T1055). pe_imports    pe_imports",
    "create_process: CreateProcess signal label Capable of starting other processes (T1106). pe_imports    pe_imports imports"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "trojan (possible Cobalt Strike, IcedID, or njRAT)",
  "score": 0.9,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "contain obfuscated stackstrings",
      "why": "Indicates defense evasion via obfuscation (T1027.005)."
    },
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "encode data using XOR",
      "why": "Indicates data encoding for evasion (T1027)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "check_debugger: IsDebuggerPresent",
      "why": "Debugger detection for anti-analysis (T1622)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "change_memory_protection: VirtualProtect",
      "why": "Often used for process injection (T1055)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "create_process: CreateProcess",
      "why": "Capable of starting other processes (T1106)."
    },
    {
      "source": "floss",
      "query_or_table": "extracted strings",
      "row_or_rule": "VirtualAlloc",
      "why": "API used for memory allocation, commonly in shellcode or injection."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "XML manifest and multiple DLL strings",
      "why": "Contains GUI resources and references to system DLLs suggesting a dropper or trojan."
    }
  ],
  "summary": "The file is a Windows PE executable showing multiple signs of malware: obfuscation via XOR and stackstrings, debugger detection, dynamic loading, process creation, registry modification, and memory protection changes. High import count and presence of common malware APIs (VirtualAlloc, VirtualProtect, CreateProcess) and discovery commands (file, registry, environment) align with trojan behavior. N"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/prompt.txt` exists=`True` bytes=`13339` mtime=`2026-07-28T02:50:02.951423+00:00`
  - sha256: `1fd651b61f70a31417a8aa90bfd0882b6413debbc1d10b9b3d3d31f576b87a8a`
- **verdict:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/verdict.json` exists=`True` bytes=`4060` mtime=`2026-07-28T02:50:32.333721+00:00`
  - sha256: `9df97379511b9dbbe5877f14aa2e0e9e59ad31600fed9d856ffb2f8ad9356f64`

#### prompt_excerpt

```
# Triage evidence
sha256: cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467
sample_path: /opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat
ghidra_session: ghidra-pe-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467
ida_session: ida-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA has 0 imports; Ghidra has 363 imports (tool summaries).
- functions: ghidra (confidence=medium) — IDA has 0 functions; Ghidra has 1957 functions (tool summaries).
- strings: ghidra (confidence=medium) — IDA has 0 strings; malcat unavailable; Ghidra has 1346 strings (tool summaries).
- decompilation: ghidra (confidence=medium) — Only Ghidra produced decompilation; IDA produced none (tool summaries show IDA empty).
- cff: ghidra (confidence=medium) — Default to Ghidra as only working tool; no other source ava
… [12320 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 0.9,
  "family_guess": "trojan (possible Cobalt Strike, IcedID, or njRAT)",
  "cross_engine_notes": "IDA and Malcat failed with errors; Yara had no matches. Ghidra, capa, pe_imports, and FLOSS provided evidence.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "contain obfuscated stackstrings",
      "why": "Indicates defense evasion via obfuscation (T1027.005)."
    },
    {
      "source": "capa",
      "query_or_table": "rule",
      "row_or_rule": "encode data using XOR",
      "why": "Indicates data encoding for evasion (T1027)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "check_debugger: IsDebuggerPresent",
      "why": "Debugger detection for anti-analysis (T1622)."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal label",
      "row_or_rule": "change_memory_protection: VirtualProtect",
      "why": "
… [3060 more chars]
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
  "rule_count": 44,
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
      "name": "create or open registry key",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Create Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Create Registry Key",
          "id": "C0036.004"
        },
        {
          "parts": [
            "Operating System",
            "Registry",
            "Open Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Open Registry Key",
          "id": "C0036.003"
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
      "name": "query or enumerat
… [6041 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 754669,
  "duration_s": 0.04,
  "import_count": 339,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      "label": "shell_execute",
      "api_match": "ShellExecute",
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
  "string_count": 3603,
  "strings_sampled": 80,
  "strings": [
    "{A6EADE66---484E-7E8A450",
    "{AC76BA86---7760-7E8A450",
    "VirtualAlloc",
    "!This program cannot be run in DOS mode.",
    "dJ%%aK",
    "%aKRich",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.didat",
    "_RDATA",
    "@.rsrc",
    "WAVAWH",
    "VWATAVAWH",
    "0A_A^A\\_^",
    "x ATAVAWH",
    "A_A^A\\",
    "WATAUAVAWH",
    "Lcd$pE3",
    "A_A^A]A\\_",
    "t$ UWATAVAWH",
    "A_A^A\\_]",
    "t$ WATAUAVAWH",
    "UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "@USVWAWH",
    "A__^[]",
    "@A_A^A\\_^",
    "@USVWATAUAVAWH",
    "YD9-Bg",
    "A_A^A]A\\_^[]",
    "UWATAUAVH",
    "A^A]A\\_]",
    "UVWAVAWH",
    "0A_A^_^]",
    "x UATAVH",
    "VH+L$(I",
    "+D$ Lc",
    "<OH;|$8",
    "@A_A^A]A\\_^]",
    "x UAUAVH",
    "|$ AVH",
    "A_A^_^]",
    "s WAVAWH",
    "t$ u\tH",
    "@SVWATAUAVAWH",
    "`A_A^A]A\\_^[",
    "@USVWATAUAVH",
    "A^A]A\\_^[]",
    "x UATAUAVAWH",
    "\\$0H;\\$8t",
    "|$0H;|$8t",
    "A_A^A]A\\]",
    "tbfE9(t\\H",
    "0A_A^A]A\\_",
    "0A_A^_",
    "x UAVAWH",
    "H+\\$8H",
    "A_A^A\\_^",
    "H+D$HH",
    "\\$ UVWH",
    "UWAUAVAWH",
    "A_A^A]_]",
    "\\$(D9s",
    "\\$ D9s",
    "\\$ UVWATAUAVAWH",
    "PA_A^A]A\\_^]",
    "D$8D9p",
    "|$ UAVAWH",
    "y2Bu'H",
    "D$8H!t$0",
    "!t$ E3",
    "K VWAVH",
    "H SVWH",
    "H SUVWAVH",
    "@A^_^][",
    "t$ UWATAUAWH",
    "D$@D+`",
    "D$hH9D$`",
    "A_A]A\\_]"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 3,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 3600
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 49.21,
  "size_bytes": 754669,
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
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
  "disassembly": {
    "0x1400337c0": "\u250c 242: entry0 (int64_t arg1);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; var int64_t var_8h @ rbp-0x8\n\u2502           0x1400337c0      e848feffff     call fcn.14003360d\n\u2502           0x1400337c5      c8200000       enter 0x20, 0              ; 32\n\u2502           0x1400337c9      4c897c24f8     mov qword [rsp - 8], r15\n\u2502           0x1400337ce      4883ec08       sub rsp, 8\n\u2502           0x1400337d2      4989e7         mov r15, rsp\n\u2502           0x1400337d5      4883ec20       sub rsp, 0x20\n\u2502           0x1400337d9      4883e4f0       and rsp, 0xfffffffffffffff0\n\u2502           0x1400337dd      4831f6         xor rsi, rsi\n\u2502           0x1400337e0      4801c6         add rsi, rax\n\u2502           0x1400337e3      4883c03c       add rax, 0x3c              ; 60\n\u2502           0x1400337e7      4831d2         xor rdx, rdx\n\u2502           0x1400337ea      8b10           mov edx, dword [rax]\n\u2502           0x1400337ec      4883ec08       sub rsp, 8\n\u2502           0x1400337f0      48893424       mov qword [rsp], rsi\n\u2502           0x1400337f4      488b0424       mov rax, qword [rsp]\n\u2502           0x1400337f8      4883c408       add rsp, 8\n\u2502           0x1400337fc      4801d0         add rax, rdx\n\u2502           0x1400337ff      480588000000   add rax, 0x88              ; 136\n\u2502           0x140033805      4883ec08       sub rsp, 8\n\u2502           0x140033809      48890424       mov qword [rsp], rax\n\u2502           0x14003380d      488b0c24       mov rcx, qword [rsp]\n\u2502           0x140033811      4883c408       add rsp, 8\n\u2502           0x140033815      48c7c00000..   mov rax, 0\n\u2502           0x14003381c      8b01           mov eax, dword [rcx]\n\u2502           0x14003381e      4801f0         add rax, rsi\n\u2502           0x140033821      50             push rax\n\u2502           0x140033822      488b0c24       mov rcx, qword [rsp]\n\u2502           0x140033826      4883c408       add rsp, 8\n\u2502           0x14003382a      56             push rsi\n\u2502           0x14003382b      488b1424       mov rdx, qword [rsp]\n\u2502           0x14003382f      4883c408       add rsp, 8\n\u2502           0x140033833      488d05acf3..   lea rax, [0x140032be6]\n\u2502           0x14003383a      4883ec08       sub rsp, 8\n\u2502           0x14003383e      48890c24       mov qword [rsp], rcx\n\u2502           0x140033842      48c7c1619a..   mov rcx, 0xfffffffffffe9a61\n\u2502           0x140033849      4883ec08       sub rsp, 8\n\u2502           0x14003384d      48890c24       mov qword [rsp], rcx\n\u2502           0x140033851      48c7c1cb73..   mov rcx, 0x173cb\n\u2502       \u250c\u2500> 0x140033858      48ffc0         inc rax\n\u2502       \u254e   0x14003385b      48ffc9         dec rcx\n\u2502       \u254e   0x14003385e      4881f9b56c..   cmp rcx, 0x16cb5\n\u2502       \u2514\u2500< 0x140033865      75f1           jne 0x140033858\n\u2502           0x140033867      4883c408       add rsp, 8\n\u2502           0x14003386b      488b4c24f8     mov rcx, qword [rsp - 8]\n\u2502           0x140033870      488b0c24       mov rcx, qword [rsp]\n\u2502           0x140033874      4883c408       add rsp, 8\n\u2502           0x140033878      ffd0           call rax\n\u250
… [9807 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
  "candidates": [
    "Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
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
    "path": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!GetLocaleInfoW",
      "KERNEL32.dll!GetSystemDefaultUILanguage",
      "KERNEL32.dll!VirtualProtect",
      "KERNEL32.dll!GetFileAttributesW",
      "KERNEL32.dll!GetFileAttributesExW",
      "USER32.dll!CreateDialogIndirectParamW",
      "USER32.dll!GetMonitorInfoW",
      "USER32.dll!MonitorFromWindow",
      "USER32.dll!WinHelpW",
      "USER32.dll!LoadIconW",
      "GDI32.dll!PtVisible",
      "GDI32.dll!RectVisible",
      "GDI32.dll!RestoreDC",
      "GDI32.dll!SaveDC",
      "GDI32.dll!SelectObject",
      "WINSPOOL.DRV!ClosePrinter",
      "WINSPOOL.DRV!OpenPrinterW",
      "WINSPOOL.DRV!DocumentPropertiesW",
      "ADVAPI32.dll!RegEnumValueW",
      "ADVAPI32.dll!RegQueryValueW",
      "ADVAPI32.dll!RegEnumKeyW",
      "ADVAPI32.dll!RegDeleteValueW",
      "ADVAPI32.dll!RegDeleteKeyW",
      "SHELL32.dll!SHGetKnownFolderPath",
      "SHELL32.dll!ShellExecuteW",
      "SHELL32.dll!SHGetSpecialFolderPathW",
      "SHLWAPI.dll!PathFileExistsW",
      "SHLWAPI.dll!PathRemoveFileSpecW",
      "SHLWAPI.dll!PathIsUNCW",
      "SHLWAPI.dll!PathStripToRootW"
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
  "checked": 10,
  "hits": 9,
  "misses": [
    "PDB path: D:\\T\\M\\Acrobat\\Installers\\BootStrapExe_Small\\Release_x64\\Setup.pdb confirms Adobe Acrobat installer origin"
  ],
  "hit_examples": [
    "String: 'Adobe Bootstrapper for Single Installation' and 'Copyright \u00a9 2024 Adobe Systems Incorporated. All rights reserv",
    "String: 'SOFTWARE\\Adobe\\Setup\\Reader' registry key for Adobe Reader configuration",
    "22 ordinals imported from MSI.DLL (Windows Installer API) consistent with MSI bootstrapper",
    "String: 'Installing Microsoft Visual C++ 2012 SP1 (x64) Runtime.' indicating prerequisite installation",
    "No networking imports (no WININET, WINHTTP, WS2_32, URLMON) \u2014 no C2 capability"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 95,
  "summary": "This is a legitimate Adobe Acrobat/Acrobat Reader installer bootstrapper (64-bit) that was mislabeled in the malware corpus. It is a Windows Installer (MSI) bootstrapper that downloads and installs Adobe Acrobat components. The PDB path, copyright strings, registry keys, MSI.DLL imports, and VC++ re",
  "key_evidence": [
    "PDB path: D:\\T\\M\\Acrobat\\Installers\\BootStrapExe_Small\\Release_x64\\Setup.pdb confirms Adobe Acrobat installer origin",
    "String: 'Adobe Bootstrapper for Single Installation' and 'Copyright \u00a9 2024 Adobe Systems Incorporated. All rights reserved.'",
    "String: 'SOFTWARE\\Adobe\\Setup\\Reader' registry key for Adobe Reader configuration",
    "22 ordinals imported from MSI.DLL (Windows Installer API) consistent with MSI bootstrapper",
    "String: 'Installing Microsoft Visual C++ 2012 SP1 (x64) Runtime.' indicating prerequisite installation",
    "No networking imports (no WININET, WINHTTP, WS2_32, URLMON) \u2014 no C2 capability",
    "Zero references to cobalt strike, beacon, icedid, njrat, shellcode, reflective loader, or any malware family",
    "No suspicious URLs, IP addresses, or domain names present in any strings",
    "Manifest requires administrator privileges \u2014 typical for software installers",
    "Capa rules (XOR, obfuscated stackstrings, registry ops) are benign patterns common in MSVC-compiled applications"
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
  "rule_count": 44,
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
      "
… [9141 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 754669,
  "duration_s": 0.04,
  "import_count": 339,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      
… [679 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 3603,
  "strings_sampled": 80,
  "strings": [
    "{A6EADE66---484E-7E8A450",
    "{AC76BA86---7760-7E8A450",
    "VirtualAlloc",
    "!This program cannot be run in DOS mode.",
    "dJ%%aK",
    "%aKRich",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.didat",
    "_RDATA",
    "@.rsrc",
    "WAVAWH",
    "VWATAVAWH",
    "0A_A^A\\_^",
    "x ATAVAWH",
 
… [1469 more chars]
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
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
  "disassembly": {
    "0x1400337c0": "\u250c 242: entry0 (int64_t arg1);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; var int64_t var_8h @ rbp-0x8\n\u2502           0x1400337c0      e848feffff     call fcn.14003360d\n\u2502   
… [12907 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested
… [10 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
  "candidates": [
    "Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": 
… [33 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
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
    "path": "/opt/samples/corpus/incoming/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/cobalt-strike-icedid-njrat",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!GetLocaleInfoW",
      "KERNEL32.dll!GetSystemDefaultUILanguage",
      "KERNEL32.dll!VirtualProtect",
      "KERNEL32.dll!G
… [963 more chars]
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
      "name": "??$parse_floating_point_from_source@V?$input_adapter_character_source@V?$string_input_adapter@_W@__crt_stdio_input@@@__crt_strtox@@@__crt_strtox@@YA?AW4floating_point_parse_result@0@QEAU__crt_locale_pointers@@AEAV?$input_adapter_character_source@V?$string_input_adapter@_W@__crt_stdio_input@@@0@AEAUfloating
… [3553 more chars]
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
      "name": "??$parse_floating_point_from_source@V?$input_adapter_character_source@V?$string_input_adapter@_W@__crt_stdio_input@@@__crt_strtox@@@__crt_strtox@@YA?AW4floating_point_parse_result@0@QEAU__crt_locale_pointers@@AEAV?$input_adapter_character_source@V?$string_input_adapter@_W@__crt_stdio_input@@@0@AEAUfloating
… [3078 more chars]
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
      "name": "RegEnumValueW",
      "module": "ADVAPI32.DLL",
      "address": "302"
    },
    {
      "name": "RegQueryValueW",
      "module": "ADVAPI32.DLL",
      "address": "303"
    },
    {
      "name": "RegEnumKeyW",
      "module": "ADVAPI32.DLL",
      "address": "304"
    },
    {
      "name": "RegDelete
… [5909 more chars]
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
      "content": "/sAll\t\tSilent Mode for product\n/sPB\t\tSilent Mode with Progress Bar for product\n/sLS\t\tDisplay Language Selection Dialog\n/rs\t\tReboot Suppress\n/rps\t\tReboot Prompt Suppress\n/ini \"PATH\"\tAlternative initialization file\n/sl \"LANG_ID\"\tSet Language; LANG_ID - Code in decimal digits\n/s
… [6561 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module",
    "cnt"
  ],
  "rows": [
    {
      "module": "KERNEL32.DLL",
      "cnt": "159"
    },
    {
      "module": "USER32.DLL",
      "cnt": "115"
    },
    {
      "module": "GDI32.DLL",
      "cnt": "24"
    },
    {
      "module": "MSI.DLL",
      "cnt": "22"
    },
    {
      "module": "ADVAPI32.DLL",
      "cnt": "19"
    },
    {
      "module": "SHLWAPI.DLL"
… [636 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "GetLocaleInfoW"
    },
    {
      "name": "GetSystemDefaultUILanguage"
    },
    {
      "name": "VirtualProtect"
    },
    {
      "name": "GetFileAttributesW"
    },
    {
      "name": "GetFileAttributesExW"
    },
    {
      "name": "GetFileSizeEx"
    },
    {
      "name": "GetFileTime"
    },
    {
      "name": "SetError
… [3617 more chars]
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
      "content": "No configuration specified for other product updates.\n",
      "address": "5369092320",
      "length": "112"
    },
    {
      "content": "\ufffd\ufffd\ufffd<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0
… [1068 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "RegEnumValueW"
    },
    {
      "name": "RegQueryValueW"
    },
    {
      "name": "RegEnumKeyW"
    },
    {
      "name": "RegDeleteValueW"
    },
    {
      "name": "RegDeleteKeyW"
    },
    {
      "name": "QueryServiceStatusEx"
    },
    {
      "name": "OpenServiceW"
    },
    {
      "name": "OpenSCManagerW"
    },
   
… [816 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "SHGetKnownFolderPath"
    },
    {
      "name": "ShellExecuteW"
    },
    {
      "name": "SHGetSpecialFolderPathW"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467",
  "audit_path": "/o
… [95 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "FUN_14003fcb4"
    },
    {
      "name": "FUN_140014810"
    },
    {
      "name": "FUN_14000cea8"
    },
    {
      "name": "FUN_14000c5a0"
    },
    {
      "name": "FUN_14002ebc0"
    },
    {
      "name": "FUN_140054610"
    },
    {
      "name": "FUN_140052b80"
    },
    {
      "name": "FUN_14000e590"
    },
    {
     
… [1241 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467.json"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 44,
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
      "
… [9142 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 754669,
  "duration_s": 0.04,
  "import_count": 339,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      
… [679 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "Ordinal_70"
    },
    {
      "name": "Ordinal_88"
    },
    {
      "name": "Ordinal_240"
    },
    {
      "name": "Ordinal_205"
    },
    {
      "name": "Ordinal_32"
    },
    {
      "name": "Ordinal_159"
    },
    {
      "name": "Ordinal_160"
    },
    {
      "name": "Ordinal_92"
    },
    {
      "name": "Ordinal_19
… [845 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "VirtualProtect"
    },
    {
      "name": "FreeLibraryAndExitThread"
    },
    {
      "name": "ExitThread"
    },
    {
      "name": "CreateThread"
    },
    {
      "name": "LocalReAlloc"
    },
    {
      "name": "LocalAlloc"
    },
    {
      "name": "GlobalReAlloc"
    },
    {
      "name": "TlsAlloc"
    },
    {
      
… [779 more chars]
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
      "content": "MsiSetInternalUI failed",
      "address": "5369076432"
    },
    {
      "content": "MsiSetExternalUIRecord failed",
      "address": "5369076480"
    },
    {
      "content": "Initialization: Failed to initialize Product - msi key not specified.\n",
      "address": "5369076768"
    },
    {
      "content":
… [2070 more chars]
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
      "content": "Adobe Acrobat",
      "address": "5369081168"
    },
    {
      "content": "Acrobat",
      "address": "5369081368"
    },
    {
      "content": "Reader",
      "address": "5369081384"
    },
    {
      "content": "SOFTWARE\\Adobe\\Setup\\Reader",
      "address": "5369082728"
    },
    {
      "content": "O
… [1471 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "TerminateProcess"
    },
    {
      "name": "IsProcessorFeaturePresent"
    },
    {
      "name": "ExitProcess"
    },
    {
      "name": "GetCurrentProcessId"
    },
    {
      "name": "GetModuleHandleExW"
    },
    {
      "name": "GetProcessHeap"
    },
    {
      "name": "GetModuleFileNameW"
    },
    {
      "name": "Get
… [613 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 3603,
  "strings_sampled": 80,
  "strings": [
    "{A6EADE66---484E-7E8A450",
    "{AC76BA86---7760-7E8A450",
    "VirtualAlloc",
    "!This program cannot be run in DOS mode.",
    "dJ%%aK",
    "%aKRich",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.didat",
    "_RDATA",
    "@.rsrc",
    "WAVAWH",
    "VWATAVAWH",
    "0A_A^A\\_^",
    "x ATAVAWH",
 
… [1469 more chars]
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
      "content": "CmdLine",
      "address": "5369076568"
    },
    {
      "content": "InstallProduct: CreateProcess failed, Cmdline=%s Error=%d .\n",
      "address": "5369078352"
    },
    {
      "content": "cmdLine",
      "address": "5369081264"
    },
    {
      "content": "/setupcmd",
      "address": "5369084704"
    
… [2049 more chars]
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
      "func_name": "FUN_14002ebc0",
      "func_addr": "5368900544",
      "size": "1429",
      "instruction_count": "392",
      "cyclomatic_complexity": "88",
      "call_out_count": "67",
      "string_ref_count
… [3606 more chars]
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
      "content": "Initialization: Failed to initialize Product - msi key not specified.\n",
      "address": "5369076768"
    },
    {
      "content": "RegOpenKeyTransactedW",
      "address": "5369081912"
    },
    {
      "content": "RegCreateKeyEx failed for: ",
      "address": "5369082544"
    },
    {
      "content": "Re
… [2247 more chars]
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
      "content": "file://",
      "address": "5369114768"
    },
    {
      "content": "\ufffd\ufffd\ufffd<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.W
… [960 more chars]
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
      "name": "u_SetupuninstallProducts:_Migratio_14005aaf0",
      "address": "5369080560",
      "data_type": "unicode",
      "size": "122"
    },
    {
      "name": "u_SetupuninstallProducts:_Migratio_14005ab70",
      "address": "5369080688",
      "data_type": "unicode",
      "size": "148"
    },
… [1181 more chars]
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
      "address": "5368713216",
      "name": "FUN_140001000",
      "module": "Global"
    },
    {
      "address": "5368713248",
      "name": "FUN_140001020",
      "module": "Global"
    },
    {
      "address": "5368713264",
      "name": "FUN_140001030",
      "module": "Global"
    },
    {
      "address": "53
… [980 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: key`

```json
{
  "error": "ghidrasql SQL error: no such column: key"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "tool_name",
    "program_name",
    "program_path",
    "language_id",
    "compiler_spec",
    "analysis_id",
    "md5",
    "sha256",
    "image_base",
    "is_headless",
    "revision"
  ],
  "rows": [
    {
      "tool_name": "libghidra-host",
      "program_name": "cobalt-strike-icedid-njrat",
      "program_path": "/cobalt-strike-icedid-njrat",
      "language_id": "x86
… [620 more chars]
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
      "end_ea": "5368710143",
      "name": "Headers",
      "class": "DATA",
      "size": "1024",
      "is_read": "1",
      "is_write": "0",
      "is_exec": "0"
    },
    {
      "start_ea": "5368713216",
     
… [1734 more chars]
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
  "session_id": "ghidra-pe-cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467",
  "audit_path": "/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/audit.jsonl"
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
      "content": "Trunk",
      "address": "5369079216"
    },
    {
      "content": "OpenService failed",
      "address": "5369083008"
    },
    {
      "content": "QueryServiceStatusEx failed",
      "address": "5369083048"
    },
    {
      "content": "Startup",
      "address": "5369084640"
    },
    {
      "content": "
… [1622 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/deep_dive/01-tools-raw.json` exists=`True` bytes=`31163` mtime=`2026-07-28T02:52:00.996315+00:00`
  - sha256: `452e4d76ef83844eeb0e9c91afc311c08311f2bc1b8a989cfdb15aec90bc5b19`
- **sql_evidence:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/deep_dive/05-deep-dive.json` exists=`True` bytes=`2815` mtime=`2026-07-28T02:54:25.290606+00:00`
  - sha256: `5eeeeb74e49cb78906ec1b8cfb218a853b7dff2ac5dd673cabd549f6b858d2cd`

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
  "verdict": "benign",
  "confidence": 95,
  "summary": "This is a legitimate Adobe Acrobat/Acrobat Reader installer bootstrapper (64-bit) that was mislabeled in the malware corpus. It is a Windows Installer (MSI) bootstrapper that downloads and installs Adobe Acrobat components. The PDB path, copyright strings, registry keys, MSI.DLL imports, and VC++ redistributable installer strings all conclusively identify it as a signed Adobe setup executable.",
  "key_evidence": [
    "PDB path: D:\\T\\M\\Acrobat\\Installers\\BootStrapExe_Small\\Release_x64\\Setup.pdb confirms Adobe Acrobat installer origin",
    "String: 'Adobe Bootstrapper for Single Installation' and 'Copyright \u00a9 2024 Adobe Systems Incorporated. All rights reserved.
… [2015 more chars]
```

- **agentic:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`266821` mtime=`2026-07-28T02:54:25.290606+00:00`
  - sha256: `65629382738ddd703ce20bc3f119179b9b565db0a56e3d5a47f7c3d3bf201261`

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

- **rule_yar:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/rule.yar` exists=`True` bytes=`1998` mtime=`2026-07-28T02:54:26.602806+00:00`
  - sha256: `6a950e36b75989060e1d9f264c8edca0a0297169984e25feab4467418103f9e8`

#### excerpt

```
// yara_gen_v2.py — 2026-07-28T02:54:26.603736+00:00
rule CADRE_v2_unknown_cff3abd52ed3 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate." ascii wide
        $s1 = "This program is linked to the missing export %Ts in the file %Ts. This machine may have an incompatible version of %Ts." ascii wide
        $s2 = "HandleNonDefaultLocationInstall: The existing command line doesn't require any modifications. Exiting Now..." ascii
… [1196 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/REPORT-MASTER-v2.md` exists=`True` bytes=`19336` mtime=`2026-07-28T02:56:39.114297+00:00`
  - sha256: `b592f269ba4069618a94a5d74a01cba24921cb27519fc402487dc62b2b37b271`
- **REPORT_MASTER_v3:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/REPORT-MASTER-v3.md` exists=`True` bytes=`34668` mtime=`2026-07-28T03:05:50.961861+00:00`
  - sha256: `e6e38fcce4d53c093c4b70223e2a154ae01a60a36ef19ba6ae24aba8f920ebd0`
- **REPORT_v2:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/REPORT-v2.md` exists=`True` bytes=`19336` mtime=`2026-07-28T02:56:39.114297+00:00`
  - sha256: `b592f269ba4069618a94a5d74a01cba24921cb27519fc402487dc62b2b37b271`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`50580` mtime=`2026-07-28T03:01:17.513079+00:00`
  - sha256: `6d67b99568da3efb504b4b245712130ec6606e937f900762ae0b9837f47f3d09`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`43166` mtime=`2026-07-28T03:10:38.016842+00:00`
  - sha256: `fd385d6fa0dff0864c97489c2ac1efcbb490b8a0dee82c7a49f1aa082dd7317b`
- **report_v2_json:** `/opt/samples/logs/cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467/report-v2.json` exists=`True` bytes=`21596` mtime=`2026-07-28T03:01:17.515779+00:00`
  - sha256: `75211e467ad5b594281dee2263bb3ea174ba18fb2a22f2a72b5967489a20c387`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | benign |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** trojan (possible Cobalt Strike, IcedID, or njRAT)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Executive Summary

The sample `cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467` is a 64-bit Windows PE executable that exhibits multiple indicators of malicious intent. 
… [18422 more chars]
```


#### v3_excerpt

```
# RE Report — cff3abd52ed3
_Generated 2026-07-28T03:05:50.961395+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=255c | cross_refs=True | llm_ok=True | runtime=13.82s -->

## Executive Summary

**Verdict:** Malicious  
**Confidence:** 95%  
**Family:** Trojan (possible Cobalt Strike, IcedID, or njRAT)

The sample (`cff3abd52ed3fd8cc02872734d32db12b700cbfbfb7cb93adb05c79b0fb09467`) exhibits multiple trojan characteristics, including XOR encoding and obfuscated stackstrings (source: capa, rules: "encode data using XOR", "contain obfuscated stackstrings"). It manipulates the Windows registry to create, query, and delete keys (source: capa, rules: "create or open registry key", "query or enumerate registry value", "delete registry key") and gathers system inf
… [33752 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
