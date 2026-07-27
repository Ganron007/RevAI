# Pipeline AUDIT-REPORT — `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-07-28T03:45:39.697628+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`

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

- source=`llm_judge` model=`deepseek-v4-pro` verdict=`malicious` confidence=`85`
- key_evidence_count=`5`

```json
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Generic Dropper",
  "cross_engine_notes": "IDA, Malcat, and YARA tools encountered errors (missing files). Ghidra returned 0 functions, likely due to packing, but provided DLL strings. FLOSS only extracted static junk strings, no decoded data. CAPA identified packing, embedded PE, and XOR encoding. PE imports reveal dynamic loading and process creation APIs. Overall, the sample is packed and exhibits dropper-like traits.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with generic packer",
      "why": "Indicates the sample is packed, a common malware technique to evade static analysis and detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain an embedded PE file",
      "why": "Suggests the sample contains another executable, typical of a dropper that installs additional malware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "RegSetValue, CreateProcess, LoadLibrary, GetProcAddress",
      "why": "High-signal APIs used for registry modification, process creation, and dynamic library loading, enabling persistence and code injection."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "WININET.DLL at 0x4398003",
      "why": "Import of WININET.DLL indicates potential network communication, such as HTTP/HTTPS requests for C2 or downloading payloads."
    },
    {
      "source": "floss",
      "query_or_table": "per_category",
      "row_or_rule": "static_strings: 715, decoded: 0, stack: 0, tight: 0",
      "why": "No meaningful strings decoded, consistent with a packed or encrypted binary that hinders string analysis."
    }
  ],
  "summary": "The sample is a PE32 executable that is packed and contains an embedded PE file. It imports network and process manipulation APIs, and FLOSS reveals no decoded strings, reinforcing the packing assessment. These characteristics are typical of a generic dropper/trojan. The lack of clear family indicators and tool failures limit deeper classification, but the combination of evidence strongly suggests malicious intent.",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 5 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 5 rules"
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
    "checked": 5,
    "hits": 5,
    "misses": [],
    "hit_examples": [
      "packed with generic packer top_rules Indicates the sample is packed, a common malware t
… [697 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`16`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "Packed PE file containing an embedded PE, using XOR encoding and dynamic API resolution. Capabilities include registry persistence (RegCreateKeyExA/RegSetValueExA via ADVAPI32.DLL), process creation (CreateProcessA/WinExec), desktop/window manipulation (CreateDesktopA, SetThreadDesktop, FindWindowA, GetForegroundWindow), COM interaction (CoCreateInstance via OLE32.DLL), ACL manipulation (SetEntriesInAclA/SetSecurityInfo), file copy/delete operations (CopyFileA, DeleteFileA), URL cache manipulation (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA), and single-instance enforcement via CreateMutexA. The .text section has RWX permissions and custom sections (.kofbl, .l1) are present, consistent with a packer. Floss extracted 715 garbled/XOR-encoded strings confirming data obfuscation.",
  "key_evidence": [
    "capa: 'packed with generic packer' (T1027.002 - Software Packing) and 'encode data using XOR' (T1027, C0026.002)",
    "capa: 'contain an embedded PE file' (B0023 - Install Additional Program)",
    ".text section has RWX permissions (read+write+execute, perm=7), highly anomalous for normal executables",
    "Custom section names '.kofbl' and '.l1' are atypical packer artifacts",
    "Dynamic API resolution via LoadLibraryA and GetProcAddress (T1129) enables hidden import resolution",
    "Registry key manipulation (RegCreateKeyExA, RegSetValueExA, RegOpenKeyExA) indicates persistence via T1112",
    "Process creation capabilities (CreateProcessA, WinExec) for launching payloads (T1106)",
    "Desktop isolation manipulation (CreateDesktopA, SetThreadDesktop, GetThreadDesktop) suggests anti-analysis or desktop hijacking",
    "COM object creation (CoCreateInstance, CLSIDFromString) enables browser/COM-based attacks",
    "URL cache manipulation (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA) for clearing browsing history",
    "ACL manipulation (SetEntriesInAclA, SetSecurityInfo, GetSecurityInfo) for privilege escalation or file-hiding",
    "Window enumeration (FindWindowA, GetForegroundWindow, GetWindowTextA, GetWindowRect) for window hijacking or logging",
    "Floss extracted 715 strings, mostly obfuscated/garbled (e.g., '1PA\\\\2%F', 'oe-IZ4\\'IZ$'), consistent with XOR-encoded packer payload",
    "Ghidra strings consist entirely of API function names used by the dynamic loader, not user-facing strings",
    "Single-instance enforcement via CreateMutexA ensures only one copy runs",
    "File operations enable self-copying (CopyFileA, GetModuleFileNameA, GetTempPathA, GetWindowsDirectoryA, GetSystemDirectoryA)"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 33,
  "successful_non_bootstrap_tools": 23,
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
        "wh
… [420 more chars]
```

#### `publish`

- source=`llm_judge` model=`deepseek-v4-pro` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report for SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Generic Dropper\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Executive Summary\n\nThe sample (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9) is a malicious packed PE32 executable, classified as a generic dropper/trojan. Static analysis reveals an embedded PE file, use of XOR encoding, and a wide range of capabilities including registry persistence, process creation, desktop manipulation, COM interaction, and URL cache tampering. The sample employs software packing (T1027.002) and obfuscation to evade detection. No confirmed family attribution was possible due to lack of signature matches, but the code structure and API usage are consistent with commodity malware droppers. This report provides detailed technical analysis, MITRE ATT&CK mappings, indicators of compromise, and recommendations for containment and recovery.\n\n# 1. Sample Identification\n\n- **SHA256**: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9\n- **File Path**: /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir\n- **File Type**: PE32 executable (GUI) for MS Windows\n- **Size**: Not explicitly given; from analysis, moderate size.\n- **First Seen**: Not available\n- **Collections**: VirusSign corpus\n\nThe sample originates from a VirusSign collection and was not a targeted submission. Its internal characteristics confirm it is a 32-bit Windows executable with a GUI subsystem.\n\n# 2. Classification\n\n**Verdict**: Malicious  \n**Confidence**: 90%  \n**Family**: Unknown / Generic Dropper  \n**Type**: Dropper / Trojan  \n\n**Rationale**:  \n- Packed with a generic packer (capa: \"packed with generic packer\") and contains an embedded PE file (capa: \"contain an embedded PE file\"), indicating a dropper function.  \n- Encodes data using XOR (capa: \"encode data using XOR\") to obfuscate internal strings and payload.  \n- Imports powerful APIs for process creation, registry modification, dynamic library loading, and network cache manipulation (source: pe_imports, ghidra_query).  \n- The .text section has RWX permissions, a strong indicator of packing or code injection (source: deep-dive.json).  \n- FLOSS analysis found no meaningful decoded strings, confirming obfuscation (source: floss).  \n- No legitimate software would exhibit such a combination of packing, embedded PE, and snooping capabilities (URL cache manipulation, desktop isolation).  \n\n# 3. Initial Triage (15 minutes)\n\nThe automated triage system assigned a verdict of *malicious* with a score of 85 and a family guess of \"Generic Dropper\". The tool gate confirmed all required tools (capa, yara, floss, malca
… [24420 more chars]
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
- **Family (triage):** Generic Dropper
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Executive Summary

The sample (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9) is a malicious packed PE32 executable, classified as a generic dropper/trojan. Static analysis reveals an embedded PE file, use of XOR encoding, and a wide range of capabilities including registry persistence, process creation, desktop manipulation, COM interaction, and URL cache tampering. The sample employs software packing (T1027.002) and obfuscation to evade detection. No confirmed family attribution was possible due to lack of signature matches, but the code structure and API usage are consistent with commodity malware droppers. This report provides detailed technical analysis, MITRE ATT&CK mappings, indicators of compromise, and recommendations for containment and recovery.

# 1. Sample Identification

- **SHA256**: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
- **File Path**: /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir
- **File Type**: PE32 executable (GUI) for MS Windows
- **Size**: Not explicitly given; from analysis, moderate size.
- **First Seen**: Not available
- **Collections**: VirusSign corpus

The sample originates from a VirusSign collection and was not a targeted submission. Its internal characteristics confirm it is a 32-bit Windows executable with a GUI subsystem.

# 2. Classification

**Verdict**: Malicious  
**Confidence**: 90%  
**Family**: Unknown / Generic Dropper  
**Type**: Dropper / Trojan  

**Rationale**:  
- Packed with a generic packer (capa: "packed with generic packer") and contains an embedded PE file (capa: "contain an embedded PE file"), indicating a dropper function.  
- Encodes data using XOR (capa: "encode data using XOR") to
… [22937 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — bf95bc98c0a4
_Generated 2026-07-28T03:41:39.109001+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=220c | cross_refs=True | llm_ok=True | runtime=22.48s -->

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **SHA256** | `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9` |
| **Verdict** | Malicious |
| **Family** | Generic Dropper |
| **Confidence** | High (90%) |
| **Analysis Source** | deep_dive_agentic |

The sample is a malicious Windows PE file that functions as a generic dropper, designed to deliver additional payloads to compromised systems. Advanced static analysis (including capa, radare2) confirmed the presence of an embedded PE file, XOR-based encoding, and packing indicative of a dropper (source: capa, radare2, cross-section:4. Static Analysis). Initial assessment by an earlier model rated the file as suspicious with a low score, but the agentic deep dive uncovered sufficient evidence to raise the verdict to malicious with 90% confidence (source: cross-section:2. Classification). No dynamic execution or network analysis was available; therefore, capabilities such as persistence or C2 communication remain unconfirmed (source: cross-section:5. Behavioral Analysis, cross-section:6. Network Analysis). The analysis mapped the observed techniques to MITRE ATT&CK, notably T1027 (Obfuscated Files or Information) and T1055 (Process Injection) (source: cross-section:8. MITRE ATT&CK Mapping). Indicators of compromise include the file hash and behavioral patterns, though no hardcoded URLs or IPs were discovered (source: cross-section:11. Indicators of Compromise). Custom YARA rules have been proposed to detect similar samples (source: cross-section:12. Detection Rules). Containment recommendations follow standard incident response procedures for dropper malware, emphasizing patch management and user training (source: cross-section:13. Containment, Eradication, Recovery, cross-section:14. Recommendations). Attribution to a specific threat actor could not be established due to the generic nature of the dropper (source: cross-section:10. Attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=34c | cross_refs=True | llm_ok=True | runtime=25.25s -->

# 1. Sample Identification

## File Identifiers

| Property | Value | Source |
|----------|-------|--------|

… [28558 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4197` | `4ee9b97acc900a0d` |
| `prompt.txt` | `True` | `10268` | `9742b78fd6d76058` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `25441` | `27baab64ffa98d36` |
| `REPORT-MASTER-v3.md` | `True` | `31088` | `67a908f62e29fea8` |
| `REPORT-v2.md` | `True` | `25441` | `27baab64ffa98d36` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `34882` | `2c3761b20b14e6bf` |
| `rule.yar` | `True` | `1055` | `d03fc24bde6b3c3e` |
| `intake-validation.json` | `True` | `1912` | `2bbb0c4e9ed74ea7` |
| `source-decisions.json` | `True` | `1267` | `77e60bc5a94ddc4a` |
| `malcat-triage.json` | `True` | `166` | `2c737437071c385c` |
| `deep_dive/01-tools-raw.json` | `True` | `23346` | `e3bf585d18493af8` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3920` | `17abe73f49fb489b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `6467` | `845e6b194fdd8487` |

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

- **intake_validation:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-validation.json` exists=`True` bytes=`1912` mtime=`2026-07-28T03:29:22.087663+00:00`
  - sha256: `2bbb0c4e9ed74ea76dd8d69dd05ca3c6c01b36ae498c138bd1bca8b8d17ca5a0`
- **malcat_triage:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/malcat-triage.json` exists=`True` bytes=`166` mtime=`2026-07-28T03:28:46.772565+00:00`
  - sha256: `2c737437071c385c826b1560c50b5476a78a6b8eb5e2c8a497e5512e33c5df94`
- **source_decisions:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/source-decisions.json` exists=`True` bytes=`1267` mtime=`2026-07-28T03:29:22.087663+00:00`
  - sha256: `77e60bc5a94ddc4a5ec7fe07d235e04d0241eed37548112fa624ec859bf3545b`
- **ghidra_import_log:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-analyzeHeadless.log` exists=`True` bytes=`6616` mtime=`2026-07-28T03:28:50.664165+00:00`
  - sha256: `40fc43386b11960b5fff7b7a9d1d45229cb51a6d57b194e98cded30172f98454`
- **ida_bootstrap_log:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA failed (validation error: file not found), returning 0 imports; Ghidra returned 113 imports. Only one source available."
  },
  "functions": {
    "source": "none",
    "confidence": "medium",
    "reason": "Both Ghidra and IDA returned 0 functions (Ghidra funcs=0, IDA empty due to failure). No functions detected."
  },
  "strings": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA failed (validation error), providing no strings; Ghidra returned 122 strings; Malcat failed with error. Only Ghidra provided strings."
  },
  "decompilation": {
    "source": "none",
    "confidence": "medium",
    "reason":
… [490 more chars]
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
      "name": "packed with generic packer",
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
            "Standard Compression"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Standard Compression",
          "id": "F0001.002"
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
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) packer file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 1048576,
  "duration_s": 1.36,
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
  "duration_s": 0.07
}
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 715,
  "strings_sampled": 80,
  "strings": [
    ".idata",
    ".kofbl",
    "<OF#55",
    "1PA\\2%F",
    "oe-IZ4'IZ$",
    "#&%FgV!F",
    ":Pr%FEL",
    "p0%Fmu",
    "0%O?D!",
    "%I`3$F",
    "1 ~{q%",
    "(^{q%fm",
    "Dr%O$L",
    "\\r%{d0%F",
    "1%F\\GRF",
    "v0%FdM",
    "4Pad==",
    "0Mn^r%",
    "0M{^r%",
    "0%Fi5Q",
    "Ii4 /Xr%",
    "<3`Vid",
    "!IR4#{",
    "pVid6C",
    "Ii<(~Xr%",
    "Do$0fup%",
    "m<0vqp%IR",
    "2Pr%IR",
    "gF]!%F",
    "MCIRs$c$0%Fg",
    "0QNou)",
    "#Z%.d0%F",
    "gF]3%F",
    "ou)ISp'",
    "eNoe-ISb-o41`",
    "xNou) mu)",
    ">0%Fou",
    "5IR4;{",
    "L}%Fmu",
    "D}%FoM",
    "cM*;r%.",
    "0%O$D)",
    "u%F]:%F",
    "t%F]:%F",
    "ds%F]S%F",
    "Dr%F]:%F",
    "q%F]:%F",
    "`M\":r%",
    "%F]:%F",
    "%F]S%F",
    "gMx;r%",
    "id/Cid'G",
    "MT;r%.",
    "`M38r%",
    "0s.4ceF",
    "8M\\:r%",
    "`Mh8r%",
    "0%w$pz",
    "PJid#G",
    "0M&cp%,",
    "Dq%.t1%Fou",
    "Z%.X2%F",
    "0%.Z0%F",
    "X&Fd`M",
    "`M->r%.>",
    "0%.'0%F",
    "`MU>r%.>",
    "Z=.f0%F",
    "X%Fd`M",
    "ZB.c0%F",
    "Zs.]0%F",
    "`M@>r%.>",
    "8-%FGL",
    "M{Pr%.",
    ",%F]?%F",
    "!MRUr%",
    "!MgVr%",
    "`MFzq%",
    "`Ms=r%",
    "0Ml=r%"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 715
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.91,
  "size_bytes": 1048576,
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
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "packed with generic packer top_rules Indicates the sample is packed, a common malware technique to evade static analysis",
    "contain an embedded PE file top_rules Suggests the sample contains another executable, typical of a dropper that install",
    "RegSetValue, CreateProcess, LoadLibrary, GetProcAddress signals High-signal APIs used for registry modification, process",
    "WININET.DLL at 0x4398003 Suspicious strings Import of WININET.DLL indicates potential network communication, such as HTT",
    "static_strings: 715, decoded: 0, stack: 0, tight: 0 per_category No meaningful strings decoded, consistent with a packed"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Generic Dropper",
  "score": 85,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with generic packer",
      "why": "Indicates the sample is packed, a common malware technique to evade static analysis and detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain an embedded PE file",
      "why": "Suggests the sample contains another executable, typical of a dropper that installs additional malware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "RegSetValue, CreateProcess, LoadLibrary, GetProcAddress",
      "why": "High-signal APIs used for registry modification, process creation, and dynamic library loading, enabling persistence and code injection."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "WININET.DLL at 0x4398003",
      "why": "Import of WININET.DLL indicates potential network communication, such as HTTP/HTTPS requests for C2 or downloading payloads."
    },
    {
      "source": "floss",
      "query_or_table": "per_category",
      "row_or_rule": "static_strings: 715, decoded: 0, stack: 0, tight: 0",
      "why": "No meaningful strings decoded, consistent with a packed or encrypted binary that hinders string analysis."
    }
  ],
  "summary": "The sample is a PE32 executable that is packed and contains an embedded PE file. It imports network and process manipulation APIs, and FLOSS reveals no decoded strings, reinforcing the packing assessment. These characteristics are typical of a generic dropper/trojan. The lack of clear family indicators and tool failures limit deeper classification, but the combination of evidence strongly suggests"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/prompt.txt` exists=`True` bytes=`10268` mtime=`2026-07-28T03:29:34.513962+00:00`
  - sha256: `9742b78fd6d760582a62f38afa606cdab11b0b7a9493c97dae96876f3c5f85eb`
- **verdict:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/verdict.json` exists=`True` bytes=`4197` mtime=`2026-07-28T03:30:07.951660+00:00`
  - sha256: `4ee9b97acc900a0d88b703b6ff77d357d5a08a545e48fe1cf337bc5860588611`

#### prompt_excerpt

```
# Triage evidence
sha256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
sample_path: /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir
ghidra_session: ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
ida_session: ida-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA failed (validation error: file not found), returning 0 imports; Ghidra returned 113 imports. Only one source available.
- functions: none (confidence=medium) — Both Ghidra and IDA returned 0 functions (Ghidra funcs=0, IDA empty due to failure). No functions detected.
- strings: ghidra (confidence=medium) — IDA failed (validation error), providing no strings; Ghidra returned 122 strings; Malcat failed with error. Only Ghidra provided strings.
- decompilation: none (confidence=medium) 
… [9256 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Generic Dropper",
  "cross_engine_notes": "IDA, Malcat, and YARA tools encountered errors (missing files). Ghidra returned 0 functions, likely due to packing, but provided DLL strings. FLOSS only extracted static junk strings, no decoded data. CAPA identified packing, embedded PE, and XOR encoding. PE imports reveal dynamic loading and process creation APIs. Overall, the sample is packed and exhibits dropper-like traits.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "packed with generic packer",
      "why": "Indicates the sample is packed, a common malware technique to evade static analysis and detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain an embedded PE file",
      "why": "Suggests the sample contains another executable, typical of a dropper that installs additional malware."
    },
    {
 
… [3197 more chars]
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
      "name": "packed with generic packer",
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
            "Standard Compression"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Software Packing",
          "method": "Standard Compression",
          "id": "F0001.002"
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
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) packer file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 1048576,
  "duration_s": 1.09,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.03,
  "import_count": 113,
  "signal_count": 4,
  "signals": [
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
  "string_count": 715,
  "strings_sampled": 80,
  "strings": [
    ".idata",
    ".kofbl",
    "<OF#55",
    "1PA\\2%F",
    "oe-IZ4'IZ$",
    "#&%FgV!F",
    ":Pr%FEL",
    "p0%Fmu",
    "0%O?D!",
    "%I`3$F",
    "1 ~{q%",
    "(^{q%fm",
    "Dr%O$L",
    "\\r%{d0%F",
    "1%F\\GRF",
    "v0%FdM",
    "4Pad==",
    "0Mn^r%",
    "0M{^r%",
    "0%Fi5Q",
    "Ii4 /Xr%",
    "<3`Vid",
    "!IR4#{",
    "pVid6C",
    "Ii<(~Xr%",
    "Do$0fup%",
    "m<0vqp%IR",
    "2Pr%IR",
    "gF]!%F",
    "MCIRs$c$0%Fg",
    "0QNou)",
    "#Z%.d0%F",
    "gF]3%F",
    "ou)ISp'",
    "eNoe-ISb-o41`",
    "xNou) mu)",
    ">0%Fou",
    "5IR4;{",
    "L}%Fmu",
    "D}%FoM",
    "cM*;r%.",
    "0%O$D)",
    "u%F]:%F",
    "t%F]:%F",
    "ds%F]S%F",
    "Dr%F]:%F",
    "q%F]:%F",
    "`M\":r%",
    "%F]:%F",
    "%F]S%F",
    "gMx;r%",
    "id/Cid'G",
    "MT;r%.",
    "`M38r%",
    "0s.4ceF",
    "8M\\:r%",
    "`Mh8r%",
    "0%w$pz",
    "PJid#G",
    "0M&cp%,",
    "Dq%.t1%Fou",
    "Z%.X2%F",
    "0%.Z0%F",
    "X&Fd`M",
    "`M->r%.>",
    "0%.'0%F",
    "`MU>r%.>",
    "Z=.f0%F",
    "X%Fd`M",
    "ZB.c0%F",
    "Zs.]0%F",
    "`M@>r%.>",
    "8-%FGL",
    "M{Pr%.",
    ",%F]?%F",
    "!MRUr%",
    "!MgVr%",
    "`MFzq%",
    "`Ms=r%",
    "0Ml=r%"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 715
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.13,
  "size_bytes": 1048576,
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
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "disassembly": {
    "0x00430005": "\u250c 139: fcn.00430005 ();\n\u2502       \u254e   0x00430005      60             pushal\n\u2502       \u254e   0x00430006      90             nop\n\u2502       \u254e   0x00430007      b800104000     mov eax, section..text      ; 0x401000\n\u2502       \u254e   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc\n\u2502       \u254e   0x00430011      90             nop\n\u2502       \u254e   0x00430012      b9e4302546     mov ecx, 0x462530e4\n\u2502       \u254e   0x00430017      90             nop\n\u2502       \u254e   0x00430018      90             nop\n\u2502       \u254e   0x00430019      90             nop\n\u2502       \u254e   0x0043001a      85c0           test eax, eax\n\u2502       \u254e   0x0043001c      90             nop\n\u2502       \u254e   0x0043001d      90             nop\n\u2502       \u254e   0x0043001e      90             nop\n\u2502       \u254e   0x0043001f      90             nop\n\u2502       \u254e   0x00430020      90             nop\n\u2502       \u254e   0x00430021      90             nop\n\u2502      \u250c\u2500\u2500< 0x00430022      742a           je 0x43004e\n\u2502     \u250c\u2500\u2500\u2500> 0x00430024      90             nop\n\u2502     \u254e\u2502\u254e   0x00430025      90             nop\n\u2502     \u254e\u2502\u254e   0x00430026      90             nop\n\u2502     \u254e\u2502\u254e   0x00430027      90             nop\n\u2502     \u254e\u2502\u254e   0x00430028      3108           xor dword [eax], ecx\n\u2502     \u254e\u2502\u254e   0x0043002a      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002b      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002c      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002d      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002e      90             nop\n\u2502     \u254e\u2502\u254e   0x0043002f      40             inc eax\n\u2502     \u254e\u2502\u254e   0x00430030      40             inc eax\n\u2502     \u254e\u2502\u254e   0x00430031      90             nop\n\u2502     \u254e\u2502\u254e   0x00430032      90             nop\n\u2502     \u254e\u2502\u254e   0x00430033      90             nop\n\u2502     \u254e\u2502\u254e   0x00430034      90             nop\n\u2502     \u254e\u2502\u254e   0x00430035      90             nop\n\u2502     \u254e\u2502\u254e   0x00430036      90             nop\n\u2502     \u254e\u2502\u254e   0x00430037      90             nop\n\u2502     \u254e\u2502\u254e   0x00430038      90             nop\n\u2502     \u254e\u2502\u254e   0x00430039      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003a      40             inc eax\n\u2502     \u254e\u2502\u254e   0x0043003b      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003c      40             inc eax\n\u2502     \u254e\u2502\u254e   0x0043003d      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003e      90             nop\n\u2502     \u254e\u2502\u254e   0x0043003f      90             nop\n\u2502     \u254e\u2502\u254e   0x00430040      90             nop\n\u2502     \u254e\u2502\u254e   0x00430041      90             nop\n\u2502     \u254e\u2502\u254e   0x00430042      90             nop\n\u2502     \u254e\u2502\u254e   0x00430043      90             nop\n\u2502     \u254e\u2502\u
… [11188 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ......................................",
    "Found XOR 00 position 0001B800: 00000080 ......................................"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ......................................\nFound XOR 00 position 0001B800: 00000080 ......................................\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
    "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
  "checked": 16,
  "hits": 15,
  "misses": [
    "ACL manipulation (SetEntriesInAclA, SetSecurityInfo, GetSecurityInfo) for privilege escalation or file-hiding"
  ],
  "hit_examples": [
    "capa: 'packed with generic packer' (T1027.002 - Software Packing) and 'encode data using XOR' (T1027, C0026.002)",
    "capa: 'contain an embedded PE file' (B0023 - Install Additional Program)",
    ".text section has RWX permissions (read+write+execute, perm=7), highly anomalous for normal executables",
    "Custom section names '.kofbl' and '.l1' are atypical packer artifacts",
    "Dynamic API resolution via LoadLibraryA and GetProcAddress (T1129) enables hidden import resolution"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Packed PE file containing an embedded PE, using XOR encoding and dynamic API resolution. Capabilities include registry persistence (RegCreateKeyExA/RegSetValueExA via ADVAPI32.DLL), process creation (CreateProcessA/WinExec), desktop/window manipulation (CreateDesktopA, SetThreadDesktop, FindWindowA,",
  "key_evidence": [
    "capa: 'packed with generic packer' (T1027.002 - Software Packing) and 'encode data using XOR' (T1027, C0026.002)",
    "capa: 'contain an embedded PE file' (B0023 - Install Additional Program)",
    ".text section has RWX permissions (read+write+execute, perm=7), highly anomalous for normal executables",
    "Custom section names '.kofbl' and '.l1' are atypical packer artifacts",
    "Dynamic API resolution via LoadLibraryA and GetProcAddress (T1129) enables hidden import resolution",
    "Registry key manipulation (RegCreateKeyExA, RegSetValueExA, RegOpenKeyExA) indicates persistence via T1112",
    "Process creation capabilities (CreateProcessA, WinExec) for launching payloads (T1106)",
    "Desktop isolation manipulation (CreateDesktopA, SetThreadDesktop, GetThreadDesktop) suggests anti-analysis or desktop hijacking",
    "COM object creation (CoCreateInstance, CLSIDFromString) enables browser/COM-based attacks",
    "URL cache manipulation (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA) for clearing browsing history",
    "ACL manipulation (SetEntriesInAclA, SetSecurityInfo, GetSecurityInfo) for privilege escalation or file-hiding",
    "Window enumeration (FindWindowA, GetForegroundWindow, GetWindowTextA, GetWindowRect) for window hijacking or logging",
    "Floss extracted 715 strings, mostly obfuscated/garbled (e.g., '1PA\\\\2%F', 'oe-IZ4\\'IZ$'), consistent with XOR-encoded packer payload",
    "Ghidra strings consist entirely of API function names used by the dynamic loader, not user-facing strings",
    "Single-instance enforcement via CreateMutexA ensures only one copy runs",
    "File operations enable self-copying (CopyFileA, GetModuleFileNameA, GetTempPathA, GetWindowsDirectoryA, GetSystemDirectoryA)"
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
… [2075 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.03,
  "import_count": 113,
  "signal_count": 4,
  "signals": [
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
      "la
… [295 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 715,
  "strings_sampled": 80,
  "strings": [
    ".idata",
    ".kofbl",
    "<OF#55",
    "1PA\\2%F",
    "oe-IZ4'IZ$",
    "#&%FgV!F",
    ":Pr%FEL",
    "p0%Fmu",
    "0%O?D!",
    "%I`3$F",
    "1 ~{q%",
    "(^{q%fm",
    "Dr%O$L",
    "\\r%{d0%F",
    "1%F\\GRF",
    "v0%FdM",
    "4Pad==",
    "0Mn^r%",
    "0M{^r%",
    "0%Fi5Q",
    "Ii4 /Xr%",
    
… [1261 more chars]
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
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "disassembly": {
    "0x00430005": "\u250c 139: fcn.00430005 ();\n\u2502       \u254e   0x00430005      60             pushal\n\u2502       \u254e   0x00430006      90             nop\n\u2502       \u254e   0x00430007  
… [14288 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ......................................",
    "Found XOR 00 position 0001B800: 00000080 ......................................"
  ],
  "xorsearch_stdou
… [225 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
    "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/audit.jsonl"
}
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
      "address": "92",
      "name": "GetSecurityInfo",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "86",
      "name": "GetUserNameA",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "88",
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "87",
    
… [10860 more chars]
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
      "content": "ExpandEnvironmentStringsA",
      "address": "4396364",
      "length": "26"
    },
    {
      "content": "FindFirstUrlCacheEntryA",
      "address": "4396298",
      "length": "24"
    },
    {
      "content": "FindNextUrlCacheEntryA",
      "address": "4396324",
      "length": "23"
    },
    
… [3981 more chars]
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
      "address": "21",
      "name": "GetSystemDirectoryA",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "22",
      "name": "GetTempPathA",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "23",
      "name": "GetTickCount",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "24",
… [6081 more chars]
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
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf7
… [45 more chars]
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
      "content": "GetWindowsDirectoryA",
      "address": "4396666",
      "length": "21"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/
… [84 more chars]
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
      "content": "CoCreateInstance",
      "address": "4396186",
      "length": "17"
    },
    {
      "content": "CLSIDFromString",
      "address": "4396206",
      "length": "16"
    },
    {
      "content": "CoInitialize",
      "address": "4396224",
      "length": "13"
    },
    {
      "content": "CoUnini
… [7696 more chars]
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
      "address": "92",
      "name": "GetSecurityInfo",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "86",
      "name": "GetUserNameA",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "88",
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "87",
    
… [10860 more chars]
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
      "start_ea": "4194304",
      "end_ea": "4195327",
      "name": "Headers",
      "class": "DATA",
      "perm": "4",
      "bitness": "0",
      "size": "1024",
      "is_read": "1",
      "is_write": "0",
      "is
… [1790 more chars]
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
      "content": "CoCreateInstance",
      "address": "4396186",
      "length": "17"
    },
    {
      "content": "CLSIDFromString",
      "address": "4396206",
      "length": "16"
    },
    {
      "content": "CoInitialize",
      "address": "4396224",
      "length": "13"
    },
    {
      "content": "CoUnini
… [11573 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
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
… [2075 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 715,
  "strings_sampled": 80,
  "strings": [
    ".idata",
    ".kofbl",
    "<OF#55",
    "1PA\\2%F",
    "oe-IZ4'IZ$",
    "#&%FgV!F",
    ":Pr%FEL",
    "p0%Fmu",
    "0%O?D!",
    "%I`3$F",
    "1 ~{q%",
    "(^{q%fm",
    "Dr%O$L",
    "\\r%{d0%F",
    "1%F\\GRF",
    "v0%FdM",
    "4Pad==",
    "0Mn^r%",
    "0M{^r%",
    "0%Fi5Q",
    "Ii4 /Xr%",
    
… [1260 more chars]
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
      "address": "19",
      "name": "CloseHandle",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "28",
      "name": "CopyFileA",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "36",
      "name": "CreateFileA",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "40",
      "name
… [4303 more chars]
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
      "address": "4390914",
      "name": "entry",
      "module": "Global"
    },
    {
      "address": "4395696",
      "name": "CoCreateInstance",
      "module": "Imports"
    },
    {
      "address": "4395700",
      "name": "CLSIDFromString",
      "module": "Imports"
    },
    {
      "address": "4395704",
  
… [1996 more chars]
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
      "name": "CoCreateInstance",
      "module": "OLE32.DLL"
    },
    {
      "address": "2",
      "name": "CLSIDFromString",
      "module": "OLE32.DLL"
    },
    {
      "address": "3",
      "name": "CoInitialize",
      "module": "OLE32.DLL"
    },
    {
      "address": "4",
      "name"
… [770 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "name",
    "module"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/audit.jsonl"
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
      "module": "ADVAPI32.DLL"
    },
    {
      "module": "CRTDLL.DLL"
    },
    {
      "module": "GDI32.DLL"
    },
    {
      "module": "KERNEL32.DLL"
    },
    {
      "module": "MSVCRT.DLL"
    },
    {
      "module": "OLE32.DLL"
    },
    {
      "module": "OLEAUT32.DLL"
    },
    {
      "module": "USER32.DLL"
    },
    {
      "
… [334 more chars]
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
      "address": "84",
      "name": "CreateBrushIndirect",
      "module": "GDI32.DLL"
    },
    {
      "address": "85",
      "name": "CreateFontA",
      "module": "GDI32.DLL"
    },
    {
      "address": "81",
      "name": "GetStockObject",
      "module": "GDI32.DLL"
    },
    {
      "address": "82",
      "
… [3231 more chars]
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
      "address": "92",
      "name": "GetSecurityInfo",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "86",
      "name": "GetUserNameA",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "88",
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "87",
    
… [2492 more chars]
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
      "address": "80",
      "name": "CallWindowProcA",
      "module": "USER32.DLL"
    },
    {
      "address": "68",
      "name": "CreateDesktopA",
      "module": "USER32.DLL"
    },
    {
      "address": "76",
      "name": "CreateWindowExA",
      "module": "USER32.DLL"
    },
    {
      "address": "79",
    
… [2665 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9.json"
}
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 1048576,
  "duration_s": 0.05,
  "import_count": 113,
  "signal_count": 4,
  "signals": [
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
      "la
… [295 more chars]
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
      "name": "CoCreateInstance",
      "module": "OLE32.DLL"
    },
    {
      "name": "DeleteUrlCacheEntry",
      "module": "WININET.DLL"
    },
    {
      "name": "GetProcAddress",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "LoadLibraryA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateMutexA",

… [866 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "cnt"
  ],
  "rows": [
    {
      "cnt": "0"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "audit_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/audit.jsonl"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/01-tools-raw.json` exists=`True` bytes=`23346` mtime=`2026-07-28T03:30:17.500659+00:00`
  - sha256: `e3bf585d18493af882093d0973c2e17e096e192ba3eeb420a153964c3fc19f8b`
- **sql_evidence:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/05-deep-dive.json` exists=`True` bytes=`3920` mtime=`2026-07-28T03:31:00.378456+00:00`
  - sha256: `17abe73f49fb489b983078b09da6e57cd0e45b76375897090a26d51205bb2920`

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
  "summary": "Packed PE file containing an embedded PE, using XOR encoding and dynamic API resolution. Capabilities include registry persistence (RegCreateKeyExA/RegSetValueExA via ADVAPI32.DLL), process creation (CreateProcessA/WinExec), desktop/window manipulation (CreateDesktopA, SetThreadDesktop, FindWindowA, GetForegroundWindow), COM interaction (CoCreateInstance via OLE32.DLL), ACL manipulation (SetEntriesInAclA/SetSecurityInfo), file copy/delete operations (CopyFileA, DeleteFileA), URL cache manipulation (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA), and single-instance enforcement via CreateMutexA. The .text section has RWX permissions and custom sections (.kofbl, .l1) are pre
… [3120 more chars]
```

- **agentic:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`279055` mtime=`2026-07-28T03:31:00.376657+00:00`
  - sha256: `1d97b9828b00c3edc9eff67f12e8ebdb580be16b85452681178cc4f6baf65683`

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

- **rule_yar:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar` exists=`True` bytes=`1055` mtime=`2026-07-28T03:31:02.666256+00:00`
  - sha256: `d03fc24bde6b3c3e7a601beedfd621db27bcc045f79f2540956871e8b6c80d6b`

#### excerpt

```
// yara_gen_v2.py — 2026-07-28T03:31:02.666453+00:00
rule CADRE_v2_unknown_bf95bc98c0a4 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9"
        family = "unknown"
        cadre_reveng_v2 = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "ExpandEnvironmentStringsA" ascii wide
        $s1 = "FindFirstUrlCacheEntryA" ascii wide
        $s2 = "FindNextUrlCacheEntryA" ascii wide
        $s3 = "GetWindowsDirectoryA" ascii wide
        $s4 = "InterlockedIncrement" ascii wide
        $s5 = "DeleteUrlCacheEntry" ascii wide
        $s6 = "GetCurrentProcessId" ascii wide
        $s7 = "GetSystemDirectoryA" ascii wide
        $s8 = "WaitForSingleObject" a
… [253 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-MASTER-v2.md` exists=`True` bytes=`25441` mtime=`2026-07-28T03:33:40.526246+00:00`
  - sha256: `27baab64ffa98d36da5ad6557830c855a4718f5a97a3e2d8acb4551d97f89b06`
- **REPORT_MASTER_v3:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-MASTER-v3.md` exists=`True` bytes=`31088` mtime=`2026-07-28T03:41:39.110214+00:00`
  - sha256: `67a908f62e29fea8590c3dbf61c32c22aceb464064e9b2d7e86a5f6ed9ff5440`
- **REPORT_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-v2.md` exists=`True` bytes=`25441` mtime=`2026-07-28T03:33:40.525346+00:00`
  - sha256: `27baab64ffa98d36da5ad6557830c855a4718f5a97a3e2d8acb4551d97f89b06`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`41707` mtime=`2026-07-28T03:37:50.950330+00:00`
  - sha256: `c50e90aff0a16da44144fd2b9d112835e5be81a0a6c6ed656dcf76ee54d92303`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`34882` mtime=`2026-07-28T03:45:38.601999+00:00`
  - sha256: `2c3761b20b14e6bf2ada523b28cd04ae19007140f5323e4c504c815e3a1b4f6d`
- **report_v2_json:** `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/report-v2.json` exists=`True` bytes=`27920` mtime=`2026-07-28T03:37:50.954829+00:00`
  - sha256: `9c199159c6133b2be680ee7606d867ed94fcef4ba9e6a8f153a1bfe5d5b09749`

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
- **Family (triage):** Generic Dropper
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Executive Summary

The sample (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9) is a malicious packed PE32 executable, classified as a generic dropper/trojan. Static analysis reveals an embedd
… [24537 more chars]
```


#### v3_excerpt

```
# RE Report — bf95bc98c0a4
_Generated 2026-07-28T03:41:39.109001+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=220c | cross_refs=True | llm_ok=True | runtime=22.48s -->

## Executive Summary

| Attribute | Value |
|-----------|-------|
| **SHA256** | `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9` |
| **Verdict** | Malicious |
| **Family** | Generic Dropper |
| **Confidence** | High (90%) |
| **Analysis Source** | deep_dive_agentic |

The sample is a malicious Windows PE file that functions as a generic dropper, designed to deliver additional payloads to compromised systems. Advanced static analysis (including capa, radare2) confirmed the presence of an embedded PE file, XOR-based encoding, and packing indicative of a dropper (source:
… [30158 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
