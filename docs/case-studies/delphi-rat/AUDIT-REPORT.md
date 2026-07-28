# Pipeline AUDIT-REPORT — `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-07-28T07:06:58.332601+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`

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
  "family_guess": "Delphi-based trojan (possible generic RAT)",
  "cross_engine_notes": "IDA and Malcat engines failed. Ghidra analysis limited (only 1 function). Yara scanner had errors. Reliance on capa, FLOSS, and PE imports.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "packed with generic packer",
      "why": "Indicates executable packing, common in malware to evade detection."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "encrypt data using HC-128",
      "why": "Use of HC-128 stream cipher for obfuscation, a non-standard algorithm."
    },
    {
      "source": "pe_imports",
      "query_or_table": "PE imports",
      "row_or_rule": "VirtualAlloc, VirtualProtect",
      "why": "APIs for memory allocation and protection changes, typical for code injection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "PE imports",
      "row_or_rule": "CreateProcess",
      "why": "API to create new processes, often used to execute malicious payloads."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "get disk information, get common file path, query registry",
      "why": "Discovery of system information and files, common in reconnaissance."
    },
    {
      "source": "floss",
      "query_or_table": "FLOSS strings",
      "row_or_rule": "TObject, TClassd, InitInstance, This program must be run under Win32",
      "why": "Delphi runtime identifiers, indicating the binary was built with Delphi."
    },
    {
      "source": "ghidra",
      "query_or_table": "Total function count (Ghidra)",
      "row_or_rule": "SELECT count(*) AS funcs FROM funcs -> 1",
      "why": "Only one function identified, consistent with heavy packing/obfuscation."
    }
  ],
  "summary": "The sample is a packed Delphi executable exhibiting obfuscation (XOR, HC-128, RC4), process injection capabilities (VirtualAlloc, VirtualProtect, CreateProcess), and discovery behaviors (file system, registry, OS version). These characteristics are consistent with a remote access trojan (RAT) or backdoor.",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 59 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 59 rules"
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
      "packed with generic packer capa rules Indicates executable packing, common in malware to evade detection. capa   ",
      "encrypt data using HC-128 c
… [622 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`7`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "The sample exhibits numerous malicious capabilities as identified by CAPA analysis, including packing, encoding/encryption (XOR, RC4, HC-128), registry manipulation, process injection, network communication (HTTP, DNS), and sandbox evasion. Although YARA and Malcat scans encountered errors, the CAPA findings are sufficient to classify the file as malware with high confidence.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "packed with generic packer",
      "why": "The sample is packed, a common technique to evade static analysis and hide malicious code."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "encrypt data using RC4 PRGA",
      "why": "RC4 encryption is frequently used in malware to obfuscate network traffic or payloads."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "encode data using XOR",
      "why": "XOR encoding is a simple obfuscation method typical in malware."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "check for Internet connection",
      "why": "Indicates potential command and control (C2) functionality."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "create or open registry key",
      "why": "Registry manipulation is often used for persistence or configuration storage."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "create process",
      "why": "Ability to spawn processes can be used for execution, injection, or persistence."
    },
    {
      "source": "yara_scan",
      "query_or_table": "yara_scan",
      "row_or_rule": "batch_errors",
      "why": "YARA scan failed with file-not-found errors, so no matches were possible. This does not indicate a clean file."
    }
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 42,
  "successful_non_bootstrap_tools": 32,
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
  "title": "Malware Analysis Report - Delphi-based Trojan (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Delphi-based trojan (possible generic RAT)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Malware Analysis Report - Delphi-based Trojan\n\n## Executive Summary\nThis report details the analysis of a malicious 32-bit PE executable (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c) identified as a Delphi-based trojan. Static analysis using CAPA, FLOSS, Ghidra, and other tools reveals capabilities including process injection, registry manipulation, system discovery, and obfuscation (XOR, RC4, HC-128). The sample is packed with a generic packer, hindering deep static analysis. No dynamic execution was performed; however, the static evidence strongly supports a verdict of malicious with high confidence (90%). The sample appears to masquerade as a game editor (\"GML_EDIT_PRO\") but contains no legitimate benign functionality. This report provides indicators of compromise, detection rules, and mitigation recommendations.\n\n## 1. Sample Identification\n| Property | Value |\n| --- | --- |\n| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |\n| File Name | virussign.com_40f9267218c144475dc0691431825779.vir |\n| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |\n| Architecture | 32-bit |\n| Compiler/Language | Delphi (inferred from FLOSS strings: InitInstance, TObject; and standard Delphi error messages) (source: floss, ghidra_query) |\n| Packer | Generic packer detected by CAPA (not UPX) (source: capa, UPX) |\n| Subsystem | Windows GUI |\n\n## 2. Classification\n- **Verdict**: Malicious\n- **Confidence**: High (90%)\n- **Family**: Delphi-based trojan (possible generic RAT)\n- **Rationale**: The sample exhibits multiple malicious capabilities: process injection (VirtualAlloc, VirtualProtect), process creation (CreateProcess), registry manipulation (capa rule \"create or open registry key\"), network connectivity checks (capa rule \"check for Internet connection\"), and various discovery behaviors. Heavy obfuscation and packing are typical of malware. The triage tool suite gave a malicious score of 0.9. No legitimate software would combine these features with such obfuscation. (source: triage verdict.json, deep-dive.json, capa, pe_imports)\n\n## 3. Initial Triage (15 minutes)\nThe initial triage was performed on the sample using a suite of tools: CAPA, FLOSS, PE imports analysis, YARA scanning, XOR string search, UPX packing check, and Ghidra disassembly.\n\n**Triage actions:**\n- CAPA analysis identified 59 capability rules triggered, including:\n  - \"packed with generic packer\"\n  - \"encode data using XOR\", \"encrypt data using HC-128\", \"encrypt data using RC4 PRGA\"\n  - \"check for Internet
… [19556 more chars]
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
- **Family (triage):** Delphi-based trojan (possible generic RAT)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report - Delphi-based Trojan

## Executive Summary
This report details the analysis of a malicious 32-bit PE executable (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c) identified as a Delphi-based trojan. Static analysis using CAPA, FLOSS, Ghidra, and other tools reveals capabilities including process injection, registry manipulation, system discovery, and obfuscation (XOR, RC4, HC-128). The sample is packed with a generic packer, hindering deep static analysis. No dynamic execution was performed; however, the static evidence strongly supports a verdict of malicious with high confidence (90%). The sample appears to masquerade as a game editor ("GML_EDIT_PRO") but contains no legitimate benign functionality. This report provides indicators of compromise, detection rules, and mitigation recommendations.

## 1. Sample Identification
| Property | Value |
| --- | --- |
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |
| File Name | virussign.com_40f9267218c144475dc0691431825779.vir |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | 32-bit |
| Compiler/Language | Delphi (inferred from FLOSS strings: InitInstance, TObject; and standard Delphi error messages) (source: floss, ghidra_query) |
| Packer | Generic packer detected by CAPA (not UPX) (source: capa, UPX) |
| Subsystem | Windows GUI |

## 2. Classification
- **Verdict**: Malicious
- **Confidence**: High (90%)
- **Family**: Delphi-based trojan (possible generic RAT)
- **Rationale**: The sample exhibits multiple malicious capabilities: process injection (VirtualAlloc, VirtualProtect), process creation (CreateProcess), registry manipulation (capa rule "create or open registry key"), network connectivity checks
… [18167 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 353ab6827b75
_Generated 2026-07-28T07:05:46.277785+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=248c | cross_refs=True | llm_ok=True | runtime=25.71s -->

## Executive Summary

| Property | Value |
|----------|-------|
| **Verdict** | Malicious (confidence: 90%) |
| **Family** | Delphi-based trojan (generic RAT) |
| **Agreement** | Disagrees with initial LLM triage (rated suspicious, score 40) |

The sample (SHA-256: `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`) is a 32-bit Windows PE executable packed with a generic packer (source: capa). Deep static analysis (source: deep_dive_agentic) reveals a Delphi-based trojan with capabilities commonly associated with remote access trojans (RATs). The malware can accept command-line arguments, manipulate registry keys, perform system reconnaissance (e.g., retrieve disk size), and encrypt data using XOR, RC4, and HC-128 algorithms (source: capa). No network indicators of compromise (C2 URLs, IP addresses) were found in the static code, suggesting the sample may operate locally or rely on offline payloads (source: cross-section:network_analysis). The absence of runtime behavioral data limits dynamic insight, but the static evidence is sufficient for a high-confidence malicious classification (source: deep_dive_agentic). This verdict overrides the preliminary automated triage that assigned a suspicious score of 40 based solely on capa rule matches (source: llm_v1_disagree). Overall, the sample exhibits classic commodity trojan features suitable for a range of cybercriminal activities, though no specific known family could be definitively matched (source: cross-section:comparison_with_known_families, cross-section:attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=34c | cross_refs=True | llm_ok=True | runtime=33.36s -->

The following table summarizes the identifiers for the analyzed sample.

| Field | Value | Evidence |
|-------|-------|----------|
| SHA-256 | `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c` | Provided sample hash. |
| File Size | Not available from provided evidence. | No tool output or section includes file size. |
| File Format | Portable Executable (PE) | Static analysis identifies the binary as a PE file (source: cross-section:4). |
| File Type | Executable (EXE) | The sample is a
… [36841 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4122` | `2beb38e29e7b9fad` |
| `prompt.txt` | `True` | `11290` | `607bbaeee83d9ddf` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `20671` | `5126822fad4f4fb2` |
| `REPORT-MASTER-v3.md` | `True` | `39439` | `40387b2d3de92dd1` |
| `REPORT-v2.md` | `True` | `20671` | `5126822fad4f4fb2` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `30247` | `48856ed2377aa2f1` |
| `rule.yar` | `True` | `1532` | `58e736be0746c364` |
| `intake-validation.json` | `True` | `1531` | `ee2c033099ecb4b5` |
| `source-decisions.json` | `True` | `886` | `cef51cfe929bb7a9` |
| `malcat-triage.json` | `True` | `166` | `2c737437071c385c` |
| `deep_dive/01-tools-raw.json` | `True` | `28240` | `d528dfbc2a840782` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3285` | `2da757ed978a5d46` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `15355` | `ca97674edf34bda3` |

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

- **intake_validation:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-validation.json` exists=`True` bytes=`1531` mtime=`2026-07-28T06:17:43.623342+00:00`
  - sha256: `ee2c033099ecb4b5b0d2fa3a51b10607cd15c8fb5cce9d581517454d2146465e`
- **malcat_triage:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/malcat-triage.json` exists=`True` bytes=`166` mtime=`2026-07-28T06:17:04.420244+00:00`
  - sha256: `2c737437071c385c826b1560c50b5476a78a6b8eb5e2c8a497e5512e33c5df94`
- **source_decisions:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/source-decisions.json` exists=`True` bytes=`886` mtime=`2026-07-28T06:17:43.623342+00:00`
  - sha256: `cef51cfe929bb7a9ae7cbc6fb0de461b4be636daa3f6fd492ea5b40f5131ebcd`
- **ghidra_import_log:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-analyzeHeadless.log` exists=`True` bytes=`6104` mtime=`2026-07-28T06:17:07.864544+00:00`
  - sha256: `8ef6f00850aab8c07a21fcb12023747b0e01b4ee9193dd4a34c90dd755940952`
- **ida_bootstrap_log:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra has 153 imports; IDA has 0."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra has 1 function; IDA has 0."
  },
  "strings": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra has 381 strings; IDA has none."
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra decompilation available; IDA errored."
  },
  "cff": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra call flow analysis available; IDA unavailable."
  },
  "static_profile": {
    "source": "ghidra",
    "confidence": "med
… [109 more chars]
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
  "rule_count": 59,
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
      "name": "encrypt data using HC-128",
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
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data",
            "HC-128"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "HC-128",
          "id": "C0027.006"
        }
      ]
    },
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
 
… [6786 more chars]
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
  "string_count": 10027,
  "strings_sampled": 80,
  "strings": [
    "j:,4;87",
    "4278124286",
    "GPVACPVA?",
    "KPVAGPVACPVA?",
    "KPVAKPVAGPVACPVA?",
    "?PVAKPVAKPVAGPVACPVA?",
    "CPVA?PVAKPVAKPVAGPVACPVA?",
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.reloc",
    "B.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "Single",
    "Extended",
    "Double",
    "Currency",
    "ShortString",
    "PAnsiChar0",
    "PWideCharL",
    "ByteBool",
    "WordBool",
    "LongBool",
    "string",
    "WideString",
    "AnsiString",
    "Variant",
    "OleVariant",
    "TClassd",
    "HRESULT",
    "&op_Equality",
    "&op_Inequality",
    "Create",
    "BigEndian",
    "AStartIndex",
    "IsEmpty",
    "PInterfaceEntry",
    "TInterfaceEntry",
    "VTable",
    "IOffset",
    "ImplGetter",
    "PInterfaceTable",
    "TInterfaceTable",
    "EntryCount",
    "Entries",
    "TMethod",
    "&op_GreaterThan",
    "&op_GreaterThanOrEqual",
    "&op_LessThan",
    "&op_LessThanOrEqual",
    "TObject&",
    "DisposeOf",
    "InitInstance",
    "Instance",
    "CleanupInstance",
    "ClassType",
    "ClassName",
    "ClassNameIs",
    "ClassParent",
    "ClassInfo",
    "InstanceSize",
    "InheritsFrom",
    "AClass",
    "MethodAddress",
    "MethodName",
    "Address",
    "QualifiedClassName"
  ],
  "per_category": {
    "decoded_strings": 2,
    "stack_strings": 5,
    "tight_strings": 2,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 10018
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 451.0,
  "size_bytes": 1005056,
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
    "packed with generic packer capa rules Indicates executable packing, common in malware to evade detection. capa   ",
    "encrypt data using HC-128 capa rules Use of HC-128 stream cipher for obfuscation, a non-standard algorithm. capa   ",
    "VirtualAlloc, VirtualProtect PE imports APIs for memory allocation and protection changes, typical for code injection. p",
    "CreateProcess PE imports API to create new processes, often used to execute malicious payloads. pe_imports    pe_imports",
    "get disk information, get common file path, query registry capa rules Discovery of system information and files, common "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Delphi-based trojan (possible generic RAT)",
  "score": 0.9,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "deepseek-v4-pro",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "packed with generic packer",
      "why": "Indicates executable packing, common in malware to evade detection."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "encrypt data using HC-128",
      "why": "Use of HC-128 stream cipher for obfuscation, a non-standard algorithm."
    },
    {
      "source": "pe_imports",
      "query_or_table": "PE imports",
      "row_or_rule": "VirtualAlloc, VirtualProtect",
      "why": "APIs for memory allocation and protection changes, typical for code injection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "PE imports",
      "row_or_rule": "CreateProcess",
      "why": "API to create new processes, often used to execute malicious payloads."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "get disk information, get common file path, query registry",
      "why": "Discovery of system information and files, common in reconnaissance."
    },
    {
      "source": "floss",
      "query_or_table": "FLOSS strings",
      "row_or_rule": "TObject, TClassd, InitInstance, This program must be run under Win32",
      "why": "Delphi runtime identifiers, indicating the binary was built with Delphi."
    },
    {
      "source": "ghidra",
      "query_or_table": "Total function count (Ghidra)",
      "row_or_rule": "SELECT count(*) AS funcs FROM funcs -> 1",
      "why": "Only one function identified, consistent with heavy packing/obfuscation."
    }
  ],
  "summary": "The sample is a packed Delphi executable exhibiting obfuscation (XOR, HC-128, RC4), process injection capabilities (VirtualAlloc, VirtualProtect, CreateProcess), and discovery behaviors (file system, registry, OS version). These characteristics are consistent with a remote access trojan (RAT) or backdoor."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/prompt.txt` exists=`True` bytes=`11290` mtime=`2026-07-28T06:25:27.668711+00:00`
  - sha256: `607bbaeee83d9ddf7f4bf1c195ac1bcbb31e451481504a57e5027f4cfa063386`
- **verdict:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/verdict.json` exists=`True` bytes=`4122` mtime=`2026-07-28T06:26:03.473409+00:00`
  - sha256: `2beb38e29e7b9fad079b9374011ddb87f38e0cd18de0867558858046bc3ab248`

#### prompt_excerpt

```
# Triage evidence
sha256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
sample_path: /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir
ghidra_session: ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
ida_session: ida-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra has 153 imports; IDA has 0.
- functions: ghidra (confidence=medium) — Ghidra has 1 function; IDA has 0.
- strings: ghidra (confidence=medium) — Ghidra has 381 strings; IDA has none.
- decompilation: ghidra (confidence=medium) — Ghidra decompilation available; IDA errored.
- cff: ghidra (confidence=medium) — Ghidra call flow analysis available; IDA unavailable.
- static_profile: ghidra (confidence=medium) — Malcat triage failed; Ghidra provides static profile data.
- llm_revised: T
… [10277 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 0.9,
  "family_guess": "Delphi-based trojan (possible generic RAT)",
  "cross_engine_notes": "IDA and Malcat engines failed. Ghidra analysis limited (only 1 function). Yara scanner had errors. Reliance on capa, FLOSS, and PE imports.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "packed with generic packer",
      "why": "Indicates executable packing, common in malware to evade detection."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "encrypt data using HC-128",
      "why": "Use of HC-128 stream cipher for obfuscation, a non-standard algorithm."
    },
    {
      "source": "pe_imports",
      "query_or_table": "PE imports",
      "row_or_rule": "VirtualAlloc, VirtualProtect",
      "why": "APIs for memory allocation and protection changes, typical for code injection."
    },
    {
      "source": "pe_imports",
      "query_or_table
… [3122 more chars]
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
  "rule_count": 59,
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
      "name": "encrypt data using HC-128",
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
            "Encryption-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encryption-Standard Algorithm",
          "id": "E1027.m05"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data",
            "HC-128"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "HC-128",
          "id": "C0027.006"
        }
      ]
    },
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
 
… [6786 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1005056,
  "duration_s": 0.04,
  "import_count": 150,
  "signal_count": 5,
  "signals": [
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
  "string_count": 10027,
  "strings_sampled": 80,
  "strings": [
    "j:,4;87",
    "4278124286",
    "GPVACPVA?",
    "KPVAGPVACPVA?",
    "KPVAKPVAGPVACPVA?",
    "?PVAKPVAKPVAGPVACPVA?",
    "CPVA?PVAKPVAKPVAGPVACPVA?",
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.reloc",
    "B.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "Single",
    "Extended",
    "Double",
    "Currency",
    "ShortString",
    "PAnsiChar0",
    "PWideCharL",
    "ByteBool",
    "WordBool",
    "LongBool",
    "string",
    "WideString",
    "AnsiString",
    "Variant",
    "OleVariant",
    "TClassd",
    "HRESULT",
    "&op_Equality",
    "&op_Inequality",
    "Create",
    "BigEndian",
    "AStartIndex",
    "IsEmpty",
    "PInterfaceEntry",
    "TInterfaceEntry",
    "VTable",
    "IOffset",
    "ImplGetter",
    "PInterfaceTable",
    "TInterfaceTable",
    "EntryCount",
    "Entries",
    "TMethod",
    "&op_GreaterThan",
    "&op_GreaterThanOrEqual",
    "&op_LessThan",
    "&op_LessThanOrEqual",
    "TObject&",
    "DisposeOf",
    "InitInstance",
    "Instance",
    "CleanupInstance",
    "ClassType",
    "ClassName",
    "ClassNameIs",
    "ClassParent",
    "ClassInfo",
    "InstanceSize",
    "InheritsFrom",
    "AClass",
    "MethodAddress",
    "MethodName",
    "Address",
    "QualifiedClassName"
  ],
  "per_category": {
    "decoded_strings": 2,
    "stack_strings": 5,
    "tight_strings": 2,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 10018
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 440.45,
  "size_bytes": 1005056,
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
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "disassembly": {
    "0x00471e60": "\u250c 290: entry0 ();\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_40h @ ebp-0x40\n\u2502           0x00471e60      55             push ebp\n\u2502           0x00471e61      8bec           mov ebp, esp\n\u2502           0x00471e63      b90f000000     mov ecx, 0xf                ; 15\n\u2502       \u250c\u2500> 0x00471e68      6a00           push 0\n\u2502       \u254e   0x00471e6a      6a00           push 0\n\u2502       \u254e   0x00471e6c      49             dec ecx\n\u2502       \u2514\u2500< 0x00471e6d      75f9           jne 0x471e68\n\u2502           0x00471e6f      51             push ecx\n\u2502           0x00471e70      53             push ebx\n\u2502           0x00471e71      56             push esi\n\u2502           0x00471e72      57             push edi\n\u2502           0x00471e73      b868ba4600     mov eax, 0x46ba68\n\u2502           0x00471e78      e827c8f5ff     call 0x3ce6a4\n\u2502           0x00471e7d      33c0           xor eax, eax\n\u2502           0x00471e7f      55             push ebp\n\u2502           0x00471e80      68c6264700     push 0x4726c6\n\u2502           0x00471e85      64ff30         push dword fs:[eax]\n\u2502           0x00471e88      648920         mov dword fs:[eax], esp\n\u2502           0x00471e8b      33d2           xor edx, edx\n\u2502           0x00471e8d      55             push ebp\n\u2502           0x00471e8e      6880264700     push 0x472680\n\u2502           0x00471e93      64ff32         push dword fs:[edx]\n\u2502           0x00471e96      648922         mov dword fs:[edx], esp\n\u2502           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000\n\u2502           0x00471e9e      e81583ffff     call 0x46a1b8\n\u2502           0x00471ea3      33c0           xor eax, eax\n\u2502           0x00471ea5      8945ec         mov dword [var_14h], eax\n\u2502           0x00471ea8      33d2           xor edx, edx\n\u2502           0x00471eaa      55             push ebp\n\u2502           0x00471eab      686f264700     push 0x47266f               ; 'o&G'\n\u2502           0x00471eb0      64ff32         push dword fs:[edx]\n\u2502           0x00471eb3      648922         mov dword fs:[edx], esp\n\u2502           0x00471eb6      8d55ec         lea edx, [var_14h]\n\u2502           0x00471eb9      33c0           xor eax, eax\n\u2502           0x00471ebb      e87c14ffff     call 0x46333c\n\u2502           0x00471ec0      8d45ec         lea eax, [var_14h]\n\u2502           0x00471ec3      e8a47cffff     call 0x469b6c\n\u2502           0x00471ec8      6a02           push 2                      ; 2\n\u2502           0x00471eca      6a00           push 0\n\u2502           0x00471ecc      6a01           push 1                      ; 1\n\u2502           0x00471ece      8b4dec         mov ecx, dword [var_14h]\n\u2502           0x00471ed1      b201           mov dl, 1\n\u2502           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc \".LF\"\n\u2502           0x00471ed8      e84f2cffff     call 0x464b2c\n\u2502           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0\n\u2502           0x00471ee2      33d2      
… [7367 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
    "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
  "checked": 7,
  "hits": 7,
  "misses": [],
  "hit_examples": [
    "packed with generic packer capa_analyze The sample is packed, a common technique to evade static analysis and hide malic",
    "encrypt data using RC4 PRGA capa_analyze RC4 encryption is frequently used in malware to obfuscate network traffic or pa",
    "encode data using XOR capa_analyze XOR encoding is a simple obfuscation method typical in malware. capa   ",
    "check for Internet connection capa_analyze Indicates potential command and control (C2) functionality. capa   ",
    "create or open registry key capa_analyze Registry manipulation is often used for persistence or configuration storage. c"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "The sample exhibits numerous malicious capabilities as identified by CAPA analysis, including packing, encoding/encryption (XOR, RC4, HC-128), registry manipulation, process injection, network communication (HTTP, DNS), and sandbox evasion. Although YARA and Malcat scans encountered errors, the CAPA",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "packed with generic packer",
      "why": "The sample is packed, a common technique to evade static analysis and hide malicious code."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "encrypt data using RC4 PRGA",
      "why": "RC4 encryption is frequently used in malware to obfuscate network traffic or payloads."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "encode data using XOR",
      "why": "XOR encoding is a simple obfuscation method typical in malware."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "check for Internet connection",
      "why": "Indicates potential command and control (C2) functionality."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "create or open registry key",
      "why": "Registry manipulation is often used for persistence or configuration storage."
    },
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "create process",
      "why": "Ability to spawn processes can be used for execution, injection, or persistence."
    },
    {
      "source": "yara_scan",
      "query_or_table": "yara_scan",
      "row_or_rule": "batch_errors",
      "why": "YARA scan failed with file-not-found errors, so no matches were possible. This does not indicate a clean file."
    }
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
  "rule_count": 59,
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
… [9886 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1005056,
  "duration_s": 0.04,
  "import_count": 150,
  "signal_count": 5,
  "signals": [
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
      "label": 
… [428 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 10027,
  "strings_sampled": 80,
  "strings": [
    "j:,4;87",
    "4278124286",
    "GPVACPVA?",
    "KPVAGPVACPVA?",
    "KPVAKPVAGPVACPVA?",
    "?PVAKPVAKPVAGPVACPVA?",
    "CPVA?PVAKPVAKPVAGPVACPVA?",
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.
… [1530 more chars]
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
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "disassembly": {
    "0x00471e60": "\u250c 290: entry0 ();\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_40h @ ebp-0x40\n\u2502
… [10467 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
    "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
      "name": "DelayLoad_MessageBoxA",
      "address": "3946656",
      "size": "1"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "audit_path": "/opt/samples/logs/353ab
… [74 more chars]
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
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n<assemblyIdentity\r\n    name=\"JR.Inno.Setup\"\r\n    processorArchitecture=\"x86\"\r\n    version=\"1.0.0.0\"\r\n    type=\"win32\"/>\r\n<description>I
… [10327 more chars]
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
      "address": "140",
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "145",
      "name": "AllocateAndInitializeSid",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "149",
      "name": "ConvertSidToStringSidW",
      "module": "ADVAPI32.DLL"
    },
 
… [6032 more chars]
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
      "name": "DelayLoad_MessageBoxA",
      "address": "3946656",
      "size": "1"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "audit_path": "/opt/samples/logs/353ab
… [74 more chars]
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
      "content": "RegOpenKeyExW",
      "address": "4718530",
      "length": "14"
    },
    {
      "content": "RegQueryValueExW",
      "address": "4718616",
      "length": "17"
    },
    {
      "content": "RegCloseKey",
      "address": "4718684",
      "length": "12"
    },
    {
      "content": "%s has not
… [3069 more chars]
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
      "content": "RegOpenKeyExW",
      "address": "4718530",
      "length": "14"
    },
    {
      "content": "RegCloseKey",
      "address": "4718684",
      "length": "12"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-353ab6827b
… [171 more chars]
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
      "content": "No single cast observer with ID %d was added to the observer collection",
      "address": "4950892",
      "length": "144"
    },
    {
      "content": "No multi cast observer with ID %d was added to the observer collection",
      "address": "4951036",
      "length": "142"
    },
    {
      "c
… [4298 more chars]
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
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n<assemblyIdentity\r\n    name=\"JR.Inno.Setup\"\r\n    processorArchitecture=\"x86\"\r\n    version=\"1.0.0.0\"\r\n    type=\"win32\"/>\r\n<description>I
… [14630 more chars]
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
      "content": "CreateProcessW",
      "address": "4716232",
      "length": "15"
    },
    {
      "content": "VirtualAlloc",
      "address": "4716928",
      "length": "13"
    },
    {
      "content": "Cannot call Start on a running or suspended thread",
      "address": "4953792",
      "length": "102"
    
… [3074 more chars]
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
      "content": "GetStartupInfoW",
      "address": "4716746",
      "length": "16"
    },
    {
      "content": "GetTempPathW",
      "address": "4716978",
      "length": "13"
    },
    {
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-c
… [2849 more chars]
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
      "content": "                                                                                                    ",
      "address": "4961720",
      "length": "202"
    },
    {
      "content": "No mapping for the Unicode character exists in the target multi-byte code page",
      "address": "4955702",
      
… [11772 more chars]
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
      "address": "3",
      "name": "CloseHandle",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "14",
      "name": "CompareStringOrdinal",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "29",
      "name": "CompareStringW",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "97"
… [9942 more chars]
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
      "content": "GetExitCodeProcess",
      "address": "4715882",
      "length": "19"
    },
    {
      "content": "VirtualProtect",
      "address": "4715948",
      "length": "15"
    },
    {
      "content": "GetProcessHeap",
      "address": "4716028",
      "length": "15"
    },
    {
      "content": "Exit
… [5445 more chars]
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
  "session_id": "ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "audit_path": "/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/audit.jsonl"
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
      "address": "107",
      "name": "CreateWindowExW",
      "module": "USER32.DLL"
    },
    {
      "address": "108",
      "name": "TranslateMessage",
      "module": "USER32.DLL"
    },
    {
      "address": "109",
      "name": "CharLowerBuffW",
      "module": "USER32.DLL"
    },
    {
      "address": "110",
… [1643 more chars]
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
      "start_ea": "3932160",
      "end_ea": "3933183",
      "name": "Headers",
      "class": "DATA",
      "perm": "4",
      "bitness": "0",
      "size": "1024",
      "is_read": "1",
      "is_write": "0",
      "is
… [3021 more chars]
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
      "content": "SetupLdr.e32",
      "address": "4726844",
      "length": "13"
    },
    {
      "content": "This installation was built with Inno Setup.",
      "address": "4961196",
      "length": "90"
    },
    {
      "content": "GML_EDIT_PRO Setup                                          ",
      "address
… [3022 more chars]
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
      "content": "                                                                                                    ",
      "address": "4961720",
      "length": "202"
    },
    {
      "content": "                                                            ",
      "address": "4961320",
      "length": "122"
  
… [20605 more chars]
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
      "content": "000004b0",
      "address": "4961154",
      "length": "18"
    },
    {
      "content": "AdjustTokenPrivileges",
      "address": "4718482",
      "length": "22"
    },
    {
      "content": "AllocateAndInitializeSid",
      "address": "4718576",
      "length": "25"
    },
    {
      "content"
… [19132 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 59,
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
… [9886 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 10027,
  "strings_sampled": 80,
  "strings": [
    "j:,4;87",
    "4278124286",
    "GPVACPVA?",
    "KPVAGPVACPVA?",
    "KPVAKPVAGPVACPVA?",
    "?PVAKPVAKPVAGPVACPVA?",
    "CPVA?PVAKPVAKPVAGPVACPVA?",
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.
… [1530 more chars]
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
      "address": "140",
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "145",
      "name": "AllocateAndInitializeSid",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "149",
      "name": "ConvertSidToStringSidW",
      "module": "ADVAPI32.DLL"
    },
 
… [15300 more chars]
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
      "address": "127",
      "name": "SafeArrayAccessData",
      "module": "OLEAUT32.DLL"
    },
    {
      "address": "129",
      "name": "SafeArrayCreate",
      "module": "OLEAUT32.DLL"
    },
    {
      "address": "130",
      "name": "SafeArrayGetElement",
      "module": "OLEAUT32.DLL"
    },
    {
      "ad
… [1518 more chars]
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
      "address": "2",
      "name": "GetExitCodeProcess",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "5",
      "name": "SizeofResource",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "6",
      "name": "VirtualProtect",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "8",

… [3534 more chars]
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
      "address": "123",
      "name": "SafeArrayPutElement",
      "module": "OLEAUT32.DLL"
    },
    {
      "address": "124",
      "name": "VariantInit",
      "module": "OLEAUT32.DLL"
    },
    {
      "address": "125",
      "name": "VariantClear",
      "module": "OLEAUT32.DLL"
    },
    {
      "address": "12
… [1518 more chars]
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
      "address": "140",
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "145",
      "name": "AllocateAndInitializeSid",
      "module": "ADVAPI32.DLL"
    },
    {
      "address": "149",
      "name": "ConvertSidToStringSidW",
      "module": "ADVAPI32.DLL"
    },
 
… [15300 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c.json"
}
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 1005056,
  "duration_s": 0.06,
  "import_count": 150,
  "signal_count": 5,
  "signals": [
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
      "label": 
… [428 more chars]
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "audit_path": "/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d2
… [36 more chars]
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
      "string_addr": "4722952",
      "string_value": "kernel32.dll",
      "string_length": "13",
      "ref_addr": "4722692",
      "func_addr": "",
      "func_name": ""
    },
    {
      "string_addr": "4723000",
      "string_value": "user32.dll
… [1175 more chars]
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
      "content": "__dbk_fcall_wrapper",
      "address": "4726857",
      "length": "20"
    },
    {
      "content": "dbkFCallWrapperAddr",
      "address": "4726877",
      "length": "20"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra
… [185 more chars]
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
      "content": "kernel32.dll",
      "address": "4715856",
      "length": "13"
    },
    {
      "content": "user32.dll",
      "address": "4717790",
      "length": "11"
    },
    {
      "content": "advapi32.dll",
      "address": "4718392",
      "length": "13"
    },
    {
      "content": "kernel32.dll",
 
… [3222 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/01-tools-raw.json` exists=`True` bytes=`28240` mtime=`2026-07-28T06:39:06.896357+00:00`
  - sha256: `d528dfbc2a840782fbfffa08adf589bd62990194f9aa9878d4bc098b437e1a95`
- **sql_evidence:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/05-deep-dive.json` exists=`True` bytes=`3285` mtime=`2026-07-28T06:53:01.386202+00:00`
  - sha256: `2da757ed978a5d463b75c4fbed46bf7e93ef9922ab162549177677011fee3462`

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
  "summary": "The sample exhibits numerous malicious capabilities as identified by CAPA analysis, including packing, encoding/encryption (XOR, RC4, HC-128), registry manipulation, process injection, network communication (HTTP, DNS), and sandbox evasion. Although YARA and Malcat scans encountered errors, the CAPA findings are sufficient to classify the file as malware with high confidence.",
  "key_evidence": [
    {
      "source": "capa",
      "query_or_table": "capa_analyze",
      "row_or_rule": "packed with generic packer",
      "why": "The sample is packed, a common technique to evade static analysis and hide malicious code."
    },
    {
      "source": "capa",
      "query_or
… [2485 more chars]
```

- **agentic:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`540955` mtime=`2026-07-28T06:53:01.385302+00:00`
  - sha256: `7190c291cf259408b31d1606edc87f648cb26856753adf1735772a0c840be4e8`

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

- **rule_yar:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar` exists=`True` bytes=`1532` mtime=`2026-07-28T06:53:03.719902+00:00`
  - sha256: `58e736be0746c364f522bba9414e1ec4555a3455e7b718c6611b0039046336a0`

#### excerpt

```
// yara_gen_v2.py — 2026-07-28T06:53:03.720794+00:00
rule CADRE_v2_unknown_353ab6827b75 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c"
        family = "unknown"
        cadre_reveng_v2 = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "No mapping for the Unicode character exists in the target multi-byte code page" ascii wide
        $s1 = "Cannot have multiple single cast observers added to the observers collection" ascii wide
        $s2 = "Access violation at address %p in module '%s' (offset %x). %s of address %p" ascii wide
        $s3 = "No single cast observer with ID %d was added to the observer collection" ascii wide
        $s4 = "N
… [730 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v2.md` exists=`True` bytes=`20671` mtime=`2026-07-28T06:58:36.976380+00:00`
  - sha256: `5126822fad4f4fb2b59b479a9b27823085f1d4e8a2b3203689ffc2e81d6f7aee`
- **REPORT_MASTER_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v3.md` exists=`True` bytes=`39439` mtime=`2026-07-28T07:05:46.278152+00:00`
  - sha256: `40387b2d3de92dd1b214f0a636ccebec2150b99ee8b0f289e36ab9d069609175`
- **REPORT_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-v2.md` exists=`True` bytes=`20671` mtime=`2026-07-28T06:58:36.976380+00:00`
  - sha256: `5126822fad4f4fb2b59b479a9b27823085f1d4e8a2b3203689ffc2e81d6f7aee`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`39677` mtime=`2026-07-28T07:00:35.054572+00:00`
  - sha256: `4e7020df2d1a61b418ad4cd44e32b906c4e10e96ec3a3ea8e985e1d9ab959e75`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`30247` mtime=`2026-07-28T07:06:57.411447+00:00`
  - sha256: `48856ed2377aa2f178bc72568408ee382ee1c5300c61a4e58bb00b84615b8b3c`
- **report_v2_json:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/report-v2.json` exists=`True` bytes=`23056` mtime=`2026-07-28T07:00:35.057272+00:00`
  - sha256: `6bb4d8aea93901f45de8df2f90aa48209eb2eb1c5f0eea5062d75211791355e4`

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
- **Family (triage):** Delphi-based trojan (possible generic RAT)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report - Delphi-based Trojan

## Executive Summary
This report details the analysis of a malicious 32-bit PE executable (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28
… [19767 more chars]
```


#### v3_excerpt

```
# RE Report — 353ab6827b75
_Generated 2026-07-28T07:05:46.277785+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=248c | cross_refs=True | llm_ok=True | runtime=25.71s -->

## Executive Summary

| Property | Value |
|----------|-------|
| **Verdict** | Malicious (confidence: 90%) |
| **Family** | Delphi-based trojan (generic RAT) |
| **Agreement** | Disagrees with initial LLM triage (rated suspicious, score 40) |

The sample (SHA-256: `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`) is a 32-bit Windows PE executable packed with a generic packer (source: capa). Deep static analysis (source: deep_dive_agentic) reveals a Delphi-based trojan with capabilities commonly associated with remote access trojans (RATs). The malware can accept comma
… [38441 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
