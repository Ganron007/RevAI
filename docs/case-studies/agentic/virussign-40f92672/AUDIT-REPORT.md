# Pipeline AUDIT-REPORT — `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:25.286542+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:25 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`

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

- source=`llm_judge` model=`mimo-v2.5` verdict=`Malicious` confidence=`75`
- key_evidence_count=`6`

```json
{
  "verdict": "Malicious",
  "score": 75,
  "family_guess": "Trojanized Inno Setup installer",
  "cross_engine_notes": "Behavioral signals (privilege escalation, registry manipulation) are corroborated across YARA, capa, and MalCat. The sample is identified as an Inno Setup installer, which may be used to deliver malicious payloads. Obfuscation and high entropy are present but are neutral per verdict calibration.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "escalate_priv",
      "row_or_rule": "YARA rule matches for 'escalate_priv' indicates privilege escalation behavior.",
      "why": "YARA rule 'escalate_priv' is a behavioral signal for privilege escalation, which is a malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "adjust_token_privileges",
      "row_or_rule": "capa rule 'adjust_token_privileges' detected with ATT&CK technique T1134.",
      "why": "Privilege escalation capability is a clear behavioral signal of malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "query_registry",
      "row_or_rule": "capa rule 'query_registry' detected with ATT&CK technique T1012.",
      "why": "Registry manipulation is often used for persistence or configuration changes in malware."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "Imports: advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW (score 8 each).",
      "why": "High-signal imports for privilege adjustment and privilege value lookup are used in privilege escalation attacks."
    },
    {
      "source": "malcat",
      "query_or_table": "Constants/registry",
      "row_or_rule": "Registry constants: HKEY_CURRENT_USER (x6), HKEY_LOCAL_MACHINE (x3), HKEY_USERS.",
      "why": "Frequent registry key references indicate registry manipulation, a common malicious behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "VersionInfo::Comments",
      "row_or_rule": "Value: 'This installation was built with Inno Setup.'",
      "why": "The sample is an Inno Setup installer, which can be used to package and deliver malware."
    }
  ],
  "summary": "This sample is a malicious Inno Setup installer (GML_EDIT_PRO Setup) with privilege escalation capabilities (evidenced by YARA, capa, and MalCat). It exhibits registry manipulation and uses high-signal imports like AdjustTokenPrivileges and LookupPrivilegeValueW. The binary is heavily obfuscated (high entropy, many anomalies) but obfuscation alone is not the basis for the malicious verdict. The combination of behavioral signals (privilege escalation, registry access) and its nature as an installer supports the malicious classification.",
  "source": "llm_judge",
  "model": "mimo-v2.5",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 16 matches",
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
    
… [1096 more chars]
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
  "summary": "Inno Setup installer (v6.7.0) masquerading as 'GML_EDIT_PRO Setup' built with Delphi v36.0. Contains process injection chain (VirtualAlloc+VirtualProtect+CreateProcessW via FUN_00469f74/FUN_0046a1b8), obfuscated stack strings (capa T1027.005), XOR and HC-128 encryption, privilege escalation APIs (AdjustTokenPrivileges/OpenProcessToken), multiple embedded PEs for dropper behavior, and extreme control-flow obfuscation (CC=201 in 1007 bytes). Product metadata is trivially forged and does not establish legitimacy.",
  "key_evidence": [
    "capa: obfuscated stack strings (T1027.005), XOR encoding (T1027), HC-128 encryption, process injection (T1055) via VirtualAlloc+VirtualProtect",
    "imports: VirtualAlloc, VirtualProtect, CreateProcessW, AdjustTokenPrivileges, OpenProcessToken, RegOpenKeyExW",
    "callgraph: FUN_00469f74(0x4628340)->CreateProcessW, FUN_0046a1b8(0x4628920)->VirtualProtect (injection chain)",
    "function_metrics: FUN_003ce188 CC=201 blocks=1007 bytes \u2014 extreme CFF/obfuscation ratio",
    "YARA 16 matches: embedded PEs, SHA512/BLAKE2 constants, XOR/base64 encoding, URLs, IPs",
    "strings: 'Inno Setup Setup Data (6.7.0)', 'GML_EDIT_PRO Setup', 'InnoSetupLdrWindow', 'Embarcadero Delphi for Win32 compiler version 36.0'",
    "malcat: 16 anomalies, multiple embedded PEs, LZMA decompression of packed payload",
    "VersionInfo product 'GML_EDIT_PRO' is trivially forged and NOT evidence of legitimacy"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 40,
  "successful_non_bootstrap_tools": 29,
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
  },
  "depth_coverage": null
}
```

#### `publish`

- source=`llm_judge` model=`mimo-v2.5` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Trojanized Inno Setup Installer",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 13:41:50 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Trojanized Inno Setup installer\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\n\nWe analyzed a PE32 executable with SHA256 `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c` presented as 'GML_EDIT_PRO Setup'. The upstream triage verdict is **malicious**, and our analysis corroborates this with high confidence (90%). The sample is a heavily obfuscated Inno Setup installer (v6.7.0) compiled with Delphi (v36.0). It exhibits a malicious capability chain including privilege escalation, process injection (T1055), registry manipulation (T1012), and defense evasion through encryption (T1027) and obfuscated stack strings (T1027.005). Embedded PE files suggest dropper behavior. While product metadata claims legitimacy, the combination of behavioral signals and anomalous code structure confirms malicious intent. Immediate containment and investigation of systems where this installer ran are recommended.\n\n## 1. Sample Identification\n\nThe primary artifact is a Windows PE32 executable (x86) with high entropy (131), indicating potential obfuscation or packing. The file is located at the path `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir`.\n\n| Property | Value |\n|----------|-------|\n| SHA256 | `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c` |\n| File Type | PE32 (x86) |\n| Architecture | x86 (32-bit) |\n| Compiler | Embarcadero Delphi for Win32 (v36.0) |\n| Installer | Inno Setup (v6.7.0) |\n| Entropy | 131 (high) |\n| Project | incoming |\n\n(Source: malcat, deep-dive.json)\n\n## 2. Classification\n\n**Verdict: Malicious**\n\n**Confidence: 90%**\n\n**Family/Class: Trojanized Inno Setup Installer / Dropper**\n\nThe sample is definitively malicious. It is not a legitimate Inno Setup installer but a weaponized version designed to gain elevated privileges and execute injected payloads. The verdict is based on confirmed behavioral intents, not mere obfuscation. Key evidence includes YARA matches for privilege escalation (`escalate_priv`), capa detection of privilege adjustment APIs (`adjust_token_privileges`, T1134), and process injection capabilities (`VirtualAlloc`, `VirtualProtect`, `CreateProcessW` for T1055). The obfuscated stack strings and encryption are evasion techniques supporting the malicious objective.\n\n(Source: triage_verdict.json, capa, yara)\n\n## 3. Background & Family Lineage\n\nThe sample masquerades as an installer for 
… [15461 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:41:50 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Trojanized Inno Setup installer
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

We analyzed a PE32 executable with SHA256 `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c` presented as 'GML_EDIT_PRO Setup'. The upstream triage verdict is **malicious**, and our analysis corroborates this with high confidence (90%). The sample is a heavily obfuscated Inno Setup installer (v6.7.0) compiled with Delphi (v36.0). It exhibits a malicious capability chain including privilege escalation, process injection (T1055), registry manipulation (T1012), and defense evasion through encryption (T1027) and obfuscated stack strings (T1027.005). Embedded PE files suggest dropper behavior. While product metadata claims legitimacy, the combination of behavioral signals and anomalous code structure confirms malicious intent. Immediate containment and investigation of systems where this installer ran are recommended.

## 1. Sample Identification

The primary artifact is a Windows PE32 executable (x86) with high entropy (131), indicating potential obfuscation or packing. The file is located at the path `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir`.

| Property | Value |
|----------|-------|
| SHA256 | `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c` |
| File Type | PE32 (x86) |
| Architecture | x86 (32-bit) |
| Compiler | Embarcadero Delphi for Win32 (v36.0) |
| Installer | Inno Setup (v6.7.0) |
| Entropy | 131 (high) |
| Project | incoming |

(Source: malcat, deep-dive.json)

## 2. Classification

**Verdict: M
… [13608 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:48:28 UTC

# RE Report — 353ab6827b75
_Generated 2026-08-08T13:48:28.068230+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=258c | cross_refs=True | llm_ok=True | runtime=24.81s -->

# Executive Summary

The malware sample with SHA-256 hash `353ab6827b750979ba12450e38e73669daa850445d28861f62d27349a32f68c` is assessed as **malicious**, belonging to the **Trojanized Inno Setup installer** family. This verdict is derived from aggregated evidence across multiple analysis engines, with a deep confidence level of **90%** (source: deep_dive_agentic), and high agreement between the LLM and initial triage (source: cross-section:Classification).

**Summary:** This malware likely abuses a legitimate Inno Setup installer to deliver trojanized payloads, enabling stealthy infection and potential evasion of security controls. It demonstrates persistent behaviors, such as registry modifications and obfuscated network communications, suggesting capabilities for maintaining access and command-and-control (C2) operations.

**Evidence and Interpretation:** We base our assessment on key findings from automated tools and cross-section analyses, as summarized below. Each point is interpreted to highlight why it indicates malice, with confidence hedged where appropriate.

| Evidence Source       | Key Finding                                  | Why It Indicates Malice                                                                 | Confidence |
|-----------------------|----------------------------------------------|-----------------------------------------------------------------------------------------|------------|
| yara                  | 16 rule matches                              | YARA signatures often detect known malicious patterns, confirming initial triage (source: yara). | High       |
| capa                  | 44 capability rules triggered                | CAPA identifies behaviors like encryption and persistence, common in malware (source: capa). | High       |
| deep_dive_agentic     | 90% confidence score                         | Deep analysis reinforces malice through behavioral and static indicators (source: deep_dive_agentic). |
… [43061 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4596` | `b2809d1b884b2a63` |
| `prompt.txt` | `True` | `31360` | `2ed53c96d9b777b0` |
| `pipeline-audit.json` | `True` | `117677` | `b1e1754d791cdfbc` |
| `AUDIT-REPORT.md` | `True` | `87882` | `a8da28ff44539d6d` |
| `REPORT-MASTER-v2.md` | `True` | `16119` | `526a8317087b464f` |
| `REPORT-MASTER-v3.md` | `True` | `45595` | `d5c40a298d768e8c` |
| `REPORT-v2.md` | `True` | `16119` | `526a8317087b464f` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `63238` | `9ce7b4899ff60ed5` |
| `rule.yar` | `True` | `2026` | `c22ab95c8da99074` |
| `intake-validation.json` | `True` | `2389` | `3d20e979f9baefc1` |
| `source-decisions.json` | `True` | `1471` | `3f4b8ab210f5d130` |
| `malcat-triage.json` | `True` | `78933` | `d547e24f6a69c1f1` |
| `deep_dive/01-tools-raw.json` | `True` | `181670` | `69e7e9fd5fb3810c` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2805` | `908ccbe242db414c` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `166583` | `5b4828175a3a3175` |

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

- **intake_validation:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-validation.json` exists=`True` bytes=`2389` mtime=`2026-08-08T13:12:09.133710+00:00`
  - sha256: `3d20e979f9baefc141393893b7fa09293c14282499fda7c8a9635a3e0b759735`
- **malcat_triage:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/malcat-triage.json` exists=`True` bytes=`78933` mtime=`2026-08-08T13:10:47.254638+00:00`
  - sha256: `d547e24f6a69c1f11b9a86fb3c168b3ec0d2e59d1d4d0691bfaaf7c3e042294b`
- **source_decisions:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/source-decisions.json` exists=`True` bytes=`1471` mtime=`2026-08-08T13:12:09.133710+00:00`
  - sha256: `3f4b8ab210f5d130ccab5288018a995f576154d2153c4d9e9e499bfa77b9dc5e`
- **ghidra_import_log:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-idasql.log` exists=`True` bytes=`259` mtime=`2026-08-08T13:10:50.314633+00:00`
  - sha256: `3933b9bebc18892f741e04066fc845e47c2bec83327a8248760c3a286f768519`

#### source_decisions_excerpt

```
{
  "sha256": "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra imports=153 matches IDA imports=153, but malcat imports=360 diverges; cite {ghidra, imports count, 153, agreement with ida despite malcat outlier}."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra funcs=2472 and IDA funcs=1982 are within 1.25x, while malcat funcs=10 is unreliable; cite {ghidra, functions count, 2472, close to ida and malcat not comparable}."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Use both ghidra strings=2004 and ida strings=8960 for comprehensive coverage; cite {ghidra and ida, strings count, 2004 and 8960, complem
… [694 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
    "file_name": "virussign.com_40f9267218c144475dc0691431825779.vir",
    "file_path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
    "file_size": 1005056,
    "type": "PE",
    "architecture": "X86",
    "entropy": 131,
    "sha256": "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
… [78133 more chars]
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
          "id": "
… [6730 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 1002335,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 782284,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2670,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 680866,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA512_Constants",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 737040,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 737044,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 737048,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 737052,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 222840,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 222850,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 222860,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 222870,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 222880,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 222890,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 222900,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 222910,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
     
… [7058 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 10018,
  "strings_sampled": 80,
  "strings": [
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
    "QualifiedClassName",
    "FieldAddress",
    "GetInterface",
    "GetInterfaceEntry",
    "GetInterfaceTable",
    "UnitName",
    "UnitScope",
    "Equals",
    "GetHashCode"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 10018
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 180.61,
  "size_bytes": 1005056,
  "static_only": true,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
    "file_name": "virussign.com_40f9267218c144475dc0691431825779.vir",
    "file_path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
    "file_size": 1005056,
    "type": "PE",
    "architecture": "X86",
    "entropy": 131,
    "sha256": "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
    "metadata": {
      "Delphi::ProjectName": "SetupLdr",
      "VersionInfo::Comments": "This installation was built with Inno Setup.",
      "VersionInfo::CompanyName": "                                                            ",
      "VersionInfo::FileDescription": "GML_EDIT_PRO Setup                                          ",
      "VersionInfo::FileVersion": "                    ",
      "VersionInfo::LegalCopyright": "                                                                                                    ",
      "VersionInfo::OriginalFileName": "                                                  ",
      "VersionInfo::ProductName": "GML_EDIT_PRO                                                ",
      "VersionInfo::ProductVersion": "3.5.1                                             ",
      "Exports::Module name": "SetupLdr.e32"
    },
    "entrypoint_ea": 726112,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1536,
        "virtual_size": 0,
        "rights": "",
        "entropy": 55
      },
      {
        "name": ".text",
        "effective_address": 1536,
        "physical_size": 718848,
        "virtual_size": 720896,
        "rights": "RX",
        "entropy": 121
      },
      {
        "name": ".itext",
        "effective_address": 722432,
        "physical_size": 6656,
        "virtual_size": 8192,
        "rights": "RX",
        "entropy": 121
      },
      {
        "name": ".data",
        "effective_address": 730624,
        "physical_size": 16384,
        "virtual_size": 16384,
        "rights": "RW",
        "entropy": 80
      },
      {
        "name": ".bss",
        "effective_address": 747008,
        "physical_size": 29184,
        "virtual_size": 32768,
        "rights": "RW",
        "entropy": 28
      },
      {
        "name": ".idata",
        "effective_address": 779776,
        "physical_size": 4608,
        "virtual_size": 8192,
        "rights": "RW",
        "entropy": 24
      },
      {
        "name": ".didata",
        "effective_address": 787968,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".edata",
        "effective_address": 792064,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".rdata",
        "effective_address": 796160,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".reloc",
        "effective_address": 800256,
        "physical_size": 73728,
        "
… [126342 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "YARA rule matches for 'escalate_priv' indicates privilege escalation behavior. escalate_priv YARA rule 'escalate_priv' i",
    "capa rule 'adjust_token_privileges' detected with ATT&CK technique T1134. adjust_token_privileges Privilege escalation c",
    "capa rule 'query_registry' detected with ATT&CK technique T1012. query_registry Registry manipulation is often used for ",
    "Imports: advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW (score 8 each). Top high-signal imports High-sig",
    "Registry constants: HKEY_CURRENT_USER (x6), HKEY_LOCAL_MACHINE (x3), HKEY_USERS. Constants/registry Frequent registry ke"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Trojanized Inno Setup installer",
  "score": 75,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "escalate_priv",
      "row_or_rule": "YARA rule matches for 'escalate_priv' indicates privilege escalation behavior.",
      "why": "YARA rule 'escalate_priv' is a behavioral signal for privilege escalation, which is a malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "adjust_token_privileges",
      "row_or_rule": "capa rule 'adjust_token_privileges' detected with ATT&CK technique T1134.",
      "why": "Privilege escalation capability is a clear behavioral signal of malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "query_registry",
      "row_or_rule": "capa rule 'query_registry' detected with ATT&CK technique T1012.",
      "why": "Registry manipulation is often used for persistence or configuration changes in malware."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "Imports: advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW (score 8 each).",
      "why": "High-signal imports for privilege adjustment and privilege value lookup are used in privilege escalation attacks."
    },
    {
      "source": "malcat",
      "query_or_table": "Constants/registry",
      "row_or_rule": "Registry constants: HKEY_CURRENT_USER (x6), HKEY_LOCAL_MACHINE (x3), HKEY_USERS.",
      "why": "Frequent registry key references indicate registry manipulation, a common malicious behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "VersionInfo::Comments",
      "row_or_rule": "Value: 'This installation was built with Inno Setup.'",
      "why": "The sample is an Inno Setup installer, which can be used to package and deliver malware."
    }
  ],
  "summary": "This sample is a malicious Inno Setup installer (GML_EDIT_PRO Setup) with privilege escalation capabilities (evidenced by YARA, capa, and MalCat). It exhibits registry manipulation and uses high-signal imports like AdjustTokenPrivileges and LookupPrivilegeValueW. The binary is heavily obfuscated (high entropy, many anomalies) but obfuscation alone is not the basis for the malicious verdict. The co"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/prompt.txt` exists=`True` bytes=`31360` mtime=`2026-08-08T13:15:30.402073+00:00`
  - sha256: `2ed53c96d9b777b09257f63d3f7c33a0267cf5d18280fc537bd4b8153cda9a22`
- **verdict:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/verdict.json` exists=`True` bytes=`4596` mtime=`2026-08-08T13:15:57.765007+00:00`
  - sha256: `b2809d1b884b2a63743a1e182cb349d4426e51a74a8706656bf4653dcdfe4a25`

#### prompt_excerpt

```
# Triage evidence
sha256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
sample_path: /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir
ghidra_session: ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
ida_session: ida-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra imports=153 matches IDA imports=153, but malcat imports=360 diverges; cite {ghidra, imports count, 153, agreement with ida despite malcat outlier}.
- functions: ghidra (confidence=medium) — Ghidra funcs=2472 and IDA funcs=1982 are within 1.25x, while malcat funcs=10 is unreliable; cite {ghidra, functions count, 2472, close to ida and malcat not comparable}.
- strings: both (confidence=high) — Use both ghidra strings=2004 and ida strings=8960 for comprehensive coverage; cite {ghidr
… [30313 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 75,
  "family_guess": "Trojanized Inno Setup installer",
  "cross_engine_notes": "Behavioral signals (privilege escalation, registry manipulation) are corroborated across YARA, capa, and MalCat. The sample is identified as an Inno Setup installer, which may be used to deliver malicious payloads. Obfuscation and high entropy are present but are neutral per verdict calibration.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "escalate_priv",
      "row_or_rule": "YARA rule matches for 'escalate_priv' indicates privilege escalation behavior.",
      "why": "YARA rule 'escalate_priv' is a behavioral signal for privilege escalation, which is a malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "adjust_token_privileges",
      "row_or_rule": "capa rule 'adjust_token_privileges' detected with ATT&CK technique T1134.",
      "why": "Privilege escalation capability is a clear behavioral signal of mal
… [3596 more chars]
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
  "rule_count": 44,
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
          "id": "
… [6729 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1005056,
  "duration_s": 0.03,
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
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 1002335,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 782284,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2670,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 680866,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA512_Constants",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 737040,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 737044,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 737048,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 737052,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 222840,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 222850,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 222860,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 222870,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 222880,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 222890,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 222900,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 222910,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
     
… [7036 more chars]
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
  "duration_s": 427.53,
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
… [7231 more chars]
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
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "capa: obfuscated stack strings (T1027.005), XOR encoding (T1027), HC-128 encryption, process injection (T1055) via Virtu",
    "imports: VirtualAlloc, VirtualProtect, CreateProcessW, AdjustTokenPrivileges, OpenProcessToken, RegOpenKeyExW",
    "callgraph: FUN_00469f74(0x4628340)->CreateProcessW, FUN_0046a1b8(0x4628920)->VirtualProtect (injection chain)",
    "function_metrics: FUN_003ce188 CC=201 blocks=1007 bytes \u2014 extreme CFF/obfuscation ratio",
    "YARA 16 matches: embedded PEs, SHA512/BLAKE2 constants, XOR/base64 encoding, URLs, IPs"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "Inno Setup installer (v6.7.0) masquerading as 'GML_EDIT_PRO Setup' built with Delphi v36.0. Contains process injection chain (VirtualAlloc+VirtualProtect+CreateProcessW via FUN_00469f74/FUN_0046a1b8), obfuscated stack strings (capa T1027.005), XOR and HC-128 encryption, privilege escalation APIs (Ad",
  "key_evidence": [
    "capa: obfuscated stack strings (T1027.005), XOR encoding (T1027), HC-128 encryption, process injection (T1055) via VirtualAlloc+VirtualProtect",
    "imports: VirtualAlloc, VirtualProtect, CreateProcessW, AdjustTokenPrivileges, OpenProcessToken, RegOpenKeyExW",
    "callgraph: FUN_00469f74(0x4628340)->CreateProcessW, FUN_0046a1b8(0x4628920)->VirtualProtect (injection chain)",
    "function_metrics: FUN_003ce188 CC=201 blocks=1007 bytes \u2014 extreme CFF/obfuscation ratio",
    "YARA 16 matches: embedded PEs, SHA512/BLAKE2 constants, XOR/base64 encoding, URLs, IPs",
    "strings: 'Inno Setup Setup Data (6.7.0)', 'GML_EDIT_PRO Setup', 'InnoSetupLdrWindow', 'Embarcadero Delphi for Win32 compiler version 36.0'",
    "malcat: 16 anomalies, multiple embedded PEs, LZMA decompression of packed payload",
    "VersionInfo product 'GML_EDIT_PRO' is trivially forged and NOT evidence of legitimacy"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      
… [10136 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
… [131718 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 44,
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
… [9829 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1005056,
  "duration_s": 0.03,
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
… [10331 more chars]
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
      "name": "FUN_003dcb00",
      "address": "4049664",
      "size": "2521"
    },
    {
      "name": "FUN_0040b5c4",
      "address": "4240836",
      "size": "2253"
    },
    {
      "name": "FUN_00467b20",
      "address": "4619040",
      "size": "2192"
    },
    {
      "name": "FUN_003de95c",
      "address":
… [2270 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 1005056,
  "duration_s": 0.05,
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
    "name",
    "module",
    "address"
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

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 44,
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
… [9829 more chars]
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
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL",
      "address": "140"
    },
    {
      "name": "AllocateAndInitializeSid",
      "module": "ADVAPI32.DLL",
      "address": "145"
    },
    {
      "name": "ConvertSidToStringSidW",
      "module": "ADVAPI32.DLL",
      "address": "149"
    },
 
… [10024 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "cyclomatic_complexity",
    "instruction_count",
    "block_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_003ce188",
      "address": "3989896",
      "size": "1007",
      "cyclomatic_complexity": "201",
      "instruction_count": "204",
      "block_count": "201",
      "string_ref_count": "0"
    },
    {
  
… [6703 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name"
  ],
  "rows": [
    {
      "name": "LoadStringW"
    },
    {
      "name": "LoadLibraryExW"
    },
    {
      "name": "DelayLoad_MessageBoxA"
    },
    {
      "name": "LoadLibraryA"
    },
    {
      "name": "LoadLibraryExW"
    },
    {
      "name": "LoadLibraryW"
    },
    {
      "name": "LoadResource"
    },
    {
      "name": "LoadStringW"
    }
  ],
  "r
… [296 more chars]
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
      "name": "SizeofResource",
      "module": "KERNEL32.DLL",
      "address": "5"
    },
    {
      "name": "VirtualProtect",
      "module": "KERNEL32.DLL",
      "address": "6"
    },
    {
      "name": "FindResourceW",
      "module": "KERNEL32.DLL",
      "address": "27"
    },
    {
      "name": "LoadResourc
… [466 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c.json"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: name`

```json
{
  "error": "ghidrasql SQL error: no such column: name"
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
      "content": "The Setup program accepts optional command line parameters.\r\n\r\n/HELP, /?\r\nShows this information.\r\n/SP-\r\nDisables the \"This will install... Do you wish to continue?\" message box at the beginning of Setup.\r\n/SILENT, /VERYSILENT\r\nInstructs Setup to be silent or very silent.\r\n/NOSTYL
… [6832 more chars]
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
… [3137 more chars]
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
      "content": "The Setup program accepts optional command line parameters.\r\n\r\n/HELP, /?\r\nShows this information.\r\n/SP-\r\nDisables the \"This will install... Do you wish to continue?\" message box at the beginning of Setup.\r\n/SILENT, /VERYSILENT\r\nInstructs Setup to be silent or very silent.\r\n/NOSTYL
… [7768 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
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
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "Software\\Embarcadero\\Locales",
      "address": "3982092",
      "length": "58"
    },
    {
      "content": "Software\\CodeGear\\Locales",
      "address": "3982152",
      "length": "52"
    },
    {
      "content": "Software\\Borland\\Locales",
      "address": "3982204",
      "length": "50
… [3970 more chars]
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      
… [10136 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "cyclomatic_complexity",
    "instruction_count",
    "block_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_003e757c",
      "address": "4093308",
      "size": "504",
      "cyclomatic_complexity": "24",
      "instruction_count": "140",
      "block_count": "24",
      "string_ref_count": "23"
    },
    {
    
… [517 more chars]
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
      "content": "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline",
      "address": "4634912",
      "length": "206"
    },
    {
      "content": "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.
… [2842 more chars]
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
      "content": "Software\\Borland\\Locales",
      "address": "3982204",
      "length": "50"
    },
    {
      "content": "Software\\Borland\\Delphi\\Locales",
      "address": "3982256",
      "length": "64"
    },
    {
      "content": "ExtractRawData",
      "address": "4182006",
      "length": "18"
    },

… [4833 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
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
    "func_name",
    "func_addr",
    "string_value",
    "string_addr"
  ],
  "rows": [
    {
      "func_name": "FUN_00463510",
      "func_addr": "4601104",
      "string_value": "GetTempPath2W",
      "string_addr": "4601384"
    },
    {
      "func_name": "FUN_00463510",
      "func_addr": "4601104",
      "string_value": "GetTempDir: GetTempPath failed (%u, %u)",
      "str
… [3559 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
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
    "func_name",
    "func_addr",
    "string_value",
    "string_addr"
  ],
  "rows": [
    {
      "func_name": "FUN_00471228",
      "func_addr": "4657704",
      "string_value": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      "string_addr": "4659244"
    },
    {
      "func_name": "FUN_00471228",
      "func_addr": "4657704",
      "string_value": "CurrentMajorVersio
… [1726 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
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
    "content",
    "address",
    "length"
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
    "content",
    "address",
    "length"
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
    "func_name",
    "func_addr",
    "string_value",
    "string_addr"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "audit_path": "/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/audit.
… [8 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: cg.from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: cg.from_func_name"
}
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
      "dst_func_addr": "3988480",
      "dst_func_name": "FUN_003cdc00",
      "call_site": "3942226"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_que
… [213 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
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
… [131488 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_name",
    "src_func_addr",
    "dst_func_name",
    "dst_func_addr"
  ],
  "rows": [
    {
      "src_func_name": "FUN_003c3b98",
      "src_func_addr": "3947416",
      "dst_func_name": "VirtualAlloc",
      "dst_func_addr": "3946892"
    },
    {
      "src_func_name": "sub_0",
      "src_func_addr": "0",
      "dst_func_name": "VirtualAlloc",
      "dst_func_addr
… [1436 more chars]
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
      "content": "InnoSetupLdrWindow",
      "address": "4663376",
      "length": "38"
    },
    {
      "content": "Inno Setup Setup Data (6.7.0)",
      "address": "4680460",
      "length": "30"
    },
    {
      "content": "Inno Setup Messages (6.5.0) (u)",
      "address": "4680524",
      "length": "32"
   
… [3493 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/01-tools-raw.json` exists=`True` bytes=`181670` mtime=`2026-08-08T13:23:16.700193+00:00`
  - sha256: `69e7e9fd5fb3810c86d9caed0c5812e7d1592657764bc877cb0fd62f0f52f015`
- **sql_evidence:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/05-deep-dive.json` exists=`True` bytes=`2805` mtime=`2026-08-08T13:36:23.446012+00:00`
  - sha256: `908ccbe242db414c6541b1a06b3e51d8d9a73fcf92f9f2f799d60b79084ec2f4`

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
  "summary": "Inno Setup installer (v6.7.0) masquerading as 'GML_EDIT_PRO Setup' built with Delphi v36.0. Contains process injection chain (VirtualAlloc+VirtualProtect+CreateProcessW via FUN_00469f74/FUN_0046a1b8), obfuscated stack strings (capa T1027.005), XOR and HC-128 encryption, privilege escalation APIs (AdjustTokenPrivileges/OpenProcessToken), multiple embedded PEs for dropper behavior, and extreme control-flow obfuscation (CC=201 in 1007 bytes). Product metadata is trivially forged and does not establish legitimacy.",
  "key_evidence": [
    "capa: obfuscated stack strings (T1027.005), XOR encoding (T1027), HC-128 encryption, process injection (T1055) via VirtualAlloc+VirtualPr
… [2005 more chars]
```

- **agentic:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`970871` mtime=`2026-08-08T13:36:23.444012+00:00`
  - sha256: `c04515ee98f29b881473020b904c12b3fcffb977a39323a4196ab922cd60bcc3`

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

- **rule_yar:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar` exists=`True` bytes=`2026` mtime=`2026-08-08T13:40:31.283112+00:00`
  - sha256: `c22ab95c8da990740b841009df22ae4120364461ce0717f2ce1ace52e8f62348`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T13:40:31.284552+00:00
rule CADRE_v2_unknown_353ab6827b75 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" ascii wide
        $s1 = "aTEnumerator<System.Generics.Collections.TPair<System.TClass,System.Classes.TFieldsCache.TFields>>(" ascii wide
        $s2 = "aTEnumerable<System.Generics.Collections.TPair<System.TClass,System.Cla
… [1224 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v2.md` exists=`True` bytes=`16119` mtime=`2026-08-08T13:41:50.916820+00:00`
  - sha256: `526a8317087b464fa322af9895d01ee30ea1b72b4808eedc50b619922fd2198a`
- **REPORT_MASTER_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v3.md` exists=`True` bytes=`45595` mtime=`2026-08-08T13:48:28.076090+00:00`
  - sha256: `d5c40a298d768e8c915d84cc9ec0fcb79034a9c15a123be9a406817b2462d302`
- **REPORT_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-v2.md` exists=`True` bytes=`16119` mtime=`2026-08-08T13:41:50.915820+00:00`
  - sha256: `526a8317087b464fa322af9895d01ee30ea1b72b4808eedc50b619922fd2198a`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`74821` mtime=`2026-08-08T13:43:23.908592+00:00`
  - sha256: `4f23dde3748c5cedb55942680e5c06fec1e4a50c0d4768c01b7ac80a823f829d`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`63238` mtime=`2026-08-08T13:49:30.970785+00:00`
  - sha256: `9ce7b4899ff60ed5ebd49cdcd778f06ffd7ecb3072ccf6084698c589e68ac69f`
- **report_v2_json:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/report-v2.json` exists=`True` bytes=`18961` mtime=`2026-08-08T13:43:23.912591+00:00`
  - sha256: `ebf730bcb258e84b8b5b7434bb3a1651faec3b519aefcc4d5d7bc31a9c87bb63`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:41:50 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Trojanized Inno Setup installer
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrativ
… [15208 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 13:48:28 UTC

# RE Report — 353ab6827b75
_Generated 2026-08-08T13:48:28.068230+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=258c | cross_refs=True | llm_ok=True | runtime=24.81s -->

# Executive Summary

The malware sample with SHA-256 hash `353ab6827b750979ba12450e38e73669daa850445d28861f62d27349a32f68c` is assessed as **malicious**, belonging to the **Trojanized Inno Setup installer** family. This verdict is derived from aggregated evidence across multiple analysis engines, with a deep confidence level of **90%** (source: deep_dive_agentic), and high agre
… [44661 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
