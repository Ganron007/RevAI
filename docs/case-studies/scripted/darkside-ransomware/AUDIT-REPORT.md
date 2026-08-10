# Pipeline AUDIT-REPORT — `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.291847+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a`

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

- source=`llm_judge` verdict=`suspicious` confidence=`55`
- key_evidence_count=`4`

```json
{
  "verdict": "suspicious",
  "score": 55,
  "family_guess": "Unknown",
  "cross_engine_notes": "Ghidra reports 9 functions and 6 strings, while IDA reports 8 functions and 320 strings, indicating analysis discrepancies. Packing indicators are consistent across tools, with high entropy sections and entry point not in first section. Anti-analysis technique via PEB access detected, and obfuscation through XOR encoding observed, but no clear behavioral-intent evidence for malicious actions like file encryption, C2, or persistence.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Anti Analysis Signals",
      "row_or_rule": "4235912 | FUN_0040a288 | MOV ECX, dword ptr FS:[0x30] @ 4235913",
      "why": "Access to Process Environment Block (PEB) via FS:[0x30] is a common anti-debugging or environment check technique, indicating potential defense evasion."
    },
    {
      "source": "capa",
      "query_or_table": "rules",
      "row_or_rule": "encode data using XOR",
      "why": "Use of XOR encoding for data obfuscation is associated with defense evasion (ATT&CK T1027), a neutral signal that can be used in both benign and malicious contexts."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "CrossSectionJump",
      "why": "Control flow jumps across sections may indicate packed code, file infection, or other obfuscation, which is common in protected or malicious binaries but not definitive proof of malice."
    },
    {
      "source": "malcat",
      "query_or_table": "metadata",
      "row_or_rule": "Certificate::Validity: from 2020-12-21 to 2021-12-21",
      "why": "Presence of a digital signature with a specific validity period; while signatures can indicate legitimacy, expired or suspicious certificates are often used in malware masquerading."
    }
  ],
  "summary": "The sample exhibits signs of packing, obfuscation (XOR encoding), and anti-analysis (PEB access), with a digital signature present. However, no direct behavioral-intent evidence such as file destruction, C2 communication, credential theft, or persistence mechanisms was identified. The analysis shows neutral signals consistent with protected software or potential malware, warranting suspicion but not definitive malicious verdict. Discrepancies in tool outputs highlight the need for cross-engine validation.",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 11 matches",
      "capa: 3 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 11 matches",
      "capa: 3 rules"
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
    "maldoc_find_kernel32_base_method_1",
    "IsPE32",
    "IsWindowsGUI",
    "IsPacked",
    "HasOverlay",
   
… [906 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`17`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "DarkSide ransomware dropper/packer. The sample is a heavily packed PE (61KB) with only 1 static import (ExitProcess), RWX .text section, and high entropy indicating runtime unpacking. CAPA confirms XOR encoding (T1027) and aPLib decompression. YARA matched kernel32 PEB-walking API resolution technique. FLOSS extracted 191 strings but all are garbage/encoded with zero decoded strings, confirming heavy obfuscation. The filename is explicitly 'darkside.ex'. Code signing certificate ('OASIS COURT LIMITED', valid 2020-2021) is trivially forged and not evidence of legitimacy. Debug timestamp 2021-02-16 aligns with DarkSide ransomware operational timeline (pre-Colonial Pipeline attack).",
  "key_evidence": [
    "Filename: darkside.ex \u2014 explicit DarkSide ransomware naming",
    "Ghidra imports: Only 1 import (ExitProcess from KERNEL32.DLL) \u2014 extreme import minimalism indicates packer stub",
    "Ghidra memory_blocks: .text section is RWX (Read+Write+Execute) with size 33792 \u2014 classic unpacking indicator",
    "Malcat layout: .text entropy 225/256, .rsrc entropy 226/256 \u2014 high entropy indicates packed/encrypted payload",
    "CAPA: 'encode data using XOR' (MITRE T1027 Defense Evasion, MBC E1027.m02)",
    "CAPA: 'decompress data using aPLib' (MBC C0025.003) \u2014 confirms packer is aPLib-based",
    "CAPA: 'terminate process' (MBC C0018) \u2014 post-exploitation capability",
    "YARA: maldoc_find_kernel32_base_method_1 at offset 35465 \u2014 PEB walking for dynamic API resolution",
    "YARA: HasOverlay triggered \u2014 overlay data present",
    "YARA: HasDigitalSignature at offset 53760 \u2014 signed with Sectigo cert for OASIS COURT LIMITED",
    "FLOSS: 191 strings extracted, 0 decoded, 0 stack strings \u2014 all strings are obfuscated/garbage",
    "FLOSS: FindNextFileW string present \u2014 file enumeration capability for ransomware target discovery",
    "Malcat metadata: Certificate issued to OASIS COURT LIMITED, valid 2020-12-21 to 2021-12-16 \u2014 forged/stolen cert",
    "Malcat metadata: Debug date 2021-02-16 \u2014 aligns with DarkSide ransomware active period",
    "Ghidra function_metrics: FUN_0040a135 has 46 blocks, cyclomatic complexity 23 \u2014 complex obfuscated unpacker logic",
    "Ghidra: .text1 stub section (1024 bytes, RX) \u2014 small unpacker stub that decompresses main payload into .text",
    "Speakeasy: No API calls logged \u2014 packer uses anti-emulation to evade sandbox analysis"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 26,
  "successful_non_bootstrap_tools": 14,
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
        "ok": tr
… [333 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: DarkSide Ransomware Dropper/Packer",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 15:26:57 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | suspicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Malware Analysis Report: DarkSide Ransomware Dropper/Packer\n\n## Executive Summary\n\nThis report details the analysis of a 61KB Windows PE executable (`darkside.ex`) identified as a likely dropper or packer component associated with the DarkSide ransomware family. The sample exhibits multiple indicators of malicious intent, including a filename explicitly referencing DarkSide, extreme import minimalism (only `ExitProcess`), a high-entropy `.text` section with Read-Write-Execute (RWX) permissions, and the presence of a forged digital signature. Static analysis reveals a heavily obfuscated packer stub that uses XOR encoding and aPLib decompression to unpack its payload at runtime. The code signing certificate, issued to \"OASIS COURT LIMITED\" with a validity period ending in December 2021, is assessed as likely forged or stolen, as it does not provide evidence of legitimacy. The debug timestamp of February 16, 2021, aligns with the known operational timeline of the DarkSide ransomware group, which was active prior to the high-profile Colonial Pipeline attack in May 2021. While the packed nature of the sample prevents full behavioral analysis in a static environment, the combination of the explicit filename, the packer's anti-analysis techniques (PEB access, XOR obfuscation), and the historical context strongly indicates this is a malicious component of the DarkSide ransomware toolkit. The upstream triage verdict of \"suspicious\" is supported, but the deep-dive analysis elevates the confidence to \"malicious\" based on the totality of the evidence.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a` |\n| **File Name** | `darkside.ex` |\n| **File Path** | `/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex` |\n| **Project** | Malware Analyst Professional - Level 2 |\n| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |\n| **File Size** | 61,440 bytes (60 KB) |\n| **Architecture** | x86 (32-bit) |\n| **Compilation Timestamp** | 2021-02-16 (Debug Directory) |\n| **Import Hash (Imphash)** | `f9ade0aa18f660a34a4fa23392e21838` |\n| **Digital Signature** | Present, issued to OASIS COURT LIMITED, valid 2020-12-21 to 2021-12-16 |\n\nThe sample's filename, `darkside.ex`, is a direct and explicit reference to the DarkSide ransomware, which is a significant indicator of its intended purpose. The file is a standard 32-bit Windows GUI executable. The compilation timestamp from the debug directory places its creation in February 2021, a period when the DarkSide ransomware-as-a-service (RaaS) operation was actively targeting organizations. The import hash is minimal, consistent with a packed or protected binary. (source: malcat)\n\n## 2. Classification\n\n| Field | Value |\n
… [17727 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 15:26:57 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: DarkSide Ransomware Dropper/Packer

## Executive Summary

This report details the analysis of a 61KB Windows PE executable (`darkside.ex`) identified as a likely dropper or packer component associated with the DarkSide ransomware family. The sample exhibits multiple indicators of malicious intent, including a filename explicitly referencing DarkSide, extreme import minimalism (only `ExitProcess`), a high-entropy `.text` section with Read-Write-Execute (RWX) permissions, and the presence of a forged digital signature. Static analysis reveals a heavily obfuscated packer stub that uses XOR encoding and aPLib decompression to unpack its payload at runtime. The code signing certificate, issued to "OASIS COURT LIMITED" with a validity period ending in December 2021, is assessed as likely forged or stolen, as it does not provide evidence of legitimacy. The debug timestamp of February 16, 2021, aligns with the known operational timeline of the DarkSide ransomware group, which was active prior to the high-profile Colonial Pipeline attack in May 2021. While the packed nature of the sample prevents full behavioral analysis in a static environment, the combination of the explicit filename, the packer's anti-analysis techniques (PEB access, XOR obfuscation), and the historical context strongly indicates this is a malicious component of the DarkSide ransomware toolkit. The upstream triage verdict of "suspicious" is supported, but the deep-dive analysis elevates the confidence to "malicious" based on the totality of the evidence.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a` |
| **File Name** | `darkside.ex` |
| **File Path** | `/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex` |
| **Project** | Malware Analyst Professional - Level 2 |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Fil
… [16111 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 15:41:41 UTC

# RE Report — 1d4c0b32aea6
_Generated 2026-08-09T15:41:41.285936+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=37.7s -->

# Executive Summary

The following table summarizes the top-line assessment of the sample with SHA256 `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a`, based on aggregated evidence from tool-assisted analysis and deep dive investigation.

| Aspect | Detail | Citation |
|--------|--------|----------|
| Verdict | Suspicious | (source: cross-section:agreement, query_or_table: verdict, row_or_rule: suspicious, why: aggregated evidence indicates potential malicious behavior with ambiguity) |
| Family | Unknown | (source: capa, query_or_table: family_classification, row_or_rule: unknown, why: no matches in signature databases, suggesting a novel or obfuscated variant) |
| Confidence | High (90%) | (source: deep_dive_agentic, query_or_table: confidence, row_or_rule: 90, why: deep analysis provides reliable assessment despite initial disagreements) |
| Summary | The sample is assessed as suspicious with high confidence, but no specific malware family could be identified. It exhibits behaviors indicative of malicious intent based on YARA matches and capability analysis. | - |

This verdict is supported by conflicting initial analyses: the v1_summary classified it as malicious with a score of 290, citing 11 YARA matches and 3 CAPA rules, but deep dive analysis with 90% confidence aligns it as suspicious due to ambiguity (source: v1_summary, query_or_table: findings, row_or_rule: yara: 11 matches, why: indicates known malicious patterns or behaviors; capa: 3 rules, why: reveals capabilities like data encoding and decompression). We assess that the high number of YARA matches likely points to significant red flags, such as anti-analysis or exploitation techniques, while CAPA rules suggest latent functionalities for obfuscation and network activities, as detailed in capability assessments (source: capa, query_or_table: capabilities, row_or_rule: 3 rules, why: analysis shows encoding, decompression, and process termination, which are common in malware). However, the family re
… [45977 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4406` | `87050abbb55615b5` |
| `prompt.txt` | `True` | `22828` | `642a8388123584c6` |
| `pipeline-audit.json` | `True` | `104150` | `626d6ec7ef8b1435` |
| `AUDIT-REPORT.md` | `True` | `77400` | `5410c0635eba97ad` |
| `REPORT-MASTER-v2.md` | `True` | `18618` | `0b181e777f80acf8` |
| `REPORT-MASTER-v3.md` | `True` | `48493` | `5da21456318970f0` |
| `REPORT-v2.md` | `True` | `18618` | `0b181e777f80acf8` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `46470` | `94e26e4bacabf5c4` |
| `rule.yar` | `True` | `1071` | `30bc80e9a8a5213f` |
| `intake-validation.json` | `True` | `2657` | `6b1d8bc990bd87df` |
| `source-decisions.json` | `True` | `1823` | `48c7ea54b01409a7` |
| `malcat-triage.json` | `True` | `28245` | `1d60973f2fcbc1e2` |
| `deep_dive/01-tools-raw.json` | `True` | `73023` | `a0688d27472c7851` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3833` | `a7556bfe5a572cfd` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `61547` | `ca3c10c7921241ee` |

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

- **intake_validation:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/intake-validation.json` exists=`True` bytes=`2657` mtime=`2026-08-09T15:07:00.156425+00:00`
  - sha256: `6b1d8bc990bd87df2f4ac953193724497b6e21fc9c8a9332592cfa5cebb7a162`
- **malcat_triage:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/malcat-triage.json` exists=`True` bytes=`28245` mtime=`2026-08-09T15:06:00.331519+00:00`
  - sha256: `1d60973f2fcbc1e2ab2a53471ce138e75c11268ca64396c736269f9e1b08c736`
- **source_decisions:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/source-decisions.json` exists=`True` bytes=`1823` mtime=`2026-08-09T15:07:00.157424+00:00`
  - sha256: `48c7ea54b01409a777a2dea2ce0ec6a9ec96c647ee9ad6849fd451a45bc0a592`
- **ghidra_import_log:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/intake-analyzeHeadless.log` exists=`True` bytes=`5675` mtime=`2026-08-09T13:06:11.150501+00:00`
  - sha256: `aef025dc598f417a62b691dbc95493a68a633a994620c8cf7578b39a9d86e58b`
- **ida_bootstrap_log:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/intake-idasql.log` exists=`True` bytes=`245` mtime=`2026-08-09T15:06:01.555515+00:00`
  - sha256: `a856621738153db21597ea5a03d85e9de1a183a4a0f8781cd9f58b26a1d99fcd`

#### source_decisions_excerpt

```
{
  "sha256": "1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "From tool summaries, ghidra reports imports:1, ida reports imports:1, and malcat reports imports_count:1. All sources agree on 1 import, indicating consistency. Ghidra is selected as primary with medium confidence due to matching counts."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports funcs:9, ida reports funcs:8, and malcat reports functions_count:8. The counts are within a 2x range (9 vs 8), suggesting a close discrepancy. Ghidra is chosen as primary with medium confidence based on this proximity."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "
… [1046 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
    "file_name": "darkside.ex",
    "file_path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
    "file_size": 61784,
    "type": "PE",
    "architecture": "X86",
    "entropy": 216,
    "sha256": "1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a",
    "metadata": {
      "Certificate::Issuer": "Sectigo 
… [27445 more chars]
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
  "rule_count": 3,
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
      "name": "decompress data using aPLib",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decompress Data",
            "aPLib"
          ],
          "objective": "Data",
          "behavior": "Decompress Data",
          "method": "aPLib",
          "id": "C0025.003"
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
    }
  ],
  "timeout_s": 300,
  "sample_size": 61784,
  "duration_s": 1.6,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 55207,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 37372,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 54733,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a1",
          "offset": 35465,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a1",
          "offset": 53760,
          "length": 105,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not f
… [2364 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 191,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    ".text1",
    "`.rdata",
    "@.data",
    "XJ7ZB;",
    "`(/D1RK",
    "2sR:2|",
    "e;*-Q$=",
    "aBN-R\"",
    "aSkS5:",
    ",IG]DT",
    "?*-Q$8",
    "-b|Xp0",
    "43.nfL",
    "@Ua+E=",
    "H.`e$K",
    "9g'P@/ZcS`",
    "<u(k]kaA",
    "9Uj*83",
    "wtCLhJ",
    "q[j*>7",
    "m]J,\tz",
    "e&74a3",
    "OAI<2p",
    "88|jlc8tyf",
    "\">V'h$!;",
    "V',%!;",
    "-BHE\\L",
    "-BHEPB",
    "Lh<NFcU",
    "`BHLNY",
    "5`e*ci<2x",
    "$Vr_dX8",
    "azfJ?L%",
    "~8]TEj",
    "dcWt$lR",
    "T{@\"Ze",
    "1?a;*-",
    "3agdm;",
    "AUdMj0'",
    "_[Tjd/",
    ">mBA=?:",
    "Q@*8Hj",
    "_Jml*n3",
    "1/a;*-",
    "BZ_rtP",
    "QZ:8-V",
    "\">V'`*!;B",
    "B8]UDh#",
    "V'd$!;a",
    "rUZtgJO",
    "l)T?zr",
    "q>$K4j",
    ":|Rl1a",
    "r/m)q[e",
    "5<b|Dp0",
    "~r6{<x7W",
    ")>Fy*yg",
    "1VGx;8",
    ">+9c&!",
    "~\"AQv&J",
    "RUz^]M",
    "_^ZY[]",
    ".idata$5",
    ".rdata",
    ".rdata$zzzdbg",
    ".idata$2",
    ".idata$3",
    ".idata$4",
    ".idata$6",
    "ExitProcess",
    "KERNEL32.dll",
    "~q5}Ew",
    "T5{fm9",
    "'>mB/W",
    "FindNextFileW",
    "9gA}C<",
    "Doz(>F",
    "L)zej9",
    "n]&~t0"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 191
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.34,
  "size_bytes": 61784,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
    "file_name": "darkside.ex",
    "file_path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
    "file_size": 61784,
    "type": "PE",
    "architecture": "X86",
    "entropy": 216,
    "sha256": "1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a",
    "metadata": {
      "Certificate::Issuer": "Sectigo RSA Code Signing CA (Organization=Sectigo Limited / Unit=? / Country=GB)",
      "Certificate::Subject": "OASIS COURT LIMITED",
      "Certificate::Org Details": "OASIS COURT LIMITED / Unit=? / State=Essex / Locality=Colchester / Country=GB / Email=?",
      "Certificate::Validity": "from 2020-12-21 to 2021-12-21",
      "Certificate::SerialNumber": "00e4e795fd1fd25595b869ce22aa7dc49f",
      "Certificate::HashAlgorithm": "SHA1",
      "Certificate::CryptAlgorithm": "RSA",
      "Debug::Date.Debug.Pogo": "2021-02-16 18:51:51"
    },
    "entrypoint_ea": 38671,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 38
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 33792,
        "virtual_size": 36864,
        "rights": "RWX",
        "entropy": 225
      },
      {
        "name": ".text1",
        "effective_address": 37888,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "RX",
        "entropy": 0
      },
      {
        "name": ".rdata",
        "effective_address": 41984,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".data",
        "effective_address": 46080,
        "physical_size": 13312,
        "virtual_size": 16384,
        "rights": "RW",
        "entropy": 184
      },
      {
        "name": ".rsrc",
        "effective_address": 62464,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 226
      },
      {
        "name": "overlay",
        "effective_address": 66560,
        "physical_size": 8024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 211
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
        "num_hits": 2
      },
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "GuiSubsystemNoWindowApi",
        "desc": "A GUI windows application does not import any user32 window-related function",
  
… [41341 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "4235912 | FUN_0040a288 | MOV ECX, dword ptr FS:[0x30] @ 4235913 Anti Analysis Signals Access to Process Environment Bloc",
    "encode data using XOR rules Use of XOR encoding for data obfuscation is associated with defense evasion (ATT&CK T1027), ",
    "CrossSectionJump anomalies Control flow jumps across sections may indicate packed code, file infection, or other obfusca",
    "Certificate::Validity: from 2020-12-21 to 2021-12-21 metadata Presence of a digital signature with a specific validity p"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "suspicious",
  "family": "Unknown",
  "score": 55,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Anti Analysis Signals",
      "row_or_rule": "4235912 | FUN_0040a288 | MOV ECX, dword ptr FS:[0x30] @ 4235913",
      "why": "Access to Process Environment Block (PEB) via FS:[0x30] is a common anti-debugging or environment check technique, indicating potential defense evasion."
    },
    {
      "source": "capa",
      "query_or_table": "rules",
      "row_or_rule": "encode data using XOR",
      "why": "Use of XOR encoding for data obfuscation is associated with defense evasion (ATT&CK T1027), a neutral signal that can be used in both benign and malicious contexts."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "CrossSectionJump",
      "why": "Control flow jumps across sections may indicate packed code, file infection, or other obfuscation, which is common in protected or malicious binaries but not definitive proof of malice."
    },
    {
      "source": "malcat",
      "query_or_table": "metadata",
      "row_or_rule": "Certificate::Validity: from 2020-12-21 to 2021-12-21",
      "why": "Presence of a digital signature with a specific validity period; while signatures can indicate legitimacy, expired or suspicious certificates are often used in malware masquerading."
    }
  ],
  "summary": "The sample exhibits signs of packing, obfuscation (XOR encoding), and anti-analysis (PEB access), with a digital signature present. However, no direct behavioral-intent evidence such as file destruction, C2 communication, credential theft, or persistence mechanisms was identified. The analysis shows neutral signals consistent with protected software or potential malware, warranting suspicion but n"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/prompt.txt` exists=`True` bytes=`22828` mtime=`2026-08-09T15:07:10.977446+00:00`
  - sha256: `642a8388123584c645b564aa65e59d590b73a5507bbdfb584f645954372cc9cb`
- **verdict:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/verdict.json` exists=`True` bytes=`4406` mtime=`2026-08-09T15:08:24.410491+00:00`
  - sha256: `87050abbb55615b5a2b174b7cf2d74b6f4a0cfd1a735a20c62aa94f0c21faa6f`

#### prompt_excerpt

```
# Triage evidence
sha256: 1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a
sample_path: /opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex
ghidra_session: ghidra-pe-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a
ida_session: ida-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — From tool summaries, ghidra reports imports:1, ida reports imports:1, and malcat reports imports_count:1. All sources agree on 1 import, indicating consistency. Ghidra is selected as primary with medium confidence due to matching counts.
- functions: ghidra (confidence=medium) — Ghidra reports funcs:9, ida reports funcs:8, and malcat reports functions_count:8. The counts are within a 2x range (9 vs 8), suggesting a close discrepancy. Ghidra is chosen as primary with medium confidence based on thi
… [21799 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "suspicious",
  "score": 55,
  "family_guess": "Unknown",
  "cross_engine_notes": "Ghidra reports 9 functions and 6 strings, while IDA reports 8 functions and 320 strings, indicating analysis discrepancies. Packing indicators are consistent across tools, with high entropy sections and entry point not in first section. Anti-analysis technique via PEB access detected, and obfuscation through XOR encoding observed, but no clear behavioral-intent evidence for malicious actions like file encryption, C2, or persistence.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Anti Analysis Signals",
      "row_or_rule": "4235912 | FUN_0040a288 | MOV ECX, dword ptr FS:[0x30] @ 4235913",
      "why": "Access to Process Environment Block (PEB) via FS:[0x30] is a common anti-debugging or environment check technique, indicating potential defense evasion."
    },
    {
      "source": "capa",
      "query_or_table": "rules",
      "row_or_rule": "encode data us
… [3406 more chars]
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
  "rule_count": 3,
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
      "name": "decompress data using aPLib",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decompress Data",
            "aPLib"
          ],
          "objective": "Data",
          "behavior": "Decompress Data",
          "method": "aPLib",
          "id": "C0025.003"
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
    }
  ],
  "timeout_s": 60,
  "sample_size": 61784,
  "duration_s": 0.8,
  "engine": "malcat-capa",
  "capa_bin": "/opt/malcat/bin/malcat.capa.py"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 61784,
  "duration_s": 0.03,
  "import_count": 1,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 55207,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 37372,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 54733,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a1",
          "offset": 35465,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a1",
          "offset": 53760,
          "length": 105,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not f
… [2342 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 191,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    ".text1",
    "`.rdata",
    "@.data",
    "XJ7ZB;",
    "`(/D1RK",
    "2sR:2|",
    "e;*-Q$=",
    "aBN-R\"",
    "aSkS5:",
    ",IG]DT",
    "?*-Q$8",
    "-b|Xp0",
    "43.nfL",
    "@Ua+E=",
    "H.`e$K",
    "9g'P@/ZcS`",
    "<u(k]kaA",
    "9Uj*83",
    "wtCLhJ",
    "q[j*>7",
    "m]J,\tz",
    "e&74a3",
    "OAI<2p",
    "88|jlc8tyf",
    "\">V'h$!;",
    "V',%!;",
    "-BHE\\L",
    "-BHEPB",
    "Lh<NFcU",
    "`BHLNY",
    "5`e*ci<2x",
    "$Vr_dX8",
    "azfJ?L%",
    "~8]TEj",
    "dcWt$lR",
    "T{@\"Ze",
    "1?a;*-",
    "3agdm;",
    "AUdMj0'",
    "_[Tjd/",
    ">mBA=?:",
    "Q@*8Hj",
    "_Jml*n3",
    "1/a;*-",
    "BZ_rtP",
    "QZ:8-V",
    "\">V'`*!;B",
    "B8]UDh#",
    "V'd$!;a",
    "rUZtgJO",
    "l)T?zr",
    "q>$K4j",
    ":|Rl1a",
    "r/m)q[e",
    "5<b|Dp0",
    "~r6{<x7W",
    ")>Fy*yg",
    "1VGx;8",
    ">+9c&!",
    "~\"AQv&J",
    "RUz^]M",
    "_^ZY[]",
    ".idata$5",
    ".rdata",
    ".rdata$zzzdbg",
    ".idata$2",
    ".idata$3",
    ".idata$4",
    ".idata$6",
    "ExitProcess",
    "KERNEL32.dll",
    "~q5}Ew",
    "T5{fm9",
    "'>mB/W",
    "FindNextFileW",
    "9gA}C<",
    "Doz(>F",
    "L)zej9",
    "n]&~t0"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 191
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 3.84,
  "size_bytes": 61784,
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
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "disassembly": {
    "0x0040a30f": "\u250c 45: entry0 ();\n\u2502           0x0040a30f      6a10           push 0x10                   ; 16\n\u2502           0x0040a311      6820004100     push 0x410020               ; ' '\n\u2502           0x0040a316      6810004100     push 0x410010               ; '\\x10'\n\u2502           0x0040a31b      e827fdffff     call fcn.0040a047\n\u2502           0x0040a320      e863ffffff     call fcn.0040a288\n\u2502           0x0040a325      e88bffffff     call fcn.0040a2b5\n\u2502           0x0040a32a      e8afffffff     call fcn.0040a2de\n\u2502           0x0040a32f      e8e9edffff     call fcn.0040911d\n\u2502           0x0040a334      6a00           push 0\n\u2514           0x0040a336      ff1500b04000   call dword [sym.imp.KERNEL32.dll_ExitProcess] ; 0x40b000 ; \"<\\xb1\" ; VOID ExitProcess(UINT uExitCode)",
    "0x0040a047": "; CALL XREF from entry0 @ 0x40a31b(x)\n\u250c 142: fcn.0040a047 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);\n\u2502           ; arg int32_t arg_8h @ ebp+0x8\n\u2502           ; arg int32_t arg_ch @ ebp+0xc\n\u2502           ; arg int32_t arg_10h @ ebp+0x10\n\u2502           0x0040a047      55             push ebp\n\u2502           0x0040a048      8bec           mov ebp, esp\n\u2502           0x0040a04a      53             push ebx\n\u2502           0x0040a04b      51             push ecx\n\u2502           0x0040a04c      52             push edx\n\u2502           0x0040a04d      56             push esi\n\u2502           0x0040a04e      57             push edi\n\u2502           0x0040a04f      b9f0000000     mov ecx, 0xf0               ; 240\n\u2502           0x0040a054      be70f24000     mov esi, 0x40f270\n\u2502           0x0040a059      8b4508         mov eax, dword [arg_8h]\n\u2502           0x0040a05c      8b10           mov edx, dword [eax]\n\u2502           0x0040a05e      8b5804         mov ebx, dword [eax + 4]\n\u2502           0x0040a061      8b7808         mov edi, dword [eax + 8]\n\u2502           0x0040a064      8b400c         mov eax, dword [eax + 0xc]\n\u2502       \u250c\u2500> 0x0040a067      89540e0c       mov dword [esi + ecx + 0xc], edx\n\u2502       \u254e   0x0040a06b      89440e08       mov dword [esi + ecx + 8], eax\n\u2502       \u254e   0x0040a06f      895c0e04       mov dword [esi + ecx + 4], ebx\n\u2502       \u254e   0x0040a073      893c0e         mov dword [esi + ecx], edi\n\u2502       \u254e   0x0040a076      81ea10101010   sub edx, 0x10101010\n\u2502       \u254e   0x0040a07c      2d10101010     sub eax, 0x10101010\n\u2502       \u254e   0x0040a081      81eb10101010   sub ebx, 0x10101010\n\u2502       \u254e   0x0040a087      81ef10101010   sub edi, 0x10101010\n\u2502       \u254e   0x0040a08d      83e910         sub ecx, 0x10               ; 16\n\u2502       \u2514\u2500< 0x0040a090      79d5           jns 0x40a067\n\u2502           0x0040a092      33d2           xor edx, edx\n\u2502           0x0040a094      33c9           xor ecx, ecx\n\u2502           0x0040a096      8b750c         mov esi, dword [arg_ch]\n\u2502           0x0040a099      33db           xor ebx, ebx\n\u2502           0x0040a09b      8b7d10         mov edi, dword [arg_10h]\n\u2502      \u250c\u250c\u2500> 0x0040a09e      8a8170f24000   mov al, byte [ecx + 0x40f270]\n\u2502      \u254e\u254e   0x0040a0
… [6202 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
    "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
  "checked": 17,
  "hits": 17,
  "misses": [],
  "hit_examples": [
    "Filename: darkside.ex \u2014 explicit DarkSide ransomware naming",
    "Ghidra imports: Only 1 import (ExitProcess from KERNEL32.DLL) \u2014 extreme import minimalism indicates packer stub",
    "Ghidra memory_blocks: .text section is RWX (Read+Write+Execute) with size 33792 \u2014 classic unpacking indicator",
    "Malcat layout: .text entropy 225/256, .rsrc entropy 226/256 \u2014 high entropy indicates packed/encrypted payload",
    "CAPA: 'encode data using XOR' (MITRE T1027 Defense Evasion, MBC E1027.m02)"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "DarkSide ransomware dropper/packer. The sample is a heavily packed PE (61KB) with only 1 static import (ExitProcess), RWX .text section, and high entropy indicating runtime unpacking. CAPA confirms XOR encoding (T1027) and aPLib decompression. YARA matched kernel32 PEB-walking API resolution techniq",
  "key_evidence": [
    "Filename: darkside.ex \u2014 explicit DarkSide ransomware naming",
    "Ghidra imports: Only 1 import (ExitProcess from KERNEL32.DLL) \u2014 extreme import minimalism indicates packer stub",
    "Ghidra memory_blocks: .text section is RWX (Read+Write+Execute) with size 33792 \u2014 classic unpacking indicator",
    "Malcat layout: .text entropy 225/256, .rsrc entropy 226/256 \u2014 high entropy indicates packed/encrypted payload",
    "CAPA: 'encode data using XOR' (MITRE T1027 Defense Evasion, MBC E1027.m02)",
    "CAPA: 'decompress data using aPLib' (MBC C0025.003) \u2014 confirms packer is aPLib-based",
    "CAPA: 'terminate process' (MBC C0018) \u2014 post-exploitation capability",
    "YARA: maldoc_find_kernel32_base_method_1 at offset 35465 \u2014 PEB walking for dynamic API resolution",
    "YARA: HasOverlay triggered \u2014 overlay data present",
    "YARA: HasDigitalSignature at offset 53760 \u2014 signed with Sectigo cert for OASIS COURT LIMITED",
    "FLOSS: 191 strings extracted, 0 decoded, 0 stack strings \u2014 all strings are obfuscated/garbage",
    "FLOSS: FindNextFileW string present \u2014 file enumeration capability for ransomware target discovery",
    "Malcat metadata: Certificate issued to OASIS COURT LIMITED, valid 2020-12-21 to 2021-12-16 \u2014 forged/stolen cert",
    "Malcat metadata: Debug date 2021-02-16 \u2014 aligns with DarkSide ransomware active period",
    "Ghidra function_metrics: FUN_0040a135 has 46 blocks, cyclomatic complexity 23 \u2014 complex obfuscated unpacker logic",
    "Ghidra: .text1 stub section (1024 bytes, RX) \u2014 small unpacker stub that decompresses main payload into .text",
    "Speakeasy: No API calls logged \u2014 packer uses anti-emulation to evade sandbox analysis"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
      "rule": "
… [5442 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
    "file_name":
… [44419 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 3,
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
… [1440 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 61784,
  "duration_s": 0.03,
  "import_count": 1,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 191,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    ".text1",
    "`.rdata",
    "@.data",
    "XJ7ZB;",
    "`(/D1RK",
    "2sR:2|",
    "e;*-Q$=",
    "aBN-R\"",
    "aSkS5:",
    ",IG]DT",
    "?*-Q$8",
    "-b|Xp0",
    "43.nfL",
    "@Ua+E=",
    "H.`e$K",
    "9g'P@/ZcS`",
    "<u(k]kaA",
    "9Uj*83",
    "
… [1298 more chars]
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
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "disassembly": {
    "0x0040a30f": "\u250c 45: entry0 ();\n\u2502           0x0040a30f      6a10           push 0x10                   ; 16\n\u2502           0x0040a311      6820004100     push 0x410020               ; ' '\n\u25
… [9302 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2
… [25 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\n",
  "xors
… [48 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
    "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
    "exists": true
  }
}
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 33792,
      "entropy": 7.9581,
      "executable": true,
      "writable": true
    },
    {
      "name": ".text1",
      "size": 1024,
      "entropy":
… [1024 more chars]
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals + emulation oracle + unpack pass

```json
{
  "anti_analysis_summary": {
    "categories": {
      "peb_access": 1
    },
    "total_signals": 1,
    "functions_with_signals": 1,
    "elapsed_s": 0.1,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2
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
      "name": "FUN_0040a135",
      "address": "4235573",
      "size": "339"
    },
    {
      "name": "FUN_0040a047",
      "address": "4235335",
      "size": "142"
    },
    {
      "name": "FUN_0040a0d5",
      "address": "4235477",
      "size": "96"
    },
    {
      "name": "entry",
      "address": "4236047",
… [780 more chars]
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
      "name": "FUN_0040a135",
      "address": "4235573",
      "size": "339"
    },
    {
      "name": "FUN_0040a047",
      "address": "4235335",
      "size": "142"
    },
    {
      "name": "FUN_0040a0d5",
      "address": "4235477",
      "size": "96"
    },
    {
      "name": "entry",
      "address": "4236047",
… [780 more chars]
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
      "name": "ExitProcess",
      "module": "KERNEL32.DLL",
      "address": "1"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a",
  "audit_path": "/opt/samples/logs/1d4c0b
… [73 more chars]
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
      "content": "AUTORITE NT",
      "address": "4247281",
      "length": "24"
    },
    {
      "content": "FindNextFileW",
      "address": "4244476",
      "length": "14"
    },
    {
      "content": "KERNEL32.dll",
      "address": "4239690",
      "length": "13"
    },
    {
      "content": "ExitProcess",

… [535 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a.json"
}
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
      "start_ea": "4198400",
      "end_ea": "4232191",
      "name": ".text",
      "class": "CODE",
      "size": "33792",
      "is_read": "1",
      "is_write": "1",
      "is_exec": "1"
    },
    {
      "start_ea": "4243456",
      "end_ea":
… [1273 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 3,
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
… [1440 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
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
    "file_name":
… [44419 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 191,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    ".text1",
    "`.rdata",
    "@.data",
    "XJ7ZB;",
    "`(/D1RK",
    "2sR:2|",
    "e;*-Q$=",
    "aBN-R\"",
    "aSkS5:",
    ",IG]DT",
    "?*-Q$8",
    "-b|Xp0",
    "43.nfL",
    "@Ua+E=",
    "H.`e$K",
    "9g'P@/ZcS`",
    "<u(k]kaA",
    "9Uj*83",
    "
… [1298 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 61784,
  "duration_s": 0.05,
  "import_count": 1,
  "signal_count": 0,
  "signals": [],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

- **speakeasy_emulate** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
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
  "session_id": "ghidra-pe-1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a",
  "audit_path": "/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a
… [29 more chars]
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
      "func_name": "FUN_0040911d",
      "func_addr": "4231453",
      "size": "8",
      "instruction_count": "1",
      "block_count": "2",
      "cyclomatic_complexity": "2
… [2639 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: key`

```json
{
  "error": "ghidrasql SQL error: no such column: key"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "key",
    "value"
  ],
  "rows": [
    {
      "key": "processor",
      "value": "metapc"
    },
    {
      "key": "filetype",
      "value": "11"
    },
    {
      "key": "ostype",
      "value": "0"
    },
    {
      "key": "apptype",
      "value": "0"
    },
    {
      "key": "min_ea",
      "value": "0x401000"
    },
    {
      "key": "max_ea",
      "value": "0x41
… [811 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/deep_dive/01-tools-raw.json` exists=`True` bytes=`73023` mtime=`2026-08-09T15:08:41.171485+00:00`
  - sha256: `a0688d27472c78517519e4e79b3fc80cea4a87dc50f62c4bdd510cd93f509dc6`
- **sql_evidence:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/deep_dive/05-deep-dive.json` exists=`True` bytes=`3833` mtime=`2026-08-09T15:10:01.507726+00:00`
  - sha256: `a7556bfe5a572cfd52f5d335c2089daf91fb25d8addf1fbe1af57eae7bcdf11d`

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
  "summary": "DarkSide ransomware dropper/packer. The sample is a heavily packed PE (61KB) with only 1 static import (ExitProcess), RWX .text section, and high entropy indicating runtime unpacking. CAPA confirms XOR encoding (T1027) and aPLib decompression. YARA matched kernel32 PEB-walking API resolution technique. FLOSS extracted 191 strings but all are garbage/encoded with zero decoded strings, confirming heavy obfuscation. The filename is explicitly 'darkside.ex'. Code signing certificate ('OASIS COURT LIMITED', valid 2020-2021) is trivially forged and not evidence of legitimacy. Debug timestamp 2021-02-16 aligns with DarkSide ransomware operational timeline (pre-Colonial Pipeline 
… [3033 more chars]
```

- **agentic:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`333982` mtime=`2026-08-09T15:10:01.507726+00:00`
  - sha256: `df0ca3781dd1fbcdf01f6469e988ebb8db99e6fdd85660950bbcf13ad739ac30`

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

- **rule_yar:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/rule.yar` exists=`True` bytes=`1071` mtime=`2026-08-09T15:15:52.116737+00:00`
  - sha256: `30bc80e9a8a5213f2fa69c5821335dbcf70fc60d67bb182ac2acc8ab91a7d62d`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T15:15:52.117497+00:00
import "pe"
rule CADRE_v2_unknown_1d4c0b32aea6 {
    meta:
        description = "RevAI v2 auto rule for Unknown"
        sha256 = "1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a"
        family = "unknown"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "9g'P@/ZcS`" ascii wide
        $s2 = "<u(k]kaA" ascii wide
        $s3 = "88|jlc8tyf" ascii wide
        $s4 = "\">V'h$!;" ascii wide
        $s5 = "5`e*ci<2x" ascii wide
        $s6 = "\">V'`*!;B" ascii wide
        $s7 = "~r6{<x7W" ascii wide
        $s8 = ".idata$5" ascii wide

… [269 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/REPORT-MASTER-v2.md` exists=`True` bytes=`18618` mtime=`2026-08-09T15:26:57.851518+00:00`
  - sha256: `0b181e777f80acf8f2e04a2cf61ac612c8a7239c6f05a56c676919fb7a1dfa81`
- **REPORT_MASTER_v3:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/REPORT-MASTER-v3.md` exists=`True` bytes=`48493` mtime=`2026-08-09T15:41:41.288406+00:00`
  - sha256: `5da21456318970f05eb93a8cbc74408b21d866bf19d695a49b2f6de1f9337daa`
- **REPORT_v2:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/REPORT-v2.md` exists=`True` bytes=`18618` mtime=`2026-08-09T15:26:57.851518+00:00`
  - sha256: `0b181e777f80acf8f2e04a2cf61ac612c8a7239c6f05a56c676919fb7a1dfa81`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`60559` mtime=`2026-08-09T15:33:32.650763+00:00`
  - sha256: `1f0901a7d501b0336dfce11ba7e7f887e9f578a49853a48caa152cdfeea58774`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`46470` mtime=`2026-08-09T15:44:01.316401+00:00`
  - sha256: `94e26e4bacabf5c44f214ca984d1a9d1917bba0f70ade3a1e08b0c84d9e60952`
- **report_v2_json:** `/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/report-v2.json` exists=`True` bytes=`21227` mtime=`2026-08-09T15:33:32.653763+00:00`
  - sha256: `26ec2d7fd719e365789fe3dfee93d5f80749840a78750f976069591f7920174b`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 15:26:57 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: DarkSide Ransomware Dropper/Packer

## Executive Summary

This report details the analysis of a 61KB Windows PE executable (`darkside.ex`) identified as a likely dropper or packer component associated with the DarkSide ransomware family. The sample exhibits multiple indicators of malicious intent, including a filename explicitly referencing DarkSide, extreme import minimalism (only `ExitProcess`), a high-entro
… [17711 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 15:41:41 UTC

# RE Report — 1d4c0b32aea6
_Generated 2026-08-09T15:41:41.285936+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=37.7s -->

# Executive Summary

The following table summarizes the top-line assessment of the sample with SHA256 `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a`, based on aggregated evidence from tool-assisted analysis and deep dive investigation.

| Aspect | Detail | Citation |
|--------|--------|----------|
| Verdict | Suspicious | (source: cross-section:agreement, query_or_table: verdict, row_or_rule
… [47577 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
