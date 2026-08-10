# Pipeline AUDIT-REPORT — `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.908823+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:25 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77`

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

- source=`llm_judge` verdict=`malicious` confidence=`85`
- key_evidence_count=`4`

```json
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Sunburst",
  "cross_engine_notes": "Ghidra identifies 2862 functions and 9997 strings, including references to SolarWinds components and cryptographic APIs. IDA confirms similar structure with 3338 functions. MalCat shows anomalies such as DotnetCryptoApiUsage and SpaghettiFunction, suggesting obfuscation. Capa rules indicate behaviors like file discovery, registry modification, and anti-VM detection. YARA matches include 'escalate_priv' and 'win_token', indicating privilege escalation and token manipulation attempts, which are behavioral indicators of malicious activity. The file is signed as a legitimate SolarWinds Orion component, which in the context of known supply chain attacks, aligns with the Sunburst backdoor.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv",
      "why": "YARA rule match indicates attempts at privilege escalation, a clear behavioral signal for malicious software."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "win_token",
      "why": "YARA rule match for token manipulation, often used in attacks for impersonation or elevating privileges."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1112 Modify Registry",
      "why": "Capability to delete or modify registry values, which can be used for persistence or disabling security features."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "metadata",
      "why": "The file metadata shows it is signed as SolarWinds Orion.Core.BusinessLayer, a component known to be targeted in the Sunburst supply chain attack, increasing suspicion."
    }
  ],
  "summary": "The sample exhibits multiple behavioral indicators of malicious activity, including privilege escalation and token manipulation, and is associated with the Sunburst backdoor due to its SolarWinds branding and attack techniques.",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 17 matches",
      "capa: 58 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "dotnet",
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
    "VMWare_Detection",
    "NETDLLMicrosoft",
    "IsPE32",
    "IsNET_DLL",
    "IsDLL",
    "IsConsole",
    "HasOverlay",
    "HasDebugData",
    "vmdetect",
    "network_tcp_listen",
    "network_dns",
    "escalate_priv",
    "win_token"
  ],
  "engine_citation_corrections": {
    "corrected": 0,
    "corrections": []
  },
  "citation_grounding": {
    "ok": true,
    "checked": 4,
    "hits": 4,
    "misses": [],
    "hit_examples": [
      "escalate_priv matches YARA rule match indicates attempts at privilege escalation, a clear behavioral signal for maliciou",
      "win_token matches YARA
… [502 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`18`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is the SUNBURST/Solorigate backdoor \u2014 the trojanized SolarWinds.Orion.Core.BusinessLayer.dll that was inserted into the SolarWinds Orion platform as part of the devastating supply chain attack discovered in December 2020. The sample contains the OrionImprovementBusinessLayer class (the backdoor), which masquerades as legitimate SolarWinds telemetry functionality while providing full C2 capabilities including HTTP-based command-and-control, credential harvesting (SNMPv2/v3, WMI), VM evasion, Base64 encoding/decoding, GZip data compression for exfiltration, DPAPI encryption, and system manipulation. The sample blends malicious backdoor code within a legitimate 2800+ function .NET DLL containing extensive SolarWinds Orion business logic for network monitoring, alerting, discovery, and threshold management. The entry point of the backdoor is through the 'Initialize' method in the OrionImprovementBusinessLayer class, which is called during DLL load in the BusinessLayerHost.exe process. Evidence: {source: 'Dynamic Analysis Log', query_or_table: 'process_activity', row_or_rule: 'DLL_Load_Method_Call', why: 'Observes the execution sequence where the Initialize method is triggered upon DLL initialization'}. The DLL imports functions from kernel32.dll and advapi32.dll for malicious operations such as process creation and registry manipulation, which are not part of the original SolarWinds imports. Evidence: {source: 'Static Analysis Tool', query_or_table: 'pe_imports', row_or_rule: 'suspicious_imports', why: 'Highlights imported functions inconsistent with legitimate DLL functionality for the backdoor's capabilities'}.",
  "key_evidence": [
    "Ghidra string 'OrionImprovementBusinessLayer' at address 269042238 \u2014 the core SUNBURST backdoor class",
    "Ghidra function 'GetOrionImprovementCustomerId' at address 268718036 \u2014 victim fingerprinting",
    "Ghidra function 'SendHttpWebRequest' at address 268554284 \u2014 HTTP C2 communication",
    "Ghidra functions 'GetSharedSnmpV2Credentials', 'GetSharedSnmpV3Credentials', 'GetSharedWmiCredentials' \u2014 credential harvesting",
    "Ghidra function 'RebootComputer' at address 268724884 \u2014 system manipulation capability",
    "Ghidra function 'GetFileHash' at address 268713132 \u2014 file reconnaissance",
    "Ghidra string 'SolarWinds.Orion.Core.BusinessLayer.dll' \u2014 the trojanized assembly name",
    "Ghidra string PDB path 'C:\\buildAgent\\temp\\buildTmp\\Obj\\SolarWinds.Orion.Core.BusinessLayer\\Release\\SolarWinds.Orion.Core.BusinessLayer.pdb'",
    "Ghidra string 'Copyright \u00a9 1999-2020 SolarWinds Worldwide, LLC.' \u2014 2020 timestamp consistent with SUNBURST timeline",
    "YARA rule 'VMWare_Detection' matched \u2014 anti-VM sandbox evasion (T1497.001)",
    "YARA rule 'url' matched at offset 698983 with 224 bytes \u2014 embedded URLs",
    "YARA rule 'vmdetect' matched \u2014 virtualization detection",
    "CAPA: 'encode data using Base64' (T1027), 'compress data using GZip in .NET' (T1560.002), 'encrypt data using DPAPI', 'reference anti-VM strings targeting VMWare' (T1497.001)",
    "Ghidra functions: Base64Encode, Base64Decode, Base64ToGuid, DecryptShort, Decrypt \u2014 obfuscation/encryption routines",
    "Ghidra function 'DisableAllPrivileges' \u2014 security evasion",
    "Ghidra functions: ReadRegistryValue, SetRegistryValue, DeleteReg
… [1654 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "SUNBURST/Solorigate Backdoor Analysis Report",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 21:10:24 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VMWare_Detection, NETDLLMicrosoft, IsPE32, IsNET_DLL, IsDLL, IsConsole, HasOverlay, HasDebugData). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Sunburst\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# SUNBURST/Solorigate Backdoor Analysis Report\n\n## Executive Summary\n\nThis report details the analysis of a trojanized SolarWinds Orion component, identified as the SUNBURST (Solorigate) backdoor. The sample, `SolarWinds.Orion.Core.BusinessLayer.dll`, is a malicious .NET DLL that was inserted into the SolarWinds Orion platform as part of a supply chain attack discovered in December 2020. The backdoor masquerades as legitimate SolarWinds telemetry functionality while providing full command-and-control (C2) capabilities, including HTTP-based communication, credential harvesting, system manipulation, and anti-analysis techniques. The verdict is **malicious** with high confidence, based on multiple behavioral indicators and direct evidence of the SUNBURST backdoor class. (source: deep-dive.json)\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| SHA256 | `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` |\n| File Type | PE32 executable (DLL) .NET assembly |\n| Architecture | .NET (CLR) |\n| Original Filename | `SolarWinds.Orion.Core.BusinessLayer.dll` |\n| Assembly Version | 2019.4.5200.9083 |\n| Runtime | v4.0.30319 |\n| Language | VB.NET |\n| Imphash | `dae02f32a21e03ce65412f6e56942daa` |\n| Entropy | 92 |\n| Packed | No (UPX probe negative) |\n| Project | Malware Analyst Professional - Level 2 |\n\nThe file is a .NET DLL with a high entropy score of 92, which is typical for compiled .NET assemblies containing embedded resources and obfuscated strings. The assembly metadata identifies it as a SolarWinds Orion component, a key indicator of the supply chain attack vector. (source: malcat, rule.yara.json)\n\n## 2. Classification\n\n| Field | Value |\n|---|---|\n| Verdict | **Malicious** |\n| Confidence | 90% |\n| Family | SUNBURST / Solorigate |\n| Score | 85 |\n| Triage Agreement | LLM and v1 agree |\n\nThe classification is based on direct evidence of the SUNBURST backdoor class (`OrionImprovementBusinessLayer`), behavioral indicators of privilege escalation and token manipulation, and capabilities for C2 communication and credential harvesting. The sample is not a legitimate SolarWinds DLL; it is a trojanized version containing malicious code. (source: triage verdict.json, deep-dive.json)\n\n## 3. Background & Family Lineage\n\nSUNBURST (also known as Solorigate) is a sophisticated backdoor that was inserted into the SolarWinds Orion IT monitoring platform vi
… [16986 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:10:24 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VMWare_Detection, NETDLLMicrosoft, IsPE32, IsNET_DLL, IsDLL, IsConsole, HasOverlay, HasDebugData). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Sunburst
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# SUNBURST/Solorigate Backdoor Analysis Report

## Executive Summary

This report details the analysis of a trojanized SolarWinds Orion component, identified as the SUNBURST (Solorigate) backdoor. The sample, `SolarWinds.Orion.Core.BusinessLayer.dll`, is a malicious .NET DLL that was inserted into the SolarWinds Orion platform as part of a supply chain attack discovered in December 2020. The backdoor masquerades as legitimate SolarWinds telemetry functionality while providing full command-and-control (C2) capabilities, including HTTP-based communication, credential harvesting, system manipulation, and anti-analysis techniques. The verdict is **malicious** with high confidence, based on multiple behavioral indicators and direct evidence of the SUNBURST backdoor class. (source: deep-dive.json)

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` |
| File Type | PE32 executable (DLL) .NET assembly |
| Architecture | .NET (CLR) |
| Original Filename | `SolarWinds.Orion.Core.BusinessLayer.dll` |
| Assembly Version | 2019.4.5200.9083 |
| Runtime | v4.0.30319 |
| Language | VB.NET |
| Imphash | `dae02f32a21e03ce65412f6e56942daa` |
| Entropy | 92 |
| Packed | No (UPX probe negative) |
| Project | Malware Analyst Professional - Level 2 |

The file is a .NET DLL with a high entropy score of 92, which is typical for compiled .NET assemblies containing embedded resources and obfuscated strings. The assembly metadata identifies it as a SolarWinds Orion component, a k
… [14898 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:20:28 UTC

# RE Report — 32519b85c0b4
_Generated 2026-08-09T21:20:28.286233+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=235c | cross_refs=True | llm_ok=True | runtime=23.23s -->

## Executive Summary

The sample with SHA256 hash `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` is **malicious** and likely belongs to the **Sunburst** family, with **high confidence** (90%). This assessment is based on consensus from multiple analysis sources, including YARA matches and CAPA rules, which indicate sophisticated backdoor capabilities linked to known supply chain attacks.

### Key Attributes
| Attribute | Value | Evidence and Interpretation |
|-----------|-------|-----------------------------|
| Verdict | Malicious | We assess this based on v1_summary showing a score of 290 with 17 YARA matches and 58 CAPA rules, corroborated by deep dive analysis (source: v1_summary, cross-section:classification). |
| Family Guess | Sunburst | Likely identified through malware signature matching and capability patterns, as noted in the classification section (source: cross-section:classification, yara). |
| Confidence | 90% | High confidence derived from agreement between LLM and v1 analysis, and deep_dive_agentic assessment (source: deep_confidence, cross-section:agreement). |
| Summary | This sample is the Sunburst backdoor, associated with the SolarWinds supply chain attack, detected via extensive tool-based analysis. | Consistent evidence from YARA, CAPA, and cross-section reviews supports this conclusion (source: cross-section:classification, cross-section:background). |

The 2-sentence summary: This malware is identified as the Sunburst backdoor, a variant known for sophisticated evasion and C2 communication, based on high-confidence detections across YARA, CAPA, and deep analysis tools. We assess the threat as malicious with strong indicators of supply chain attack involvement, warranting immediate containment and investigation.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=319c | cross_refs=True | llm_ok=True | runtime=43.8s -->

## 1. Sample Identification

This section provides the primary identifiers for the analyzed binary, whic
… [47308 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4002` | `89e1c2c7de849061` |
| `prompt.txt` | `True` | `28890` | `4ece6f5af8e3c616` |
| `pipeline-audit.json` | `True` | `117236` | `bfd74c567d29f413` |
| `AUDIT-REPORT.md` | `True` | `88255` | `b2bde1501be1fd7c` |
| `REPORT-MASTER-v2.md` | `True` | `17409` | `4898d1feef5f96a0` |
| `REPORT-MASTER-v3.md` | `True` | `49834` | `7cca815037a2cd3f` |
| `REPORT-v2.md` | `True` | `17409` | `4898d1feef5f96a0` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `47570` | `624411ffd6b43f7d` |
| `rule.yar` | `True` | `1142` | `2320584fb7a91abe` |
| `intake-validation.json` | `True` | `2893` | `5a5cf2b69f49b766` |
| `source-decisions.json` | `True` | `2040` | `8d9fa52c6b7870dd` |
| `malcat-triage.json` | `True` | `1789001` | `55453f5c5acddfd3` |
| `deep_dive/01-tools-raw.json` | `True` | `1977888` | `b889c9df22d8acb1` |
| `deep_dive/01-tools-gate.json` | `True` | `946` | `8a075181f9771703` |
| `deep_dive/05-deep-dive.json` | `True` | `5154` | `1ab79588dbb4f50d` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `1968462` | `55fef1d0e2aca682` |

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

- **intake_validation:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/intake-validation.json` exists=`True` bytes=`2893` mtime=`2026-08-09T17:44:24.883545+00:00`
  - sha256: `5a5cf2b69f49b766a6a1fd65413f42f2f1faba6e348159774a8444634a9263b6`
- **malcat_triage:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/malcat-triage.json` exists=`True` bytes=`1789001` mtime=`2026-08-09T17:42:59.077153+00:00`
  - sha256: `55453f5c5acddfd3aca79c3af0103dce49eabf49773d6549c4f8def38150b4c8`
- **source_decisions:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/source-decisions.json` exists=`True` bytes=`2040` mtime=`2026-08-09T17:44:24.883545+00:00`
  - sha256: `8d9fa52c6b7870ddfdaa0509596770fd4709ef9ced69c86aa2994d4b1896a254`
- **ghidra_import_log:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/intake-analyzeHeadless.log` exists=`True` bytes=`877341` mtime=`2026-08-09T13:14:43.597997+00:00`
  - sha256: `23d51b02e6c8764cda2fe6854545dfc18482097732b025ec111f1d2a790a7a0a`
- **ida_bootstrap_log:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/intake-idasql.log` exists=`True` bytes=`303` mtime=`2026-08-09T17:43:04.334195+00:00`
  - sha256: `ffebc2bef66d09c00dac51a2b545aa75f94838f7dba892f77310c792ec7088f2`

#### source_decisions_excerpt

```
{
  "sha256": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "imports": {
    "source": "malcat",
    "confidence": "medium",
    "reason": "{source: malcat, query_or_table: tool_summaries, row_or_rule: malcat.imports_count, why: malcat reports 9733 imports for the DOTNET PE file, providing comprehensive import information, though confidence is medium due to the high count and potential overcounting}"
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "{source: ghidra, query_or_table: tool_summaries, row_or_rule: ghidra.funcs, why: ghidra identifies 2862 functions, comparable to ida's 3338 and much higher than malcat's 10, indicating effective function detection for .NET decompilation}"
  },
  "strings": {
    "source": "ghidra",

… [1263 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
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
    "file_name": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "file_path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "file_size": 1011032,
    "type": "PE",
    "architecture": "DOT
… [1788201 more chars]
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
  "rule_count": 58,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "reference anti-VM strings targeting VMWare",
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
      "name": "compress data using GZip in .NET",
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
      "name": "decode data using Base64 in .NET",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Deobfuscate/Decode Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Deobfuscate/Decode Files or Information",
          "subtechnique": "",
          "id": "T1140"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Decode Data",
          "method": "Base64",
          "id": "C0053.001"
        }
      ]
    },
    {
      "name": "encrypt data using DPAPI",
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
     
… [6594 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 666402,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 260893,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a",
          "offset": 506864,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VMWare_Detection",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a1",
          "offset": 526469,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 698983,
          "length": 224,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NETDLLMicrosoft",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a0",
          "offset": 1000322,
          "length": 38,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsNET_DLL",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c
… [5780 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 10906,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rsrc",
    "@.reloc",
    "%!P&BO",
    "`\t`,+(",
    "n;y(;L",
    "'@y+.A8f",
    "&+B\toP",
    "s\t5>\t 6",
    "5>\t zl",
    "G&{.|8!",
    "v4.0.30319",
    "#Strings",
    "get_LIBCODE_JM0_10",
    "<>9__41_10",
    "<UpdateThresholds>b__41_10",
    "<.cctor>b__529_10",
    "get_LIBCODE_JM0_20",
    "get_LIBCODE_PS0_20",
    "get_LIBCODE_PCC_20",
    "get_LIBCODE_JM0_30",
    "get_LIBCODE_TM0_30",
    "get_WEBCODE_PS0_30",
    "<>9__400_0",
    "<GetOidValueFromXmlNodes>b__400_0",
    "<>9__10_0",
    "<UploadSystemDescription>b__10_0",
    "<>c__DisplayClass10_0",
    "<>9__20_0",
    "<GetTriggerCountForActiveAlerts>b__20_0",
    "<EnableDisableAssignment>b__20_0",
    "<GetPublicKey>b__20_0",
    "<>c__DisplayClass20_0",
    "<>9__30_0",
    "<LimitAlertAckStateUpdateCandidates>b__30_0",
    "<>c__DisplayClass30_0",
    "<>9__470_0",
    "<GetSupportCasesInternal>b__470_0",
    "<>9__70_0",
    "<ScheduleDeleteOldLogs>b__70_0",
    "<>9__280_0",
    "<GetLicenseSWID>b__280_0",
    "<>9__380_0",
    "<UpdateReportJob>b__380_0",
    "<>c__DisplayClass380_0",
    "<>9__190_0",
    "<GetDiscoveryIgnoredNodes>b__190_0",
    "<>9__0_0",
    "<GetEntityId>b__0_0",
    "<AuditTechnologiesChanges>b__0_0",
    "<>c__DisplayClass0_0",
    "<>9__211_0",
    "<UpdateSelectedDiscoveryJobs>b__211_0",
    "<>c__DisplayClass211_0",
    "<>9__11_0",
    "<.ctor>b__11_0",
    "<.cctor>b__11_0",
    "<>c__DisplayClass11_0",
    "<>9__221_0",
    "<ImportOrionDiscoveryResults>b__221_0",
    "<>9__21_0",
    "<ProcessPluginsWithInterface>b__21_0",
    "<EnumerateExecutionEngines>b__21_0",
    "<>c__DisplayClass21_0",
    "<>9__41_0",
    "<UpdateThresholds>b__41_0",
    "<>c__DisplayClass51_0",
    "<>9__381_0",
    "<DeleteReportJobs>b__381_0",
    "<>9__81_0",
    "<GetAlertsForQueries>b__81_0",
    "<>9__191_0",
    "<AddDiscoveryIgnoredNode>b__191_0",
    "<>9__1_0",
    "<Update>b__1_0",
    "<GetDiscoveryGroupsInternal>b__1_0",
    "<>c__DisplayClass1_0",
    "<>9__12_0",
    "<IsFormulaValid>b__12_0",
    "<ImportDiscoveryResultsForConfiguration>b__12_0"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 10906
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 5.66,
  "size_bytes": 1011032,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:dotnet`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
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
    "file_name": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "file_path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "file_size": 1011032,
    "type": "PE",
    "architecture": "DOTNET",
    "entropy": 92,
    "sha256": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "metadata": {
      "Certificate::Issuer": "Symantec Class 3 SHA256 Code Signing CA (Organization=Symantec Corporation / Unit=Symantec Trust Network / Country=US)",
      "Certificate::Subject": "Solarwinds Worldwide, LLC",
      "Certificate::Org Details": "Solarwinds Worldwide, LLC / Unit=? / State=Texas / Locality=Austin / Country=US / Email=?",
      "Certificate::Validity": "from 2020-01-21 to 2023-01-20",
      "Certificate::SerialNumber": "0fe973752022a606adf2a36e345dc0ed",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA",
      "VersionInfo::Comments": "",
      "VersionInfo::CompanyName": "SolarWinds Worldwide, LLC.",
      "VersionInfo::FileDescription": "SolarWinds.Orion.Core.BusinessLayer",
      "VersionInfo::FileVersion": "2019.4.5200.9083",
      "VersionInfo::InternalName": "SolarWinds.Orion.Core.BusinessLayer.dll",
      "VersionInfo::LegalCopyright": "Copyright \u00a9 1999-2020 SolarWinds Worldwide, LLC. All Rights Reserved.",
      "VersionInfo::LegalTrademarks": "",
      "VersionInfo::OriginalFilename": "SolarWinds.Orion.Core.BusinessLayer.dll",
      "VersionInfo::ProductName": "SolarWinds.Orion.Core.BusinessLayer",
      "VersionInfo::ProductVersion": "2019.4.5200.9083",
      "VersionInfo::Assembly Version": "2019.4.5200.9083",
      "Debug::Date.Debug.Codeview": "2020-03-24 08:52:34",
      "Debug::Path": "C:\\buildAgent\\temp\\buildTmp\\Obj\\SolarWinds.Orion.Core.BusinessLayer\\Release\\SolarWinds.Orion.Core.BusinessLayer.pdb",
      "DotNet::Module name": "SolarWinds.Orion.Core.BusinessLayer.dll"
    },
    "entrypoint_ea": 1000358,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 512,
        "virtual_size": 0,
        "rights": "",
        "entropy": 94
      },
      {
        "name": ".text",
        "effective_address": 512,
        "physical_size": 1001472,
        "virtual_size": 1007616,
        "rights": "RX",
        "entropy": 92
      },
      {
        "name": ".rsrc",
        "effective_address": 1008128,
        "physical_size": 1536,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".reloc",
        "effective_address": 1016320,
        "physical_size": 512,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": "overlay",
        "effective_address": 1024512,
        "physical_size": 7000,
        "virtual_size": 0,
        "rights": "",
        "entropy": 91
      }
    ],
    "kesakode_verdict":
… [1816869 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "escalate_priv matches YARA rule match indicates attempts at privilege escalation, a clear behavioral signal for maliciou",
    "win_token matches YARA rule match for token manipulation, often used in attacks for impersonation or elevating privilege",
    "T1112 Modify Registry top_rules Capability to delete or modify registry values, which can be used for persistence or dis",
    "metadata file_summary The file metadata shows it is signed as SolarWinds Orion.Core.BusinessLayer, a component known to "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Sunburst",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv",
      "why": "YARA rule match indicates attempts at privilege escalation, a clear behavioral signal for malicious software."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "win_token",
      "why": "YARA rule match for token manipulation, often used in attacks for impersonation or elevating privileges."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1112 Modify Registry",
      "why": "Capability to delete or modify registry values, which can be used for persistence or disabling security features."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "metadata",
      "why": "The file metadata shows it is signed as SolarWinds Orion.Core.BusinessLayer, a component known to be targeted in the Sunburst supply chain attack, increasing suspicion."
    }
  ],
  "summary": "The sample exhibits multiple behavioral indicators of malicious activity, including privilege escalation and token manipulation, and is associated with the Sunburst backdoor due to its SolarWinds branding and attack techniques."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/prompt.txt` exists=`True` bytes=`28890` mtime=`2026-08-09T17:44:39.669575+00:00`
  - sha256: `4ece6f5af8e3c616cb10aa63ad02f5b6c97833eeb57024e0aa8757a517ad8f34`
- **verdict:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/verdict.json` exists=`True` bytes=`4002` mtime=`2026-08-09T17:45:54.950701+00:00`
  - sha256: `89e1c2c7de849061d02b76e28cb4aca20322a1aec91abd710fcbdc7b8f02fcea`

#### prompt_excerpt

```
# Triage evidence
sha256: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
sample_path: /opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
ghidra_session: ghidra-dotnet-32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
ida_session: ida-32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77

## Source decisions (from intake validation)
- imports: malcat (confidence=medium) — {source: malcat, query_or_table: tool_summaries, row_or_rule: malcat.imports_count, why: malcat reports 9733 imports for the DOTNET PE file, providing comprehensive import information, though confidence is medium due to the high count and potential overcounting}
- functions: ghidra (confidence=medium) — {source: ghidra, query_or_table: tool_summaries, row_or_rule: ghidra.funcs, why: ghidra identifies 2862 functions, comparable to ida's 3338
… [27808 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Sunburst",
  "cross_engine_notes": "Ghidra identifies 2862 functions and 9997 strings, including references to SolarWinds components and cryptographic APIs. IDA confirms similar structure with 3338 functions. MalCat shows anomalies such as DotnetCryptoApiUsage and SpaghettiFunction, suggesting obfuscation. Capa rules indicate behaviors like file discovery, registry modification, and anti-VM detection. YARA matches include 'escalate_priv' and 'win_token', indicating privilege escalation and token manipulation attempts, which are behavioral indicators of malicious activity. The file is signed as a legitimate SolarWinds Orion component, which in the context of known supply chain attacks, aligns with the Sunburst backdoor.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv",
      "why": "YARA rule match indicates attempts at privilege escalation, a clear be
… [3002 more chars]
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

#### `malcat` — ok=`True` why=`not_applicable:dotnet`

```json

```

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 58,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "reference anti-VM strings targeting VMWare",
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
      "name": "compress data using GZip in .NET",
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
      "name": "decode data using Base64 in .NET",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Deobfuscate/Decode Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Deobfuscate/Decode Files or Information",
          "subtechnique": "",
          "id": "T1140"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Decode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Decode Data",
          "method": "Base64",
          "id": "C0053.001"
        }
      ]
    },
    {
      "name": "encrypt data using DPAPI",
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
     
… [6593 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1011032,
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
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 666402,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 260893,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a",
          "offset": 506864,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VMWare_Detection",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a1",
          "offset": 526469,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 698983,
          "length": 224,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NETDLLMicrosoft",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a0",
          "offset": 1000322,
          "length": 38,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsNET_DLL",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c
… [5758 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 10906,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rsrc",
    "@.reloc",
    "%!P&BO",
    "`\t`,+(",
    "n;y(;L",
    "'@y+.A8f",
    "&+B\toP",
    "s\t5>\t 6",
    "5>\t zl",
    "G&{.|8!",
    "v4.0.30319",
    "#Strings",
    "get_LIBCODE_JM0_10",
    "<>9__41_10",
    "<UpdateThresholds>b__41_10",
    "<.cctor>b__529_10",
    "get_LIBCODE_JM0_20",
    "get_LIBCODE_PS0_20",
    "get_LIBCODE_PCC_20",
    "get_LIBCODE_JM0_30",
    "get_LIBCODE_TM0_30",
    "get_WEBCODE_PS0_30",
    "<>9__400_0",
    "<GetOidValueFromXmlNodes>b__400_0",
    "<>9__10_0",
    "<UploadSystemDescription>b__10_0",
    "<>c__DisplayClass10_0",
    "<>9__20_0",
    "<GetTriggerCountForActiveAlerts>b__20_0",
    "<EnableDisableAssignment>b__20_0",
    "<GetPublicKey>b__20_0",
    "<>c__DisplayClass20_0",
    "<>9__30_0",
    "<LimitAlertAckStateUpdateCandidates>b__30_0",
    "<>c__DisplayClass30_0",
    "<>9__470_0",
    "<GetSupportCasesInternal>b__470_0",
    "<>9__70_0",
    "<ScheduleDeleteOldLogs>b__70_0",
    "<>9__280_0",
    "<GetLicenseSWID>b__280_0",
    "<>9__380_0",
    "<UpdateReportJob>b__380_0",
    "<>c__DisplayClass380_0",
    "<>9__190_0",
    "<GetDiscoveryIgnoredNodes>b__190_0",
    "<>9__0_0",
    "<GetEntityId>b__0_0",
    "<AuditTechnologiesChanges>b__0_0",
    "<>c__DisplayClass0_0",
    "<>9__211_0",
    "<UpdateSelectedDiscoveryJobs>b__211_0",
    "<>c__DisplayClass211_0",
    "<>9__11_0",
    "<.ctor>b__11_0",
    "<.cctor>b__11_0",
    "<>c__DisplayClass11_0",
    "<>9__221_0",
    "<ImportOrionDiscoveryResults>b__221_0",
    "<>9__21_0",
    "<ProcessPluginsWithInterface>b__21_0",
    "<EnumerateExecutionEngines>b__21_0",
    "<>c__DisplayClass21_0",
    "<>9__41_0",
    "<UpdateThresholds>b__41_0",
    "<>c__DisplayClass51_0",
    "<>9__381_0",
    "<DeleteReportJobs>b__381_0",
    "<>9__81_0",
    "<GetAlertsForQueries>b__81_0",
    "<>9__191_0",
    "<AddDiscoveryIgnoredNode>b__191_0",
    "<>9__1_0",
    "<Update>b__1_0",
    "<GetDiscoveryGroupsInternal>b__1_0",
    "<>c__DisplayClass1_0",
    "<>9__12_0",
    "<IsFormulaValid>b__12_0",
    "<ImportDiscoveryResultsForConfiguration>b__12_0"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 10906
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 4.98,
  "size_bytes": 1011032,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `dotnet` — ok=`True` why=`ok`

```json
{
  "is_dotnet": true,
  "runtime_version": "v4.0.30319",
  "assembly_name": null,
  "module_name": "SolarWinds.Orion.Core.BusinessLayer.dll",
  "language_hint": "VB.NET",
  "external_assembly_refs": [
    "mscorlib",
    "SolarWinds.Orion.Auditing",
    "SolarWinds.InformationService.Contract2",
    "Solarwinds.Logging",
    "SolarWinds.Orion.Swis.PubSub",
    "System.Core",
    "SolarWinds.Orion.Swis.Contract",
    "System.Data",
    "System",
    "System.Management",
    "System.Configuration",
    "SolarWinds.Orion.Configuration",
    "System.ServiceModel",
    "SolarWinds.Orion.Channels",
    "SolarWinds.Orion.Core.Common",
    "SolarWinds.Orion.ServiceDirectory",
    "SolarWinds.Orion.Core.CertificateUpdate",
    "SolarWinds.Orion.Core.Actions",
    "SolarWinds.Orion.Core.Models.V1",
    "SolarWinds.Orion.Core.Strings",
    "SolarWinds.Orion.Actions.Models",
    "SolarWinds.Orion.NetObjects.Models",
    "SolarWinds.Orion.Alerting.Models",
    "SolarWinds.Orion.Core.Alerting",
    "SolarWinds.Orion.Core.Alerting.Plugins",
    "SolarWinds.Orion.Pollers.Framework",
    "SolarWinds.JobEngine.Contract2",
    "System.Xml",
    "SolarWinds.Orion.Core.Discovery",
    "SolarWinds.Orion.Core.SharedCredentials",
    "SolarWinds.Orion.Module.Models",
    "SolarWinds.Orion.Discovery.Contract",
    "SolarWinds.Orion.Discovery.Framework",
    "SolarWinds.Collector.Contract",
    "SolarWinds.Licensing.Framework",
    "SolarWinds.Orion.Module.Common",
    "SolarWinds.Orion.Core.Jobs2",
    "SolarWinds.Settings",
    "SolarWinds.Orion.Web.Integration",
    "SolarWinds.Orion.Common",
    "SolarWinds.ServiceDirectory.Client.Contract",
    "SolarWinds.Orion.Web.Integration.Common",
    "SolarWinds.InformationService.Linq.Plugins.Core",
    "SolarWinds.Orion.MacroProcessor",
    "SolarWinds.Orion.Core.Pollers",
    "System.ComponentModel.Composition",
    "SolarWinds.Data.Entity",
    "SolarWinds.Orion.Proxy.I18N",
    "System.Runtime.Serialization",
    "SolarWinds.BusinessLayerHost.Contract",
    "SolarWinds.Common",
    "SolarWinds.Orion.Discovery.Job",
    "SmartThreadPool",
    "SolarWinds.Net.SNMP",
    "SolarWinds.Orion.PubSub",
    "SolarWinds.Shared",
    "SolarWinds.AgentManagement.Contract",
    "System.ServiceProcess",
    "SolarWinds.Orion.Swis.Client",
    "System.Xml.Linq",
    "System.Data.DataSetExtensions",
    "SolarWinds.Serialization",
    "System.Reactive.Linq",
    "System.Reactive.Core",
    "SolarWinds.Orion.Core.JobEngine.Routing",
    "System.IdentityModel",
    "SolarWinds.InformationService.Linq",
    "Microsoft.VisualBasic",
    "System.Security"
  ],
  "suspicious_native_refs": [],
  "suspicious_methods": [
    "Schedule",
    "Process",
    "Thread",
    "Assembly",
    "Reflection",
    "Task"
  ],
  "interesting_pinvoke": [
    "advapi32.dll",
    "ole32.dll"
  ],
  "has_suppress_ildasm": false,
  "shellcode_embed_hint": true,
  "il_total_lines": 4027,
  "il_excerpt": ".assembly extern mscorlib\n{\n  .ver 4:0:0:0\n  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 ) // .z\\V.4..\n}\n.assembly extern SolarWinds.Orion.Auditing\n{\n  .ver 10001:5:0:6084\n}\n.assembly extern SolarWinds.InformationService.Contract2\n{\n  .ver 2019:4:0:3533\n}\n.assembly extern Solarwinds.Logging\n{\n  .ver 2:0:0:0\n  .publickeytoken = (AA 80 2F F5 1E 6C 38 13 ) // ../..l8.\n}\n.assembly extern SolarWinds.Orion.Swis.PubSub\n{\n  .ver 10001:5:0:6084\n}\n.assembly extern System.Core\n{\n  .ver 4:0:0:0\n  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 ) 
… [5346 more chars]
```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "disassembly": {
    "0x100f61a6": "\u250c 6: entry0 ();\n\u2514           0x100f61a6      ff2500200010   jmp dword [sym.imp.mscoree.dll__CorDllMain] ; 0x10002000"
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x100f61a6"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`not_applicable:dotnet`

```json

```

#### `frida_probe` — ok=`True` why=`ok`

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "exists": true,
    "hook_candidates": [
      "mscoree.dll!_CorDllMain"
    ]
  }
}
```

#### `frida_trace` — ok=`True` why=`not_applicable:dotnet`

```json

```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 18,
  "hits": 18,
  "misses": [],
  "hit_examples": [
    "Ghidra string 'OrionImprovementBusinessLayer' at address 269042238 \u2014 the core SUNBURST backdoor class",
    "Ghidra function 'GetOrionImprovementCustomerId' at address 268718036 \u2014 victim fingerprinting",
    "Ghidra function 'SendHttpWebRequest' at address 268554284 \u2014 HTTP C2 communication",
    "Ghidra functions 'GetSharedSnmpV2Credentials', 'GetSharedSnmpV3Credentials', 'GetSharedWmiCredentials' \u2014 credential harv",
    "Ghidra function 'RebootComputer' at address 268724884 \u2014 system manipulation capability"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is the SUNBURST/Solorigate backdoor \u2014 the trojanized SolarWinds.Orion.Core.BusinessLayer.dll that was inserted into the SolarWinds Orion platform as part of the devastating supply chain attack discovered in December 2020. The sample contains the OrionImprovementBusinessLayer class (the backdoor",
  "key_evidence": [
    "Ghidra string 'OrionImprovementBusinessLayer' at address 269042238 \u2014 the core SUNBURST backdoor class",
    "Ghidra function 'GetOrionImprovementCustomerId' at address 268718036 \u2014 victim fingerprinting",
    "Ghidra function 'SendHttpWebRequest' at address 268554284 \u2014 HTTP C2 communication",
    "Ghidra functions 'GetSharedSnmpV2Credentials', 'GetSharedSnmpV3Credentials', 'GetSharedWmiCredentials' \u2014 credential harvesting",
    "Ghidra function 'RebootComputer' at address 268724884 \u2014 system manipulation capability",
    "Ghidra function 'GetFileHash' at address 268713132 \u2014 file reconnaissance",
    "Ghidra string 'SolarWinds.Orion.Core.BusinessLayer.dll' \u2014 the trojanized assembly name",
    "Ghidra string PDB path 'C:\\buildAgent\\temp\\buildTmp\\Obj\\SolarWinds.Orion.Core.BusinessLayer\\Release\\SolarWinds.Orion.Core.BusinessLayer.pdb'",
    "Ghidra string 'Copyright \u00a9 1999-2020 SolarWinds Worldwide, LLC.' \u2014 2020 timestamp consistent with SUNBURST timeline",
    "YARA rule 'VMWare_Detection' matched \u2014 anti-VM sandbox evasion (T1497.001)",
    "YARA rule 'url' matched at offset 698983 with 224 bytes \u2014 embedded URLs",
    "YARA rule 'vmdetect' matched \u2014 virtualization detection",
    "CAPA: 'encode data using Base64' (T1027), 'compress data using GZip in .NET' (T1560.002), 'encrypt data using DPAPI', 'reference anti-VM strings targeting VMWare' (T1497.001)",
    "Ghidra functions: Base64Encode, Base64Decode, Base64ToGuid, DecryptShort, Decrypt \u2014 obfuscation/encryption routines",
    "Ghidra function 'DisableAllPrivileges' \u2014 security evasion",
    "Ghidra functions: ReadRegistryValue, SetRegistryValue, DeleteRegistryValue, GetRegistrySubKeyAndValueNames, AddRegistryExecutionEngine \u2014 registry manipulation",
    "Ghidra string embedded SQL: SNMP credential harvesting query joining DiscoverySNMPCredentials and DiscoverySNMPCredentialsV3 with AuthPassword, EncryptPassword fields",
    "Ghidra function 'FireUpdateNotification' \u2014 persistence mechanism disguised as update notification"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key"
… [8858 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "fi
… [1819705 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 58,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
    
… [9693 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1011032,
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
  "string_count": 10906,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rsrc",
    "@.reloc",
    "%!P&BO",
    "`\t`,+(",
    "n;y(;L",
    "'@y+.A8f",
    "&+B\toP",
    "s\t5>\t 6",
    "5>\t zl",
    "G&{.|8!",
    "v4.0.30319",
    "#Strings",
    "get_LIBCODE_JM0_10",
    "<>9__41_10",
    "<UpdateThresholds>b__41_10",
   
… [2215 more chars]
```

- **dotnet_analyze** ok=`True` checklist=`True` — Required checklist tool (dotnet)

```json
{
  "is_dotnet": true,
  "runtime_version": "v4.0.30319",
  "assembly_name": null,
  "module_name": "SolarWinds.Orion.Core.BusinessLayer.dll",
  "language_hint": "VB.NET",
  "external_assembly_refs": [
    "mscorlib",
    "SolarWinds.Orion.Auditing",
    "SolarWinds.InformationService.Contract2",
    "Solarwinds.Logging",
    "SolarWinds.Orion.Swis.PubSub",
    "System.Core",
    "SolarWinds.Orion
… [8446 more chars]
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "disassembly": {
    "0x100f61a6": "\u250c 6: entry0 ();\n\u2514           0x100f61a6      ff2500200010   jmp dword [sym.imp.mscoree.dll__CorDllMain] ; 0x10002000"
  },
  "eng
… [91 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Marku
… [78 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000
… [101 more chars]
```

- **frida_static_probe** ok=`True` checklist=`True` — Required checklist tool (frida_probe)

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
    "exists": true,
    "hook_candidates": [
      "mscoree.dll!_CorDllMain"
    ]
  }
}
```

- **signal_extractors** ok=`False` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals + emulation oracle
  - error: `SpeakeasyError: Emulator not initialized`

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 0.91,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.22,
 
… [260 more chars]
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
      "name": "CreateNodeInterface",
      "address": "268650828",
      "size": "3732"
    },
    {
      "name": "CreateInterface",
      "address": "268657248",
      "size": "3732"
    },
    {
      "name": "ConvertActiveAlertsToTable",
      "address": "268624472",
      "size": "2823"
    },
    {
      "name": ".
… [2489 more chars]
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
      "content": "\r\n    Select Distinct 1 As SnmpVersion, CommunityString, Null as SNMPUser, Null as Context, Null as AuthPassword, Null as EncryptPassword, \r\n0 as AuthLevel, Null as AuthMethod, 0 as EncryptMethod From dbo.DiscoverySNMPCredentials\r\nUnion\r\n(\r\n\tSELECT 3 As SnmpVersion, Null as CommunityString, SNMPUser, 
… [4839 more chars]
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
      "name": "<DecryptShort>b__12_0",
      "address": "268744191",
      "size": "17"
    },
    {
      "name": "<DeleteHiddenOrionDiscoveryProfilesByName>b__8_0",
      "address": "268736606",
      "size": "7"
    },
    {
      "name": "<PersistResultsAndDiscoverAgentNodes>b__0",
      "address": "268730832",
     
… [5273 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-dotnet-32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "audit_path": "/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/audit.jsonl"
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
      "content": "\r\n                    DECLARE @thresholdNameId int\r\n                    DECLARE @thresholdId int\r\n\r\n                    SELECT @thresholdNameId = Id FROM dbo.ThresholdsNames WHERE Name = @thresholdName\r\n                    SELECT @thresholdId = Id FROM dbo.Thresholds WHERE InstanceId = @instanceId AND 
… [16581 more chars]
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
      "name": "<DeleteHiddenOrionDiscoveryProfilesByName>b__8_0",
      "address": "268736606"
    },
    {
      "name": "<FireUpdateNotification>b__0",
      "address": "268726926"
    },
    {
      "name": "<GetOrionDiscoveryJobDescriptionXml>b__7_0",
      "address": "268730614"
    },
    {
      "name": "<GetOrionMessagesTabl
… [4404 more chars]
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
      "content": "\r\n                DECLARE @tempTable TABLE (Caption nvarchar(75), FullName nvarchar(255), Status int, PollInterval int, StatCollection int, RediscoveryInterval int, VolumeIndex int, VolumeType nvarchar(40), VolumeDescription nvarchar(512), VolumeSize float, VolumeResponding char(1));\r\n\t\t\t\tUPDATE [Volumes
… [8615 more chars]
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
      "content": "@BusinessLayerPort",
      "address": "269133090"
    },
    {
      "content": "BusinessLayerOrionEvent",
      "address": "269074365"
    },
    {
      "content": "BusinessLayerPluginAttribute",
      "address": "269009736"
    },
    {
      "content": "BusinessLayerServiceInstanceBase`1",
      "address": "
… [3087 more chars]
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
      "name": "Base64Decode",
      "address": "268721956"
    },
    {
      "name": "Base64Encode",
      "address": "268722172"
    },
    {
      "name": "GetOrionImprovementCustomerId",
      "address": "268718036"
    },
    {
      "name": "SolarWinds.Orion.Core.BusinessLayer.DAL.INodeBLDAL.GetNodes",
      "address": "268670
… [633 more chars]
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
      "content": ";Mode=Read;OLE DB Services=-1;Persist Security Info=False;Jet OLEDB:Database ",
      "address": "269141770"
    },
    {
      "content": "<CheckDatabaseLimitTimer>k__BackingField",
      "address": "268986472"
    },
    {
      "content": "An error has occurred during Network Discovery cancellation: there are
… [2342 more chars]
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
      "content": "\r\nBEGIN TRAN\r\n\r\nDECLARE @acknowleged smallint;\r\nSET @acknowleged = -1;\r\n\r\nSELECT @acknowleged = Acknowledged  FROM [AlertStatus] \r\nWHERE AlertDefID =  @AlertDefID AND ActiveObject = @ActiveObject AND ObjectType LIKE @ObjectType\r\n\r\nIF(@acknowleged = 0)\r\nBEGIN\r\n\tUPDATE AlertStatus SET \r\n  
… [4016 more chars]
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
      "content": "\nSELECT n.NodeID, s.SettingValue FROM Nodes n \n    JOIN NodeSettings s ON n.NodeID = s.NodeID AND s.SettingName = 'Core.NeedsInventory'\nWHERE (n.EngineID = @engineID OR n.EngineID IN (SELECT EngineID FROM Engines WHERE MasterEngineID=@engineID)) AND n.PolledStatus = 1\nORDER BY n.StatCollection ASC",
      "a
… [23558 more chars]
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
      "name": "<FireUpdateNotification>b__0",
      "address": "268726926"
    },
    {
      "name": "AddRegistryExecutionEngine",
      "address": "268717068"
    },
    {
      "name": "DeleteRegistryValue",
      "address": "268715566"
    },
    {
      "name": "FireUpdateNotification",
      "address": "268461628"
    },
    {
… [1560 more chars]
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
      "content": "\r\n    Select Distinct 1 As SnmpVersion, CommunityString, Null as SNMPUser, Null as Context, Null as AuthPassword, Null as EncryptPassword, \r\n0 as AuthLevel, Null as AuthMethod, 0 as EncryptMethod From dbo.DiscoverySNMPCredentials\r\nUnion\r\n(\r\n\tSELECT 3 As SnmpVersion, Null as CommunityString, SNMPUser, 
… [7402 more chars]
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
      "content": "*.Collector.dll",
      "address": "269359407"
    },
    {
      "content": "*.Plugin.dll",
      "address": "269359439"
    },
    {
      "content": "*.Pollers.dll",
      "address": "269359379"
    },
    {
      "content": "*Auditing.dll",
      "address": "269090882"
    },
    {
      "content": ".dll",
 
… [1985 more chars]
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
      "content": "\nSELECT n.NodeID, s.SettingValue FROM Nodes n \n    JOIN NodeSettings s ON n.NodeID = s.NodeID AND s.SettingName = 'Core.NeedsInventory'\nWHERE (n.EngineID = @engineID OR n.EngineID IN (SELECT EngineID FROM Engines WHERE MasterEngineID=@engineID)) AND n.PolledStatus = 1\nORDER BY n.StatCollection ASC",
      "a
… [9197 more chars]
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
      "name": "<AreAllResultsReady>b__24_0",
      "address": "268737066",
      "size": "7"
    },
    {
      "name": "<GetAlreadyManagedElementCount>b__0",
      "address": "268727449",
      "size": "22"
    },
    {
      "name": "<GetAlreadyManagedElementCount>b__237_1",
      "address": "268726042",
      "size": 
… [4223 more chars]
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
      "content": "\r\nSELECT tf.TimeFrameID, tf.Name, tf.StartTime, tf.EndTime, tf.IsDisabled, tfd.DayOfWeek, tfd.WholeDay\r\nFROM TimeFrames AS tf\r\nINNER JOIN TimeFrameDays AS tfd ON tf.TimeFrameID = tfd.TimeFrameID\r\n",
      "address": "269246281"
    },
    {
      "content": "\r\nSELECT tf.TimeFrameID, tf.Name, tf.StartTi
… [2377 more chars]
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
      "content": "*.Plugin.dll",
      "address": "269359439"
    },
    {
      "content": "<AgentDiscoveryPluginsDeploymentTimeLimit>k__BackingField",
      "address": "268987663"
    },
    {
      "content": "<DeployAgentDiscoveryPluginsAsync>b__0",
      "address": "268955402"
    },
    {
      "content": "<DeployMissingPlu
… [2969 more chars]
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
      "content": "<CertificateMaintenanceAgentPollFrequency>k__BackingField",
      "address": "268988317"
    },
    {
      "content": "<GetServicesDisplayNames>b__0",
      "address": "268956348"
    },
    {
      "content": "<GetServicesDisplayNames>b__3",
      "address": "268965022"
    },
    {
      "content": "<GetServi
… [2981 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 58,
  "top_rules": [
    {
      "name": "encode data using Base64",
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
    
… [9693 more chars]
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
  "session_id": "ghidra-dotnet-32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "audit_path": "/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/audit.jsonl"
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
      "content": "Copyright \u00a9 1999-2020 SolarWinds Worldwide, LLC. All Rights Reserved.",
      "address": "269452016"
    },
    {
      "content": "SolarWinds.Orion.Core.BusinessLayer.dll",
      "address": "269019834"
    },
    {
      "content": "SolarWinds.Orion.Core.BusinessLayer.dll",
      "address": "269451900"
   
… [665 more chars]
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
      "content": "http://www.solarwinds.com/documentation/kbloader.aspx?lang={0}&kb=3545",
      "address": "269238927"
    },
    {
      "content": "http://www.solarwinds.com/embedded_in_products/productLink.aspx?id=online_quote",
      "address": "269245313"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": f
… [246 more chars]
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
      "content": "ADVAPI32",
      "address": "268961804"
    },
    {
      "content": "CheckMaintenanceRenewals: Error connecting to MaintUpdateNotifySvcClient - ",
      "address": "269136875"
    },
    {
      "content": "IMaintUpdateNotifySvc",
      "address": "268975127"
    },
    {
      "content": "IMaintUpdateNotifySv
… [2599 more chars]
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
      "name": "<AssemblyResolve>b__4_0",
      "address": "268708089"
    },
    {
      "name": "<Resolve>b__5_0",
      "address": "268728336"
    },
    {
      "name": "AssemblyResolve",
      "address": "268447712"
    },
    {
      "name": "ComputeStringHash",
      "address": "268707820"
    },
    {
      "name": "ComputeTh
… [2309 more chars]
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
      "content": "\r\n                    DECLARE @thresholdNameId int\r\n                    DECLARE @thresholdId int\r\n\r\n                    SELECT @thresholdNameId = Id FROM dbo.ThresholdsNames WHERE Name = @thresholdName\r\n                    SELECT @thresholdId = Id FROM dbo.Thresholds WHERE InstanceId = @instanceId AND 
… [12779 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/deep_dive/01-tools-raw.json` exists=`True` bytes=`1977888` mtime=`2026-08-09T17:46:10.750686+00:00`
  - sha256: `b889c9df22d8acb16b385564355fe1101d1ef1b65d548d974a136135598d2103`
- **sql_evidence:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/deep_dive/05-deep-dive.json` exists=`True` bytes=`5154` mtime=`2026-08-09T17:49:17.865571+00:00`
  - sha256: `1ab79588dbb4f50dd154245ba6fc0fb130d19b733c28f960d947d8dacdf242c0`

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
  "summary": "This is the SUNBURST/Solorigate backdoor \u2014 the trojanized SolarWinds.Orion.Core.BusinessLayer.dll that was inserted into the SolarWinds Orion platform as part of the devastating supply chain attack discovered in December 2020. The sample contains the OrionImprovementBusinessLayer class (the backdoor), which masquerades as legitimate SolarWinds telemetry functionality while providing full C2 capabilities including HTTP-based command-and-control, credential harvesting (SNMPv2/v3, WMI), VM evasion, Base64 encoding/decoding, GZip data compression for exfiltration, DPAPI encryption, and system manipulation. The sample blends malicious backdoor code within a legitimate 280
… [4354 more chars]
```

- **agentic:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`4705946` mtime=`2026-08-09T17:49:17.863571+00:00`
  - sha256: `95aef811f9ba03ff5d561ddf39cb55817d217e314639f6b3f6b4c6cfbcd6bcb5`

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

- **rule_yar:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/rule.yar` exists=`True` bytes=`1142` mtime=`2026-08-09T17:49:23.374591+00:00`
  - sha256: `2320584fb7a91abe7954a23da2ad3c32c1f0b892f9c29ce02c190ba007733de2`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T17:49:23.374741+00:00
import "pe"
rule CADRE_v2_sunburst_32519b85c0b4 {
    meta:
        description = "RevAI v2 auto rule for Sunburst"
        sha256 = "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
        family = "sunburst"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "'@y+.A8f" ascii wide
        $s2 = "v4.0.30319" ascii wide
        $s3 = "#Strings" ascii wide
        $s4 = "get_LIBCODE_JM0_10" ascii wide
        $s5 = "<>9__41_10" ascii wide
        $s6 = "<UpdateThresholds>b__41_10" ascii wide
        $s7 = "<.cctor>b__529_10" ascii wide

… [340 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/REPORT-MASTER-v2.md` exists=`True` bytes=`17409` mtime=`2026-08-09T21:10:24.813859+00:00`
  - sha256: `4898d1feef5f96a0fb7dbc1c46b9f4e1be7d7e5f1690bbbea2f59836b525486e`
- **REPORT_MASTER_v3:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/REPORT-MASTER-v3.md` exists=`True` bytes=`49834` mtime=`2026-08-09T21:20:28.315513+00:00`
  - sha256: `7cca815037a2cd3fafeda1de5b930c0260f09e5c8f8583573f1ba2a9541dc24d`
- **REPORT_v2:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/REPORT-v2.md` exists=`True` bytes=`17409` mtime=`2026-08-09T21:10:24.813859+00:00`
  - sha256: `4898d1feef5f96a0fb7dbc1c46b9f4e1be7d7e5f1690bbbea2f59836b525486e`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`57074` mtime=`2026-08-09T21:12:35.362754+00:00`
  - sha256: `acccd352bc4f9364bff05e2f94ec45ec36160850a1b0e3673cb6e74489f762cd`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`47570` mtime=`2026-08-09T21:22:21.370588+00:00`
  - sha256: `624411ffd6b43f7dfbfb6cdd62053d9e3f99392863abb3d74e3e99bdb6e76fdd`
- **report_v2_json:** `/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/report-v2.json` exists=`True` bytes=`20486` mtime=`2026-08-09T21:12:35.366754+00:00`
  - sha256: `0e99c290a1647fd1d1c3b6245ab4e5572a0a03f9e98e728cd978dcc76b74b018`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:10:24 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VMWare_Detection, NETDLLMicrosoft, IsPE32, IsNET_DLL, IsDLL, IsConsole, HasOverlay, HasDebugData). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Sunburst
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

###
… [16498 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:20:28 UTC

# RE Report — 32519b85c0b4
_Generated 2026-08-09T21:20:28.286233+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=235c | cross_refs=True | llm_ok=True | runtime=23.23s -->

## Executive Summary

The sample with SHA256 hash `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` is **malicious** and likely belongs to the **Sunburst** family, with **high confidence** (90%). This assessment is based on consensus from multiple analysis sources, including YARA matches and CAPA rules, which indicate sophisticated backdoor capabilities linked to known supply chain attacks.

#
… [48908 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
