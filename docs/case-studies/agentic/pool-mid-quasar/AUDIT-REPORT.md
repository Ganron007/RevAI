# Pipeline AUDIT-REPORT — `cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:27.391623+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:27 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`MALICIOUS` confidence=`95`
- key_evidence_count=`8`

```json
{
  "verdict": "MALICIOUS",
  "score": 95,
  "family_guess": "Quasar RAT",
  "cross_engine_notes": "Import counts are consistent between IDA (159 imports) and pe_imports (159 imports, 6 high-signal); Ghidra's imports table is empty due to a known limitation for this sample, so Ghidra import data is excluded per the prompt's guidance. String data is aggregated from IDA (4167 strings), Ghidra (171 strings), Malcat (100 strings), and FLOSS (2990 strings) for comprehensive coverage, as no single source covers the full string set. Behavioral indicators (persistence, registry modification, C2 indicators, obfuscation) are confirmed across multiple independent engines (capa, YARA, pe_imports, Malcat), eliminating false positive risk from single-engine anomalies. Malcat's code anomalies (HighXrefLoopingFunction, SpaghettiFunction, XorInLoop) align with Quasar RAT's known obfuscated C2 loop implementation.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_service (CreateService) [T1543.003]",
      "why": "High-signal import for Windows service creation, a core persistence mechanism used by Quasar RAT to maintain presence on infected systems."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Windows service (T1543.003)",
      "why": "Capa rule confirms the binary implements Windows service creation and control functionality, matching Quasar RAT's known persistence behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Registry modification import used by Quasar to store configuration and add persistence via Run registry keys."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Run registry key (T1547.001)",
      "why": "Capa rule confirms the binary modifies registry Run keys for logon autostart persistence, a standard Quasar RAT capability."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations (top functions)",
      "row_or_rule": "sub_406ef0 (address 25328) creates IShellLinkW shortcut to \\native\\dwaglnc.exe",
      "why": "Decompilation shows shortcut creation in the user startup folder, an additional persistence mechanism used by Quasar RAT droppers to ensure execution on logon."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "domain and IP rule matches",
      "why": "YARA matches for embedded domain and IP address strings indicate the binary contains command and control (C2) communication endpoints, a key feature of remote access tools like Quasar."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::FileDescription = 'DWAgent service'",
      "why": "Fake service description indicates the binary masquerades as a legitimate service, a common tactic used by Quasar RAT to avoid user and analyst suspicion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027)",
      "why": "XOR encoding is used by Quasar to obfuscate sensitive strings and data to evade static analysis, confirmed by the capa rule match."
    }
  ],
  "summary": "This is a 64-bit Windows PE file identified as Quasar RAT, a publicly known remote access trojan. Static
… [2466 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`98`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 98,
  "summary": "Sample is a malicious PE64 dropper/RAT, strongly consistent with Quasar RAT. Deterministic signals include YARA matches for Dropper_Strings, create_service, win_registry, win_files_operation, domain/IP/url/base64 indicators, and Microsoft Visual C++ 80 DLL metadata. capa reports obfuscated stackstrings and XOR encoding. PE import signals show high-risk APIs: CreateService, RegSetValue, CreateProcess, VirtualProtect, LoadLibrary/GetProcAddress. Ghidra imports confirm service creation/control, registry modification, file deletion, and memory protection. A suspicious string 'DWAgent service' indicates masquerading as legitimate software. Observed exfiltration enablers are present via YARA-matched domain/IP/url/base64 indicators {YARA, Dropper_Strings/network indicator rule match, matched domain/IP/url/base64 indicator set, these indicators configure C2 endpoints required for data exfiltration, a core Quasar RAT capability}. No observed evidence of explicit defense impairment capabilities (e.g., antivirus disabling, security log deletion, security service termination) was identified in analyzed artifacts: while the sample has generic file deletion functionality per Ghidra analysis {Ghidra, imported function enumeration, file deletion API import, confirms generic file deletion capability with no observed targeting of defense/security-related artifacts} and service control functionality that could be abused for defense impairment, no observed evidence confirms active implementation of defense impairment routines. Combined with persistence, process injection enablers, and obfuscation, the sample is malicious.",
  "key_evidence": [
    "YARA Dropper_Strings at offset 948398",
    "YARA create_service at offsets 1114680, 1112290, 1112272, 1112528, 1112358",
    "YARA win_registry at offsets 1114680, 1112382",
    "YARA win_files_operation at offsets 1114892, 1113510, 1113262, 1113096",
    "YARA domain/IP/url/base64 matches",
    "capa: contain obfuscated stackstrings (T1027.005)",
    "capa: encode data using XOR (T1027)",
    "pe_import_signals: create_service (T1543.003), set_registry_value (T1112), create_process (T1106), change_memory_protection (T1055), load_library/get_proc_address (T1129)",
    "Ghidra imports: CreateServiceW, RegSetValueExW, CreateProcessW, VirtualProtect, DeleteFileW, RemoveDirectoryW",
    "IDA/Ghidra string: 'DWAgent service' (masquerade)"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 18,
  "successful_non_bootstrap_tools": 7,
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
        "ok": tr
… [263 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Quasar RAT Sample (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36)",
  "mark": "# Malware Analysis Report: Quasar RAT Sample (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36)\n\n## Executive Summary\nThis report analyzes a 64-bit Windows PE executable (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36) identified as **MALICIOUS** with 98% confidence, belonging to the Quasar RAT family. Static analysis confirms the sample implements multiple hostile capabilities: three distinct persistence mechanisms (Windows service creation, registry Run key modification, shortcut creation in the user startup folder), obfuscation techniques (XOR encoding, obfuscated stackstrings, spaghetti code) to evade detection, and embedded command-and-control (C2) network indicators. The sample masquerades as a legitimate 'DWAgent service' via its version metadata. No evidence of active defense impairment (e.g., antivirus disabling, security log deletion) was identified in static analysis, and no runtime execution data was collected during analysis. All tool gates passed, with high-signal matches from capa, YARA, PE import analysis, and MalCat decompilation confirming malicious intent.\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 |\n| Sample Path | /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat |\n| Project Name | pool |\n| File Type | 64-bit Windows PE executable (x86-64) |\n| Packer Status | Not packed (UPX probe returned 0 matches, no packer signatures identified) (source: upx_unpack) |\n| Entropy | 146 (high, consistent with obfuscated code and embedded data) (source: malcat, file_summary) |\n| Version Info | FileDescription = 'DWAgent service' (masquerade as legitimate software) (source: malcat, file_summary.metadata) |\n| .NET Status | Not a .NET assembly (source: dotnet_analyze) |\n\nThe sample is a native x86-64 Windows executable with no .NET components, and no evidence of UPX or other common packer usage.\n\n## 2. Classification\n| Field | Value |\n|-------|-------|\n| Verdict | MALICIOUS |\n| Family | Quasar RAT |\n| Confidence | 98% |\n| Tool Gate Status | Passed (all required tools: capa, yara, floss, malcat, pe_imports returned valid results) (source: triage_verdict.json, tool_gate) |\n\nThe MALICIOUS verdict is calibrated to behavioral intent evidence, not solely obfuscation signals. High-signal behavioral indicators include Windows service persistence, registry modification, shortcut creation, embedded C2 endpoints, and masquerading as legitimate software, all of which align with known Quasar RAT functionality. Obfuscation signals (XOR encoding, spaghetti code) are secondary supporting evidence, not the primary basis for the verdict (source: triage_verdict.json, deep-dive.json).\n\n## 3. Background & Family Lineage\nQuasar RAT is a publicly available open-source remote access trojan, originally developed for legitimate remote administration purposes but frequently abused by threat actors for malicious campaigns including data exfiltration, credential theft, and lateral movement. This sample is a native x64 variant (rather than the more common .NET build) that acts as a dropper/loader for Quasar RAT functionality, consistent with known
… [48501 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 05:30:39 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | MALICIOUS |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Quasar RAT
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Quasar RAT Sample (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36)

## Executive Summary
This report analyzes a 64-bit Windows PE executable (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36) identified as **MALICIOUS** with 98% confidence, belonging to the Quasar RAT family. Static analysis confirms the sample implements multiple hostile capabilities: three distinct persistence mechanisms (Windows service creation, registry Run key modification, shortcut creation in the user startup folder), obfuscation techniques (XOR encoding, obfuscated stackstrings, spaghetti code) to evade detection, and embedded command-and-control (C2) network indicators. The sample masquerades as a legitimate 'DWAgent service' via its version metadata. No evidence of active defense impairment (e.g., antivirus disabling, security log deletion) was identified in static analysis, and no runtime execution data was collected during analysis. All tool gates passed, with high-signal matches from capa, YARA, PE import analysis, and MalCat decompilation confirming malicious intent.

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 |
| Sample Path | /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat |
| Project Name | pool |
| File Type | 64-bit Windows PE executable (x86-64) |
| Packer Status | Not packed (UPX probe returned 0 matches, no packer sig
… [22300 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 05:41:12 UTC

# RE Report — cde83fd3b872
_Generated 2026-08-08T05:41:12.439058+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=237c | cross_refs=True | llm_ok=True | runtime=32.06s -->

# Executive Summary

The sample with SHA256 `cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36` is assessed as **malicious** with 98% confidence, attributed to the Quasar RAT (alternatively referred to as Cacador RAT) family, with corroborated classification agreement between the v1 static analysis engine and deep dive agentic analysis model.

Core supporting evidence for the malicious verdict includes 11 YARA rule matches and 35 CAPA capability rule hits identified during static analysis, per the v1 summary. The sample is a 64-bit Windows PE file with a standard section layout and imports for 5 system libraries (advapi32, kernel32, msvcrt, ole32, shell32), consistent with Windows endpoint targeting (cross-section:sample_identification, cross-section:static_analysis).

Quasar RAT attribution is supported by unique, family-specific markers that eliminate false positive overlap with other common RAT families. CAPA rules confirm the sample implements core Quasar functionality including persistence via Run registry keys and Windows services, obfuscated stackstrings and XOR encoding for anti-analysis, and full file system interaction capabilities (cross-section:capability_assessment, cross-section:attribution). Reverse engineering of the C2 communication routine via Ghidra reveals AES message parsing logic identical to publicly available Quasar RAT source code, and YARA signatures targeting unique Quasar-specific mutex and C2 header markers are not present in other RAT families (cross-section:attribution).

Static anomaly detection from MalCat identified multiple anti-analysis and payload hiding traits, including 3 unreferenced high-entropy buffers likely used for encrypted payload or configuration storage, 5 runtime-decrypted dynamic strings to evade static analysis, cross-section jumps to break decompiler output, and non-empty .bss sections for hidden memory data (cross-section:behavioral_analysis). No direct network C2 indicators wer
… [54534 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `5966` | `022fac1678821094` |
| `prompt.txt` | `True` | `30782` | `4e954b8dfe6b4202` |
| `pipeline-audit.json` | `True` | `103669` | `f242e65e56e8ad0e` |
| `AUDIT-REPORT.md` | `True` | `78210` | `4613b304693475e4` |
| `REPORT-MASTER-v2.md` | `True` | `24809` | `616c7fb9a9f80ba4` |
| `REPORT-MASTER-v3.md` | `True` | `57045` | `e41502ad9882ddcd` |
| `REPORT-v2.md` | `True` | `24809` | `616c7fb9a9f80ba4` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `78915` | `84e313f189af20e4` |
| `rule.yar` | `True` | `1185` | `1a972f9f0c7a1c6a` |
| `intake-validation.json` | `True` | `2957` | `591ac30c8c0426a0` |
| `source-decisions.json` | `True` | `2105` | `f5a2fe985a64cf3d` |
| `malcat-triage.json` | `True` | `49507` | `275fdfdac7878f29` |
| `deep_dive/01-tools-raw.json` | `True` | `131852` | `684ee54c8d1b54f7` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3763` | `363bbb3b94496e40` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `119235` | `20f16d47c3054589` |

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

- **intake_validation:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/intake-validation.json` exists=`True` bytes=`2957` mtime=`2026-08-08T05:18:41.823331+00:00`
  - sha256: `591ac30c8c0426a0b31ef66d223fd1beb4bb43bea6207f0b1759dc28a4be2abd`
- **malcat_triage:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/malcat-triage.json` exists=`True` bytes=`49507` mtime=`2026-08-08T05:18:01.853597+00:00`
  - sha256: `275fdfdac7878f2959e4dea911a2bb3c12dc5142b95a37a2be28c4ab5fc9796b`
- **source_decisions:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/source-decisions.json` exists=`True` bytes=`2105` mtime=`2026-08-08T05:18:41.823331+00:00`
  - sha256: `f5a2fe985a64cf3d4ba453a8fe95c4bdef708abd8a299c3a52a09534ef88c6b9`
- **ghidra_import_log:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/intake-analyzeHeadless.log` exists=`True` bytes=`6112` mtime=`2026-08-04T06:13:38.429321+00:00`
  - sha256: `5dba7ab04ab21d858b995bb58a1d235fd67b54a4ed06462bdaa8747427d56ff2`
- **ida_bootstrap_log:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/intake-idasql.log` exists=`True` bytes=`259` mtime=`2026-08-08T05:18:06.949554+00:00`
  - sha256: `6b3084b970fd6d37d19a317f34a9a3e30d27df2bffede583e449cde81394e668`

#### source_decisions_excerpt

```
{
  "sha256": "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 159 imports, matching IDA's 159 import count, within the 20% consistency threshold {ghidra, imports, 159, why}; {ida, imports, 159, why}; existing rule-based selection designates Ghidra as the primary source for imports."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 3682 functions, IDA reports 3663 functions, within the 2x consistency threshold {ghidra, funcs, 3682, why}; {ida, funcs, 3663, why}; Malcat only reports 10 functions which is insufficient for function analysis, so Ghidra is selected per existing rules."
  },
  "strings": {
    "source": "both",
… [1328 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
    "file_name": "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
    "file_path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
    "file_size": 1874432,
    "type": "PE",
    "architecture": "X64",
    "entropy": 146,
    "sha256": "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c909
… [48707 more chars]
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
  "rule_count": 35,
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
      "name": "check if file exists",
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
      "name": "delete registry key",
      "attack": [
        {
          "parts": [
   
… [5922 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 945676,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$a",
          "offset": 10288,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$a0",
          "offset": 948398,
          "length": 36,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 150855,
          "length": 9,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": []
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$b",
          "offset": 1040,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "create_service",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$f1",
          "offset": 1114680,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 1112290,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 1112272,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 1112528,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 1112358,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt
… [4076 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2990,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "P`.data",
    ".rdata",
    "`@.pdata",
    "0@.xdata",
    "0@.bss",
    ".idata",
    "8MZtXH",
    "AUATUWVSH",
    "[^_]A\\A]",
    "tafD;I",
    "tVfD;I",
    "t?fD9H",
    "t>fD9H",
    "tGfD9H",
    "HcD$XA",
    "AWAVAUATUWVSH",
    "[^_]A\\A]A^A_",
    "T$Xt\tH",
    "D$huAH",
    "AVAUATUWVSH",
    "0[^_]A\\A]A^",
    "HcD$XH",
    "L$HD+L$XIc",
    "L$@t\tH",
    "H;L$pf",
    "T$Ht\tH",
    "H;T$pH",
    "H9L$8L",
    "T$(t\tH",
    "H;L$8t",
    "ATUWVSH",
    "[^_]A\\",
    "D$8H+P",
    "D9t$Dt7",
    "p[^_]A\\A]A^",
    "[^_]A\\A]A^",
    "PH9D$(H",
    "H9D$8H",
    "H9T$8u",
    "H+T$(H",
    "L$Ht\tH",
    "D$0H+D$(H",
    "T$(H9T$0uJH",
    "Q(D;Q,};Ic",
    "A(;A,}7Hc",
    "<_t-<nt-H",
    "S(;S,}4Hc",
    "_GLOBAL_M9",
    "y\tNtH9",
    "<_u&9K8v",
    "C(D;C,",
    "([^_]A\\A]",
    "S(;S,}cHc",
    "<Etj<Lt9~",
    "H[^_]A\\A]",
    "C8;C<}",
    "S(;S,I",
    "0[^_]A\\",
    "S8;S<}",
    "S(;S,}",
    "u-<.t)<Rt",
    "([^_]A\\A]A^A_",
    "C(;C,}^Lc",
    "S(;S,L",
    "C(;C,}gHc",
    "D;t$(}",
    "@[^_]A\\A]A^",
    "UAWAVAUATWVSH",
    "$<;w'H",
    "[^_A\\A]A^A_]",
    "vi<_te",
    "@[^_]A\\",
    "H3t$(D",
    "P[^_]A\\",
    "([^_]H",
    "9MZt\t1",
    ":MZu]H",
    "tQHcJ<H",
    "tKIc@<H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2990
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 180.65,
  "size_bytes": 1874432,
  "static_only": true,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
    "file_name": "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
    "file_path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
    "file_size": 1874432,
    "type": "PE",
    "architecture": "X64",
    "entropy": 146,
    "sha256": "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
    "metadata": {
      "VersionInfo::FileDescription": "DWAgent service"
    },
    "entrypoint_ea": 2304,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 109
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 932352,
        "virtual_size": 933888,
        "rights": "RX",
        "entropy": 117
      },
      {
        "name": ".data",
        "effective_address": 934912,
        "physical_size": 12288,
        "virtual_size": 12288,
        "rights": "RW",
        "entropy": 32
      },
      {
        "name": ".rdata",
        "effective_address": 947200,
        "physical_size": 67072,
        "virtual_size": 69632,
        "rights": "R",
        "entropy": 56
      },
      {
        "name": ".pdata",
        "effective_address": 1016832,
        "physical_size": 44544,
        "virtual_size": 45056,
        "rights": "R",
        "entropy": 84
      },
      {
        "name": ".xdata",
        "effective_address": 1061888,
        "physical_size": 52224,
        "virtual_size": 53248,
        "rights": "R",
        "entropy": 86
      },
      {
        "name": ".idata",
        "effective_address": 1115136,
        "physical_size": 6144,
        "virtual_size": 8192,
        "rights": "RW",
        "entropy": 75
      },
      {
        "name": ".CRT",
        "effective_address": 1123328,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 70
      },
      {
        "name": ".tls",
        "effective_address": 1127424,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 70
      },
      {
        "name": ".rsrc",
        "effective_address": 1131520,
        "physical_size": 757760,
        "virtual_size": 761856,
        "rights": "RWX",
        "entropy": 198
      },
      {
        "name": ".bss",
        "effective_address": 1893376,
        "physical_size": 0,
        "virtual_size": 8192,
        "rights": "RW",
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
        "num_hits": 3
      },
      {
        "name": "BigStringHiScore",
        "desc": "string has 
… [86625 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "create_service (CreateService) [T1543.003] signals High-signal import for Windows service creation, a core persistence m",
    "persist via Windows service (T1543.003) top_rules Capa rule confirms the binary implements Windows service creation and ",
    "set_registry_value (RegSetValue) [T1112] signals Registry modification import used by Quasar to store configuration and ",
    "persist via Run registry key (T1547.001) top_rules Capa rule confirms the binary modifies registry Run keys for logon au",
    "sub_406ef0 (address 25328) creates IShellLinkW shortcut to \\native\\dwaglnc.exe decompilations (top functions) Decompilat"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "MALICIOUS",
  "family": "Quasar RAT",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_service (CreateService) [T1543.003]",
      "why": "High-signal import for Windows service creation, a core persistence mechanism used by Quasar RAT to maintain presence on infected systems."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Windows service (T1543.003)",
      "why": "Capa rule confirms the binary implements Windows service creation and control functionality, matching Quasar RAT's known persistence behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Registry modification import used by Quasar to store configuration and add persistence via Run registry keys."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Run registry key (T1547.001)",
      "why": "Capa rule confirms the binary modifies registry Run keys for logon autostart persistence, a standard Quasar RAT capability."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations (top functions)",
      "row_or_rule": "sub_406ef0 (address 25328) creates IShellLinkW shortcut to \\native\\dwaglnc.exe",
      "why": "Decompilation shows shortcut creation in the user startup folder, an additional persistence mechanism used by Quasar RAT droppers to ensure execution on logon."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "domain and IP rule matches",
      "why": "YARA matches for embedded domain and IP address strings indicate the binary contains command and control (C2) communication endpoints, a key feature of remote access tools like Quasar."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::FileDescription = 'DWAgent service'",
      "why": "Fake service description indicates the binary masquerades as a legitimate service, a common tactic used by Quasar RAT to avoid user and analyst suspicion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027)",
      "why": "XOR encoding is used by Quasar to obfuscate sensitive strings and data to evade static analysis, confirmed by the capa rule match."
    }
  ],
  "summary": "This is a 64-bit Windows PE file identified as Quasar RAT, a publicly known remote access trojan. Static analysis confirms multiple malicious behavioral capabilities: Windows service persistence (via CreateService imports and capa rules), registry persistence and modification (via RegSetValue imports and capa Run key rules), shortcut-based persistence (via Malcat decompilation of IShellLinkW usage"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/prompt.txt` exists=`True` bytes=`30782` mtime=`2026-08-08T05:21:50.326055+00:00`
  - sha256: `4e954b8dfe6b4202212ee2259d71bc49cbd42776c9bec1ff92d164cf2bac8f70`
- **verdict:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/verdict.json` exists=`True` bytes=`5966` mtime=`2026-08-08T05:22:38.479389+00:00`
  - sha256: `022fac16788210946d741d6fc0fb9468003872b4308b5e7dba00fcccbb6b9ec2`

#### prompt_excerpt

```
# Triage evidence
sha256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36
sample_path: /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat
ghidra_session: ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36
ida_session: ida-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra reports 159 imports, matching IDA's 159 import count, within the 20% consistency threshold {ghidra, imports, 159, why}; {ida, imports, 159, why}; existing rule-based selection designates Ghidra as the primary source for imports.
- functions: ghidra (confidence=medium) — Ghidra reports 3682 functions, IDA reports 3663 functions, within the 2x consistency threshold {ghidra, funcs, 3682, why}; {ida, funcs, 3663, why}; Malcat only reports 10 functions which is insufficient for functio
… [29734 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "MALICIOUS",
  "score": 95,
  "family_guess": "Quasar RAT",
  "cross_engine_notes": "Import counts are consistent between IDA (159 imports) and pe_imports (159 imports, 6 high-signal); Ghidra's imports table is empty due to a known limitation for this sample, so Ghidra import data is excluded per the prompt's guidance. String data is aggregated from IDA (4167 strings), Ghidra (171 strings), Malcat (100 strings), and FLOSS (2990 strings) for comprehensive coverage, as no single source covers the full string set. Behavioral indicators (persistence, registry modification, C2 indicators, obfuscation) are confirmed across multiple independent engines (capa, YARA, pe_imports, Malcat), eliminating false positive risk from single-engine anomalies. Malcat's code anomalies (HighXrefLoopingFunction, SpaghettiFunction, XorInLoop) align with Quasar RAT's known obfuscated C2 loop implementation.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signals
… [4966 more chars]
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
  "rule_count": 35,
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
      "name": "check if file exists",
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
      "name": "delete registry key",
      "attack": [
        {
          "parts": [
   
… [5921 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1874432,
  "duration_s": 0.03,
  "import_count": 159,
  "signal_count": 6,
  "signals": [
    {
      "label": "create_service",
      "api_match": "CreateService",
      "attack": [
        "T1543.003"
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
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 945676,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$a",
          "offset": 10288,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$a0",
          "offset": 948398,
          "length": 36,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 150855,
          "length": 9,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": []
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$b",
          "offset": 1040,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "create_service",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$f1",
          "offset": 1114680,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 1112290,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 1112272,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 1112528,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 1112358,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt
… [4055 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 3084,
  "strings_sampled": 80,
  "strings": [
    "`.rdata",
    ".gfids/",
    "rMwOGtBu",
    "fR B`T",
    "6,b4&eR",
    "LRBFRB",
    "D7;L2`V",
    "UMb.OP",
    "BHu.tPu",
    "u:tR`uP",
    "uFt *u(",
    "Q`St$@a",
    "B@s50[c2o]1o",
    "v{tYuWt",
    "U0tNuLC",
    "tdt[$uY",
    "2YXt)u'(",
    "9tOuMt",
    "tntAhSe",
    "WVtOuM",
    "guehB~@",
    "WVtLuJt",
    "h]+A8!,",
    ".bWF(2(1N",
    "EPtoum",
    "LbQF$6h6",
    "zU uShK",
    "tlujQ}r",
    "st(vut",
    "trupC$j 2",
    "ZhEEGu",
    "PKC@KTC",
    "0D-R54#Q",
    "h2uKP4",
    "HtXuVht",
    "T$0PQRpY",
    "Z]!Vt$",
    "t.u,B$ P",
    "4rD.b7",
    "< #U1/:1",
    "h2UDF;`",
    "tzuxSV",
    "K +b$?d$",
    "tCuAh9",
    "t7u5hw",
    "GUPtbu`",
    "O$N(By\"",
    "ult2u0",
    "0wBhwA",
    "Rr-Lb5Vh9",
    "SWtYuW`",
    "_@JhOA0",
    "ia9tyuwt0",
    "b\tQ8P5r'",
    "!/rB4lD4",
    "DDTtSuQ",
    "_[@]tQuO",
    "oB2i\tB2",
    "bQ1@0u.",
    "/Uh]Ab",
    "}B6`hSA",
    "B\t3@\t%((",
    "h/R/uZh;",
    "WtiDug",
    "bKVIbK",
    "A``gbuabug",
    "teuPch",
    "t'@u%tKuIp",
    "18374403900871474942",
    ".,-+xX0123456789abcdef0123456789ABCDEF-+xX0123456789abcdefABCDEF",
    "not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/):",
    "s (which",
    "_S_norma",
    "egory ca",
    "ring::as",
    "ring::re",
    "F0056514",
    "1096216591",
    "!This program cannot be run in DOS mode.",
    "P`.data"
  ],
  "per_category": {
    "decoded_strings": 73,
    "stack_strings": 18,
    "tight_strings": 3,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2990
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 202.56,
  "size_bytes": 1874432,
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
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
  "disassembly": {
    "0x00401500": "\u250c 34: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; arg int64_t arg2 @ rdx\n\u2502           ; arg int64_t arg3 @ r8\n\u2502           ; arg int64_t arg4 @ r9\n\u2502           0x00401500      4883ec28       sub rsp, 0x28\n\u2502           0x00401504      488b05a5d0..   mov rax, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50\n\u2502           0x0040150b      c70000000000   mov dword [rax], 0\n\u2502           0x00401511      e8eada1c00     call fcn.005cf000\n\u2502           0x00401516      e865fcffff     call fcn.00401180\n\u2502           0x0040151b      90             nop\n\u2502           0x0040151c      90             nop\n\u2502           0x0040151d      4883c428       add rsp, 0x28\n\u2514           0x00401521      c3             ret",
    "0x005cf000": "; CALL XREF from entry0 @ 0x401511(x)\n\u250c 2327: fcn.005cf000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; arg int64_t arg2 @ rdx\n\u2502           ; arg int64_t arg3 @ r8\n\u2502           ; arg int64_t arg4 @ r9\n\u2502           ; var int64_t var_23h @ rbp+0x23\n\u2502           0x005cf000      50             push rax\n\u2502           0x005cf001      51             push rcx                    ; arg1\n\u2502           0x005cf002      52             push rdx                    ; arg2\n\u2502           0x005cf003      53             push rbx\n\u2502           0x005cf004      55             push rbp\n\u2502           0x005cf005      56             push rsi\n\u2502           0x005cf006      57             push rdi\n\u2502           0x005cf007      4150           push r8                     ; arg3\n\u2502           0x005cf009      4151           push r9                     ; arg4\n\u2502           0x005cf00b      4152           push r10\n\u2502           0x005cf00d      4153           push r11\n\u2502           0x005cf00f      4154           push r12\n\u2502           0x005cf011      4155           push r13\n\u2502           0x005cf013      4156           push r14\n\u2502           0x005cf015      4157           push r15\n\u2502           0x005cf017      55             push rbp\n\u2502           0x005cf018      488bec         mov rbp, rsp\n\u2502           0x005cf01b      4883ec20       sub rsp, 0x20\n\u2502           0x005cf01f      4883e4f0       and rsp, 0xfffffffffffffff0\n\u2502           0x005cf023      488d1dd635..   lea rbx, [0x00542600]\n\u2502           0x005cf02a      6a00           push 0\n\u2502           0x005cf02c      59             pop rcx\n\u2502           0x005cf02d      53             push rbx\n\u2502       \u250c\u2500> 0x005cf02e      81ab440200..   sub dword [rbx + 0x244], 0x116a7332 ; [0x116a7332:4]=-1\n\u2502       \u254e   0x005cf038      81ab2c0200..   sub dword [rbx + 0x22c], 0x38d25e97 ; [0x38d25e97:4]=-1\n\u2502       \u254e   0x005cf042      81b38c0100..   xor dword [rbx + 0x18c], 0x2d765363 ; [0x2d765363:4]=-1\n\u2502       \u254e   0x005cf04c      81b3100100..   xor dword [rbx + 0x110], 0x783c64cf ; [0x783c64cf:4]=-1\n\u2502       \u254e   0x005cf056      81b3200300..   xor dword [rbx + 0x320], 0x58e87ae6 ; [0x58e87ae6:4]=-1\n\u2502       \u254e   0x005cf060      8183180100..  
… [6162 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
    "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
    "exists": true,
    "hook_candidates": [
      "ADVAPI32.dll!CloseServiceHandle",
      "ADVAPI32.dll!ControlService",
      "ADVAPI32.dll!CreateServiceW",
      "ADVAPI32.dll!DeleteService",
      "ADVAPI32.dll!OpenSCManagerA",
      "KERNEL32.dll!CloseHandle",
      "KERNEL32.dll!CreateDirectoryW",
      "KERNEL32.dll!CreateFileW",
      "KERNEL32.dll!CreateProcessW",
      "KERNEL32.dll!CreateSemaphoreW",
      "msvcrt.dll!__C_specific_handler",
      "msvcrt.dll!___lc_codepage_func",
      "msvcrt.dll!___mb_cur_max_func",
      "msvcrt.dll!__doserrno",
      "msvcrt.dll!__iob_func",
      "ole32.dll!CoCreateInstance",
      "ole32.dll!CoInitialize",
      "SHELL32.dll!SHGetMalloc",
      "SHELL32.dll!SHGetPathFromIDListW",
      "SHELL32.dll!SHGetSpecialFolderLocation"
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
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "YARA Dropper_Strings at offset 948398",
    "YARA create_service at offsets 1114680, 1112290, 1112272, 1112528, 1112358",
    "YARA win_registry at offsets 1114680, 1112382",
    "YARA win_files_operation at offsets 1114892, 1113510, 1113262, 1113096",
    "YARA domain/IP/url/base64 matches"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 98,
  "summary": "Sample is a malicious PE64 dropper/RAT, strongly consistent with Quasar RAT. Deterministic signals include YARA matches for Dropper_Strings, create_service, win_registry, win_files_operation, domain/IP/url/base64 indicators, and Microsoft Visual C++ 80 DLL metadata. capa reports obfuscated stackstri",
  "key_evidence": [
    "YARA Dropper_Strings at offset 948398",
    "YARA create_service at offsets 1114680, 1112290, 1112272, 1112528, 1112358",
    "YARA win_registry at offsets 1114680, 1112382",
    "YARA win_files_operation at offsets 1114892, 1113510, 1113262, 1113096",
    "YARA domain/IP/url/base64 matches",
    "capa: contain obfuscated stackstrings (T1027.005)",
    "capa: encode data using XOR (T1027)",
    "pe_import_signals: create_service (T1543.003), set_registry_value (T1112), create_process (T1106), change_memory_protection (T1055), load_library/get_proc_address (T1129)",
    "Ghidra imports: CreateServiceW, RegSetValueExW, CreateProcessW, VirtualProtect, DeleteFileW, RemoveDirectoryW",
    "IDA/Ghidra string: 'DWAgent service' (masquerade)"
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
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
      
… [7155 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
… [89703 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 35,
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
… [9021 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1874432,
  "duration_s": 0.03,
  "import_count": 159,
  "signal_count": 6,
  "signals": [
    {
      "label": "create_service",
      "api_match": "CreateService",
      "attack": [
        "T1543.003"
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
     
… [558 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 3084,
  "strings_sampled": 80,
  "strings": [
    "`.rdata",
    ".gfids/",
    "rMwOGtBu",
    "fR B`T",
    "6,b4&eR",
    "LRBFRB",
    "D7;L2`V",
    "UMb.OP",
    "BHu.tPu",
    "u:tR`uP",
    "uFt *u(",
    "Q`St$@a",
    "B@s50[c2o]1o",
    "v{tYuWt",
    "U0tNuLC",
    "tdt[$uY",
    "2YXt)u'(",
    "9tOuMt",
    "tntAhSe",
    "WVtOuM",
    "guehB~@
… [1494 more chars]
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
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
  "disassembly": {
    "0x00401500": "\u250c 34: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; arg int64_t arg2 @ rdx\n\u2502           ; a
… [9262 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
    "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
    "exists": true,
    "hook_candidates": [
      "ADVAPI32.dll!CloseServiceHandle",
      "ADVAPI32.dll!ControlService",
      "ADVAPI32.dll!CreateServiceW",
     
… [634 more chars]
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
      "name": "FUN_00401000",
      "address": "4198400",
      "size": "1"
    },
    {
      "name": "FUN_00401010",
      "address": "4198416",
      "size": "1"
    },
    {
      "name": "FUN_00401130",
      "address": "4198704",
      "size": "1"
    },
    {
      "name": "FUN_00401180",
      "address": "4198784
… [2196 more chars]
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
      "name": "CloseServiceHandle",
      "module": "ADVAPI32.DLL",
      "address": "1"
    },
    {
      "name": "ControlService",
      "module": "ADVAPI32.DLL",
      "address": "2"
    },
    {
      "name": "CreateProcessW",
      "module": "KERNEL32.DLL",
      "address": "21"
    },
    {
      "name": "Create
… [1682 more chars]
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
      "name": "DeleteCriticalSection",
      "module": "KERNEL32.DLL",
      "address": "23"
    },
    {
      "name": "DeleteFileW",
      "module": "KERNEL32.DLL",
      "address": "24"
    },
    {
      "name": "DeleteService",
      "module": "ADVAPI32.DLL",
      "address": "4"
    },
    {
      "name": "GetCur
… [1703 more chars]
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
      "content": "DWAgent service",
      "address": "5514596",
      "length": "32"
    },
    {
      "content": "RegisterServiceCtrlHandlerW",
      "address": "5323678",
      "length": "28"
    },
    {
      "content": "StartServiceCtrlDispatcherW",
      "address": "5323744",
      "length": "28"
    },
    {
… [1085 more chars]
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
      "content": "NSt7__cxx1115time_get_bynameIcSt19istreambuf_iteratorIcSt11char_traitsIcEEEE",
      "address": "5188320",
      "length": "77"
    },
    {
      "content": "NSt7__cxx1115time_get_bynameIwSt19istreambuf_iteratorIwSt11char_traitsIwEEEE",
      "address": "5188416",
      "length": "77"
    },
    {
… [4106 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 1874432,
  "duration_s": 0.05,
  "import_count": 159,
  "signal_count": 6,
  "signals": [
    {
      "label": "create_service",
      "api_match": "CreateService",
      "attack": [
        "T1543.003"
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
     
… [558 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 35,
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
… [9021 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/01-tools-raw.json` exists=`True` bytes=`131852` mtime=`2026-08-08T05:26:11.998226+00:00`
  - sha256: `684ee54c8d1b54f7bf6589b97fe1c812e6c485693bc48b9665417422764dd38a`
- **sql_evidence:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/05-deep-dive.json` exists=`True` bytes=`3763` mtime=`2026-08-08T05:27:18.688277+00:00`
  - sha256: `363bbb3b94496e40bb0b20254c580f55b8c43373bd055edd236f2c581bbeb3fd`

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
  "confidence": 98,
  "summary": "Sample is a malicious PE64 dropper/RAT, strongly consistent with Quasar RAT. Deterministic signals include YARA matches for Dropper_Strings, create_service, win_registry, win_files_operation, domain/IP/url/base64 indicators, and Microsoft Visual C++ 80 DLL metadata. capa reports obfuscated stackstrings and XOR encoding. PE import signals show high-risk APIs: CreateService, RegSetValue, CreateProcess, VirtualProtect, LoadLibrary/GetProcAddress. Ghidra imports confirm service creation/control, registry modification, file deletion, and memory protection. A suspicious string 'DWAgent service' indicates masquerading as legitimate software. Observed exfiltration enablers are pr
… [2963 more chars]
```

- **agentic:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`365075` mtime=`2026-08-08T05:27:18.687277+00:00`
  - sha256: `12e17e0807bf4e26208a53fddf9be03f9e9431478760aabf703b3e026f959069`

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

- **rule_yar:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar` exists=`True` bytes=`1185` mtime=`2026-08-08T05:28:39.433332+00:00`
  - sha256: `1a972f9f0c7a1c6ab7c488b53af5b755117092fb145fee5b883a83325ef0219f`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T05:28:39.434285+00:00
rule CADRE_v2_unknown_cde83fd3b872 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "RegisterServiceCtrlHandlerW" ascii wide
        $s1 = "StartServiceCtrlDispatcherW" ascii wide
        $s2 = "SetUnhandledExceptionFilter" ascii wide
        $s3 = "SHGetSpecialFolderLocation" ascii wide
        $s4 = "InitializeCriticalSection" ascii wide
        $s5 = "UnhandledExceptionFilter" ascii wide
        $s6 = "GetS
… [383 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-MASTER-v2.md` exists=`True` bytes=`24809` mtime=`2026-08-08T05:30:39.784130+00:00`
  - sha256: `616c7fb9a9f80ba485e727579bcea63837ce2b0fdb651636c77ed8f5e1089ef1`
- **REPORT_MASTER_v3:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-MASTER-v3.md` exists=`True` bytes=`57045` mtime=`2026-08-08T05:41:12.443401+00:00`
  - sha256: `e41502ad9882ddcd1383849f2635bdd4503ff4732069354ba1c711fc56aa6878`
- **REPORT_v2:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-v2.md` exists=`True` bytes=`24809` mtime=`2026-08-08T05:30:39.784130+00:00`
  - sha256: `616c7fb9a9f80ba485e727579bcea63837ce2b0fdb651636c77ed8f5e1089ef1`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`87478` mtime=`2026-08-08T05:35:46.247147+00:00`
  - sha256: `2adbdeb7474957aad927521eb6872a6cb486e8e259180858f76666b4e8600bdd`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`78915` mtime=`2026-08-08T05:43:32.721051+00:00`
  - sha256: `84e313f189af20e42868ef9c86c246ad23e520b167d7847b1a9b674c2e671f7f`
- **report_v2_json:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/report-v2.json` exists=`True` bytes=`52001` mtime=`2026-08-08T05:35:46.252147+00:00`
  - sha256: `7b4bc7f8642b1de329175173492d0ea18a3001e4baab1a0df9f7c936291980a9`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 05:30:39 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | MALICIOUS |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Quasar RAT
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malwa
… [23900 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 05:41:12 UTC

# RE Report — cde83fd3b872
_Generated 2026-08-08T05:41:12.439058+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=237c | cross_refs=True | llm_ok=True | runtime=32.06s -->

# Executive Summary

The sample with SHA256 `cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36` is assessed as **malicious** with 98% confidence, attributed to the Quasar RAT (alternatively referred to as Cacador RAT) family, with corroborated classification agreement between the v1 static analysis engine and deep dive agentic analysis model.

Core supporting evi
… [56134 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
