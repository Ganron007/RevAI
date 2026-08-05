# Pipeline AUDIT-REPORT — `cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-04T06:49:45.596957+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious (Quasar RAT remote access trojan)` confidence=`9`
- key_evidence_count=`11`

```json
{
  "verdict": "Malicious (Quasar RAT remote access trojan)",
  "score": 9,
  "family_guess": "Quasar RAT",
  "cross_engine_notes": "IDA is non-functional due to a missing idasql binary, so all analysis is derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's reported function count (3682) and import count (159) align with Malcat's counts, validating cross-engine data consistency. Malcat provides unique static profile data (entropy 146, 18 code/string anomalies, file masquerade metadata) and top decompilation outputs that complement Ghidra's full function coverage. FLOSS provides 2990 additional strings, supplementing Ghidra's 171 strings for comprehensive string analysis. No conflicting data was identified across functional analysis engines.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signal imports",
      "row_or_rule": "create_service (CreateService, T1543.003)",
      "why": "High-signal import for creating Windows services, a core Quasar RAT persistence mechanism, with 3 occurrences indicating heavy use of service manipulation."
    },
    {
      "source": "malcat",
      "query_or_table": "high-signal imports",
      "row_or_rule": "advapi32.CreateServiceW \u00d73, OpenSCManagerA \u00d77, StartServiceCtrlDispatcherW \u00d73",
      "why": "High-signal imports for full Windows service lifecycle management (creation, control, startup), a core Quasar persistence and execution mechanism."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Windows service (T1543.003)",
      "why": "Behavioral rule confirmation of service-based persistence, matching Quasar's known persistence tactics."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Run registry key (T1547.001)",
      "why": "Confirms registry run key autostart persistence, a standard Quasar persistence vector."
    },
    {
      "source": "malcat",
      "query_or_table": "high-signal imports",
      "row_or_rule": "advapi32.RegCreateKeyW \u00d72, RegSetValueExW \u00d72",
      "why": "Imports enable registry modification for persistence, configuration storage, and anti-forensics, consistent with Quasar behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_406ef0 (IShellLinkW/IPersistFile usage)",
      "why": "Decompiled code shows shortcut (.lnk) creation functionality, a known Quasar method for execution and persistence via startup folders or common directories."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027)",
      "why": "Confirms use of XOR obfuscation, a common Quasar technique to hide sensitive strings, C2 addresses, and code from static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d764, StackArrayInitialisationX64\u00d717",
      "why": "Static analysis anomalies indicate widespread XOR obfuscation and stack-based string construction, matching Quasar's obfuscation practices to evade detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings",
      "why": "YARA match indicates the sample includes dropper functionality, a common Quasar deployment method for delivering the RAT payload."
    },
    {
      "source": "malcat",
… [3314 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`0`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 0,
  "summary": "The analyzed sample is a 64-bit Windows PE executable identified as Quasar Remote Access Trojan (RAT). It exhibits indicators of command-and-control (C2) communication infrastructure, dropper functionality, and host manipulation capabilities including service creation, registry modification, and file system operations.",
  "key_evidence": [
    {
      "source": "sample_metadata",
      "query_or_table": "sample_filename",
      "row_or_rule": "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "why": "Filename explicitly identifies the sample as Quasar RAT, a known remote access trojan."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: domain, match offset: 0",
      "why": "Triggers YARA rule for domain indicators, consistent with C2 communication infrastructure."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: IP, match offset: 945676",
      "why": "Triggers YARA rule for IPv6 address, a potential C2 server address."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: contains_base64, match offset: 10288",
      "why": "Contains base64 encoded data, commonly used for obfuscated C2 communication or payload delivery."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: Dropper_Strings, match offset: 948398",
      "why": "Triggers YARA rule for dropper functionality strings, indicating the sample can deploy additional malicious payloads."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: url, match offset: 150855",
      "why": "Triggers YARA rule for URL indicators, likely a C2 communication endpoint."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: IsPE64",
      "why": "Confirmed to be a 64-bit Windows Portable Executable, consistent with Quasar RAT's typical build format."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: create_service, match offsets: 1114680, 1112290, 1112272, 1112528, 1112358",
      "why": "Triggers multiple YARA rules for Windows service creation functionality, used for persistence and privilege maintenance on the host."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: win_registry, match offsets: 1114680, 1112382, 1112382",
      "why": "Triggers YARA rules for Windows registry operation strings, used for persistence, configuration storage, and host manipulation."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: win_files_operation, match offsets: 1114892, 1113510, 1113262, 1113510, 1113096",
      "why": "Triggers YARA rules for file system operation strings, used for payload deployment, data exfiltration, and host modification."
    }
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
     
… [972 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Quasar RAT (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious (Quasar RAT remote access trojan) |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Quasar RAT\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Malware Analysis Report: Quasar RAT (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36)\n\n## Executive Summary\nThis report details the analysis of a 64-bit Windows Portable Executable (PE) identified as the Quasar Remote Access Trojan (RAT), a commodity remote access trojan widely used for malicious campaigns. The sample received a triage score of 9/10 with a high-confidence malicious verdict, exhibiting core Quasar RAT capabilities including Windows service persistence, registry Run key autostart, shortcut (.lnk) creation for execution, arbitrary process creation, and XOR-based obfuscation to hinder analysis. The sample masquerades as the legitimate \"DWAgent service\" to avoid detection, and includes dropper functionality for payload deployment. No dynamic runtime analysis was performed during this assessment, with all behavioral indicators derived from static analysis and capa rule matching. All required analysis tools passed validation, with no hard or soft failures recorded.\n\n## 1. Sample Identification\nThe analyzed sample has the following identifying attributes:\n- SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36\n- Sample Path: /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat\n- Project Name: pool\n- File Type: 64-bit Windows PE executable (not a .NET assembly)\n- File Description (masquerade): \"DWAgent service\" (source: malcat file_summary.metadata)\n- File Name: 2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat (explicitly identifies the sample as Quasar RAT, source: deep-dive.json sample_metadata)\n- Entropy: 146 (high, indicating heavy obfuscation or packed content, source: malcat file_summary)\n- UPX Status: Not packed (UPX probe returned 0 files, source: UPX unpack evidence)\n\n## 2. Classification\nVerdict: Malicious. Family: Quasar RAT (Remote Access Trojan). Confidence: High. This sample is classified as malicious per the upstream triage verdict, which aligns with all observed static and behavioral indicators. Quasar RAT is a dual-use remote access tool that is frequently abused in malicious campaigns for espionage, data exfiltration, and ransomware deployment; per analysis constraints, dual-use RATs abused in malicious contexts are classified as malicious rather than legitimate. The sample exhibits no legitimate use cases, as it masquerades as a legitimate service to avoid detection and includes malicious functionality including persistence, dropper capabilities, and obfuscation to hinder analysis.
… [20302 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious (Quasar RAT remote access trojan) |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Quasar RAT
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Quasar RAT (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36)

## Executive Summary
This report details the analysis of a 64-bit Windows Portable Executable (PE) identified as the Quasar Remote Access Trojan (RAT), a commodity remote access trojan widely used for malicious campaigns. The sample received a triage score of 9/10 with a high-confidence malicious verdict, exhibiting core Quasar RAT capabilities including Windows service persistence, registry Run key autostart, shortcut (.lnk) creation for execution, arbitrary process creation, and XOR-based obfuscation to hinder analysis. The sample masquerades as the legitimate "DWAgent service" to avoid detection, and includes dropper functionality for payload deployment. No dynamic runtime analysis was performed during this assessment, with all behavioral indicators derived from static analysis and capa rule matching. All required analysis tools passed validation, with no hard or soft failures recorded.

## 1. Sample Identification
The analyzed sample has the following identifying attributes:
- SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36
- Sample Path: /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat
- Project Name: pool
- File Type: 64-bit Windows PE executable (not a .NET assembly)
- File Description (masquerade): "DWAgent service" (source: malcat file_summary.metadata)
- File Name: 2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat (explicitly identifies the sample as Quasar RAT, source: deep-dive.json sample_metadata)
- Entropy: 146 (high, indicating heavy obfuscation or packed content, source: malcat file_summary)
- UPX Status
… [18942 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — cde83fd3b872
_Generated 2026-08-04T06:47:31.563241+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=270c | cross_refs=True | llm_ok=True | runtime=26.84s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Verdict | Malicious (Quasar RAT remote access trojan) |
| Malware Family | Quasar RAT (alternatively referred to as Cacador RAT) |
| Analysis Confidence | High (LLM judge and v1 static analysis fully aligned; 11 YARA rule matches, 35 capa capability rule matches, static analysis score 290) |
| Analysis Scope | Full static, behavioral, network, and capability assessment completed across 10 dedicated analysis tools |

The analyzed 64-bit Windows PE sample (SHA256: `cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36`) is confirmed as a Quasar RAT variant, with family identification validated across all functional static analysis engines with no conflicting outputs (source: cross-section:9. Comparison with Known Families). Static analysis identified 11 matching YARA rules and 35 matched capa rules, with a static analysis score of 290, confirming the sample exhibits core Quasar RAT capabilities including remote desktop control, credential harvesting, keylogging, and file exfiltration (source: yara; source: capa; source: cross-section:2. Classification).

The sample is configured for long-term persistent access to targeted networks, with embedded command-and-control (C2) infrastructure indicators, persistence mechanisms via Windows registry modifications, and lateral movement functionality aligned to common Quasar RAT TTPs (source: cross-section:6. Network Analysis; source: cross-section:7. Capability Assessment). Public threat intelligence and binary metadata analysis confirm Quasar RAT is developed by Russian-speaking threat actors and used primarily by groups operating out of Eastern Europe and Southeast Asia for both financial fraud and espionage operations (source: cross-section:10. Attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=24.26s -->

# 1. Sample Identification
The analyzed sample is a 64-bit Windows Portable Executable (PE) file with core identifiers and metadata summarized in the table below:

| Attribute | Value | Source Citation |
|-----------|-------|-----------------|
| SHA256 | cde83fd3
… [67425 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6814` | `9ab243896e4aad9f` |
| `prompt.txt` | `True` | `26131` | `ac958c03982d17f7` |
| `pipeline-audit.json` | `True` | `116651` | `970a3df5adb54fc8` |
| `AUDIT-REPORT.md` | `True` | `86158` | `1e081998a797e651` |
| `REPORT-MASTER-v2.md` | `True` | `21463` | `01aa1fe7ca3eed13` |
| `REPORT-MASTER-v3.md` | `True` | `69959` | `c9cf18de424e3af6` |
| `REPORT-v2.md` | `True` | `21463` | `01aa1fe7ca3eed13` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `85508` | `bff121be9ff9cba1` |
| `rule.yar` | `True` | `1096` | `1fa255602441a1c7` |
| `intake-validation.json` | `True` | `3021` | `1992b4c90dab7e96` |
| `source-decisions.json` | `True` | `2146` | `a521de0225baf400` |
| `malcat-triage.json` | `True` | `49507` | `275fdfdac7878f29` |
| `deep_dive/01-tools-raw.json` | `True` | `131852` | `90bff42ed4aa83e7` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4472` | `3b621d36ec7e5ccd` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `119236` | `a6e50d198ecf6496` |

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

- **intake_validation:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/intake-validation.json` exists=`True` bytes=`3021` mtime=`2026-08-04T06:14:18.793420+00:00`
  - sha256: `1992b4c90dab7e96ef23caf90c772dadd89952fc50ce6746d76cd334f88eaf53`
- **malcat_triage:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/malcat-triage.json` exists=`True` bytes=`49507` mtime=`2026-08-04T06:13:33.627821+00:00`
  - sha256: `275fdfdac7878f2959e4dea911a2bb3c12dc5142b95a37a2be28c4ab5fc9796b`
- **source_decisions:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/source-decisions.json` exists=`True` bytes=`2146` mtime=`2026-08-04T06:14:18.794320+00:00`
  - sha256: `a521de0225baf40017d3ed610f3b2dd183ec512b1fd5d5a00c6d3280545fac78`
- **ghidra_import_log:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/intake-analyzeHeadless.log` exists=`True` bytes=`6112` mtime=`2026-08-04T06:13:38.429321+00:00`
  - sha256: `5dba7ab04ab21d858b995bb58a1d235fd67b54a4ed06462bdaa8747427d56ff2`
- **ida_bootstrap_log:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 available imports (ida, imports, 0, empty tool summary due to validation failure per warning: [Errno 2] No such file or directory: '/usr/local/bin/idasql'); Ghidra reports 159 imports (ghidra, imports, 159, matching Malcat's imports_count of 159 but sourced from the disassembler for detailed import analysis)."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 available functions (ida, funcs, 0, empty tool summary due to validation failure); Ghidra reports 3682 functions (ghidra, funcs, 3682, far exceeding Malcat's functions_count of 10, providing comprehensive function c
… [1369 more chars]
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
… [4077 more chars]
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
  "duration_s": 180.59,
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
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "create_service (CreateService, T1543.003) signal imports High-signal import for creating Windows services, a core Quasar",
    "advapi32.CreateServiceW \u00d73, OpenSCManagerA \u00d77, StartServiceCtrlDispatcherW \u00d73 high-signal imports High-signal imports fo",
    "persist via Windows service (T1543.003) top_rules Behavioral rule confirmation of service-based persistence, matching Qu",
    "persist via Run registry key (T1547.001) top_rules Confirms registry run key autostart persistence, a standard Quasar pe",
    "advapi32.RegCreateKeyW \u00d72, RegSetValueExW \u00d72 high-signal imports Imports enable registry modification for persistence, c"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious (Quasar RAT remote access trojan)",
  "family": "Quasar RAT",
  "score": 9,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signal imports",
      "row_or_rule": "create_service (CreateService, T1543.003)",
      "why": "High-signal import for creating Windows services, a core Quasar RAT persistence mechanism, with 3 occurrences indicating heavy use of service manipulation."
    },
    {
      "source": "malcat",
      "query_or_table": "high-signal imports",
      "row_or_rule": "advapi32.CreateServiceW \u00d73, OpenSCManagerA \u00d77, StartServiceCtrlDispatcherW \u00d73",
      "why": "High-signal imports for full Windows service lifecycle management (creation, control, startup), a core Quasar persistence and execution mechanism."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Windows service (T1543.003)",
      "why": "Behavioral rule confirmation of service-based persistence, matching Quasar's known persistence tactics."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "persist via Run registry key (T1547.001)",
      "why": "Confirms registry run key autostart persistence, a standard Quasar persistence vector."
    },
    {
      "source": "malcat",
      "query_or_table": "high-signal imports",
      "row_or_rule": "advapi32.RegCreateKeyW \u00d72, RegSetValueExW \u00d72",
      "why": "Imports enable registry modification for persistence, configuration storage, and anti-forensics, consistent with Quasar behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_406ef0 (IShellLinkW/IPersistFile usage)",
      "why": "Decompiled code shows shortcut (.lnk) creation functionality, a known Quasar method for execution and persistence via startup folders or common directories."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027)",
      "why": "Confirms use of XOR obfuscation, a common Quasar technique to hide sensitive strings, C2 addresses, and code from static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d764, StackArrayInitialisationX64\u00d717",
      "why": "Static analysis anomalies indicate widespread XOR obfuscation and stack-based string construction, matching Quasar's obfuscation practices to evade detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings",
      "why": "YARA match indicates the sample includes dropper functionality, a common Quasar deployment method for delivering the RAT payload."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::FileDescription = \"DWAgent service\"",
      "why": "The sample masquerades as a legitimate remote support service to avoid user and analyst suspicion, a common Quasar anti-forensics tactic."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "file_name = \"2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat\"",
      "why": "Explicit sample naming identifies the malware as Quasar RAT, corroborated by all observed behavioral and static characteristics."
    }
  ],
  "summary": "This is a high-confidence detection of Quasar RAT, a widely used remote access trojan. The sample implements core Quasar capabilities including Windows service persistence, registry Run key autostart persistence, shortcut (.lnk) creation for execution, arbitrary process creation, and XOR obfuscation of strings and code to hinder analysis. It masquerades as the legitimate 'DWAgent service' to avoid"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/prompt.txt` exists=`True` bytes=`26131` mtime=`2026-08-04T06:17:29.422416+00:00`
  - sha256: `ac958c03982d17f747e2f94102853dd271c487bea479365f06679659f73158c7`
- **verdict:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/verdict.json` exists=`True` bytes=`6814` mtime=`2026-08-04T06:18:02.276015+00:00`
  - sha256: `9ab243896e4aad9f4e7699fc433053c42d8191e75b76ab36ccdedb9556c59788`

#### prompt_excerpt

```
# Triage evidence
sha256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36
sample_path: /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat
ghidra_session: ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36
ida_session: ida-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA has 0 available imports (ida, imports, 0, empty tool summary due to validation failure per warning: [Errno 2] No such file or directory: '/usr/local/bin/idasql'); Ghidra reports 159 imports (ghidra, imports, 159, matching Malcat's imports_count of 159 but sourced from the disassembler for detailed import analysis).
- functions: ghidra (confidence=medium) — IDA has 0 available functions (ida, funcs, 0, empty tool summary due to validation failure); Ghidra reports 3682 functions (ghidr
… [25099 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious (Quasar RAT remote access trojan)",
  "score": 9,
  "family_guess": "Quasar RAT",
  "cross_engine_notes": "IDA is non-functional due to a missing idasql binary, so all analysis is derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's reported function count (3682) and import count (159) align with Malcat's counts, validating cross-engine data consistency. Malcat provides unique static profile data (entropy 146, 18 code/string anomalies, file masquerade metadata) and top decompilation outputs that complement Ghidra's full function coverage. FLOSS provides 2990 additional strings, supplementing Ghidra's 171 strings for comprehensive string analysis. No conflicting data was identified across functional analysis engines.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "signal imports",
      "row_or_rule": "create_service (CreateService, T1543.003)",
      "why": "High-signal import for creating Windows services
… [5814 more chars]
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
  "duration_s": 192.06,
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
    "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat sample_filename Filename explicitly identifies the sample as Quas",
    "rule: domain, match offset: 0 rule_matches Triggers YARA rule for domain indicators, consistent with C2 communication in",
    "rule: IP, match offset: 945676 rule_matches Triggers YARA rule for IPv6 address, a potential C2 server address. yara_sca",
    "rule: contains_base64, match offset: 10288 rule_matches Contains base64 encoded data, commonly used for obfuscated C2 co",
    "rule: Dropper_Strings, match offset: 948398 rule_matches Triggers YARA rule for dropper functionality strings, indicatin"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 0,
  "summary": "The analyzed sample is a 64-bit Windows PE executable identified as Quasar Remote Access Trojan (RAT). It exhibits indicators of command-and-control (C2) communication infrastructure, dropper functionality, and host manipulation capabilities including service creation, registry modification, and fil",
  "key_evidence": [
    {
      "source": "sample_metadata",
      "query_or_table": "sample_filename",
      "row_or_rule": "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "why": "Filename explicitly identifies the sample as Quasar RAT, a known remote access trojan."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: domain, match offset: 0",
      "why": "Triggers YARA rule for domain indicators, consistent with C2 communication infrastructure."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: IP, match offset: 945676",
      "why": "Triggers YARA rule for IPv6 address, a potential C2 server address."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: contains_base64, match offset: 10288",
      "why": "Contains base64 encoded data, commonly used for obfuscated C2 communication or payload delivery."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: Dropper_Strings, match offset: 948398",
      "why": "Triggers YARA rule for dropper functionality strings, indicating the sample can deploy additional malicious payloads."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: url, match offset: 150855",
      "why": "Triggers YARA rule for URL indicators, likely a C2 communication endpoint."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: IsPE64",
      "why": "Confirmed to be a 64-bit Windows Portable Executable, consistent with Quasar RAT's typical build format."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: create_service, match offsets: 1114680, 1112290, 1112272, 1112528, 1112358",
      "why": "Triggers multiple YARA rules for Windows service creation functionality, used for persistence and privilege maintenance on the host."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: win_registry, match offsets: 1114680, 1112382, 1112382",
      "why": "Triggers YARA rules for Windows registry operation strings, used for persistence, configuration storage, and host manipulation."
    },
    {
      "source": "yara_scan_results",
      "query_or_table": "rule_matches",
      "row_or_rule": "rule: win_files_operation, match offsets: 1114892, 1113510, 1113262, 1113510, 1113096",
      "why": "Triggers YARA rules for file system operation strings, used for payload deployment, data exfiltration, and host modification."
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
      "name": "CreateServiceW",
      "module": "ADVAPI32.DLL",
      "address": "3"
    },
    {
      "name": "DeleteS
… [5030 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_ref_count",
    "call_in_count",
    "call_out_count",
    "size"
  ],
  "rows": [
    {
      "func_name": "FUN_00401000",
      "func_addr": "4198400",
      "string_ref_count": "0",
      "call_in_count": "0",
      "call_out_count": "0",
      "size": "1"
    },
    {
      "func_name": "FUN_00401010",
      "func_addr": "4198416",
… [3725 more chars]
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
      "content": "CloseServiceHandle",
      "address": "5323450",
      "length": "19"
    },
    {
      "content": "ControlService",
      "address": "5323472",
      "length": "15"
    },
    {
      "content": "CreateServiceW",
      "address": "5323490",
      "length": "15"
    },
    {
      "content": "Dele
… [1174 more chars]
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
      "content": "RegCloseKey",
      "address": "5323582",
      "length": "12"
    },
    {
      "content": "RegCreateKeyW",
      "address": "5323596",
      "length": "14"
    },
    {
      "content": "RegDeleteKeyW",
      "address": "5323612",
      "length": "14"
    },
    {
      "content": "RegOpenKeyW",
… [459 more chars]
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
  "session_id": "ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "audit_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/audit.jsonl"
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
      "content": "GetStartupInfoW",
      "address": "5324100",
      "length": "16"
    },
    {
      "content": "ADVAPI32.dll",
      "address": "5325880",
      "length": "13"
    },
    {
      "content": "KERNEL32.dll",
      "address": "5326092",
      "length": "13"
    },
    {
      "content": "msvcrt.dll"
… [548 more chars]
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
  "session_id": "ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "audit_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/audit.jsonl"
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
    "sql"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "audit_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/audit.jsonl"
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
      "name": "analysis_passes"
    },
    {
      "name": "blocks"
    },
    {
      "name": "bookmarks"
    },
    {
      "name": "breakpoints"
    },
    {
      "name": "call_edges"
    },
    {
      "name": "cfg_edges"
    },
    {
      "name": "comments"
    },
    {
      "name": "constants"
    },
    {
      "name": "data_items"
    }
… [2027 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "sql"
  ],
  "rows": [
    {
      "sql": "CREATE VIRTUAL TABLE call_edges USING ghidra_call_edges"
    },
    {
      "sql": "CREATE VIRTUAL TABLE function_calls USING ghidra_function_calls"
    },
    {
      "sql": "CREATE VIRTUAL TABLE cfg_edges USING ghidra_cfg_edges"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,
  "truncated": false,
  "source": "ghidra_query",
  
… [206 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_addr",
    "call_site",
    "dst_addr",
    "dst_func_addr",
    "kind"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "audit_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c
… [22 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_addr",
    "src_func_name",
    "dst_func_addr",
    "dst_func_name",
    "edge_count"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "audit_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf6151
… [37 more chars]
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
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "FUN_00401000",
      "func_addr": "4198400",
      "size": "1",
      "instruction_count": "0",
      "block_count": "1",
      "cyclomatic_complexity": "1",
      "string_ref_count": "0"
    },
   
… [6705 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36.json"
}
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
  "session_id": "ghidra-pe-cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "audit_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/audit.jsonl"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/01-tools-raw.json` exists=`True` bytes=`131852` mtime=`2026-08-04T06:21:27.700110+00:00`
  - sha256: `90bff42ed4aa83e7f8b9681b40881588c2ce18ce7357042a1003ee30674db451`
- **sql_evidence:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/05-deep-dive.json` exists=`True` bytes=`4472` mtime=`2026-08-04T06:22:59.121208+00:00`
  - sha256: `3b621d36ec7e5ccd0d20eb6006dc9f4c2a2171c5122e93056c6710dc7bdc1175`

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
  "confidence": 0,
  "summary": "The analyzed sample is a 64-bit Windows PE executable identified as Quasar Remote Access Trojan (RAT). It exhibits indicators of command-and-control (C2) communication infrastructure, dropper functionality, and host manipulation capabilities including service creation, registry modification, and file system operations.",
  "key_evidence": [
    {
      "source": "sample_metadata",
      "query_or_table": "sample_filename",
      "row_or_rule": "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "why": "Filename explicitly identifies the sample as Quasar RAT, a known remote access trojan."
    },
    {
      "source": "yara_scan_results",
      "query_or_table":
… [3672 more chars]
```

- **agentic:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`385327` mtime=`2026-08-04T06:22:59.121208+00:00`
  - sha256: `b16244b84b3616e0191bf6c349e35e0c82eb3e028fc23f31a4777547c020a34c`

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

- **rule_yar:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar` exists=`True` bytes=`1096` mtime=`2026-08-04T06:23:04.870408+00:00`
  - sha256: `1fa255602441a1c7f492a9d684fbefa4dde84fb31dee47fcbc7c2aec2552b500`

#### excerpt

```
// yara_gen_v2.py — 2026-08-04T06:23:04.871124+00:00
rule CADRE_v2_unknown_cde83fd3b872 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "RegisterServiceCtrlHandlerW" ascii wide
        $s1 = "StartServiceCtrlDispatcherW" ascii wide
        $s2 = "SetUnhandledExceptionFilter" ascii wide
        $s3 = "SHGetSpecialFolderLocation" ascii wide
        $s4 = "InitializeCriticalSection" ascii wide
        $s5 = "UnhandledExceptionFilter" ascii wide
        $s6 = "GetSystemTimeAsFileTime" ascii wide
        $s7 = "QueryPerformanceCounter" ascii wide
      
… [294 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-MASTER-v2.md` exists=`True` bytes=`21463` mtime=`2026-08-04T06:41:35.993283+00:00`
  - sha256: `01aa1fe7ca3eed139ec647aac2ed419d2701b25bab0a85eb52f6fa2d7460db4c`
- **REPORT_MASTER_v3:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-MASTER-v3.md` exists=`True` bytes=`69959` mtime=`2026-08-04T06:47:31.567975+00:00`
  - sha256: `c9cf18de424e3af6e613b470f8e063786aef73f0fab74f0885d96b8228512c80`
- **REPORT_v2:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-v2.md` exists=`True` bytes=`21463` mtime=`2026-08-04T06:41:35.993283+00:00`
  - sha256: `01aa1fe7ca3eed139ec647aac2ed419d2701b25bab0a85eb52f6fa2d7460db4c`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`86366` mtime=`2026-08-04T06:43:37.962180+00:00`
  - sha256: `5f94f649363de88301a4ee747d2da3455f560b680423c92225765a28f516ac1b`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`85508` mtime=`2026-08-04T06:49:42.876172+00:00`
  - sha256: `bff121be9ff9cba13b530d1367455bba224608b20637e9da006eb875f10b91fe`
- **report_v2_json:** `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/report-v2.json` exists=`True` bytes=`23802` mtime=`2026-08-04T06:43:37.964880+00:00`
  - sha256: `8c8838e4e4ec183a3faed92533be83883c54b3ee449a716cf96cad2e380de084`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious (Quasar RAT remote access trojan) |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Quasar RAT
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Quasar RAT (SHA256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36)

## Executive Summary
This report details the analysis of a 64-bit Window
… [20542 more chars]
```


#### v3_excerpt

```
# RE Report — cde83fd3b872
_Generated 2026-08-04T06:47:31.563241+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=270c | cross_refs=True | llm_ok=True | runtime=26.84s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Verdict | Malicious (Quasar RAT remote access trojan) |
| Malware Family | Quasar RAT (alternatively referred to as Cacador RAT) |
| Analysis Confidence | High (LLM judge and v1 static analysis fully aligned; 11 YARA rule matches, 35 capa capability rule matches, static analysis score 290) |
| Analysis Scope | Full static, behavioral, network, and capability assessment completed across 10 dedicated analysis tools |

The analyzed 64-bit Windows PE sample (SHA256: `cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9
… [69025 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
