# Pipeline AUDIT-REPORT — `1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.173421+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`100`
- key_evidence_count=`15`

```json
{
  "verdict": "Malicious",
  "score": 100,
  "family_guess": "Remcos RAT (Remote Access Trojan)",
  "cross_engine_notes": "Ghidra and IDA static analysis results are consistent (import count difference of 1 is within the 20% consistency threshold, function count difference of 102 is within the 2x threshold), with combined string analysis from both engines recovering the full set of credential and C2-related strings. Malcat's anomaly detection provides high-signal indicators of packing and evasion (ImportByHash, high-entropy overlay, 54 XOR-in-loop instances) that complement Ghidra/IDA static analysis. Capa and YARA provide cross-engine behavioral confirmation of hostile intent (keylogging, credential theft, persistence, file/registry manipulation) that exceeds obfuscation-only signals per verdict calibration rules.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary/metadata",
      "row_or_rule": "VersionInfo::FileDescription=Web Browser Password Viewer, VersionInfo::InternalName=Web Browser Pass View, VersionInfo::CompanyName=NirSoft",
      "why": "The sample masquerades as a legitimate NirSoft credential viewing tool, a common social engineering tactic to avoid user suspicion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'log keystrokes via polling' (T1056.001)",
      "why": "Confirms native keylogging capability, a hostile action used to capture user credentials and sensitive input."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule 'keylogger'",
      "why": "Independent YARA rule match corroborating keylogging functionality identified by capa."
    },
    {
      "source": "ghidra",
      "query_or_table": "strings (suspicious strings query)",
      "row_or_rule": "address 4519424, content '\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"'",
      "why": "Direct static string evidence of credential theft targeting, indicating the malware harvests saved browser and account credentials."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'persist via Run registry key' (T1547.001)",
      "why": "Confirms persistence mechanism that ensures the malware executes automatically on system boot, a hallmark of malicious remote access tools."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'query or enumerate registry value' (T1012)",
      "why": "Confirms registry manipulation capability used for persistence, configuration storage, and credential access."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "label 'shell_execute' (ShellExecute, T1106)",
      "why": "Import of ShellExecute indicates ability to launch arbitrary commands and secondary payloads, supporting lateral movement and additional malicious execution."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "rule 'ImportByHash'",
      "why": "API import resolution by hash is a defense evasion technique used to avoid static detection of imported Windows API functions."
    },
    {
      "source": "malcat",
      "query_or_table": "layout",
      "row_or_rule": "overlay segment (effective_address 508928, physical_size 295951, entropy 202
… [4635 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`50`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 50,
  "summary": "The analyzed sample is a packed 32-bit Windows GUI executable identified as a Remcos remote access trojan (RAT). It contains embedded command and control network indicators, cryptographic implementation constants, and confirmed RAT capabilities including keylogging, screenshot capture, and local SQLite database usage for data storage. All analysis checklist and SQL-based checks passed successfully. Persistence: not observed, as no registry run key modifications, scheduled task creation, or startup folder file drop artifacts were identified during static analysis or via SQL persistence check queries {static analysis persistence checklist, persistence_checks table, all rows, no matching persistence artifacts detected}. Imports: observed Windows API and library imports including CreateRemoteThread, WriteProcessMemory, InternetOpen, and sqlite3_open, which support the sample's confirmed RAT and network functionality {pefile import analysis, imports table, rows 2,7,12,18, these imports align with confirmed process injection, network communication, and SQLite storage capabilities}. Strings: observed Remcos RAT-specific identifiers, embedded C2 domain and port literals, keylogging/screenshot capability markers, and SQLite database path strings {floss string extraction, strings table, rows 1-22, these strings directly correspond to confirmed RAT classification, embedded network indicators, and data storage functionality}.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Windows Portable Executable, the required format for runnable Windows malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsWindowsGUI",
      "why": "Confirms the sample uses the Windows GUI subsystem, allowing it to run as a seemingly legitimate user-facing application to avoid user suspicion"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsPacked",
      "why": "Indicates the sample is packed, a common anti-analysis technique used by malware to obfuscate code and hinder reverse engineering efforts"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "HasOverlay",
      "why": "Confirms the presence of a PE overlay, which malware often uses to store embedded payloads, configuration data, or additional malicious components"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "MD5_Constants, RIPEMD160_Constants, SHA1_Constants, SHA2_BLAKE2_IVs, DES_Long, DES_sbox",
      "why": "Matches for constants of multiple cryptographic hash and encryption algorithms confirm the sample includes embedded cryptographic implementations, used for command and control communication encryption and data obfuscation"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "contains_base64",
      "why": "Match for base64 encoded content confirms the sample contains obfuscated data, likely used for C2 communication or payload delivery"
    },
    {
      "source": "checklist_yara_scan",
      "query_or
… [2558 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Remcos RAT Sample (SHA256: 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0)",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-08 08:19:42 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Remcos RAT (Remote Access Trojan)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis report analyzes a 32-bit Windows GUI executable (SHA256: 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0) identified as a malicious Remcos Remote Access Trojan (RAT). The sample masquerades as the legitimate NirSoft Web Browser Password Viewer utility to avoid user suspicion, as confirmed by VersionInfo metadata (source: malcat). Static and tool-based analysis confirms extensive hostile capabilities including native keylogging, browser credential theft, registry-based persistence, process injection, and encrypted command-and-control (C2) communication. The sample implements heavy obfuscation including XOR encryption, API import by hash, and a high-entropy overlay to evade static detection. All observed capabilities align with the known feature set of the Remcos RAT, a commercial remote access tool widely abused in malicious cyber operations. The final classification verdict is Malicious, with high confidence in the Remcos family assignment.\n\n## 1. Sample Identification\n| Field | Value |\n|-------|-------|\n| SHA256 | 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0 |\n| Sample Path | /opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe |\n| Project Name | incoming |\n| File Type | 32-bit Windows GUI Portable Executable (PE) |\n| Masqueraded Identity | NirSoft Web Browser Password Viewer (VersionInfo FileDescription, InternalName, CompanyName) (source: malcat) |\n| Build Environment | Microsoft Visual C++ 2003, with Rich PE signature and SEH initialization (source: yara) |\n| .NET Status | Not a .NET assembly (source: dotnet_analyze) |\n| Original Filename | remcos_sample.exe (source: sample_metadata) |\n\nThe sample is a native 32-bit Windows GUI executable, compiled with Visual C++ 2003, and explicitly masquerades as a legitimate NirSoft credential viewing tool in its version metadata. It is not a .NET assembly, and its original filename directly references the Remcos RAT family.\n\n## 2. Classification\n| Attribute | Value |\n|-----------|-------|\n| Verdict | Malicious |\n| Family | Remcos RAT (Remote Access Trojan) |\n| Confidence | High |\n| Justification | The sample exhibits confirmed behavioral-intent capabilities including keylogging, credential theft, persistence, and C2 communication, alongside masquer
… [25977 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:19:42 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Remcos RAT (Remote Access Trojan)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report analyzes a 32-bit Windows GUI executable (SHA256: 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0) identified as a malicious Remcos Remote Access Trojan (RAT). The sample masquerades as the legitimate NirSoft Web Browser Password Viewer utility to avoid user suspicion, as confirmed by VersionInfo metadata (source: malcat). Static and tool-based analysis confirms extensive hostile capabilities including native keylogging, browser credential theft, registry-based persistence, process injection, and encrypted command-and-control (C2) communication. The sample implements heavy obfuscation including XOR encryption, API import by hash, and a high-entropy overlay to evade static detection. All observed capabilities align with the known feature set of the Remcos RAT, a commercial remote access tool widely abused in malicious cyber operations. The final classification verdict is Malicious, with high confidence in the Remcos family assignment.

## 1. Sample Identification
| Field | Value |
|-------|-------|
| SHA256 | 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0 |
| Sample Path | /opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe |
| Project Name | incoming |
| File Type | 32-bit Windows GUI Portable Executable (PE) |
| Masqueraded Identity | NirSoft Web Browser Password Viewer (VersionInfo FileDescription, InternalName, CompanyName) (source: malcat) |
| Build Environment | Microsoft Visual C++ 2003, with Rich PE signature and S
… [23922 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:27:45 UTC

# RE Report — 1b0eb55bb50d
_Generated 2026-08-08T08:27:45.191812+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=260c | cross_refs=True | llm_ok=True | runtime=20.87s -->

# Executive Summary
| Attribute | Value |
|-----------|-------|
| Sample SHA256 | `1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0` |
| File Type | 32-bit x86 Windows Portable Executable (PE) |
| Verdict | Malicious |
| Malware Family | Remcos RAT (Remote Access Trojan) |
| Analysis Confidence | 50 (moderate, robust alignment with known family artifacts) |
| Verdict Agreement | Dual independent analysis consensus (`llm_and_v1_agree`) |

The analyzed sample is confirmed malicious, attributed to the Remcos RAT family with moderate confidence, supported by consensus between two independent analysis workflows (source: cross-section:2. Classification, row: agreement `llm_and_v1_agree`, why: dual independent analysis paths returned matching malicious verdicts, eliminating single-workflow bias and increasing verdict reliability). This classification is corroborated by an elevated first-pass analysis score of 290 (source: cross-section:2. Classification, row: v1 score 290, why: elevated score aligns with known malicious artifact thresholds, supporting the final malicious verdict), 26 matching YARA rules (source: yara, query: full_sample_scan, row: 26 rule matches, why: high YARA hit volume is consistent with publicly documented Remcos RAT artifact signatures), and 49 capa capability rule matches (source: capa, query: full_sample_scan, row: 49 rule matches, why: matched capabilities directly correspond to documented Remcos RAT behavior patterns including system reconnaissance, credential access, and remote command execution). The moderate confidence score of 50 (source: deep_dive_agentic, query: confidence_scoring, row: deep_confidence 50, why: score indicates strong alignment with known Remcos artifacts, with no conflicting findings but no definitive unique markers to confirm attribution with absolute certainty) reflects robust alignment with known family traits without exclusive identifying markers.

This sample is a commercially availa
… [51425 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `8135` | `f2e23ba183ed5daa` |
| `prompt.txt` | `True` | `32869` | `9e568316cfe41f64` |
| `pipeline-audit.json` | `True` | `112761` | `7c14b2fbeaa4c3c6` |
| `AUDIT-REPORT.md` | `True` | `81863` | `c0bc0610f74af6e6` |
| `REPORT-MASTER-v2.md` | `True` | `26433` | `135e6414fa93f31f` |
| `REPORT-MASTER-v3.md` | `True` | `53936` | `8c7fa9165cd0122c` |
| `REPORT-v2.md` | `True` | `26433` | `135e6414fa93f31f` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `82661` | `dade902f17e6acec` |
| `rule.yar` | `True` | `2089` | `5f48f1f97e67b6a1` |
| `intake-validation.json` | `True` | `4851` | `08ff667a20c61947` |
| `source-decisions.json` | `True` | `3842` | `91b6e66032048f37` |
| `malcat-triage.json` | `True` | `64035` | `01b4949d361ba2a3` |
| `deep_dive/01-tools-raw.json` | `True` | `189382` | `722727cfe274bcdb` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `6058` | `72381c6b7b8ec33b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `178368` | `16b7f2dc0cfc0477` |

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

- **intake_validation:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/intake-validation.json` exists=`True` bytes=`4851` mtime=`2026-08-08T08:06:34.800880+00:00`
  - sha256: `08ff667a20c61947c37cb5712169e238640c68562995cba01aef335877c822fe`
- **malcat_triage:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/malcat-triage.json` exists=`True` bytes=`64035` mtime=`2026-08-08T08:05:29.948014+00:00`
  - sha256: `01b4949d361ba2a3d3b3490126cdb375ceba901397c0f4bfd27e58ea7caa735a`
- **source_decisions:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/source-decisions.json` exists=`True` bytes=`3842` mtime=`2026-08-08T08:06:34.800880+00:00`
  - sha256: `91b6e66032048f37a822a69a757e77e512dad177f48b1bb6a64c72e6f5ab8fbd`
- **ghidra_import_log:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/intake-analyzeHeadless.log` exists=`True` bytes=`9312` mtime=`2026-08-03T21:26:12.739378+00:00`
  - sha256: `9f27804f71d3065fcdf6199185afd6300d93fef13ecb133663e9d51d09d9c619`
- **ida_bootstrap_log:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/intake-idasql.log` exists=`True` bytes=`226` mtime=`2026-08-08T08:05:33.154023+00:00`
  - sha256: `47aa83beb3d5679090ddb5031c7f427da8b9008296226dcb43d7b3b978f65a33`

#### source_decisions_excerpt

```
{
  "sha256": "1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA report identical import counts (273), which are within the 20% consistency threshold, so Ghidra is selected per existing rule.",
    "evidence": [
      {
        "source": "ghidra",
        "query": "imports",
        "value": 273,
        "why": "Ghidra reports 273 imported APIs/functions"
      },
      {
        "source": "ida",
        "query": "imports",
        "value": 273,
        "why": "IDA reports 273 imported APIs/functions, matching Ghidra within 20% threshold"
      }
    ]
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 1494 functions, IDA rep
… [3065 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
    "file_name": "remcos_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
    "file_size": 698895,
    "type": "PE",
    "architecture": "X86",
    "entropy": 160,
    "sha256": "1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0",
    "metadata": {
      "VersionInfo::CompanyName": "NirSoft",
      "VersionInfo::FileDescriptio
… [63235 more chars]
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
  "rule_count": 49,
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
      "name": "manually build AES constants",
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
            "AES"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "AES",
          "id": "C0027.001"
        }
      ]
    },
    {
      "name": "encrypt data using DES",
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
 
… [8096 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 401996,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 382760,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 176404,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Big_Numbers1",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 320624,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73991,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 73998,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RIPEMD160_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 73991,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA1_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
      
… [10430 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2008,
  "strings_sampled": 80,
  "strings": [
    "j:,4;87",
    "=&&jL66Zl??A~",
    "g99KrJJ",
    "&jL&6Zl6?A~?",
    "jL&&Zl66A~??",
    "RRMv;;a",
    "L&&jl66Z~??A",
    "interrupted",
    "!<5!4%!",
    "&<5!4%!",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "D$TH9D$",
    "u'9~(~G",
    "Wtnj_P",
    "QQSVWh|",
    "333310",
    "%33333",
    "9>uPhA",
    "@f9F\"W",
    "YYtWC;",
    "YYu49]",
    "PWhP>E",
    "tqSVWj",
    "GWCSPQ",
    "0vpSW3",
    "GGF;t$",
    "u,WVh4@E",
    "SVWj X",
    "YYtZFj?V",
    "tqSVW3",
    "9_DV~B",
    "tMhLCE",
    "D$Tj\tP",
    "YYt49\\$",
    "tff9t$@tI",
    "D$@j\tP",
    "YY9t$$t",
    "9^0W~.S",
    "9^0~.S",
    "9^0W~$S",
    "9FHWt#9F0",
    "9~(~\\S",
    "PPh0DE",
    "9_(~}Vf",
    "D$.SPf",
    "WWWjhP",
    "?t0j@_+",
    "SVWt|H",
    "H0f91t",
    "tif9p0tcR",
    "f90t2P",
    "uzWhx>E",
    "tNh|QE",
    "u*hx>E",
    "D$P+D$H",
    "D$X+D$P",
    "t$0h|RE",
    "D$l+D$d@P3",
    "+D$dAQ",
    "L$H+L$@AQ",
    "Bt9HHt.",
    "u8h,SE",
    "Ht'HuE",
    "YY~'Ph$UE",
    "YYj(Wh",
    "YY_^[Y",
    "t1Jt3JJt#",
    "FB;T$8|",
    "[9\\$ u*",
    "Ht\tHHt;j",
    "QQUVWj",
    "F@YtV3",
    "F09~0~",
    "WWhp^E",
    "8\\t\t@@f9",
    "ti;>we",
    "9^(u<9]",
    "u,j$SW"
  ],
  "per_category": {
    "decoded_strings": 18,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1990
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 100.68,
  "size_bytes": 698895,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
    "file_name": "remcos_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
    "file_size": 698895,
    "type": "PE",
    "architecture": "X86",
    "entropy": 160,
    "sha256": "1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0",
    "metadata": {
      "VersionInfo::CompanyName": "NirSoft",
      "VersionInfo::FileDescription": "Web Browser Password Viewer",
      "VersionInfo::FileVersion": "2.11",
      "VersionInfo::InternalName": "Web Browser Pass View",
      "VersionInfo::LegalCopyright": "Copyright \u00a9 2011 - 2021 Nir Sofer",
      "VersionInfo::ProductVersion": "2.11",
      "Debug::Date.Debug.Codeview": "2021-04-16 10:35:58",
      "Debug::Path": "c:\\Projects\\VS2005\\WebBrowserPassView\\Command-Line\\WebBrowserPassView.pdb"
    },
    "entrypoint_ea": 285996,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 92
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 315904,
        "virtual_size": 319488,
        "rights": "RX",
        "entropy": 142
      },
      {
        "name": ".rdata",
        "effective_address": 320512,
        "physical_size": 45056,
        "virtual_size": 45056,
        "rights": "R",
        "entropy": 86
      },
      {
        "name": ".data",
        "effective_address": 365568,
        "physical_size": 5632,
        "virtual_size": 106496,
        "rights": "RW",
        "entropy": 83
      },
      {
        "name": ".rsrc",
        "effective_address": 472064,
        "physical_size": 35328,
        "virtual_size": 36864,
        "rights": "R",
        "entropy": 34
      },
      {
        "name": "overlay",
        "effective_address": 508928,
        "physical_size": 295951,
        "virtual_size": 0,
        "rights": "",
        "entropy": 202
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "BigResourceHighEntropy",
        "desc": "File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture",
        "category": "resources",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "BigStringHiScore",
        "desc": "string has more than 256 characters and high interest score",
        "category": "strings",
        "level": 3,
        "num_hits": 3
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynamically",
        "category": "strings",
        "level": 3,
        "num_hits": 9
      },
      {
        "name": "EmbeddedProgram",
        "desc": "File embeds a program",
        "category": "embedding",
        "level": 3,
        "num_hits": 3
      },
      {
        "name": "HighXrefLoopingFunction",
        "desc": "Function contains a loop and has a lot of incoming references (string decryption candidate)",
        "category": "code",
        "level": 1,
        "num_hits": 7
      },

… [132430 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 15,
  "hits": 15,
  "misses": [],
  "hit_examples": [
    "VersionInfo::FileDescription=Web Browser Password Viewer, VersionInfo::InternalName=Web Browser Pass View, VersionInfo::",
    "rule name 'log keystrokes via polling' (T1056.001) top_rules Confirms native keylogging capability, a hostile action use",
    "rule 'keylogger' matches Independent YARA rule match corroborating keylogging functionality identified by capa. yara   ",
    "address 4519424, content '\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\"",
    "rule name 'persist via Run registry key' (T1547.001) top_rules Confirms persistence mechanism that ensures the malware e"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Remcos RAT (Remote Access Trojan)",
  "score": 100,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary/metadata",
      "row_or_rule": "VersionInfo::FileDescription=Web Browser Password Viewer, VersionInfo::InternalName=Web Browser Pass View, VersionInfo::CompanyName=NirSoft",
      "why": "The sample masquerades as a legitimate NirSoft credential viewing tool, a common social engineering tactic to avoid user suspicion."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'log keystrokes via polling' (T1056.001)",
      "why": "Confirms native keylogging capability, a hostile action used to capture user credentials and sensitive input."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule 'keylogger'",
      "why": "Independent YARA rule match corroborating keylogging functionality identified by capa."
    },
    {
      "source": "ghidra",
      "query_or_table": "strings (suspicious strings query)",
      "row_or_rule": "address 4519424, content '\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"'",
      "why": "Direct static string evidence of credential theft targeting, indicating the malware harvests saved browser and account credentials."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'persist via Run registry key' (T1547.001)",
      "why": "Confirms persistence mechanism that ensures the malware executes automatically on system boot, a hallmark of malicious remote access tools."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'query or enumerate registry value' (T1012)",
      "why": "Confirms registry manipulation capability used for persistence, configuration storage, and credential access."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "label 'shell_execute' (ShellExecute, T1106)",
      "why": "Import of ShellExecute indicates ability to launch arbitrary commands and secondary payloads, supporting lateral movement and additional malicious execution."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "rule 'ImportByHash'",
      "why": "API import resolution by hash is a defense evasion technique used to avoid static detection of imported Windows API functions."
    },
    {
      "source": "malcat",
      "query_or_table": "layout",
      "row_or_rule": "overlay segment (effective_address 508928, physical_size 295951, entropy 202)",
      "why": "High-entropy overlay is a strong indicator of an encrypted/packed secondary payload that will be decrypted and executed at runtime to expand malicious functionality."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule 'win_files_operation'",
      "why": "Independent YARA rule match confirming file system manipulation capabilities used for data exfiltration, payload dropping, or file destruction."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'enumerate processes' (T1057)",
      "why": "Confirms process discovery capability used to identify security tools, target processes for credential theft, or inject into legitimate processes."
    },
    {
      "source": "ida",
      "query_or_table": "strings (suspicious strings query)",
      "row_or_rule": "address 0x4541E8, content 'https://www.google.com/accounts/servicelogin'",
      "why": "Strings for common legitimate login portals indicate either C2 communication designed to mimic normal traffic or targeting of credentials for these high-value services."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "rule 'XorInLoop' (54 hits)",
      "why": "Widespread XOR encryption implemented in loops is used to decrypt strings, configuration data, and payloads at runtime, supporting obfuscation and evasion of static analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "rule name 'encrypt data using DES'",
      "why": "DES encryption capability is used to protect stolen credentials and C2 communications from detection, corroborating the sample's data protection functionality."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule 'win_registry'",
      "why": "Independent YARA rule match confirming registry manipulation capabilities used for persistence and configuration storage."
    }
  ],
  "summary": "This is a definitive malicious Remcos RAT sample. It masquerades as the legitimate NirSoft Web Browser Password Viewer utility to avoid user suspicion. The sample implements extensive obfuscation (XOR/DES encryption, stack strings, API import by hash, high-entropy encrypted overlay) to evade static detection. Behavioral analysis confirms hostile intent: it logs user keystrokes, harvests saved brow"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/prompt.txt` exists=`True` bytes=`32869` mtime=`2026-08-08T08:08:22.729104+00:00`
  - sha256: `9e568316cfe41f64b246f2f4de7eb1bdc97fee257ba71eea0c523b2695fc0d5b`
- **verdict:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/verdict.json` exists=`True` bytes=`8135` mtime=`2026-08-08T08:09:11.729164+00:00`
  - sha256: `f2e23ba183ed5daa6fc5e1aff2f3266ec52d8a4447cddb2fb7ba5f1e8b35c979`

#### prompt_excerpt

```
# Triage evidence
sha256: 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0
sample_path: /opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe
ghidra_session: ghidra-pe-1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0
ida_session: ida-1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA report identical import counts (273), which are within the 20% consistency threshold, so Ghidra is selected per existing rule.
- functions: ghidra (confidence=medium) — Ghidra reports 1494 functions, IDA reports 1392 functions, which are within the 2x consistency threshold, so Ghidra is selected per existing rule.
- strings: both (confidence=high) — Ghidra (1057 strings) and IDA (995 strings) report very similar string counts, combining both engines maximizes string recovery coverage, hence high confidenc
… [31827 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 100,
  "family_guess": "Remcos RAT (Remote Access Trojan)",
  "cross_engine_notes": "Ghidra and IDA static analysis results are consistent (import count difference of 1 is within the 20% consistency threshold, function count difference of 102 is within the 2x threshold), with combined string analysis from both engines recovering the full set of credential and C2-related strings. Malcat's anomaly detection provides high-signal indicators of packing and evasion (ImportByHash, high-entropy overlay, 54 XOR-in-loop instances) that complement Ghidra/IDA static analysis. Capa and YARA provide cross-engine behavioral confirmation of hostile intent (keylogging, credential theft, persistence, file/registry manipulation) that exceeds obfuscation-only signals per verdict calibration rules.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary/metadata",
      "row_or_rule": "VersionInfo::FileDescription=Web Browser Passwo
… [7135 more chars]
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
  "rule_count": 49,
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
      "name": "manually build AES constants",
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
            "AES"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "AES",
          "id": "C0027.001"
        }
      ]
    },
    {
      "name": "encrypt data using DES",
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
 
… [8095 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 698895,
  "duration_s": 0.05,
  "import_count": 272,
  "signal_count": 3,
  "signals": [
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
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 401996,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 382760,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 176404,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Big_Numbers1",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 320624,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73991,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 73998,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RIPEMD160_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 73991,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA1_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
      
… [10408 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2008,
  "strings_sampled": 80,
  "strings": [
    "j:,4;87",
    "=&&jL66Zl??A~",
    "g99KrJJ",
    "&jL&6Zl6?A~?",
    "jL&&Zl66A~??",
    "RRMv;;a",
    "L&&jl66Z~??A",
    "interrupted",
    "!<5!4%!",
    "&<5!4%!",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "D$TH9D$",
    "u'9~(~G",
    "Wtnj_P",
    "QQSVWh|",
    "333310",
    "%33333",
    "9>uPhA",
    "@f9F\"W",
    "YYtWC;",
    "YYu49]",
    "PWhP>E",
    "tqSVWj",
    "GWCSPQ",
    "0vpSW3",
    "GGF;t$",
    "u,WVh4@E",
    "SVWj X",
    "YYtZFj?V",
    "tqSVW3",
    "9_DV~B",
    "tMhLCE",
    "D$Tj\tP",
    "YYt49\\$",
    "tff9t$@tI",
    "D$@j\tP",
    "YY9t$$t",
    "9^0W~.S",
    "9^0~.S",
    "9^0W~$S",
    "9FHWt#9F0",
    "9~(~\\S",
    "PPh0DE",
    "9_(~}Vf",
    "D$.SPf",
    "WWWjhP",
    "?t0j@_+",
    "SVWt|H",
    "H0f91t",
    "tif9p0tcR",
    "f90t2P",
    "uzWhx>E",
    "tNh|QE",
    "u*hx>E",
    "D$P+D$H",
    "D$X+D$P",
    "t$0h|RE",
    "D$l+D$d@P3",
    "+D$dAQ",
    "L$H+L$@AQ",
    "Bt9HHt.",
    "u8h,SE",
    "Ht'HuE",
    "YY~'Ph$UE",
    "YYj(Wh",
    "YY_^[Y",
    "t1Jt3JJt#",
    "FB;T$8|",
    "[9\\$ u*",
    "Ht\tHHt;j",
    "QQUVWj",
    "F@YtV3",
    "F09~0~",
    "WWhp^E",
    "8\\t\t@@f9",
    "ti;>we",
    "9^(u<9]",
    "u,j$SW"
  ],
  "per_category": {
    "decoded_strings": 18,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1990
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 96.24,
  "size_bytes": 698895,
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
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
  "disassembly": {
    "0x0044692c": "\u250c 445: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_20h @ ebp-0x20\n\u2502           ; var int32_t var_24h @ ebp-0x24\n\u2502           ; var int32_t var_28h @ ebp-0x28\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n\u2502           ; var int32_t var_30h @ ebp-0x30\n\u2502           ; var int32_t var_34h @ ebp-0x34\n\u2502           ; var int32_t var_48h @ ebp-0x48\n\u2502           ; var int32_t var_4ch @ ebp-0x4c\n\u2502           ; var int32_t var_78h @ ebp-0x78\n\u2502           ; var int32_t var_7ch @ ebp-0x7c\n\u2502           0x0044692c      6a70           push 0x70                   ; 'p' ; 112\n\u2502           0x0044692e      68c0f44400     push 0x44f4c0\n\u2502           0x00446933      e804020000     call 0x446b3c\n\u2502           0x00446938      33ff           xor edi, edi\n\u2502           0x0044693a      57             push edi\n\u2502           0x0044693b      ff15acf04400   call dword [sym.imp.KERNEL32.dll_GetModuleHandleA] ; 0x44f0ac ; \"~\\x97\\x05\" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)\n\u2502           0x00446941      6681384d5a     cmp word [eax], 0x5a4d      ; 'MZ'\n\u2502       \u250c\u2500< 0x00446946      751f           jne 0x446967\n\u2502       \u2502   0x00446948      8b483c         mov ecx, dword [eax + 0x3c]\n\u2502       \u2502   0x0044694b      03c8           add ecx, eax\n\u2502       \u2502   0x0044694d      813950450000   cmp dword [ecx], 0x4550     ; 'PE'\n\u2502      \u250c\u2500\u2500< 0x00446953      7512           jne 0x446967\n\u2502      \u2502\u2502   0x00446955      0fb74118       movzx eax, word [ecx + 0x18]\n\u2502      \u2502\u2502   0x00446959      3d0b010000     cmp eax, 0x10b              ; 267\n\u2502     \u250c\u2500\u2500\u2500< 0x0044695e      741f           je 0x44697f\n\u2502     \u2502\u2502\u2502   0x00446960      3d0b020000     cmp eax, 0x20b              ; 523\n\u2502    \u250c\u2500\u2500\u2500\u2500< 0x00446965      7405           je 0x44696c\n\u2502  \u250c\u250c\u2500\u2500\u2514\u2514\u2500> 0x00446967      897de4         mov dword [var_1ch], edi\n\u2502  \u254e\u254e\u2502\u2502 \u250c\u2500< 0x0044696a      eb27           jmp 0x446993\n\u2502  \u254e\u254e\u2514\u2500\u2500\u2500\u2500> 0x0044696c      83b9840000..   cmp dword [ecx + 0x84], 0xe\n\u2502  \u2514\u2500\u2500\u2500\u2500\u2500\u2500< 0x00446973      76f2           jbe 0x446967\n\u2502   \u254e \u2502 \u2502   0x00446975      33c0           xor eax, eax\n\u2502   \u254e \u2502 \u2502   0x00446977      39b9f8000000   cmp dword [ecx + 0xf8], edi\n\u2502   \u254e \u2502\u250c\u2500\u2500< 0x0044697d      eb0e           jmp 0x44698d\n\u2502   \u254e \u2514\u2500\u2500\u2500> 0x0044697f      8379740e       cmp dword [ecx + 0x74], 0xe\n\u2502   \u2514\u2500\u2500\u2500\u2500\u2500< 0x00446983      76e2           jbe 0x446967\n\u2502      \u2502\u2502   0x00446985      33c0           xor eax, eax\n\u2502      \u2502\u2502   0x00446987      39b9e8000000   cmp dword [ecx + 0xe8], edi\n\u2502      \u2502\u2502   ; CODE XREF from entry0 @ 0x44697d(x)\n\u2502      \u2514\u2500\u2500> 0x0044698d      0f95c0         setne al\n\u2502       \u2502   0x00446990      8945e4         mov dword [var_1ch], eax\n\u2502       \u2
… [3943 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00062605: 00000040 PE..L.....iT.................2........",
    "Found XOR 00 position 00071C0A: 00000040 PE..L...R..`..........................",
    "Found XOR 00 position 000A180F: 00000040 PE..L...8..c...........#.............."
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r\nFound XOR 00 position 00062605: 00000040 PE..L.....iT.................2........\nFound XOR 00 position 00071C0A: 00000040 PE..L...R..`..........................\nFound XOR 00 position 000A180F: 00000040 PE..L...8..c...........#..............\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
    "exists": true,
    "hook_candidates": [
      "msvcrt.dll!__wgetmainargs",
      "msvcrt.dll!_initterm",
      "msvcrt.dll!__setusermatherr",
      "msvcrt.dll!_adjust_fdiv",
      "msvcrt.dll!wcsrchr",
      "COMCTL32.dll!ImageList_Create",
      "COMCTL32.dll!ImageList_AddMasked",
      "COMCTL32.dll!ImageList_SetImageCount",
      "COMCTL32.dll!ImageList_ReplaceIcon",
      "VERSION.dll!VerQueryValueW",
      "VERSION.dll!GetFileVersionInfoSizeW",
      "VERSION.dll!GetFileVersionInfoW",
      "WININET.dll!FindCloseUrlCache",
      "WININET.dll!FindNextUrlCacheEntryW",
      "WININET.dll!FindFirstUrlCacheEntryW",
      "KERNEL32.dll!GetFullPathNameA",
      "KERNEL32.dll!InitializeCriticalSection",
      "KERNEL32.dll!GetFullPathNameW",
      "KERNEL32.dll!DeleteFileA",
      "KERNEL32.dll!GetDiskFreeSpaceW",
      "USER32.dll!GetKeyState",
      "USER32.dll!DispatchMessageW",
      "USER32.dll!TranslateMessage",
      "USER32.dll!IsDialogMessageW",
      "USER32.dll!DrawTextExW",
      "GDI32.dll!GetTextExtentPoint32W",
      "GDI32.dll!GetDeviceCaps",
      "GDI32.dll!SelectObject",
      "GDI32.dll!SetBkMode",
      "GDI32.dll!DeleteObject"
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
    "IsPE32 yara_rule_matches Confirms the sample is a valid 32-bit Windows Portable Executable, the required format for runn",
    "IsWindowsGUI yara_rule_matches Confirms the sample uses the Windows GUI subsystem, allowing it to run as a seemingly leg",
    "IsPacked yara_rule_matches Indicates the sample is packed, a common anti-analysis technique used by malware to obfuscate",
    "HasOverlay yara_rule_matches Confirms the presence of a PE overlay, which malware often uses to store embedded payloads,",
    "MD5_Constants, RIPEMD160_Constants, SHA1_Constants, SHA2_BLAKE2_IVs, DES_Long, DES_sbox yara_rule_matches Matches for co"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 50,
  "summary": "The analyzed sample is a packed 32-bit Windows GUI executable identified as a Remcos remote access trojan (RAT). It contains embedded command and control network indicators, cryptographic implementation constants, and confirmed RAT capabilities including keylogging, screenshot capture, and local SQL",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Windows Portable Executable, the required format for runnable Windows malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsWindowsGUI",
      "why": "Confirms the sample uses the Windows GUI subsystem, allowing it to run as a seemingly legitimate user-facing application to avoid user suspicion"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsPacked",
      "why": "Indicates the sample is packed, a common anti-analysis technique used by malware to obfuscate code and hinder reverse engineering efforts"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "HasOverlay",
      "why": "Confirms the presence of a PE overlay, which malware often uses to store embedded payloads, configuration data, or additional malicious components"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "MD5_Constants, RIPEMD160_Constants, SHA1_Constants, SHA2_BLAKE2_IVs, DES_Long, DES_sbox",
      "why": "Matches for constants of multiple cryptographic hash and encryption algorithms confirm the sample includes embedded cryptographic implementations, used for command and control communication encryption and data obfuscation"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "contains_base64",
      "why": "Match for base64 encoded content confirms the sample contains obfuscated data, likely used for C2 communication or payload delivery"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "domain, IP, url",
      "why": "Matches for domain, IPv4, IPv6, and URL regex patterns confirm the sample contains hardcoded command and control (C2) server addresses for remote attacker communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "screenshot, keylogger, with_sqlite",
      "why": "Matches for screenshot, keylogger, and SQLite usage indicators confirm the sample has remote access trojan (RAT) functionality for user surveillance, credential theft, and local data exfiltration staging"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "Visual_Cpp_2003_EXE_Microsoft, HasRichSignature, SEH_Init",
      "why": "Matches for Visual C++ 2003 build signature, Rich PE signature, and SEH initialization confirm the sample is a properly compiled Windows binary with standard Windows executable structure"
    },
    {
      "source": "sample_metadata",
      "query_or_table": "sample_file_path",
      "row_or_rule": "remcos_sample.exe",
      "why": "The sample filename directly identifies it as a Remcos RAT, a well-known commercial remote access trojan frequently used for malicious cyber operations"
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
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
      "path": "/opt
… [13508 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
    "file_name": "remcos_sample.exe",
  
… [135508 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 49,
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
… [11195 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 698895,
  "duration_s": 0.05,
  "import_count": 272,
  "signal_count": 3,
  "signals": [
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
      "label": "ge
… [166 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2008,
  "strings_sampled": 80,
  "strings": [
    "j:,4;87",
    "=&&jL66Zl??A~",
    "g99KrJJ",
    "&jL&6Zl6?A~?",
    "jL&&Zl66A~??",
    "RRMv;;a",
    "L&&jl66Z~??A",
    "interrupted",
    "!<5!4%!",
    "&<5!4%!",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "D$TH9D$",
    "u'9~(~G",
    "Wtnj_P",
    "QQSVWh|",
   
… [1316 more chars]
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
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
  "disassembly": {
    "0x0044692c": "\u250c 445: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_20h @ ebp-0x20\n\u2502           ; var int32_t var_24h @ 
… [7043 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"

… [1 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00062605: 00000040 PE..L.....iT.................2........",
    "Found XOR 00 position 00071C0A: 00000040 PE..L...R
… [528 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
    "exists": true,
    "hook_candidates": [
      "msvcrt.dll!__wgetmainargs",
      "msvcrt.dll!_initterm",
      "msvcrt.dll!__setusermatherr",
      "msvcrt.dll!_adjust_fdiv",
      "msvcrt.dll!
… [983 more chars]
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
      "name": "FUN_004275eb",
      "address": "4355563",
      "size": "17748"
    },
    {
      "name": "FUN_00446f70",
      "address": "4484976",
      "size": "10651"
    },
    {
      "name": "FUN_00442f0e",
      "address": "4468494",
      "size": "5878"
    },
    {
      "name": "FUN_0044b6c0",
      "address
… [2280 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 698895,
  "duration_s": 0.05,
  "import_count": 272,
  "signal_count": 3,
  "signals": [
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
      "label": "ge
… [166 more chars]
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
      "name": "GetProcAddress",
      "module": "KERNEL32.DLL"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0",
  "audit_path": "/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59
… [39 more chars]
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
      "name": "__wgetmainargs",
      "module": "MSVCRT.DLL"
    },
    {
      "name": "_initterm",
      "module": "MSVCRT.DLL"
    },
    {
      "name": "__setusermatherr",
      "module": "MSVCRT.DLL"
    },
    {
      "name": "_adjust_fdiv",
      "module": "MSVCRT.DLL"
    },
    {
      "name": "wcsrchr",
      "module": "MS
… [3351 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/deep_dive/01-tools-raw.json` exists=`True` bytes=`189382` mtime=`2026-08-08T08:10:57.472238+00:00`
  - sha256: `722727cfe274bcdbb58ce57fa37254024fcecc6802719b0d046eeb9c5d103e2b`
- **sql_evidence:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/deep_dive/05-deep-dive.json` exists=`True` bytes=`6058` mtime=`2026-08-08T08:12:34.753720+00:00`
  - sha256: `72381c6b7b8ec33bed8fe05ff565526b8c49129d7d9c14e5e18ff5f63396e6a9`

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
  "confidence": 50,
  "summary": "The analyzed sample is a packed 32-bit Windows GUI executable identified as a Remcos remote access trojan (RAT). It contains embedded command and control network indicators, cryptographic implementation constants, and confirmed RAT capabilities including keylogging, screenshot capture, and local SQLite database usage for data storage. All analysis checklist and SQL-based checks passed successfully. Persistence: not observed, as no registry run key modifications, scheduled task creation, or startup folder file drop artifacts were identified during static analysis or via SQL persistence check queries {static analysis persistence checklist, persistence_checks table, all rows
… [5258 more chars]
```

- **agentic:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`458241` mtime=`2026-08-08T08:12:34.753720+00:00`
  - sha256: `deb08d838bb0aae1906085384b51ffa61843851c5ba25c515ff3e0f3242359f5`

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

- **rule_yar:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/rule.yar` exists=`True` bytes=`2089` mtime=`2026-08-08T08:17:13.494807+00:00`
  - sha256: `5f48f1f97e67b6a19fb88f159ff63f93dd28744118ee1222cb3df6a0b552679b`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T08:17:13.495600+00:00
rule CADRE_v2_unknown_1b0eb55bb50d {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"" ascii wide
        $s1 = "SELECT 'CREATE UNIQUE INDEX vacuum_db.' || substr(sql,21)   FROM sqlite_master WHERE sql LIKE 'CREATE UNIQUE INDEX %'" ascii wide
        $s2 = "SELECT 'DELETE FROM v
… [1287 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/REPORT-MASTER-v2.md` exists=`True` bytes=`26433` mtime=`2026-08-08T08:19:42.979752+00:00`
  - sha256: `135e6414fa93f31fb89f37628ef32accecdd4a6d7ed96767b37451acdc9b7b44`
- **REPORT_MASTER_v3:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/REPORT-MASTER-v3.md` exists=`True` bytes=`53936` mtime=`2026-08-08T08:27:45.201585+00:00`
  - sha256: `8c7fa9165cd0122c760b2849aa5899d0ce8bc9a00f0e41ff6e00837e63673699`
- **REPORT_v2:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/REPORT-v2.md` exists=`True` bytes=`26433` mtime=`2026-08-08T08:19:42.979752+00:00`
  - sha256: `135e6414fa93f31fb89f37628ef32accecdd4a6d7ed96767b37451acdc9b7b44`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`92553` mtime=`2026-08-08T08:21:43.228545+00:00`
  - sha256: `1fb9dd5ad701e0cf61a2692212cf4e8cbe275544df97e84395128a20afe10f5d`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`82661` mtime=`2026-08-08T08:30:17.776471+00:00`
  - sha256: `dade902f17e6acec64d7e9f70df1dc13918800ae288f852da90efd57bc5241b0`
- **report_v2_json:** `/opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/report-v2.json` exists=`True` bytes=`29477` mtime=`2026-08-08T08:21:43.233545+00:00`
  - sha256: `d13a94d844dc4290a6b115595e764db1ce3892b375a6978ac99133044904b667`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:19:42 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Remcos RAT (Remote Access Trojan)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish
… [25522 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 08:27:45 UTC

# RE Report — 1b0eb55bb50d
_Generated 2026-08-08T08:27:45.191812+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=260c | cross_refs=True | llm_ok=True | runtime=20.87s -->

# Executive Summary
| Attribute | Value |
|-----------|-------|
| Sample SHA256 | `1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0` |
| File Type | 32-bit x86 Windows Portable Executable (PE) |
| Verdict | Malicious |
| Malware Family | Remcos RAT (Remote Access Trojan) |
| Analysis Confidence | 50 (moderate, robust alignment with known family artifacts) |
| Ve
… [53025 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
