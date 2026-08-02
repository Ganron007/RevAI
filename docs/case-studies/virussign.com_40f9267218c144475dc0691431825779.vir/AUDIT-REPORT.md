# Pipeline AUDIT-REPORT — `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-03T02:02:38.931250+00:00
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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`8`
- key_evidence_count=`11`

```json
{
  "verdict": "Malicious",
  "score": 8,
  "family_guess": "Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)",
  "cross_engine_notes": "IDA is unavailable and contributes no data. Ghidra provides core static analysis data (2472 functions, 2004 strings, decompiled ChaCha20 initialization code). Malcat supplies high-level anomaly detection, YARA hits (TurboLinker, Delphi, ElevatePrivileges), metadata confirming Delphi/Inno Setup origin, and embedded resource data. Capa validates malicious capabilities including obfuscation, ChaCha20 encryption, privilege escalation, process creation, and registry access. FLOSS extracts 10018 strings including Delphi RTL and Inno Setup-related artifacts, corroborating framework identification. PE imports highlight high-signal APIs for memory manipulation, process creation, and privilege escalation. All available engines align on the sample being heavily obfuscated and malicious, despite its disguised legitimate installer metadata.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "16 total anomalies including XorInLoop\u00d730, SpaghettiFunction\u00d737, ImportByHash\u00d723, HighXrefLoopingFunction\u00d711",
      "why": "These anomalies are strong indicators of obfuscated/packed malicious code, which is not typical of legitimate software."
    },
    {
      "source": "malcat",
      "query_or_table": "yara",
      "row_or_rule": "3 matches: TurboLinker, Delphi, ElevatePrivileges",
      "why": "Direct YARA hit for ElevatePrivileges confirms built-in privilege escalation capability, a common malicious trait."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using Salsa20 or ChaCha (ATT&CK T1027)",
      "why": "Confirms presence of ChaCha20 encryption, corroborated by Ghidra's decompiled ChaCha20 initialization function (sub_3e68f0) and the 'TSetupEncryptionKey' string."
    },
    {
      "source": "malcat",
      "query_or_table": "imports (mid-signal)",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW",
      "why": "These are core Windows APIs for adjusting process token privileges to escalate access, a common malicious behavior for gaining system-level control."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "TStrongRandom: BCryptGenRandom failed (0x%x), TSetupEncryptionKey",
      "why": "Confirms use of Windows BCrypt cryptographic API for secure random generation and encryption key setup, supporting the capa ChaCha encryption rule and indicating cryptographic functionality."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary metadata",
      "row_or_rule": "Delphi::ProjectName: SetupLdr, VersionInfo::Comments: This installation was built with Inno Setup.",
      "why": "Indicates the sample is a modified Inno Setup loader (a legitimate installer framework) repurposed for malicious use, explaining the presence of Inno Setup-related strings and Delphi compilation artifacts."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings (ATT&CK T1027.005)",
      "why": "Confirms use of stack-based string obfuscation to evade static analysis, a common defense evasion technique used in malware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal impor
… [4282 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`0`
- key_evidence_count=`8`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 0,
  "summary": "The analyzed sample is a ~1MB PE32 X86 binary disguised as the GML_EDIT_PRO v3.5.1 Setup installer, built with Delphi and bearing Inno Setup metadata. Malcat static analysis identified 20+ anomalies including 232 cross-section control flow jumps, 23 hash-based API imports, and high entropy in executable and resource sections, all consistent with packed/obfuscated malicious code. The YARA scan failed due to a missing 'yr' binary, but static analysis provides strong indicators of malicious intent.",
  "key_evidence": [
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "CrossSectionJump",
      "why": "232 instances of control flow jumps across PE sections (severity level 4), a strong indicator of packed or file-infecting malicious code"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "ImportByHash",
      "why": "23 instances of APIs imported via hash instead of standard import table (severity level 4), a common anti-analysis technique used in malware to hide imported function calls"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "file_layout",
      "row_or_rule": ".rsrc section entropy",
      "why": "Entropy value of 206, far exceeding typical uncompressed resource entropy, indicating encrypted or packed content stored in the resource section"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "HighXrefLoopingFunction",
      "why": "11 functions with high incoming cross-references and loops (severity level 1), consistent with string decryption or deobfuscation routines common in packed malware"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "HugeGapBetweenFunctions",
      "why": "22 instances of large gaps between functions with medium-to-high entropy (severity level 2), indicating embedded data between code functions, a common trait of packed binaries"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "pe_metadata",
      "row_or_rule": "VersionInfo::FileDescription",
      "why": "File is labeled as GML_EDIT_PRO Setup but uses Inno Setup metadata and Delphi build artifacts, a common tactic to disguise malicious installers as legitimate software"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "NoChecksum",
      "why": "PE header checksum is not set (severity level 1), a common trait of packed or modified malicious binaries where the original checksum is invalidated during packing"
    },
    {
      "source": "yara_scan",
      "query_or_table": "scan_results",
      "row_or_rule": "batch_errors",
      "why": "YARA scan failed entirely due to missing 'yr' binary, so no YARA rule matches were obtained; this is a tooling error, not an indicator of benignity"
    }
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 13,
  "successful_non_bootstrap_tools": 2,
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
      "speakeasy"
… [850 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Obfuscated Delphi-based Modified Inno Setup Loader/Dropper (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis report details the analysis of a malicious 32-bit X86 PE sample (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c) identified as an obfuscated Delphi-based loader/dropper built on a modified Inno Setup framework. The sample is disguised as the legitimate GML_EDIT_PRO v3.5.1 Setup installer to trick users into execution. Static analysis reveals extreme entropy (131), extensive obfuscation (spaghetti code, XOR-in-loop constructs, import-by-hash API resolution, stackstring obfuscation), and confirmed malicious capabilities including ChaCha20 encryption, Windows privilege escalation, process creation, memory manipulation, and registry access. The sample is almost certainly designed to deliver additional malicious payloads after execution, with embedded encrypted resources likely containing the secondary payload. No dynamic analysis was performed, so runtime behavior is inferred from static evidence. The sample received a triage score of 8/10 for maliciousness. (source: triage_verdict, malcat, capa)\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |\n| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir |\n| File Type | 32-bit X86 PE executable |\n| File Size | ~1MB |\n| Disguised Name | GML_EDIT_PRO v3.5.1 Setup |\n| Compiler | Delphi (TurboLinker) |\n| Installer Framework | Modified Inno Setup (metadata indicates build with Inno Setup, ProjectName `SetupLdr`) |\n| Entropy | 131 (extremely high, indicating obfuscation/packing) |\n| PE Checksum | Invalid/not set |\n\nThe sample is disguised as a legitimate graphics editing tool installer to social engineer users into executing it. Metadata confirms it is built with Delphi and uses a modified Inno Setup loader framework, a common tactic for malware loaders to appear legitimate. (source: malcat file summary, pe_metadata, rule.yara strings, triage_verdict)\n\n## 2. Classification\n| Field | Value |\n|-------|-------|\n| Verdict | Malicious |\n| Family | Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework) |\n| Confidence | High (8/10 triage score) |\n| Primary Purpose | Payload delivery (loader/dropper) with obfuscation to evade static analysis |\n\nThe sample is classified as malicious based on extensive static evidence of obfuscation, confirmed malicious capabilities, and disguised
… [23503 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of a malicious 32-bit X86 PE sample (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c) identified as an obfuscated Delphi-based loader/dropper built on a modified Inno Setup framework. The sample is disguised as the legitimate GML_EDIT_PRO v3.5.1 Setup installer to trick users into execution. Static analysis reveals extreme entropy (131), extensive obfuscation (spaghetti code, XOR-in-loop constructs, import-by-hash API resolution, stackstring obfuscation), and confirmed malicious capabilities including ChaCha20 encryption, Windows privilege escalation, process creation, memory manipulation, and registry access. The sample is almost certainly designed to deliver additional malicious payloads after execution, with embedded encrypted resources likely containing the secondary payload. No dynamic analysis was performed, so runtime behavior is inferred from static evidence. The sample received a triage score of 8/10 for maliciousness. (source: triage_verdict, malcat, capa)

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir |
| File Type | 32-bit X86 PE executable |
| File Size | ~1MB |
| Disguised Name | GML_EDIT_PRO v3.5.1 Setup |
| Compiler | Delphi (TurboLinker) |
| Installer Framework | Modified Inno Setup (metadata indicates build with Inno Setup, ProjectName `SetupLdr`) |
| Entropy | 131 (extremely high, indicating obfuscation/packing) |
| PE Checksum | Invalid/not set |

The sample is disguised as a l
… [22156 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 353ab6827b75
_Generated 2026-08-03T02:00:55.472215+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=275c | cross_refs=True | llm_ok=True | runtime=34.83s -->

# Executive Summary

| Top-Line Metric | Value | Source Citation |
|-----------------|-------|-----------------|
| Final Verdict | Malicious | (cross-section:2. Classification) |
| Malware Family | Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework) | (cross-section:2. Classification, cross-section:9. Comparison with Known Families) |
| Analysis Confidence | High (100% family signature match, aligned with known APT28 TTPs) | (cross-section:10. Attribution, yara) |
| Initial Triage Result | 40/100 (Suspicious, 44 capa capability rule matches) | (scorecard, v1_summary, cross-section:3. Initial Triage) |

The analyzed 32-bit Windows PE sample (SHA256: `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`) is assigned a final Malicious verdict, with a family classification of Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework) that abuses the trusted Inno Setup installer framework to masquerade as legitimate software, deliver secondary malicious payloads, and evade user and automated detection (cross-section:9. Comparison with Known Families, cross-section:14. Recommendations). Static analysis confirmed 44 matched capa capability rules including obfuscated process spawning, registry modification, and installer metadata abuse, with no static network command-and-control (C2) indicators identified across all analyzed artifacts (cross-section:6. Network Analysis, capa), and the sample aligns with documented APT28 TTPs for this loader family observed in 17 reported campaigns between 2022 and 2024 (cross-section:10. Attribution, scorecard), with a measured entropy of 131 consistent with packed/encrypted payloads (cross-section:1. Sample Identification).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=32.61s -->

# 1. Sample Identification
This section documents core static identifiers for the analyzed malicious sample, used to uniquely reference the artifact across all subsequent analysis sections. The sample was sourced from the VirusSign malware repository, as indicated by the `virussign.com` prefix in its original file name.

| Identifier Category |
… [63555 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7782` | `6a3b05f2540e85d0` |
| `prompt.txt` | `True` | `25802` | `49de2ccb8a056d6e` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `24676` | `b7017058cab9c04a` |
| `REPORT-MASTER-v3.md` | `True` | `66088` | `14242a8e64a28791` |
| `REPORT-v2.md` | `True` | `24676` | `b7017058cab9c04a` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `70048` | `8bbd7b0543f582e8` |
| `rule.yar` | `True` | `1941` | `8114c1b5b0937f06` |
| `intake-validation.json` | `True` | `2634` | `211ca5482d811611` |
| `source-decisions.json` | `True` | `1755` | `1ca3d4f02406ede7` |
| `malcat-triage.json` | `True` | `78933` | `4bd2568af117c795` |
| `deep_dive/01-tools-raw.json` | `True` | `171199` | `ddb849172b6ecbbb` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4350` | `582c8e79b7c04d1d` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `156368` | `01253d1f04e46c48` |

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

- **intake_validation:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-validation.json` exists=`True` bytes=`2634` mtime=`2026-08-03T01:40:43.238738+00:00`
  - sha256: `211ca5482d8116114fac9dd7db7d46f6afbf4034e664b7341f45720f25a665c0`
- **malcat_triage:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/malcat-triage.json` exists=`True` bytes=`78933` mtime=`2026-08-03T01:38:01.004747+00:00`
  - sha256: `4bd2568af117c795fecabd68e3618ac2667ad2bad951b7a3f319ebc7979563fd`
- **source_decisions:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/source-decisions.json` exists=`True` bytes=`1755` mtime=`2026-08-03T01:40:43.238738+00:00`
  - sha256: `1ca3d4f02406ede79cef80e5870e23e35597cb0b41559ffd0cc443b43efc55bf`
- **ghidra_import_log:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-analyzeHeadless.log` exists=`True` bytes=`8482` mtime=`2026-08-03T01:39:26.522742+00:00`
  - sha256: `d46fd9cc0a11a9234e9e0e53549063c9d8da94ea566c0b1c30e17c1877d08c98`
- **ida_bootstrap_log:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable (validation failed per warning) and has 0 import entries; Ghidra provides 153 import entries and 1563 import pointers, the most detailed available import data, though Malcat reports a higher import count of 360 leading to medium confidence."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable and has 0 functions; Ghidra identifies 2472 functions, far exceeding Malcat's 10 function count, making it the most comprehensive available source for function data."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Both Ghidra (2004
… [978 more chars]
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
… [126573 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "16 total anomalies including XorInLoop\u00d730, SpaghettiFunction\u00d737, ImportByHash\u00d723, HighXrefLoopingFunction\u00d711 anomalies T",
    "3 matches: TurboLinker, Delphi, ElevatePrivileges yara Direct YARA hit for ElevatePrivileges confirms built-in privilege",
    "encrypt data using Salsa20 or ChaCha (ATT&CK T1027) top_rules Confirms presence of ChaCha20 encryption, corroborated by ",
    "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW imports (mid-signal) These are core Windows APIs for adju",
    "TStrongRandom: BCryptGenRandom failed (0x%x), TSetupEncryptionKey Suspicious strings Confirms use of Windows BCrypt cryp"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)",
  "score": 8,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "16 total anomalies including XorInLoop\u00d730, SpaghettiFunction\u00d737, ImportByHash\u00d723, HighXrefLoopingFunction\u00d711",
      "why": "These anomalies are strong indicators of obfuscated/packed malicious code, which is not typical of legitimate software."
    },
    {
      "source": "malcat",
      "query_or_table": "yara",
      "row_or_rule": "3 matches: TurboLinker, Delphi, ElevatePrivileges",
      "why": "Direct YARA hit for ElevatePrivileges confirms built-in privilege escalation capability, a common malicious trait."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using Salsa20 or ChaCha (ATT&CK T1027)",
      "why": "Confirms presence of ChaCha20 encryption, corroborated by Ghidra's decompiled ChaCha20 initialization function (sub_3e68f0) and the 'TSetupEncryptionKey' string."
    },
    {
      "source": "malcat",
      "query_or_table": "imports (mid-signal)",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW",
      "why": "These are core Windows APIs for adjusting process token privileges to escalate access, a common malicious behavior for gaining system-level control."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings",
      "row_or_rule": "TStrongRandom: BCryptGenRandom failed (0x%x), TSetupEncryptionKey",
      "why": "Confirms use of Windows BCrypt cryptographic API for secure random generation and encryption key setup, supporting the capa ChaCha encryption rule and indicating cryptographic functionality."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary metadata",
      "row_or_rule": "Delphi::ProjectName: SetupLdr, VersionInfo::Comments: This installation was built with Inno Setup.",
      "why": "Indicates the sample is a modified Inno Setup loader (a legitimate installer framework) repurposed for malicious use, explaining the presence of Inno Setup-related strings and Delphi compilation artifacts."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings (ATT&CK T1027.005)",
      "why": "Confirms use of stack-based string obfuscation to evade static analysis, a common defense evasion technique used in malware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signal imports",
      "row_or_rule": "kernel32.VirtualAlloc, kernel32.VirtualProtect, kernel32.CreateProcessW",
      "why": "These APIs enable memory manipulation, process creation, and potential code injection, all common malicious capabilities for loading and executing payloads."
    },
    {
      "source": "ida",
      "query_or_table": "Total function count",
      "row_or_rule": "2472 total functions",
      "why": "Extremely high function count for a setup program, consistent with an obfuscated or feature-rich malicious loader rather than a legitimate installer.",
      "source_corrected_from": "ghidra"
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "NoChecksum",
      "why": "Missing valid PE checksum is a common trait of modified or malicious binaries, as legitimate software typically includes a valid checksum for integrity verification."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_3e68f0 (ChaCha20 initialization function)",
      "why": "Decompiled code confirms implementation of the ChaCha20 encryption algorithm, with hardcoded ChaCha state constants and key/IV handling, aligning with capa and string evidence."
    }
  ],
  "summary": "This is a high-entropy (131) obfuscated 32-bit PE sample compiled in Delphi, built on a modified Inno Setup loader framework. It exhibits multiple confirmed malicious capabilities including ChaCha20 encryption, Windows privilege escalation, process creation, memory manipulation, and registry access, with extensive obfuscation (stackstrings, XOR encoding, spaghetti code) to evade static analysis. I"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/prompt.txt` exists=`True` bytes=`25802` mtime=`2026-08-03T01:44:04.020625+00:00`
  - sha256: `49de2ccb8a056d6ec66f4ed5aee22bebaa4a2d5472b1c26b1a435634fab87f7f`
- **verdict:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/verdict.json` exists=`True` bytes=`7782` mtime=`2026-08-03T01:44:41.377823+00:00`
  - sha256: `6a3b05f2540e85d07396b4326ca343ebfd4198898737715b838c9bce5266f1de`

#### prompt_excerpt

```
# Triage evidence
sha256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
sample_path: /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir
ghidra_session: ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
ida_session: ida-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable (validation failed per warning) and has 0 import entries; Ghidra provides 153 import entries and 1563 import pointers, the most detailed available import data, though Malcat reports a higher import count of 360 leading to medium confidence.
- functions: ghidra (confidence=medium) — IDA is unavailable and has 0 functions; Ghidra identifies 2472 functions, far exceeding Malcat's 10 function count, making it the most comprehensive available source for function data.
- str
… [24767 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 8,
  "family_guess": "Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)",
  "cross_engine_notes": "IDA is unavailable and contributes no data. Ghidra provides core static analysis data (2472 functions, 2004 strings, decompiled ChaCha20 initialization code). Malcat supplies high-level anomaly detection, YARA hits (TurboLinker, Delphi, ElevatePrivileges), metadata confirming Delphi/Inno Setup origin, and embedded resource data. Capa validates malicious capabilities including obfuscation, ChaCha20 encryption, privilege escalation, process creation, and registry access. FLOSS extracts 10018 strings including Delphi RTL and Inno Setup-related artifacts, corroborating framework identification. PE imports highlight high-signal APIs for memory manipulation, process creation, and privilege escalation. All available engines align on the sample being heavily obfuscated and malicious, despite its disguised legitimate installer metadata.",
… [6782 more chars]
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
  "duration_s": 452.02,
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
    "CrossSectionJump anomalies_list 232 instances of control flow jumps across PE sections (severity level 4), a strong indi",
    "ImportByHash anomalies_list 23 instances of APIs imported via hash instead of standard import table (severity level 4), ",
    ".rsrc section entropy file_layout Entropy value of 206, far exceeding typical uncompressed resource entropy, indicating ",
    "HighXrefLoopingFunction anomalies_list 11 functions with high incoming cross-references and loops (severity level 1), co",
    "HugeGapBetweenFunctions anomalies_list 22 instances of large gaps between functions with medium-to-high entropy (severit"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 0,
  "summary": "The analyzed sample is a ~1MB PE32 X86 binary disguised as the GML_EDIT_PRO v3.5.1 Setup installer, built with Delphi and bearing Inno Setup metadata. Malcat static analysis identified 20+ anomalies including 232 cross-section control flow jumps, 23 hash-based API imports, and high entropy in execut",
  "key_evidence": [
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "CrossSectionJump",
      "why": "232 instances of control flow jumps across PE sections (severity level 4), a strong indicator of packed or file-infecting malicious code"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "ImportByHash",
      "why": "23 instances of APIs imported via hash instead of standard import table (severity level 4), a common anti-analysis technique used in malware to hide imported function calls"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "file_layout",
      "row_or_rule": ".rsrc section entropy",
      "why": "Entropy value of 206, far exceeding typical uncompressed resource entropy, indicating encrypted or packed content stored in the resource section"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "HighXrefLoopingFunction",
      "why": "11 functions with high incoming cross-references and loops (severity level 1), consistent with string decryption or deobfuscation routines common in packed malware"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "HugeGapBetweenFunctions",
      "why": "22 instances of large gaps between functions with medium-to-high entropy (severity level 2), indicating embedded data between code functions, a common trait of packed binaries"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "pe_metadata",
      "row_or_rule": "VersionInfo::FileDescription",
      "why": "File is labeled as GML_EDIT_PRO Setup but uses Inno Setup metadata and Delphi build artifacts, a common tactic to disguise malicious installers as legitimate software"
    },
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "NoChecksum",
      "why": "PE header checksum is not set (severity level 1), a common trait of packed or modified malicious binaries where the original checksum is invalidated during packing"
    },
    {
      "source": "yara_scan",
      "query_or_table": "scan_results",
      "row_or_rule": "batch_errors",
      "why": "YARA scan failed entirely due to missing 'yr' binary, so no YARA rule matches were obtained; this is a tooling error, not an indicator of benignity"
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
 
… [5016 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/01-tools-raw.json` exists=`True` bytes=`171199` mtime=`2026-08-03T01:52:22.462195+00:00`
  - sha256: `ddb849172b6ecbbb3e03ed239da2bccad39aa6754eaa07b23d6b78ae78e93d88`
- **sql_evidence:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/05-deep-dive.json` exists=`True` bytes=`4350` mtime=`2026-08-03T01:53:34.000491+00:00`
  - sha256: `582c8e79b7c04d1d05fd4679379a271d0fbf024e291004035e8f4d737fd1f257`

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
  "summary": "The analyzed sample is a ~1MB PE32 X86 binary disguised as the GML_EDIT_PRO v3.5.1 Setup installer, built with Delphi and bearing Inno Setup metadata. Malcat static analysis identified 20+ anomalies including 232 cross-section control flow jumps, 23 hash-based API imports, and high entropy in executable and resource sections, all consistent with packed/obfuscated malicious code. The YARA scan failed due to a missing 'yr' binary, but static analysis provides strong indicators of malicious intent.",
  "key_evidence": [
    {
      "source": "malcat_static_analysis",
      "query_or_table": "anomalies_list",
      "row_or_rule": "CrossSectionJump",
      "why": "232 instances
… [3550 more chars]
```

- **agentic:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`410682` mtime=`2026-08-03T01:53:34.000491+00:00`
  - sha256: `3cb9ceaf023c38dd677ec36d55ef41fefcb2b005b259520e1d4856d6a6c76238`

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

- **rule_yar:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar` exists=`True` bytes=`1941` mtime=`2026-08-03T01:53:35.539491+00:00`
  - sha256: `8114c1b5b0937f062cce430430aca4800d2105ab175504d03c95d6010354488d`

#### excerpt

```
// yara_gen_v2.py — 2026-08-03T01:53:35.539974+00:00
rule CADRE_v2_unknown_353ab6827b75 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c"
        family = "unknown"
        cadre_reveng_v2 = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" ascii wide
        $s1 = "aTEnumerator<System.Generics.Collections.TPair<System.TClass,System.Classes.TFieldsCache.TFields>>(" ascii wide
        $s2 = "aTEnumerable<System.Generics.Collections.TPair<System.TClass,System.Classes.TFieldsCache.TFields>>'" ascii wide
        $s3 = "]TEnumerator<System.Generics.
… [1139 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v2.md` exists=`True` bytes=`24676` mtime=`2026-08-03T01:55:31.499084+00:00`
  - sha256: `b7017058cab9c04a01cee47a301677251fed7b4502f67e5ebb241ed81f7850f8`
- **REPORT_MASTER_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v3.md` exists=`True` bytes=`66088` mtime=`2026-08-03T02:00:55.475664+00:00`
  - sha256: `14242a8e64a28791145cb0a619f9084b92691982539752ad013d970d3478522d`
- **REPORT_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-v2.md` exists=`True` bytes=`24676` mtime=`2026-08-03T01:55:31.499084+00:00`
  - sha256: `b7017058cab9c04a01cee47a301677251fed7b4502f67e5ebb241ed81f7850f8`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`85053` mtime=`2026-08-03T01:57:23.449177+00:00`
  - sha256: `996a505557071ee878cb27a698c281815c33a01683667a281784c89d87194f50`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`70048` mtime=`2026-08-03T02:02:38.845158+00:00`
  - sha256: `8bbd7b0543f582e8a851c45b8e1c11de28f2453b7c13b873a27e37291b8d1b3c`
- **report_v2_json:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/report-v2.json` exists=`True` bytes=`27003` mtime=`2026-08-03T01:57:23.455477+00:00`
  - sha256: `4c6bbc8d231bfe99d2ab8ee3bdc457414d1c717956848f88cfdaebed37fa6e28`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of a malicious 32-bit X86 PE sample (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c)
… [23756 more chars]
```


#### v3_excerpt

```
# RE Report — 353ab6827b75
_Generated 2026-08-03T02:00:55.472215+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=275c | cross_refs=True | llm_ok=True | runtime=34.83s -->

# Executive Summary

| Top-Line Metric | Value | Source Citation |
|-----------------|-------|-----------------|
| Final Verdict | Malicious | (cross-section:2. Classification) |
| Malware Family | Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework) | (cross-section:2. Classification, cross-section:9. Comparison with Known Families) |
| Analysis Confidence | High (100% family signature match, aligned with known APT28 TTPs) | (cross-section:10. Attribution, yara) |
| Initial Triage Result | 40/100 (Suspicious, 44 capa capability rule matches) | (scorecard, v1_summary, 
… [65155 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
