# Pipeline AUDIT-REPORT — `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-04T05:28:51.008079+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities` confidence=`8`
- key_evidence_count=`11`

```json
{
  "verdict": "Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities",
  "score": 8,
  "family_guess": "Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers)",
  "cross_engine_notes": "Cross-engine validation confirms consistent malicious indicators: 1) Import count alignment between Malcat (145) and pe_imports (142) validates the import dataset. 2) Delphi/Borland origin is confirmed across 4 engines: Malcat YARA hits for Borland/Delphi, Ghidra decompilation shows Delphi RTL function calls, FLOSS strings include Delphi RTL type definitions, Malcat metadata lists Delphi::ProjectName as 'SetupLdr'. 3) Obfuscation indicators are consistent: Malcat reports high entropy (184) and obfuscation anomalies, capa identifies XOR/RC4 obfuscation rules, YARA flags packed code. 4) Malicious capability alignment: Privilege escalation imports from Malcat match the YARA 'escalate_priv' hit and capa's privilege-related behavior; process injection imports are flagged by both pe_imports (T1055) and capa's process injection rules.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy=184",
      "why": "Extremely high file entropy is a strong indicator of packed/obfuscated code, a common technique used by malware to hinder static analysis and evade detection."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d719, SpaghettiFunction\u00d730, HighXrefLoopingFunction\u00d712",
      "why": "These static analysis anomalies are characteristic of heavily obfuscated, packed malicious code designed to break disassembly and control flow analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027)",
      "why": "Confirms active use of obfuscation and encryption techniques to hide malicious payloads and logic, aligning with the high entropy and obfuscation anomalies from Malcat."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "allocate_memory (VirtualAlloc) [T1055], change_memory_protection (VirtualProtect) [T1055]",
      "why": "These imports are core primitives for process injection, a common malicious tactic used to execute arbitrary code in the context of legitimate processes to evade detection."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW, advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "why": "These imports are used for privilege escalation, a common malicious tactic to gain elevated system access to perform sensitive actions like modifying system files or disabling security tools."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv",
      "why": "YARA rule explicitly flags privilege escalation functionality, directly corroborating the observed privilege-related imports from Malcat and pe_imports."
    },
    {
      "source": "malcat",
      "query_or_table": "metadata",
      "row_or_rule": "VersionInfo::Comments = \"This installation was built with Inno Setup.\", Delphi::ProjectName = \"SetupLdr\"",
      "why": "Confirms t
… [4065 more chars]
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
  "summary": "The analyzed sample is a packed, Borland Delphi-compiled Windows GUI PE32 executable containing multiple indicators of malicious activity, including embedded network indicators (domain, IPv4/IPv6 addresses, URL), functionality to disable Data Execution Prevention (DEP), privilege escalation code, Windows registry manipulation, token manipulation, and file operation capabilities, all consistent with malware designed to compromise system security.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsPacked",
      "why": "Confirms the executable is packed, a common obfuscation technique used by malware to hinder analysis and evade detection."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "borland_delphi",
      "why": "Indicates the sample is compiled with Borland Delphi, a development toolchain frequently used to create malware."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "domain",
      "why": "Confirms the presence of an embedded domain name, a network indicator typically used for command-and-control (C2) communication or malicious payload delivery."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IP",
      "why": "Confirms embedded IPv4 and IPv6 address strings, which are network indicators for malicious communication endpoints."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "url",
      "why": "Confirms an embedded URL, likely used for downloading additional malicious payloads or communicating with C2 infrastructure."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "disable_dep",
      "why": "Indicates the sample contains code to disable Data Execution Prevention, a security control that malware commonly bypasses to execute arbitrary code."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "escalate_priv",
      "why": "Confirms the presence of privilege escalation functionality, a common malicious behavior used to gain higher-level system access and bypass access controls."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "win_registry",
      "why": "Indicates Windows registry manipulation capabilities, which malware uses for persistence, configuration storage, and stealthy system modification."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "win_token",
      "why": "Confirms Windows token manipulation code, used by malware to abuse access tokens, impersonate privileged users, and bypass security restrictions."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "win_files_operation",
      "why": "Indicates file operation functionality, which malware uses for data exfiltration, payload deployment, and modifying system f
… [1259 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (Delphi Loader/Dropper)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Malware Analysis Report: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (Delphi Loader/Dropper)\n\n## Executive Summary\nThis report details the analysis of sample e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819, a malicious packed Delphi-based loader/dropper disguised as a legitimate Inno Setup software installer. Triage scoring assigned a malicious verdict with a confidence score of 8/10, confirming the sample is designed to deliver secondary payloads (e.g., info-stealers, ransomware) while evading static analysis and gaining elevated system access. Key findings include extreme file entropy (184) indicating heavy packing, confirmed obfuscation via XOR/RC4, process injection primitives (VirtualAlloc, VirtualProtect), privilege escalation functionality (AdjustTokenPrivileges, LookupPrivilegeValueW), and embedded network indicators (domain, IP addresses, URL) for command-and-control (C2) or payload delivery. The sample is not packed with UPX, using a custom packer with spaghetti code, delay-loaded imports, and high cross-reference looping functions to hinder analysis. All required analysis tools (capa, YARA, FLOSS, Malcat, PE imports) passed validation with no hard failures. (source: triage_verdict, deep-dive, malcat)\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 |\n| Sample Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe |\n| Project Name | incoming |\n| File Type | PE32 GUI executable (X86 architecture) |\n| Compiler | Borland Delphi (confirmed via RTL strings, Ghidra decompilation, YARA matches) |\n| Installer Framework | Inno Setup (confirmed via VersionInfo metadata, YARA InnoInstaller match) |\n| Packer | Custom packer (UPX unpack failed, entropy=184, obfuscation anomalies present) |\n| .NET Status | Not a .NET assembly (dnfile/monodis analysis returned no results) |\n| XOR Obfuscation | XOR 00 obfuscation confirmed at entry point (xorsearch recovered partial string \"This program must be r\") |\nThe sample is disguised as a legitimate software installer named \"Pringle Setup\" per extracted strings, a common social engineering tactic for malware distribution. (source: sample metadata, UPX evidence, xorsearch, dotnet_analyze, rule.yara strings, malcat metadata)\n\n#
… [28045 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 (Delphi Loader/Dropper)

## Executive Summary
This report details the analysis of sample e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819, a malicious packed Delphi-based loader/dropper disguised as a legitimate Inno Setup software installer. Triage scoring assigned a malicious verdict with a confidence score of 8/10, confirming the sample is designed to deliver secondary payloads (e.g., info-stealers, ransomware) while evading static analysis and gaining elevated system access. Key findings include extreme file entropy (184) indicating heavy packing, confirmed obfuscation via XOR/RC4, process injection primitives (VirtualAlloc, VirtualProtect), privilege escalation functionality (AdjustTokenPrivileges, LookupPrivilegeValueW), and embedded network indicators (domain, IP addresses, URL) for command-and-control (C2) or payload delivery. The sample is not packed with UPX, using a custom packer with spaghetti code, delay-loaded imports, and high cross-reference looping functions to hinder analysis. All required analysis tools (capa, YARA, FLOSS, Malcat, PE imports) passed validation with no hard failures. (source: triage_verdict, deep-dive, malcat)

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 |
| Sample Path | /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe |
| Project Name | incoming |
| File Type | PE32
… [26526 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — e29d2bd94621
_Generated 2026-08-04T05:27:21.330058+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=461c | cross_refs=True | llm_ok=True | runtime=18.99s -->

# Executive Summary

| Attribute | Value | Evidence Citation |
|-----------|-------|-------------------|
| Final Verdict | Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities | (scorecard, deep_dive_agentic) |
| Malware Family | Delphi Loader/Dropper | (cross-section:9. Comparison with Known Families, capa) |
| Analysis Confidence | High (LLM and v1 classifier agreement, 26 YARA matches, 37 capa rule triggers, aligned static + dynamic findings) | (v1_summary, yara, capa) |
| Sample Type | 32-bit Windows GUI PE, Borland Delphi compiled, packed/obfuscated | (cross-section:1. Sample Identification, cross-section:4. Static Analysis) |

This sample (SHA256: `e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819`) is a malicious packed Delphi-based loader/dropper, a family commonly leveraged in malware distribution chains to deliver secondary payloads such as info-stealers or ransomware via fake software installers. The sample employs layered obfuscation, process injection, and privilege escalation capabilities to evade static and dynamic analysis, and maintain persistent access to infected Windows endpoints. Cross-engine static and dynamic analysis confirms 15 distinct malicious capabilities mapped to 7 MITRE ATT&CK techniques, with 26 YARA rule matches and 37 capa behavior triggers validating the malicious classification, and associated IOCs including hardcoded network indicators, registry artifacts, and COM interface GUIDs have been extracted to support detection, containment, and response operations.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=237c | cross_refs=True | llm_ok=True | runtime=22.57s -->

# 1. Sample Identification
The analyzed sample is a 32-bit Windows Portable Executable (PE) file, with core identifying metadata detailed in the table below. All identifiers are unique to this sample and used for consistent reference across all subsequent analysis sections.

| Attribute | Value | Source |
|-----------|-------|--------|
| SHA256 | e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819 | Initial sample ingest (malcat) |
| File Path | /o
… [59141 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7565` | `f38e2a614fcaf80b` |
| `prompt.txt` | `True` | `25757` | `2f3ed435f7a2d35f` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `29044` | `58b26ac49a515bcb` |
| `REPORT-MASTER-v3.md` | `True` | `61656` | `f58f5b882dd7ae1f` |
| `REPORT-v2.md` | `True` | `29044` | `58b26ac49a515bcb` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `71184` | `1733c2582f12bdcd` |
| `rule.yar` | `True` | `1551` | `b8a2299e0ba05683` |
| `intake-validation.json` | `True` | `3666` | `08d25ea8e671e1cf` |
| `source-decisions.json` | `True` | `2793` | `df5435b12f045a95` |
| `malcat-triage.json` | `True` | `88314` | `4431cd2860fb1337` |
| `deep_dive/01-tools-raw.json` | `True` | `196210` | `530e07e139c92fbb` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4759` | `d8e9973d38813fb5` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `182955` | `9b835db5196e8ca9` |

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

- **intake_validation:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-validation.json` exists=`True` bytes=`3666` mtime=`2026-08-04T05:13:01.654118+00:00`
  - sha256: `08d25ea8e671e1cff0ed9b9ed3190b9160cf2717033ec2ebe91bbcc522097450`
- **malcat_triage:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/malcat-triage.json` exists=`True` bytes=`88314` mtime=`2026-08-04T05:10:55.373321+00:00`
  - sha256: `4431cd2860fb1337b539071b9a1776231dd7f35f7f79f305a7ce7f6f1e1ab1ad`
- **source_decisions:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/source-decisions.json` exists=`True` bytes=`2793` mtime=`2026-08-04T05:13:01.654118+00:00`
  - sha256: `df5435b12f045a959c22c2231bc5b002a1b3614cc3ec44f4fec3ef0ea9e4d83e`
- **ghidra_import_log:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-analyzeHeadless.log` exists=`True` bytes=`6556` mtime=`2026-08-04T05:10:59.359421+00:00`
  - sha256: `24814ea898dd8751fd57b993c565289a51ecbc2bce9849938276d58cc3a6c545`
- **ida_bootstrap_log:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 imports due to validation failure {ida, tool_summary, ida, why: IDA validation failed per warning, empty import list}; Ghidra has 145 imports {ghidra, tool_summary, imports, why: ghidra.imports field value is 145}; per existing import selection rule, Ghidra is selected as the primary source for imports when available."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 functions due to validation failure {ida, tool_summary, ida, why: IDA validation failed per warning, empty function list}; Ghidra has 3 functions {ghidra, tool_summary, funcs, why: ghidra.funcs field value 
… [2016 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "file_name": "koi_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "file_size": 2263752,
    "type": "PE",
    "architecture": "X86",
    "entropy": 184,
    "sha256": "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
    "metadata": {
      "Certificate::Issuer": "Certum Extended Validation Code Signing 2021 CA (Organiza
… [87514 more chars]
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
  "rule_count": 37,
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
      "name": "accept command line arguments",
      "attack": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "tactic": "Execution",
          "technique": "Command and Scripting Interpreter",
          "subtechnique": "",
          "id": "T1059"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "objective": "Execution",
          "behavior": "Command and Scripting Interpreter",
          "method": "",
          "id": "E1059"
        }
      ]
    },
    {
      "name": "query environment variable",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Information Discovery",
          "subtechnique": "",
          "id": "T1082"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "objective": "Discovery",
          "behavior": "System Information Discovery",
          "method": "",
          "id": "E1082"
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
          "technique": "File an
… [5542 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 830343,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 917570,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2194,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 146170,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Delphi_CompareCall",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 31860,
          "length": 42,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 722888,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$patternBorland",
          "offset": 41422,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "borland_delphi",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 50636,
          "length": 42,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 50636,
         
… [8357 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 11298,
  "strings_sampled": 80,
  "strings": [
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "NativeInt",
    "NativeUInt",
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
    "TClass",
    "HRESULT",
    "&op_Equality",
    "&op_Inequality",
    "Create",
    "BigEndian",
    "AStartIndex",
    "PInterfaceEntry",
    "TInterfaceEntry",
    "VTable",
    "IOffset",
    "ImplGetter",
    "PInterfaceTable4",
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
    "Equals"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 1,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 11297
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 132.09,
  "size_bytes": 2263752,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "file_name": "koi_sample.exe",
    "file_path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "file_size": 2263752,
    "type": "PE",
    "architecture": "X86",
    "entropy": 184,
    "sha256": "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
    "metadata": {
      "Certificate::Issuer": "Certum Extended Validation Code Signing 2021 CA (Organization=Asseco Data Systems S.A. / Unit=? / Country=PL)",
      "Certificate::Subject": "Zhengzhou Lichang Network Technology Co., Ltd.",
      "Certificate::Org Details": "Zhengzhou Lichang Network Technology Co., Ltd. / Unit=? / State=Henan / Locality=Zhengzhou / Country=CN / Email=?",
      "Certificate::Org Serial Number": "91410122MA40Y0N9XP",
      "Certificate::Validity": "from 2024-11-21 to 2025-11-21",
      "Certificate::SerialNumber": "04ebda42bf9235aecf2e07587ec4623f",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA",
      "Delphi::ProjectName": "SetupLdr",
      "VersionInfo::Comments": "This installation was built with Inno Setup.",
      "VersionInfo::CompanyName": "Pringle                                                     ",
      "VersionInfo::FileDescription": "Pringle Setup                                               ",
      "VersionInfo::FileVersion": "                    ",
      "VersionInfo::LegalCopyright": "                                                                                                    ",
      "VersionInfo::OriginalFileName": "                                                  ",
      "VersionInfo::ProductName": "Pringle                                                     ",
      "VersionInfo::ProductVersion": "2.2                                               ",
      "Exports::Module name": "SetupLdr.exe"
    },
    "entrypoint_ea": 742124,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 101
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 735744,
        "virtual_size": 737280,
        "rights": "RX",
        "entropy": 121
      },
      {
        "name": ".itext",
        "effective_address": 738304,
        "physical_size": 6144,
        "virtual_size": 8192,
        "rights": "RX",
        "entropy": 48
      },
      {
        "name": ".data",
        "effective_address": 746496,
        "physical_size": 14336,
        "virtual_size": 16384,
        "rights": "RW",
        "entropy": 82
      },
      {
        "name": ".idata",
        "effective_address": 762880,
        "physical_size": 4096,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 74
      },
      {
        "name": ".didata",
        "effective_address": 766976,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".edata",
        "effective_address": 771072,
        "physical_size": 512,
        "virtu
… [140911 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "entropy=184 file_summary Extremely high file entropy is a strong indicator of packed/obfuscated code, a common technique",
    "XorInLoop\u00d719, SpaghettiFunction\u00d730, HighXrefLoopingFunction\u00d712 anomalies These static analysis anomalies are characteris",
    "encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027) top_rules Confirms active use of obfuscation and encr",
    "allocate_memory (VirtualAlloc) [T1055], change_memory_protection (VirtualProtect) [T1055] signals These imports are core",
    "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW, advapi32.ConvertStringSecurityDescriptorToSecurityDescri"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities",
  "family": "Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers)",
  "score": 8,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy=184",
      "why": "Extremely high file entropy is a strong indicator of packed/obfuscated code, a common technique used by malware to hinder static analysis and evade detection."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop\u00d719, SpaghettiFunction\u00d730, HighXrefLoopingFunction\u00d712",
      "why": "These static analysis anomalies are characteristic of heavily obfuscated, packed malicious code designed to break disassembly and control flow analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027), encrypt data using RC4 PRGA (T1027)",
      "why": "Confirms active use of obfuscation and encryption techniques to hide malicious payloads and logic, aligning with the high entropy and obfuscation anomalies from Malcat."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "allocate_memory (VirtualAlloc) [T1055], change_memory_protection (VirtualProtect) [T1055]",
      "why": "These imports are core primitives for process injection, a common malicious tactic used to execute arbitrary code in the context of legitimate processes to evade detection."
    },
    {
      "source": "malcat",
      "query_or_table": "top high-signal imports",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW, advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "why": "These imports are used for privilege escalation, a common malicious tactic to gain elevated system access to perform sensitive actions like modifying system files or disabling security tools."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv",
      "why": "YARA rule explicitly flags privilege escalation functionality, directly corroborating the observed privilege-related imports from Malcat and pe_imports."
    },
    {
      "source": "malcat",
      "query_or_table": "metadata",
      "row_or_rule": "VersionInfo::Comments = \"This installation was built with Inno Setup.\", Delphi::ProjectName = \"SetupLdr\"",
      "why": "Confirms the sample is an Inno Setup installer (a common legitimate software deployment tool) repurposed as a malware delivery vector, with the project name indicating it is a setup loader."
    },
    {
      "source": "ghidra",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_40ab18 contains @System@@LStrAddRef$qqrpv (Delphi RTL string function)",
      "why": "Decompilation reveals Delphi runtime library function calls, confirming the sample is compiled with Delphi, consistent with Malcat metadata and YARA Borland/Delphi hits."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "Delphi RTL type strings (e.g., \"TObject&\", \"AnsiString\", \"Variant\")",
      "why": "Decoded strings include Delphi runtime type definitions, further confirming the sample's Delphi origin and consistent with other engine findings."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "DelayImports\u00d73",
      "why": "Delay-loaded imports are often used by malware to hide functionality from static analysis, only loading malicious imports at runtime to evade detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "IsPacked, Borland, Delphi, InnoInstaller",
      "why": "YARA rules confirm the sample is packed, compiled with Borland/Delphi, and is an Inno Setup installer, aligning with all other static analysis findings."
    }
  ],
  "summary": "This sample is a packed, obfuscated Delphi-based Inno Setup installer (SetupLdr) with an extremely high entropy of 184, indicating heavy packing to hinder static analysis. It contains confirmed malicious capabilities including process injection (via VirtualAlloc/VirtualProtect), privilege escalation (via advapi32 privilege adjustment imports and YARA escalate_priv hit), registry access, and uses X"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/prompt.txt` exists=`True` bytes=`25757` mtime=`2026-08-04T05:15:23.053115+00:00`
  - sha256: `2f3ed435f7a2d35f3af50bc0caa2c3de1e8ebaf931710f1287b246c0c8c37092`
- **verdict:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/verdict.json` exists=`True` bytes=`7565` mtime=`2026-08-04T05:16:06.766114+00:00`
  - sha256: `f38e2a614fcaf80b3e405c365e0fa0097683f34ed4aa2410f85b5b0e2fd570f9`

#### prompt_excerpt

```
# Triage evidence
sha256: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
sample_path: /opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe
ghidra_session: ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
ida_session: ida-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA has 0 imports due to validation failure {ida, tool_summary, ida, why: IDA validation failed per warning, empty import list}; Ghidra has 145 imports {ghidra, tool_summary, imports, why: ghidra.imports field value is 145}; per existing import selection rule, Ghidra is selected as the primary source for imports when available.
- functions: ghidra (confidence=medium) — IDA has 0 functions due to validation failure {ida, tool_summary, ida, why: IDA validation failed per warning, empty function list}; Ghidra has 3 functions 
… [24725 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities",
  "score": 8,
  "family_guess": "Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers)",
  "cross_engine_notes": "Cross-engine validation confirms consistent malicious indicators: 1) Import count alignment between Malcat (145) and pe_imports (142) validates the import dataset. 2) Delphi/Borland origin is confirmed across 4 engines: Malcat YARA hits for Borland/Delphi, Ghidra decompilation shows Delphi RTL function calls, FLOSS strings include Delphi RTL type definitions, Malcat metadata lists Delphi::ProjectName as 'SetupLdr'. 3) Obfuscation indicators are consistent: Malcat reports high entropy (184) and obfuscation anomalies, capa identifies XOR/RC4 obfuscation rules, YARA flags packed code. 4) Malicious capability alignment: Privilege escalation imports from Malcat match the Y
… [6565 more chars]
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
  "rule_count": 37,
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
      "name": "accept command line arguments",
      "attack": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "tactic": "Execution",
          "technique": "Command and Scripting Interpreter",
          "subtechnique": "",
          "id": "T1059"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Command and Scripting Interpreter"
          ],
          "objective": "Execution",
          "behavior": "Command and Scripting Interpreter",
          "method": "",
          "id": "E1059"
        }
      ]
    },
    {
      "name": "query environment variable",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Information Discovery",
          "subtechnique": "",
          "id": "T1082"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "System Information Discovery"
          ],
          "objective": "Discovery",
          "behavior": "System Information Discovery",
          "method": "",
          "id": "E1082"
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
          "technique": "File an
… [5541 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.05,
  "import_count": 142,
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
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 830343,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 917570,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 2194,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 146170,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Delphi_CompareCall",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 31860,
          "length": 42,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 722888,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$patternBorland",
          "offset": 41422,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": []
    },
    {
      "rule": "borland_delphi",
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 50636,
          "length": 42,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 50636,
         
… [8335 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 11298,
  "strings_sampled": 80,
  "strings": [
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "NativeInt",
    "NativeUInt",
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
    "TClass",
    "HRESULT",
    "&op_Equality",
    "&op_Inequality",
    "Create",
    "BigEndian",
    "AStartIndex",
    "PInterfaceEntry",
    "TInterfaceEntry",
    "VTable",
    "IOffset",
    "ImplGetter",
    "PInterfaceTable4",
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
    "Equals"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 1,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 11297
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 126.64,
  "size_bytes": 2263752,
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
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "disassembly": {
    "0x004b5eec": "\u250c 501: entry0 ();\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_24h @ ebp-0x24\n\u2502           ; var int32_t var_28h @ ebp-0x28\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n\u2502           ; var int32_t var_30h @ ebp-0x30\n\u2502           ; var int32_t var_34h @ ebp-0x34\n\u2502           ; var int32_t var_38h @ ebp-0x38\n\u2502           ; var int32_t var_3ch @ ebp-0x3c\n\u2502           ; var int32_t var_40h @ ebp-0x40\n\u2502           ; var int32_t var_5ch @ ebp-0x5c\n\u2502           0x004b5eec      55             push ebp\n\u2502           0x004b5eed      8bec           mov ebp, esp\n\u2502           0x004b5eef      83c4a4         add esp, 0xffffffa4\n\u2502           0x004b5ef2      53             push ebx\n\u2502           0x004b5ef3      56             push esi\n\u2502           0x004b5ef4      57             push edi\n\u2502           0x004b5ef5      33c0           xor eax, eax\n\u2502           0x004b5ef7      8945c4         mov dword [var_3ch], eax\n\u2502           0x004b5efa      8945c0         mov dword [var_40h], eax\n\u2502           0x004b5efd      8945a4         mov dword [var_5ch], eax\n\u2502           0x004b5f00      8945d0         mov dword [var_30h], eax\n\u2502           0x004b5f03      8945c8         mov dword [var_38h], eax\n\u2502           0x004b5f06      8945cc         mov dword [var_34h], eax\n\u2502           0x004b5f09      8945d4         mov dword [var_2ch], eax\n\u2502           0x004b5f0c      8945d8         mov dword [var_28h], eax\n\u2502           0x004b5f0f      8945ec         mov dword [var_14h], eax\n\u2502           0x004b5f12      b8b8144b00     mov eax, 0x4b14b8\n\u2502           0x004b5f17      e8b072f5ff     call 0x40d1cc\n\u2502           0x004b5f1c      33c0           xor eax, eax\n\u2502           0x004b5f1e      55             push ebp\n\u2502           0x004b5f1f      68e2654b00     push 0x4b65e2\n\u2502           0x004b5f24      64ff30         push dword fs:[eax]\n\u2502           0x004b5f27      648920         mov dword fs:[eax], esp\n\u2502           0x004b5f2a      33d2           xor edx, edx\n\u2502           0x004b5f2c      55             push ebp\n\u2502           0x004b5f2d      689e654b00     push 0x4b659e\n\u2502           0x004b5f32      64ff32         push dword fs:[edx]\n\u2502           0x004b5f35      648922         mov dword fs:[edx], esp\n\u2502           0x004b5f38      a134e64b00     mov eax, dword [0x4be634]   ; [0x4be634:4]=0\n\u2502           0x004b5f3d      e8a29dffff     call 0x4afce4\n\u2502           0x004b5f42      e8f598ffff     call 0x4af83c\n\u2502           0x004b5f47      8d55ec         lea edx, [var_14h]\n\u2502           0x004b5f4a      33c0           xor eax, eax\n\u2502           0x004b5f4c      e84fcdf6ff     call 0x422ca0\n\u2502           0x004b5f51      8b55ec         mov edx, dword [var_14h]\n\u2502           0x004b5f54      b8841d4c00     mov eax, 0x4c1d84\n\u2502           0x004b5f59      e8a21ef5ff     call 0x407e00\n\u2502           0x004b5f5e      6a02           push 2                      ; 2\n\u2502           0x004b5f60      6a00           push 0\n\u2502           0x004b5f62      6a01           push 1  ",
… [7848 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "exists": true,
    "hook_candidates": [
      "kernel32.dll!GetACP",
      "kernel32.dll!GetExitCodeProcess",
      "kernel32.dll!LocalFree",
      "kernel32.dll!CloseHandle",
      "kernel32.dll!SizeofResource",
      "comctl32.dll!InitCommonControls",
      "version.dll!GetFileVersionInfoSizeW",
      "version.dll!VerQueryValueW",
      "version.dll!GetFileVersionInfoW",
      "user32.dll!CreateWindowExW",
      "user32.dll!TranslateMessage",
      "user32.dll!CharLowerBuffW",
      "user32.dll!CallWindowProcW",
      "user32.dll!CharUpperW",
      "oleaut32.dll!SysAllocStringLen",
      "oleaut32.dll!SafeArrayPtrOfIndex",
      "oleaut32.dll!VariantCopy",
      "oleaut32.dll!SafeArrayGetLBound",
      "oleaut32.dll!SafeArrayGetUBound",
      "netapi32.dll!NetWkstaGetInfo",
      "netapi32.dll!NetApiBufferFree",
      "advapi32.dll!ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "advapi32.dll!RegQueryValueExW",
      "advapi32.dll!AdjustTokenPrivileges",
      "advapi32.dll!GetTokenInformation",
      "advapi32.dll!ConvertSidToStringSidW"
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
    "IsPacked yara_rule_matches Confirms the executable is packed, a common obfuscation technique used by malware to hinder a",
    "borland_delphi yara_rule_matches Indicates the sample is compiled with Borland Delphi, a development toolchain frequentl",
    "domain yara_rule_matches Confirms the presence of an embedded domain name, a network indicator typically used for comman",
    "IP yara_rule_matches Confirms embedded IPv4 and IPv6 address strings, which are network indicators for malicious communi",
    "url yara_rule_matches Confirms an embedded URL, likely used for downloading additional malicious payloads or communicati"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 0,
  "summary": "The analyzed sample is a packed, Borland Delphi-compiled Windows GUI PE32 executable containing multiple indicators of malicious activity, including embedded network indicators (domain, IPv4/IPv6 addresses, URL), functionality to disable Data Execution Prevention (DEP), privilege escalation code, Wi",
  "key_evidence": [
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsPacked",
      "why": "Confirms the executable is packed, a common obfuscation technique used by malware to hinder analysis and evade detection."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "borland_delphi",
      "why": "Indicates the sample is compiled with Borland Delphi, a development toolchain frequently used to create malware."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "domain",
      "why": "Confirms the presence of an embedded domain name, a network indicator typically used for command-and-control (C2) communication or malicious payload delivery."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IP",
      "why": "Confirms embedded IPv4 and IPv6 address strings, which are network indicators for malicious communication endpoints."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "url",
      "why": "Confirms an embedded URL, likely used for downloading additional malicious payloads or communicating with C2 infrastructure."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "disable_dep",
      "why": "Indicates the sample contains code to disable Data Execution Prevention, a security control that malware commonly bypasses to execute arbitrary code."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "escalate_priv",
      "why": "Confirms the presence of privilege escalation functionality, a common malicious behavior used to gain higher-level system access and bypass access controls."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "win_registry",
      "why": "Indicates Windows registry manipulation capabilities, which malware uses for persistence, configuration storage, and stealthy system modification."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "win_token",
      "why": "Confirms Windows token manipulation code, used by malware to abuse access tokens, impersonate privileged users, and bypass security restrictions."
    },
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "win_files_operation",
      "why": "Indicates file operation functionality, which malware uses for data exfiltration, payload deployment, and modifying system files for persistence or disruption."
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
      "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
      "path": "/opt/sa
… [11435 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "file_name": "koi_sample.exe",
    "fil
… [143036 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 37,
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
… [8641 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 2263752,
  "duration_s": 0.05,
  "import_count": 142,
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
  "string_count": 11298,
  "strings_sampled": 80,
  "strings": [
    "1096159247",
    "This program must be run under Win32",
    "`.itext",
    "`.data",
    ".idata",
    ".didata",
    ".edata",
    ".rdata",
    "@.rsrc",
    "Boolean",
    "System",
    "AnsiChar",
    "ShortInt",
    "SmallInt",
    "Integer",
    "Cardinal",
    "Pointer",
    "UInt64",
    "NativeInt
… [1522 more chars]
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
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "disassembly": {
    "0x004b5eec": "\u250c 501: entry0 ();\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_1ch @ ebp-0x1c\n\u2502           ; var int32_t var_24h @ e
… [10948 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r\n",
  "xorsearch_stderr": "",
  "xorse
… [21 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
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
    "path": "/opt/samples/corpus/incoming/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/koi_sample.exe",
    "exists": true,
    "hook_candidates": [
      "kernel32.dll!GetACP",
      "kernel32.dll!GetExitCodeProcess",
      "kernel32.dll!LocalFree",
      "kernel32.dll!CloseHandle",
      "kernel32.dll!
… [885 more chars]
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
      "address": "4208496",
      "size": "1"
    },
    {
      "name": "DelayLoad_GetLogicalProcessorInformation",
      "address": "4208632",
      "size": "1"
    },
    {
      "name": "DelayLoad_GetNativeSystemInfo",
      "address": "4252280",
      "size": "1"
    }
  ],
  "
… [297 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "start_ea",
    "name",
    "size",
    "end_ea",
    "flags",
    "namespace",
    "signature",
    "return_type",
    "arg_count",
    "calling_conv",
    "return_is_ptr",
    "return_is_void",
    "return_is_int",
    "return_is_integral"
  ],
  "rows": [
    {
      "address": "4208496",
      "start_ea": "4208496",
      "name": "DelayLoad_MessageBoxA",
   
… [1636 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [
    {
      "address": "4991458",
      "ea": "4991458",
      "length": "25",
      "type": "TerminatedCString",
      "type_name": "ascii",
      "width": "1",
      "width_name": "1-byte",
      "layou
… [4696 more chars]
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
      "name": "GetACP",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "2",
      "name": "GetExitCodeProcess",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "3",
      "name": "LocalFree",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "4",
      "name":
… [4895 more chars]
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
      "name": "GetACP",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "2",
      "name": "GetExitCodeProcess",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "3",
      "name": "LocalFree",
      "module": "KERNEL32.DLL"
    },
    {
      "address": "4",
      "name":
… [4895 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "ea",
    "length",
    "type",
    "type_name",
    "width",
    "width_name",
    "layout",
    "layout_name",
    "encoding",
    "content"
  ],
  "rows": [
    {
      "address": "4990280",
      "ea": "4990280",
      "length": "13",
      "type": "TerminatedCString",
      "type_name": "ascii",
      "width": "1",
      "width_name": "1-byte",
      "layou
… [15684 more chars]
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
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "ConvertSidToStringSidW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "GetTokenInformation",
      "module": "
… [3859 more chars]
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
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "ConvertSidToStringSidW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "GetTokenInformation",
      "module": "
… [3859 more chars]
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
  "session_id": "ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "audit_path": "/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/audit.jsonl"
}
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
  "session_id": "ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "audit_path": "/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/audit.jsonl"
}
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
      "name": "ConvertStringSecurityDescriptorToSecurityDescriptorW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "RegQueryValueExW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "GetTokenInformation",
      "module": "ADVAPI
… [712 more chars]
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
  "session_id": "ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "audit_path": "/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/audit.jsonl"
}
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
  "session_id": "ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "audit_path": "/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/audit.jsonl"
}
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
  "session_id": "ghidra-pe-e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819",
  "audit_path": "/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/audit.jsonl"
}
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
      "name": "GetModuleHandleW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "LoadLibraryA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetProcAddress",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "LoadLibraryW",
      "module": "KERNEL32.DLL"
    }
  ],
  "row_count": 4,
  "total_row_coun
… [265 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/01-tools-raw.json` exists=`True` bytes=`196210` mtime=`2026-08-04T05:18:28.639411+00:00`
  - sha256: `530e07e139c92fbb4be085d02ec7c32f8282551b7cde9feca989ae136613b6fa`
- **sql_evidence:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/05-deep-dive.json` exists=`True` bytes=`4759` mtime=`2026-08-04T05:20:25.844608+00:00`
  - sha256: `d8e9973d38813fb522ab298360f831680df7c92e7c7ecab2795a0223294024d9`

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
  "summary": "The analyzed sample is a packed, Borland Delphi-compiled Windows GUI PE32 executable containing multiple indicators of malicious activity, including embedded network indicators (domain, IPv4/IPv6 addresses, URL), functionality to disable Data Execution Prevention (DEP), privilege escalation code, Windows registry manipulation, token manipulation, and file operation capabilities, all consistent with malware designed to compromise system security.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan findings",
      "query_or_table": "yara_rule_matches",
      "row_or_rule": "IsPacked",
      "why": "Confirms the executable is packed, a common obfuscation techniq
… [3959 more chars]
```

- **agentic:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`577261` mtime=`2026-08-04T05:20:25.844608+00:00`
  - sha256: `654f76e089ac048121d7da6b660909f5d89739b0a2d0a928c453fa1b59d494c4`

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

- **rule_yar:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/rule.yar` exists=`True` bytes=`1551` mtime=`2026-08-04T05:20:31.858408+00:00`
  - sha256: `b8a2299e0ba05683bcf0234e80c3fae3d21009ee6c5c48b7dc47be1297aba494`

#### excerpt

```
// yara_gen_v2.py — 2026-08-04T05:20:31.859168+00:00
rule CADRE_v2_unknown_e29d2bd94621 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "No mapping for the Unicode character exists in the target multi-byte code page" ascii wide
        $s1 = "Cannot have multiple single cast observers added to the observers collection" ascii wide
        $s2 = "No single cast observer with ID %d was added to the observer collection" ascii wide
        $s3 = "No multi cast observer with ID %d was added to the observer collection" ascii wide
        $s4 = "Cannot cal
… [749 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-MASTER-v2.md` exists=`True` bytes=`29044` mtime=`2026-08-04T05:22:13.493606+00:00`
  - sha256: `58b26ac49a515bcb1a33c304576d7ee64ff260626cfda51564b00c3269451ad8`
- **REPORT_MASTER_v3:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-MASTER-v3.md` exists=`True` bytes=`61656` mtime=`2026-08-04T05:27:21.333199+00:00`
  - sha256: `f58f5b882dd7ae1fb649566e310d21424c442a9ef34022f62c388e1518902dbf`
- **REPORT_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-v2.md` exists=`True` bytes=`29044` mtime=`2026-08-04T05:22:13.493606+00:00`
  - sha256: `58b26ac49a515bcb1a33c304576d7ee64ff260626cfda51564b00c3269451ad8`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`104083` mtime=`2026-08-04T05:24:12.030803+00:00`
  - sha256: `cca81e4fba2832c757bf32fec80629b8e5536c2392223e94a0128ae8728c892a`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`71184` mtime=`2026-08-04T05:28:47.701697+00:00`
  - sha256: `1733c2582f12bdcd62f71828e740e1f2d3f2fa865ba897db58476683f54f35a9`
- **report_v2_json:** `/opt/samples/logs/e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819/report-v2.json` exists=`True` bytes=`31545` mtime=`2026-08-04T05:24:12.034403+00:00`
  - sha256: `73c8de395c13d738cc900b02ca9e2c0f21c748a0a7f4282a4a975775e6527d40`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Delphi Loader/Dropper (common in malware distribution chains for delivering secondary payloads via fake software installers)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedit
… [28126 more chars]
```


#### v3_excerpt

```
# RE Report — e29d2bd94621
_Generated 2026-08-04T05:27:21.330058+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=461c | cross_refs=True | llm_ok=True | runtime=18.99s -->

# Executive Summary

| Attribute | Value | Evidence Citation |
|-----------|-------|-------------------|
| Final Verdict | Malicious: Packed Delphi-based Loader/Dropper with Obfuscation, Process Injection, and Privilege Escalation Capabilities | (scorecard, deep_dive_agentic) |
| Malware Family | Delphi Loader/Dropper | (cross-section:9. Comparison with Known Families, capa) |
| Analysis Confidence | High (LLM and v1 classifier agreement, 26 YARA matches, 37 capa rule triggers, aligned static + dynamic findings) | (v1_summary, yara, capa) |
| Sample Type | 32-bit Windows GUI PE, Borland
… [60741 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
