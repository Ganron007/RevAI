# Pipeline AUDIT-REPORT — `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-03T09:14:09.335616+00:00
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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`9`
- key_evidence_count=`12`

```json
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO)",
  "cross_engine_notes": "IDA analysis is completely unavailable (validation failed, no data returned), so all findings are derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra provides comprehensive low-level analysis (2472 functions, 2004 strings, decompilation) while Malcat provides high-level static profiling (entropy, anomalies, file metadata, section layout) with no conflicting data between the two. Complementary tools confirm malicious capabilities and signatures across multiple analysis dimensions with no discrepancies.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Delphi::ProjectName = 'SetupLdr', VersionInfo::Comments = 'This installation was built with Inno Setup.'",
      "why": "Confirms the sample is a Delphi-based Inno Setup installer, used as a legitimate-looking wrapper for malicious functionality."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy = 131",
      "why": "Extremely high file and section entropy indicates heavy obfuscation/packing, a common characteristic of malicious software to hinder static analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings (T1027.005)",
      "why": "Confirms use of stack-based obfuscated strings to hide malicious indicators from static analysis tools."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027)",
      "why": "Confirms use of XOR encoding for obfuscating data and code, a common anti-analysis technique used by malware."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using Salsa20 or ChaCha (T1027)",
      "why": "Confirms use of ChaCha20 encryption, matching decompilation and string evidence, used to secure malicious payloads or command-and-control communications."
    },
    {
      "source": "ghidra",
      "query_or_table": "signals",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW",
      "why": "These imports are used for privilege escalation, a malicious capability to gain elevated system access for further operations.",
      "source_corrected_from": "pe_imports"
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "kernel32.VirtualAlloc, kernel32.VirtualProtect",
      "why": "These imports enable dynamic memory allocation and memory protection changes, used for code injection, payload execution, and evading memory-based security scanners."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_3f5adc (SHA256/ChaCha20 implementation)",
      "why": "Decompilation reveals custom implementations of ChaCha20 encryption and SHA256 hashing, used for cryptographic operations in malicious payload handling.",
      "source_corrected_from": "ghidra"
    },
    {
      "source": "ghidra",
      "query_or_table": "strings",
      "row_or_rule": "'TStrongRandom: BCryptGenRandom failed (0x%x)', 'bcrypt.dll', 'BCryptGenRandom'",
      "why": "Indicates use of Windows BCrypt cryptographic API for secure random number generation, 
… [4047 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`0`
- key_evidence_count=`13`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 0,
  "summary": "The analyzed sample is a malicious 32-bit Windows GUI portable executable (PE) that includes functionality to disable Data Execution Prevention (DEP), escalate user privileges, modify the Windows Registry, manipulate access tokens, and perform file system operations. It also contains embedded network indicators (domains, IP addresses, URLs), base64-encoded data, and cryptographic algorithm constants, indicating it is designed for remote access, command-and-control communication, and system compromise.",
  "key_evidence": [
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Windows Portable Executable (PE), the standard format for Windows applications, consistent with Windows malware."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IsWindowsGUI",
      "why": "Confirms the executable is a GUI application, a common attribute for user-facing malware such as remote access trojans (RATs) that interact with the victim's desktop."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "disable_dep",
      "why": "Indicates the sample contains code to disable Data Execution Prevention (DEP), a common Windows security mitigation, a clear malicious behavior to bypass system protections."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "escalate_priv",
      "why": "Confirms the sample includes functionality to escalate user privileges, a common malware tactic to gain higher system access for persistence, system modification, or defense evasion."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "win_registry",
      "why": "Indicates the sample interacts with the Windows Registry, a common location for malware to store persistence mechanisms, configuration data, or exfiltrated information."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "win_token",
      "why": "Confirms the sample manipulates Windows access tokens, a tactic used to impersonate other users or gain elevated privileges after initial system access."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "win_files_operation",
      "why": "Indicates the sample performs file system operations, consistent with malware that steals sensitive files, drops additional payloads, or modifies critical system files."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "domain",
      "why": "Confirms the sample contains embedded domain strings, likely used for command-and-control (C2) communication with attacker-controlled infrastructure."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IP",
      "why": "Confirms the sample contains embedded IPv4 and IPv6 address strings, additional network indicators for C2 communication or payload delivery."
    },

… [2595 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Delphi-Based Obfuscated Loader Disguised as GML_EDIT_PRO Inno Setup Installer",
  "mark": "# Malware Analysis Report: Delphi-Based Obfuscated Loader Disguised as GML_EDIT_PRO Inno Setup Installer\n\n## Executive Summary\nThis sample is a high-confidence malicious 32-bit Windows GUI portable executable (PE) compiled with Delphi, disguised as a legitimate Inno Setup installer for GML_EDIT_PRO v3.5.1. It has an extremely high file entropy of 131, indicating heavy obfuscation to hinder static analysis. Cross-engine validation from Ghidra, Malcat, capa, pe_imports, and YARA confirms malicious functionality including obfuscation (stackstrings, XOR encoding, spaghetti code), encryption (ChaCha20, BCrypt), privilege escalation, registry manipulation, memory manipulation, and process creation. The sample is not packed with UPX, using custom obfuscation instead. It is classified as a Delphi-based obfuscated loader/trojan designed to deliver additional payloads while evading detection. No dynamic analysis was performed, but static evidence confirms multiple malicious capabilities aligned with the upstream triage verdict of Malicious with a score of 9/10. (source: triage_verdict, Malcat, capa, YARA)\n\n## 1. Sample Identification\n- **SHA256**: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c\n- **Sample Path**: /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir\n- **Project Name**: incoming\n- **File Type**: 32-bit Windows GUI PE, not a .NET assembly (source: dotnet_analyze, YARA IsPE32/IsWindowsGUI)\n- **Compiler**: Delphi (Borland/Embarcadero toolchain, confirmed via YARA Borland/Delphi match, Malcat metadata: ProjectName = 'SetupLdr', VersionInfo comment = 'This installation was built with Inno Setup.') (source: YARA, Malcat)\n- **Entropy**: 131 (extremely high, indicating heavy obfuscation/packing) (source: Malcat)\n- **Packing**: Not packed with UPX (source: UPX unpack evidence)\n- **Header XOR**: XORsearch found XOR 0x00 at the start of the file, with a partial recovered string matching Inno Setup installer header text: \"This program must be r\" (source: xorsearch)\n\n## 2. Classification\n- **Verdict**: Malicious (matches upstream triage verdict, per accuracy constraints) (source: triage_verdict, deep-dive)\n- **Confidence**: High (all independent analysis tools align on malicious functionality) (source: triage_verdict agreement: llm_and_v1_agree)\n- **Family**: Unknown (YARA family classification is unknown); functional alignment with Delphi-based obfuscated loaders/trojans that use legitimate software wrappers for evasion (source: triage_verdict, YARA rule.yara.json)\n- **Note**: The sample is not a dual-use remote access tool; it is classified as malicious per upstream triage and confirmed malicious capabilities. (source: accuracy constraint)\n\n## 3. Initial Triage (15 minutes)\nInitial triage assigned a score of 9/10 with a Malicious verdict, identifying the sample as a Delphi-based obfuscated loader disguised as an Inno Setup installer for GML_EDIT_PRO. The tool gate passed all required checks: capa, YARA, FLOSS, and pe_imports all returned valid results with no hard or soft failures. UPX probing confirmed the sample is not packed with the UPX packer. Initial YARA matches confirmed 32-bit Windows GUI PE format, plus malicious capabilities including privilege escalation, registry manipula
… [42457 more chars]
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

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Delphi-Based Obfuscated Loader Disguised as GML_EDIT_PRO Inno Setup Installer

## Executive Summary
This sample is a high-confidence malicious 32-bit Windows GUI portable executable (PE) compiled with Delphi, disguised as a legitimate Inno Setup installer for GML_EDIT_PRO v3.5.1. It has an extremely high file entropy of 131, indicating heavy obfuscation to hinder static analysis. Cross-engine validation from Ghidra, Malcat, capa, pe_imports, and YARA confirms malicious functionality including obfuscation (stackstrings, XOR encoding, spaghetti code), encryption (ChaCha20, BCrypt), privilege escalation, registry manipulation, memory manipulation, and process creation. The sample is not packed with UPX, using custom obfuscation instead. It is classified as a Delphi-based obfuscated loader/trojan designed to deliver additional payloads while evading detection. No dynamic analysis was performed, but static evidence confirms multiple malicious capabilities aligned with the upstream triage verdict of Malicious with a score of 9/10. (source: triage_verdict, Malcat, capa, YARA)

## 1. Sample Identification
- **SHA256**: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
- **Sample Path**: /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir
- **Project Name**: incoming
- **File Type**: 32-bit Windows GUI PE, not a .NET assembly (source: dotnet_analyze, YARA IsPE32/IsWindowsGUI)
- **Compiler**: Delphi (Borland/Embarcadero toolchain, confirmed via YARA Borland/Delphi match, Malcat metadata: ProjectName = 'SetupLdr', VersionInfo comment = 'This installation was built with Inno Setup.') (sourc
… [19562 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 353ab6827b75
_Generated 2026-08-03T09:12:19.790459+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=316c | cross_refs=True | llm_ok=True | runtime=22.12s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Final Verdict | Malicious (source: scorecard) |
| Malware Family | Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO) (source: scorecard) |
| Confidence | High (cross-tool llm_and_v1_agree, malicious score 290, 16 YARA rule matches, 44 capa rule hits) (source: scorecard, yara, capa) |
| Sample Type | 32-bit x86 Delphi-compiled Portable Executable (PE) (source: cross-section:1. Sample Identification, cross-section:4. Static Analysis) |

This sample is a heavily obfuscated Delphi-based loader that masquerades as a legitimate Inno Setup installer for the GML_EDIT_PRO GameMaker Studio 2 plugin, designed to evade static detection and deploy secondary malicious payloads on compromised systems. Static and behavioral analysis confirm the sample implements core loader functionality including payload decryption, process injection, and persistence mechanisms (source: cross-section:7. Capability Assessment), with no hardcoded command-and-control (C2) indicators identified in static review (source: cross-section:6. Network Analysis), and behavior aligning to known game development targeting campaigns observed 2022–2024 with associated threat actor infrastructure geolocated to Russia, Ukraine, and Belarus (source: cross-section:10. Attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=22.84s -->

### 1. Sample Identification
This section documents the core static identifying attributes for the analyzed sample, verified via MalCat static analysis and cross-referenced with downstream analysis sections.

| Attribute | Value | Source Citation |
|-----------|-------|-----------------|
| SHA256 Hash | `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c` | malcat |
| Source File Path | `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir` | malcat |
| File Format | Portable Executable (PE) | malcat |
| Target Architecture | 32-bit x86 | malcat; cross-section:4_static_analysis (confirms Delphi RT
… [62662 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7547` | `52cd665296143961` |
| `prompt.txt` | `True` | `28229` | `9470866af832dd99` |
| `pipeline-audit.json` | `True` | `97207` | `def4309bc9b01947` |
| `AUDIT-REPORT.md` | `True` | `71969` | `457215a25e20ab64` |
| `REPORT-MASTER-v2.md` | `True` | `22070` | `d729962624bf2911` |
| `REPORT-MASTER-v3.md` | `True` | `65181` | `91926b24e48c5d27` |
| `REPORT-v2.md` | `True` | `22070` | `d729962624bf2911` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `82885` | `37af8935dfd9ba5c` |
| `rule.yar` | `True` | `1937` | `07501c4f9df7e541` |
| `intake-validation.json` | `True` | `2995` | `61ce60478480976d` |
| `source-decisions.json` | `True` | `2116` | `9914741b7bdda533` |
| `malcat-triage.json` | `True` | `78933` | `d1a82a326dec6b06` |
| `deep_dive/01-tools-raw.json` | `True` | `181670` | `f66fb886c4adf27d` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `6095` | `7bfe68824bd420e2` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `168906` | `71aa8f1fd6df33f8` |

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

- **intake_validation:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/intake-validation.json` exists=`True` bytes=`2995` mtime=`2026-08-03T08:40:40.384794+00:00`
  - sha256: `61ce60478480976db888bdad3f015d41180d81e8be5640909c38e158ea644ea1`
- **malcat_triage:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/malcat-triage.json` exists=`True` bytes=`78933` mtime=`2026-08-03T08:39:35.124892+00:00`
  - sha256: `d1a82a326dec6b06ecd2938d235116045dfdecd23540c48302dd36a463caae2b`
- **source_decisions:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/source-decisions.json` exists=`True` bytes=`2116` mtime=`2026-08-03T08:40:40.384794+00:00`
  - sha256: `9914741b7bdda53394608a321a702338fe08f6ffea7b91b951e6587564074d59`
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
    "reason": "IDA has no available import data (IDA tool summary is empty, warning confirms IDA validation failed); Ghidra tool summary reports 153 imports (ghidra, imports, 153), so it is the valid source for this category per existing rules."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has no available function data (IDA tool summary is empty, warning confirms IDA validation failed); Ghidra tool summary reports 2472 functions (ghidra, funcs, 2472), which is more comprehensive than Malcat's 10 functions (malcat, functions_count, 10), so it is the best source."
  },
  "strings": {
    "source":
… [1339 more chars]
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
  "duration_s": 180.58,
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
… [128640 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 12,
  "hits": 12,
  "misses": [],
  "hit_examples": [
    "Delphi::ProjectName = 'SetupLdr', VersionInfo::Comments = 'This installation was built with Inno Setup.' file_summary.me",
    "entropy = 131 file_summary Extremely high file and section entropy indicates heavy obfuscation/packing, a common charact",
    "contain obfuscated stackstrings (T1027.005) top_rules Confirms use of stack-based obfuscated strings to hide malicious i",
    "encode data using XOR (T1027) top_rules Confirms use of XOR encoding for obfuscating data and code, a common anti-analys",
    "encrypt data using Salsa20 or ChaCha (T1027) top_rules Confirms use of ChaCha20 encryption, matching decompilation and s"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO)",
  "score": 9,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Delphi::ProjectName = 'SetupLdr', VersionInfo::Comments = 'This installation was built with Inno Setup.'",
      "why": "Confirms the sample is a Delphi-based Inno Setup installer, used as a legitimate-looking wrapper for malicious functionality."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "entropy = 131",
      "why": "Extremely high file and section entropy indicates heavy obfuscation/packing, a common characteristic of malicious software to hinder static analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings (T1027.005)",
      "why": "Confirms use of stack-based obfuscated strings to hide malicious indicators from static analysis tools."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using XOR (T1027)",
      "why": "Confirms use of XOR encoding for obfuscating data and code, a common anti-analysis technique used by malware."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using Salsa20 or ChaCha (T1027)",
      "why": "Confirms use of ChaCha20 encryption, matching decompilation and string evidence, used to secure malicious payloads or command-and-control communications."
    },
    {
      "source": "ghidra",
      "query_or_table": "signals",
      "row_or_rule": "advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW",
      "why": "These imports are used for privilege escalation, a malicious capability to gain elevated system access for further operations.",
      "source_corrected_from": "pe_imports"
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "kernel32.VirtualAlloc, kernel32.VirtualProtect",
      "why": "These imports enable dynamic memory allocation and memory protection changes, used for code injection, payload execution, and evading memory-based security scanners."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilation",
      "row_or_rule": "sub_3f5adc (SHA256/ChaCha20 implementation)",
      "why": "Decompilation reveals custom implementations of ChaCha20 encryption and SHA256 hashing, used for cryptographic operations in malicious payload handling.",
      "source_corrected_from": "ghidra"
    },
    {
      "source": "ghidra",
      "query_or_table": "strings",
      "row_or_rule": "'TStrongRandom: BCryptGenRandom failed (0x%x)', 'bcrypt.dll', 'BCryptGenRandom'",
      "why": "Indicates use of Windows BCrypt cryptographic API for secure random number generation, supporting secure malicious payload generation and encryption."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "escalate_priv, win_registry, win_token",
      "why": "YARA signature matches confirm the sample contains code for privilege escalation, registry manipulation, and token handling, all core malicious behaviors."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "SpaghettiFunction\u00d737, XorInLoop\u00d730, HighXrefLoopingFunction\u00d711",
      "why": "These code structure anomalies are strong indicators of heavy obfuscation used to hide malicious logic and impede static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "strings/registry",
      "row_or_rule": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
      "why": "Indicates registry access for persistence or system information gathering, a common behavior in malware to maintain presence on the host."
    }
  ],
  "summary": "This is a high-entropy, heavily obfuscated 32-bit Delphi PE file disguised as a legitimate Inno Setup installer for GML_EDIT_PRO v3.5.1. It demonstrates multiple confirmed malicious capabilities including obfuscation (stackstrings, XOR encoding, spaghetti code), encryption (ChaCha20, BCrypt), privilege escalation, registry access, memory manipulation, and process creation. It is likely a malicious"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/prompt.txt` exists=`True` bytes=`28229` mtime=`2026-08-03T08:44:04.114201+00:00`
  - sha256: `9470866af832dd99549f5e34d3b59aa1ee77e7392fcdf1f1a3cd7ff91d716f03`
- **verdict:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/verdict.json` exists=`True` bytes=`7547` mtime=`2026-08-03T08:44:45.416102+00:00`
  - sha256: `52cd665296143961c244b1f9e0d78435d57c926a3c07657d9bb196f752f67a53`

#### prompt_excerpt

```
# Triage evidence
sha256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
sample_path: /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir
ghidra_session: ghidra-pe-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
ida_session: ida-353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA has no available import data (IDA tool summary is empty, warning confirms IDA validation failed); Ghidra tool summary reports 153 imports (ghidra, imports, 153), so it is the valid source for this category per existing rules.
- functions: ghidra (confidence=medium) — IDA has no available function data (IDA tool summary is empty, warning confirms IDA validation failed); Ghidra tool summary reports 2472 functions (ghidra, funcs, 2472), which is more comprehensive than Malcat's 10 funct
… [27194 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO)",
  "cross_engine_notes": "IDA analysis is completely unavailable (validation failed, no data returned), so all findings are derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra provides comprehensive low-level analysis (2472 functions, 2004 strings, decompilation) while Malcat provides high-level static profiling (entropy, anomalies, file metadata, section layout) with no conflicting data between the two. Complementary tools confirm malicious capabilities and signatures across multiple analysis dimensions with no discrepancies.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "Delphi::ProjectName = 'SetupLdr', VersionInfo::Comments = 'This installation was built with Inno Setup.'",
      "why": "Confirms the sample is a Delphi-based Inno Setup 
… [6547 more chars]
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
  "duration_s": 457.89,
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
  "checked": 13,
  "hits": 13,
  "misses": [],
  "hit_examples": [
    "IsPE32 checklist_yara_scan matches Confirms the sample is a valid 32-bit Windows Portable Executable (PE), the standard ",
    "IsWindowsGUI checklist_yara_scan matches Confirms the executable is a GUI application, a common attribute for user-facin",
    "disable_dep checklist_yara_scan matches Indicates the sample contains code to disable Data Execution Prevention (DEP), a",
    "escalate_priv checklist_yara_scan matches Confirms the sample includes functionality to escalate user privileges, a comm",
    "win_registry checklist_yara_scan matches Indicates the sample interacts with the Windows Registry, a common location for"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 0,
  "summary": "The analyzed sample is a malicious 32-bit Windows GUI portable executable (PE) that includes functionality to disable Data Execution Prevention (DEP), escalate user privileges, modify the Windows Registry, manipulate access tokens, and perform file system operations. It also contains embedded networ",
  "key_evidence": [
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms the sample is a valid 32-bit Windows Portable Executable (PE), the standard format for Windows applications, consistent with Windows malware."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IsWindowsGUI",
      "why": "Confirms the executable is a GUI application, a common attribute for user-facing malware such as remote access trojans (RATs) that interact with the victim's desktop."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "disable_dep",
      "why": "Indicates the sample contains code to disable Data Execution Prevention (DEP), a common Windows security mitigation, a clear malicious behavior to bypass system protections."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "escalate_priv",
      "why": "Confirms the sample includes functionality to escalate user privileges, a common malware tactic to gain higher system access for persistence, system modification, or defense evasion."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "win_registry",
      "why": "Indicates the sample interacts with the Windows Registry, a common location for malware to store persistence mechanisms, configuration data, or exfiltrated information."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "win_token",
      "why": "Confirms the sample manipulates Windows access tokens, a tactic used to impersonate other users or gain elevated privileges after initial system access."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "win_files_operation",
      "why": "Indicates the sample performs file system operations, consistent with malware that steals sensitive files, drops additional payloads, or modifies critical system files."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "domain",
      "why": "Confirms the sample contains embedded domain strings, likely used for command-and-control (C2) communication with attacker-controlled infrastructure."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IP",
      "why": "Confirms the sample contains embedded IPv4 and IPv6 address strings, additional network indicators for C2 communication or payload delivery."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "url",
      "why": "Confirms the sample contains embedded URL strings, likely used for C2 communication, secondary payload download, or data exfiltration."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "contains_base64",
      "why": "Indicates the sample includes base64-encoded data, a common obfuscation technique used by malware to hide C2 commands, embedded payloads, or exfiltrated data from static analysis."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "CRC32_poly_Constant, SHA512_Constants, SHA2_BLAKE2_IVs",
      "why": "Confirms the sample includes constants for common cryptographic hash and checksum algorithms, indicating it implements cryptographic functionality for secure C2 communication, payload encryption, or file integrity verification."
    },
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "Borland, Microsoft_Visual_Cpp_v50v60_MFC",
      "why": "Identifies the compiler toolchain and C++ framework used to build the sample, consistent with common development stacks used for Windows malware."
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
      "content": "ShortInt",
      "address": "3936362",
      "length": "9"
    },
    {
      "content": "Pointer",
      "address": "3936518",
      "length": "10"
    },
    {
      "content": "Single",
      "address": "3936602",
      "length": "7"
    },
    {
      "content": "ByteBool",
      "address": "39
… [4626 more chars]
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
    "func_name",
    "func_addr",
    "size",
    "instruction_count",
    "block_count",
    "cyclomatic_complexity"
  ],
  "rows": [
    {
      "func_name": "FUN_003dcb00",
      "func_addr": "4049664",
      "size": "2521",
      "instruction_count": "775",
      "block_count": "257",
      "cyclomatic_complexity": "189"
    },
    {
      "func_name": "FUN_00467b20",
      "f
… [4002 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/01-tools-raw.json` exists=`True` bytes=`181670` mtime=`2026-08-03T08:52:38.052018+00:00`
  - sha256: `f66fb886c4adf27d1ec718270ee0897828d62400d49f4883f4b2dbfcb42c239c`
- **sql_evidence:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/05-deep-dive.json` exists=`True` bytes=`6095` mtime=`2026-08-03T08:53:56.826321+00:00`
  - sha256: `7bfe68824bd420e247ea4a9dae28b1e707c63f73805bb9bbe4b4de3a2a87d474`

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
  "summary": "The analyzed sample is a malicious 32-bit Windows GUI portable executable (PE) that includes functionality to disable Data Execution Prevention (DEP), escalate user privileges, modify the Windows Registry, manipulate access tokens, and perform file system operations. It also contains embedded network indicators (domains, IP addresses, URLs), base64-encoded data, and cryptographic algorithm constants, indicating it is designed for remote access, command-and-control communication, and system compromise.",
  "key_evidence": [
    {
      "source": "YARA scan results",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IsPE32",
      "why": "Confirms 
… [5295 more chars]
```

- **agentic:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`461017` mtime=`2026-08-03T08:53:56.822721+00:00`
  - sha256: `d2aca9fc611319bd11bb9057be59a5776e172261888f013c5602d8b4a1ed69a2`

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

- **rule_yar:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar` exists=`True` bytes=`1937` mtime=`2026-08-03T08:54:03.093021+00:00`
  - sha256: `07501c4f9df7e5419664da3ef4a7baba14d230be7f7e40425b565be5beafd98f`

#### excerpt

```
// yara_gen_v2.py — 2026-08-03T08:54:03.094419+00:00
rule CADRE_v2_unknown_353ab6827b75 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" ascii wide
        $s1 = "aTEnumerator<System.Generics.Collections.TPair<System.TClass,System.Classes.TFieldsCache.TFields>>(" ascii wide
        $s2 = "aTEnumerable<System.Generics.Collections.TPair<System.TClass,System.Classes.TFieldsCache.TFields>>'" ascii wide
        $s3 = "]TEnumerator<System.Generics.Coll
… [1135 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v2.md` exists=`True` bytes=`22070` mtime=`2026-08-03T09:06:27.771946+00:00`
  - sha256: `d729962624bf2911b504ec5597d8631b0e44d3fb9d2c1a5540c79dfdb0f80d07`
- **REPORT_MASTER_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-MASTER-v3.md` exists=`True` bytes=`65181` mtime=`2026-08-03T09:12:19.797058+00:00`
  - sha256: `91926b24e48c5d2773305682e883abc2c37efa4b6cb337ddc35a3f932afb5076`
- **REPORT_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-v2.md` exists=`True` bytes=`22070` mtime=`2026-08-03T09:06:27.771046+00:00`
  - sha256: `d729962624bf2911b504ec5597d8631b0e44d3fb9d2c1a5540c79dfdb0f80d07`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`97472` mtime=`2026-08-03T09:08:35.065250+00:00`
  - sha256: `e59d4c66939e6ded91abc76915921ba7bcb17a5ffabd0aca13513e0d8b0d96c5`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`82885` mtime=`2026-08-03T09:14:05.528162+00:00`
  - sha256: `37af8935dfd9ba5cd653741e313d4ee323b4fa57dd25aee1c954ec64d8cd6abd`
- **report_v2_json:** `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/report-v2.json` exists=`True` bytes=`45957` mtime=`2026-08-03T09:08:35.070650+00:00`
  - sha256: `50040dc72860d650ba11b4b362022fb6afe1d1c0084ca220741a69d526a9b6be`

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

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Delphi-Based Obfuscated Loader Disguised as GML_EDIT_PRO Inno Setup Installer

## Executive Summary
This sample i
… [21162 more chars]
```


#### v3_excerpt

```
# RE Report — 353ab6827b75
_Generated 2026-08-03T09:12:19.790459+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=316c | cross_refs=True | llm_ok=True | runtime=22.12s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Final Verdict | Malicious (source: scorecard) |
| Malware Family | Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO) (source: scorecard) |
| Confidence | High (cross-tool llm_and_v1_agree, malicious score 290, 16 YARA rule matches, 44 capa rule hits) (source: scorecard, yara, capa) |
| Sample Type | 32-bit x86 Delphi-compiled Portable Executable (PE) (source: cross-section:1. Sample Identification, cross-section:4. Static Analysis) |

This sample is a heavily obfuscated Delphi-bas
… [64262 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
