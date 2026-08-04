# Pipeline AUDIT-REPORT — `2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-04T06:04:08.977092+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`

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
- key_evidence_count=`6`

```json
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan and ransomware capabilities",
  "cross_engine_notes": "IDA was unavailable for analysis due to a tooling failure (missing idasql binary), so all static analysis is derived from Ghidra, Malcat, capa, YARA, pe_imports, and FLOSS. Ghidra reports 1641 functions and 1525 strings, while Malcat reports 100 strings and 17 high-severity anomalies; combining both tools maximizes coverage of code and string indicators. Malcat's static profile provides unique structural metrics (entropy, section flags, anomaly count) not present in Ghidra's output. Capa, pe_imports, and YARA results are consistent across engines, corroborating the malicious capability assessment.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "deep profile anomalies & file_summary",
      "row_or_rule": "Entropy=109, CrossSectionJump, SpaghettiFunction\u00d714, XorInLoop\u00d77, HighXrefLoopingFunction\u00d75, SectionWX, DelayImports\u00d721, InvalidChecksum",
      "why": "Extremely high entropy indicates packed/encrypted payload; cross-section jumps, spaghetti code, XOR loops, and high cross-reference looping functions are strong indicators of code obfuscation common in malware; WX (write-execute) section and delay imports are frequently used by malware to hide functionality and evade detection; invalid checksum further indicates the file is not a legitimate, unmodified PE."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "anti_dbg, network_dropper, escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation",
      "why": "YARA rule matches confirm the sample contains anti-debugging, network dropper, privilege escalation, screenshot capture, keylogging, registry manipulation, token manipulation, and file operation capabilities, all consistent with malicious remote access or ransomware behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports high-signal signals",
      "row_or_rule": "IsDebuggerPresent (T1622), URLDownloadToFileW (T1105), RegSetValueExW (T1112), CreateProcessW/ShellExecute (T1106), LoadLibrary/GetProcAddress (T1129)",
      "why": "These high-signal imports directly map to core malware capabilities: anti-debugging, payload download, registry modification for persistence/configuration, process execution for running malicious code, and dynamic DLL loading to hide functionality."
    },
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "T1082 (System Information Discovery), T1083 (File and Directory Discovery), T1012 (Query Registry), T1112 (Modify Registry), T1105 (Ingress Tool Transfer), T1106 (Process Execution), T1529 (System Shutdown/Reboot)",
      "why": "Capa capability mapping confirms the sample performs discovery, registry manipulation, payload download, process execution, and system shutdown, which align with both RAT (discovery, execution) and ransomware (system shutdown, file discovery for encryption) behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "deep profile file_summary metadata",
      "row_or_rule": "VersionInfo claims to be Adobe Bootstrapper Setup.exe, but has 17 anomalies including ExecutableSectionNoCode and ExtraSpaceAfterResour
… [3270 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`0`
- key_evidence_count=`12`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 0,
  "summary": "The analyzed sample is a malicious PE32 Windows GUI executable explicitly associated with multiple known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos) per its filename. YARA scanning matched 23 rules confirming the sample contains network indicators (domains, IPs, URLs), base64 encoded content, and implements a range of malicious behaviors including anti-debugging, SEH exception handling, Windows hooking, network dropper functionality, privilege escalation, screenshot capture, and keylogging capabilities consistent with remote access trojan (RAT) and ransomware functionality.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "all match entries share path /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "why": "Sample filename explicitly references known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos), indicating pre-existing classification as malicious"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: IsPE32",
      "why": "Confirms the sample is a valid PE32 executable, the standard format for Windows malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: IsWindowsGUI",
      "why": "Confirms the sample is a Windows GUI application, consistent with RAT and ransomware user-facing functionality"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: domain",
      "why": "Indicates the sample contains hardcoded domain indicators for command and control (C2) communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: IP",
      "why": "Indicates the sample contains hardcoded IPv4 and IPv6 addresses for C2 communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: url",
      "why": "Indicates the sample contains hardcoded URLs for C2 communication or payload delivery"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: anti_dbg",
      "why": "Confirms the sample includes anti-debugging functionality to evade security analysis"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: network_dropper",
      "why": "Confirms the sample has functionality to download and execute additional malicious payloads from remote sources"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: keylogger",
      "why": "Confirms the sample includes keylogging functionality to steal user credentials and sensitive input"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: screenshot",
      "why": "Confirms the sample includes functionality to capture user desktop screenshots for surveillance and data theft"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: escalate_priv",
   
… [1626 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Multi-Functional Loader/Dropper (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c)",
  "markdown": "# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan and ransomware capabilities\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis report details the analysis of a high-confidence malicious PE32 x86 Windows GUI executable (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c) masquerading as a legitimate Adobe Bootstrapper installer. The sample received a triage score of 9/10, with a verdict of malicious, classified as a multi-functional loader/dropper combining remote access trojan (RAT) and ransomware capabilities, with indicators matching the BK Ransomware, Elex, Hawkeye, Maze, and Remcos malware families.\nStatic analysis reveals extensive obfuscation: entropy of 109 (indicating packed/encrypted content), 17 MalCat anomalies including 14 spaghetti functions, 7 XOR-in-loop patterns, 5 high cross-reference looping functions, 21 delay imports, and a writable-executable (WX) section. The sample implements core malicious capabilities including anti-debugging, payload download, registry modification for persistence, process execution, privilege escalation, file system discovery, screenshot capture, keylogging, and system shutdown. No dynamic behavioral analysis (sandbox, Speakeasy, Frida) was performed during this analysis, so observed behavior is limited to static indicators. The sample masquerades as Adobe software using stolen version metadata and Adobe-related registry paths to evade user detection.\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c |\n| Sample Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos |\n| Project Name | pool |\n| File Type | PE32 x86 Windows GUI executable |\n| Claimed Product | Adobe Bootstrapper Setup.exe (stolen version metadata) |\n| Compilation Metadata | MSVC 2013 (per YARA rich header match: VC8_Microsoft_Corporation) |\n| Filename Indicators | Explicitly references BK Ransomware, Elex, Hawkeye, Maze, and Remcos families in sample path |\nThe sample filename explicitly references five known malware families, providing an initial strong indicator of malicious intent (source: deep-dive.json). The claimed Adobe Bootstrapper metadata is inconsistent with 17 structural PE anomalies, confirming the sample is not a legitimate Adobe binary (source: malcat).\n\n## 2. Classification\n| Attribute | Value |\n|
… [31027 more chars]
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

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan and ransomware capabilities
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of a high-confidence malicious PE32 x86 Windows GUI executable (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c) masquerading as a legitimate Adobe Bootstrapper installer. The sample received a triage score of 9/10, with a verdict of malicious, classified as a multi-functional loader/dropper combining remote access trojan (RAT) and ransomware capabilities, with indicators matching the BK Ransomware, Elex, Hawkeye, Maze, and Remcos malware families.
Static analysis reveals extensive obfuscation: entropy of 109 (indicating packed/encrypted content), 17 MalCat anomalies including 14 spaghetti functions, 7 XOR-in-loop patterns, 5 high cross-reference looping functions, 21 delay imports, and a writable-executable (WX) section. The sample implements core malicious capabilities including anti-debugging, payload download, registry modification for persistence, process execution, privilege escalation, file system discovery, screenshot capture, keylogging, and system shutdown. No dynamic behavioral analysis (sandbox, Speakeasy, Frida) was performed during this analysis, so observed behavior is limited to static indicators. The sample masquerades as Adobe software using stolen version metadata and Adobe-related registry paths to evade user detection.

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c |
| Sample Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164
… [29530 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 2f2c6d9466e8
_Generated 2026-08-04T06:02:49.339345+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=406c | cross_refs=True | llm_ok=True | runtime=31.26s -->

## Executive Summary

| Core Metric | Value |
|-------------|-------|
| Final Verdict | Malicious (source: scorecard) |
| Malware Family | Multi-functional loader/dropper with overlapping indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan (RAT) and ransomware capabilities (source: cross-section:9. Comparison with Known Families) |
| Cross-Engine Agreement | llm_and_v1_agree (source: scorecard) |
| Static Maliciousness Score | 290, supported by 23 YARA rule matches and 30 capa behavioral rule matches (source: scorecard, yara, capa) |
| Deep Analysis Confidence Offset | 0 (source: deep_dive_agentic) |

The analyzed sample (SHA256: `2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`) is a 32-bit x86 Windows PE file confirmed malicious via cross-validated static and behavioral analysis (source: cross-section:1. Sample Identification, cross-section:2. Classification). It demonstrates 15 distinct functional capabilities spanning collection, credential access, defense evasion, exfiltration, and impact categories, consistent with combined RAT and ransomware operational profiles (source: cross-section:7. Capability Assessment). Overlapping static code signatures, behavioral routines, and network artifacts match indicators for five established malware families, indicating the sample is either a modular payload deployed across multiple threat actor campaigns or a blended malware variant designed to consolidate the functionality of these distinct families (source: cross-section:9. Comparison with Known Families, cross-section:10. Attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=300c | cross_refs=True | llm_ok=True | runtime=22.41s -->

# 1. Sample Identification

The analyzed malicious sample is uniquely identified by its SHA256 cryptographic hash, with core static metadata extracted via MalCat static analysis (source: malcat, query: file summary, why: provides standardized file identification attributes for the sample).

| Attribute | Value | Source |
|-----------|-------|--------|
| Primary Hash (SHA256) | `2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af
… [57951 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6770` | `4231fbcfbb135d58` |
| `prompt.txt` | `True` | `25408` | `64d1ae6f77508e23` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `32035` | `9c7948af362fcd03` |
| `REPORT-MASTER-v3.md` | `True` | `60465` | `5ca865837403be1f` |
| `REPORT-v2.md` | `True` | `32035` | `9c7948af362fcd03` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `65460` | `25240154d222cb6e` |
| `rule.yar` | `True` | `1955` | `c0736b4035451ec2` |
| `intake-validation.json` | `True` | `2821` | `5b00e0735de4d384` |
| `source-decisions.json` | `True` | `1942` | `dd6cf6fe9552a6d9` |
| `malcat-triage.json` | `True` | `347916` | `4422293a584070da` |
| `deep_dive/01-tools-raw.json` | `True` | `497619` | `619fbaffcfded1ee` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `5126` | `12c24e667154383b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `486294` | `342b8e036e302a37` |

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

- **intake_validation:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-validation.json` exists=`True` bytes=`2821` mtime=`2026-08-04T05:51:02.412054+00:00`
  - sha256: `5b00e0735de4d384ad0e32a2a7a9b34f867ee617a7dfbb86d54ce7e626a6a479`
- **malcat_triage:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/malcat-triage.json` exists=`True` bytes=`347916` mtime=`2026-08-04T05:49:04.395957+00:00`
  - sha256: `4422293a584070da9942f76194ce46691c88c2681f050570578129cca8a0ecca`
- **source_decisions:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/source-decisions.json` exists=`True` bytes=`1942` mtime=`2026-08-04T05:51:02.412054+00:00`
  - sha256: `dd6cf6fe9552a6d955afd4c446eb1dfe5d4ac98f0af692378d137ae88977c6a9`
- **ghidra_import_log:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-analyzeHeadless.log` exists=`True` bytes=`10191` mtime=`2026-08-04T05:49:50.436356+00:00`
  - sha256: `7c8c6b62d2008d1e5c8871ca16c644f5e6a2b2cb794cbe91486ed4888f896f37`
- **ida_bootstrap_log:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 imports (IDA tool summary is empty, IDA validation failed per warning: [Errno 2] No such file or directory: '/usr/local/bin/idasql'); Ghidra reports 339 imports (ghidra tool summary, imports field)."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA has 0 functions (IDA tool summary is empty, IDA validation failed per warning); Ghidra reports 1641 functions (ghidra tool summary, funcs field), far exceeding Malcat's 10 functions (malcat tool summary, functions_count field)."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Both tools report val
… [1165 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
    "file_name": "2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "file_path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "file_size": 485376,
    "type": "PE",
    "architecture": "X86",
    "entropy": 
… [347116 more chars]
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
  "rule_count": 30,
  "top_rules": [
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
      "name": "get file version info",
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
      "name": "check OS version",
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
      "name": "query or enumerate registry value",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Query Registry"
          ],
          "tactic": "Discovery",
          "technique": "Query Registry",
          "subtechnique": "",
          "id": "T1012"
        }
      ],
      "mbc": 
… [3883 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 459893,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 252878,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 245300,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a3",
          "offset": 400684,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 396920,
          "length": 96,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 460864,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a0",
          "offset": 2
… [9769 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2846,
  "strings_sampled": 80,
  "strings": [
    "?GetPu",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "ttHt=Hu095",
    "QWWWWWWPW",
    "jEjCjB@j8",
    "XSVWjD_W3",
    "QSSSSSSPS",
    "QPWWhL",
    "t8PPPPh",
    "9G t!j",
    "t'9~ u\"",
    "t\t9p(u",
    "u8hd)D",
    "u\t9wlt>",
    "~(9~8t\tWW",
    "u h<)D",
    "At;F u",
    "t49^ u'",
    "~ 9^$u",
    "t>9~ t9j0",
    "t7j(SV",
    ";7u<;G",
    "uij0[SQ",
    "t)9w u$",
    "PjShp.D",
    "jShp.D",
    "+t=Ht-Ht",
    "HtpHHt",
    "Pj^h`1D",
    "j^h`1D",
    "SSWPSSSS",
    "j.Zf9P,u",
    "u\tf9p0u",
    "WQh,8D",
    "W9qXtDV",
    "9wXt8V",
    "VW9AXtw",
    "t-h@8D",
    "F(@;F,v",
    "^[9O s",
    "G(9G,t",
    "O$+G,j",
    "G,+G(;",
    "O(;O0u SPSQ",
    "_(^_[]",
    "9w uL9u",
    "t;VWHhhyE",
    "u3hhyE",
    "t.hl>D",
    "t0hL>D",
    "u+h4<D",
    "t9h(>D",
    "tn9~8uCj",
    "C9~8uDj",
    "^49~<u",
    "F4_^[]",
    "Zj9Yf9",
    "Yj9Yj1",
    "j1Zj9f;",
    "u2h$?D",
    "PSSh(GD",
    "u\"9^,t",
    "^,9^(t",
    "O<9NHt",
    "G09N4t",
    "Ht*Ht#HHt",
    "Ht/Ht'HHt",
    "QQSVWd",
    "9E v_PW",
    "9u(vAVS",
    "SVWjA_jZ+",
    "uBjAYjZ+",
    "uHjAXf;",
    "uaPPPS",
    "YY_^[]",
    "Y;=<>E",
    "~pjCXf",
    "j@j _W"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2845
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 57.14,
  "size_bytes": 485376,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
    "file_name": "2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "file_path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "file_size": 485376,
    "type": "PE",
    "architecture": "X86",
    "entropy": 109,
    "sha256": "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
    "metadata": {
      "VersionInfo::CompanyName": "Adobe Systems Incorporated",
      "VersionInfo::FileDescription": "Adobe Bootstrapper for Single Installation",
      "VersionInfo::FileVersion": "20.6.20034.366983",
      "VersionInfo::InternalName": "Setup.exe",
      "VersionInfo::LegalCopyright": "Copyright \u00a9 2020 Adobe Systems Incorporated.  All rights reserved.",
      "VersionInfo::OriginalFilename": "Setup.exe",
      "VersionInfo::ProductName": "Bootstrapper Small",
      "VersionInfo::ProductVersion": "20.6.20034.366983",
      "Debug::Date.Debug.Codeview": "2020-02-04 19:04:20",
      "Debug::Path": "D:\\DCB\\CBT_Main\\Acrobat\\Installers\\BootStrapExe_Small\\Release\\Setup.pdb",
      "Debug::Date.Debug.VcFeature": "2020-02-04 19:04:20"
    },
    "entrypoint_ea": 135201,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 52
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 242688,
        "virtual_size": 245760,
        "rights": "RX",
        "entropy": 139
      },
      {
        "name": ".rdata",
        "effective_address": 246784,
        "physical_size": 86528,
        "virtual_size": 90112,
        "rights": "R",
        "entropy": 76
      },
      {
        "name": ".data",
        "effective_address": 336896,
        "physical_size": 10752,
        "virtual_size": 28672,
        "rights": "RW",
        "entropy": 71
      },
      {
        "name": ".rsrc",
        "effective_address": 365568,
        "physical_size": 144384,
        "virtual_size": 147456,
        "rights": "RWX",
        "entropy": 77
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "BigStringHiScore",
        "desc": "string has more than 256 characters and high interest score",
        "category": "strings",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "CrossSectionJump",
        "desc": "Control flow jumps across section, could be a packed file, a patched file or a file infector",
        "category": "code",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "DelayImports",
        "desc": "There are delay imports",
        "category": "imports",
        "level": 3,
        "num_hits": 21
      },
      {
        "name": "DownloaderApiUsage",
        "desc": "Downloader-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 1
      },
     
… [417483 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "Entropy=109, CrossSectionJump, SpaghettiFunction\u00d714, XorInLoop\u00d77, HighXrefLoopingFunction\u00d75, SectionWX, DelayImports\u00d721,",
    "anti_dbg, network_dropper, escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation yara match",
    "IsDebuggerPresent (T1622), URLDownloadToFileW (T1105), RegSetValueExW (T1112), CreateProcessW/ShellExecute (T1106), Load",
    "T1082 (System Information Discovery), T1083 (File and Directory Discovery), T1012 (Query Registry), T1112 (Modify Regist",
    "VersionInfo claims to be Adobe Bootstrapper Setup.exe, but has 17 anomalies including ExecutableSectionNoCode and ExtraS"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan and ransomware capabilities",
  "score": 9,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "deep profile anomalies & file_summary",
      "row_or_rule": "Entropy=109, CrossSectionJump, SpaghettiFunction\u00d714, XorInLoop\u00d77, HighXrefLoopingFunction\u00d75, SectionWX, DelayImports\u00d721, InvalidChecksum",
      "why": "Extremely high entropy indicates packed/encrypted payload; cross-section jumps, spaghetti code, XOR loops, and high cross-reference looping functions are strong indicators of code obfuscation common in malware; WX (write-execute) section and delay imports are frequently used by malware to hide functionality and evade detection; invalid checksum further indicates the file is not a legitimate, unmodified PE."
    },
    {
      "source": "yara",
      "query_or_table": "yara matches",
      "row_or_rule": "anti_dbg, network_dropper, escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation",
      "why": "YARA rule matches confirm the sample contains anti-debugging, network dropper, privilege escalation, screenshot capture, keylogging, registry manipulation, token manipulation, and file operation capabilities, all consistent with malicious remote access or ransomware behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports high-signal signals",
      "row_or_rule": "IsDebuggerPresent (T1622), URLDownloadToFileW (T1105), RegSetValueExW (T1112), CreateProcessW/ShellExecute (T1106), LoadLibrary/GetProcAddress (T1129)",
      "why": "These high-signal imports directly map to core malware capabilities: anti-debugging, payload download, registry modification for persistence/configuration, process execution for running malicious code, and dynamic DLL loading to hide functionality."
    },
    {
      "source": "capa",
      "query_or_table": "capa top_rules",
      "row_or_rule": "T1082 (System Information Discovery), T1083 (File and Directory Discovery), T1012 (Query Registry), T1112 (Modify Registry), T1105 (Ingress Tool Transfer), T1106 (Process Execution), T1529 (System Shutdown/Reboot)",
      "why": "Capa capability mapping confirms the sample performs discovery, registry manipulation, payload download, process execution, and system shutdown, which align with both RAT (discovery, execution) and ransomware (system shutdown, file discovery for encryption) behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "deep profile file_summary metadata",
      "row_or_rule": "VersionInfo claims to be Adobe Bootstrapper Setup.exe, but has 17 anomalies including ExecutableSectionNoCode and ExtraSpaceAfterResourcesDataDirectory",
      "why": "The sample masquerades as a legitimate Adobe installer using stolen version metadata, while structural PE anomalies confirm it is not a genuine Adobe binary."
    },
    {
      "source": "ghidra",
      "query_or_table": "suspicious strings",
      "row_or_rule": "Strings containing 'http://', 'kernel32.dll', 'SOFTWARE\\Adobe\\Setup\\Reader'",
      "why": "HTTP-prefixed strings indicate potential C2 communication or payload download endpoints; registry paths masquerading as Adobe-related paths suggest persistence or configuration storage; DLL import strings confirm reliance on standard Windows APIs for malicious operations."
    }
  ],
  "summary": "This is a high-confidence malicious PE32 x86 sample masquerading as a legitimate Adobe Bootstrapper installer. It exhibits strong indicators of obfuscation (high entropy, spaghetti code, XOR loops, delay imports) and implements core malware capabilities including anti-debugging, payload download, registry modification, process execution, privilege escalation, file system discovery, screenshot capt"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/prompt.txt` exists=`True` bytes=`25408` mtime=`2026-08-04T05:52:06.408353+00:00`
  - sha256: `64d1ae6f77508e2327968a9d94140d15677be4f076fa22edf29e7aaa05095158`
- **verdict:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/verdict.json` exists=`True` bytes=`6770` mtime=`2026-08-04T05:52:38.278252+00:00`
  - sha256: `4231fbcfbb135d58ab0a57bdce4d31c52f7d2e1ed3ca3e07c51eaa34aba8ee94`

#### prompt_excerpt

```
# Triage evidence
sha256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
sample_path: /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos
ghidra_session: ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
ida_session: ida-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA has 0 imports (IDA tool summary is empty, IDA validation failed per warning: [Errno 2] No such file or directory: '/usr/local/bin/idasql'); Ghidra reports 339 imports (ghidra tool summary, imports field).
- functions: ghidra (confidence=medium) — IDA has 0 functions (IDA tool summary is empty, IDA validation failed per warning); Ghidra reports 1641 functions (ghidra tool summary, funcs field), far exceeding Malcat's 10 functions (malcat tool summary, functi
… [24373 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan and ransomware capabilities",
  "cross_engine_notes": "IDA was unavailable for analysis due to a tooling failure (missing idasql binary), so all static analysis is derived from Ghidra, Malcat, capa, YARA, pe_imports, and FLOSS. Ghidra reports 1641 functions and 1525 strings, while Malcat reports 100 strings and 17 high-severity anomalies; combining both tools maximizes coverage of code and string indicators. Malcat's static profile provides unique structural metrics (entropy, section flags, anomaly count) not present in Ghidra's output. Capa, pe_imports, and YARA results are consistent across engines, corroborating the malicious capability assessment.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "deep profile anomalies & file_summary",
      "
… [5770 more chars]
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
  "rule_count": 30,
  "top_rules": [
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
      "name": "get file version info",
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
      "name": "check OS version",
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
      "name": "query or enumerate registry value",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Query Registry"
          ],
          "tactic": "Discovery",
          "technique": "Query Registry",
          "subtechnique": "",
          "id": "T1012"
        }
      ],
      "mbc": 
… [3882 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 485376,
  "duration_s": 0.03,
  "import_count": 318,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
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
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 459893,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 252878,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 245300,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a3",
          "offset": 400684,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 396920,
          "length": 96,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a",
          "offset": 460864,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$a0",
          "offset": 2
… [9747 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2846,
  "strings_sampled": 80,
  "strings": [
    "?GetPu",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "ttHt=Hu095",
    "QWWWWWWPW",
    "jEjCjB@j8",
    "XSVWjD_W3",
    "QSSSSSSPS",
    "QPWWhL",
    "t8PPPPh",
    "9G t!j",
    "t'9~ u\"",
    "t\t9p(u",
    "u8hd)D",
    "u\t9wlt>",
    "~(9~8t\tWW",
    "u h<)D",
    "At;F u",
    "t49^ u'",
    "~ 9^$u",
    "t>9~ t9j0",
    "t7j(SV",
    ";7u<;G",
    "uij0[SQ",
    "t)9w u$",
    "PjShp.D",
    "jShp.D",
    "+t=Ht-Ht",
    "HtpHHt",
    "Pj^h`1D",
    "j^h`1D",
    "SSWPSSSS",
    "j.Zf9P,u",
    "u\tf9p0u",
    "WQh,8D",
    "W9qXtDV",
    "9wXt8V",
    "VW9AXtw",
    "t-h@8D",
    "F(@;F,v",
    "^[9O s",
    "G(9G,t",
    "O$+G,j",
    "G,+G(;",
    "O(;O0u SPSQ",
    "_(^_[]",
    "9w uL9u",
    "t;VWHhhyE",
    "u3hhyE",
    "t.hl>D",
    "t0hL>D",
    "u+h4<D",
    "t9h(>D",
    "tn9~8uCj",
    "C9~8uDj",
    "^49~<u",
    "F4_^[]",
    "Zj9Yf9",
    "Yj9Yj1",
    "j1Zj9f;",
    "u2h$?D",
    "PSSh(GD",
    "u\"9^,t",
    "^,9^(t",
    "O<9NHt",
    "G09N4t",
    "Ht*Ht#HHt",
    "Ht/Ht'HHt",
    "QQSVWd",
    "9E v_PW",
    "9u(vAVS",
    "SVWjA_jZ+",
    "uBjAYjZ+",
    "uHjAXf;",
    "uaPPPS",
    "YY_^[]",
    "Y;=<>E",
    "~pjCXf",
    "j@j _W"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2845
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 56.36,
  "size_bytes": 485376,
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
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "disassembly": {
    "0x00421c21": "\u250c 300: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_24h @ ebp-0x24\n\u2502       \u254e   0x00421c21      e81a580500     call 0x477440\n\u2502       \u2514\u2500< 0x00421c26      e97ffeffff     jmp 0x421aaa\n..",
    "0x004391d2": "; CALL XREF from entry0 @ 0x421ba2(x)\n\u250c 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);\n\u2502           ; arg char **argv @ ebp+0x8\n\u2502           ; arg char **envp @ ebp+0xc\n\u2502           ; arg int32_t envp @ ebp+0x10\n\u2502           ; arg int32_t arg_14h @ ebp+0x14\n\u2502           0x004391d2      55             push ebp\n\u2502           0x004391d3      8bec           mov ebp, esp\n\u2502           0x004391d5      5d             pop ebp\n\u2502       \u250c\u2500< 0x004391d6      e900000000     jmp 0x4391db\n\u2502       \u2502   ; JUMP XREF from main @ 0x4391d6(x)\n\u2502       \u2514\u2500> 0x004391db      55             push ebp\n\u2502           0x004391dc      8bec           mov ebp, esp\n\u2502           0x004391de      53             push ebx\n\u2502           0x004391df      56             push esi\n\u2502           0x004391e0      57             push edi\n\u2502           0x004391e1      83cfff         or edi, 0xffffffff          ; -1\n\u2502           0x004391e4      e803a8fdff     call fcn.004139ec\n\u2502           0x004391e9      8bf0           mov esi, eax\n\u2502           0x004391eb      e87302feff     call fcn.00419463\n\u2502           0x004391f0      ff7514         push dword [arg_14h]\n\u2502           0x004391f3      ff7510         push dword [envp]\n\u2502           0x004391f6      8b5804         mov ebx, dword [eax + 4]\n\u2502           0x004391f9      ff750c         push dword [envp]\n\u2502           0x004391fc      ff7508         push dword [argv]\n\u2502           0x004391ff      e86845feff     call fcn.0041d76c\n\u2502           0x00439204      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x00439206      743b           je 0x439243\n\u2502       \u2502   0x00439208      85db           test ebx, ebx\n\u2502      \u250c\u2500\u2500< 0x0043920a      740e           je 0x43921a\n\u2502      \u2502\u2502   0x0043920c      8b03           mov eax, dword [ebx]\n\u2502      \u2502\u2502   0x0043920e      8bcb           mov ecx, ebx\n\u2502      \u2502\u2502   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172\n\u2502      \u2502\u2502   0x00439216      85c0           test eax, eax\n\u2502     \u250c\u2500\u2500\u2500< 0x00439218      7429           je 0x439243\n\u2502     \u2502\u2514\u2500\u2500> 0x0043921a      8b06           mov eax, dword [esi]\n\u2502     \u2502 \u2502   0x0043921c      8bce           mov ecx, esi\n\u2502     \u2502 \u2502   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80\n\u2502     \u2502 \u2502   0x00439221      85c0           test eax, eax\n\u2502     \u2502\u250c\u2500\u2500< 0x00439223      7515           jne 0x43923a\n\u2502     \u2502\u2502\u2502   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]\n\u2502     \u2502\u2502\u2502   0x00439228      85c9           test ecx, ecx\n\u2502    \u250c\u2500\u2500\u250
… [4481 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "candidates": [
    "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
    "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!VerQueryValueW",
      "VERSION.dll!GetFileVersionInfoW",
      "VERSION.dll!GetFileVersionInfoSizeW",
      "KERNEL32.dll!LocalReAlloc",
      "KERNEL32.dll!GlobalFlags",
      "KERNEL32.dll!CompareStringW",
      "KERNEL32.dll!GetLocaleInfoW",
      "KERNEL32.dll!GetSystemDefaultUILanguage",
      "USER32.dll!InvalidateRect",
      "USER32.dll!DestroyMenu",
      "USER32.dll!RealChildWindowFromPoint",
      "USER32.dll!ClientToScreen",
      "USER32.dll!EndPaint",
      "GDI32.dll!TextOutW",
      "GDI32.dll!ExtTextOutW",
      "GDI32.dll!SetViewportExtEx",
      "GDI32.dll!SetViewportOrgEx",
      "GDI32.dll!SetWindowExtEx",
      "WINSPOOL.DRV!OpenPrinterW",
      "WINSPOOL.DRV!ClosePrinter",
      "WINSPOOL.DRV!DocumentPropertiesW",
      "ADVAPI32.dll!RegEnumValueW",
      "ADVAPI32.dll!RegQueryValueW",
      "ADVAPI32.dll!RegEnumKeyW",
      "ADVAPI32.dll!RegDeleteValueW",
      "ADVAPI32.dll!RegDeleteKeyW",
      "SHELL32.dll!ShellExecuteW",
      "SHELL32.dll!SHGetSpecialFolderPathW",
      "SHLWAPI.dll!PathFileExistsW",
      "SHLWAPI.dll!PathIsUNCW"
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
  "checked": 12,
  "hits": 12,
  "misses": [],
  "hit_examples": [
    "all match entries share path /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2",
    "rule: IsPE32 matches Confirms the sample is a valid PE32 executable, the standard format for Windows malware checklist_y",
    "rule: IsWindowsGUI matches Confirms the sample is a Windows GUI application, consistent with RAT and ransomware user-fac",
    "rule: domain matches Indicates the sample contains hardcoded domain indicators for command and control (C2) communicatio",
    "rule: IP matches Indicates the sample contains hardcoded IPv4 and IPv6 addresses for C2 communication checklist_yara_sca"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 0,
  "summary": "The analyzed sample is a malicious PE32 Windows GUI executable explicitly associated with multiple known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos) per its filename. YARA scanning matched 23 rules confirming the sample contains network indicators (domains, IPs, URLs), base64 encod",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "all match entries share path /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "why": "Sample filename explicitly references known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos), indicating pre-existing classification as malicious"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: IsPE32",
      "why": "Confirms the sample is a valid PE32 executable, the standard format for Windows malware"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: IsWindowsGUI",
      "why": "Confirms the sample is a Windows GUI application, consistent with RAT and ransomware user-facing functionality"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: domain",
      "why": "Indicates the sample contains hardcoded domain indicators for command and control (C2) communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: IP",
      "why": "Indicates the sample contains hardcoded IPv4 and IPv6 addresses for C2 communication"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: url",
      "why": "Indicates the sample contains hardcoded URLs for C2 communication or payload delivery"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: anti_dbg",
      "why": "Confirms the sample includes anti-debugging functionality to evade security analysis"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: network_dropper",
      "why": "Confirms the sample has functionality to download and execute additional malicious payloads from remote sources"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: keylogger",
      "why": "Confirms the sample includes keylogging functionality to steal user credentials and sensitive input"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: screenshot",
      "why": "Confirms the sample includes functionality to capture user desktop screenshots for surveillance and data theft"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: escalate_priv",
      "why": "Confirms the sample includes functionality to gain elevated system privileges for persistent, unrestricted system access"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "matches",
      "row_or_rule": "rule: win_hook",
      "why": "Confirms the sample uses Windows hooking to intercept user input and system events, consistent with RAT surveillance functionality"
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
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }

… [12847 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
  
… [420561 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 30,
  "top_rules": [
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
     
… [6982 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 485376,
  "duration_s": 0.03,
  "import_count": 318,
  "signal_count": 7,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
      ]
    },
    {
     
… [671 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2846,
  "strings_sampled": 80,
  "strings": [
    "?GetPu",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "ttHt=Hu095",
    "QWWWWWWPW",
    "jEjCjB@j8",
    "XSVWjD_W3",
    "QSSSSSSPS",
    "QPWWhL",
    "t8PPPPh",
    "9G t!j",
    "t'9~ u\"",
    "t\t9p(u",
    "u8hd)D",
    "u\t9wlt>",
    "~(9~8t\tWW",
    "u h<)D",
 
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
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "disassembly": {
    "0x00421c21": "\u250c 300: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   
… [7581 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Lasz
… [61 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
  "candidates": [
    "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000110 ........!..L.!
… [84 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
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
    "path": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!VerQueryValueW",
      "VERSION.dll!GetFileVersionInfoW",
      "VERSION.d
… [1014 more chars]
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
      "name": "FUN_004242a4",
      "address": "4342436",
      "size": "5878"
    },
    {
      "name": "FUN_0042e8ea",
      "address": "4385002",
      "size": "5165"
    },
    {
      "name": "FUN_0042b3b0",
      "address": "4371376",
      "size": "3099"
    },
    {
      "name": "FUN_0042a733",
      "address":
… [2275 more chars]
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
      "address": "298"
    },
    {
      "name": "CloseServiceHandle",
      "module": "ADVAPI32.DLL",
      "address": "288"
    },
    {
      "name": "InitiateSystemShutdownW",
      "module": "ADVAPI32.DLL",
      "address": "289"
    },
    {

… [4866 more chars]
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
      "name": "CloseServiceHandle",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "InitiateSystemShutdownW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "LookupPrivilegeValueW",
      "module": "ADVAPI32.DLL"
    },
    {
    
… [3654 more chars]
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
      "name": "CloseHandle",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CompareStringW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CopyFileW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateEventW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateFileW",
      "modul
… [3798 more chars]
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
      "name": "CloseHandle",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CompareStringW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CopyFileW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateEventW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateFileW",
      "modul
… [3798 more chars]
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
      "name": "CloseHandle",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CompareStringW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CopyFileW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateEventW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateFileW",
      "modul
… [11109 more chars]
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
      "name": "FlushFileBuffers",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetDriveTypeW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetFileAttributesW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetFileSize",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetFileSizeEx"
… [2134 more chars]
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
      "name": "SHGetSpecialFolderPathW",
      "module": "SHELL32.DLL"
    },
    {
      "name": "ShellExecuteW",
      "module": "SHELL32.DLL"
    },
    {
      "name": "AdjustWindowRectEx",
      "module": "USER32.DLL"
    },
    {
      "name": "BeginPaint",
      "module": "USER32.DLL"
    },
    {
      "name": "CallNextHookEx
… [3625 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/01-tools-raw.json` exists=`True` bytes=`497619` mtime=`2026-08-04T05:53:42.507651+00:00`
  - sha256: `619fbaffcfded1eefaa595d6353424dd53291973a4014baa87d429eccef88884`
- **sql_evidence:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/05-deep-dive.json` exists=`True` bytes=`5126` mtime=`2026-08-04T05:55:04.747849+00:00`
  - sha256: `12c24e667154383b9d7267fb4bff456f879fb561cd22364a0db5e051d142c0df`

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
  "summary": "The analyzed sample is a malicious PE32 Windows GUI executable explicitly associated with multiple known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos) per its filename. YARA scanning matched 23 rules confirming the sample contains network indicators (domains, IPs, URLs), base64 encoded content, and implements a range of malicious behaviors including anti-debugging, SEH exception handling, Windows hooking, network dropper functionality, privilege escalation, screenshot capture, and keylogging capabilities consistent with remote access trojan (RAT) and ransomware functionality.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or
… [4326 more chars]
```

- **agentic:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`1237707` mtime=`2026-08-04T05:55:04.747849+00:00`
  - sha256: `ba5d3984274dc7aa929b4a1db8b0b40708a2ed75cc1db4d6353caaf837a42c89`

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

- **rule_yar:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar` exists=`True` bytes=`1955` mtime=`2026-08-04T05:55:06.026749+00:00`
  - sha256: `c0736b4035451ec227c8c19488478f25a5e6daacb94fc24848a5b31e2bde5e60`

#### excerpt

```
// yara_gen_v2.py — 2026-08-04T05:55:06.028127+00:00
rule CADRE_v2_unknown_2f2c6d9466e8 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate." ascii wide
        $s1 = "This program is linked to the missing export %s in the file %s. This machine may have an incompatible version of %s." ascii wide
        $s2 = "Another installation is in progress. You must complete that installation before continuing this one." ascii wide
        $
… [1153 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-MASTER-v2.md` exists=`True` bytes=`32035` mtime=`2026-08-04T05:57:02.535346+00:00`
  - sha256: `9c7948af362fcd03ffa947def6557f8729d07458c011a7ed7406380dbad432ec`
- **REPORT_MASTER_v3:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-MASTER-v3.md` exists=`True` bytes=`60465` mtime=`2026-08-04T06:02:49.346738+00:00`
  - sha256: `5ca865837403be1fddffb125bfde565260abd38580ba5dc6f948314d57cf2f91`
- **REPORT_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-v2.md` exists=`True` bytes=`32035` mtime=`2026-08-04T05:57:02.535346+00:00`
  - sha256: `9c7948af362fcd03ffa947def6557f8729d07458c011a7ed7406380dbad432ec`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`77653` mtime=`2026-08-04T05:59:02.787043+00:00`
  - sha256: `ff18ef5d5a46d9974f86ec00fcd8e563d177f452eebe88d35151ed600c842f69`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`65460` mtime=`2026-08-04T06:04:08.928336+00:00`
  - sha256: `25240154d222cb6efdc1ed1eb9387e63db2372b2c1e270ee90ff364bb51aa847`
- **report_v2_json:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/report-v2.json` exists=`True` bytes=`34527` mtime=`2026-08-04T05:59:02.792443+00:00`
  - sha256: `c687f26a34baf6271b17fb3616ffd47cf48ccc5e87c087683b7d1ce9c59db046`

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

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan and ransomware capabilities
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive
… [31130 more chars]
```


#### v3_excerpt

```
# RE Report — 2f2c6d9466e8
_Generated 2026-08-04T06:02:49.339345+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=406c | cross_refs=True | llm_ok=True | runtime=31.26s -->

## Executive Summary

| Core Metric | Value |
|-------------|-------|
| Final Verdict | Malicious (source: scorecard) |
| Malware Family | Multi-functional loader/dropper with overlapping indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan (RAT) and ransomware capabilities (source: cross-section:9. Comparison with Known Families) |
| Cross-Engine Agreement | llm_and_v1_agree (source: scorecard) |
| Static Maliciousness Score | 290, supported by 23 YARA rule matches and 30 capa behavioral rule matches (source: scorecard, yara, capa)
… [59551 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
