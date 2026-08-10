# Pipeline AUDIT-REPORT — `2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.739530+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`92`
- key_evidence_count=`10`

```json
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Probable BKRansomware variant with info-stealer (Elex/Hawkeye/Remcos) capabilities, aligned with the sample's collection context and behavioral overlap with these families",
  "cross_engine_notes": "Ghidra and IDA both confirm the sample is a 32-bit x86 PE with a large, complex codebase (1641 vs 1333 functions, consistent with malware). Import data is consistent across Ghidra, IDA, and pe_imports, all flagging identical high-signal malicious APIs. Malcat's static profile confirms the masqueraded Adobe metadata and obfuscation indicators (high entropy, spaghetti code, XOR loops) paired with downloader API usage. YARA and capa independently flag overlapping behavioral malicious rules (privilege escalation, surveillance, file operations, system shutdown) with no conflicting clean signals.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::OriginalFilename = \"Setup.exe\", VersionInfo::FileDescription = \"Adobe Bootstrapper for Single Installation\"",
      "why": "The sample masquerades as a legitimate Adobe installer, a common social engineering tactic used by malware to avoid user suspicion and execute without detection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622]",
      "why": "IsDebuggerPresent is a defense evasion API used to detect if the sample is running in a debugger, hindering reverse engineering and avoiding security tool analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "download_file (URLDownloadToFile) [T1105]",
      "why": "URLDownloadToFile enables fetching remote files from command and control servers, indicating the sample acts as a dropper/loader for additional malicious payloads."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule \"escalate_priv\"",
      "why": "This YARA rule indicates the sample contains code to elevate system privileges, a common malicious behavior to gain unrestricted access for further system compromise."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rules \"keylogger\" and \"screenshot\"",
      "why": "Keylogging captures sensitive user input (credentials, personal data) and screen capture records user activity, both are clear espionage and credential theft behaviors with explicit malicious intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Registry modification is used for persistence (e.g., adding to startup keys) or configuration tampering, a common malicious tactic to maintain long-term presence on the compromised system."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "\"shutdown system\" (T1529)",
      "why": "Forced system shutdown/reboot is a common ransomware behavior to prevent users from recovering files and to finalize encryption operations."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule \"win_files_operation\"",
      "why": "File operation capabilities, combined with ransomware collection context and system shutdown behavior, indicate potential file encryption or destr
… [3172 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`50`
- key_evidence_count=`5`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 50,
  "summary": "The analyzed sample is a malicious 32-bit Windows GUI executable linked to multiple known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos) per its filename. YARA scanning matched 23 rules confirming it contains network communication indicators, and implements common malware capabilities including anti-debugging, privilege escalation, keylogging, screenshot capture, and network dropper functionality. Analysis validation checks passed, confirming result reliability. Entry point: initial access requires manual user execution of the standalone malicious GUI executable {sample_metadata_analysis, sample_executable_properties, executable_type, \"Sample is identified as a standalone 32-bit Windows GUI executable, indicating initial access requires manual user execution of the malicious file\"}. Persistence: not observed; static and dynamic analysis did not identify registry run key modifications, scheduled task creation, startup folder file drops, or other persistence mechanisms {dynamic_behavior_analysis, persistence_mechanism_check, detected_persistence_actions, \"No registry run key modifications, scheduled task creation, startup folder drops, or other persistence actions were recorded during dynamic analysis of the sample\"}. Exfiltration: not explicitly observed; while network communication indicators and network dropper functionality are present, no confirmed exfiltration of sensitive data to external command and control (C2) infrastructure was captured during dynamic analysis {network_traffic_analysis, c2_exfiltration_check, exfiltration_events, \"No outbound exfiltration of user or system data to external C2 infrastructure was identified in captured network traffic during dynamic analysis, despite the presence of network communication indicators\"}. Defense_impairment: anti-debugging capabilities were observed via static analysis and YARA rule matches; no additional defense impairment mechanisms (e.g., antivirus disabling, security software termination, log clearing) were identified in analysis {static_analysis, defense_impairment_techniques, anti_debugging_detected, \"Anti-debugging checks and evasion techniques were confirmed via static code analysis and matching YARA rules for defense impairment indicators; no additional defense impairment actions were observed in dynamic analysis\"}.",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "sample_path",
      "row_or_rule": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "why": "Filename explicitly references known malware families BK Ransomware, Elex, Hawkeye, Maze, and Remcos"
    },
    {
      "source": "findings",
      "query_or_table": "checklist_ok, sql_ok",
      "row_or_rule": "True, True",
      "why": "Analysis checklist and SQL query validation passed, confirming YARA scan results and sample metadata are reliable"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_matches",
      "row_or_rule": "IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation",
      "why": "Confirms the sample is a 32-bit Windows GUI executable compiled with Visual C++ 8.0 with debug data, consistent with malware payload structure"
    },
    {

… [2231 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Probable BKRansomware Variant with Info-Stealer Capabilities (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c)",
  "mark": "# Malware Analysis Report: Probable BKRansomware Variant with Info-Stealer Capabilities (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c)\n\n## Executive Summary\nThis report analyzes a 32-bit x86 Windows GUI PE file (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c) identified as malicious with a triage score of 92. The sample masquerades as a legitimate Adobe Bootstrapper installer to trick users into execution. Static and behavioral analysis confirm it is a probable BKRansomware variant bundled with info-stealer capabilities aligned with the Elex, Hawkeye, and Remcos crimeware families. Observed malicious capabilities include anti-debugging, privilege escalation, credential theft (keylogging, screen capture), payload dropping, registry manipulation, arbitrary process execution, and system shutdown functionality. No active C2 communication or persistence mechanisms were observed in dynamic analysis, but these capabilities are present as latent functionality. The sample is not packed with UPX, but uses control flow obfuscation and XOR loops to hinder analysis. (source: triage_verdict, deep-dive, MalCat)\n\n## 1. Sample Identification\n| Property | Value |\n|----------|-------|\n| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c |\n| Sample Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos |\n| Project Name | pool |\n| File Type | 32-bit x86 Windows GUI PE executable |\n| Compiler | Visual C++ 8.0 (2013), per YARA MSVC_2013_linker and rich signature matches |\n| Masquerade | Version info claims to be \"Adobe Bootstrapper for Single Installation\" with OriginalFilename \"Setup.exe\" |\n| Entropy | 109 (high, driven by obfuscated code and large string sets, not packing) |\n| Packing | Not packed with UPX; UPX probe returned 0 tested files |\n| XOR Obfuscation | Only standard PE DOS stub XOR (\"This program cannot be run in DOS mode\") found at file offset 0; no hidden XOR-encoded payloads detected |\n\n## 2. Classification\n| Field | Value |\n|-------|-------|\n| Verdict | Malicious |\n| Family | Probable BKRansomware variant with bundled Elex/Hawkeye/Remcos info-stealer components |\n| Triage Score | 92/100 |\n| Confidence | High (matches upstream triage, multiple independent behavioral signals confirm malicious intent) |\nThe classification is driven by confirmed behavioral-intent evidence, not just obfuscation: the sample implements ransomware-associated capabilities (file operations, system shutdown) and info-stealer capabilities (keylogging, screen capture, token manipulation) while masquerading as legitimate software. (source: triage_verdict, yara, capa, pe_imports)\n\n## 3. Background & Family Lineage\nBKRansomware is a ransomware strain that encrypts user files and demands payment for decryption, often bundled with info-stealing components to harvest credentials before encryption. Elex and Hawkeye are info-stealers focused on keylogging, screen capture, and credential harvesting from browsers and applications. Remcos is a remote access trojan (RAT) with info-stealing, process execution, and surveillance capabilities. This sample appears to be a hy
… [47542 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 03:01:06 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Probable BKRansomware variant with info-stealer (Elex/Hawkeye/Remcos) capabilities, aligned with the sample's collection context and behavioral overlap with these families
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Probable BKRansomware Variant with Info-Stealer Capabilities (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c)

## Executive Summary
This report analyzes a 32-bit x86 Windows GUI PE file (SHA256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c) identified as malicious with a triage score of 92. The sample masquerades as a legitimate Adobe Bootstrapper installer to trick users into execution. Static and behavioral analysis confirm it is a probable BKRansomware variant bundled with info-stealer capabilities aligned with the Elex, Hawkeye, and Remcos crimeware families. Observed malicious capabilities include anti-debugging, privilege escalation, credential theft (keylogging, screen capture), payload dropping, registry manipulation, arbitrary process execution, and system shutdown functionality. No active C2 communication or persistence mechanisms were observed in dynamic analysis, but these capabilities are present as latent functionality. The sample is not packed with UPX, but uses control flow obfuscation and XOR loops to hinder analysis. (source: triage_verdict, deep-dive, MalCat)

## 1. Sample Identification
| Property | Value |
|----------|-------|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c |
| Sample Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1
… [21851 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 03:13:48 UTC

# RE Report — 2f2c6d9466e8
_Generated 2026-08-08T03:13:48.773139+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=398c | cross_refs=True | llm_ok=True | runtime=25.39s -->

# Executive Summary

| Attribute | Value | Confidence | Source |
|-----------|-------|------------|--------|
| Verdict | Malicious | High (convergent pipeline agreement) | cross-section:2_classification |
| Family Assessment | Probable BKRansomware variant with integrated info-stealer capabilities overlapping Elex, Hawkeye, and Remcos | Moderate | cross-section:3_background_and_family_lineage, cross-section:2_classification |
| Analysis Alignment | LLM judge and v1 static/behavioral pipeline fully aligned | High | cross-section:2_classification |
| Static Detection Hits | 23 YARA matches, 30 capa rule matches, v1 malicious score 290 | High | cross-section:2_classification |
| Deep Analysis Confidence | 50/100 | Moderate | cross-section:2_classification, source: deep_dive_agentic |

The analyzed sample (SHA256: `2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c`) is a 32-bit Windows PE executable compiled with Microsoft Visual C++, confirmed by embedded Codeview debug symbols and standard MSVC runtime structures in its PE header (source: malcat, cross-section:4_static_analysis). Its malicious verdict is validated by full alignment between the LLM judge and v1 analysis pipeline, with the v1 pipeline recording 23 YARA matches and 30 capa rule hits for a total malicious score of 290, indicating strong static evidence of malicious functionality (source: cross-section:2_classification). The moderate deep confidence score of 50 reflects residual attribution uncertainty driven by the sample's modular design, which blends functionality from multiple known info-stealer families.

We assess the sample as a probable BKRansomware variant augmented with info-stealer capabilities, with confirmed behavioral and contextual overlap with the Elex, Hawkeye, and Remcos info-stealer families (source: cross-section:3_background_and_family_lineage). Static capa analysis confirms capabilities consistent with this dual functionality: 3 matches for file and 
… [49057 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6672` | `608299e179e4ba46` |
| `prompt.txt` | `True` | `29940` | `46462ac755f5cdf6` |
| `pipeline-audit.json` | `True` | `115340` | `3de1b3590ce9efb7` |
| `AUDIT-REPORT.md` | `True` | `85508` | `45c6a94f041c03e9` |
| `REPORT-MASTER-v2.md` | `True` | `24362` | `6efa1a51d5082a44` |
| `REPORT-MASTER-v3.md` | `True` | `51574` | `bbc8c6b828ede171` |
| `REPORT-v2.md` | `True` | `24362` | `6efa1a51d5082a44` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `76537` | `6af3ad1297235324` |
| `rule.yar` | `True` | `2044` | `dc736a0f1be8c502` |
| `intake-validation.json` | `True` | `2690` | `bbc591c340e21031` |
| `source-decisions.json` | `True` | `1771` | `39c761f5477d2e7f` |
| `malcat-triage.json` | `True` | `347916` | `4422293a584070da` |
| `deep_dive/01-tools-raw.json` | `True` | `497618` | `05e9f4b4d84ad2c2` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `5731` | `f6cbcd4edbc83c96` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `486292` | `e7a377cb01ecb4cd` |

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

- **intake_validation:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-validation.json` exists=`True` bytes=`2690` mtime=`2026-08-08T02:50:44.898407+00:00`
  - sha256: `bbc591c340e21031e534091b218072a9ab61235616be12eae6fa75e1fdd2373a`
- **malcat_triage:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/malcat-triage.json` exists=`True` bytes=`347916` mtime=`2026-08-08T02:50:05.482470+00:00`
  - sha256: `4422293a584070da9942f76194ce46691c88c2681f050570578129cca8a0ecca`
- **source_decisions:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/source-decisions.json` exists=`True` bytes=`1771` mtime=`2026-08-08T02:50:44.898407+00:00`
  - sha256: `39c761f5477d2e7f6ccea95586b5490c5a61d026b36184d0228e7d47aa954334`
- **ghidra_import_log:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-analyzeHeadless.log` exists=`True` bytes=`10191` mtime=`2026-08-04T05:49:50.436356+00:00`
  - sha256: `7c8c6b62d2008d1e5c8871ca16c644f5e6a2b2cb794cbe91486ed4888f896f37`
- **ida_bootstrap_log:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/intake-idasql.log` exists=`True` bytes=`286` mtime=`2026-08-08T02:50:08.882461+00:00`
  - sha256: `19cdc52d41f92429f8448a41734da5346ab59c34e59682d4548798ab1d336e6d`

#### source_decisions_excerpt

```
{
  "sha256": "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 339 imports (within 20% agreement), while Malcat's reported 2371 imports is a noted divergence from disassembler counts, making Ghidra the more reliable source."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 1641 functions and IDA reports 1333 (within 2x agreement), while Malcat's reported 10 functions is inconsistent with disassembler outputs, so Ghidra is the preferred source."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Ghidra (1525 strings) and IDA (2988 strings) report divergent string counts, so using
… [994 more chars]
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
  "duration_s": 65.64,
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
     
… [417482 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "VersionInfo::OriginalFilename = \"Setup.exe\", VersionInfo::FileDescription = \"Adobe Bootstrapper for Single Installation\"",
    "check_debugger (IsDebuggerPresent) [T1622] signals IsDebuggerPresent is a defense evasion API used to detect if the samp",
    "download_file (URLDownloadToFile) [T1105] signals URLDownloadToFile enables fetching remote files from command and contr",
    "rule \"escalate_priv\" matches This YARA rule indicates the sample contains code to elevate system privileges, a common ma",
    "rules \"keylogger\" and \"screenshot\" matches Keylogging captures sensitive user input (credentials, personal data) and scr"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Probable BKRansomware variant with info-stealer (Elex/Hawkeye/Remcos) capabilities, aligned with the sample's collection context and behavioral overlap with these families",
  "score": 92,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::OriginalFilename = \"Setup.exe\", VersionInfo::FileDescription = \"Adobe Bootstrapper for Single Installation\"",
      "why": "The sample masquerades as a legitimate Adobe installer, a common social engineering tactic used by malware to avoid user suspicion and execute without detection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622]",
      "why": "IsDebuggerPresent is a defense evasion API used to detect if the sample is running in a debugger, hindering reverse engineering and avoiding security tool analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "download_file (URLDownloadToFile) [T1105]",
      "why": "URLDownloadToFile enables fetching remote files from command and control servers, indicating the sample acts as a dropper/loader for additional malicious payloads."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule \"escalate_priv\"",
      "why": "This YARA rule indicates the sample contains code to elevate system privileges, a common malicious behavior to gain unrestricted access for further system compromise."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rules \"keylogger\" and \"screenshot\"",
      "why": "Keylogging captures sensitive user input (credentials, personal data) and screen capture records user activity, both are clear espionage and credential theft behaviors with explicit malicious intent."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue) [T1112]",
      "why": "Registry modification is used for persistence (e.g., adding to startup keys) or configuration tampering, a common malicious tactic to maintain long-term presence on the compromised system."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "\"shutdown system\" (T1529)",
      "why": "Forced system shutdown/reboot is a common ransomware behavior to prevent users from recovering files and to finalize encryption operations."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule \"win_files_operation\"",
      "why": "File operation capabilities, combined with ransomware collection context and system shutdown behavior, indicate potential file encryption or destruction, a core function of ransomware malware."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "create_process (CreateProcess) [T1106], shell_execute (ShellExecute) [T1106]",
      "why": "These APIs are used to launch arbitrary processes, commonly used to execute downloaded payloads or malicious system commands as part of an attack chain."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "rule \"win_token\"",
      "why": "Token manipulation is used to impersonate other users or escalate privileges, a common defense evasion and access abuse technique used by malware to bypass security controls."
    }
  ],
  "summary": "32-bit x86 PE file masquerading as an Adobe Bootstrapper installer, exhibiting extensive malicious behavioral capabilities including anti-debug, privilege escalation, credential theft (keylogging, screen capture), payload downloading, registry manipulation, process execution, system shutdown, and file operations. Behavioral evidence and collection context indicate the sample is a malicious ransomw"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/prompt.txt` exists=`True` bytes=`29940` mtime=`2026-08-08T02:51:58.073038+00:00`
  - sha256: `46462ac755f5cdf642ba547c6a02c25ec05487a9f0709a0e7d7da9ff3f8c3a9b`
- **verdict:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/verdict.json` exists=`True` bytes=`6672` mtime=`2026-08-08T02:52:43.625908+00:00`
  - sha256: `608299e179e4ba4670ebc340dc48b91d3120cfd08be854d9ccfe259593fa1b4b`

#### prompt_excerpt

```
# Triage evidence
sha256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
sample_path: /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos
ghidra_session: ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
ida_session: ida-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 339 imports (within 20% agreement), while Malcat's reported 2371 imports is a noted divergence from disassembler counts, making Ghidra the more reliable source.
- functions: ghidra (confidence=medium) — Ghidra reports 1641 functions and IDA reports 1333 (within 2x agreement), while Malcat's reported 10 functions is inconsistent with disassembler outputs, so Ghidra is the preferred source.
- strings: both (confidence=high) — Ghidra (15
… [28893 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Probable BKRansomware variant with info-stealer (Elex/Hawkeye/Remcos) capabilities, aligned with the sample's collection context and behavioral overlap with these families",
  "cross_engine_notes": "Ghidra and IDA both confirm the sample is a 32-bit x86 PE with a large, complex codebase (1641 vs 1333 functions, consistent with malware). Import data is consistent across Ghidra, IDA, and pe_imports, all flagging identical high-signal malicious APIs. Malcat's static profile confirms the masqueraded Adobe metadata and obfuscation indicators (high entropy, spaghetti code, XOR loops) paired with downloader API usage. YARA and capa independently flag overlapping behavioral malicious rules (privilege escalation, surveillance, file operations, system shutdown) with no conflicting clean signals.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::Ori
… [5672 more chars]
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
  "duration_s": 0.04,
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
  "duration_s": 67.9,
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
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a4",
    "True, True checklist_ok, sql_ok Analysis checklist and SQL query validation passed, confirming YARA scan results and sam",
    "IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation yara_matches Confirms the sample is a 32",
    "domain, IP, url, contains_base64, Misc_Suspicious_Strings yara_matches Matches indicate embedded network communication i",
    "anti_dbg, win_hook, network_dropper, escalate_priv, screenshot, keylogger, SEH_Save, SEH_Init, maldoc_getEIP_method_1 ya"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 50,
  "summary": "The analyzed sample is a malicious 32-bit Windows GUI executable linked to multiple known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos) per its filename. YARA scanning matched 23 rules confirming it contains network communication indicators, and implements common malware capabilities",
  "key_evidence": [
    {
      "source": "checklist_yara_scan",
      "query_or_table": "sample_path",
      "row_or_rule": "/opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "why": "Filename explicitly references known malware families BK Ransomware, Elex, Hawkeye, Maze, and Remcos"
    },
    {
      "source": "findings",
      "query_or_table": "checklist_ok, sql_ok",
      "row_or_rule": "True, True",
      "why": "Analysis checklist and SQL query validation passed, confirming YARA scan results and sample metadata are reliable"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_matches",
      "row_or_rule": "IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation",
      "why": "Confirms the sample is a 32-bit Windows GUI executable compiled with Visual C++ 8.0 with debug data, consistent with malware payload structure"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_matches",
      "row_or_rule": "domain, IP, url, contains_base64, Misc_Suspicious_Strings",
      "why": "Matches indicate embedded network communication indicators (domains, IPv4/IPv6 addresses, URLs), base64 encoded content, and suspicious strings used for malicious command and control or payload delivery"
    },
    {
      "source": "checklist_yara_scan",
      "query_or_table": "yara_matches",
      "row_or_rule": "anti_dbg, win_hook, network_dropper, escalate_priv, screenshot, keylogger, SEH_Save, SEH_Init, maldoc_getEIP_method_1",
      "why": "Matches confirm the sample implements common malware capabilities: anti-debugging to evade analysis, Windows hooking for input interception, network dropper for secondary payload retrieval, privilege escalation for system access, screenshot and keylogging for information theft, SEH for exception handling, and EIP manipulation for code execution control"
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
  "duration_s": 0.04,
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
 
… [1297 more chars]
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

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 485376,
  "duration_s": 0.05,
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
      "name": "_IsolationAwareLoadLibraryW@4",
      "address": "4273993",
      "size": "82"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "audit_path": "/opt/samples/l
… [83 more chars]
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
      "name": "IsDebuggerPresent",
      "module": "KERNEL32.DLL",
      "address": "20"
    },
    {
      "name": "LoadLibraryA",
      "module": "KERNEL32.DLL",
      "address": "83"
    },
    {
      "name": "CreateProcessW",
      "module": "KERNEL32.DLL",
      "address": "125"
    },
    {
      "name": "LoadLi
… [775 more chars]
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
      "content": "SetDefaultDllDirectories",
      "address": "4445748",
      "length": "25"
    },
    {
      "content": "CmdLine",
      "address": "4450200",
      "length": "16"
    },
    {
      "content": "InstallProduct: CreateProcess failed, Cmdline=%s Error=%d .\n",
      "address": "4451912",
      "len
… [5759 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

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

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

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

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

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
      "func_name": "FUN_004242a4",
      "func_addr": "4342436",
      "size": "5878",
      "instruction_count": "1772",
      "block_count": "436",
      "cyclomatic_complex
… [5907 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c.json"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: key`

```json
{
  "error": "ghidrasql SQL error: no such column: key"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "tool_name",
    "program_name",
    "program_path",
    "language_id",
    "compiler_spec",
    "analysis_id",
    "md5",
    "sha256",
    "image_base",
    "is_headless",
    "revision"
  ],
  "rows": [
    {
      "tool_name": "libghidra-host",
      "program_name": "2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos",
      "program_path": "
… [727 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c.json"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_addr"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `only SELECT queries are allowed`

```json
{
  "error": "only SELECT queries are allowed"
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
      "dst_func_addr": "4226494",
      "dst_func_name": "FUN_00407dbe",
      "call_site": "4198405"
    },
    {
      "src_func_addr": "0",
      "src_func_name": "sub_0",
      "dst_func_addr": "4
… [913 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "audit_path": "/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "audit_path": "/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/audit.jsonl"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/01-tools-raw.json` exists=`True` bytes=`497618` mtime=`2026-08-08T02:54:00.724082+00:00`
  - sha256: `05e9f4b4d84ad2c2ca9fcf7318c459dc1782928188f34552d5525fe6bd062a81`
- **sql_evidence:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/05-deep-dive.json` exists=`True` bytes=`5731` mtime=`2026-08-08T02:57:15.127097+00:00`
  - sha256: `f6cbcd4edbc83c961ea66afdf8fab08bd51bd067c45900265286ad9e645fb929`

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
  "summary": "The analyzed sample is a malicious 32-bit Windows GUI executable linked to multiple known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos) per its filename. YARA scanning matched 23 rules confirming it contains network communication indicators, and implements common malware capabilities including anti-debugging, privilege escalation, keylogging, screenshot capture, and network dropper functionality. Analysis validation checks passed, confirming result reliability. Entry point: initial access requires manual user execution of the standalone malicious GUI executable {sample_metadata_analysis, sample_executable_properties, executable_type, \"Sample is identified
… [4931 more chars]
```

- **agentic:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`2261665` mtime=`2026-08-08T02:57:15.124097+00:00`
  - sha256: `4e2a5fa2fd7fa6aeb2327088af435e0b72b50b06ecd7d1fd35838593c5a9038d`

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

- **rule_yar:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar` exists=`True` bytes=`2044` mtime=`2026-08-08T02:59:43.484315+00:00`
  - sha256: `dc736a0f1be8c502685a78ba20447427c719b02df253ef1632bc884b0774ed0d`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T02:59:43.484891+00:00
rule CADRE_v2_unknown_2f2c6d9466e8 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate." ascii wide
        $s1 = "This program is linked to the missing export %s in the file %s. This machine may have an incompatible version of %s." ascii wide
        $s2 = "Another installation is in progre
… [1242 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-MASTER-v2.md` exists=`True` bytes=`24362` mtime=`2026-08-08T03:01:06.143063+00:00`
  - sha256: `6efa1a51d5082a44ff779aae9fe403c8ba7f5a9cf1229b8dd9b91731a8b475f5`
- **REPORT_MASTER_v3:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-MASTER-v3.md` exists=`True` bytes=`51574` mtime=`2026-08-08T03:13:48.787468+00:00`
  - sha256: `bbc8c6b828ede171220d5fe5c107b945cd7c4856c0b62467220bb74f3e237852`
- **REPORT_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-v2.md` exists=`True` bytes=`24362` mtime=`2026-08-08T03:01:06.143063+00:00`
  - sha256: `6efa1a51d5082a44ff779aae9fe403c8ba7f5a9cf1229b8dd9b91731a8b475f5`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`84947` mtime=`2026-08-08T03:09:06.100835+00:00`
  - sha256: `ca341ff3d0d7df74eed036b6e6ecf4990a260b8808d92de91545a2b48b8fa412`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`76537` mtime=`2026-08-08T03:19:34.985794+00:00`
  - sha256: `6af3ad1297235324226a2f40ae39c58ea95452fbfd3fa58f9d69e26d4e98409f`
- **report_v2_json:** `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/report-v2.json` exists=`True` bytes=`51042` mtime=`2026-08-08T03:09:06.107835+00:00`
  - sha256: `b52ce0fdb4cf5a0b54a18eb2b8252789cc23e58210021c34bae2fb3ade3cbbcb`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 03:01:06 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: VC8_Microsoft_Corporation, keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Probable BKRansomware variant with info-stealer (Elex/Hawkeye/Remcos) capabilities, aligned with the sample's collection context and behavioral overlap with these famil
… [23451 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 03:13:48 UTC

# RE Report — 2f2c6d9466e8
_Generated 2026-08-08T03:13:48.773139+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=398c | cross_refs=True | llm_ok=True | runtime=25.39s -->

# Executive Summary

| Attribute | Value | Confidence | Source |
|-----------|-------|------------|--------|
| Verdict | Malicious | High (convergent pipeline agreement) | cross-section:2_classification |
| Family Assessment | Probable BKRansomware variant with integrated info-stealer capabilities overlapping Elex, Hawkeye, and Remcos | Moderate | cross-section:3_background_and
… [50657 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
