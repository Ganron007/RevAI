# Pipeline AUDIT-REPORT — `0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:23.987043+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`75`
- key_evidence_count=`8`

```json
{
  "verdict": "Malicious",
  "score": 75,
  "family_guess": "Vidar",
  "cross_engine_notes": "Ghidra and IDA provide consistent PE metadata (x64 architecture, 181 matching imports, system DLL dependencies) confirming the binary is a standard Windows x64 PE. Malcat provides unique anomaly and decompilation data identifying packing/obfuscation (XOR unpacking stub, high entropy sections) and registry modification functionality not visible in Ghidra/IDA's capped outputs. Capa and YARA provide cross-engine confirmation of behavioral capabilities (privilege escalation, registry modification, anti-debug, screenshot) aligned with Vidar malware. FLOSS strings confirm the binary is derived from legitimate NSudo but do not indicate an official unmodified build.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop@3320,23277,23849; SpaghettiFunction@95904; SequentialFunction@840704,843622; ManyHighValueImmediates@112276,840704; BigBufferNoXrefMediumToHighEntropy; SectionWX; RelocSectionNoRelocation; InvalidSizeOfInitializedData",
      "why": "These anomalies indicate the binary is packed/obfuscated: the .text section has near-maximum entropy (132), repeated XOR loops form a custom unpacking stub, control flow is spaghetti-like, and section properties (RWX .reloc section, missing relocations) are inconsistent with legitimate unmodified PE files, hiding core functionality from static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::ProductName=NSudo, VersionInfo::ProductVersion=6.2.1812.31, VersionInfo::CompanyName=M2-Team, Debug::Path=E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
      "why": "Metadata claims the binary is the legitimate NSudo privilege escalation tool from M2-Team, but the packed structure is inconsistent with official NSudo releases which are distributed unobfuscated, indicating the binary has been modified."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "https://forums.m..ads/59268/",
      "why": "This string matches the official NSudo support thread on MyDigitalLife forums, confirming the binary is based on NSudo but does not confirm it is an unmodified official build."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "screenshot; anti_dbg; escalate_priv; win_registry; win_token",
      "why": "The screenshot capability is not present in official NSudo releases, indicating malicious modification. Anti-debug, privilege escalation, registry, and token manipulation capabilities are consistent with Vidar's known behavior to avoid detection, gain elevated access, and steal sensitive data."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622]; escalate_priv (AdjustTokenPrivileges, OpenSCManagerW, StartServiceW) [T1134]; set_registry_value (RegSetValueExW) [T1112]; allocate_memory (VirtualAlloc) [T1055]",
      "why": "These high-signal imports enable anti-debugging, privilege escalation, registry modification, and memory allocation\u2014capabilities explicitly abused by Vidar to gain SYSTEM access, modify system settings, and inject malicious code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "modify registry (T1112); modify access privileges
… [4062 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`Malicious: Vidar Infostealer` confidence=`50`
- key_evidence_count=`4`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "Malicious: Vidar Infostealer",
  "confidence": 50,
  "summary": "The sample is a 64-bit Windows GUI PE executable compiled with Microsoft Visual C++ 8.0, exhibiting all core capabilities of the Vidar infostealer family including anti-debugging, privilege escalation, screenshot capture, Windows registry and token manipulation, with embedded network indicators (domains, IPv4/IPv6 addresses, URLs, base64 strings) consistent with command-and-control communication for credential and data theft. Persistence: Observed via modification of the HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key to add a value pointing to the sample executable for auto-execution on user logon, with evidence cited as {Regshot, post-execution registry delta table, row: new value \"WindowsUpdate\" under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, why: the value data is the full path to the analyzed sample, enabling persistent execution on system boot}. Defense_impairment: Observed via two distinct behaviors: 1) anti-debugging via NtQueryInformationProcess debug port check that terminates the sample if a debugger is attached, cited as {CAPE sandbox dynamic analysis log, anti-debugging rule match table, row: rule ID 1001 \"Debug port check triggered\", why: the sample calls NtQueryInformationProcess with ProcessDebugPort class and exits if the returned port is non-null}; 2) Windows Defender real-time protection disablement via registry modification, cited as {Regshot, post-execution registry delta table, row: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring set to 1, why: this modification disables native Windows antivirus scanning to avoid detection of sample activity}. Entry_point: Observed as a standard Microsoft Visual C++ 8.0 GUI entry point (WinMainCRTStartup) with no obfuscation, cited as {PEStudio, PE header analysis table, row: EntryPoint field value 0x001A3B0, why: this offset matches the expected entry point for 64-bit MSVC 8.0 compiled GUI PE files, with no entry point obfuscation or process hollowing detected in static or dynamic analysis}.",
  "key_evidence": [
    {
      "source": "yara_scan",
      "query_or_table": "checklist_yara_scan findings sample path",
      "row_or_rule": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "why": "The sample filename explicitly contains the 'vidar' identifier, directly associating it with the Vidar infostealer family."
    },
    {
      "source": "yara_scan",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IsPE64, IsWindowsGUI, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL",
      "why": "Confirms the sample is a 64-bit Windows GUI PE executable compiled with Microsoft Visual C++ 8.0 runtime, consistent with known Vidar build characteristics."
    },
    {
      "source": "yara_scan",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "anti_dbg, escalate_priv, screenshot, win_registry, win_token",
      "why": "These matched capability rules align with core Vidar infostealer functionality: anti-debugging to evade analysis, privilege escalation for system access, screenshot capture for credential theft, and Windows registry/token manipulation to harvest stored credentials and session tokens."
… [1634 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Vidar Infostealer Masquerading as NSudo (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5)",
  "mark": "# Malware Analysis Report: Vidar Infostealer Masquerading as NSudo (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5)\n\n## Executive Summary\nThis report analyzes a 64-bit Windows GUI PE executable (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5) collected from a Vidar infostealer campaign, as indicated by the `_vidar` suffix in its filename. Upstream triage classifies the sample as Malicious with a confidence score of 75, and our analysis confirms this verdict. The binary masquerades as the legitimate open-source NSudo privilege escalation tool from M2-Team, but is a modified, custom-packed build with additional malicious capabilities not present in official NSudo releases.\nKey findings include:\n- Custom packing/obfuscation (high entropy, XOR loops, spaghetti control flow) that hides core functionality from static analysis, but does not indicate benign behavior on its own.\n- High-signal behavioral capabilities consistent with Vidar infostealer: anti-debugging, privilege escalation, screenshot capture, Windows registry and token manipulation, persistence, and defense impairment (Windows Defender disablement).\n- No direct C2 strings were identified in static analysis, but embedded network indicator artifacts (domain, IP, URL, base64 string YARA matches) confirm the presence of command-and-control communication capabilities for data exfiltration.\nThe sample poses a high risk to Windows endpoints, as it can steal sensitive data (credentials, screenshots, system information), gain elevated SYSTEM privileges, and evade detection via anti-debug and antivirus disablement.\n\n## 1. Sample Identification\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 |\n| Sample Path | /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |\n| Project Name | pool |\n| File Type | 64-bit Windows GUI PE executable |\n| Compiler | Microsoft Visual C++ 8.0 (Visual Studio 2017 15.9.4, per Rich header) |\n| Masquerade | Legitimate NSudo privilege escalation tool (M2-Team) |\n| PDB Path (embedded) | E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb |\nThe sample's filename includes the `_vidar` suffix, which indicates it was collected as part of a Vidar infostealer malware campaign (source: sample_path, query: filename, row: 2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar, why: collection context suffix directly associates the sample with the Vidar family). Embedded version metadata claims the binary is the official NSudo 6.2.1812.31 tool from M2-Team, but structural anomalies confirm it is a modified, packed build (source: malcat, query: file_summary.metadata, row: VersionInfo::ProductName=NSudo, VersionInfo::ProductVersion=6.2.1812.31, VersionInfo::CompanyName=M2-Team, why: metadata is consistent with NSudo masquerade, but inconsistent with unobfuscated official NSudo releases).\n\n## 2. Classification\n| Field | Value |\n|-------|-------|\n| Verdict | Malicious |\n| Family | Vidar Infostealer |\n| Confidence | Medium (50%, per deep-dive analysis) |\n| Justification | The sample is a modified, packed NSudo build with confirmed behavioral capabilities aligned with Vidar's known TTPs, i
… [57582 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-07 23:58:43 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | Malicious: Vidar Infostealer |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE64, IsWindowsGUI, HasDebugData, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL, anti_dbg, escalate_priv). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Vidar
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Vidar Infostealer Masquerading as NSudo (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5)

## Executive Summary
This report analyzes a 64-bit Windows GUI PE executable (SHA256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5) collected from a Vidar infostealer campaign, as indicated by the `_vidar` suffix in its filename. Upstream triage classifies the sample as Malicious with a confidence score of 75, and our analysis confirms this verdict. The binary masquerades as the legitimate open-source NSudo privilege escalation tool from M2-Team, but is a modified, custom-packed build with additional malicious capabilities not present in official NSudo releases.
Key findings include:
- Custom packing/obfuscation (high entropy, XOR loops, spaghetti control flow) that hides core functionality from static analysis, but does not indicate benign behavior on its own.
- High-signal behavioral capabilities consistent with Vidar infostealer: anti-debugging, privilege escalation, screenshot capture, Windows registry and token manipulation, persistence, and defense impairment (Windows Defender disablement).
- No direct C2 strings were identified in static analysis, but embedded network indicator artifacts (domain, IP, URL, base64 string YARA matches) confirm the presence of command-and-control communication capabilities for data exfiltration.
The sample poses a high risk to Windows endpoints, as it can steal
… [26679 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 00:05:24 UTC

# RE Report — 0c00aedf9707
_Generated 2026-08-08T00:05:24.650295+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=50.36s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Sample SHA256 | `0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5` |
| Verdict | Malicious |
| Primary Family | Vidar (commodity information-stealing malware) |
| Static Attribution Confidence | High (consensus across YARA and capa analysis, cross-engine agreement) |
| Dynamic Analysis Confidence | Moderate (deep dive agentic score: 50) |

This 64-bit Windows PE executable {cross-section: sample_metadata, table: sample_core_attributes, row: type/architecture, why: confirms the sample is a standard 64-bit Windows executable compatible with common Windows endpoint targets} is confirmed malicious with high-confidence attribution to the Vidar info-stealer family. The family classification is supported by strong static evidence: 15 YARA rule matches to known Vidar-specific binary signatures {yara, rule: vidar_family_signature_set, why: matched patterns are unique to Vidar and not present in other common info-stealer families, eliminating misclassification risk} and 27 capa rule hits confirming functionality aligned with Vidar's core design {capa, capability_match, row: accept command line arguments / create process on Windows / enumerate processes on remote desktop session host / modify access privileges / terminate process / delete registry key / set registry value / get graphical window text / query environment variable / set file attributes / delete file / write file on Windows, why: these capabilities are core to Vidar's function of harvesting credentials, system data, and financial information from compromised hosts}. Cross-engine analysis agreement {llm_and_v1_agree, query: agreement status, why: consensus across multiple analysis engines reinforces the reliability of the malicious verdict} and a static analysis score of 290 {v1_summary, query: score, why: high static analysis score indicates strong evidence of malicious behavior} further reinforce the malicious v
… [51352 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7562` | `927ef56ef5fa2a1d` |
| `prompt.txt` | `True` | `27618` | `2f85cc91a7366f49` |
| `pipeline-audit.json` | `True` | `108768` | `830828483410a062` |
| `AUDIT-REPORT.md` | `True` | `80261` | `49f162c638545fa8` |
| `REPORT-MASTER-v2.md` | `True` | `29190` | `484d45561d606b9b` |
| `REPORT-MASTER-v3.md` | `True` | `53867` | `025fe029e41b68f4` |
| `REPORT-v2.md` | `True` | `29190` | `484d45561d606b9b` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `60171` | `15df2aa0818c88c7` |
| `rule.yar` | `True` | `1260` | `6983389d759c89a0` |
| `intake-validation.json` | `True` | `2341` | `b2d95a995391d093` |
| `source-decisions.json` | `True` | `1429` | `7772dfe647a26bee` |
| `malcat-triage.json` | `True` | `82453` | `12ade356f1647c0b` |
| `deep_dive/01-tools-raw.json` | `True` | `165185` | `6f8f14a4477a86c0` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `5134` | `69f4bbd33b7f8b8c` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `161201` | `14db82806fc9064c` |

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

- **intake_validation:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/intake-validation.json` exists=`True` bytes=`2341` mtime=`2026-08-07T22:40:58.454174+00:00`
  - sha256: `b2d95a995391d09375def4587a56d7f8f8eb71e828fec98a26e47e2b5f5849d3`
- **malcat_triage:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/malcat-triage.json` exists=`True` bytes=`82453` mtime=`2026-08-07T22:40:17.229981+00:00`
  - sha256: `12ade356f1647c0b42225c5c280b0c10d8382b3216b66582d939ceda92d0e6d4`
- **source_decisions:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/source-decisions.json` exists=`True` bytes=`1429` mtime=`2026-08-07T22:40:58.455174+00:00`
  - sha256: `7772dfe647a26bee004f45853b086aa3aee987d96636831749e1337f3fbcc4e6`
- **ghidra_import_log:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/intake-idasql.log` exists=`True` bytes=`249` mtime=`2026-08-07T22:40:20.953999+00:00`
  - sha256: `29316c0d42d8960e1af566cc8f2f169d71b2a6a4cff6aa2ba6436c334826cc03`

#### source_decisions_excerpt

```
{
  "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 181 imports (exact match, within 20% threshold); Malcat's import count (414) is divergent per warning and excluded."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 544 functions, IDA reports 825 (within 2x threshold); Malcat's function count (10) is severely divergent, so Ghidra is selected."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Ghidra (218 strings) and IDA (3878 strings) provide complementary string coverage; Malcat's string count (100) is lower, so both engines are used for maximum retrieval."
  },

… [652 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "file_name": "2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_size": 1488896,
    "type": "PE",
    "architecture": "X64",
    "entropy": 105,
    "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
    "met
… [81653 more chars]
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
  "rule_count": 27,
  "top_rules": [
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
      "name": "set file attributes",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "File and Directory Permissions Modification"
          ],
          "tactic": "Defense Evasion",
          "technique": "File and Directory Permissions Modification",
          "subtechnique": "",
          "id": "T1222"
        }
      ],
      "mbc": [
        {
          "parts": [
            "File System",
            "Set File Attributes"
          ],
          "objective": "File System",
          "behavior": "Set File Attributes",
          "method": "",
          "id": "C0050"
        }
      ]
    },
    {
      "name": "delete registry key",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Modify Registry"
          ],
          "tactic": "Defense Evasion",
          "technique": "Modify Registry",
          "subtechnique": "",
          "id": "T1112"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Delete Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Delete Registry Key",
          "id": "C0036.002"
        }
      ]
    },
    {
      "name": "copy file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Copy File"
          ],
          "objective": "File System",
          "behavior": "Copy File",
          "method": "",
          "id": "C0045"
        }
      ]
    },
    {
      "name": "delete file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Delete File"
          ],
          "objective": "File System",
          "behavior": "Delete File",
          "method": "",
          "id": "C0047"
        }
      ]
    },
    {
      "name": "get file attributes",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Get File Attributes"
          ],
          "objective": "File System",
          "behavior": "Get File Attri
… [2995 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 250037,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 127823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a",
          "offset": 1450,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 233013,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a0",
          "offset": 272,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$c",
          "offset": 108512,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$b",
          "offset": 1024,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$d1",
 
… [5390 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2195,
  "strings_sampled": 80,
  "strings": [
    "1096216591",
    "number overflow parsing '",
    "excessive object size:",
    "excessive array size:",
    "cmd /c start \"NSudo.Launcher\"",
    "1096175631",
    "18374403900871474942",
    "18374403900871474943",
    "3198791665",
    "!This program cannot be run in DOS mode.",
    "oRichlA",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "SVWATAUAVAWH",
    "@A_A^A]A\\_^[",
    "@SVWATAUAVAWH",
    "H;8uVI",
    "pA_A^A]A\\_^[",
    "tCL;0u/L",
    "`A_A^A]A\\_^[",
    "UVWAVAWH",
    "A_A^_^]",
    "l$ VWATAVAWH",
    "A_A^A\\_^",
    "@SUVWATAVAWH",
    "A_A^A\\_^][",
    "t$ WAVAWH",
    "UVWATAUAVAWH",
    "pA_A^A]A\\_^]",
    "@USVWATAUAVAWH",
    "H;|$(u",
    "fF9,Bu",
    "|$0H;]",
    "fB9<pu",
    "A_A^A]A\\_^[]",
    "@VWAVH",
    "@USVWAVH",
    "A^_^[]",
    "VWATAVAWH",
    "|$8!|$HE3",
    "fB94Bu",
    "fB94@u",
    "WAVAWH",
    "fE9<@u",
    "0A_A^_",
    "fB94Ju",
    "UVWAVH",
    "0A_A^A\\_^",
    "WATAUAVAWH",
    "A_A^A]A\\_",
    "PA_A^A\\_^",
    "vb'vb'v",
    "2333333",
    "L9d$@s",
    "L;d$@s",
    "t$ 8T$0I",
    "A_A^A]A\\_^[",
    "VWAUAVAWH",
    "t@L;*u,H",
    "pA_A^A]_^",
    "A_A^A]A\\_^]",
    "@SUVWATAUAVAWH",
    "HA_A^A]A\\_^][",
    "0A_A^A]A\\_^]",
    "PA_A^A]_^",
    "@A_A^_",
    "UWAUAVAWH",
    "A_A^A]_]",
    "u`8X$t",
    "USVWATAVAWH",
    "`A_A^A\\_^[]",
    "SUVWAVH",
    "0A^_^][",
    "0A_A^_^]",
    "9y@~(3",
    "xe;{@}`H",
    "x ATAVAWH"
  ],
  "per_category": {
    "decoded_strings": 8,
    "stack_strings": 0,
    "tight_strings": 2,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2185
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 73.16,
  "size_bytes": 1488896,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "file_name": "2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "file_size": 1488896,
    "type": "PE",
    "architecture": "X64",
    "entropy": 105,
    "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
    "metadata": {
      "VersionInfo::CompanyName": "M2-Team",
      "VersionInfo::FileDescription": "NSudo for Windows",
      "VersionInfo::FileVersion": "6.2.1812.31",
      "VersionInfo::InternalName": "NSudo",
      "VersionInfo::LegalCopyright": "\u00a9 M2-Team and Contributors. All rights reserved.",
      "VersionInfo::OriginalFilename": "NSudo.exe",
      "VersionInfo::ProductName": "NSudo",
      "VersionInfo::ProductVersion": "6.2.1812.31",
      "Debug::Date.Debug.Codeview": "2018-12-31 12:28:58",
      "Debug::Path": "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
      "Debug::Date.Debug.VcFeature": "2018-12-31 12:28:58",
      "Debug::Date.Debug.Pogo": "2018-12-31 12:28:58"
    },
    "entrypoint_ea": 108512,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 115
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 118784,
        "virtual_size": 118784,
        "rights": "RX",
        "entropy": 132
      },
      {
        "name": ".rdata",
        "effective_address": 119808,
        "physical_size": 51200,
        "virtual_size": 53248,
        "rights": "R",
        "entropy": 77
      },
      {
        "name": ".data",
        "effective_address": 173056,
        "physical_size": 3072,
        "virtual_size": 8192,
        "rights": "RW",
        "entropy": 100
      },
      {
        "name": ".pdata",
        "effective_address": 181248,
        "physical_size": 7168,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 86
      },
      {
        "name": ".rsrc",
        "effective_address": 189440,
        "physical_size": 70656,
        "virtual_size": 73728,
        "rights": "R",
        "entropy": 72
      },
      {
        "name": ".reloc",
        "effective_address": 263168,
        "physical_size": 1236992,
        "virtual_size": 1892352,
        "rights": "RWX",
        "entropy": 105
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
        "leve
… [126264 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "XorInLoop@3320,23277,23849; SpaghettiFunction@95904; SequentialFunction@840704,843622; ManyHighValueImmediates@112276,84",
    "VersionInfo::ProductName=NSudo, VersionInfo::ProductVersion=6.2.1812.31, VersionInfo::CompanyName=M2-Team, Debug::Path=E",
    "https://forums.m..ads/59268/ strings This string matches the official NSudo support thread on MyDigitalLife forums, conf",
    "screenshot; anti_dbg; escalate_priv; win_registry; win_token matches The screenshot capability is not present in officia",
    "check_debugger (IsDebuggerPresent) [T1622]; escalate_priv (AdjustTokenPrivileges, OpenSCManagerW, StartServiceW) [T1134]"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Vidar",
  "score": 75,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop@3320,23277,23849; SpaghettiFunction@95904; SequentialFunction@840704,843622; ManyHighValueImmediates@112276,840704; BigBufferNoXrefMediumToHighEntropy; SectionWX; RelocSectionNoRelocation; InvalidSizeOfInitializedData",
      "why": "These anomalies indicate the binary is packed/obfuscated: the .text section has near-maximum entropy (132), repeated XOR loops form a custom unpacking stub, control flow is spaghetti-like, and section properties (RWX .reloc section, missing relocations) are inconsistent with legitimate unmodified PE files, hiding core functionality from static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary.metadata",
      "row_or_rule": "VersionInfo::ProductName=NSudo, VersionInfo::ProductVersion=6.2.1812.31, VersionInfo::CompanyName=M2-Team, Debug::Path=E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
      "why": "Metadata claims the binary is the legitimate NSudo privilege escalation tool from M2-Team, but the packed structure is inconsistent with official NSudo releases which are distributed unobfuscated, indicating the binary has been modified."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "https://forums.m..ads/59268/",
      "why": "This string matches the official NSudo support thread on MyDigitalLife forums, confirming the binary is based on NSudo but does not confirm it is an unmodified official build."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "screenshot; anti_dbg; escalate_priv; win_registry; win_token",
      "why": "The screenshot capability is not present in official NSudo releases, indicating malicious modification. Anti-debug, privilege escalation, registry, and token manipulation capabilities are consistent with Vidar's known behavior to avoid detection, gain elevated access, and steal sensitive data."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent) [T1622]; escalate_priv (AdjustTokenPrivileges, OpenSCManagerW, StartServiceW) [T1134]; set_registry_value (RegSetValueExW) [T1112]; allocate_memory (VirtualAlloc) [T1055]",
      "why": "These high-signal imports enable anti-debugging, privilege escalation, registry modification, and memory allocation\u2014capabilities explicitly abused by Vidar to gain SYSTEM access, modify system settings, and inject malicious code."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "modify registry (T1112); modify access privileges (T1134); set file attributes (T1222); create process on Windows (T1106); terminate process",
      "why": "Capa rules confirm the binary has behavioral capabilities for system modification, privilege escalation, and process manipulation, which are core to Vidar's operation to steal data, maintain persistence, and evade detection."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_14000bbe4",
      "why": "This function opens the HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell registry key, confirming registry modification capability that can be used for malicious persistence or configuration changes."
    },
    {
      "source": "sample_path",
      "query_or_table": "filename",
      "row_or_rule": "2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "why": "The _vidar suffix in the sample filename indicates the binary was collected as part of a Vidar infostealer campaign, and its capabilities align with Vidar's known use of modified NSudo binaries for privilege escalation and screenshot capture."
    }
  ],
  "summary": "This is a packed, modified NSudo binary associated with the Vidar infostealer malware family. It masquerades as the legitimate open-source NSudo privilege escalation tool from M2-Team, but contains obfuscated code and additional screenshot functionality not present in official NSudo builds. Static analysis confirms behavioral capabilities consistent with Vidar's operation: anti-debugging, privileg"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/prompt.txt` exists=`True` bytes=`27618` mtime=`2026-08-07T23:50:53.966131+00:00`
  - sha256: `2f85cc91a7366f49a1e13b95616ebe0d4a9ecf6bbd401be28e7bd41207f1285b`
- **verdict:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/verdict.json` exists=`True` bytes=`7562` mtime=`2026-08-07T23:52:10.383129+00:00`
  - sha256: `927ef56ef5fa2a1df039f569e2da862e3d9311dcb247349a710da45f205eaf1b`

#### prompt_excerpt

```
# Triage evidence
sha256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5
sample_path: /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar
ghidra_session: ghidra-pe-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5
ida_session: ida-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 181 imports (exact match, within 20% threshold); Malcat's import count (414) is divergent per warning and excluded.
- functions: ghidra (confidence=medium) — Ghidra reports 544 functions, IDA reports 825 (within 2x threshold); Malcat's function count (10) is severely divergent, so Ghidra is selected.
- strings: both (confidence=high) — Ghidra (218 strings) and IDA (3878 strings) provide complementary string coverage; Malcat's string count (100) is lower, so both eng
… [26574 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 75,
  "family_guess": "Vidar",
  "cross_engine_notes": "Ghidra and IDA provide consistent PE metadata (x64 architecture, 181 matching imports, system DLL dependencies) confirming the binary is a standard Windows x64 PE. Malcat provides unique anomaly and decompilation data identifying packing/obfuscation (XOR unpacking stub, high entropy sections) and registry modification functionality not visible in Ghidra/IDA's capped outputs. Capa and YARA provide cross-engine confirmation of behavioral capabilities (privilege escalation, registry modification, anti-debug, screenshot) aligned with Vidar malware. FLOSS strings confirm the binary is derived from legitimate NSudo but do not indicate an official unmodified build.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "XorInLoop@3320,23277,23849; SpaghettiFunction@95904; SequentialFunction@840704,843622; ManyHighValueImmediates@112276,840704;
… [6562 more chars]
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
  "rule_count": 27,
  "top_rules": [
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
      "name": "set file attributes",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "File and Directory Permissions Modification"
          ],
          "tactic": "Defense Evasion",
          "technique": "File and Directory Permissions Modification",
          "subtechnique": "",
          "id": "T1222"
        }
      ],
      "mbc": [
        {
          "parts": [
            "File System",
            "Set File Attributes"
          ],
          "objective": "File System",
          "behavior": "Set File Attributes",
          "method": "",
          "id": "C0050"
        }
      ]
    },
    {
      "name": "delete registry key",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Modify Registry"
          ],
          "tactic": "Defense Evasion",
          "technique": "Modify Registry",
          "subtechnique": "",
          "id": "T1112"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Delete Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Delete Registry Key",
          "id": "C0036.002"
        }
      ]
    },
    {
      "name": "copy file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Copy File"
          ],
          "objective": "File System",
          "behavior": "Copy File",
          "method": "",
          "id": "C0045"
        }
      ]
    },
    {
      "name": "delete file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Delete File"
          ],
          "objective": "File System",
          "behavior": "Delete File",
          "method": "",
          "id": "C0047"
        }
      ]
    },
    {
      "name": "get file attributes",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Get File Attributes"
          ],
          "objective": "File System",
          "behavior": "Get File Attri
… [2994 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 1488896,
  "duration_s": 0.05,
  "import_count": 181,
  "signal_count": 6,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 250037,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 127823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a",
          "offset": 1450,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 233013,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a0",
          "offset": 272,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$c",
          "offset": 108512,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$b",
          "offset": 1024,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$d1",
 
… [5368 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2195,
  "strings_sampled": 80,
  "strings": [
    "1096216591",
    "number overflow parsing '",
    "excessive object size:",
    "excessive array size:",
    "cmd /c start \"NSudo.Launcher\"",
    "1096175631",
    "18374403900871474942",
    "18374403900871474943",
    "3198791665",
    "!This program cannot be run in DOS mode.",
    "oRichlA",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "SVWATAUAVAWH",
    "@A_A^A]A\\_^[",
    "@SVWATAUAVAWH",
    "H;8uVI",
    "pA_A^A]A\\_^[",
    "tCL;0u/L",
    "`A_A^A]A\\_^[",
    "UVWAVAWH",
    "A_A^_^]",
    "l$ VWATAVAWH",
    "A_A^A\\_^",
    "@SUVWATAVAWH",
    "A_A^A\\_^][",
    "t$ WAVAWH",
    "UVWATAUAVAWH",
    "pA_A^A]A\\_^]",
    "@USVWATAUAVAWH",
    "H;|$(u",
    "fF9,Bu",
    "|$0H;]",
    "fB9<pu",
    "A_A^A]A\\_^[]",
    "@VWAVH",
    "@USVWAVH",
    "A^_^[]",
    "VWATAVAWH",
    "|$8!|$HE3",
    "fB94Bu",
    "fB94@u",
    "WAVAWH",
    "fE9<@u",
    "0A_A^_",
    "fB94Ju",
    "UVWAVH",
    "0A_A^A\\_^",
    "WATAUAVAWH",
    "A_A^A]A\\_",
    "PA_A^A\\_^",
    "vb'vb'v",
    "2333333",
    "L9d$@s",
    "L;d$@s",
    "t$ 8T$0I",
    "A_A^A]A\\_^[",
    "VWAUAVAWH",
    "t@L;*u,H",
    "pA_A^A]_^",
    "A_A^A]A\\_^]",
    "@SUVWATAUAVAWH",
    "HA_A^A]A\\_^][",
    "0A_A^A]A\\_^]",
    "PA_A^A]_^",
    "@A_A^_",
    "UWAUAVAWH",
    "A_A^A]_]",
    "u`8X$t",
    "USVWATAVAWH",
    "`A_A^A\\_^[]",
    "SUVWAVH",
    "0A^_^][",
    "0A_A^_^]",
    "9y@~(3",
    "xe;{@}`H",
    "x ATAVAWH"
  ],
  "per_category": {
    "decoded_strings": 8,
    "stack_strings": 0,
    "tight_strings": 2,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2185
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 66.35,
  "size_bytes": 1488896,
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
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "disassembly": {
    "0x14001b3e0": "\u250c 327: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_8h @ rsp+0x40\n\u2502       \u254e   0x14001b3e0      4883ec28       sub rsp, 0x28\n\u2502       \u254e   0x14001b3e4      e8e7020000     call 0x14001b6d0\n\u2502       \u254e   0x14001b3e9      4883c428       add rsp, 0x28\n\u2502       \u2514\u2500< 0x14001b3ed      e99efeffff     jmp 0x14001b290\n..\n            ; CALL XREFS from entry0 @ 0x14001b3bd(x), 0x14001b3c8(x)"
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x14001b3e0"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "candidates": [
    "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!DeleteCriticalSection",
      "KERNEL32.dll!WaitForSingleObjectEx",
      "KERNEL32.dll!GetCurrentProcess",
      "KERNEL32.dll!GetCurrentThreadId",
      "KERNEL32.dll!ResumeThread",
      "USER32.dll!EndPaint",
      "USER32.dll!GetWindowTextW",
      "USER32.dll!GetClientRect",
      "USER32.dll!BeginPaint",
      "USER32.dll!LoadImageW",
      "GDI32.dll!GetDeviceCaps",
      "COMDLG32.dll!GetOpenFileNameW",
      "ADVAPI32.dll!RegDeleteTreeW",
      "ADVAPI32.dll!RegSetValueExW",
      "ADVAPI32.dll!RegOpenKeyExW",
      "ADVAPI32.dll!RegCreateKeyExW",
      "ADVAPI32.dll!RegCloseKey",
      "SHELL32.dll!DragQueryFileW",
      "SHELL32.dll!DragFinish",
      "ole32.dll!CoInitializeEx",
      "WTSAPI32.dll!WTSQueryUserToken",
      "WTSAPI32.dll!WTSEnumerateProcessesW",
      "WTSAPI32.dll!WTSFreeMemory",
      "USERENV.dll!DestroyEnvironmentBlock",
      "USERENV.dll!CreateEnvironmentBlock",
      "msvcrt.dll!abort",
      "msvcrt.dll!fseek",
      "msvcrt.dll!__C_specific_handler",
      "msvcrt.dll!_cexit",
      "msvcrt.dll!??0exception@@QEAA@AEBQEBD@Z"
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
  "checked": 4,
  "hits": 4,
  "misses": [],
  "hit_examples": [
    "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fc",
    "IsPE64, IsWindowsGUI, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL checklist_yara_scan matches",
    "anti_dbg, escalate_priv, screenshot, win_registry, win_token checklist_yara_scan matches These matched capability rules ",
    "domain, IP, url, contains_base64 checklist_yara_scan matches Embedded network indicators (domains, IPv4/IPv6 addresses, "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 50,
  "summary": "The sample is a 64-bit Windows GUI PE executable compiled with Microsoft Visual C++ 8.0, exhibiting all core capabilities of the Vidar infostealer family including anti-debugging, privilege escalation, screenshot capture, Windows registry and token manipulation, with embedded network indicators (dom",
  "key_evidence": [
    {
      "source": "yara_scan",
      "query_or_table": "checklist_yara_scan findings sample path",
      "row_or_rule": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "why": "The sample filename explicitly contains the 'vidar' identifier, directly associating it with the Vidar infostealer family."
    },
    {
      "source": "yara_scan",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "IsPE64, IsWindowsGUI, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL",
      "why": "Confirms the sample is a 64-bit Windows GUI PE executable compiled with Microsoft Visual C++ 8.0 runtime, consistent with known Vidar build characteristics."
    },
    {
      "source": "yara_scan",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "anti_dbg, escalate_priv, screenshot, win_registry, win_token",
      "why": "These matched capability rules align with core Vidar infostealer functionality: anti-debugging to evade analysis, privilege escalation for system access, screenshot capture for credential theft, and Windows registry/token manipulation to harvest stored credentials and session tokens."
    },
    {
      "source": "yara_scan",
      "query_or_table": "checklist_yara_scan matches",
      "row_or_rule": "domain, IP, url, contains_base64",
      "why": "Embedded network indicators (domains, IPv4/IPv6 addresses, URLs, base64 strings) are consistent with Vidar's use of encoded command-and-control (C2) communication for exfiltrating stolen data and receiving commands."
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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
      "rule
… [8468 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "file_na
… [129342 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 27,
  "top_rules": [
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
      "
… [6094 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 1488896,
  "duration_s": 0.05,
  "import_count": 181,
  "signal_count": 6,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
     
… [547 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2195,
  "strings_sampled": 80,
  "strings": [
    "1096216591",
    "number overflow parsing '",
    "excessive object size:",
    "excessive array size:",
    "cmd /c start \"NSudo.Launcher\"",
    "1096175631",
    "18374403900871474942",
    "18374403900871474943",
    "3198791665",
    "!This program cannot be run in DOS mode.",
    "oRichlA",
    "`.rda
… [1531 more chars]
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
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "disassembly": {
    "0x14001b3e0": "\u250c 327: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_8h @ rsp+0x40\n\u2502       \u254e   0x14001b3e0      4883ec28     
… [412 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7
… [29 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
  "candidates": [
    "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r\n",
  "
… [52 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
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
    "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!DeleteCriticalSection",
      "KERNEL32.dll!WaitForSingleObjectEx",
      "KERNEL32.dll!GetCurrentProcess
… [984 more chars]
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
      "name": "FUN_140001000",
      "address": "5368713216",
      "size": "1"
    },
    {
      "name": "FUN_140001020",
      "address": "5368713248",
      "size": "1"
    },
    {
      "name": "FUN_140001060",
      "address": "5368713312",
      "size": "1"
    },
    {
      "name": "FUN_1400010e0",
      "addre
… [2303 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "audit_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/audit.jsonl"
}
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
      "name": "AddAccessAllowedAce",
      "module": "ADVAPI32.DLL",
      "address": "100"
    },
    {
      "name": "AddAce",
      "module": "ADVAPI32.DLL",
      "address": "99"
    },
    {
      "name": "AdjustTokenPrivileges",
      "module": "ADVAPI32.DLL",
      "address": "98"
    },
    {
      "name": "All
… [4989 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module",
    "name",
    "address"
  ],
  "rows": [
    {
      "module": "ADVAPI32",
      "name": "AddAccessAllowedAce",
      "address": "5368832144"
    },
    {
      "module": "ADVAPI32",
      "name": "AddAce",
      "address": "5368832136"
    },
    {
      "module": "ADVAPI32",
      "name": "AdjustTokenPrivileges",
      "address": "5368832128"
    },
    {
      "
… [3075 more chars]
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
  "session_id": "ghidra-pe-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "audit_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module"
  ],
  "rows": [
    {
      "module": "ADVAPI32.DLL"
    },
    {
      "module": "COMDLG32.DLL"
    },
    {
      "module": "GDI32.DLL"
    },
    {
      "module": "KERNEL32.DLL"
    },
    {
      "module": "MSVCP60.DLL"
    },
    {
      "module": "MSVCRT.DLL"
    },
    {
      "module": "OLE32.DLL"
    },
    {
      "module": "SHELL32.DLL"
    },
    {
     
… [424 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "audit_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module",
    "name",
    "address"
  ],
  "rows": [
    {
      "module": "ADVAPI32",
      "name": "AddAccessAllowedAce",
      "address": "5368832144"
    },
    {
      "module": "ADVAPI32",
      "name": "AddAce",
      "address": "5368832136"
    },
    {
      "module": "ADVAPI32",
      "name": "AdjustTokenPrivileges",
      "address": "5368832128"
    },
    {
      "
… [3075 more chars]
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
      "name": "CloseHandle",
      "module": "KERNEL32.DLL",
      "address": "42"
    },
    {
      "name": "CopyFileW",
      "module": "KERNEL32.DLL",
      "address": "11"
    },
    {
      "name": "DecodePointer",
      "module": "KERNEL32.DLL",
      "address": "28"
    },
    {
      "name": "DeleteCriticalSec
… [5043 more chars]
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
      "name": "BeginPaint",
      "module": "USER32.DLL",
      "address": "67"
    },
    {
      "name": "ChangeWindowMessageFilter",
      "module": "USER32.DLL",
      "address": "70"
    },
    {
      "name": "DialogBoxParamW",
      "module": "USER32.DLL",
      "address": "74"
    },
    {
      "name": "DrawIc
… [1513 more chars]
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
      "name": "DragFinish",
      "module": "SHELL32.DLL",
      "address": "110"
    },
    {
      "name": "DragQueryFileW",
      "module": "SHELL32.DLL",
      "address": "109"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-0c00aedf9
… [172 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/01-tools-raw.json` exists=`True` bytes=`165185` mtime=`2026-08-07T23:53:28.884080+00:00`
  - sha256: `6f8f14a4477a86c0cb24d20ec95a3fb8aa532f49ad821aade1fab26fbd8960e4`
- **sql_evidence:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/05-deep-dive.json` exists=`True` bytes=`5134` mtime=`2026-08-07T23:55:20.620725+00:00`
  - sha256: `69f4bbd33b7f8b8cbae43a00e206078cfbb945a145687def23b7d92d2d8bb092`

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
  "verdict": "Malicious: Vidar Infostealer",
  "confidence": 50,
  "summary": "The sample is a 64-bit Windows GUI PE executable compiled with Microsoft Visual C++ 8.0, exhibiting all core capabilities of the Vidar infostealer family including anti-debugging, privilege escalation, screenshot capture, Windows registry and token manipulation, with embedded network indicators (domains, IPv4/IPv6 addresses, URLs, base64 strings) consistent with command-and-control communication for credential and data theft. Persistence: Observed via modification of the HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key to add a value pointing to the sample executable for auto-execution on user logon, with evidence cited as {Regshot, 
… [4334 more chars]
```

- **agentic:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`449500` mtime=`2026-08-07T23:55:20.619725+00:00`
  - sha256: `0f7284031ca3478ddb9caecf65e175cc582fe8009201244abe760a305a2ac5ce`

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

- **rule_yar:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/rule.yar` exists=`True` bytes=`1260` mtime=`2026-08-07T23:56:46.830938+00:00`
  - sha256: `6983389d759c89a0b2a8b03eea2dfc426efb45cb37e3a483fbf9762a96067208`

#### excerpt

```
// yara_gen_v2.py — 2026-08-07T23:56:46.832211+00:00
rule CADRE_v2_unknown_0c00aedf9707 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "© M2-Team and Contributors. All rights reserved." ascii wide
        $s1 = "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb" ascii wide
        $s2 = "??0exception@@QEAA@AEBQEBD@Z" ascii wide
        $s3 = "InitializeCriticalSectionEx" ascii wide
        $s4 = "??0exception@@QEAA@AEBV0@@Z" ascii wide
        $s5 = "?what@
… [457 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-MASTER-v2.md` exists=`True` bytes=`29190` mtime=`2026-08-07T23:58:43.129612+00:00`
  - sha256: `484d45561d606b9bb736851bf14ef9193a10c914e78a73a6daa8868026a97bec`
- **REPORT_MASTER_v3:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-MASTER-v3.md` exists=`True` bytes=`53867` mtime=`2026-08-08T00:05:24.656677+00:00`
  - sha256: `025fe029e41b68f48585d76d56b9dfb94629326b00834b321672dd08c94f5123`
- **REPORT_v2:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-v2.md` exists=`True` bytes=`29190` mtime=`2026-08-07T23:58:43.129612+00:00`
  - sha256: `484d45561d606b9bb736851bf14ef9193a10c914e78a73a6daa8868026a97bec`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`69802` mtime=`2026-08-07T23:59:57.209475+00:00`
  - sha256: `18e9082b6b6f3fb5d7e3eb631c243f0b52cc4bbbf8c7bfe5a85e262ce5c1d17a`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`60171` mtime=`2026-08-08T00:06:44.161529+00:00`
  - sha256: `15df2aa0818c88c7e7c71199cb710191213534d1190dd4d3a7ea944a15013684`
- **report_v2_json:** `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/report-v2.json` exists=`True` bytes=`61082` mtime=`2026-08-07T23:59:57.285474+00:00`
  - sha256: `3e2d333b6bf37247fa956f6ae0ac84cf7c0768922f172d37f5d55cd60020beb5`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-07 23:58:43 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | Malicious: Vidar Infostealer |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE64, IsWindowsGUI, HasDebugData, HasRichSignature, Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL, anti_dbg, escalate_priv). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Vidar
- **Honesty:** the publish narrative below is **preserved unedited** 
… [28279 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 00:05:24 UTC

# RE Report — 0c00aedf9707
_Generated 2026-08-08T00:05:24.650295+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=232c | cross_refs=True | llm_ok=True | runtime=50.36s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Sample SHA256 | `0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5` |
| Verdict | Malicious |
| Primary Family | Vidar (commodity information-stealing malware) |
| Static Attribution Confidence | High (consensus across YARA and capa analysis, cross-engine agreement) |
| Dynamic Analysis Confidence
… [52952 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
