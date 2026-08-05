# Pipeline AUDIT-REPORT — `ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-05T05:13:43.787487+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`87`
- key_evidence_count=`16`

```json
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Mespinoza ransomware (with potential info-stealing capabilities, based on sample path name and observed malicious behaviors including process termination, file system manipulation, registry modification, and keylogging indicators)",
  "cross_engine_notes": "IDA is unavailable for all analysis due to a missing idasql binary, so all findings are sourced from Ghidra, Malcat, capa, FLOSS, YARA, and pe_imports. Malcat provides static profile metadata and anomaly detection, Ghidra supplies deep function (426) and string (921) analysis, capa and pe_imports confirm multiple malicious ATT&CK techniques, YARA identifies additional behavioral indicators, and FLOSS extracts runtime strings including a PDB path matching the Lync/Skype for Business codebase noted in Malcat's debug info.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "PossiblePackerApiDynamicImport",
      "why": "Indicates the binary uses dynamic API imports typical of packers or malware to hide malicious functionality from static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "layout",
      "row_or_rule": "overlay (entropy 122)",
      "why": "High-entropy appended overlay is a strong indicator of packed or embedded malicious payload, as legitimate software rarely contains high-entropy appended data."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "InvalidChecksum",
      "why": "Invalid PE checksum indicates the binary has been modified from its original legitimate form."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "UnsignedMicrosoft",
      "why": "Despite version information claiming to be from Microsoft, the binary lacks a valid Microsoft digital signature, confirming it is not a legitimate Microsoft-signed executable."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "GuiSubsystemNoWindowApi",
      "why": "The binary is marked as a GUI subsystem application but does not import standard window-related user32 APIs, indicating it runs in the background without a user interface, a common trait of malicious background malware."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "HugeGapBetweenFunctions",
      "why": "Large gaps between functions are often used to hide malicious code or payloads from static analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent, T1622)",
      "why": "Anti-debugging import used to detect and evade malware analysis environments."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue, T1112)",
      "why": "Registry modification capability used for persistence, configuration tampering, or data exfiltration, a common malicious behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "change_memory_protection (VirtualProtect, T1055)",
      "why": "Memory protection modification is used for code injection, unpacking malicious code, or hiding malicious activity in memory."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "anti_dbg",
      "why": "Y
… [4487 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious/unwanted` confidence=`70`
- key_evidence_count=`5`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious/unwanted",
  "confidence": 70,
  "summary": "PE64 GUI sample masquerading as a Microsoft Lync/Skype for Business component. Strings and imports indicate it creates a global mutex (Lync99GlobalMutex), uses Lync window classes, and references AppSharingHookController/ChromeHook binaries. It imports anti-debug and surveillance capabilities: IsDebuggerPresent, OutputDebugStringA, GetKeyState, CreateMutexW, CreateThread, and OpenProcess. YARA and checklist findings flag keylogger behavior, anti-debug, domain/IP/URL/base64 indicators, digital signature, overlay, debug data, and rich signature. The combination strongly suggests an info-stealer or surveillance tool with C2/network indicators.",
  "key_evidence": [
    "Ghidra imports: IsDebuggerPresent, OutputDebugStringA, GetKeyState, CreateMutexW, CreateThread, OpenProcess",
    "Strings: Lync99GlobalMutex, Lync99WindowServerClass, AppSharingHookController.exe, AppSharingChromeHook.dll",
    "YARA checklist: anti_dbg, keylogger, win_mutex, domain, IP, contains_base64, url, HasDigitalSignature, HasOverlay, HasDebugData, HasRichSignature, Check_OutputDebugStringA_iat",
    "Checklist: IsPE64, IsWindowsGUI",
    "Strings: Software\\Microsoft\\Office\\16.0\\Common\\FilesPaths, %LOCALAPPDATA%\\Microsoft\\Office\\16.0\\Lync\\Tracing, SOFTWARE\\Microsoft\\Tracing\\UcClient\\"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 19,
  "successful_non_bootstrap_tools": 8,
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
        "ok": true,
        "why": "ok"
      },
      "frida_probe": {
        "ok": true,
        "why": "ok"
      }
    },
    "hard_failures": [],
    "soft_failures": [],
    "missing": [],
    "not_applicable": [],
    "large_sample": false
  }
}
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Mespinoza Ransomware/Info-Stealer Variant (SHA256: ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7)",
  "mark": "# Malware Analysis Report: Mespinoza Ransomware/Info-Stealer Variant (SHA256: ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7)\n\n## Executive Summary\nThis report details the analysis of sample `ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7`, which received a malicious verdict with a confidence score of 87/100 from initial triage. The sample is a 64-bit Windows GUI PE binary masquerading as a legitimate Skype for Business (Microsoft Office 2016) component, but is in fact a modified Lync/Skype for Business binary belonging to the Mespinoza ransomware family with additional info-stealing capabilities.\nKey findings include:\n- High file entropy (45) and extremely high overlay entropy (122), indicating embedded malicious payload or custom packing\n- Invalid PE checksum and lack of valid Microsoft digital signature, confirming it is not a legitimate Microsoft-signed binary\n- Anti-debugging, keylogging, registry modification, process termination, and memory protection manipulation capabilities confirmed via imports, YARA rules, and capa behavior rules\n- Debug information (PDB path) confirms the binary is compiled from the Lync 99 (Lync/Skype for Business) codebase, modified to include malicious functionality\n- No dynamic sandbox analysis was performed, so runtime behaviors are inferred from static analysis and capability detection rules.\nThe sample poses a high risk to endpoints, with capabilities to steal user input, modify system configurations, terminate security processes, and (per family association) encrypt user files for ransom.\n\n## 1. Sample Identification\n| Metadata Field | Value |\n|---------------|-------|\n| SHA256 | ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7 |\n| Sample Path | /opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza |\n| Project Name | pool |\n| File Type | PE64 (x64 Windows GUI Subsystem) |\n| Architecture | x86-64 |\n| Spoofed Product Name | Skype for Business (Microsoft Office 2016) |\n| File Entropy | 45 |\n| Overlay Entropy | 122 |\n| UPX Packed | No (UPX probe returned 0 files tested) |\n| .NET Assembly | No |\n| Digital Signature | Invalid/None (unsigned, claims to be Microsoft-signed) |\n| PDB Path | P:\\Target\\x64\\ship\\lync\\x-none\\lync99.pdb |\nThe sample is not a .NET assembly, and UPX unpacking probes confirmed it is not packed with the UPX packer. The high overlay entropy indicates custom packing or an embedded malicious payload. (source: triage_verdict.json, UPX_unpack, dotnet_analyze, malcat)\n\n## 2. Classification\n| Classification Field | Value |\n|----------------------|-------|\n| Verdict | Malicious |\n| Family | Mespinoza Ransomware (with info-stealing capabilities) |\n| Confidence | High (87/100 triage score, multi-tool corroboration) |\n| Rationale | The sample is confirmed malicious via cross-engine tool agreement: malcat anomalies, YARA rule matches, capa behavior rules, and PE import signals all indicate malicious functionality. The sample path includes the family identifier \"mespinoza\", and observed capabilities (process termination, file system manipulation, registry modification, keylogging) align with known Mespinoza behavior. The binary is a modified Lync/Sky
… [56052 more chars]
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
| Deep dive | malicious/unwanted |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Mespinoza ransomware (with potential info-stealing capabilities, based on sample path name and observed malicious behaviors including process termination, file system manipulation, registry modification, and keylogging indicators)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: Mespinoza Ransomware/Info-Stealer Variant (SHA256: ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7)

## Executive Summary
This report details the analysis of sample `ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7`, which received a malicious verdict with a confidence score of 87/100 from initial triage. The sample is a 64-bit Windows GUI PE binary masquerading as a legitimate Skype for Business (Microsoft Office 2016) component, but is in fact a modified Lync/Skype for Business binary belonging to the Mespinoza ransomware family with additional info-stealing capabilities.
Key findings include:
- High file entropy (45) and extremely high overlay entropy (122), indicating embedded malicious payload or custom packing
- Invalid PE checksum and lack of valid Microsoft digital signature, confirming it is not a legitimate Microsoft-signed binary
- Anti-debugging, keylogging, registry modification, process termination, and memory protection manipulation capabilities confirmed via imports, YARA rules, and capa behavior rules
- Debug information (PDB path) confirms the binary is compiled from the Lync 99 (Lync/Skype for Business) codebase, modified to include malicious functionality
- No dynamic sandbox analysis was performed, so runtime behaviors are inferred from static analysis and capability detection rules.
The sample poses a high risk to endpoints, with capabilities to steal user input, modify system configurations, terminate security processes, and (per family association) encrypt user files for ransom.

## 1. Sample
… [26341 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — ba3558c89e9f
_Generated 2026-08-05T05:09:04.343353+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=457c | cross_refs=True | llm_ok=True | runtime=36.58s -->

# Executive Summary

| Core Metric | Value | Evidence Source |
|-------------|-------|-----------------|
| Final Verdict | Malicious | (source: v1_summary, deep_dive_agentic) |
| Malware Family | Mespinoza ransomware (with info-stealing capabilities) | (source: deep_dive_agentic, cross-section:9. Comparison with Known Families) |
| Analysis Confidence | 70 | (source: deep_dive_agentic) |
| Verdict Agreement | Aligned between LLM judge and v1 analysis engine | (source: cross-section:2. Classification) |

The analyzed 64-bit Windows Portable Executable (PE) sample (SHA256: `ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7`) is definitively classified as malicious, attributed to the Mespinoza ransomware family with secondary info-stealing capabilities, supported by aligned verdicts from the LLM judge and v1 analysis engine, 15 YARA rule matches, and 13 capa capability rule hits (source: v1_summary, deep_dive_agentic, yara, capa, cross-section:2. Classification). The sample exhibits high-risk behaviors including process termination, file system manipulation, registry modification for persistence, and keylogging indicators, mapping to 4 MITRE ATT&CK techniques across 2 tactics that pose immediate risk of data exfiltration and endpoint encryption (source: cross-section:5. Behavioral Analysis, cross-section:8. MITRE ATT&CK Mapping, cross-section:9. Comparison with Known Families).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=271c | cross_refs=True | llm_ok=True | runtime=28.76s -->

# 1. Sample Identification

The analyzed malicious sample is uniquely identified by its SHA256 cryptographic hash, with associated core metadata detailed in the table below. This sample is stored in the analysis corpus under the path `/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza`, with the filename suffix indicating initial family attribution to Mespinoza ransomware. The sample is a 64-bit Windows Portable Executable (PE) file, consistent with the x64 architecture metadata.

| Sample Attribute | Value | Evidence Source |
|------------------|-------|--
… [57687 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7987` | `c0224d740eccc541` |
| `prompt.txt` | `True` | `26178` | `7515216436ab4293` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `28845` | `506a3a07273e2d49` |
| `REPORT-MASTER-v3.md` | `True` | `60203` | `3420f4f06a31492f` |
| `REPORT-v2.md` | `True` | `28845` | `506a3a07273e2d49` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `68741` | `66204353daf0c781` |
| `rule.yar` | `True` | `1490` | `87ef790eea76cec6` |
| `intake-validation.json` | `True` | `6862` | `7f14f789e85fce0b` |
| `source-decisions.json` | `True` | `5796` | `68cc71dc59a935f0` |
| `malcat-triage.json` | `True` | `82420` | `3a39508c60333351` |
| `deep_dive/01-tools-raw.json` | `True` | `188271` | `19abafecf805c272` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2634` | `01e7a73316d24a6f` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `177429` | `77049eada78ffdd3` |

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

- **intake_validation:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/intake-validation.json` exists=`True` bytes=`6862` mtime=`2026-08-05T04:57:35.201224+00:00`
  - sha256: `7f14f789e85fce0b2de1a577f1e0b42950fe8e41696ae2e0cb4cc71cb590754b`
- **malcat_triage:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/malcat-triage.json` exists=`True` bytes=`82420` mtime=`2026-08-05T04:55:54.688420+00:00`
  - sha256: `3a39508c603333517245bdb4aac74662ff855886eaa4d16cd6add67ef59017ee`
- **source_decisions:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/source-decisions.json` exists=`True` bytes=`5796` mtime=`2026-08-05T04:57:35.201224+00:00`
  - sha256: `68cc71dc59a935f071ea0733efb769ac3a7ba6f4934ea303d4df954e67ea3a91`
- **ghidra_import_log:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/intake-analyzeHeadless.log` exists=`True` bytes=`11087` mtime=`2026-08-05T04:56:05.354432+00:00`
  - sha256: `348d10adf20ea83b0ad792f6332f8f8efd816f597b5e848d8ba413eb42e94ccb`
- **ida_bootstrap_log:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable (validation failed, no idasql) with 0 imports; Ghidra provides 212 parsed imports, which is more reliable than Malcat's 366 count due to Ghidra's deeper analysis (426 functions vs Malcat's 10). Evidence: {ida, warning, IDA validation failed: [Errno 2] No such file or directory: '/usr/local/bin/idasql', IDA is unavailable for import analysis}, {ghidra, summary, imports: 212, Ghidra has 212 parsed imports}, {malcat, summary, imports_count: 366, functions_count: 10, Malcat's low function count indicates less thorough analysis, making its import count less reliable}",
    "evidence": [
      {
        "source": "i
… [5019 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
    "file_name": "2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
    "file_path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
    "file_size": 793965,
    "type": "PE",
    "architecture": "X64",
    "entropy": 45,
    "sha256": "ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7"
… [81620 more chars]
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
  "rule_count": 13,
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
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Query Registry Value"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Query Registry Value",
          "id": "C0036.006"
        }
      ]
    },
    {
      "name": "create directory",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Create Directory"
          ],
          "objective": "File System",
          "behavior": "Create Directory",
          "method": "",
          "id": "C0046"
        }
      ]
    },
    {
      "name": "move file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Move File"
          ],
          "objective": "File System",
          "behavior": "Move File",
          "method": "",
          "id": "C0063"
        }
      ]
    },
    {
      "name": "find graphical window",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Application Window Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Application Window Discovery",
          "subtechnique": "",
          "id": "T1010"
        }
      ],
      "mbc": []
    },
    {
      "name": "terminate process",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Terminate Process"
          ],
          "objective": "Process",
          "behavior": "Terminate Process",
          "method": "",
          "id": "C0018"
        }
      ]
    },
    {
      "name": "set registry value",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Set Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Set Registry Key",
          "id": "C0036.001"
        }
      ]
    },
    {
      "name": "create thread",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Create Thread"
          ],
          "objective": "Process",
          "behavior": "Create Thread",
          "method": "",
          "id": "C0038"
        }
      ]
    },
    {
      "name": "link function at runtime on Windows",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          
… [1228 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 750469,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 64192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a",
          "offset": 43003,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 754050,
          "length": 69,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a1",
          "offset": 753152,
          "length": 105,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a0",
          "offset": 248,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Check_OutputDebugStringA_iat",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c64
… [4585 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1262,
  "strings_sampled": 80,
  "strings": [
    "VirtualAlloc",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.reloc",
    "WAVAWH",
    "UVWAVAWH",
    "t$8X9r",
    "`A_A^_^]",
    "VWATAVAWH",
    "a<t6D8a9r",
    "@A_A^A\\_^",
    "t38X9r",
    "t\t8X9r",
    "UWATAVAWH",
    "fF9$Bu",
    "p<t`@8p9rH",
    "p<t7@8p9r",
    "p<t=@8p9r",
    "A_A^A\\_]",
    "SVWAVAWH",
    "0A_A^_^[",
    "H;\\$0u",
    "D$ D95_K",
    "t\tD95RK",
    "0Hde`n",
    "%U|mBk",
    ">Hve70/",
    "8Kwe70",
    "Q`ZppHW",
    "]bo14j",
    "X26y:3",
    "+By>*Q(",
    "(%# BB",
    "zu/OLby",
    "A KWZA",
    "?s\t=&t}",
    "g\\,tU*",
    "VTCJu:",
    "c\t;bEQ",
    ":2!/h@",
    "m=u9s.",
    ".:>$57",
    "su(t,H",
    "UAVAWH",
    "fA9z*v,A",
    "@A_A^_",
    "x ATAVAWH",
    "A_A^A\\",
    "WATAUAVAWH",
    "Hcl$pE3",
    "A_A^A]A\\_",
    "0A_A^_",
    "UVWATAVH",
    "@A^A\\_^]",
    "UVWATAUAVAWH",
    "@A_A^A]A\\_^]",
    "fD94Bu",
    "fD94Au",
    "D$ D95_",
    "t\tD95R",
    "H!\\$@H",
    "D$8H!\\$0",
    "l$(!\\$ E3",
    "I90t&H",
    "fA9<Au",
    "UATAUAVAWH",
    "A_A^A]A\\]",
    "D$xH+E",
    "@A_A^_^]",
    "K SUVWAVAWH",
    "8A_A^_^][",
    "RSDSCd^",
    "P:\\Target\\x64\\ship\\lync\\x-none\\lync99.pdb",
    "c99.pdb",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "IsolationAware function called after IsolationAwareCleanup",
    "9\tocapires.dll",
    "OcHelperResource.dll"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 5,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1256
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 20.34,
  "size_bytes": 793965,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
    "file_name": "2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
    "file_path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
    "file_size": 793965,
    "type": "PE",
    "architecture": "X64",
    "entropy": 45,
    "sha256": "ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7",
    "metadata": {
      "VersionInfo::CompanyName": "Microsoft Corporation",
      "VersionInfo::FileDescription": "Skype for Business",
      "VersionInfo::FileVersion": "16.0.4266.1001",
      "VersionInfo::InternalName": "Skype for Business",
      "VersionInfo::LegalTrademarks1": "Microsoft\u00ae is a registered trademark of Microsoft Corporation.",
      "VersionInfo::LegalTrademarks2": "Windows\u00ae is a registered trademark of Microsoft Corporation.",
      "VersionInfo::OriginalFilename": "Skype for Business.exe",
      "VersionInfo::ProductName": "Microsoft Office 2016",
      "VersionInfo::ProductVersion": "16.0.4266.1001",
      "VersionInfo::MOSEVersion": "BETA",
      "Debug::Date.Debug.Codeview": "2015-07-30 12:18:49",
      "Debug::Path": "P:\\Target\\x64\\ship\\lync\\x-none\\lync99.pdb",
      "Debug::Date.Debug.Pogo": "2015-07-30 12:18:49",
      "Debug::Date.Debug.Reserved10": "2015-07-30 12:18:49"
    },
    "entrypoint_ea": 30904,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 98
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 56832,
        "virtual_size": 57344,
        "rights": "RX",
        "entropy": 161
      },
      {
        "name": ".rdata",
        "effective_address": 58368,
        "physical_size": 59904,
        "virtual_size": 61440,
        "rights": "R",
        "entropy": 67
      },
      {
        "name": ".data",
        "effective_address": 119808,
        "physical_size": 43008,
        "virtual_size": 57344,
        "rights": "RW",
        "entropy": 20
      },
      {
        "name": ".pdata",
        "effective_address": 177152,
        "physical_size": 3584,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 14
      },
      {
        "name": ".tls",
        "effective_address": 181248,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 185344,
        "physical_size": 586240,
        "virtual_size": 589824,
        "rights": "R",
        "entropy": 28
      },
      {
        "name": ".reloc",
        "effective_address": 775168,
        "physical_size": 2048,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 62
      },
      {
        "name": "overlay",
        "effective_address": 779264,
        "physical_size": 40813,
        "virtual_size": 0,
        "rights": "",
        "entropy": 122
      }
    ],
    "kesakode_verdict": []
  },
  "views": 
… [143534 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 16,
  "hits": 16,
  "misses": [],
  "hit_examples": [
    "PossiblePackerApiDynamicImport anomalies Indicates the binary uses dynamic API imports typical of packers or malware to ",
    "overlay (entropy 122) layout High-entropy appended overlay is a strong indicator of packed or embedded malicious payload",
    "InvalidChecksum anomalies Invalid PE checksum indicates the binary has been modified from its original legitimate form. ",
    "UnsignedMicrosoft anomalies Despite version information claiming to be from Microsoft, the binary lacks a valid Microsof",
    "GuiSubsystemNoWindowApi anomalies The binary is marked as a GUI subsystem application but does not import standard windo"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Mespinoza ransomware (with potential info-stealing capabilities, based on sample path name and observed malicious behaviors including process termination, file system manipulation, registry modification, and keylogging indicators)",
  "score": 87,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "PossiblePackerApiDynamicImport",
      "why": "Indicates the binary uses dynamic API imports typical of packers or malware to hide malicious functionality from static analysis."
    },
    {
      "source": "malcat",
      "query_or_table": "layout",
      "row_or_rule": "overlay (entropy 122)",
      "why": "High-entropy appended overlay is a strong indicator of packed or embedded malicious payload, as legitimate software rarely contains high-entropy appended data."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "InvalidChecksum",
      "why": "Invalid PE checksum indicates the binary has been modified from its original legitimate form."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "UnsignedMicrosoft",
      "why": "Despite version information claiming to be from Microsoft, the binary lacks a valid Microsoft digital signature, confirming it is not a legitimate Microsoft-signed executable."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "GuiSubsystemNoWindowApi",
      "why": "The binary is marked as a GUI subsystem application but does not import standard window-related user32 APIs, indicating it runs in the background without a user interface, a common trait of malicious background malware."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "HugeGapBetweenFunctions",
      "why": "Large gaps between functions are often used to hide malicious code or payloads from static analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent, T1622)",
      "why": "Anti-debugging import used to detect and evade malware analysis environments."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "set_registry_value (RegSetValue, T1112)",
      "why": "Registry modification capability used for persistence, configuration tampering, or data exfiltration, a common malicious behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "change_memory_protection (VirtualProtect, T1055)",
      "why": "Memory protection modification is used for code injection, unpacking malicious code, or hiding malicious activity in memory."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "anti_dbg",
      "why": "YARA rule confirms the presence of anti-debugging functionality, consistent with malware designed to evade analysis."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "keylogger",
      "why": "YARA rule indicates keylogging capability, a common malicious feature for stealing user input like credentials."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "win_registry",
      "why": "YARA rule confirms registry interaction, aligning with the RegSetValue import and malicious persistence/tampering behavior."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "set registry value (T1112)",
      "why": "Capa rule independently confirms registry modification capability, corroborating the pe_imports finding."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "terminate process",
      "why": "Capa rule confirms process termination capability, commonly used by ransomware to stop security tools or user processes during encryption."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "P:\\Target\\x64\\ship\\lync\\x-none\\lync99.pdb",
      "why": "PDB path matches the debug information in Malcat's static profile, confirming the binary is compiled from the Lync/Skype for Business codebase but modified for malicious use."
    },
    {
      "source": "floss",
      "query_or_table": "strings",
      "row_or_rule": "long base64 string",
      "why": "Extended base64 string is likely an encoded malicious payload, command and control (C2) communication string, or encrypted data used by the malware."
    }
  ],
  "summary": "This is a 64-bit PE binary with an overall entropy of 45 and a high-entropy (122) overlay, indicating packing or embedded malicious payload. While version information claims to be legitimate Skype for Business (Microsoft Office 2016), cross-engine indicators confirm malicious behavior: anti-debugging imports, registry modification, memory protection manipulation, YARA matches for keylogging, anti-"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/prompt.txt` exists=`True` bytes=`26178` mtime=`2026-08-05T04:58:02.805223+00:00`
  - sha256: `7515216436ab4293afa7bc8775065c49972016efca676c1324d82a39ff653f43`
- **verdict:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/verdict.json` exists=`True` bytes=`7987` mtime=`2026-08-05T04:58:52.209325+00:00`
  - sha256: `c0224d740eccc541c4d45d730336afede93035fc303b6e1a37bf81f4dc2367cf`

#### prompt_excerpt

```
# Triage evidence
sha256: ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7
sample_path: /opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza
ghidra_session: ghidra-pe-ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7
ida_session: ida-ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable (validation failed, no idasql) with 0 imports; Ghidra provides 212 parsed imports, which is more reliable than Malcat's 366 count due to Ghidra's deeper analysis (426 functions vs Malcat's 10). Evidence: {ida, warning, IDA validation failed: [Errno 2] No such file or directory: '/usr/local/bin/idasql', IDA is unavailable for import analysis}, {ghidra, summary, imports: 212, Ghidra has 212 parsed imports}, {malcat, summary, imports_count: 366, functions_count: 10, Malcat
… [25153 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 87,
  "family_guess": "Mespinoza ransomware (with potential info-stealing capabilities, based on sample path name and observed malicious behaviors including process termination, file system manipulation, registry modification, and keylogging indicators)",
  "cross_engine_notes": "IDA is unavailable for all analysis due to a missing idasql binary, so all findings are sourced from Ghidra, Malcat, capa, FLOSS, YARA, and pe_imports. Malcat provides static profile metadata and anomaly detection, Ghidra supplies deep function (426) and string (921) analysis, capa and pe_imports confirm multiple malicious ATT&CK techniques, YARA identifies additional behavioral indicators, and FLOSS extracts runtime strings including a PDB path matching the Lync/Skype for Business codebase noted in Malcat's debug info.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "PossiblePackerApiDynamicImport",
      "w
… [6987 more chars]
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
  "rule_count": 13,
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
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Query Registry Value"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Query Registry Value",
          "id": "C0036.006"
        }
      ]
    },
    {
      "name": "create directory",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Create Directory"
          ],
          "objective": "File System",
          "behavior": "Create Directory",
          "method": "",
          "id": "C0046"
        }
      ]
    },
    {
      "name": "move file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "File System",
            "Move File"
          ],
          "objective": "File System",
          "behavior": "Move File",
          "method": "",
          "id": "C0063"
        }
      ]
    },
    {
      "name": "find graphical window",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Application Window Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Application Window Discovery",
          "subtechnique": "",
          "id": "T1010"
        }
      ],
      "mbc": []
    },
    {
      "name": "terminate process",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Terminate Process"
          ],
          "objective": "Process",
          "behavior": "Terminate Process",
          "method": "",
          "id": "C0018"
        }
      ]
    },
    {
      "name": "set registry value",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Operating System",
            "Registry",
            "Set Registry Key"
          ],
          "objective": "Operating System",
          "behavior": "Registry",
          "method": "Set Registry Key",
          "id": "C0036.001"
        }
      ]
    },
    {
      "name": "create thread",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Create Thread"
          ],
          "objective": "Process",
          "behavior": "Create Thread",
          "method": "",
          "id": "C0038"
        }
      ]
    },
    {
      "name": "link function at runtime on Windows",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          
… [1228 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 793965,
  "duration_s": 0.04,
  "import_count": 150,
  "signal_count": 5,
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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 750469,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 64192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a",
          "offset": 43003,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 754050,
          "length": 69,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a1",
          "offset": 753152,
          "length": 105,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a0",
          "offset": 248,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Check_OutputDebugStringA_iat",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c64
… [4563 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1262,
  "strings_sampled": 80,
  "strings": [
    "VirtualAlloc",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.reloc",
    "WAVAWH",
    "UVWAVAWH",
    "t$8X9r",
    "`A_A^_^]",
    "VWATAVAWH",
    "a<t6D8a9r",
    "@A_A^A\\_^",
    "t38X9r",
    "t\t8X9r",
    "UWATAVAWH",
    "fF9$Bu",
    "p<t`@8p9rH",
    "p<t7@8p9r",
    "p<t=@8p9r",
    "A_A^A\\_]",
    "SVWAVAWH",
    "0A_A^_^[",
    "H;\\$0u",
    "D$ D95_K",
    "t\tD95RK",
    "0Hde`n",
    "%U|mBk",
    ">Hve70/",
    "8Kwe70",
    "Q`ZppHW",
    "]bo14j",
    "X26y:3",
    "+By>*Q(",
    "(%# BB",
    "zu/OLby",
    "A KWZA",
    "?s\t=&t}",
    "g\\,tU*",
    "VTCJu:",
    "c\t;bEQ",
    ":2!/h@",
    "m=u9s.",
    ".:>$57",
    "su(t,H",
    "UAVAWH",
    "fA9z*v,A",
    "@A_A^_",
    "x ATAVAWH",
    "A_A^A\\",
    "WATAUAVAWH",
    "Hcl$pE3",
    "A_A^A]A\\_",
    "0A_A^_",
    "UVWATAVH",
    "@A^A\\_^]",
    "UVWATAUAVAWH",
    "@A_A^A]A\\_^]",
    "fD94Bu",
    "fD94Au",
    "D$ D95_",
    "t\tD95R",
    "H!\\$@H",
    "D$8H!\\$0",
    "l$(!\\$ E3",
    "I90t&H",
    "fA9<Au",
    "UATAUAVAWH",
    "A_A^A]A\\]",
    "D$xH+E",
    "@A_A^_^]",
    "K SUVWAVAWH",
    "8A_A^_^][",
    "RSDSCd^",
    "P:\\Target\\x64\\ship\\lync\\x-none\\lync99.pdb",
    "c99.pdb",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "IsolationAware function called after IsolationAwareCleanup",
    "9\tocapires.dll",
    "OcHelperResource.dll"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 5,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1256
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 19.5,
  "size_bytes": 793965,
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
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
  "disassembly": {
    "0x1400084b8": "\u250c 242: entry0 (int64_t arg1);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; var int64_t var_8h @ rbp-0x8\n\u2502           0x1400084b8      e848feffff     call fcn.140008305\n\u2502           0x1400084bd      c8200000       enter 0x20, 0              ; 32\n\u2502           0x1400084c1      4c897c24f8     mov qword [rsp - 8], r15\n\u2502           0x1400084c6      4883ec08       sub rsp, 8\n\u2502           0x1400084ca      4989e7         mov r15, rsp\n\u2502           0x1400084cd      4883ec20       sub rsp, 0x20\n\u2502           0x1400084d1      4883e4f0       and rsp, 0xfffffffffffffff0\n\u2502           0x1400084d5      4831f6         xor rsi, rsi\n\u2502           0x1400084d8      4801c6         add rsi, rax\n\u2502           0x1400084db      4883c03c       add rax, 0x3c              ; 60\n\u2502           0x1400084df      4831d2         xor rdx, rdx\n\u2502           0x1400084e2      8b10           mov edx, dword [rax]\n\u2502           0x1400084e4      4883ec08       sub rsp, 8\n\u2502           0x1400084e8      48893424       mov qword [rsp], rsi\n\u2502           0x1400084ec      488b0424       mov rax, qword [rsp]\n\u2502           0x1400084f0      4883c408       add rsp, 8\n\u2502           0x1400084f4      4801d0         add rax, rdx\n\u2502           0x1400084f7      480588000000   add rax, 0x88              ; 136\n\u2502           0x1400084fd      4883ec08       sub rsp, 8\n\u2502           0x140008501      48890424       mov qword [rsp], rax\n\u2502           0x140008505      488b0c24       mov rcx, qword [rsp]\n\u2502           0x140008509      4883c408       add rsp, 8\n\u2502           0x14000850d      48c7c00000..   mov rax, 0\n\u2502           0x140008514      8b01           mov eax, dword [rcx]\n\u2502           0x140008516      4801f0         add rax, rsi\n\u2502           0x140008519      50             push rax\n\u2502           0x14000851a      488b0c24       mov rcx, qword [rsp]\n\u2502           0x14000851e      4883c408       add rsp, 8\n\u2502           0x140008522      56             push rsi\n\u2502           0x140008523      488b1424       mov rdx, qword [rsp]\n\u2502           0x140008527      4883c408       add rsp, 8\n\u2502           0x14000852b      488d05acf3..   lea rax, [0x1400078de]\n\u2502           0x140008532      4883ec08       sub rsp, 8\n\u2502           0x140008536      48890c24       mov qword [rsp], rcx\n\u2502           0x14000853a      48c7c1619a..   mov rcx, 0xfffffffffffe9a61\n\u2502           0x140008541      4883ec08       sub rsp, 8\n\u2502           0x140008545      48890c24       mov qword [rsp], rcx\n\u2502           0x140008549      48c7c1cb73..   mov rcx, 0x173cb\n\u2502       \u250c\u2500> 0x140008550      48ffc0         inc rax\n\u2502       \u254e   0x140008553      48ffc9         dec rcx\n\u2502       \u254e   0x140008556      4881f9b56c..   cmp rcx, 0x16cb5\n\u2502       \u2514\u2500< 0x14000855d      75f1           jne 0x140008550\n\u2502           0x14000855f      4883c408       add rsp, 8\n\u2502           0x140008563      488b4c24f8     mov rcx, qword [rsp - 8]\n\u2502           0x140008568      488b0c24       mov rcx, qword [rsp]\n\u2502           0x14000856c      4883c408       add rsp, 8\n\u2502           0x140008570      ffd0   
… [3863 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
    "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
    "exists": true,
    "hook_candidates": [
      "ADVAPI32.dll!RegisterTraceGuidsW",
      "ADVAPI32.dll!UnregisterTraceGuids",
      "ADVAPI32.dll!GetTraceLoggerHandle",
      "ADVAPI32.dll!GetTraceEnableLevel",
      "ADVAPI32.dll!GetTraceEnableFlags",
      "KERNEL32.dll!GetCommandLineW",
      "KERNEL32.dll!CloseHandle",
      "KERNEL32.dll!WaitForSingleObject",
      "KERNEL32.dll!CreateMutexW",
      "KERNEL32.dll!ExitProcess",
      "ole32.dll!OleInitialize",
      "ole32.dll!CoUninitialize",
      "ole32.dll!CoInitializeEx",
      "VCRUNTIME140.dll!__std_terminate",
      "VCRUNTIME140.dll!_CxxThrowException",
      "VCRUNTIME140.dll!memmove",
      "VCRUNTIME140.dll!__C_specific_handler",
      "VCRUNTIME140.dll!__CxxFrameHandler3",
      "MSVCP140.dll!?_Xinvalid_argument@std@@YAXPEBD@Z",
      "MSVCP140.dll!?_Xlength_error@std@@YAXPEBD@Z",
      "MSVCP140.dll!?_Xout_of_range@std@@YAXPEBD@Z",
      "MSVCP140.dll!?_Xbad_alloc@std@@YAXXZ",
      "api-ms-win-crt-heap-l1-1-0.dll!calloc",
      "api-ms-win-crt-heap-l1-1-0.dll!_set_new_mode",
      "api-ms-win-crt-heap-l1-1-0.dll!malloc",
      "api-ms-win-crt-heap-l1-1-0.dll!free",
      "api-ms-win-crt-runtime-l1-1-0.dll!_invalid_parameter_noinfo_noreturn",
      "api-ms-win-crt-runtime-l1-1-0.dll!_crt_atexit",
      "api-ms-win-crt-runtime-l1-1-0.dll!_register_onexit_function",
      "api-ms-win-crt-runtime-l1-1-0.dll!_initialize_onexit_table"
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
    "Ghidra imports: IsDebuggerPresent, OutputDebugStringA, GetKeyState, CreateMutexW, CreateThread, OpenProcess",
    "Strings: Lync99GlobalMutex, Lync99WindowServerClass, AppSharingHookController.exe, AppSharingChromeHook.dll",
    "YARA checklist: anti_dbg, keylogger, win_mutex, domain, IP, contains_base64, url, HasDigitalSignature, HasOverlay, HasDe",
    "Checklist: IsPE64, IsWindowsGUI",
    "Strings: Software\\Microsoft\\Office\\16.0\\Common\\FilesPaths, %LOCALAPPDATA%\\Microsoft\\Office\\16.0\\Lync\\Tracing, SOFTWARE\\M"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 70,
  "summary": "PE64 GUI sample masquerading as a Microsoft Lync/Skype for Business component. Strings and imports indicate it creates a global mutex (Lync99GlobalMutex), uses Lync window classes, and references AppSharingHookController/ChromeHook binaries. It imports anti-debug and surveillance capabilities: IsDeb",
  "key_evidence": [
    "Ghidra imports: IsDebuggerPresent, OutputDebugStringA, GetKeyState, CreateMutexW, CreateThread, OpenProcess",
    "Strings: Lync99GlobalMutex, Lync99WindowServerClass, AppSharingHookController.exe, AppSharingChromeHook.dll",
    "YARA checklist: anti_dbg, keylogger, win_mutex, domain, IP, contains_base64, url, HasDigitalSignature, HasOverlay, HasDebugData, HasRichSignature, Check_OutputDebugStringA_iat",
    "Checklist: IsPE64, IsWindowsGUI",
    "Strings: Software\\Microsoft\\Office\\16.0\\Common\\FilesPaths, %LOCALAPPDATA%\\Microsoft\\Office\\16.0\\Lync\\Tracing, SOFTWARE\\Microsoft\\Tracing\\UcClient\\"
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
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
      "
… [7663 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
    "fil
… [146612 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 13,
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
     
… [4328 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 793965,
  "duration_s": 0.04,
  "import_count": 150,
  "signal_count": 5,
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
      
… [433 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 1262,
  "strings_sampled": 80,
  "strings": [
    "VirtualAlloc",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.reloc",
    "WAVAWH",
    "UVWAVAWH",
    "t$8X9r",
    "`A_A^_^]",
    "VWATAVAWH",
    "a<t6D8a9r",
    "@A_A^A\\_^",
    "t38X9r",
    "t\t8X9r",
    "UWATAVAWH",
    "fF9$Bu",
    "p<t`@8p9rH"
… [1651 more chars]
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
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
  "disassembly": {
    "0x1400084b8": "\u250c 242: entry0 (int64_t arg1);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; var int64_t var_8h @ rbp-0x8\n\u2502           0x1400084b8      e848feffff     call f
… [6963 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    J
… [33 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
  "candidates": [
    "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r\n",
… [56 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
    "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
    "exists": true,
    "hook_candidates": [
      "ADVAPI32.dll!RegisterTraceGuidsW",
      "ADVAPI32.dll!UnregisterTraceGuids",
      "ADVAPI32.dll!GetTraceLoggerHa
… [1270 more chars]
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
      "name": "FUN_14000acf0",
      "address": "5368753392",
      "size": "926"
    },
    {
      "name": "FUN_14000326c",
      "address": "5368722028",
      "size": "875"
    },
    {
      "name": "FUN_140002f34",
      "address": "5368721204",
      "size": "824"
    },
    {
      "name": "FUN_140001b7c",
      
… [2355 more chars]
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
  "session_id": "ghidra-pe-ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7",
  "audit_path": "/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/audit.jsonl"
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
      "name": "RegisterTraceGuidsW",
      "module": "ADVAPI32.DLL",
      "address": "1"
    },
    {
      "name": "UnregisterTraceGuids",
      "module": "ADVAPI32.DLL",
      "address": "2"
    },
    {
      "name": "GetTraceLoggerHandle",
      "module": "ADVAPI32.DLL",
      "address": "3"
    },
    {
      "na
… [5001 more chars]
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
      "name": "IsDebuggerPresent",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "OutputDebugStringA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "GetKeyState",
      "module": "USER32.DLL"
    }
  ],
  "row_count": 3,
  "total_row_count": 3,
  "truncated": false,
  "source": "ghidra_query",
  "session_id":
… [193 more chars]
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
      "content": "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">\r\n  <noInherit />\r\n  <assemblyIdentity name=\"Lync99\" 
… [6580 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: near "LIMK": syntax error`

```json
{
  "error": "ghidrasql SQL error: near \"LIMK\": syntax error"
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
      "content": "P:\\Target\\x64\\ship\\lync\\x-none\\lync99.pdb",
      "address": "5368769748",
      "length": "41"
    },
    {
      "content": "Lync",
      "address": "5368772216",
      "length": "10"
    },
    {
      "content": "AppSharingHookController.exe",
      "address": "5368773112",
      "length"
… [5366 more chars]
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
      "name": "CreateMutexW",
      "module": "KERNEL32.DLL",
      "address": "22"
    },
    {
      "name": "CreateThread",
      "module": "KERNEL32.DLL",
      "address": "24"
    },
    {
      "name": "GetKeyState",
      "module": "USER32.DLL",
      "address": "154"
    },
    {
      "name": "IsDebuggerPresen
… [568 more chars]
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
      "name": "entry",
      "address": "5368743096",
      "size": "239"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7",
  "audit_path": "/opt/samples/logs/ba3558c89e9ff2e3
… [63 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7.json"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/deep_dive/01-tools-raw.json` exists=`True` bytes=`188271` mtime=`2026-08-05T04:59:20.361381+00:00`
  - sha256: `19abafecf805c27265e592fe6ab065854d122912b831613de3986257b6c29553`
- **sql_evidence:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/deep_dive/05-deep-dive.json` exists=`True` bytes=`2634` mtime=`2026-08-05T05:00:01.604685+00:00`
  - sha256: `01e7a73316d24a6fb2d48bcb1421ca00c7d899d6480e7dea3e02bc4268f0bb8c`

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
  "verdict": "malicious/unwanted",
  "confidence": 70,
  "summary": "PE64 GUI sample masquerading as a Microsoft Lync/Skype for Business component. Strings and imports indicate it creates a global mutex (Lync99GlobalMutex), uses Lync window classes, and references AppSharingHookController/ChromeHook binaries. It imports anti-debug and surveillance capabilities: IsDebuggerPresent, OutputDebugStringA, GetKeyState, CreateMutexW, CreateThread, and OpenProcess. YARA and checklist findings flag keylogger behavior, anti-debug, domain/IP/URL/base64 indicators, digital signature, overlay, debug data, and rich signature. The combination strongly suggests an info-stealer or surveillance tool with C2/network indicators.",
  "key_evidence": [

… [1834 more chars]
```

- **agentic:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`500314` mtime=`2026-08-05T05:00:01.604685+00:00`
  - sha256: `4d6ebc7e68dbd35882610eb1357e0d10742d6e128af365141d4059d43fa76375`

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

- **rule_yar:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/rule.yar` exists=`True` bytes=`1490` mtime=`2026-08-05T05:00:02.987692+00:00`
  - sha256: `87ef790eea76cec6c01dcc12bd698648e42e313936922f6b6c56974b3916affb`

#### excerpt

```
// yara_gen_v2.py — 2026-08-05T05:00:02.988670+00:00
rule CADRE_v2_unknown_ba3558c89e9f {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = ".?AU?$IServicesNotificationCallback@UIConnectedService@OfficeServicesManager@Mso@@@OfficeServicesManager@Mso@@" ascii wide
        $s1 = "ERROR : Unable to initialize critical section in CAtlBaseModule" ascii wide
        $s2 = "Microsoft® is a registered trademark of Microsoft Corporation." ascii wide
        $s3 = "Windows® is a registered trademark of Microsoft Corporation." ascii wide
        $s4 = "IsolationA
… [686 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/REPORT-MASTER-v2.md` exists=`True` bytes=`28845` mtime=`2026-08-05T05:02:13.005466+00:00`
  - sha256: `506a3a07273e2d4967b76e2d80ab4c10ddbbef03ea3352360328da1e067bb532`
- **REPORT_MASTER_v3:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/REPORT-MASTER-v3.md` exists=`True` bytes=`60203` mtime=`2026-08-05T05:09:04.351097+00:00`
  - sha256: `3420f4f06a31492f81347b2560ad8ac9db3cbcaefcde89a2805b7295daa6acb6`
- **REPORT_v2:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/REPORT-v2.md` exists=`True` bytes=`28845` mtime=`2026-08-05T05:02:13.005466+00:00`
  - sha256: `506a3a07273e2d4967b76e2d80ab4c10ddbbef03ea3352360328da1e067bb532`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`80632` mtime=`2026-08-05T05:04:40.867343+00:00`
  - sha256: `55a71b26c6db8a8c3e8788cb8a8754e75fc77bf2ee4ad21ca71d7dc11e7929ec`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`68741` mtime=`2026-08-05T05:13:43.713794+00:00`
  - sha256: `66204353daf0c78115f3ac98c580a3c1036e0277c6174f39c18ae72f0a7ff08c`
- **report_v2_json:** `/opt/samples/logs/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/report-v2.json` exists=`True` bytes=`59552` mtime=`2026-08-05T05:04:40.873343+00:00`
  - sha256: `e828d1ae91cdccaa8a81c483b45a465c19e0230fd0f2651d2b4b408eb4f3e824`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious/unwanted |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Mespinoza ransomware (with potential info-stealing capabilities, based on sample path name and observed malicious behaviors including process termination, file system manipulation, registry modification, and keylogging indicators)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

#
… [27941 more chars]
```


#### v3_excerpt

```
# RE Report — ba3558c89e9f
_Generated 2026-08-05T05:09:04.343353+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=457c | cross_refs=True | llm_ok=True | runtime=36.58s -->

# Executive Summary

| Core Metric | Value | Evidence Source |
|-------------|-------|-----------------|
| Final Verdict | Malicious | (source: v1_summary, deep_dive_agentic) |
| Malware Family | Mespinoza ransomware (with info-stealing capabilities) | (source: deep_dive_agentic, cross-section:9. Comparison with Known Families) |
| Analysis Confidence | 70 | (source: deep_dive_agentic) |
| Verdict Agreement | Aligned between LLM judge and v1 analysis engine | (source: cross-section:2. Classification) |

The analyzed 64-bit Windows Portable Executable (PE) sample (SHA256: `ba3558c89e9ff2
… [59287 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
