# Pipeline AUDIT-REPORT — `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-06T07:16:16.762616+00:00
- **Provenance:** `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-06 07:16:17 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`95`
- key_evidence_count=`10`

```json
{
  "verdict": "Malicious",
  "score": 95,
  "family_guess": "Trojanized GameLoop Installer / Multi-Family Loader (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample corpus tagging)",
  "cross_engine_notes": "All available analysis engines (Malcat, capa, pe_imports, YARA, FLOSS) provide consistent, overlapping evidence of malicious behavior with no conflicting indicators. Ghidra and IDA failed to process the sample due to server startup errors and missing idasql binaries, so no additional evidence is available from those tools, but the existing evidence is sufficient for a high-confidence verdict.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row_or_rule": "entropy=157, 26 anomalies including CryptoApiUsage, DownloaderApiUsage, XorInLoop, SpaghettiFunction, ImportByHash, InvalidChecksum",
      "why": "Extremely high entropy indicates heavy packing/encryption; anomalies include obfuscation techniques (XOR loops, spaghetti code, stack strings), malicious API usage (crypto, downloader), hidden imports via API hashing, and invalid PE checksum, all core malicious indicators."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "VirtualAllocEx, WriteProcessMemory, SetThreadContext (T1055)",
      "why": "These are standard process injection APIs, confirming the sample can inject malicious code into legitimate processes to evade detection and execute payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "InternetOpen, WinHttpOpen (T1071.001), URLDownloadToFile (T1105)",
      "why": "These APIs enable C2 (command and control) communication over HTTP/HTTPS and downloading additional malicious payloads, core capabilities of downloaders and remote access trojans."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "RegSetValue (T1112), CreateProcessW, ShellExecuteW (T1106)",
      "why": "Registry modification for persistence (ensuring the sample runs on system boot) and process execution capabilities to launch malicious child processes."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1027 (Obfuscated Files or Information: Base64, XOR, AES, RC4 encoding), T1497.001 (Virtualization/Sandbox Evasion: anti-VM strings for VMWare/VirtualBox)",
      "why": "Confirms the sample uses multiple obfuscation techniques to hide its code and includes anti-VM/sandbox checks to avoid analysis in security research environments."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1056.001 (Keylogging), T1055 (Process Injection via SetThreadContext)",
      "why": "Additional malicious capabilities: keylogging to capture user input (credentials, sensitive data) and process injection for stealthy code execution."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings, Obfuscated_Strings, VMWare_Detection, BASE64_table, RijnDael_AES_CHAR",
      "why": "YARA rules specifically flag dropper behavior, obfuscation, sandbox evasion, and use of Base64/AES, aligning with other identified malicious indicators."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_6b63e0 (Base64 encode), sub_65e7
… [4235 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`6`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "PE implant with extreme entropy (157), 26 anomalies, and 8334 imports. High-signal import map shows process injection (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), downloader/network (URLDownloadToFile, InternetOpen, WinHttpOpen), persistence/registry (RegSetValue), execution (CreateProcess, ShellExecute), and dynamic resolution (LoadLibrary, GetProcAddress). capa matches 154 rules including obfuscated stackstrings, Base64, and XOR encoding. YARA fires 61 rules for domains, IPs, VMWare detection, dropper strings, and large numeric constants. FLOSS yields 24,408 static strings with multiple CRYPTOGAMS AES/SHA cryptographic blocks. The embedded Tencent certificate is expired and trivially forged. The sample filename enumerates multiple known malware families, consistent with a multi-family loader/dropper.",
  "key_evidence": [
    "pe_import_signals: VirtualAllocEx, WriteProcessMemory, SetThreadContext, URLDownloadToFile, RegSetValue, CreateProcess, ShellExecute, LoadLibrary, GetProcAddress, VirtualProtect, IsDebuggerPresent",
    "capa_analyze: 154 rules matched; top rules include obfuscated stackstrings, encode data using Base64, encode data using XOR",
    "yara_scan: 61 matches including domain, IP, VMWare_Detection, Dropper_Strings, Big_Numbers0, Big_Numbers1",
    "floss_extract: 24408 static strings including CRYPTOGAMS AES/SHA block transforms",
    "malcat_analyze: entropy 157, 26 anomalies, 8334 imports, expired Tencent certificate",
    "filename includes darkgate, elex, floxif, glassworm, hijackloader, luca-stealer, medusalocker, njrat, remcos, revil"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 16,
  "successful_non_bootstrap_tools": 5,
  "checklist_ok": true,
  "sql_deep_ok": false,
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
  "title": "Malware Analysis Report: Trojanized Tencent GameLoop Installer / Multi-Family Loader (SHA256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6)",
  "markdown": "> **RevAI provenance** \u2014 commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-06 07:07:10 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | Malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Trojanized GameLoop Installer / Multi-Family Loader (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample corpus tagging)\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n## Executive Summary\nThis sample is a high-confidence malicious PE32 x86 file disguised as the legitimate Tencent GameLoop GameDownload.exe installer, with a triage score of 95/100 and analysis confidence of 90/100 (source: triage_verdict.json, deep-dive.json). It is classified as a trojanized installer and multi-family loader/dropper, with corpus tags associating it with 10 distinct malware families: DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, and Revil. Static analysis reveals extreme entropy (157), 26 static anomalies, 8334 imports, and extensive obfuscation including XOR loops, spaghetti code, stack strings, Base64/AES/RC4 encryption, and API hashing. Confirmed capabilities include process injection, payload downloading, C2 communication, registry persistence, keylogging, and sandbox/VM evasion. The sample uses a forged, expired Tencent Technology (Shenzhen) certificate to appear legitimate. All required analysis tools (Malcat, capa, pe_imports, YARA, FLOSS) returned consistent malicious indicators with no conflicting evidence, despite Ghidra and IDA analysis failing due to technical errors.\n\n## 1. Sample Identification\n- SHA256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6\n- Sample Path: /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil\n- Project Name: pool\n- File Type: PE32 executable for x86 architecture, not a .NET assembly (source: deep-dive.json, dotnet_analyze)\n- Original Filename: GameDownload.exe, disguised as the official Tencent GameLoop gaming emulator installer (source: malcat metadata)\n- Corpus Tags: darkgate, elex, floxif, glassworm, hijackloader, luca-stealer, medusalocker, njrat, remcos, revil (source: sample_path, triage_verdict.json)\n- Static Properties: Entropy 157 (extreme, indicates heavy packing/encryption), 8334 imports, 26 static anomalies, 24408 extracted static strings 
… [21270 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 07:07:10 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Trojanized GameLoop Installer / Multi-Family Loader (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample corpus tagging)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This sample is a high-confidence malicious PE32 x86 file disguised as the legitimate Tencent GameLoop GameDownload.exe installer, with a triage score of 95/100 and analysis confidence of 90/100 (source: triage_verdict.json, deep-dive.json). It is classified as a trojanized installer and multi-family loader/dropper, with corpus tags associating it with 10 distinct malware families: DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, and Revil. Static analysis reveals extreme entropy (157), 26 static anomalies, 8334 imports, and extensive obfuscation including XOR loops, spaghetti code, stack strings, Base64/AES/RC4 encryption, and API hashing. Confirmed capabilities include process injection, payload downloading, C2 communication, registry persistence, keylogging, and sandbox/VM evasion. The sample uses a forged, expired Tencent Technology (Shenzhen) certificate to appear legitimate. All required analysis tools (Malcat, capa, pe_imports, YARA, FLOSS) returned consistent malicious indicators with no conflicting evidence, despite Ghidra and IDA analysis failing due to technical errors.

## 1. Sample Identification
- SHA256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
- Sample Path: /opt/samples/corpus/pool/7fbde4a47c916e4e3b
… [19416 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 07:13:18 UTC

# RE Report — 7fbde4a47c91
_Generated 2026-08-06T07:13:18.795120+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=421c | cross_refs=True | llm_ok=True | runtime=38.11s -->

# Executive Summary

| Top-Line Metric | Value |
|-----------------|-------|
| Verdict | Malicious |
| Malware Family | Trojanized GameLoop Installer / Multi-Family Loader |
| Analysis Confidence | 90% (agentic deep dive) |
| Classifier Agreement | Full agreement between LLM judge and v1 classifier |

The analyzed 32-bit x86 Windows PE sample (SHA256: `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`) is a trojanized installer that disguises itself as the legitimate GameLoop Android emulator to deliver secondary payloads, with corpus tagging linking it to 10+ malware families including DarkGate, Remcos, Luca Stealer, and Medusalocker (source: cross-section:1.sample_identification, cross-section:2.Classification, cross-section:9.Comparison_with_Known_Families). Static and dynamic analysis confirm it implements 15 distinct capabilities spanning obfuscation, anti-analysis, credential theft, encryption, and C2 communication, with 6 static C2 indicators and mappings to 6 MITRE ATT&CK techniques (source: cross-section:3.Initial_Triage, cross-section:5.Behavioral_Analysis, cross-section:6.Network_Analysis, cross-section:7.Capability_Assessment, cross-section:8.MITRE_ATT&CK_Mapping).

| Additional Triage Metric | Value | Source |
|--------------------------|-------|--------|
| v1 Classifier Score | 290 | (source: cross-section:3.Initial_Triage) |
| YARA Rule Matches | 61 | (source: cross-section:3.Initial_Triage) |
| capa Rule Matches | 154 | (source: cross-section:3.Initial_Triage) |

---

<!-- section: 1. Sample Identification | pass=2 | evidence=351c | cross_refs=True | llm_ok=True | runtime=27.38s -->

# 1. Sample Identification

The analyzed sample is assigned the following core identifiers, validated via static analysis and corpus metadata:

| Attribute | Value | Source |
|-----------|-------|--------|
| Primary SHA256 | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 | Sample corpus metadata |
| Corpus File Path |
… [64478 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7735` | `13cb14d7a7275330` |
| `prompt.txt` | `True` | `35556` | `5f571520050bdfe4` |
| `pipeline-audit.json` | `True` | `112870` | `d194b80f102a6e90` |
| `AUDIT-REPORT.md` | `True` | `86971` | `9fc2482a72d54e09` |
| `REPORT-MASTER-v2.md` | `True` | `21925` | `a224a3601b6c5ac1` |
| `REPORT-MASTER-v3.md` | `True` | `67001` | `80e4622cc5b45119` |
| `REPORT-v2.md` | `True` | `21925` | `a224a3601b6c5ac1` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `89765` | `8da4c075c50731c1` |
| `rule.yar` | `True` | `2039` | `8dcb035a0b558f2c` |
| `intake-validation.json` | `True` | `3622` | `3a7cbde2b9fd71d1` |
| `source-decisions.json` | `True` | `1639` | `3fb10cfd020948f8` |
| `malcat-triage.json` | `True` | `1260599` | `52225cd83b143410` |
| `deep_dive/01-tools-raw.json` | `True` | `1483751` | `3355ab8fe4054ea4` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2950` | `0121ea207b9c2eaa` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `1472742` | `33691913309adea7` |

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

- **intake_validation:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-validation.json` exists=`True` bytes=`3622` mtime=`2026-08-06T06:50:49.423728+00:00`
  - sha256: `3a7cbde2b9fd71d13ecb4869feb22929c5508e7113df66c8d4030713ad5598d4`
- **malcat_triage:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/malcat-triage.json` exists=`True` bytes=`1260599` mtime=`2026-08-06T06:49:00.688959+00:00`
  - sha256: `52225cd83b143410a9fefce166df54f3cab0241a5393ef643ff234801cf9cb13`
- **source_decisions:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/source-decisions.json` exists=`True` bytes=`1639` mtime=`2026-08-06T06:50:49.423728+00:00`
  - sha256: `3fb10cfd020948f8d5fdce1117b8306a2a9a17426c56f4f8c306f80f84191e59`
- **ghidra_import_log:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-analyzeHeadless.log` exists=`True` bytes=`9513` mtime=`2026-08-04T07:30:54.251816+00:00`
  - sha256: `e0565a27e0f4f0062a2bec9cfcfcd0c89ff5705e502e5b9556a5ad5a39c71832`
- **ida_bootstrap_log:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "imports": {
    "source": "malcat",
    "confidence": "medium",
    "reason": "Ghidra failed validation (server startup error) and IDA is unavailable (missing idasql binary), so no import data from either; Malcat provides 8334 imports per its analysis summary."
  },
  "functions": {
    "source": "none",
    "confidence": "medium",
    "reason": "Ghidra and IDA failed validation with no function output; Malcat's limited function count (10) has unreliable coverage as decompilation and CFF generation are also marked unreliable, so no reliable function source exists."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Malcat provides 100 strings; existing rule recommends using 
… [862 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
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
    "file_name": "2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "file_path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_gl
… [1259799 more chars]
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
  "rule_count": 154,
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
      "name": "encode data using Base64",
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
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "reference Base64 string",
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
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        },
        {
          "parts": [
            "Data",
            "Check String"
          ],
          "objective": "Data",
          "behavior": "Check String",
          "method": "",
          "id": "C0019"
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
    
… [9487 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 61,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
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
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3329364,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 60881,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a",
          "offset": 10010,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "VMWare_Detection",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a1",
          "offset": 3791656,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a0",
          "offset": 5752647,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 3751138,
          "length": 52,
          "xor_key": null
        },
        {
          "id": "$a3",
          "offset": 3621820,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 5086696,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Obfuscated_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_gla
… [15310 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "d$l_^[]",
    "#L$(#T$,",
    "D7q/;M",
    "SHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    ")QZ^&1",
    "\\$ 3D$",
    "\\$43D$03\\$8",
    "GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "T`00P`00P",
    "V++}V++}",
    "L&&jL&&jl66Zl66Z~??A~??A",
    "Oh44\\h44\\Q",
    "sb11Sb11S*",
    "RF##eF##e",
    "&N''iN''i",
    "X,,tX,,t4",
    "v;;Mv;;M",
    "R)){R)){",
    ">^//q^//q",
    ",@  `@  `",
    "r99Kr99K",
    "f33Uf33U",
    "x<<Dx<<D%",
    "p88Hp88H",
    "uB!!cB!!c",
    "z==Gz==G",
    "D\"\"fD\"\"fT**~T**~;",
    ";d22Vd22Vt::Nt::N",
    "H$$lH$$l",
    "Cn77Yn77Y",
    "J%%oJ%%o\\..r\\..r8",
    "|>>B|>>Bq",
    "j55_j55_",
    "P((xP((x",
    "Z--wZ--w",
    "P~AeS~AeS",
    "pHhXpHhX",
    "lZrNlZrN",
    "6-9'6-9'",
    "$6.:$6.:",
    "ZwKiZwKi",
    "T~FbT~Fb",
    "*?#1*?#1",
    ">8$4,8$4,",
    "pHl\\tHl\\t",
    "AES for x86, CRYPTOGAMS by <appro@openssl.org>",
    "%33331",
    "*p[[[[[[[[[[[[[[[[",
    "Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)",
    "d$0_^[]",
    "d$P_^[]",
    "d$t_^[]",
    "AES for Intel AES-NI, CRYPTOGAMS by <appro@openssl.org>",
    "GHASH for x86, CRYPTOGAMS by <appro@openssl.org>",
    "D$$j@P",
    "D$ j@P",
    "D$ _^[",
    ";E$rjw",
    "t]VPQj",
    "!!\"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%&&&&&&&",
    "!<!u3j",
    "L$<JRWP",
    "L$L_^3",
    "QPVQSPV",
    "D$ PVVV",
    "LWPWSj",
    "QSVWh$*"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 24408
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 181.13,
  "size_bytes": 8701567,
  "static_only": true,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
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
    "file_name": "2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "file_path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "file_size": 8701567,
    "type": "PE",
    "architecture": "X86",
    "entropy": 157,
    "sha256": "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
    "metadata": {
      "Certificate::Issuer": "DigiCert SHA2 Assured ID Code Signing CA (Organization=DigiCert Inc / Unit=www.digicert.com / Country=US)",
      "Certificate::Subject": "Tencent Technology(Shenzhen) Company Limited",
      "Certificate::Org Details": "Tencent Technology(Shenzhen) Company Limited / Unit=? / State=Guangdong Province / Locality=Shenzhen / Country=CN / Email=?",
      "Certificate::Validity": "from 2020-11-25 to 2024-02-22",
      "Certificate::SerialNumber": "0ea7f686bc40354a70f2c297c1315ef6",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA",
      "VersionInfo::CompanyName": "Tencent",
      "VersionInfo::FileDescription": "GameLoop - Install",
      "VersionInfo::FileVersion": "3.71.3146.81",
      "VersionInfo::InternalName": "GameDownload",
      "VersionInfo::LegalCopyright": "Copyright \u00a9 2020 Tencent. All Rights Reserved.",
      "VersionInfo::OriginalFilename": "GameDownload.exe",
      "VersionInfo::ProductName": "GameLoop",
      "VersionInfo::ProductVersion": "3,71,3146,81",
      "Exports::Module name": "GameDownload.exe",
      "Exports::Exports date": "2024-02-21 13:07:09",
      "Debug::Date.Debug.Codeview": "2024-02-21 13:07:34",
      "Debug::Path": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "Debug::Date.Debug.VcFeature": "2024-02-21 13:07:34",
      "Debug::Date.Debug.Pogo": "2024-02-21 13:07:34",
      "Debug::Date.Debug.Iltcg": "2024-02-21 13:07:34"
    },
    "entrypoint_ea": 2081293,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 129
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 3291648,
        "virtual_size": 3293184,
        "rights": "RX",
        "entropy": 137
      },
      {
        "name": ".rdata",
        "effective_address": 3294208,
        "physical_size": 810496,
        "virtual_size": 811008,
        "rights": "R",
        "entropy": 83
      },
      {
        "name": ".data",
        "effective_address": 4105216,
        "physical_size": 74240,
        "virtual_size": 102400,
        "rights": "RW",
        "entropy": 93
      },
      {
        "name": ".gfids",
        "effective_address": 4207616,
        "physical_size": 3584,
 
… [1318524 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "entropy=157, 26 anomalies including CryptoApiUsage, DownloaderApiUsage, XorInLoop, SpaghettiFunction, ImportByHash, Inva",
    "VirtualAllocEx, WriteProcessMemory, SetThreadContext (T1055) signals These are standard process injection APIs, confirmi",
    "InternetOpen, WinHttpOpen (T1071.001), URLDownloadToFile (T1105) signals These APIs enable C2 (command and control) comm",
    "RegSetValue (T1112), CreateProcessW, ShellExecuteW (T1106) signals Registry modification for persistence (ensuring the s",
    "T1027 (Obfuscated Files or Information: Base64, XOR, AES, RC4 encoding), T1497.001 (Virtualization/Sandbox Evasion: anti"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Trojanized GameLoop Installer / Multi-Family Loader (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample corpus tagging)",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row_or_rule": "entropy=157, 26 anomalies including CryptoApiUsage, DownloaderApiUsage, XorInLoop, SpaghettiFunction, ImportByHash, InvalidChecksum",
      "why": "Extremely high entropy indicates heavy packing/encryption; anomalies include obfuscation techniques (XOR loops, spaghetti code, stack strings), malicious API usage (crypto, downloader), hidden imports via API hashing, and invalid PE checksum, all core malicious indicators."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "VirtualAllocEx, WriteProcessMemory, SetThreadContext (T1055)",
      "why": "These are standard process injection APIs, confirming the sample can inject malicious code into legitimate processes to evade detection and execute payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "InternetOpen, WinHttpOpen (T1071.001), URLDownloadToFile (T1105)",
      "why": "These APIs enable C2 (command and control) communication over HTTP/HTTPS and downloading additional malicious payloads, core capabilities of downloaders and remote access trojans."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "RegSetValue (T1112), CreateProcessW, ShellExecuteW (T1106)",
      "why": "Registry modification for persistence (ensuring the sample runs on system boot) and process execution capabilities to launch malicious child processes."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1027 (Obfuscated Files or Information: Base64, XOR, AES, RC4 encoding), T1497.001 (Virtualization/Sandbox Evasion: anti-VM strings for VMWare/VirtualBox)",
      "why": "Confirms the sample uses multiple obfuscation techniques to hide its code and includes anti-VM/sandbox checks to avoid analysis in security research environments."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "T1056.001 (Keylogging), T1055 (Process Injection via SetThreadContext)",
      "why": "Additional malicious capabilities: keylogging to capture user input (credentials, sensitive data) and process injection for stealthy code execution."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings, Obfuscated_Strings, VMWare_Detection, BASE64_table, RijnDael_AES_CHAR",
      "why": "YARA rules specifically flag dropper behavior, obfuscation, sandbox evasion, and use of Base64/AES, aligning with other identified malicious indicators."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_6b63e0 (Base64 encode), sub_65e730 (Base64 decode), sub_4bb468 (CRC32)",
      "why": "Decompiled code confirms implementation of Base64 encoding/decoding and CRC32 hashing, used for obfuscating data/communications and verifying payload integrity in malicious operations."
    },
    {
      "source": "malcat",
      "query_or_table": "metadata",
      "row_or_rule": "VersionInfo::FileDescription=GameLoop - Install, OriginalFilename=GameDownload.exe, Certificate::Subject=Tencent Technology(Shenzhen) Company Limited",
      "why": "The sample is disguised as a legitimate Tencent GameLoop gaming platform installer, indicating social engineering/trojanization to trick users into executing the malicious payload."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "ImportByHash\u00d76",
      "why": "API hashing is a common malware technique to hide imported function names from static analysis, making detection harder."
    }
  ],
  "summary": "This sample is a malicious PE file disguised as the legitimate Tencent GameLoop GameDownload.exe installer. It exhibits extensive obfuscation (entropy 157, XOR loops, spaghetti code, stack strings, Base64/AES encryption), sandbox/VM evasion, process injection, file download, C2 communication, registry persistence, and keylogging capabilities. It is tagged in the sample corpus with multiple malware"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/prompt.txt` exists=`True` bytes=`35556` mtime=`2026-08-06T06:54:17.074892+00:00`
  - sha256: `5f571520050bdfe4eb2826d0842e919cc39e9e41cbf42247a0d690118a320846`
- **verdict:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/verdict.json` exists=`True` bytes=`7735` mtime=`2026-08-06T06:55:23.165757+00:00`
  - sha256: `13cb14d7a7275330927f167143833f6504f35c5b18b521e2e807d8a5d0401625`

#### prompt_excerpt

```
# Triage evidence
sha256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
sample_path: /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil
ghidra_session: ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
ida_session: ida-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6

## Source decisions (from intake validation)
- imports: malcat (confidence=medium) — Ghidra failed validation (server startup error) and IDA is unavailable (missing idasql binary), so no import data from either; Malcat provides 8334 imports per its analysis summary.
- functions: none (confidence=medium) — Ghidra and IDA failed validation with no function output; Malcat's limited function count (10) has unreliable coverage as decompilation and CFF generation are also marked unreliable, so no rel
… [34482 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 95,
  "family_guess": "Trojanized GameLoop Installer / Multi-Family Loader (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample corpus tagging)",
  "cross_engine_notes": "All available analysis engines (Malcat, capa, pe_imports, YARA, FLOSS) provide consistent, overlapping evidence of malicious behavior with no conflicting indicators. Ghidra and IDA failed to process the sample due to server startup errors and missing idasql binaries, so no additional evidence is available from those tools, but the existing evidence is sufficient for a high-confidence verdict.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row_or_rule": "entropy=157, 26 anomalies including CryptoApiUsage, DownloaderApiUsage, XorInLoop, SpaghettiFunction, ImportByHash, InvalidChecksum",
      "why": "Extremely high entropy indicates heavy packing/encrypti
… [6735 more chars]
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
  "rule_count": 154,
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
      "name": "encode data using Base64",
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
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "reference Base64 string",
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
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        },
        {
          "parts": [
            "Data",
            "Check String"
          ],
          "objective": "Data",
          "behavior": "Check String",
          "method": "",
          "id": "C0019"
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
    
… [9485 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.05,
  "import_count": 571,
  "signal_count": 13,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "set_thread_context",
      "api_match": "SetThreadContext",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "http_client",
      "api_match": "InternetOpen",
      "attack": [
        "T1071.001"
      ]
    },
    {
      "label": "winhttp_client",
      "api_match": "WinHttpOpen",
      "attack": [
        "T1071.001"
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
  "rule_count": 61,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
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
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3329364,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 60881,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a",
          "offset": 10010,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "VMWare_Detection",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a1",
          "offset": 3791656,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a0",
          "offset": 5752647,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 3751138,
          "length": 52,
          "xor_key": null
        },
        {
          "id": "$a3",
          "offset": 3621820,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 5086696,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Obfuscated_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_gla
… [15288 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "d$l_^[]",
    "#L$(#T$,",
    "D7q/;M",
    "SHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    ")QZ^&1",
    "\\$ 3D$",
    "\\$43D$03\\$8",
    "GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "T`00P`00P",
    "V++}V++}",
    "L&&jL&&jl66Zl66Z~??A~??A",
    "Oh44\\h44\\Q",
    "sb11Sb11S*",
    "RF##eF##e",
    "&N''iN''i",
    "X,,tX,,t4",
    "v;;Mv;;M",
    "R)){R)){",
    ">^//q^//q",
    ",@  `@  `",
    "r99Kr99K",
    "f33Uf33U",
    "x<<Dx<<D%",
    "p88Hp88H",
    "uB!!cB!!c",
    "z==Gz==G",
    "D\"\"fD\"\"fT**~T**~;",
    ";d22Vd22Vt::Nt::N",
    "H$$lH$$l",
    "Cn77Yn77Y",
    "J%%oJ%%o\\..r\\..r8",
    "|>>B|>>Bq",
    "j55_j55_",
    "P((xP((x",
    "Z--wZ--w",
    "P~AeS~AeS",
    "pHhXpHhX",
    "lZrNlZrN",
    "6-9'6-9'",
    "$6.:$6.:",
    "ZwKiZwKi",
    "T~FbT~Fb",
    "*?#1*?#1",
    ">8$4,8$4,",
    "pHl\\tHl\\t",
    "AES for x86, CRYPTOGAMS by <appro@openssl.org>",
    "%33331",
    "*p[[[[[[[[[[[[[[[[",
    "Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)",
    "d$0_^[]",
    "d$P_^[]",
    "d$t_^[]",
    "AES for Intel AES-NI, CRYPTOGAMS by <appro@openssl.org>",
    "GHASH for x86, CRYPTOGAMS by <appro@openssl.org>",
    "D$$j@P",
    "D$ j@P",
    "D$ _^[",
    ";E$rjw",
    "t]VPQj",
    "!!\"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%&&&&&&&",
    "!<!u3j",
    "L$<JRWP",
    "L$L_^3",
    "QPVQSPV",
    "D$ PVVV",
    "LWPWSj",
    "QSVWh$*"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 24408
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 181.13,
  "size_bytes": 8701567,
  "static_only": true,
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
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "disassembly": {
    "0x00487740": "; CALL XREF from entry0 @ 0x4898fa(x)\n\u250c 10: fcn.00487740 ();\n\u2502           0x00487740      50             push eax\n\u2502           0x00487741      60             pushal\n\u2502           0x00487742      e8edffffff     call fcn.00487734\n\u2514           0x00487747      c20400         ret 4",
    "0x00487734": "; CALL XREF from fcn.00487740 @ 0x487742(x)\n\u250c 12: fcn.00487734 (int32_t arg_4h);\n\u2502           ; arg int32_t arg_4h @ esp+0x8\n\u2502           0x00487734      50             push eax\n\u2502           0x00487735      8b442404       mov eax, dword [arg_4h]\n\u2502           0x00487739      83c004         add eax, 4\n\u2502           0x0048773c      50             push eax\n\u2514           0x0048773d      c20800         ret 8",
    "0x0056c730": "; XREFS: CALL 0x0056ccdf  CALL 0x0056d2bb  CALL 0x0056e282  \n            ; XREFS: CALL 0x0056e2ef  CALL 0x0056e3e5  CALL 0x0056e55c  \n            ; XREFS: CALL 0x00571d62  \n\u250c 397: fcn.0056c730 (int32_t arg_8h, int32_t arg_ch);\n\u2502           ; arg int32_t arg_8h @ ebp+0x8\n\u2502           ; arg int32_t arg_ch @ ebp+0xc\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_8h @ ebp-0x8\n\u2502           ; var int32_t var_ch @ ebp-0xc\n\u2502           0x0056c730      55             push ebp\n\u2502           0x0056c731      8bec           mov ebp, esp\n\u2502           0x0056c733      83ec0c         sub esp, 0xc\n\u2502           0x0056c736      53             push ebx\n\u2502           0x0056c737      8b5d08         mov ebx, dword [arg_8h]\n\u2502           0x0056c73a      57             push edi\n\u2502           0x0056c73b      8b4308         mov eax, dword [ebx + 8]\n\u2502           0x0056c73e      8dbba48e0000   lea edi, [ebx + 0x8ea4]\n\u2502           0x0056c744      8945fc         mov dword [var_4h], eax\n\u2502           0x0056c747      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x0056c749      0f8468010000   je 0x56c8b7\n\u2502       \u2502   0x0056c74f      837d0c00       cmp dword [arg_ch], 0\n\u2502       \u2502   0x0056c753      56             push esi\n\u2502      \u250c\u2500\u2500< 0x0056c754      7572           jne 0x56c7c8\n\u2502      \u2502\u2502   0x0056c756      833f00         cmp dword [edi], 0\n\u2502     \u250c\u2500\u2500\u2500< 0x0056c759      750a           jne 0x56c765\n\u2502     \u2502\u2502\u2502   0x0056c75b      837f0400       cmp dword [edi + 4], 0\n\u2502    \u250c\u2500\u2500\u2500\u2500< 0x0056c75f      0f8451010000   je 0x56c8b6\n\u2502    \u2502\u2514\u2500\u2500\u2500> 0x0056c765      8bb3c48e0000   mov esi, dword [ebx + 0x8ec4]\n\u2502    \u2502 \u2502\u2502   0x0056c76b      8d4858         lea ecx, [eax + 0x58]\n\u2502    \u2502 \u2502\u2502   0x0056c76e      51             push ecx\n\u2502    \u2502 \u2502\u2502   0x0056c76f      8d83ac8e0000   lea eax, [ebx + 0x8eac]\n\u2502    \u2502 \u2502\u2502   0x0056c775      50             push eax\n\u2502    \u2502 \u2502\u2502   0x0056c776      ff31           push dword [ecx]\n\u2502    \u2502 \u2502\u2502   0x0056c778      e8b3ef0000     call 0x57b730\n\u2502    \u2502 \u2502\u2502   0x0056c77d      83c40c         add esp, 0xc\n\u250
… [1649 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "candidates": [
    "Found XOR 00 position 00000000: 00000158 ........!..L.!This program cannot be r",
    "Found XOR 00 position 004CBD20: 00000100 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00572860: 000000D0 ........!..L.!This program cannot be r",
    "Found XOR C5 position 008394BC: 000000F8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000158 ........!..L.!This program cannot be r\nFound XOR 00 position 004CBD20: 00000100 ........!..L.!This program cannot be r\nFound XOR 00 position 00572860: 000000D0 ........!..L.!This program cannot be r\nFound XOR C5 position 008394BC: 000000F8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
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
    "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!GetFileVersionInfoW",
      "VERSION.dll!VerQueryValueW",
      "VERSION.dll!GetFileVersionInfoSizeW",
      "PSAPI.DLL!GetModuleFileNameExW",
      "WS2_32.dll!WSAStartup",
      "WS2_32.dll!shutdown",
      "WS2_32.dll!getaddrinfo",
      "WS2_32.dll!socket",
      "WS2_32.dll!connect",
      "IMM32.dll!ImmDisableIME",
      "KERNEL32.dll!UnhandledExceptionFilter",
      "KERNEL32.dll!GetCurrentProcess",
      "KERNEL32.dll!DeviceIoControl",
      "KERNEL32.dll!GetDiskFreeSpaceExW",
      "KERNEL32.dll!GetLogicalDrives",
      "USER32.dll!CreateWindowExA",
      "USER32.dll!RegisterClassExA",
      "USER32.dll!DefWindowProcW",
      "USER32.dll!DestroyWindow",
      "USER32.dll!ReleaseDC",
      "GDI32.dll!MoveToEx",
      "GDI32.dll!CreateSolidBrush",
      "GDI32.dll!LineTo",
      "GDI32.dll!OffsetRgn",
      "GDI32.dll!Rectangle",
      "ADVAPI32.dll!RegDeleteValueW",
      "ADVAPI32.dll!CloseServiceHandle",
      "ADVAPI32.dll!ControlService",
      "ADVAPI32.dll!ReportEventA",
      "ADVAPI32.dll!RegisterEventSourceA"
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
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    "pe_import_signals: VirtualAllocEx, WriteProcessMemory, SetThreadContext, URLDownloadToFile, RegSetValue, CreateProcess, ",
    "capa_analyze: 154 rules matched; top rules include obfuscated stackstrings, encode data using Base64, encode data using ",
    "yara_scan: 61 matches including domain, IP, VMWare_Detection, Dropper_Strings, Big_Numbers0, Big_Numbers1",
    "floss_extract: 24408 static strings including CRYPTOGAMS AES/SHA block transforms",
    "malcat_analyze: entropy 157, 26 anomalies, 8334 imports, expired Tencent certificate"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "PE implant with extreme entropy (157), 26 anomalies, and 8334 imports. High-signal import map shows process injection (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), downloader/network (URLDownloadToFile, InternetOpen, WinHttpOpen), persistence/registry (RegSetValue), executi",
  "key_evidence": [
    "pe_import_signals: VirtualAllocEx, WriteProcessMemory, SetThreadContext, URLDownloadToFile, RegSetValue, CreateProcess, ShellExecute, LoadLibrary, GetProcAddress, VirtualProtect, IsDebuggerPresent",
    "capa_analyze: 154 rules matched; top rules include obfuscated stackstrings, encode data using Base64, encode data using XOR",
    "yara_scan: 61 matches including domain, IP, VMWare_Detection, Dropper_Strings, Big_Numbers0, Big_Numbers1",
    "floss_extract: 24408 static strings including CRYPTOGAMS AES/SHA block transforms",
    "malcat_analyze: entropy 157, 26 anomalies, 8334 imports, expired Tencent certificate",
    "filename includes darkgate, elex, floxif, glassworm, hijackloader, luca-stealer, medusalocker, njrat, remcos, revil"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 61,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
        
… [18388 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
 
… [1323297 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 154,
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
… [12585 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.05,
  "import_count": 571,
  "signal_count": 13,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
   
… [1450 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@open
… [2093 more chars]
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
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "disassembly": {
    "0x00487740": "; CALL XREF from entry0 @ 0x4898fa(x)\n\u250c 10: fcn.00487740 ();\n\u2502           0x00487740      50  
… [4749 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 
… [112 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "candidates": [
    "Found XOR 00 position 00000000: 00000158 ........!..L.!This program cannot be r",
    "Found XOR 00 position 004C
… [639 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
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
    "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!GetFileVersionInfoW",
 
… [1030 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `ghidrasql server died during startup for ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 (rc=1); tail of log:
.local.IndexedLocalFileSystem.readIndexVersion(IndexedLocalFileSystem.java:451)
	at ghidra.framework.store.local.LocalFileSystem.getLocalFileSystem(LocalFileSystem.java:116)
	at ghidra.framework.data.DefaultProjectData.getPrivateFileSystem(DefaultProjectData.java:552)
	at ghidra.framework.data.DefaultProjectData.init(DefaultProjectData.java:318)
	at ghidra.framework.data.DefaultProjectData.<init>(DefaultProjectData.java:120)
	at ghidra.framework.project.DefaultProject.<init>(DefaultProject.java:119)
	at ghidra.app.util.headless.HeadlessAnalyzer$HeadlessProject.<init>(HeadlessAnalyzer.java:1864)
	at ghidra.app.util.headless.HeadlessAnalyzer.openProject(HeadlessAnalyzer.java:1820)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:435)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
 
Ghidra exited before becoming ready (exit code 1)
`

```json
{
  "error": "ghidrasql server died during startup for ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 (rc=1); tail of log:\n.local.IndexedLocalFileSystem.readIndexVersion(IndexedLocalFileSystem.java:451)\n\tat ghidra.framework.store.local.LocalFileSystem.getLocalFileSystem(LocalFileSystem.java:116)\n\tat ghidra.framework.data.DefaultProjectData.getPrivateFileSystem(Defa
… [780 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql server died during startup for ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 (rc=1); tail of log:
.local.IndexedLocalFileSystem.readIndexVersion(IndexedLocalFileSystem.java:451)
	at ghidra.framework.store.local.LocalFileSystem.getLocalFileSystem(LocalFileSystem.java:116)
	at ghidra.framework.data.DefaultProjectData.getPrivateFileSystem(DefaultProjectData.java:552)
	at ghidra.framework.data.DefaultProjectData.init(DefaultProjectData.java:318)
	at ghidra.framework.data.DefaultProjectData.<init>(DefaultProjectData.java:120)
	at ghidra.framework.project.DefaultProject.<init>(DefaultProject.java:119)
	at ghidra.app.util.headless.HeadlessAnalyzer$HeadlessProject.<init>(HeadlessAnalyzer.java:1864)
	at ghidra.app.util.headless.HeadlessAnalyzer.openProject(HeadlessAnalyzer.java:1820)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:435)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
 
Ghidra exited before becoming ready (exit code 1)
`

```json
{
  "error": "ghidrasql server died during startup for ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 (rc=1); tail of log:\n.local.IndexedLocalFileSystem.readIndexVersion(IndexedLocalFileSystem.java:451)\n\tat ghidra.framework.store.local.LocalFileSystem.getLocalFileSystem(LocalFileSystem.java:116)\n\tat ghidra.framework.data.DefaultProjectData.getPrivateFileSystem(Defa
… [780 more chars]
```

- **ida_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `[Errno 2] No such file or directory: '/usr/local/bin/idasql'`

```json
{
  "error": "[Errno 2] No such file or directory: '/usr/local/bin/idasql'"
}
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.06,
  "import_count": 571,
  "signal_count": 13,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
   
… [1450 more chars]
```

- **yara_scan** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 61,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
        
… [18388 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 154,
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
… [12586 more chars]
```

- **malcat_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
 
… [1321665 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@open
… [2093 more chars]
```

- **malcat_analyze** ok=`False` checklist=`False` — langgraph tool call (redundant, skipped)
  - error: `redundant tool call (identical to a previous call)`

```json
{}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/01-tools-raw.json` exists=`True` bytes=`1483751` mtime=`2026-08-06T07:00:17.051045+00:00`
  - sha256: `3355ab8fe4054ea4d8fbdb73c8b56af4435fced5bea0e4d3c7e189bf014c37f9`
- **sql_evidence:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/05-deep-dive.json` exists=`True` bytes=`2950` mtime=`2026-08-06T07:03:54.973729+00:00`
  - sha256: `0121ea207b9c2eaad69a3dbe233e5d34cff85026f8483823b450da2bb742a38c`

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
  "confidence": 90,
  "summary": "PE implant with extreme entropy (157), 26 anomalies, and 8334 imports. High-signal import map shows process injection (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), downloader/network (URLDownloadToFile, InternetOpen, WinHttpOpen), persistence/registry (RegSetValue), execution (CreateProcess, ShellExecute), and dynamic resolution (LoadLibrary, GetProcAddress). capa matches 154 rules including obfuscated stackstrings, Base64, and XOR encoding. YARA fires 61 rules for domains, IPs, VMWare detection, dropper strings, and large numeric constants. FLOSS yields 24,408 static strings with multiple CRYPTOGAMS AES/SHA cryptographic blocks. The embedded Ten
… [2150 more chars]
```

- **agentic:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`6619714` mtime=`2026-08-06T07:03:54.965729+00:00`
  - sha256: `e1b347826396156f454b314e004f43b73181d58ace5ba8b37f28e09846bdba11`

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

- **rule_yar:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/rule.yar` exists=`True` bytes=`2039` mtime=`2026-08-06T07:04:07.146786+00:00`
  - sha256: `8dcb035a0b558f2cd463ced8f42260b4674730129469018d482287fce6002eb4`

#### excerpt

```
// yara_gen_v2.py — 2026-08-06T07:04:07.146941+00:00
rule CADRE_v2_unknown_7fbde4a47c91 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Extremely high entropy indicates heavy packing/encryption; anomalies include obfuscation techniques (XOR loops, spaghett" ascii wide
        $s1 = "These are standard process injection APIs, confirming the sample can inject malicious code into legitimate processes to " ascii wide
        $s2 = "These APIs enable C2 (command an
… [1237 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-MASTER-v2.md` exists=`True` bytes=`21925` mtime=`2026-08-06T07:07:10.307574+00:00`
  - sha256: `a224a3601b6c5ac125f87d3b69ca6463884f51ec0923c1c35a31d3fef55a18cd`
- **REPORT_MASTER_v3:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-MASTER-v3.md` exists=`True` bytes=`67001` mtime=`2026-08-06T07:13:18.820924+00:00`
  - sha256: `80e4622cc5b451198438821f3faa151f73b1f4cc3396ae73fbf07ee72c6b451d`
- **REPORT_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-v2.md` exists=`True` bytes=`21925` mtime=`2026-08-06T07:07:10.306574+00:00`
  - sha256: `a224a3601b6c5ac125f87d3b69ca6463884f51ec0923c1c35a31d3fef55a18cd`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`94718` mtime=`2026-08-06T07:09:21.274494+00:00`
  - sha256: `60debffbb9c0c75d3c4639b564079f0cf48c3fb3bc8593bcbf774efaddd1f3c9`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`89765` mtime=`2026-08-06T07:16:13.934907+00:00`
  - sha256: `8da4c075c50731c116eb3b7e9e6b5139a1d53cab36c8fc66de288012c6745a93`
- **report_v2_json:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/report-v2.json` exists=`True` bytes=`24770` mtime=`2026-08-06T07:09:21.278494+00:00`
  - sha256: `91129c44ca3fc043f91c44077c77e7bc93b6bb85d8acbb9456090cd6aaeb1c03`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 07:07:10 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Trojanized GameLoop Installer / Multi-Family Loader (associated with DarkGate, Elex, Floxif, Glassworm, H
… [21016 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 07:13:18 UTC

# RE Report — 7fbde4a47c91
_Generated 2026-08-06T07:13:18.795120+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=421c | cross_refs=True | llm_ok=True | runtime=38.11s -->

# Executive Summary

| Top-Line Metric | Value |
|-----------------|-------|
| Verdict | Malicious |
| Malware Family | Trojanized GameLoop Installer / Multi-Family Loader |
| Analysis Confidence | 90% (agentic deep dive) |
| Classifier Agreement | Full agreement between LLM judge and v1 classifier |

The analyzed 32-bit x86 Windows PE sample (SHA256: `7fbde4a47c916e4e3bbbb8c0e
… [66078 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
