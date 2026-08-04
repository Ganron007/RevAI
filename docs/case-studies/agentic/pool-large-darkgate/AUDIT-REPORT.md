# Pipeline AUDIT-REPORT — `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-04T07:57:48.657465+00:00
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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`9`
- key_evidence_count=`11`

```json
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample metadata; exhibits loader, process injection, and info-stealer capabilities)",
  "cross_engine_notes": "IDA is non-functional due to a missing idasql binary, so all analysis is derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra reports only 1 function, likely due to heavy obfuscation, while Malcat identifies 15 functions and high-signal anomalies not visible in Ghidra's output. All engines confirm consistent indicators of obfuscation (high entropy, XOR loops, Base64 routines, spaghetti code) and malicious capabilities (process injection, payload downloading, crypto usage, anti-VM/anti-debug, keylogging).",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile file summary",
      "row_or_rule": "entropy=157, 26 anomalies including CryptoApiUsage (6), DownloaderApiUsage (18), XorInLoop (424), SpaghettiFunction (77)",
      "why": "Entropy of 157 indicates the sample is packed/obfuscated; the listed anomalies are strong markers of malicious, anti-analysis code, including heavy use of XOR obfuscation and crypto APIs."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), set_thread_context (SetThreadContext)",
      "why": "These process injection APIs map to ATT&CK T1055, a common malware technique for executing malicious code within legitimate processes to evade endpoint detection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "download_file (URLDownloadToFile), http_client (InternetOpen), winhttp_client (WinHttpOpen)",
      "why": "These downloader-related APIs map to ATT&CK T1071.001 and T1105, confirming the sample can fetch additional payloads from remote servers, consistent with loader/dropper behavior."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using Base64, encode data using XOR, encrypt data using AES",
      "why": "These obfuscation rules map to ATT&CK T1027, confirming the sample uses standard encoding/encryption to hide malicious payloads and evade static analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "reference anti-VM strings targeting VMWare, reference anti-VM strings targeting VirtualBox",
      "why": "These sandbox evasion rules map to ATT&CK T1497.001, indicating the sample includes checks to avoid execution in malware analysis sandboxes."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings, Obfuscated_Strings, VMWare_Detection",
      "why": "YARA signatures confirm the sample contains strings associated with dropper functionality, obfuscation, and anti-VM checks, aligning with other malicious indicators."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary metadata",
      "row_or_rule": "file_name: 2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "why": "The sample file name explicitly lists 10 known malware families, indicating the sample is associated with or designed to delive
… [4350 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malware` confidence=`90`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malware",
  "confidence": 90,
  "summary": "PE32 sample with strong indicators of a loader/dropper and process-injection malware. Imports include process-injection APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), downloader/network APIs (URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW), registry modification (RegSetValueExW), process creation (CreateProcessW, ShellExecuteExW), and anti-analysis (IsDebuggerPresent). Capa flags obfuscated stackstrings, Base64 and XOR encoding. PDB path reveals a front executable named 'GameDownload' built from an Android emulator marketplace project (7KMarket), suggesting a game-downloader facade. YARA matches include domain/IP, base64, system tools, antivirus, VMWare detection, dropper strings, and large numeric constants. FLOSS shows 24,408 static strings but no decoded stack/tight strings, consistent with heavy obfuscation. The sample is associated with multiple malware families (DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil) per corpus naming, indicating it is a multi-payload loader or dropper.",
  "key_evidence": [
    "Ghidra imports: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (process injection T1055)",
    "Ghidra imports: URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW (download/network T1105, T1071.001)",
    "Ghidra imports: RegSetValueExW (registry modification T1112)",
    "Ghidra imports: CreateProcessW, ShellExecuteExW (process execution T1106)",
    "Ghidra imports: IsDebuggerPresent (anti-debugging T1622)",
    "Capa rules: obfuscated stackstrings, Base64 encoding, XOR encoding (T1027)",
    "PDB string: E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb (front name GameDownload)",
    "YARA matches: domain, IP, base64, system tools, antivirus, VMWare detection, dropper strings, big numbers",
    "FLOSS: 24408 static strings, 0 decoded/stack/tight strings (heavy obfuscation)",
    "PE import signals: 13 high-signal matches including allocate_memory, write_process_memory, set_thread_context, download_file, http_client, create_process, shell_execute, change_memory_protection"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 28,
  "successful_non_bootstrap_tools": 17,
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

… [57 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Multi-Family Loader/Dropper Disguised as Tencent GameLoop Installer",
  "mark": "# Executive Summary\n\nThis sample is a high-confidence malicious PE32 loader/dropper, scoring 9/10 on the triage verdict (source: triage_verdict). It is disguised as a legitimate Tencent GameLoop installer using an expired code signing certificate (valid 2020-11-25 to 2024-02-22) (source: malcat). The sample exhibits heavy obfuscation (entropy 157, custom XOR/Base64/AES encoding) (source: malcat, capa), process injection capabilities, downloader functionality, keylogging, and extensive anti-analysis features (anti-VM, anti-debug) (source: pe_imports, capa, yara). Corpus metadata links the sample to 10 known malware families (DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil), indicating it is a multi-payload loader or bundled malicious package (source: triage_verdict, deep-dive). All required analysis tools (capa, yara, floss, malcat, pe_imports) returned valid results with no failures (source: triage_verdict tool_gate).\n\n## 1. Sample Identification\n\n| Property | Value |\n|----------|-------|\n| SHA256 | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 |\n| Sample Path | /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil |\n| Project Name | pool |\n| File Type | PE32 X86 executable |\n| Entropy | 157 (indicates packed/obfuscated content) (source: malcat) |\n| Code Signing Certificate | Subject: Tencent, Validity: 2020-11-25 to 2024-02-22 (expired at time of collection) (source: malcat) |\n| Front Disguise | Tencent GameLoop Installer / GameDownload (source: malcat, rule.yara) |\n| PDB Path | E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb (source: rule.yara, deep-dive) |\n| Corpus Metadata | File name explicitly lists 10 associated malware families (source: triage_verdict) |\n\n## 2. Classification\n\n| Field | Value |\n|-------|-------|\n| Verdict | Malicious |\n| Confidence | 90% (source: deep-dive) |\n| Family | Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil) (source: triage_verdict, deep-dive) |\n| Rationale | The sample is not a single-family malware strain, but a loader/dropper designed to deliver multiple payloads. It shares capabilities with all listed families: loader functionality (DarkGate, HijackLoader), process injection (Revil, Remcos), info-stealing/keylogging (Luca Stealer, Njrat), and anti-analysis (Elex, Floxif, Glassworm). The sample path metadata and capability overlap confirm it is a multi-payload delivery tool. (source: triage_verdict, deep-dive, capability assessment) |\n\n## 3. Initial Triage (15 minutes)\n\nInitial triage was completed within 15 minutes of sample ingestion, with a final verdict of Malicious (score 9/10) (source: triage_verdict). Key initial observations:\n- High entropy (157) indicating packed/obfuscated code (source: malcat)\n- Expired Tencent code signing certificate, with a GameLoop installer facade (source: malcat)\n- High-signal malicious API imports: process injection (VirtualAllocEx, WriteProcessMemory, SetThreadContext), downloader (URLDownloadToFile, InternetOpen, Win
… [50839 more chars]
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
| Deep dive | malware |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample metadata; exhibits loader, process injection, and info-stealer capabilities)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Executive Summary

This sample is a high-confidence malicious PE32 loader/dropper, scoring 9/10 on the triage verdict (source: triage_verdict). It is disguised as a legitimate Tencent GameLoop installer using an expired code signing certificate (valid 2020-11-25 to 2024-02-22) (source: malcat). The sample exhibits heavy obfuscation (entropy 157, custom XOR/Base64/AES encoding) (source: malcat, capa), process injection capabilities, downloader functionality, keylogging, and extensive anti-analysis features (anti-VM, anti-debug) (source: pe_imports, capa, yara). Corpus metadata links the sample to 10 known malware families (DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil), indicating it is a multi-payload loader or bundled malicious package (source: triage_verdict, deep-dive). All required analysis tools (capa, yara, floss, malcat, pe_imports) returned valid results with no failures (source: triage_verdict tool_gate).

## 1. Sample Identification

| Property | Value |
|----------|-------|
| SHA256 | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 |
| Sample Path | /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil |
| Project Name | pool |
| File Type | PE32 X86 executable |
| Entropy | 157 (indicates packed/obfuscated content) (source: malca
… [23611 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 7fbde4a47c91
_Generated 2026-08-04T07:56:44.347026+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=458c | cross_refs=True | llm_ok=True | runtime=21.27s -->

# Executive Summary

The analyzed sample (SHA256: `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`) is a 32-bit x86 Windows Portable Executable (PE) classified as **Malicious** with a 90% confidence score, per agentic deep dive assessment (source: deep_dive_agentic). It is identified as a multi-family loader/dropper with documented associations to 10 established malware families: DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, and Revil (source: cross-section:9_comparison_with_known_families). The sample exhibits core capabilities including payload loading, process injection, and information theft, alongside heavy obfuscation, multi-method encryption, and anti-analysis features.

| Metric Category | Value | Source |
|-----------------|-------|--------|
| Verdict Agreement | LLM and v1 analysis aligned | scorecard |
| YARA Rule Matches | 61 total, 10 high-confidence active signatures | yara, cross-section:12_detection_rules |
| capa Capability Matches | 154 total rules, 15 distinct functional capabilities | capa, cross-section:7_capability_assessment |
| Key MalCat Anomalies | 22 high-score large strings, 6 crypto API usage instances, 18 downloader API usage instances, 75 dynamic strings | malcat, cross-section:5_behavioral_analysis |
| Static C2 Indicators | 6 embedded C2-related URLs | ghidra_query, cross-section:6_network_analysis |

Static analysis confirms standard PE structure with 16 imported Windows system DLL function tables, and decompiled code reveals Base64 lookup table implementation and nibble extraction logic for payload decoding (source: cross-section:4_static_analysis). Runtime analysis confirms the sample operates as an obfuscated downloader with embedded staged payloads, with no exclusive single threat actor attribution; it is linked to broad financially motivated cybercrime and ransomware operations (source: cross-section:10_attribution). MITRE ATT&CK mapping covers observed behaviors across 5 core operational categories including data obfuscation, defense evasion, execution, exfiltration, and persistence (source: cross-section:8_mitre_attack_mapping).

---

<!-- section: 1. 
… [66494 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7850` | `91a9fd67cd065a31` |
| `prompt.txt` | `True` | `32314` | `28b7941c910e5fa1` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `26117` | `08621d04e3044aee` |
| `REPORT-MASTER-v3.md` | `True` | `69012` | `e27d825693c56538` |
| `REPORT-v2.md` | `True` | `26117` | `08621d04e3044aee` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `82780` | `b32e42437ea9a665` |
| `rule.yar` | `True` | `1277` | `9445a4bcbf5754a2` |
| `intake-validation.json` | `True` | `3784` | `13963b15f0a6fe4d` |
| `source-decisions.json` | `True` | `2908` | `f8ea7e21bd7edaf3` |
| `malcat-triage.json` | `True` | `1259319` | `7205ab5dd262caa2` |
| `deep_dive/01-tools-raw.json` | `True` | `1483218` | `b787ee1ba43adf70` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3557` | `210dcbf72bc1d58c` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `1472120` | `fdffcf2c6c0d81b5` |

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

- **intake_validation:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-validation.json` exists=`True` bytes=`3784` mtime=`2026-08-04T07:32:09.956214+00:00`
  - sha256: `13963b15f0a6fe4d7fda2a9b6840557d2a144ec44ed507a53a0eed8d20c692d1`
- **malcat_triage:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/malcat-triage.json` exists=`True` bytes=`1259319` mtime=`2026-08-04T07:30:47.948216+00:00`
  - sha256: `7205ab5dd262caa26fbf1f953004fc6f51b63b6378f01c4f437412fcdf32b714`
- **source_decisions:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/source-decisions.json` exists=`True` bytes=`2908` mtime=`2026-08-04T07:32:09.956214+00:00`
  - sha256: `f8ea7e21bd7edaf327b882a5e1eb9a6d89dc4a678223a26dfe5aaa12e2d0237d`
- **ghidra_import_log:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-analyzeHeadless.log` exists=`True` bytes=`9513` mtime=`2026-08-04T07:30:54.251816+00:00`
  - sha256: `e0565a27e0f4f0062a2bec9cfcfcd0c89ff5705e502e5b9556a5ad5a39c71832`
- **ida_bootstrap_log:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable per {warning, ida_validation, \"IDA validation failed: [Errno 2] No such file or directory: '/usr/local/bin/idasql'\"} and has 0 imports per {ida, imports, 0, \"IDA tool summary has empty imports field\"}; Ghidra reports 588 imports per {ghidra, imports, 588, \"Ghidra tool summary lists 588 imports\"}, selected per existing rule {existing_rules, imports, \"ghidra\", \"Existing rule selects Ghidra for imports as IDA has no valid import data\"}."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA is unavailable per {warning, ida_validation, \"IDA validation failed\"} and
… [2131 more chars]
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
… [1258519 more chars]
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
  "duration_s": 181.74,
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
 
… [1317950 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "entropy=157, 26 anomalies including CryptoApiUsage (6), DownloaderApiUsage (18), XorInLoop (424), SpaghettiFunction (77)",
    "allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), set_thread_context (SetThreadContext) signa",
    "download_file (URLDownloadToFile), http_client (InternetOpen), winhttp_client (WinHttpOpen) signals These downloader-rel",
    "encode data using Base64, encode data using XOR, encrypt data using AES top_rules These obfuscation rules map to ATT&CK ",
    "reference anti-VM strings targeting VMWare, reference anti-VM strings targeting VirtualBox top_rules These sandbox evasi"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample metadata; exhibits loader, process injection, and info-stealer capabilities)",
  "score": 9,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile file summary",
      "row_or_rule": "entropy=157, 26 anomalies including CryptoApiUsage (6), DownloaderApiUsage (18), XorInLoop (424), SpaghettiFunction (77)",
      "why": "Entropy of 157 indicates the sample is packed/obfuscated; the listed anomalies are strong markers of malicious, anti-analysis code, including heavy use of XOR obfuscation and crypto APIs."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), set_thread_context (SetThreadContext)",
      "why": "These process injection APIs map to ATT&CK T1055, a common malware technique for executing malicious code within legitimate processes to evade endpoint detection."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "download_file (URLDownloadToFile), http_client (InternetOpen), winhttp_client (WinHttpOpen)",
      "why": "These downloader-related APIs map to ATT&CK T1071.001 and T1105, confirming the sample can fetch additional payloads from remote servers, consistent with loader/dropper behavior."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encode data using Base64, encode data using XOR, encrypt data using AES",
      "why": "These obfuscation rules map to ATT&CK T1027, confirming the sample uses standard encoding/encryption to hide malicious payloads and evade static analysis."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "reference anti-VM strings targeting VMWare, reference anti-VM strings targeting VirtualBox",
      "why": "These sandbox evasion rules map to ATT&CK T1497.001, indicating the sample includes checks to avoid execution in malware analysis sandboxes."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings, Obfuscated_Strings, VMWare_Detection",
      "why": "YARA signatures confirm the sample contains strings associated with dropper functionality, obfuscation, and anti-VM checks, aligning with other malicious indicators."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary metadata",
      "row_or_rule": "file_name: 2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "why": "The sample file name explicitly lists 10 known malware families, indicating the sample is associated with or designed to deliver these threats."
    },
    {
      "source": "malcat",
      "query_or_table": "file_summary metadata",
      "row_or_rule": "Certificate validity: 2020-11-25 to 2024-02-22, VersionInfo: GameLoop Installer by Tencent",
      "why": "The code signing certificate is expired as of the sample collection date (2026-07-03); the sample is disguised as a legitimate Tencent GameLoop installer but contains malicious functionality."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_6b63e0 (Base64 encode), sub_65e730 (Base64 decode)",
      "why": "Decompiled code confirms the presence of Base64 encoding/decoding routines, matching the capa rule for Base64 usage for data obfuscation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent)",
      "why": "This anti-debugging API maps to ATT&CK T1622, used to prevent reverse engineering of the sample by detecting debugger presence."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "log keystrokes via polling",
      "why": "This rule maps to ATT&CK T1056.001, indicating the sample has info-stealing capabilities to capture user keystrokes."
    }
  ],
  "summary": "This is a high-confidence malicious sample: a packed/obfuscated PE file disguised as a Tencent GameLoop installer, with an expired code signing certificate. It exhibits loader/dropper capabilities (downloads additional payloads), process injection (T1055), info-stealing (keylogging via T1056.001), and extensive anti-analysis (obfuscation via Base64/XOR/AES, anti-VM, anti-debug). The sample path me"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/prompt.txt` exists=`True` bytes=`32314` mtime=`2026-08-04T07:35:24.173510+00:00`
  - sha256: `28b7941c910e5fa1713c40b572670c3a7ca8b356009c17b4c6ea136603b8747f`
- **verdict:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/verdict.json` exists=`True` bytes=`7850` mtime=`2026-08-04T07:35:57.917209+00:00`
  - sha256: `91a9fd67cd065a31585a1c5c89b4a1e7bab5a862fc2cd4557f93e4907f32ae36`

#### prompt_excerpt

```
# Triage evidence
sha256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
sample_path: /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil
ghidra_session: ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
ida_session: ida-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA is unavailable per {warning, ida_validation, "IDA validation failed: [Errno 2] No such file or directory: '/usr/local/bin/idasql'"} and has 0 imports per {ida, imports, 0, "IDA tool summary has empty imports field"}; Ghidra reports 588 imports per {ghidra, imports, 588, "Ghidra tool summary lists 588 imports"}, selected per existing rule {existing_rules, imports, "ghidra", "Existing rule selects Ghidra for 
… [31244 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 9,
  "family_guess": "Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample metadata; exhibits loader, process injection, and info-stealer capabilities)",
  "cross_engine_notes": "IDA is non-functional due to a missing idasql binary, so all analysis is derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra reports only 1 function, likely due to heavy obfuscation, while Malcat identifies 15 functions and high-signal anomalies not visible in Ghidra's output. All engines confirm consistent indicators of obfuscation (high entropy, XOR loops, Base64 routines, spaghetti code) and malicious capabilities (process injection, payload downloading, crypto usage, anti-VM/anti-debug, keylogging).",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "static_profile file summary",
      "row_or_rule": "entropy=157, 26 anomal
… [6850 more chars]
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
    
… [9486 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.08,
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
  "duration_s": 181.87,
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
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "Ghidra imports: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (process injection T1055)",
    "Ghidra imports: URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW (download/network T1105, T1071.001)",
    "Ghidra imports: RegSetValueExW (registry modification T1112)",
    "Ghidra imports: CreateProcessW, ShellExecuteExW (process execution T1106)",
    "Ghidra imports: IsDebuggerPresent (anti-debugging T1622)"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "PE32 sample with strong indicators of a loader/dropper and process-injection malware. Imports include process-injection APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), downloader/network APIs (URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW), registry mo",
  "key_evidence": [
    "Ghidra imports: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (process injection T1055)",
    "Ghidra imports: URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW (download/network T1105, T1071.001)",
    "Ghidra imports: RegSetValueExW (registry modification T1112)",
    "Ghidra imports: CreateProcessW, ShellExecuteExW (process execution T1106)",
    "Ghidra imports: IsDebuggerPresent (anti-debugging T1622)",
    "Capa rules: obfuscated stackstrings, Base64 encoding, XOR encoding (T1027)",
    "PDB string: E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb (front name GameDownload)",
    "YARA matches: domain, IP, base64, system tools, antivirus, VMWare detection, dropper strings, big numbers",
    "FLOSS: 24408 static strings, 0 decoded/stack/tight strings (heavy obfuscation)",
    "PE import signals: 13 high-signal matches including allocate_memory, write_process_memory, set_thread_context, download_file, http_client, create_process, shell_execute, change_memory_protection"
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
 
… [1322811 more chars]
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
… [12586 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.08,
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
      "name": "_guard_check_icall",
      "address": "4304560",
      "size": "1"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "audit_path": "/opt/samples/logs/7fbde4a4
… [71 more chars]
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
      "name": "CryptAcquireContextA",
      "module": "ADVAPI32.DLL",
      "address": "463"
    },
    {
      "name": "CryptAcquireContextW",
      "module": "ADVAPI32.DLL",
      "address": "440"
    },
    {
      "name": "CryptCreateHash",
      "module": "ADVAPI32.DLL",
      "address": "460"
    },
    {
      "
… [1403 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "instruction_count",
    "cyclomatic_complexity",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "_guard_check_icall",
      "func_addr": "4304560",
      "size": "1",
      "instruction_count": "0",
      "cyclomatic_complexity": "1",
      "call_out_count": "0",
      "string_ref_count": "0
… [313 more chars]
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
      "content": "GameDownload.exe",
      "address": "8287410",
      "length": "17"
    },
    {
      "content": "VERSION.dll",
      "address": "8291406",
      "length": "12"
    },
    {
      "content": "PSAPI.DLL",
      "address": "8291442",
      "length": "10"
    },
    {
      "content": "WS2_32.dll",
 
… [4786 more chars]
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
      "content": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "address": "8142128",
      "length": "110"
    },
    {
      "content": "GetSystemDirectoryW",
      "address": "8291750",
      "length": "20"
    },
    {
      "conte
… [4998 more chars]
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
      "content": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "address": "8142128",
      "length": "110"
    },
    {
      "content": "GameDownload.exe",
      "address": "8287410",
      "length": "17"
    },
    {
      "content"
… [4959 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
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
      "content": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "address": "8142128",
      "length": "110"
    },
    {
      "content": "GetSystemDirectoryW",
      "address": "8291750",
      "length": "20"
    },
    {
      "conte
… [4998 more chars]
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
      "content": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "address": "8142128",
      "length": "110"
    },
    {
      "content": "GameDownload.exe",
      "address": "8287410",
      "length": "17"
    },
    {
      "content"
… [4959 more chars]
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
      "content": "DeviceIoControl",
      "address": "8292546",
      "length": "16"
    },
    {
      "content": "GetExitCodeProcess",
      "address": "8292686",
      "length": "19"
    },
    {
      "content": "GetCommandLineW",
      "address": "8292934",
      "length": "16"
    },
    {
      "content": "De
… [4350 more chars]
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
      "content": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "address": "8142128",
      "length": "110"
    },
    {
      "content": "GameDownload.exe",
      "address": "8287410",
      "length": "17"
    },
    {
      "content"
… [4959 more chars]
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
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "CreateProcessW",
      "address": "8292204",
      "length": "15"
    },
    {
      "content": "OpenProcess",
      "address": "8292708",
      "length": "12"
    },
    {
      "content": "CreateProcessA",
      "address": "8292770",
      "length": "15"
    },
    {
      "content": "WriteProces
… [960 more chars]
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
      "content": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "address": "8142128",
      "length": "110"
    },
    {
      "content": "GameDownload.exe",
      "address": "8287410",
      "length": "17"
    },
    {
      "content"
… [4967 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.12,
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
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "audit_path": "/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e
… [36 more chars]
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

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/01-tools-raw.json` exists=`True` bytes=`1483218` mtime=`2026-08-04T07:41:40.151201+00:00`
  - sha256: `b787ee1ba43adf70bd77a9d99c9b2a9f9e887328d00d4c9f95a23da5d58403ff`
- **sql_evidence:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/05-deep-dive.json` exists=`True` bytes=`3557` mtime=`2026-08-04T07:46:25.668995+00:00`
  - sha256: `210dcbf72bc1d58cfe72d54a6f110d1367ecda36b4d4872ebd0ae09686020428`

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
  "verdict": "malware",
  "confidence": 90,
  "summary": "PE32 sample with strong indicators of a loader/dropper and process-injection malware. Imports include process-injection APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), downloader/network APIs (URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW), registry modification (RegSetValueExW), process creation (CreateProcessW, ShellExecuteExW), and anti-analysis (IsDebuggerPresent). Capa flags obfuscated stackstrings, Base64 and XOR encoding. PDB path reveals a front executable named 'GameDownload' built from an Android emulator marketplace project (7KMarket), suggesting a game-downloader facade. YARA matches include domain/IP, base64, syst
… [2757 more chars]
```

- **agentic:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`3612860` mtime=`2026-08-04T07:46:25.668095+00:00`
  - sha256: `ed2f4590cf34000adfe989aea927aa58c476cc0611ad2d08356723fe791bef55`

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

- **rule_yar:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/rule.yar` exists=`True` bytes=`1277` mtime=`2026-08-04T07:46:29.824295+00:00`
  - sha256: `9445a4bcbf5754a29a208ea9f8936ec238ab7ddb6d9f9db6162df46806d4094e`

#### excerpt

```
// yara_gen_v2.py — 2026-08-04T07:46:29.824538+00:00
rule CADRE_v2_unknown_7fbde4a47c91 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb" ascii wide
        $s1 = "Copyright © 2020 Tencent. All Rights Reserved." ascii wide
        $s2 = "InitializeCriticalSectionAndSpinCount" ascii wide
        $s3 = "WinHttpGetIEProxyConfigForCurrentUser" ascii wide
        $s4 = "GdipSetImageAttributesColorMatrix" ascii wide
        $s5 = "Syste
… [474 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-MASTER-v2.md` exists=`True` bytes=`26117` mtime=`2026-08-04T07:48:23.418692+00:00`
  - sha256: `08621d04e3044aee8b83837eb31607beb0dd20d9ef1ba75da48731159e8fb834`
- **REPORT_MASTER_v3:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-MASTER-v3.md` exists=`True` bytes=`69012` mtime=`2026-08-04T07:56:44.391981+00:00`
  - sha256: `e27d825693c565386002bceff0e6bad4e5bd6fab42faabe09a16e0a2aa2cd850`
- **REPORT_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-v2.md` exists=`True` bytes=`26117` mtime=`2026-08-04T07:48:23.418692+00:00`
  - sha256: `08621d04e3044aee8b83837eb31607beb0dd20d9ef1ba75da48731159e8fb834`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`93563` mtime=`2026-08-04T07:53:16.422686+00:00`
  - sha256: `a218502398e336450389030e2c3ee88cad40b8140f8df9a2f0f34f11d9781fe6`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`82780` mtime=`2026-08-04T07:57:46.237280+00:00`
  - sha256: `b32e42437ea9a665ad7c5f95bbe1e341606426ca767f8d712a26e8fc3bb45853`
- **report_v2_json:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/report-v2.json` exists=`True` bytes=`54339` mtime=`2026-08-04T07:53:16.428086+00:00`
  - sha256: `089c7ffb81e6d15ed91b77adebfa7741079743b23a556428001956899c2c9363`

#### v2_excerpt

```
# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malware |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample metadata; exhibits loader, process injection, and info-stealer capabilities)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see 
… [25211 more chars]
```


#### v3_excerpt

```
# RE Report — 7fbde4a47c91
_Generated 2026-08-04T07:56:44.347026+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=458c | cross_refs=True | llm_ok=True | runtime=21.27s -->

# Executive Summary

The analyzed sample (SHA256: `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`) is a 32-bit x86 Windows Portable Executable (PE) classified as **Malicious** with a 90% confidence score, per agentic deep dive assessment (source: deep_dive_agentic). It is identified as a multi-family loader/dropper with documented associations to 10 established malware families: DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, and Revil (source: cross-section:9_comparison_with_known_families). The sample exhibits core capabil
… [68094 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
