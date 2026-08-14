# Pipeline AUDIT-REPORT — `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T07:06:57.150755+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 07:06:57 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e`

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

- source=`llm_judge` verdict=`malicious` confidence=`95`
- key_evidence_count=`10`

```json
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "trojan.blocker/bckn (botnet trojan)",
  "cross_engine_notes": "Ghidra and IDA confirm 225 functions and consistent crypto/HTTP imports. Malcat highlights persistence via registry run key and crypto anomalies. Capa maps to multiple ATT&CK techniques including persistence and encryption. YARA rules indicate network and downloader behaviors. External VT shows 57 malicious detections.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Microso..rrentVersion\\Run",
      "why": "Indicates persistence by setting a registry run key, a common autostart mechanism for malware."
    },
    {
      "source": "capa",
      "query_or_table": "All rules",
      "row_or_rule": "persist via Run registry key",
      "why": "Confirms capability for persistence via registry run keys, mapped to ATT&CK T1547.001."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "HTTP/1.1",
      "why": "Suggests HTTP protocol usage for communication, indicative of C2 activity."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "module: WININET, name: InternetOpenA",
      "why": "API for establishing internet connections, enabling C2 beaconing or data exfiltration."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "crypto_encrypt with CryptEncrypt",
      "why": "Encryption API used for data protection, obfuscation, or potential ransomware behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations",
      "row_or_rule": "sub_140002c50",
      "why": "Decompilation shows crypto operations with hardcoded key 'YnJiYm90' for config file encryption/decryption, suggesting C2 configuration handling."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "DownloadUsingWininet",
      "why": "Rule matching indicates download functionality via WinINet, a common technique for malware payload retrieval.",
      "source_corrected_from": "yara"
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "CryptoApiUsage",
      "why": "Multiple crypto API usages detected, supporting encryption capabilities for evasion or data manipulation."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using RC4 via WinAPI",
      "why": "Specific encryption method using RC4, often employed in malware for data obfuscation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "check_debugger with IsDebuggerPresent",
      "why": "Anti-debugging check to evade analysis, a defense evasion technique."
    }
  ],
  "summary": "The sample brbbot.exe is malicious trojan exhibiting persistence via registry run keys, HTTP-based C2 communication, data encryption with hardcoded keys, and anti-debugging behaviors. Evidence is consistent across multiple analysis engines and supported by external threat intelligence with 57 VirusTotal detections.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 17 matches",
      "capa: 35 rules"
    ]
  },
  "tool_gate": {
 
… [3644 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`13`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is the 'brbbot' backdoor/RAT. It establishes persistence via the Windows Run registry key using the name 'brbbot', encrypts/decrypts its configuration file (brbconfig.tmp) using RC4 via the Windows Crypto API with a base64-encoded key 'YnJiYm90' (= 'brbbot'), communicates with a C2 server over HTTP/1.1 using a spoofed IE8 user-agent, and supports remote command execution via CreateProcessA. The binary includes anti-debug checks via ZwQuerySystemInformation and XOR-based data encoding. CAPA identified 35 capability matches covering encryption, persistence, network, and process injection techniques. YARA rules flagged anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, and WinCrypt usage. Exfiltration was not observed based on CAPA's capability matches and YARA rule outputs {CAPA, capability matches, 'encryption, persistence, network, process injection', 'no exfiltration techniques listed'} {YARA, rules, 'anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, WinCrypt usage', 'no exfiltration indicators'}. Credential access was not observed based on the same sources {CAPA, capability matches, 'encryption, persistence, network, process injection', 'no credential access techniques listed'} {YARA, rules, 'anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, WinCrypt usage', 'no credential access indicators'}.",
  "key_evidence": [
    "Ghidra string_refs: FUN_140002230 and FUN_140002550 reference 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' with registry value name 'brbbot' \u2014 classic persistence mechanism",
    "Ghidra string_refs: FUN_140002230 references 'APPDATA' and 'brbconfig.tmp' \u2014 config file stored in user AppData",
    "Ghidra string_refs: FUN_140002940 and FUN_140002c50 reference 'Microsoft Enhanced Cryptographic Provider v1.0' and base64-encoded key 'YnJiYm90' (= 'brbbot') for RC4 encryption of config",
    "Ghidra imports: Full CryptoAPI chain \u2014 CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptDecrypt, CryptDestroyKey, CryptDestroyHash, CryptReleaseContext",
    "Ghidra imports: RegSetValueExA, RegOpenKeyExA, RegDeleteValueA, RegFlushKey, RegCloseKey \u2014 registry manipulation for persistence",
    "Ghidra imports: CreateProcessA, CreateFileA/W, CopyFileA, DeleteFileA, FindResourceA, GetModuleFileNameA \u2014 dropper/file operations and remote command execution",
    "Ghidra string_refs: FUN_140003030 references 'HTTP/1.1' and 'Connection: close\\r\\n' \u2014 C2 HTTP communication",
    "Ghidra string_refs: FUN_140002f50 references 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)' \u2014 spoofed user-agent for C2",
    "Ghidra string_refs: FUN_140003300 references 'ZwQuerySystemInformation' and 'ntdll.dll' \u2014 anti-analysis/process enumeration",
    "Ghidra string_refs: FUN_1400012e0 references 'encode' and 'sleep' \u2014 data encoding and C2 sleep/beacon loop",
    "CAPA: 35 rules matched including 'encode data using XOR' (T1027), 'encrypt or decrypt via WinCrypt' (T1027), 'encrypt data using RC4 via WinAPI' (C0027.009), 'create new key via CryptAcquireContext'",
    "YARA: 17 rules matched including anti_dbg, network_http, screenshot, win_registry, win_files_operation, Dropper_Strings, Advapi_Hash_API, contains_base64",
    "Gh
… [1497 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: brbbot.exe (SHA256: f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 06:49:50 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Malware Analysis Report: brbbot.exe\n\n## Executive Summary\n\nThe sample `brbbot.exe` (SHA256: `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e`) is a malicious backdoor/RAT identified as the 'brbbot' botnet trojan. The binary is a 64-bit Windows PE executable with a high-confidence malicious verdict (95/100) supported by 57 VirusTotal detections and consistent evidence across multiple analysis engines. The malware establishes persistence via the Windows Run registry key using the name 'brbbot', encrypts/decrypts its configuration file (`brbconfig.tmp`) using RC4 via the Windows Crypto API with a hardcoded base64-encoded key `YnJiYm90` (which decodes to 'brbbot'), and communicates with a command-and-control (C2) server over HTTP/1.1 using a spoofed Internet Explorer 8 user-agent string. The binary supports remote command execution via `CreateProcessA` and includes anti-debugging checks via `ZwQuerySystemInformation` and XOR-based data encoding. CAPA identified 35 capability matches covering encryption, persistence, network, and process injection techniques. YARA rules flagged anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, and WinCrypt usage. The sample is not packed (UPX probe failed) and is not a .NET assembly. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events; all findings are based on static analysis. The primary risk is unauthorized remote access and control of infected systems, with potential for data exfiltration and lateral movement, though exfiltration and credential access techniques were not directly observed in the static analysis.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e` |\n| **File Name** | `brbbot.exe` |\n| **File Path** | `/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe` |\n| **File Type** | PE (Portable Executable), 64-bit (x86-64) |\n| **Architecture** | x86-64 (source: MalCat, file type analysis) |\n| **Entropy** | 5.92 bits/byte (source: MalCat, whole-file Shannon entropy) |\n| **Import Hash (imphash)** | `475b069fec5e5868caeb7d4d89236c89` (source: rule.yara.json) |\n| **Packed** | No (UPX probe failed; `upx_ok: false`, `is_packed: false`) (source: UPX unpack evidence) |\n| **.NET Assembly** | No (source: .NET analysis evidence) |\n| **Project** | malware |\n\nThe sample is a native x86-64 Windows executable. The entropy of 5.92 bits/byte is within the normal range for compiled code and does not indicate packing or heavy obfuscation. The imphash `475b069fec5e5868caeb7d4d89236c89` can be used for clustering related samples. The file was not packed with UPX, as the UPX probe returned `Tested 0
… [29119 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 06:49:50 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: brbbot.exe

## Executive Summary

The sample `brbbot.exe` (SHA256: `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e`) is a malicious backdoor/RAT identified as the 'brbbot' botnet trojan. The binary is a 64-bit Windows PE executable with a high-confidence malicious verdict (95/100) supported by 57 VirusTotal detections and consistent evidence across multiple analysis engines. The malware establishes persistence via the Windows Run registry key using the name 'brbbot', encrypts/decrypts its configuration file (`brbconfig.tmp`) using RC4 via the Windows Crypto API with a hardcoded base64-encoded key `YnJiYm90` (which decodes to 'brbbot'), and communicates with a command-and-control (C2) server over HTTP/1.1 using a spoofed Internet Explorer 8 user-agent string. The binary supports remote command execution via `CreateProcessA` and includes anti-debugging checks via `ZwQuerySystemInformation` and XOR-based data encoding. CAPA identified 35 capability matches covering encryption, persistence, network, and process injection techniques. YARA rules flagged anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, and WinCrypt usage. The sample is not packed (UPX probe failed) and is not a .NET assembly. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events; all findings are based on static analysis. The primary risk is unauthorized remote access and control of infected systems, with potential for data exfiltration and lateral movement, though exfiltration and credential access techniques were not directly observed in the static analysis.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e` |
| **File Name** | `brbbot.exe` |
| **File Path** | `/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe` |
| **File Type** | PE (Portable 
… [27013 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 07:03:02 UTC

# RE Report — f47060d0f7de
_Generated 2026-08-13T07:03:02.393736+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=262c | cross_refs=True | llm_ok=True | runtime=49.98s -->

# Executive Summary

**Verdict:** Malicious  
**Family:** trojan.blocker/bckn (botnet trojan)  
**Confidence:** High (90%)  

This sample is assessed as a malicious botnet trojan with high confidence, based on extensive static analysis indicators and agreement between multiple analysis engines. Dynamic analysis tools were executed but recorded no significant malicious runtime events, which may indicate evasion techniques or environmental dependencies.

| Key Aspect | Assessment | Evidence Source |
|------------|------------|----------------|
| Verdict | Malicious | v1_summary reports a score of 290 with 17 YARA matches and 35 capa rules (source: v1_summary); deep_dive_agentic confirms 90% confidence (source: deep_dive_agentic). |
| Family | trojan.blocker/bckn | Likely derived from static code patterns and behavioral signatures typical of botnets that block system functions and facilitate C2 communications (source: malcat, query: family_detection, row: trojan.blocker/bckn). |
| Static Capabilities | Encryption, persistence, network APIs | Capa rules indicate T1027 for obfuscation and T1547.001 for persistence (source: capa, rule: T1027, etc.), consistent with malware behavior. |
| Dynamic Analysis | Tools ran, no significant events | Speakeasy and Frida probes were executed, but no notable malicious activities were recorded during sandbox execution (source: cross-section:behavioral_analysis). |
| Network Indicators | HTTP-based C2 communication | Static analysis suggests network APIs and HTTP capabilities, common in botnet trojans for command-and-control (source: cross-section:network_analysis). |

The sample exhibits common malware tactics, such as registry manipulation for persistence and cryptographic APIs for obfuscation, aligning with the trojan.blocker/bckn family's characteristics. While dynamic analysis did not capture runtime behavior, the static evidence strongly supports the malicious classification.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=233
… [41489 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `7144` | `82795985b5885d95` |
| `prompt.txt` | `True` | `36145` | `44b99431b05c14c0` |
| `pipeline-audit.json` | `True` | `116715` | `bc4e5a6a6bc8afe3` |
| `AUDIT-REPORT.md` | `True` | `85214` | `a75c9f5217e88e46` |
| `REPORT-MASTER-v2.md` | `True` | `29520` | `a14be51b8d6ff4b4` |
| `REPORT-MASTER-v3.md` | `True` | `44015` | `30d3ecaf6d450450` |
| `REPORT-v2.md` | `True` | `29520` | `a14be51b8d6ff4b4` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `64120` | `d74f7e9e8ca16e04` |
| `rule.yar` | `True` | `1167` | `3b7a31cb56817b53` |
| `intake-validation.json` | `True` | `2410` | `00464a32ab780987` |
| `source-decisions.json` | `True` | `1500` | `4c295cab3c24bc3d` |
| `malcat-triage.json` | `True` | `59225` | `a11a8daa2a2746c0` |
| `deep_dive/01-tools-raw.json` | `True` | `137219` | `7baea149a7a2e54a` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4997` | `8cf13ad767d446c8` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `132539` | `df5a9d8c731750cb` |

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

- **intake_validation:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/intake-validation.json` exists=`True` bytes=`2410` mtime=`2026-08-12T16:39:18.950248+00:00`
  - sha256: `00464a32ab7809872986413c2d25a46a28e40cf4b0cb74e5cee50488083b4a8c`
- **malcat_triage:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/malcat-triage.json` exists=`True` bytes=`59225` mtime=`2026-08-13T01:47:23.501883+00:00`
  - sha256: `a11a8daa2a2746c09f8283a9d9fef4f627e513494cf32d8b1f9b1d7f5b70a4fa`
- **source_decisions:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/source-decisions.json` exists=`True` bytes=`1500` mtime=`2026-08-12T16:39:18.950248+00:00`
  - sha256: `4c295cab3c24bc3dae933376f8e3c0a26e4a3e08332e00ffc897719c2a77cc86`
- **ghidra_import_log:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/intake-analyzeHeadless.log` exists=`True` bytes=`7773` mtime=`2026-08-12T16:38:23.980757+00:00`
  - sha256: `8abcc4adbf64b2ebf17fd601588e639b1ffe0191cf2430ef7a9a9dc57b2acd00`
- **ida_bootstrap_log:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/intake-idasql.log` exists=`True` bytes=`213` mtime=`2026-08-12T16:38:27.638895+00:00`
  - sha256: `cc291d858861c4fca1f49fbc97705e72d392b3710e793a33a2c2c2171d0a5e00`

#### source_decisions_excerpt

```
{
  "sha256": "f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra (115) and IDA (115) agree on import counts, indicating reliability, while Malcat (276) diverges, suggesting potential counting differences or errors."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra (225) and IDA (225) show consistent function counts, whereas Malcat (10) has a low count, likely due to different analysis depth or methodology."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Using both Ghidra (210) and IDA (226) ensures comprehensive string coverage, as all sources (including Malcat at 100) show varying counts, reducing omiss
… [723 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
    "file_name": "brbbot.exe",
    "file_path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
    "file_size": 75776,
    "type": "PE",
    "architecture": "X64",
    "entropy": 5.92,
    "sha256": "f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e",
    "metadata": {},
    "entrypoint_ea": 13204,
    "layout": [
      {
        "name": "header",
        "effective_add
… [58425 more chars]
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
  "rule_count": 35,
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
      "name": "encrypt or decrypt via WinCrypt",
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
            "Decrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Decrypt Data",
          "method": "",
          "id": "C0031"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "",
          "id": "C0027"
        }
      ]
    },
    {
      "name": "encrypt data using RC4 via WinAPI",
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
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        }
      ]
    },
    {
      "name": "create new key via CryptAcquireContext",
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
            "Encryption Key"
          ],
          "objective": "Cryptography",
          "behavior": "Encryption Key",
          "method": "",
          "id": 
… [5936 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4117,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 59035,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 63816,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 63730,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 63802,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 63650,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 208,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 13204,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 64588,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 64758,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "network_http",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 64018,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 63922,
          "length": 
… [7506 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 310,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "WATAUH",
    "USVATH",
    "xA\\^[]",
    "UVATAVAWH",
    "\\$ D9d$x",
    "0A_A^A\\^]",
    "\\$ UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "UVWATAUAVAWH",
    "|$ H9=",
    "@SATAUH",
    "@A]A\\[",
    "\\$ UVATAUAWH",
    "D9&t3H",
    "A_A]A\\^]",
    "L$ USWH",
    "D8D$0u9D",
    "D9D$`t",
    "D$<D9D$`t",
    "D)\\$4A;",
    "t$\\D9D$`t",
    "t$\\D8D$@t",
    "D8D$0u",
    "t$4D8D$8t",
    "|$ UATAUAVAWH",
    "A_A^A]A\\]",
    "D$DD9T$\\",
    "t$hD+d$DD+",
    "9D$Pti",
    "UVWATAUH",
    "D$&8\\$&t-8X",
    "@A]A\\_^]",
    "WATAUAVAWH",
    "@A_A^A]A\\_",
    "t$ WATAUH",
    "A_A^A]A\\_",
    "fD9#tSH",
    "CfD9#u",
    "fD91u:A",
    "Hct$PH",
    "shHcD$XH",
    "ATAUAVH",
    "fD9t$b",
    "A^A]A\\",
    "fffffff",
    "D8\"u%H",
    "VWATAUAVH",
    "A^A]A\\_^",
    "!|$DHc",
    "|$DD9d$X",
    "f;D$@ug",
    "f;D$@uD",
    "H!\\$ H",
    "HcD$HH;",
    "H!|$ L",
    "L$ UVWH",
    "@UATAUAVAWH",
    "!t$(H!t$ A",
    "0A_A^A]A\\_",
    "LcA<E3",
    "@SUVWATAUAVH",
    "PA^A]A\\_^][",
    "USVWATAUAVAWH",
    "XA_A^A]A\\_^[]",
    "ATAUAWH",
    "0A_A]A\\",
    "(null)",
    "`h````",
    "xpxxxx",
    "HH:mm:ss",
    "dddd, MMMM dd, yyyy",
    "MM/dd/yy",
    "December",
    "November"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 310
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 11.63,
  "size_bytes": 75776,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
    "file_name": "brbbot.exe",
    "file_path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
    "file_size": 75776,
    "type": "PE",
    "architecture": "X64",
    "entropy": 5.92,
    "sha256": "f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e",
    "metadata": {},
    "entrypoint_ea": 13204,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 49
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 50176,
        "virtual_size": 53248,
        "rights": "RX",
        "entropy": 136
      },
      {
        "name": ".rdata",
        "effective_address": 54272,
        "physical_size": 14848,
        "virtual_size": 16384,
        "rights": "R",
        "entropy": 73
      },
      {
        "name": ".data",
        "effective_address": 70656,
        "physical_size": 5120,
        "virtual_size": 16384,
        "rights": "RW",
        "entropy": 77
      },
      {
        "name": ".pdata",
        "effective_address": 87040,
        "physical_size": 3072,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 32
      },
      {
        "name": ".rsrc",
        "effective_address": 91136,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 5
      },
      {
        "name": ".reloc",
        "effective_address": 95232,
        "physical_size": 1024,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 18
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 114,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "CryptoApiUsage",
        "desc": "Crypto-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 12
      },
      {
        "name": "DownloaderApiUsage",
        "desc": "Downloader-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 2
      },
      {
        "name": "HighXrefLoopingFunction",
        "desc": "Function contains a loop and has a lot of incoming references (string decryption candidate)",
        "category": "code",
        "level": 1,
        "num_hits": 1
      },
      {
        "name": "ManyUniqueImmediateBytes",
        "desc": "More than 48 unique bytes defined across all immediate operands in the function",
        "category": "code",
        "level": 3,
        "num_hits": 2
      },
      {
        "name": "NoChecksum",
        "desc": "PE Header checksum is not set",
        "category": "integrity",
        "level": 1,
        "num_hits": 1
      },
      {
        "name": "SpaghettiFunction",
        "desc": "Function with lots of intra jumps, could be obfuscated",
        "category": "code",
        "level": 1,
        "num_hits": 8
      },
      {
        "name": "XorInLoop",
        "desc": "XOR instruction in a loop",
        "category": "code",
        "level
… [86138 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 10,
  "hits": 10,
  "misses": [],
  "hit_examples": [
    "Software\\Microso..rrentVersion\\Run Strings/registry Indicates persistence by setting a registry run key, a common autost",
    "persist via Run registry key All rules Confirms capability for persistence via registry run keys, mapped to ATT&CK T1547",
    "HTTP/1.1 Suspicious strings (Ghidra) Suggests HTTP protocol usage for communication, indicative of C2 activity. ghidra  ",
    "module: WININET, name: InternetOpenA Imports (IDA) API for establishing internet connections, enabling C2 beaconing or d",
    "crypto_encrypt with CryptEncrypt pe_imports Encryption API used for data protection, obfuscation, or potential ransomwar"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "trojan.blocker/bckn (botnet trojan)",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Microso..rrentVersion\\Run",
      "why": "Indicates persistence by setting a registry run key, a common autostart mechanism for malware."
    },
    {
      "source": "capa",
      "query_or_table": "All rules",
      "row_or_rule": "persist via Run registry key",
      "why": "Confirms capability for persistence via registry run keys, mapped to ATT&CK T1547.001."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "HTTP/1.1",
      "why": "Suggests HTTP protocol usage for communication, indicative of C2 activity."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "module: WININET, name: InternetOpenA",
      "why": "API for establishing internet connections, enabling C2 beaconing or data exfiltration."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "crypto_encrypt with CryptEncrypt",
      "why": "Encryption API used for data protection, obfuscation, or potential ransomware behavior."
    },
    {
      "source": "malcat",
      "query_or_table": "Decompilations",
      "row_or_rule": "sub_140002c50",
      "why": "Decompilation shows crypto operations with hardcoded key 'YnJiYm90' for config file encryption/decryption, suggesting C2 configuration handling."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "DownloadUsingWininet",
      "why": "Rule matching indicates download functionality via WinINet, a common technique for malware payload retrieval.",
      "source_corrected_from": "yara"
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "CryptoApiUsage",
      "why": "Multiple crypto API usages detected, supporting encryption capabilities for evasion or data manipulation."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using RC4 via WinAPI",
      "why": "Specific encryption method using RC4, often employed in malware for data obfuscation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "check_debugger with IsDebuggerPresent",
      "why": "Anti-debugging check to evade analysis, a defense evasion technique."
    }
  ],
  "summary": "The sample brbbot.exe is malicious trojan exhibiting persistence via registry run keys, HTTP-based C2 communication, data encryption with hardcoded keys, and anti-debugging behaviors. Evidence is consistent across multiple analysis engines and supported by external threat intelligence with 57 VirusTotal detections."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/prompt.txt` exists=`True` bytes=`36145` mtime=`2026-08-12T16:39:43.978760+00:00`
  - sha256: `44b99431b05c14c026362949fa2b725f894d591cbb1f599cc399025267cd5c64`
- **verdict:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/verdict.json` exists=`True` bytes=`7144` mtime=`2026-08-12T16:41:50.247325+00:00`
  - sha256: `82795985b5885d952b36dca4112747db4564022d22f90a6b00af5c0b55ef0924`

#### prompt_excerpt

```
# Triage evidence
sha256: f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e
sample_path: /opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe
ghidra_session: ghidra-pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e
ida_session: ida-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra (115) and IDA (115) agree on import counts, indicating reliability, while Malcat (276) diverges, suggesting potential counting differences or errors.
- functions: ghidra (confidence=medium) — Ghidra (225) and IDA (225) show consistent function counts, whereas Malcat (10) has a low count, likely due to different analysis depth or methodology.
- strings: both (confidence=high) — Using both Ghidra (210) and IDA (226) ensures comprehensive string coverage, as all sources (including Malcat at 100) show varying counts, reducin
… [35080 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "trojan.blocker/bckn (botnet trojan)",
  "cross_engine_notes": "Ghidra and IDA confirm 225 functions and consistent crypto/HTTP imports. Malcat highlights persistence via registry run key and crypto anomalies. Capa maps to multiple ATT&CK techniques including persistence and encryption. YARA rules indicate network and downloader behaviors. External VT shows 57 malicious detections.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Microso..rrentVersion\\Run",
      "why": "Indicates persistence by setting a registry run key, a common autostart mechanism for malware."
    },
    {
      "source": "capa",
      "query_or_table": "All rules",
      "row_or_rule": "persist via Run registry key",
      "why": "Confirms capability for persistence via registry run keys, mapped to ATT&CK T1547.001."
    },
    {
      "source": "ghidra",
      "query_or_t
… [6144 more chars]
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
  "rule_count": 35,
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
      "name": "encrypt or decrypt via WinCrypt",
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
            "Decrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Decrypt Data",
          "method": "",
          "id": "C0031"
        },
        {
          "parts": [
            "Cryptography",
            "Encrypt Data"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "",
          "id": "C0027"
        }
      ]
    },
    {
      "name": "encrypt data using RC4 via WinAPI",
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
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        }
      ]
    },
    {
      "name": "create new key via CryptAcquireContext",
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
            "Encryption Key"
          ],
          "objective": "Cryptography",
          "behavior": "Encryption Key",
          "method": "",
          "id": 
… [5935 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 75776,
  "duration_s": 0.04,
  "import_count": 115,
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
      "label": "crypto_encrypt",
      "api_match": "CryptEncrypt",
      "attack": [
        "T1573"
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
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4117,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 59035,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 63816,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 63730,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 63802,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 63650,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 208,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 13204,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 64588,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 64758,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "network_http",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 64018,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 63922,
          "length": 
… [7484 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 310,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "WATAUH",
    "USVATH",
    "xA\\^[]",
    "UVATAVAWH",
    "\\$ D9d$x",
    "0A_A^A\\^]",
    "\\$ UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "UVWATAUAVAWH",
    "|$ H9=",
    "@SATAUH",
    "@A]A\\[",
    "\\$ UVATAUAWH",
    "D9&t3H",
    "A_A]A\\^]",
    "L$ USWH",
    "D8D$0u9D",
    "D9D$`t",
    "D$<D9D$`t",
    "D)\\$4A;",
    "t$\\D9D$`t",
    "t$\\D8D$@t",
    "D8D$0u",
    "t$4D8D$8t",
    "|$ UATAUAVAWH",
    "A_A^A]A\\]",
    "D$DD9T$\\",
    "t$hD+d$DD+",
    "9D$Pti",
    "UVWATAUH",
    "D$&8\\$&t-8X",
    "@A]A\\_^]",
    "WATAUAVAWH",
    "@A_A^A]A\\_",
    "t$ WATAUH",
    "A_A^A]A\\_",
    "fD9#tSH",
    "CfD9#u",
    "fD91u:A",
    "Hct$PH",
    "shHcD$XH",
    "ATAUAVH",
    "fD9t$b",
    "A^A]A\\",
    "fffffff",
    "D8\"u%H",
    "VWATAUAVH",
    "A^A]A\\_^",
    "!|$DHc",
    "|$DD9d$X",
    "f;D$@ug",
    "f;D$@uD",
    "H!\\$ H",
    "HcD$HH;",
    "H!|$ L",
    "L$ UVWH",
    "@UATAUAVAWH",
    "!t$(H!t$ A",
    "0A_A^A]A\\_",
    "LcA<E3",
    "@SUVWATAUAVH",
    "PA^A]A\\_^][",
    "USVWATAUAVAWH",
    "XA_A^A]A\\_^[]",
    "ATAUAWH",
    "0A_A]A\\",
    "(null)",
    "`h````",
    "xpxxxx",
    "HH:mm:ss",
    "dddd, MMMM dd, yyyy",
    "MM/dd/yy",
    "December",
    "November"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 310
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 10.6,
  "size_bytes": 75776,
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
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
  "disassembly": {
    "0x140003f94": "\u250c 401: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_30h @ rsp+0x30\n\u2502       \u254e   ; var int64_t var_6ch @ rsp+0x6c\n\u2502       \u254e   ; var int64_t var_70h @ rsp+0x70\n\u2502       \u254e   ; var int64_t var_b0h @ rsp+0xb0\n\u2502       \u254e   ; var int64_t var_10h @ rsp+0xb8\n\u2502       \u254e   0x140003f94      4883ec28       sub rsp, 0x28\n\u2502       \u254e   0x140003f98      e8f7490000     call 0x140008994\n\u2502       \u254e   0x140003f9d      4883c428       add rsp, 0x28\n\u2502       \u2514\u2500< 0x140003fa1      e952feffff     jmp 0x140003df8\n.."
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x140003f94"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
    "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
    "exists": true,
    "hook_candidates": [
      "ADVAPI32.dll!RegSetValueExA",
      "ADVAPI32.dll!RegOpenKeyExA",
      "ADVAPI32.dll!RegDeleteValueA",
      "ADVAPI32.dll!RegFlushKey",
      "ADVAPI32.dll!RegCloseKey",
      "WININET.dll!HttpSendRequestA",
      "WININET.dll!InternetQueryDataAvailable",
      "WININET.dll!InternetReadFile",
      "WININET.dll!InternetCloseHandle",
      "WININET.dll!HttpQueryInfoA",
      "WS2_32.dll!gethostbyname",
      "WS2_32.dll!WSACleanup",
      "WS2_32.dll!WSAStartup",
      "WS2_32.dll!inet_ntoa",
      "WS2_32.dll!gethostname",
      "KERNEL32.dll!CreateFileW",
      "KERNEL32.dll!HeapSize",
      "KERNEL32.dll!WriteConsoleW",
      "KERNEL32.dll!SetStdHandle",
      "KERNEL32.dll!LoadLibraryW",
      "USER32.dll!GetDC"
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
  "checked": 13,
  "hits": 13,
  "misses": [],
  "hit_examples": [
    "Ghidra string_refs: FUN_140002230 and FUN_140002550 reference 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' with regis",
    "Ghidra string_refs: FUN_140002230 references 'APPDATA' and 'brbconfig.tmp' \u2014 config file stored in user AppData",
    "Ghidra string_refs: FUN_140002940 and FUN_140002c50 reference 'Microsoft Enhanced Cryptographic Provider v1.0' and base6",
    "Ghidra imports: Full CryptoAPI chain \u2014 CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncryp",
    "Ghidra imports: RegSetValueExA, RegOpenKeyExA, RegDeleteValueA, RegFlushKey, RegCloseKey \u2014 registry manipulation for per"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is the 'brbbot' backdoor/RAT. It establishes persistence via the Windows Run registry key using the name 'brbbot', encrypts/decrypts its configuration file (brbconfig.tmp) using RC4 via the Windows Crypto API with a base64-encoded key 'YnJiYm90' (= 'brbbot'), communicates with a C2 server over ",
  "key_evidence": [
    "Ghidra string_refs: FUN_140002230 and FUN_140002550 reference 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' with registry value name 'brbbot' \u2014 classic persistence mechanism",
    "Ghidra string_refs: FUN_140002230 references 'APPDATA' and 'brbconfig.tmp' \u2014 config file stored in user AppData",
    "Ghidra string_refs: FUN_140002940 and FUN_140002c50 reference 'Microsoft Enhanced Cryptographic Provider v1.0' and base64-encoded key 'YnJiYm90' (= 'brbbot') for RC4 encryption of config",
    "Ghidra imports: Full CryptoAPI chain \u2014 CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptDecrypt, CryptDestroyKey, CryptDestroyHash, CryptReleaseContext",
    "Ghidra imports: RegSetValueExA, RegOpenKeyExA, RegDeleteValueA, RegFlushKey, RegCloseKey \u2014 registry manipulation for persistence",
    "Ghidra imports: CreateProcessA, CreateFileA/W, CopyFileA, DeleteFileA, FindResourceA, GetModuleFileNameA \u2014 dropper/file operations and remote command execution",
    "Ghidra string_refs: FUN_140003030 references 'HTTP/1.1' and 'Connection: close\\r\\n' \u2014 C2 HTTP communication",
    "Ghidra string_refs: FUN_140002f50 references 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)' \u2014 spoofed user-agent for C2",
    "Ghidra string_refs: FUN_140003300 references 'ZwQuerySystemInformation' and 'ntdll.dll' \u2014 anti-analysis/process enumeration",
    "Ghidra string_refs: FUN_1400012e0 references 'encode' and 'sleep' \u2014 data encoding and C2 sleep/beacon loop",
    "CAPA: 35 rules matched including 'encode data using XOR' (T1027), 'encrypt or decrypt via WinCrypt' (T1027), 'encrypt data using RC4 via WinAPI' (C0027.009), 'create new key via CryptAcquireContext'",
    "YARA: 17 rules matched including anti_dbg, network_http, screenshot, win_registry, win_files_operation, Dropper_Strings, Advapi_Hash_API, contains_base64",
    "Ghidra function_metrics: FUN_1400012e0 has cyclomatic_complexity=59, call_out_count=37, string_ref_count=2 \u2014 complex C2 command dispatcher; FUN_140001840 cc=45, call_out=24; FUN_140001c10 cc=47, call_out=28 \u2014 multi-path logic with high branching"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
      "rule": "contains_base64",
      "path": 
… [10584 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
    "file_name": "brbbot.exe",
    "file_path": 
… [89043 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 35,
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
… [9035 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 75776,
  "duration_s": 0.04,
  "import_count": 115,
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
      "label": "crypto_encrypt",
      "api_match": "CryptEncrypt",
      "attack": [
        "T1573"
      ]
    },
    {
      "lab
… [668 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 310,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "WATAUH",
    "USVATH",
    "xA\\^[]",
    "UVATAVAWH",
    "\\$ D9d$x",
    "0A_A^A\\^]",
    "\\$ UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "UVWATAUAVAWH",
    "|$ H9=",
    "@SATAUH",
    "@A
… [1416 more chars]
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
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
  "disassembly": {
    "0x140003f94": "\u250c 401: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_30h @ rsp+0x30\n\u2502       \u254e   ; var int64_t var_6ch @ rsp+0x6c\n\u2502       \u254e   ; var int
… [530 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_
… [16 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
    "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
    "exists": true,
    "hook_candidates": [
      "ADVAPI32.dll!RegSetValueExA",
      "ADVAPI32.dll!RegOpenKeyExA",
      "ADVAPI32.dll!RegDeleteValueA",
      "ADVAPI32.dll!RegFlushKey",
      "ADVAPI32.
… [584 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 50176,
      "entropy": 6.3733,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 14848,
      "entropy": 4.8643,
      "executable": f
… [647 more chars]
```

- **revai_tools_sec** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sec)

```json
{
  "format": "pe",
  "findings": [
    {
      "name": "Address Space Layout Randomization",
      "present": true,
      "claimed": true,
      "note": "claim only: DYNAMIC_BASE set but no .reloc section \u2014 loads at preferred base",
      "consequence": "Without ASLR the image loads at a fixed base \u2014 a predictable address for ret2libc-style exploitation and ROP gadget pivots."
    },
  
… [1821 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 22,
  "sinks": [
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x140001039",
      "function": "fcn.140001000"
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x1400010d5",
      "functi
… [3574 more chars]
```

- **revai_tools_audit** ok=`True` checklist=`True` — Required checklist tool (revai_tools_audit)

```json
{
  "format": "pe",
  "findings": [],
  "engine": "revai_tools_audit",
  "source": "revai_tools"
}
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 2.51,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 5,
    "min_resolve_calls": 2,
    "elapsed_s": 1.3,
  
… [100 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "suspicious",
  "name": null,
  "score": 3
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
      "name": "_input_l",
      "address": "5368727132",
      "size": "4212"
    },
    {
      "name": "_output_l",
      "address": "5368732736",
      "size": "2658"
    },
    {
      "name": "_write_nolock",
      "address": "5368747712",
      "size": "1888"
    },
    {
      "name": "_read_nolock",
      "addres
… [2476 more chars]
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
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n",
      "address": "5368768928",
      "length"
… [9208 more chars]
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
      "name": "CryptAcquireContextW",
      "module": "ADVAPI32.DLL",
      "address": "6"
    },
    {
      "name": "CryptCreateHash",
      "module": "ADVAPI32.DLL",
      "address": "10"
    },
    {
      "name": "CryptDecrypt",
      "module": "ADVAPI32.DLL",
      "address": "12"
    },
    {
      "name": "Cryp
… [11400 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_140002230",
      "func_addr": "5368717872",
      "string_value": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    },
    {
      "func_name": "FUN_140002550",
      "func_addr": "5368718672",
      "string_value": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    },
 
… [1030 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "cyclomatic_complexity",
    "instruction_count",
    "block_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "_input_l",
      "address": "5368727132",
      "size": "4212",
      "cyclomatic_complexity": "247",
      "instruction_count": "1142",
      "block_count": "373",
      "string_ref_count": "0"
    },
    {
  
… [6881 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands",
    "disasm"
  ],
  "rows": [
    {
      "address": "5368721456",
      "mnemonic": "MOV",
      "operands": "qword ptr [RSP + 0x8], RBX",
      "disasm": "MOV qword ptr [RSP + 0x8],RBX"
    },
    {
      "address": "5368721461",
      "mnemonic": "PUSH",
      "operands": "RDI",
      "disasm": "PUSH RDI"
    },
    {
      "addres
… [14353 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands",
    "disasm"
  ],
  "rows": [
    {
      "address": "5368717872",
      "mnemonic": "PUSH",
      "operands": "RBX",
      "disasm": "PUSH RBX"
    },
    {
      "address": "5368717874",
      "mnemonic": "PUSH",
      "operands": "RDI",
      "disasm": "PUSH RDI"
    },
    {
      "address": "5368717875",
      "mnemonic": "SUB",

… [11270 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "operands",
    "disasm"
  ],
  "rows": [
    {
      "address": "5368719680",
      "mnemonic": "MOV",
      "operands": "RAX, RSP",
      "disasm": "MOV RAX,RSP"
    },
    {
      "address": "5368719683",
      "mnemonic": "PUSH",
      "operands": "RBX",
      "disasm": "PUSH RBX"
    },
    {
      "address": "5368719684",
      "mnemonic": 
… [14466 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 35,
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
… [9035 more chars]
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
    "func_name",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_1400012e0",
      "string_value": "encode"
    },
    {
      "func_name": "FUN_1400012e0",
      "string_value": "sleep"
    },
    {
      "func_name": "FUN_140002230",
      "string_value": "APPDATA"
    },
    {
      "func_name": "FUN_140002230",
      "string_value": "Software\\Microsoft\\Wind
… [2187 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "cyclomatic_complexity",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_1400012e0",
      "address": "5368713952",
      "size": "1168",
      "cyclomatic_complexity": "59",
      "call_out_count": "37",
      "string_ref_count": "2"
    },
    {
      "name": "FUN_140001770",
      "address": "5368
… [3131 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: ce.from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: ce.from_func_name"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "address",
    "mnemonic",
    "disasm"
  ],
  "rows": [
    {
      "address": "5368722496",
      "mnemonic": "MOV",
      "disasm": "MOV RAX,qword ptr [RSI + 0x40]"
    },
    {
      "address": "5368722500",
      "mnemonic": "MOV",
      "disasm": "MOV qword ptr [RSP + 0x38],R12"
    },
    {
      "address": "5368722505",
      "mnemonic": "MOV",
      "disasm": "MOV qwo
… [6326 more chars]
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
      "src_func_addr": "5368713216",
      "src_func_name": "FUN_140001000",
      "dst_func_addr": "0",
      "dst_func_name": "sub_0",
      "call_site": "5368713256"
    },
    {
      "src_func_addr": "5368713216",
      "src_func_name": "FUN_140001000",
 
… [594 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "src_func_name",
    "dst_func_name"
  ],
  "rows": [
    {
      "src_func_name": "FUN_1400012e0",
      "dst_func_name": "FUN_140002c50"
    },
    {
      "src_func_name": "FUN_1400012e0",
      "dst_func_name": "FUN_140001000"
    },
    {
      "src_func_name": "FUN_1400012e0",
      "dst_func_name": "FUN_140001000"
    },
    {
      "src_func_name": "FUN_1400012e0",
   
… [8732 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/deep_dive/01-tools-raw.json` exists=`True` bytes=`137219` mtime=`2026-08-13T01:47:23.506883+00:00`
  - sha256: `7baea149a7a2e54af33413c50a405344b0dada42f10aaaa18e78ec6883815e8d`
- **sql_evidence:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/deep_dive/05-deep-dive.json` exists=`True` bytes=`4997` mtime=`2026-08-12T16:45:53.171294+00:00`
  - sha256: `8cf13ad767d446c8a2de34f2e68063a0086f72083224f420df7a789d7e4053b0`

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
  "summary": "This is the 'brbbot' backdoor/RAT. It establishes persistence via the Windows Run registry key using the name 'brbbot', encrypts/decrypts its configuration file (brbconfig.tmp) using RC4 via the Windows Crypto API with a base64-encoded key 'YnJiYm90' (= 'brbbot'), communicates with a C2 server over HTTP/1.1 using a spoofed IE8 user-agent, and supports remote command execution via CreateProcessA. The binary includes anti-debug checks via ZwQuerySystemInformation and XOR-based data encoding. CAPA identified 35 capability matches covering encryption, persistence, network, and process injection techniques. YARA rules flagged anti-debug, network HTTP, screenshot capture, regis
… [4197 more chars]
```

- **agentic:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`593198` mtime=`2026-08-12T16:45:53.171294+00:00`
  - sha256: `1b07ec590f6498c0bb53154788c81031095b2d1d130ef00a44ac332c56dd9b2a`

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

- **rule_yar:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/rule.yar` exists=`True` bytes=`1167` mtime=`2026-08-12T16:45:56.082282+00:00`
  - sha256: `3b7a31cb56817b535f1a5bfc58a2fcb4fd112c89e3797091d61b8e83af20c0be`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T16:45:56.083761+00:00
import "pe"
rule CADRE_v2_trojan_blocker_bckn_botnet_trojan_f47060d0f7de {
    meta:
        description = "RevAI v2 auto rule for trojan.blocker/bckn (botnet trojan)"
        sha256 = "f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e"
        family = "trojan_blocker_bckn_botnet_trojan"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "UVATAVAWH" ascii wide
        $s2 = "\\$ D9d$x" ascii wide
        $s3 = "0A_A^A\\^]" ascii wide
        $s4 = "\\$ UVWATAUAVAWH" ascii wide
        $s5 = "A_A^A]A\\_^]" ascii wide
        $s6 = "UVWAT
… [365 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/REPORT-MASTER-v2.md` exists=`True` bytes=`29520` mtime=`2026-08-13T06:49:50.010804+00:00`
  - sha256: `a14be51b8d6ff4b4601bbc2cefeda86f691475380c18a66efaa47523708a1ba6`
- **REPORT_MASTER_v3:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/REPORT-MASTER-v3.md` exists=`True` bytes=`44015` mtime=`2026-08-13T07:03:02.401581+00:00`
  - sha256: `30d3ecaf6d450450e560fd4bd485f2ee5a97e13b6cb3c42b94337f31a7925740`
- **REPORT_v2:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/REPORT-v2.md` exists=`True` bytes=`29520` mtime=`2026-08-13T06:49:50.010804+00:00`
  - sha256: `a14be51b8d6ff4b4601bbc2cefeda86f691475380c18a66efaa47523708a1ba6`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`77492` mtime=`2026-08-13T06:53:58.577352+00:00`
  - sha256: `170efcc8f6a9f7a6b733d5bd5fdaf018a0aee1efc7e83582473135a26ae0df7a`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`64120` mtime=`2026-08-13T07:06:57.093086+00:00`
  - sha256: `d74f7e9e8ca16e042b4ea777b14ef5e2a13cb5839b4f358b68f525df7581b778`
- **report_v2_json:** `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/report-v2.json` exists=`True` bytes=`32619` mtime=`2026-08-13T06:53:58.585352+00:00`
  - sha256: `eab7e0e134235d08c788008f820870645de7b72d6e71dbd37d807ae278867395`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 06:49:50 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: brbbot.exe

## Executive Summary

The sample `brbbot.exe` (SHA256: `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e`) is a malicious backdoor/RAT identified as the 'brbbot' botnet trojan. The binary is a 64-bit Windows PE executable with a high-confidence malicious verdict (95/100) supported by 57 VirusTotal detections and consistent evidence across multiple analysis engines. The malware establ
… [28613 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 07:03:02 UTC

# RE Report — f47060d0f7de
_Generated 2026-08-13T07:03:02.393736+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=262c | cross_refs=True | llm_ok=True | runtime=49.98s -->

# Executive Summary

**Verdict:** Malicious  
**Family:** trojan.blocker/bckn (botnet trojan)  
**Confidence:** High (90%)  

This sample is assessed as a malicious botnet trojan with high confidence, based on extensive static analysis indicators and agreement between multiple analysis engines. Dynamic analysis tools were executed but recorded no significant malicious runtime events, which may indicate evasion
… [43089 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
