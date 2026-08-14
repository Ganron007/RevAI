# Pipeline AUDIT-REPORT — `8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-14T02:57:49.677568+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-14 02:57:49 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde`

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
- key_evidence_count=`27`

```json
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "Dyreza/Battdil",
  "cross_engine_notes": "Multiple engines (Ghidra, IDA, MalCat, capa, YARA, pe_imports) converge on a DLL with extensive C2, credential theft, and persistence capabilities. The sample uses HTTP for C2 (wininet APIs, 'http://icanhazip.com'), cryptographic APIs for credential theft (BCrypt, CryptoAPI), process injection (CreateRemoteThread), and registry manipulation for persistence. High entropy in .rsrc section suggests embedded payloads. VirusTotal confirms 55/72 detections as Dyreza/Battdil trojan.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "http://icanhazip.com",
      "why": "External IP check URL indicates C2 communication or environment fingerprinting."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "CryptGetHashParam, CryptAcquireContextW, CryptCreateHash, CryptHashData",
      "why": "Cryptographic API strings indicate credential theft or data encryption capabilities."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "HttpSendRequestExW, HttpQueryInfoW, HttpOpenRequestA, HttpSendRequestA",
      "why": "HTTP client API strings indicate C2 communication capabilities."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "WININET | InternetConnectA, WININET | HttpSendRequestExW, WININET | InternetReadFile",
      "why": "HTTP client imports confirm C2 communication functionality."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "WS2_32 | WSAConnect, WS2_32 | WSASend, WS2_32 | WSARecv",
      "why": "Winsock imports indicate additional network communication capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "CryptoApiUsage\u00d73 (imports)",
      "why": "Cryptographic API usage indicates credential theft or data encryption."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "DownloaderApiUsage\u00d76 (imports)",
      "why": "Downloader API usage indicates payload retrieval capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "BigResourceHighEntropy\u00d74 (resources)",
      "why": "High-entropy resources suggest embedded/encrypted payloads."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "kernel32.CreateRemoteThread",
      "why": "Process injection API indicates code injection capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "advapi32.CryptAcquireContextW, advapi32.CryptCreateHash, advapi32.CryptHashData",
      "why": "Cryptographic APIs for credential theft or data encryption."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "wininet.InternetConnectA, wininet.HttpSendRequestA, wininet.InternetReadFile",
      "why": "HTTP client APIs for C2 communication."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Microso..ccounts\\UserList, Software\\Microso..Version\\Winlogon",
      "why": "Registry paths indicate pe
… [7784 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`98`
- key_evidence_count=`17`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 98,
  "summary": "This 64-bit DLL (named 'win32k.dll' to masquerade as the legitimate Windows kernel component) is a fully-featured backdoor/RAT with 855 exports, HTTP-based C2, persistence via scheduled tasks, privilege escalation, process injection, and browser credential theft capabilities. It fingerprints the OS version for beaconing, checks its public IP via icanhazip.com, uses a custom HTTP protocol ('httprdc'/'httprex'), and employs multiple encryption layers (AES, XOR, Base64, SHA-2/BLAKE2). Evasion techniques are evident through masquerading as 'win32k.dll' and using encryption layers to hinder analysis. Exfiltration capabilities are not explicitly observed, though data theft is implied via credential theft and HTTP C2. Defense impairment techniques are not observed.",
  "key_evidence": [
    "855 exports in a single DLL is abnormal and consistent with a modular malware framework (Ghidra exports table: 855 rows)",
    "Persistence via scheduled tasks every 1 minute running as System: '/c echo N|schtasks /create /tn \"%s\" /tr \"%s\" /sc minute /mo 1 /ru \"System\"' (Ghidra string_refs to FUN_18000bf10)",
    "Privilege escalation APIs imported: AdjustTokenPrivileges, DuplicateTokenEx, CreateProcessAsUserW, LookupPrivilegeValueW, OpenProcessToken, GetTokenInformation (Ghidra imports from ADVAPI32.DLL)",
    "Process injection: CreateRemoteThread + VirtualAlloc + OpenProcess from KERNEL32.DLL (pe_import_signals: T1055 injection)",
    "HTTP C2 channel: InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestA, HttpSendRequestExW, InternetReadFile (Ghidra imports from WININET.DLL)",
    "External IP check via http://icanhazip.com referenced in FUN_180013cb0 (Ghidra string_refs)",
    "Custom C2 protocol strings 'httprdc' and 'httprex' with command-response pattern including 'success' and 'no\\r\\n\\r\\n\\r\\n' (Ghidra string_refs to FUN_18000deb0, FUN_18000e4d0, FUN_18000e6e0)",
    "OS fingerprinting beacon URL: '/%s/%s/0/%s/%d/%s/%s/' with version strings Win_XP through Win_10_TH1 and _64bit detection (Ghidra string_refs to FUN_180005120)",
    "Browser credential theft targeting: chrome.exe, firefox.exe, iexplore.exe, microsoftedge (Ghidra string_refs to FUN_180018b90)",
    "CAPA: 74 behavioral rules including Base64 encoding (T1027), XOR encoding (T1027), manually built AES constants (T1027), socket operations, registry manipulation (T1112), process creation (T1106)",
    "YARA SHA2/BLAKE2 IVs match at offsets 40612-40665 indicating embedded cryptographic constants (checklist_yara_scan)",
    "YARA Advapi_Hash_API matches: CryptAcquireContext, CryptCreateHash, CryptHashData at offsets 120654-120914 (checklist_yara_scan)",
    "BCrypt cryptographic API chain: BCryptOpenAlgorithmProvider, BCryptCreateHash, BCryptHashData, BCryptFinishHash, BCryptVerifySignature (Ghidra imports from BCRYPT.DLL)",
    "Extremely high cyclomatic complexity functions: CC=97 (FUN_18000b5e0, 144 blocks), CC=91 (FUN_18000d940, 118 blocks), CC=75 (FUN_180015390, 109 blocks) indicating obfuscated or complex C2 logic (Ghidra function_metrics)",
    "Service manipulation: ControlService imported from ADVAPI32.DLL (Ghidra imports)",
    "User-Agent masquerade as Chrome: 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36' (Ghidra string_refs to FUN_1800095b0)",
    "YARA Dropper_Strings match and 
… [1324 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Dyreza/Battdil Trojan Analysis Report",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-14 02:42:36 UTC\n\n# Classification (multi-source \u2014 V5.12)\n\n| Source | Verdict |\n|--------|--------|\n| **Final (locked)** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | benign |\n\n- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.\n- **Family (triage):** Dyreza/Battdil\n- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.\n\n---\n\n### Publish LLM narrative (unedited)\n\n# Dyreza/Battdil Trojan Analysis Report\n\n## Executive Summary\n\nThis report details the analysis of a 64-bit Windows DLL (SHA256: 8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde) masquerading as the legitimate Windows kernel component `win32k.dll`. The sample is identified as a variant of the Dyreza/Battdil banking trojan with high confidence (98/100). It is a fully-featured backdoor/RAT with 855 exports, indicating a modular framework. Its primary capabilities include HTTP-based command-and-control (C2) communication, credential theft targeting major web browsers, persistence via scheduled tasks, privilege escalation, and process injection. The malware fingerprints the infected system's OS version and checks its public IP address via `http://icanhazip.com` for beaconing. It employs multiple encryption layers (AES, XOR, Base64, SHA-2/BLAKE2) and masquerades as a system DLL to evade detection. The verdict is **malicious** based on clear behavioral intent for credential theft, C2 communication, and persistence, corroborated by 55/72 VirusTotal detections and multiple tool analyses.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | 8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde |\n| **File Name** | win32k.dll |\n| **File Type** | PE32+ (64-bit) DLL |\n| **Architecture** | x86-64 |\n| **Size** | Not specified in evidence |\n| **Entropy** | 7.37 bits/byte (source: malcat) |\n| **Imphash** | 8d7e3e41cd993d5a41f4e96d6076c4f7 (source: rule.yara.json) |\n| **Packed** | No (UPX probe failed, not packed) (source: upx_unpack) |\n| **.NET Assembly** | No (source: dotnet_analyze) |\n| **Project** | malware |\n\nThe file is a 64-bit DLL with a high entropy of 7.37 bits/byte, suggesting significant obfuscation or encryption within its sections (source: malcat). The filename `win32k.dll` is a deliberate attempt to masquerade as the legitimate Windows kernel-mode driver, a common evasion tactic (source: deep-dive.json). The import hash (imphash) is a unique fingerprint for its import table configuration.\n\n## 2. Classification\n\n**Verdict: Malicious**\n\n**Family: Dyreza/Battdil**\n\n**Confidence: 98/100**\n\nThe classification is based on a convergence of evidence from multiple analysis engines. The upstream triage verdict is malicious with a score of 95/100, identifying the family as Dyreza/Battdil (source: triage verdict.json). VirusTotal reports 55/72 detections for this family (source: triage verdict.json). The de
… [20542 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:42:36 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Dyreza/Battdil
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Dyreza/Battdil Trojan Analysis Report

## Executive Summary

This report details the analysis of a 64-bit Windows DLL (SHA256: 8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde) masquerading as the legitimate Windows kernel component `win32k.dll`. The sample is identified as a variant of the Dyreza/Battdil banking trojan with high confidence (98/100). It is a fully-featured backdoor/RAT with 855 exports, indicating a modular framework. Its primary capabilities include HTTP-based command-and-control (C2) communication, credential theft targeting major web browsers, persistence via scheduled tasks, privilege escalation, and process injection. The malware fingerprints the infected system's OS version and checks its public IP address via `http://icanhazip.com` for beaconing. It employs multiple encryption layers (AES, XOR, Base64, SHA-2/BLAKE2) and masquerades as a system DLL to evade detection. The verdict is **malicious** based on clear behavioral intent for credential theft, C2 communication, and persistence, corroborated by 55/72 VirusTotal detections and multiple tool analyses.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | 8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde |
| **File Name** | win32k.dll |
| **File Type** | PE32+ (64-bit) DLL |
| **Architecture** | x86-64 |
| **Size** | Not specified in evidence |
| **Entropy** | 7.37 bits/byte (source: malcat) |
| **Imphash** | 8d7e3e41cd993d5a41f4e96d6076c4f7 (source: rule.yara.json) |
| **Packed** | No (UPX probe failed, not packed) (source: upx_unpack) |
| **.NET Assembly** | No (source: dotnet
… [18522 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:55:06 UTC

# RE Report — 8088f08a5636
_Generated 2026-08-14T02:55:06.578806+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=241c | cross_refs=True | llm_ok=True | runtime=54.12s -->

## Executive Summary

| Key Aspect | Details | Evidence Basis |
|------------|---------|----------------|
| Verdict | Malicious | Based on v1_summary score of 290 with 26 YARA matches and 74 CAPA rules (source: v1_summary, row: yara: 26 matches, row: capa: 74 rules), indicating widespread malicious patterns and high likelihood of harm. |
| Malware Family | Dyreza/Battdil | Supported by static analysis evidence, including YARA rule matches and string indicators (source: cross-section:3, row: contains 'Dyre' and 'Battdil' markers), which align with known Dyreza characteristics for credential theft. |
| Confidence Level | 98% | Derived from deep dive agentic analysis (source: deep_confidence, why: comprehensive static assessment and tool convergence), reflecting strong agreement across analysis methods. |
| Agreement | LLM and v1 concur | Both automated assessments independently label the sample as malicious (source: agreement, row: llm_and_v1_agree), reducing false-positive risk. |

**Summary:** This sample is assessed as malicious with high confidence, belonging to the Dyreza banking trojan family, which likely targets financial data for credential theft and man-in-the-browser attacks. Dynamic analysis tools, including Speakeasy and Frida, were executed but recorded no runtime events in the filtered evidence (source: cross-section:5, why: tools ran but data excluded), so behavioral inferences are drawn from static analysis artifacts such as registry modifications and network-related strings.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=114.0s -->

## 1. Sample Identification

This section provides the key identifiers for the sample under analysis, derived from static examination using tools such as MalCat. We present the evidence and interpret each component to establish the sample's characteristics, with citations indicating the source of each piece of data.

### Sample Identifiers

| Identifier       | Value    
… [48835 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `11284` | `4441a3ad1d40a1a4` |
| `prompt.txt` | `True` | `37198` | `4a73350cc51f6e74` |
| `pipeline-audit.json` | `True` | `121560` | `45d5c8e7495534d4` |
| `AUDIT-REPORT.md` | `True` | `90186` | `413c645041ec08e5` |
| `REPORT-MASTER-v2.md` | `True` | `21031` | `16b5e2c7207a5b87` |
| `REPORT-MASTER-v3.md` | `True` | `51354` | `7e2b8d454f258a28` |
| `REPORT-v2.md` | `True` | `21031` | `16b5e2c7207a5b87` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `63495` | `a1fa81cc73d1c07b` |
| `rule.yar` | `True` | `1111` | `92e1d8277cbbab7b` |
| `intake-validation.json` | `True` | `3235` | `495852a6df5515f3` |
| `source-decisions.json` | `True` | `2386` | `be0924bba433d64e` |
| `malcat-triage.json` | `True` | `48416` | `0b0d431ac80c1dec` |
| `deep_dive/01-tools-raw.json` | `True` | `150680` | `3e2f293eaba44a4c` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4824` | `4ad4655d4d36d48b` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `140519` | `98656cf989b1350e` |

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

- **intake_validation:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/intake-validation.json` exists=`True` bytes=`3235` mtime=`2026-08-12T18:09:20.709409+00:00`
  - sha256: `495852a6df5515f36122a79cb9c56fc49869beffa8e9455fc8ed2a021cf7029e`
- **malcat_triage:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/malcat-triage.json` exists=`True` bytes=`48416` mtime=`2026-08-13T04:19:03.183360+00:00`
  - sha256: `0b0d431ac80c1dec734a07b85c127a71138c03c04d1a84d2b044990b5cb6a267`
- **source_decisions:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/source-decisions.json` exists=`True` bytes=`2386` mtime=`2026-08-12T18:09:20.709409+00:00`
  - sha256: `be0924bba433d64ee817c3b005190115dd86599c9e3e7e0a746247e560d2512d`
- **ghidra_import_log:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/intake-analyzeHeadless.log` exists=`True` bytes=`8982` mtime=`2026-08-12T18:08:21.979133+00:00`
  - sha256: `0838af78311431f1508bae3bce2c47e75f37956a44ed6d8b1b916b33cd740166`
- **ida_bootstrap_log:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/intake-idasql.log` exists=`True` bytes=`213` mtime=`2026-08-12T18:08:23.786149+00:00`
  - sha256: `44d2e34d4a97572ed91808418b8e7668a56fc87fd4e37d1b00ab56cc062f3efb`

#### source_decisions_excerpt

```
{
  "sha256": "8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "{malcat, imports_count, 192, same count}; {ghidra, imports, 192, same count}; {ida, imports, 192, same count} - All tools report 192 imports, indicating high consistency; Ghidra is a reliable source for detailed import analysis."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "{ghidra, funcs, 655, high count}; {ida, funcs, 655, high count}; {malcat, functions_count, 10, low count} - Ghidra and ida report significantly higher function counts (655) compared to malcat (10), providing more comprehensive function identification; Ghidra is chosen for robust analysis."
  },
  "strings": {
    "sourc
… [1609 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
    "file_name": "win32k.dll",
    "file_path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
    "file_size": 268800,
    "type": "PE",
    "architecture": "X64",
    "entropy": 7.37,
    "sha256": "8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde",
    "metadata": {},
    "entrypoint_ea": 80560,
    "layout": [
      {
        "name": "header",
        "effective_ad
… [47616 more chars]
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
  "rule_count": 74,
  "top_rules": [
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
      "name": "manually build AES constants",
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
            "AES"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "AES",
          "id": "C0027.001"
        }
      ]
    },
    {
      "name": "get socket status",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Network Configuration Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Network Configuration Discovery",
          "subtechnique": "",
          "id": "T1016"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Get Socket
… [7351 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 106664,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 135082,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 43498,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Browsers",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$ie",
          "offset": 109464,
          "length": 24,
          "xor_key": null
        },
        {
          "id": "$ff",
          "offset": 109440,
          "length": 22,
          "xor_key": null
        },
        {
          "id": "$chrome",
          "offset": 109416,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$a1",
          "offset": 108846,
          "length": 52,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$a4",
          "offset": 104200,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 104456,
          "length": 24,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 120804,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 120914,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 120654,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$c0",
          "offset": 40612,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 40619,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 40626,
          "le
… [11783 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 907,
  "strings_sampled": 80,
  "strings": [
    "=&&jL66Zl??A~",
    "&jL&6Zl6?A~?",
    "jL&&Zl66A~??",
    "L&&jl66Z~??A",
    "j:,4;87",
    "unknown_64bit",
    "daYdnc",
    "daYdnce",
    "daYdnceM",
    "daYdnceMm",
    "daYdnceMmb",
    "daYdnceMmbN",
    "daYdnceMmbNJ",
    "daYdnceMmbNJX",
    "daYdnceMmbNJXp",
    "daYdnceMmbNJXpF",
    "daYdnceMmbNJXpFB",
    "daYdnceMmbNJXpFBN",
    "daYdnceMmbNJXpFBNX",
    "daYdnceMmbNJXpFBNXc",
    "daYdnceMmbNJXpFBNXci",
    "daYdnceMmbNJXpFBNXciG",
    "daYdnceMmbNJXpFBNXciGG",
    "daYdnceMmbNJXpFBNXciGGe",
    "daYdnceMmbNJXpFBNXciGGeW",
    "daYdnceMmbNJXpFBNXciGGeWm",
    "daYdnceMmbNJXpFBNXciGGeWmS",
    "daYdnceMmbNJXpFBNXciGGeWmSx",
    "daYdnceMmbNJXpFBNXciGGeWmSxB",
    "daYdnceMmbNJXpFBNXciGGeWmSxBe",
    "daYdnceMmbNJXpFBNXciGGeWmSxBeP",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePk",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkF",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFp",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpN",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNP",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPq",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPqu",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquU",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUk",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkC",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCo",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoT",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTA",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAn",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnx",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxo",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxof",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofd",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofdd",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofdds",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsK",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKA",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAn",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAni",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniq",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqR",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRm",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmx",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxo",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJ",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJi",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiG",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGm",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmy",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmyl",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylD",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDj",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjI",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjIS",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISw",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISwS",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISwSL",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISwSLy",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGm
… [557 more chars]
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
    "file_name": "win32k.dll",
    "file_path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
    "file_size": 268800,
    "type": "PE",
    "architecture": "X64",
    "entropy": 7.37,
    "sha256": "8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde",
    "metadata": {},
    "entrypoint_ea": 80560,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 50
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 99840,
        "virtual_size": 102400,
        "rights": "RX",
        "entropy": 129
      },
      {
        "name": ".rdata",
        "effective_address": 103424,
        "physical_size": 22528,
        "virtual_size": 24576,
        "rights": "R",
        "entropy": 82
      },
      {
        "name": ".data",
        "effective_address": 128000,
        "physical_size": 512,
        "virtual_size": 12288,
        "rights": "RW",
        "entropy": 110
      },
      {
        "name": ".pdata",
        "effective_address": 140288,
        "physical_size": 9216,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 94
      },
      {
        "name": ".rsrc",
        "effective_address": 152576,
        "physical_size": 135168,
        "virtual_size": 135168,
        "rights": "R",
        "entropy": 213
      },
      {
        "name": ".reloc",
        "effective_address": 287744,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 221
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 167,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "BigResourceHighEntropy",
        "desc": "File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture",
        "category": "resources",
        "level": 2,
        "num_hits": 4
      },
      {
        "name": "CryptoApiUsage",
        "desc": "Crypto-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 3
      },
      {
        "name": "DllNoExportTable",
        "desc": "no valid ExportDirectory found and PE is a DLL",
        "category": "exports",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "DownloaderApiUsage",
        "desc": "Downloader-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 6
      },
      {
        "name": "InvalidChecksum",
        "desc": "PE Header checksum is wrong",
        "category": "integrity",
        "level": 4,
        "num_hits": 1
      },
      {
        "name": "ManyHighValueImmediates",
        "desc": "Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values that contains at least 2 non-zero non-FF bytes and are not a valid address)",
        "category": "code",
        "level": 3,
        "num_hits": 1
      },
    
… [81405 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 27,
  "hits": 27,
  "misses": [],
  "hit_examples": [
    "http://icanhazip.com Suspicious strings (Ghidra) External IP check URL indicates C2 communication or environment fingerp",
    "CryptGetHashParam, CryptAcquireContextW, CryptCreateHash, CryptHashData Suspicious strings (Ghidra) Cryptographic API st",
    "HttpSendRequestExW, HttpQueryInfoW, HttpOpenRequestA, HttpSendRequestA Suspicious strings (Ghidra) HTTP client API strin",
    "WININET | InternetConnectA, WININET | HttpSendRequestExW, WININET | InternetReadFile Imports (IDA) HTTP client imports c",
    "WS2_32 | WSAConnect, WS2_32 | WSASend, WS2_32 | WSARecv Imports (IDA) Winsock imports indicate additional network commun"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Dyreza/Battdil",
  "score": 95,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "http://icanhazip.com",
      "why": "External IP check URL indicates C2 communication or environment fingerprinting."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "CryptGetHashParam, CryptAcquireContextW, CryptCreateHash, CryptHashData",
      "why": "Cryptographic API strings indicate credential theft or data encryption capabilities."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "HttpSendRequestExW, HttpQueryInfoW, HttpOpenRequestA, HttpSendRequestA",
      "why": "HTTP client API strings indicate C2 communication capabilities."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "WININET | InternetConnectA, WININET | HttpSendRequestExW, WININET | InternetReadFile",
      "why": "HTTP client imports confirm C2 communication functionality."
    },
    {
      "source": "ida",
      "query_or_table": "Imports (IDA)",
      "row_or_rule": "WS2_32 | WSAConnect, WS2_32 | WSASend, WS2_32 | WSARecv",
      "why": "Winsock imports indicate additional network communication capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "CryptoApiUsage\u00d73 (imports)",
      "why": "Cryptographic API usage indicates credential theft or data encryption."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "DownloaderApiUsage\u00d76 (imports)",
      "why": "Downloader API usage indicates payload retrieval capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "Anomalies",
      "row_or_rule": "BigResourceHighEntropy\u00d74 (resources)",
      "why": "High-entropy resources suggest embedded/encrypted payloads."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "kernel32.CreateRemoteThread",
      "why": "Process injection API indicates code injection capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "advapi32.CryptAcquireContextW, advapi32.CryptCreateHash, advapi32.CryptHashData",
      "why": "Cryptographic APIs for credential theft or data encryption."
    },
    {
      "source": "malcat",
      "query_or_table": "Top high-signal imports",
      "row_or_rule": "wininet.InternetConnectA, wininet.HttpSendRequestA, wininet.InternetReadFile",
      "why": "HTTP client APIs for C2 communication."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/registry",
      "row_or_rule": "Software\\Microso..ccounts\\UserList, Software\\Microso..Version\\Winlogon",
      "why": "Registry paths indicate persistence or credential theft targeting Windows authentication."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/suspicious",
      "row_or_rule": "Tcmd.exe",
      "why": "Suspicious executable name suggests command execution capabilities."
    },
    {
      "source": "malcat",
      "query_or_table": "Strings/paths",
      "row_or_rule": "C:\\windows\\system32\\shutdown.exe, \\\\.\\pipe\\, \\\\.\\PhysicalDrive0",
      "why": "System paths indicate potential destructive actions or system manipulation."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1027 - Obfuscated Files or Information",
      "why": "Multiple encoding techniques (Base64, XOR, AES) indicate defense evasion."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1083 - File and Directory Discovery",
      "why": "File system reconnaissance capabilities."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1012 - Query Registry",
      "why": "Registry enumeration for persistence or credential theft."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1082 - System Information Discovery",
      "why": "System fingerprinting for C2 communication."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1057 - Process Discovery",
      "why": "Process enumeration for injection or termination."
    },
    {
      "source": "capa",
      "query_or_table": "ATT&CK",
      "row_or_rule": "T1543.003 - Windows Service",
      "why": "Service manipulation for persistence."
    },
    {
      "source": "malcat",
      "query_or_table": "malcat_evidence",
      "row_or_rule": "PublicIP",
      "why": "Public IP detection rule indicates C2 communication or environment fingerprinting.",
      "source_corrected_from": "yara"
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "network_http, network_tcp_socket",
      "why": "Network communication rules indicate C2 capabilities."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "escalate_priv, win_token, win_registry",
      "why": "Privilege escalation, token manipulation, and registry rules indicate malicious behavior."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "create_remote_thread (CreateRemoteThread) [T1055]",
      "why": "Process injection API indicates code injection capabilities."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "http_client (InternetOpen) [T1071.001]",
      "why": "HTTP client API indicates C2 communication."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule":
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/prompt.txt` exists=`True` bytes=`37198` mtime=`2026-08-14T02:37:50.475900+00:00`
  - sha256: `4a73350cc51f6e749ef293ddf21e5b7605d837346ca9b0e4349dd8873155e88e`
- **verdict:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/verdict.json` exists=`True` bytes=`11284` mtime=`2026-08-14T02:39:44.839885+00:00`
  - sha256: `4441a3ad1d40a1a4d56056cbd75a5b5d5b4acb3cfb1fe2b3c13fc68e927586a6`

#### prompt_excerpt

```
# Triage evidence
sha256: 8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde
sample_path: /opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll
ghidra_session: ghidra-pe-8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde
ida_session: ida-8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — {malcat, imports_count, 192, same count}; {ghidra, imports, 192, same count}; {ida, imports, 192, same count} - All tools report 192 imports, indicating high consistency; Ghidra is a reliable source for detailed import analysis.
- functions: ghidra (confidence=high) — {ghidra, funcs, 655, high count}; {ida, funcs, 655, high count}; {malcat, functions_count, 10, low count} - Ghidra and ida report significantly higher function counts (655) compared to malcat (10), providing more comprehensive function identification; Ghidra is chos
… [36131 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 95,
  "family_guess": "Dyreza/Battdil",
  "cross_engine_notes": "Multiple engines (Ghidra, IDA, MalCat, capa, YARA, pe_imports) converge on a DLL with extensive C2, credential theft, and persistence capabilities. The sample uses HTTP for C2 (wininet APIs, 'http://icanhazip.com'), cryptographic APIs for credential theft (BCrypt, CryptoAPI), process injection (CreateRemoteThread), and registry manipulation for persistence. High entropy in .rsrc section suggests embedded payloads. VirusTotal confirms 55/72 detections as Dyreza/Battdil trojan.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "http://icanhazip.com",
      "why": "External IP check URL indicates C2 communication or environment fingerprinting."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "CryptGetHashParam, CryptAcquireContextW, CryptCrea
… [10284 more chars]
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
  "rule_count": 74,
  "top_rules": [
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
      "name": "manually build AES constants",
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
            "AES"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "AES",
          "id": "C0027.001"
        }
      ]
    },
    {
      "name": "get socket status",
      "attack": [
        {
          "parts": [
            "Discovery",
            "System Network Configuration Discovery"
          ],
          "tactic": "Discovery",
          "technique": "System Network Configuration Discovery",
          "subtechnique": "",
          "id": "T1016"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Communication",
            "Socket Communication",
            "Get Socket
… [7350 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 268800,
  "duration_s": 0.03,
  "import_count": 192,
  "signal_count": 7,
  "signals": [
    {
      "label": "create_remote_thread",
      "api_match": "CreateRemoteThread",
      "attack": [
        "T1055"
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
      "label": "shell_execute",
      "api_match": "ShellExecute",
      "attack": [
        "T1106"
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
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 106664,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 135082,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$a",
          "offset": 43498,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Browsers",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$ie",
          "offset": 109464,
          "length": 24,
          "xor_key": null
        },
        {
          "id": "$ff",
          "offset": 109440,
          "length": 22,
          "xor_key": null
        },
        {
          "id": "$chrome",
          "offset": 109416,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$a1",
          "offset": 108846,
          "length": 52,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$a4",
          "offset": 104200,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 104456,
          "length": 24,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 120804,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 120914,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 120654,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
      "strings": [
        {
          "id": "$c0",
          "offset": 40612,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 40619,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 40626,
          "le
… [11761 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 907,
  "strings_sampled": 80,
  "strings": [
    "=&&jL66Zl??A~",
    "&jL&6Zl6?A~?",
    "jL&&Zl66A~??",
    "L&&jl66Z~??A",
    "j:,4;87",
    "unknown_64bit",
    "daYdnc",
    "daYdnce",
    "daYdnceM",
    "daYdnceMm",
    "daYdnceMmb",
    "daYdnceMmbN",
    "daYdnceMmbNJ",
    "daYdnceMmbNJX",
    "daYdnceMmbNJXp",
    "daYdnceMmbNJXpF",
    "daYdnceMmbNJXpFB",
    "daYdnceMmbNJXpFBN",
    "daYdnceMmbNJXpFBNX",
    "daYdnceMmbNJXpFBNXc",
    "daYdnceMmbNJXpFBNXci",
    "daYdnceMmbNJXpFBNXciG",
    "daYdnceMmbNJXpFBNXciGG",
    "daYdnceMmbNJXpFBNXciGGe",
    "daYdnceMmbNJXpFBNXciGGeW",
    "daYdnceMmbNJXpFBNXciGGeWm",
    "daYdnceMmbNJXpFBNXciGGeWmS",
    "daYdnceMmbNJXpFBNXciGGeWmSx",
    "daYdnceMmbNJXpFBNXciGGeWmSxB",
    "daYdnceMmbNJXpFBNXciGGeWmSxBe",
    "daYdnceMmbNJXpFBNXciGGeWmSxBeP",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePk",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkF",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFp",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpN",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNP",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPq",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPqu",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquU",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUk",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkC",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCo",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoT",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTA",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAn",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnx",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxo",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxof",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofd",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofdd",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofdds",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsK",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKA",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAn",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAni",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniq",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqR",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRm",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmx",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxo",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJ",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJi",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiG",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGm",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmy",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmyl",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylD",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDj",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjI",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjIS",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISw",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISwS",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISwSL",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGmylDjISwSLy",
    "daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsKAniqRmxoJiGm
… [557 more chars]
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
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
  "disassembly": {
    "0x1800146b0": "\u250c 42: entry0 (int64_t arg1, int64_t arg2);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; arg int64_t arg2 @ rdx\n\u2502           0x1800146b0      4883ec28       sub rsp, 0x28\n\u2502           0x1800146b4      85d2           test edx, edx              ; arg2\n\u2502       \u250c\u2500< 0x1800146b6      7413           je 0x1800146cb\n\u2502       \u2502   0x1800146b8      ffca           dec edx                    ; arg2\n\u2502      \u250c\u2500\u2500< 0x1800146ba      7514           jne 0x1800146d0\n\u2502      \u2502\u2502   0x1800146bc      e84f390000     call fcn.180018010\n\u2502      \u2502\u2502   0x1800146c1      b801000000     mov eax, 1\n\u2502      \u2502\u2502   0x1800146c6      4883c428       add rsp, 0x28\n\u2502      \u2502\u2502   0x1800146ca      c3             ret\n\u2502      \u2502\u2514\u2500> 0x1800146cb      e8c0390000     call fcn.180018090\n\u2502      \u2514\u2500\u2500> 0x1800146d0      b801000000     mov eax, 1\n\u2502           0x1800146d5      4883c428       add rsp, 0x28\n\u2514           0x1800146d9      c3             ret",
    "0x180018010": "\u2502\u254e\u254e\u254e   ; CALL XREF from entry0 @ 0x1800146bc(x)\n\u250c 875: fcn.180018010 (int64_t arg1);\n\u2502    \u2502\u254e\u254e\u254e   ; arg int64_t arg1 @ rcx\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_28h @ rsp+0x28\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_30h @ rsp+0x30\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_38h @ rsp+0x38\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_40h @ rsp+0x40\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_1e0h @ rsp+0x1e0\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_1e8h @ rsp+0x1e8\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_200h @ rsp+0x200\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_208h @ rsp+0x208\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_210h @ rsp+0x210\n\u2502    \u2502\u254e\u254e\u254e   ; var int64_t var_218h @ rsp+0x218\n\u2502    \u2514\u2500\u2500\u2500\u2500< 0x180018010      e98bfcffff     jmp 0x180017ca0\n..\n\u2502     \u254e\u254e\u254e   ; CODE XREF from fcn.180018090 @ 0x180018090(x)\n     \u2502 \u254e\u254e   ; CALL XREF from entry0 @ 0x1800146cb(x)\n       \u2502    ; CALL XREFS from fcn.180018010 @ 0x180017f9d(x), 0x180017fb9(x), 0x180017fd5(x)\n       \u2502    ; CALL XREFS from fcn.180018090 @ 0x180018051(x), 0x18001806d(x)"
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x1800146b0",
    "0x180018010",
    "0x180018090"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
    "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
    "exists": true,
    "hook_candidates": [
      "IPHLPAPI.DLL!GetAdaptersAddresses",
      "WININET.dll!InternetConnectA",
      "WININET.dll!HttpSendRequestExW",
      "WININET.dll!InternetQueryDataAvailable",
      "WININET.dll!InternetReadFile",
      "WININET.dll!InternetWriteFile",
      "WS2_32.dll!WSAConnect",
      "WS2_32.dll!htons",
      "WS2_32.dll!select",
      "WS2_32.dll!WSACreateEvent",
      "WS2_32.dll!closesocket",
      "SHLWAPI.dll!StrToIntA",
      "SHLWAPI.dll!StrTrimA",
      "SHLWAPI.dll!StrStrIA",
      "SHLWAPI.dll!StrToIntW",
      "SHLWAPI.dll!StrStrIW",
      "ADVAPI32.dll!OpenProcessToken",
      "ADVAPI32.dll!RegEnumKeyExW",
      "ADVAPI32.dll!RegOpenKeyW",
      "ADVAPI32.dll!QueryServiceConfigW",
      "ADVAPI32.dll!ControlService",
      "USERENV.dll!CreateEnvironmentBlock",
      "USERENV.dll!DestroyEnvironmentBlock",
      "USERENV.dll!LoadUserProfileW",
      "bcrypt.dll!BCryptOpenAlgorithmProvider",
      "bcrypt.dll!BCryptDestroyHash",
      "bcrypt.dll!BCryptHashData",
      "bcrypt.dll!BCryptFinishHash",
      "bcrypt.dll!BCryptVerifySignature",
      "NETAPI32.dll!NetApiBufferFree"
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
    "855 exports in a single DLL is abnormal and consistent with a modular malware framework (Ghidra exports table: 855 rows)",
    "Persistence via scheduled tasks every 1 minute running as System: '/c echo N|schtasks /create /tn \"%s\" /tr \"%s\" /sc minu",
    "Privilege escalation APIs imported: AdjustTokenPrivileges, DuplicateTokenEx, CreateProcessAsUserW, LookupPrivilegeValueW",
    "Process injection: CreateRemoteThread + VirtualAlloc + OpenProcess from KERNEL32.DLL (pe_import_signals: T1055 injection",
    "HTTP C2 channel: InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestA, HttpSendRequestExW, InternetReadFi"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 98,
  "summary": "This 64-bit DLL (named 'win32k.dll' to masquerade as the legitimate Windows kernel component) is a fully-featured backdoor/RAT with 855 exports, HTTP-based C2, persistence via scheduled tasks, privilege escalation, process injection, and browser credential theft capabilities. It fingerprints the OS ",
  "key_evidence": [
    "855 exports in a single DLL is abnormal and consistent with a modular malware framework (Ghidra exports table: 855 rows)",
    "Persistence via scheduled tasks every 1 minute running as System: '/c echo N|schtasks /create /tn \"%s\" /tr \"%s\" /sc minute /mo 1 /ru \"System\"' (Ghidra string_refs to FUN_18000bf10)",
    "Privilege escalation APIs imported: AdjustTokenPrivileges, DuplicateTokenEx, CreateProcessAsUserW, LookupPrivilegeValueW, OpenProcessToken, GetTokenInformation (Ghidra imports from ADVAPI32.DLL)",
    "Process injection: CreateRemoteThread + VirtualAlloc + OpenProcess from KERNEL32.DLL (pe_import_signals: T1055 injection)",
    "HTTP C2 channel: InternetOpenA, InternetConnectA, HttpOpenRequestA, HttpSendRequestA, HttpSendRequestExW, InternetReadFile (Ghidra imports from WININET.DLL)",
    "External IP check via http://icanhazip.com referenced in FUN_180013cb0 (Ghidra string_refs)",
    "Custom C2 protocol strings 'httprdc' and 'httprex' with command-response pattern including 'success' and 'no\\r\\n\\r\\n\\r\\n' (Ghidra string_refs to FUN_18000deb0, FUN_18000e4d0, FUN_18000e6e0)",
    "OS fingerprinting beacon URL: '/%s/%s/0/%s/%d/%s/%s/' with version strings Win_XP through Win_10_TH1 and _64bit detection (Ghidra string_refs to FUN_180005120)",
    "Browser credential theft targeting: chrome.exe, firefox.exe, iexplore.exe, microsoftedge (Ghidra string_refs to FUN_180018b90)",
    "CAPA: 74 behavioral rules including Base64 encoding (T1027), XOR encoding (T1027), manually built AES constants (T1027), socket operations, registry manipulation (T1112), process creation (T1106)",
    "YARA SHA2/BLAKE2 IVs match at offsets 40612-40665 indicating embedded cryptographic constants (checklist_yara_scan)",
    "YARA Advapi_Hash_API matches: CryptAcquireContext, CryptCreateHash, CryptHashData at offsets 120654-120914 (checklist_yara_scan)",
    "BCrypt cryptographic API chain: BCryptOpenAlgorithmProvider, BCryptCreateHash, BCryptHashData, BCryptFinishHash, BCryptVerifySignature (Ghidra imports from BCRYPT.DLL)",
    "Extremely high cyclomatic complexity functions: CC=97 (FUN_18000b5e0, 144 blocks), CC=91 (FUN_18000d940, 118 blocks), CC=75 (FUN_180015390, 109 blocks) indicating obfuscated or complex C2 logic (Ghidra function_metrics)",
    "Service manipulation: ControlService imported from ADVAPI32.DLL (Ghidra imports)",
    "User-Agent masquerade as Chrome: 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36' (Ghidra string_refs to FUN_1800095b0)",
    "YARA Dropper_Strings match and Misc_Suspicious_Strings match at offsets 108846 and 104200 (checklist_yara_scan)"
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
      "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
      "path": "/opt/samples
… [14861 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
    "file_name": "win32k.dll",
    "file_path": 
… [84348 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 74,
  "top_rules": [
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
    
… [10450 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 268800,
  "duration_s": 0.03,
  "import_count": 192,
  "signal_count": 7,
  "signals": [
    {
      "label": "create_remote_thread",
      "api_match": "CreateRemoteThread",
      "attack": [
        "T1055"
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
 
… [679 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 907,
  "strings_sampled": 80,
  "strings": [
    "=&&jL66Zl??A~",
    "&jL&6Zl6?A~?",
    "jL&&Zl66A~??",
    "L&&jl66Z~??A",
    "j:,4;87",
    "unknown_64bit",
    "daYdnc",
    "daYdnce",
    "daYdnceM",
    "daYdnceMm",
    "daYdnceMmb",
    "daYdnceMmbN",
    "daYdnceMmbNJ",
    "daYdnceMmbNJX",
    "daYdnceMmbNJXp",
    "daYdnceMmbNJXpF",
    "daYdnceM
… [3657 more chars]
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
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
  "disassembly": {
    "0x1800146b0": "\u250c 42: entry0 (int64_t arg1, int64_t arg2);\n\u2502           ; arg int64_t arg1 @ rcx\n\u2502           ; arg int64_t arg2 @ rdx\n\u2502           0x1800146b0      4883ec28       sub rsp, 0x28\n\u2502           0x18001
… [2428 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_
… [16 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
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
    "path": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
    "exists": true,
    "hook_candidates": [
      "IPHLPAPI.DLL!GetAdaptersAddresses",
      "WININET.dll!InternetConnectA",
      "WININET.dll!HttpSendRequestExW",
      "WININET.dll!InternetQueryDataAvai
… [952 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/win32k.dll",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 99840,
      "entropy": 6.1989,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 22528,
      "entropy": 5.1115,
      "executable": f
… [649 more chars]
```

- **revai_tools_sec** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sec)

```json
{
  "format": "pe",
  "findings": [
    {
      "name": "Address Space Layout Randomization",
      "present": false,
      "claimed": false,
      "note": "no DYNAMIC_BASE flag",
      "consequence": "Without ASLR the image loads at a fixed base \u2014 a predictable address for ret2libc-style exploitation and ROP gadget pivots."
    },
    {
      "name": "64-bit high-entropy ASLR",
      "presen
… [1762 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 49,
  "sinks": [
    {
      "api": "virtualalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x18000767b",
      "function": "fcn.1800075f0"
    },
    {
      "api": "virtualalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x18000b195",
      "
… [7809 more chars]
```

- **revai_tools_audit** ok=`True` checklist=`True` — Required checklist tool (revai_tools_audit)

```json
{
  "format": "pe",
  "findings": [
    {
      "api": "wsprintfw",
      "class": "format_string",
      "address": "0x18000c8f5",
      "function": "fcn.18000c6c0",
      "patterns": [
        "format_from_memory"
      ],
      "provenance": {
        "rcx": "mov rbx",
        "rdx": "sub rcx",
        "r8": "sub rax"
      }
    },
    {
      "api": "wsprintfw",
      "class": "format_string"
… [2597 more chars]
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 4.34,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 15,
    "min_resolve_calls": 2,
    "elapsed_s": 2.28,

… [102 more chars]
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
      "name": "FUN_180010bc0",
      "address": "6442519488",
      "size": "2712"
    },
    {
      "name": "FUN_180010330",
      "address": "6442517296",
      "size": "1588"
    },
    {
      "name": "FUN_18000b5e0",
      "address": "6442497504",
      "size": "1577"
    },
    {
      "name": "FUN_1800123b0",
   
… [2362 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 268800,
  "duration_s": 0.06,
  "import_count": 192,
  "signal_count": 7,
  "signals": [
    {
      "label": "create_remote_thread",
      "api_match": "CreateRemoteThread",
      "attack": [
        "T1055"
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
 
… [679 more chars]
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
    "string_ref_count",
    "call_out_count"
  ],
  "rows": [
    {
      "name": "FUN_18000b5e0",
      "address": "6442497504",
      "size": "1577",
      "cyclomatic_complexity": "97",
      "instruction_count": "429",
      "block_count": "144",
      "string_ref_co
… [5184 more chars]
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
      "content": "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\r\n    <security>\r\n      <requestedPrivileges>\r\n        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>\r\n      <
… [3858 more chars]
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
  "session_id": "ghidra-pe-8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde",
  "audit_path": "/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/audit.jsonl"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 74,
  "top_rules": [
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
    
… [10450 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde.json"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name",
    "func_addr"
  ],
  "rows": [
    {
      "content": "SeDebugPrivilege",
      "func_name": "FUN_1800074f0",
      "func_addr": "6442480880"
    },
    {
      "content": "SeShutdownPrivilege",
      "func_name": "FUN_180007570",
      "func_addr": "6442481008"
    },
    {
      "content": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML,
… [1593 more chars]
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
      "name": "AllocateAndInitializeSid",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CreateProcessAsUserW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptAcquireContextW",
      "module": "ADVAPI32.DLL"
    },
    {
  
… [4634 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address"
  ],
  "rows": [
    {
      "name": "FUN_180001000",
      "address": "6442455040"
    },
    {
      "name": "FUN_180001080",
      "address": "6442455168"
    },
    {
      "name": "FUN_180001180",
      "address": "6442455424"
    },
    {
      "name": "FUN_180001340",
      "address": "6442455872"
    },
    {
      "name": "FUN_180001490",
      "
… [2192 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name",
    "func_addr"
  ],
  "rows": [
    {
      "content": "SeDebugPrivilege",
      "func_name": "FUN_1800074f0",
      "func_addr": "6442480880"
    },
    {
      "content": "SeShutdownPrivilege",
      "func_name": "FUN_180007570",
      "func_addr": "6442481008"
    },
    {
      "content": "/c \"echo N|schtasks /create /tn \"%s\" /tr \"%s\" /sc 
… [1505 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name",
    "func_addr"
  ],
  "rows": [
    {
      "content": "empty",
      "func_name": "FUN_180005120",
      "func_addr": "6442471712"
    },
    {
      "content": "Win_7",
      "func_name": "FUN_180005120",
      "func_addr": "6442471712"
    },
    {
      "content": "Win_7_SP1",
      "func_name": "FUN_180005120",
      "func_addr": "6442471712"

… [4557 more chars]
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
      "name": "ControlService",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptAcquireContextW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptReleaseContext",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "LookupAccountSidW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "Op
… [3051 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "total_exports"
  ],
  "rows": [
    {
      "total_exports": "855"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde",
  "audit_path": "/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name"
  ],
  "rows": [
    {
      "content": "empty",
      "func_name": "FUN_180005120"
    },
    {
      "content": "Win_7",
      "func_name": "FUN_180005120"
    },
    {
      "content": "Win_7_SP1",
      "func_name": "FUN_180005120"
    },
    {
      "content": "Win_XP",
      "func_name": "FUN_180005120"
    },
    {
      "content": "Win_8",
  
… [1233 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/deep_dive/01-tools-raw.json` exists=`True` bytes=`150680` mtime=`2026-08-13T04:19:03.190360+00:00`
  - sha256: `3e2f293eaba44a4c35e209025da95eda8e309d957521a278c6de5fbf3a264669`
- **sql_evidence:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/deep_dive/05-deep-dive.json` exists=`True` bytes=`4824` mtime=`2026-08-12T18:18:47.216966+00:00`
  - sha256: `4ad4655d4d36d48bfd490ef2593228022889b6f85210f63f4a48d28ff24e94d4`

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
  "confidence": 98,
  "summary": "This 64-bit DLL (named 'win32k.dll' to masquerade as the legitimate Windows kernel component) is a fully-featured backdoor/RAT with 855 exports, HTTP-based C2, persistence via scheduled tasks, privilege escalation, process injection, and browser credential theft capabilities. It fingerprints the OS version for beaconing, checks its public IP via icanhazip.com, uses a custom HTTP protocol ('httprdc'/'httprex'), and employs multiple encryption layers (AES, XOR, Base64, SHA-2/BLAKE2). Evasion techniques are evident through masquerading as 'win32k.dll' and using encryption layers to hinder analysis. Exfiltration capabilities are not explicitly observed, though data theft is i
… [4024 more chars]
```

- **agentic:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`473751` mtime=`2026-08-12T18:18:47.216966+00:00`
  - sha256: `3ec8022820d306b10b846904fec7a1c2a2b9e14703ebda164fb388f9eaaa1672`

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

- **rule_yar:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/rule.yar` exists=`True` bytes=`1111` mtime=`2026-08-12T18:18:50.096956+00:00`
  - sha256: `92e1d8277cbbab7b76ac08ce91989ca7df9b9d55421e822c42c0951035a22ffb`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T18:18:50.098218+00:00
import "pe"
rule CADRE_v2_trojan_dyreza_battdil_8088f08a5636 {
    meta:
        description = "RevAI v2 auto rule for trojan.dyreza/battdil"
        sha256 = "8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde"
        family = "trojan_dyreza_battdil"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "=&&jL66Zl??A~" ascii wide
        $s1 = "&jL&6Zl6?A~?" ascii wide
        $s2 = "jL&&Zl66A~??" ascii wide
        $s3 = "L&&jl66Z~??A" ascii wide
        $s4 = "unknown_64bit" ascii wide
        $s5 = "daYdnceM" ascii wide
        $s6 = "daYdnceMm" ascii wide
        $s7 = "daYdnceMmb" ascii wide
        $
… [309 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/REPORT-MASTER-v2.md` exists=`True` bytes=`21031` mtime=`2026-08-14T02:42:36.075001+00:00`
  - sha256: `16b5e2c7207a5b87a95ebca477eb7b69f46e9375280befed0388d270092ebcd2`
- **REPORT_MASTER_v3:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/REPORT-MASTER-v3.md` exists=`True` bytes=`51354` mtime=`2026-08-14T02:55:06.586225+00:00`
  - sha256: `7e2b8d454f258a2842798f00225c71ac9922797559fe438408500293a2a0f998`
- **REPORT_v2:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/REPORT-v2.md` exists=`True` bytes=`21031` mtime=`2026-08-14T02:42:36.075001+00:00`
  - sha256: `16b5e2c7207a5b87a95ebca477eb7b69f46e9375280befed0388d270092ebcd2`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`62897` mtime=`2026-08-14T02:45:07.798002+00:00`
  - sha256: `9214df06030aa26c568e359bf149a2c00dd928e2004d4c48b33d0728665ac6db`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`63495` mtime=`2026-08-14T02:57:49.627670+00:00`
  - sha256: `a1fa81cc73d1c07bd38b57da23241d6ec3bc3e09f06e2070c0cb7a77bd55f303`
- **report_v2_json:** `/opt/samples/logs/8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde/report-v2.json` exists=`True` bytes=`24042` mtime=`2026-08-14T02:45:07.803002+00:00`
  - sha256: `afcb2805fedc5ac4b8bc0d58bd550c369524cdfa0544a032bca1f74e9a7bdb63`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:42:36 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Dyreza/Battdil
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Dyreza/Battdil Trojan Analysis Rep
… [20122 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 02:55:06 UTC

# RE Report — 8088f08a5636
_Generated 2026-08-14T02:55:06.578806+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=241c | cross_refs=True | llm_ok=True | runtime=54.12s -->

## Executive Summary

| Key Aspect | Details | Evidence Basis |
|------------|---------|----------------|
| Verdict | Malicious | Based on v1_summary score of 290 with 26 YARA matches and 74 CAPA rules (source: v1_summary, row: yara: 26 matches, row: capa: 74 rules), indicating widespread malicious patterns and high likelihood of harm. |
| Malware Family | Dyreza/Battdil | Supported by static analysis evidence
… [50435 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
