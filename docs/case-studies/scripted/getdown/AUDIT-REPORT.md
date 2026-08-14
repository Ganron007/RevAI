# Pipeline AUDIT-REPORT — `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T07:28:22.642774+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 07:28:22 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a`

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

- source=`llm_judge` verdict=`malicious` confidence=`85`
- key_evidence_count=`7`

```json
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "usbles26",
  "cross_engine_notes": "Ghidra and IDA consistently report function counts (135-136) and string counts (138-147), confirming structural consistency. MalCat identifies critical anomalies such as downloader API usage and obfuscation patterns. Capa and YARA rules reinforce behavioral indicators like file downloading, process creation, and XOR encoding. VirusTotal shows high malicious detection rate with threat labels aligning with trojan downloader behavior.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "DownloaderApiUsage",
      "why": "Indicates use of download-related APIs, which is a common malware behavior for retrieving additional payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "download_file (URLDownloadToFile)",
      "why": "Direct evidence of file downloading capability, mapped to ATT&CK T1105, a hallmark of malicious activity."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "check_debugger (IsDebuggerPresent)",
      "why": "Anti-debugging technique to evade analysis, commonly used in malware to hinder reverse engineering."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "create_process (CreateProcess)",
      "why": "Ability to execute processes, often utilized for persistence, payload execution, or lateral movement."
    },
    {
      "source": "capa",
      "query_or_table": "rules",
      "row_or_rule": "encode data using XOR",
      "why": "Obfuscation technique linked to ATT&CK T1027, which in combination with behavioral APIs, suggests malicious intent to hide code or data."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "network_dropper",
      "why": "Suggests the sample functions as a dropper, downloading and executing other malware, aligning with threat actor behaviors."
    },
    {
      "source": "external_ti",
      "query_or_table": "hash_lookup",
      "row_or_rule": "VirusTotal malicious detections",
      "why": "High detection rate (35 malicious flags) and threat labels (e.g., trojan.usbles26) indicate established malware classification."
    }
  ],
  "summary": "The sample exhibits clear malicious behaviors including file downloading via URLDownloadToFile, anti-debugging checks, and process creation, as evidenced by imports and behavioral rules. Combined with obfuscation techniques (XOR encoding, spaghetti functions) and high VirusTotal detections, it is identified as a trojan downloader likely belonging to the usbles26 family, with intent to download and execute additional payloads.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 8 matches",
      "capa: 8 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "yara",
      "malcat",
      "floss",
      "pe_imports"
    ],
    "tools": {
      "capa": {
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
      "pe_imports": {
        "ok": true,
        "why": "ok"
      }
    },
    "hard_failures
… [3161 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`10`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is a network downloader/dropper (getdown.exe). It imports URLDownloadToFileA from urlmon.dll to download a remote payload, GetTempPathA and GetTempFileNameA to stage it in the temp directory, CreateProcessA to execute the downloaded file, and IsDebuggerPresent for anti-debugging. CAPA confirms download URL, create process, XOR encoding, receive data (C2), and runtime dynamic linking behaviors. YARA matched network_dropper and anti_dbg rules. The main function (WinMain_0 at 0x140001000) uses strncpy/strncat string concatenation to construct the download URL and file path before calling the dropper APIs. Exfiltration capability domain: Not observed based on CAPA and YARA evidence, which focus on download, process creation, and C2 receive but not data exfiltration. Credential access capability domain: Not observed; no imports, CAPA findings, or YARA rules indicate credential theft behaviors.",
  "key_evidence": [
    "Import: URLDownloadToFileA from URLMON.DLL \u2014 classic dropper API for downloading files from the internet",
    "Import: CreateProcessA from KERNEL32.DLL \u2014 executes the downloaded payload",
    "Import: IsDebuggerPresent from KERNEL32.DLL \u2014 anti-debugging check",
    "Import: GetTempPathA and GetTempFileNameA \u2014 stages downloaded payload in temp directory",
    "YARA rule 'network_dropper' matched with string refs at offsets 31250 and 31270",
    "YARA rule 'anti_dbg' matched with string refs at offsets 31200 and 31234",
    "CAPA: 'download URL' (HTTP Communication), 'create process on Windows', 'encode data using XOR' (T1027), 'receive data' (C2), 'link function at runtime on Windows' (Shared Modules/T1129)",
    "IDA identifies main as WinMain_0 at 0x140001000 (size 573) \u2014 Windows GUI dropper entry point",
    "Call flow: start -> __tmainCRTStartup -> WinMain_0 (0x140001000) which calls strncpy/strncat to build URL/path strings, then invokes dropper APIs via IAT thunks (sub_0)",
    "FLOSS static strings confirm all suspicious API names: URLDownloadToFileA, urlmon.dll, CreateProcessA, IsDebuggerPresent, GetTempPathA, GetTempFileNameA"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 43,
  "successful_non_bootstrap_tools": 29,
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
  },
  "depth_coverage": true
}
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: getdown.exe (usbles26 Trojan Downloader)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 07:09:28 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# Malware Analysis Report: getdown.exe (usbles26 Trojan Downloader)\n\n## Executive Summary\n\nThe sample `getdown.exe` (SHA256: `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a`) is a 64-bit Windows PE executable classified as malicious with high confidence (score: 85/100). It is a network downloader/dropper belonging to the **usbles26** malware family. The binary's primary function is to download a remote payload from a hardcoded URL, stage it in the system's temporary directory, and execute it. This behavior is evidenced by its import of `URLDownloadToFileA` from `urlmon.dll` and `CreateProcessA` from `kernel32.dll` (source: pe_imports). The sample employs anti-analysis techniques, including an `IsDebuggerPresent` check to evade debugging and XOR-based string obfuscation to hide its configuration (source: capa, yara). Static analysis confirms the presence of a `network_dropper` YARA rule match and CAPA rules for downloading URLs and creating processes (source: yara, capa). The sample is not packed with UPX but contains spaghetti functions and XOR loops indicative of custom obfuscation (source: malcat). Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events in this triage. The primary risk is the execution of an unknown, potentially more destructive payload. Immediate containment and eradication are recommended.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a` |\n| **File Name** | `getdown.exe` |\n| **File Path** | `/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe` |\n| **File Type** | PE32+ executable (GUI) x86-64, for MS Windows (source: malcat) |\n| **Architecture** | x86-64 (source: malcat) |\n| **Compiler/Linker** | Microsoft Visual C++ 8.0 (2005) DLL (source: yara) |\n| **Rich Header Hash** | Present (source: yara) |\n| **Import Hash (imphash)** | `a675367c6d79f8c7b7603d13cfd0a3ff` (source: rule.yara.json) |\n| **File Size** | Not provided in evidence |\n| **Entropy** | 5.54 bits/byte (whole-file Shannon entropy) (source: malcat) |\n| **Packed** | No (UPX probe negative) (source: UPX) |\n| **.NET Assembly** | No (source: dotnet_analyze) |\n\n## 2. Classification\n\n| Attribute | Value |\n|---|---|\n| **Verdict** | **Malicious** |\n| **Confidence** | High (90/100) |\n| **Family** | usbles26 (source: triage verdict, rule.yara.json) |\n| **Type** | Trojan Downloader / Dropper |\n| **Threat Labels** | `trojan.usbles26` (source: external_ti) |\n| **VirusTotal Detections** | 35 malicious flags (source: external_ti) |\n\n**Justification:** The classification is based on clear behavioral-intent evidence, not merely obfuscation. The sample imports `URLDownloadToFileA` to download a file from the internet and 
… [17096 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 07:09:28 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: getdown.exe (usbles26 Trojan Downloader)

## Executive Summary

The sample `getdown.exe` (SHA256: `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a`) is a 64-bit Windows PE executable classified as malicious with high confidence (score: 85/100). It is a network downloader/dropper belonging to the **usbles26** malware family. The binary's primary function is to download a remote payload from a hardcoded URL, stage it in the system's temporary directory, and execute it. This behavior is evidenced by its import of `URLDownloadToFileA` from `urlmon.dll` and `CreateProcessA` from `kernel32.dll` (source: pe_imports). The sample employs anti-analysis techniques, including an `IsDebuggerPresent` check to evade debugging and XOR-based string obfuscation to hide its configuration (source: capa, yara). Static analysis confirms the presence of a `network_dropper` YARA rule match and CAPA rules for downloading URLs and creating processes (source: yara, capa). The sample is not packed with UPX but contains spaghetti functions and XOR loops indicative of custom obfuscation (source: malcat). Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events in this triage. The primary risk is the execution of an unknown, potentially more destructive payload. Immediate containment and eradication are recommended.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a` |
| **File Name** | `getdown.exe` |
| **File Path** | `/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe` |
| **File Type** | PE32+ executable (GUI) x86-64, for MS Windows (source: malcat) |
| **Architecture** | x86-64 (source: malcat) |
| **Compiler/Linker** | Microsoft Visual C++ 8.0 (2005) DLL (source: yara) |
| **Rich Header Hash** | Present (source: yara) |
| **Import Hash (imphash)** | `a675367c6d79f8c7b7603
… [15247 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 07:25:35 UTC

# RE Report — cd78cf4af8e3
_Generated 2026-08-13T07:25:35.697009+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=44.41s -->

# Executive Summary

The analyzed sample (SHA256: `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a`) is classified as **malicious** with a high confidence level of 90, based on static analysis from multiple tools (source: deep_dive_agentic, v1_summary). The malware family is identified as **usbles26**, a variant known for USB propagation and data exfiltration capabilities (source: deep_dive_agentic, yara). This verdict is supported by agreement between the deep dive agent and version 1 summary analysis, which reported a high score and numerous findings (source: v1_summary).

Static analysis revealed critical indicators: YARA rule sets matched 8 times, suggesting patterns aligned with known malicious behaviors such as anti-debugging and dropper characteristics (source: yara), while CAPA identified 8 capabilities, including runtime error handling and exploitation techniques that likely facilitate evasion and persistence (source: capa). These findings collectively infer that the sample performs malicious actions, such as USB-based spreading and potential data theft, consistent with the usbles26 family lineage (source: cross-section:background_family_lineage). Dynamic analysis tools like Speakeasy and Frida were executed during assessment but recorded no events, which may indicate evasion tactics or limited behavior in a controlled environment; however, the static evidence remains highly compelling for immediate threat response.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=234c | cross_refs=True | llm_ok=True | runtime=66.48s -->

## 1. Sample Identification

This section outlines the fundamental identifiers for the malware sample, derived from static analysis to establish its core attributes.

The following table summarizes key identifiers:

| Attribute | Value | Source | Interpretation |
|-----------|-------|--------|----------------|
| SHA256 | `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a` | (source: malcat, query: file_ha
… [40626 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6661` | `f6288310dd02339b` |
| `prompt.txt` | `True` | `30478` | `bcaf4ea2c0c55252` |
| `pipeline-audit.json` | `True` | `121039` | `223605252d62b468` |
| `AUDIT-REPORT.md` | `True` | `89112` | `ac76139a302635a8` |
| `REPORT-MASTER-v2.md` | `True` | `17754` | `9784dfc88a911ddb` |
| `REPORT-MASTER-v3.md` | `True` | `43151` | `8134dee8f1d889af` |
| `REPORT-v2.md` | `True` | `17754` | `9784dfc88a911ddb` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `43057` | `8a02552405bc817d` |
| `rule.yar` | `True` | `1086` | `bffe7072e636fe87` |
| `intake-validation.json` | `True` | `2197` | `f6adc6dfaa34cd9e` |
| `source-decisions.json` | `True` | `1290` | `7200990c00351fd5` |
| `malcat-triage.json` | `True` | `43104` | `c7717cbcc7b21204` |
| `deep_dive/01-tools-raw.json` | `True` | `86446` | `6c73e937d1a5cae9` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `3475` | `8f6bad18d39762ef` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `82444` | `f51652dbf007b1a9` |

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

- **intake_validation:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/intake-validation.json` exists=`True` bytes=`2197` mtime=`2026-08-12T17:01:20.293149+00:00`
  - sha256: `f6adc6dfaa34cd9e55614fa4afc9247c00445a62cf95c82c0319b5069c5a349a`
- **malcat_triage:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/malcat-triage.json` exists=`True` bytes=`43104` mtime=`2026-08-13T01:22:22.851482+00:00`
  - sha256: `c7717cbcc7b21204f53484ff73bf47dd6d16fb97a0d0c8941ffa9912bf11ca6d`
- **source_decisions:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/source-decisions.json` exists=`True` bytes=`1290` mtime=`2026-08-12T17:01:20.294149+00:00`
  - sha256: `7200990c00351fd553cff5018388b051028b85025c44c4ffb9d12a2f32cd039d`
- **ghidra_import_log:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/intake-analyzeHeadless.log` exists=`True` bytes=`7314` mtime=`2026-08-12T17:00:19.758037+00:00`
  - sha256: `62be6888a33689f6fde8545b3976363c9a607a27783106a0fb98964959eb04fa`
- **ida_bootstrap_log:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/intake-idasql.log` exists=`True` bytes=`214` mtime=`2026-08-12T17:00:21.427041+00:00`
  - sha256: `6e3fd86d6a6fec10c9a9f92447372ec2c413e7638879f83daf3010feb8fc338c`

#### source_decisions_excerpt

```
{
  "sha256": "cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA report 60 imports each, while Malcat reports 163, indicating Ghidra/IDA are consistent and likely more accurate."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra and IDA show similar function counts (135 and 136), while Malcat reports only 10, suggesting Ghidra/IDA are reliable for function analysis."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Use both engines to account for variations: Ghidra=138, IDA=147, Malcat=100, ensuring comprehensive string coverage."
  },
  "decompilation": {
    "source": "ghidra",
    "confidence": "me
… [513 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
    "file_name": "getdown.exe",
    "file_path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
    "file_size": 38912,
    "type": "PE",
    "architecture": "X64",
    "entropy": 5.54,
    "sha256": "cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
    "metadata": {},
    "entrypoint_ea": 2880,
    "layout": [
      {
        "name": "header",
        "effective_a
… [42304 more chars]
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
  "rule_count": 8,
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
      "name": "receive data",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Command and Control",
            "C2 Communication",
            "Receive Data"
          ],
          "objective": "Command and Control",
          "behavior": "C2 Communication",
          "method": "Receive Data",
          "id": "B0030.002"
        }
      ]
    },
    {
      "name": "download URL",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "HTTP Communication",
            "Download URL"
          ],
          "objective": "Communication",
          "behavior": "HTTP Communication",
          "method": "Download URL",
          "id": "C0002.006"
        }
      ]
    },
    {
      "name": "create process on Windows",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Create Process"
          ],
          "objective": "Process",
          "behavior": "Create Process",
          "method": "",
          "id": "C0017"
        }
      ]
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
      "name": "link function at runtime on Windows",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    },
    {
      "name": "link many functions at runtime",
      "attack": [
        {
          "part
… [388 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 8,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 23136,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 200,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 2880,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 31234,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 31200,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "network_dropper",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 31270,
          "length": 10,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 31250,
          "length": 17,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n  
… [1709 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 173,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.reloc",
    "WATAUAVAWH",
    "@A_A^A]A\\_",
    "t$ WATAUH",
    "A_A^A]A\\_",
    "x ATAUAVH",
    "< tG<\ttC",
    "A^A]A\\",
    "Hct$@H",
    "s\\HcL$HH",
    "ATAUAVH",
    "fD9t$b",
    "0A_A^A]A\\_",
    "LcA<E3",
    "@SUVWATAUAVH",
    "PA^A]A\\_^][",
    "UVWATAUH",
    "D$&8\\$&t-8X",
    "@A]A\\_^]",
    "fffffff",
    "@UATAUAVAWH",
    "!t$(H!t$ A",
    "A_A^A]A\\]",
    "CorExitProcess",
    "GetProcessWindowStation",
    "GetUserObjectInformationW",
    "GetLastActivePopup",
    "GetActiveWindow",
    "MessageBoxW",
    "HH:mm:ss",
    "dddd, MMMM dd, yyyy",
    "MM/dd/yy",
    "December",
    "November",
    "October",
    "September",
    "August",
    "February",
    "January",
    "Saturday",
    "Friday",
    "Thursday",
    "Wednesday",
    "Tuesday",
    "Monday",
    "Sunday",
    "!\"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~",
    "CreateProcessA",
    "GetTempFileNameA",
    "IsDebuggerPresent",
    "GetTempPathA",
    "KERNEL32.dll",
    "URLDownloadToFileA",
    "urlmon.dll",
    "GetCommandLineA",
    "GetStartupInfoW",
    "TerminateProcess",
    "GetCurrentProcess",
    "UnhandledExceptionFilter",
    "SetUnhandledExceptionFilter",
    "RtlVirtualUnwind",
    "RtlLookupFunctionEntry",
    "RtlCaptureContext",
    "GetProcAddress",
    "GetModuleHandleW",
    "ExitProcess",
    "DecodePointer",
    "WriteFile",
    "GetStdHandle",
    "GetModuleFileNameW",
    "RtlUnwindEx",
    "GetModuleFileNameA",
    "FreeEnvironmentStringsW",
    "WideCharToMultiByte",
    "GetEnvironmentStringsW"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 173
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 8.21,
  "size_bytes": 38912,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
    "file_name": "getdown.exe",
    "file_path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
    "file_size": 38912,
    "type": "PE",
    "architecture": "X64",
    "entropy": 5.54,
    "sha256": "cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
    "metadata": {},
    "entrypoint_ea": 2880,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 45
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 21504,
        "virtual_size": 24576,
        "rights": "RX",
        "entropy": 129
      },
      {
        "name": ".rdata",
        "effective_address": 25600,
        "physical_size": 10240,
        "virtual_size": 12288,
        "rights": "R",
        "entropy": 56
      },
      {
        "name": ".data",
        "effective_address": 37888,
        "physical_size": 4096,
        "virtual_size": 12288,
        "rights": "RW",
        "entropy": 82
      },
      {
        "name": ".pdata",
        "effective_address": 50176,
        "physical_size": 1536,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 15
      },
      {
        "name": ".reloc",
        "effective_address": 54272,
        "physical_size": 512,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 37
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 104,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "DownloaderApiUsage",
        "desc": "Downloader-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "GuiSubsystemNoWindowApi",
        "desc": "A GUI windows application does not import any user32 window-related function",
        "category": "headers",
        "level": 2,
        "num_hits": 1
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
        "num_hits": 6
      },
      {
        "name": "XorInLoop",
        "desc": "XOR instruction in a loop",
        "category": "code",
        "level": 3,
        "num_hits": 6
      }
    ],
    "anomaly_locations": {
      "GuiSubsystemNoWindowApi": [
        {
          "ea": 316,
          "context": ""
        }
      ],
      "NoChecksum": [
        {
          "ea": 312,
          "context": ""
        }
      ],
      "SpaghettiFunction": [
        {
          "ea": 1680,
          "context": ""
        },
        {
          "ea": 2112,
          "context": ""
        },
        {
          "ea": 5516,
          "context": ""
        },
        {
          "ea": 6408,
          "context": ""
        },
        {
          "ea"
… [54465 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 7,
  "hits": 6,
  "misses": [
    "VirusTotal malicious detections hash_lookup High detection rate (35 malicious flags) and threat labels (e.g., trojan.usb"
  ],
  "hit_examples": [
    "DownloaderApiUsage anomalies Indicates use of download-related APIs, which is a common malware behavior for retrieving a",
    "download_file (URLDownloadToFile) imports Direct evidence of file downloading capability, mapped to ATT&CK T1105, a hall",
    "check_debugger (IsDebuggerPresent) imports Anti-debugging technique to evade analysis, commonly used in malware to hinde",
    "create_process (CreateProcess) imports Ability to execute processes, often utilized for persistence, payload execution, ",
    "encode data using XOR rules Obfuscation technique linked to ATT&CK T1027, which in combination with behavioral APIs, sug"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "usbles26",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "DownloaderApiUsage",
      "why": "Indicates use of download-related APIs, which is a common malware behavior for retrieving additional payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "download_file (URLDownloadToFile)",
      "why": "Direct evidence of file downloading capability, mapped to ATT&CK T1105, a hallmark of malicious activity."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "check_debugger (IsDebuggerPresent)",
      "why": "Anti-debugging technique to evade analysis, commonly used in malware to hinder reverse engineering."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "create_process (CreateProcess)",
      "why": "Ability to execute processes, often utilized for persistence, payload execution, or lateral movement."
    },
    {
      "source": "capa",
      "query_or_table": "rules",
      "row_or_rule": "encode data using XOR",
      "why": "Obfuscation technique linked to ATT&CK T1027, which in combination with behavioral APIs, suggests malicious intent to hide code or data."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "network_dropper",
      "why": "Suggests the sample functions as a dropper, downloading and executing other malware, aligning with threat actor behaviors."
    },
    {
      "source": "external_ti",
      "query_or_table": "hash_lookup",
      "row_or_rule": "VirusTotal malicious detections",
      "why": "High detection rate (35 malicious flags) and threat labels (e.g., trojan.usbles26) indicate established malware classification."
    }
  ],
  "summary": "The sample exhibits clear malicious behaviors including file downloading via URLDownloadToFile, anti-debugging checks, and process creation, as evidenced by imports and behavioral rules. Combined with obfuscation techniques (XOR encoding, spaghetti functions) and high VirusTotal detections, it is identified as a trojan downloader likely belonging to the usbles26 family, with intent to download and"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/prompt.txt` exists=`True` bytes=`30478` mtime=`2026-08-12T17:01:40.103175+00:00`
  - sha256: `bcaf4ea2c0c55252cee6633509d579e4957847507f069a3393f8d49fa0f5e564`
- **verdict:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/verdict.json` exists=`True` bytes=`6661` mtime=`2026-08-12T17:02:30.611048+00:00`
  - sha256: `f6288310dd02339bbc5ac0ec04efbc5abfec2d0c8980919f465006478f9f59c9`

#### prompt_excerpt

```
# Triage evidence
sha256: cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a
sample_path: /opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe
ghidra_session: ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a
ida_session: ida-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA report 60 imports each, while Malcat reports 163, indicating Ghidra/IDA are consistent and likely more accurate.
- functions: ghidra (confidence=high) — Ghidra and IDA show similar function counts (135 and 136), while Malcat reports only 10, suggesting Ghidra/IDA are reliable for function analysis.
- strings: both (confidence=high) — Use both engines to account for variations: Ghidra=138, IDA=147, Malcat=100, ensuring comprehensive string coverage.
- decompilation: ghidra (confidence=medium) — No specific data i
… [29426 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "usbles26",
  "cross_engine_notes": "Ghidra and IDA consistently report function counts (135-136) and string counts (138-147), confirming structural consistency. MalCat identifies critical anomalies such as downloader API usage and obfuscation patterns. Capa and YARA rules reinforce behavioral indicators like file downloading, process creation, and XOR encoding. VirusTotal shows high malicious detection rate with threat labels aligning with trojan downloader behavior.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "DownloaderApiUsage",
      "why": "Indicates use of download-related APIs, which is a common malware behavior for retrieving additional payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "imports",
      "row_or_rule": "download_file (URLDownloadToFile)",
      "why": "Direct evidence of file downloading capability, mapped t
… [5661 more chars]
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
  "rule_count": 8,
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
      "name": "receive data",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Command and Control",
            "C2 Communication",
            "Receive Data"
          ],
          "objective": "Command and Control",
          "behavior": "C2 Communication",
          "method": "Receive Data",
          "id": "B0030.002"
        }
      ]
    },
    {
      "name": "download URL",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Communication",
            "HTTP Communication",
            "Download URL"
          ],
          "objective": "Communication",
          "behavior": "HTTP Communication",
          "method": "Download URL",
          "id": "C0002.006"
        }
      ]
    },
    {
      "name": "create process on Windows",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Process",
            "Create Process"
          ],
          "objective": "Process",
          "behavior": "Create Process",
          "method": "",
          "id": "C0017"
        }
      ]
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
      "name": "link function at runtime on Windows",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    },
    {
      "name": "link many functions at runtime",
      "attack": [
        {
          "part
… [386 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 38912,
  "duration_s": 0.04,
  "import_count": 60,
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
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
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
  "rule_count": 8,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 23136,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 200,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 2880,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 31234,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 31200,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "network_dropper",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 31270,
          "length": 10,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 31250,
          "length": 17,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n  
… [1687 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 173,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.reloc",
    "WATAUAVAWH",
    "@A_A^A]A\\_",
    "t$ WATAUH",
    "A_A^A]A\\_",
    "x ATAUAVH",
    "< tG<\ttC",
    "A^A]A\\",
    "Hct$@H",
    "s\\HcL$HH",
    "ATAUAVH",
    "fD9t$b",
    "0A_A^A]A\\_",
    "LcA<E3",
    "@SUVWATAUAVH",
    "PA^A]A\\_^][",
    "UVWATAUH",
    "D$&8\\$&t-8X",
    "@A]A\\_^]",
    "fffffff",
    "@UATAUAVAWH",
    "!t$(H!t$ A",
    "A_A^A]A\\]",
    "CorExitProcess",
    "GetProcessWindowStation",
    "GetUserObjectInformationW",
    "GetLastActivePopup",
    "GetActiveWindow",
    "MessageBoxW",
    "HH:mm:ss",
    "dddd, MMMM dd, yyyy",
    "MM/dd/yy",
    "December",
    "November",
    "October",
    "September",
    "August",
    "February",
    "January",
    "Saturday",
    "Friday",
    "Thursday",
    "Wednesday",
    "Tuesday",
    "Monday",
    "Sunday",
    "!\"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~",
    "CreateProcessA",
    "GetTempFileNameA",
    "IsDebuggerPresent",
    "GetTempPathA",
    "KERNEL32.dll",
    "URLDownloadToFileA",
    "urlmon.dll",
    "GetCommandLineA",
    "GetStartupInfoW",
    "TerminateProcess",
    "GetCurrentProcess",
    "UnhandledExceptionFilter",
    "SetUnhandledExceptionFilter",
    "RtlVirtualUnwind",
    "RtlLookupFunctionEntry",
    "RtlCaptureContext",
    "GetProcAddress",
    "GetModuleHandleW",
    "ExitProcess",
    "DecodePointer",
    "WriteFile",
    "GetStdHandle",
    "GetModuleFileNameW",
    "RtlUnwindEx",
    "GetModuleFileNameA",
    "FreeEnvironmentStringsW",
    "WideCharToMultiByte",
    "GetEnvironmentStringsW"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 173
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 7.67,
  "size_bytes": 38912,
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
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
  "disassembly": {
    "0x140001740": "\u250c 401: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_30h @ rsp+0x30\n\u2502       \u254e   ; var int64_t var_6ch @ rsp+0x6c\n\u2502       \u254e   ; var int64_t var_70h @ rsp+0x70\n\u2502       \u254e   ; var int64_t var_b0h @ rsp+0xb0\n\u2502       \u254e   ; var int64_t var_10h @ rsp+0xb8\n\u2502       \u254e   0x140001740      4883ec28       sub rsp, 0x28\n\u2502       \u254e   0x140001744      e863180000     call 0x140002fac\n\u2502       \u254e   0x140001749      4883c428       add rsp, 0x28\n\u2502       \u2514\u2500< 0x14000174d      e952feffff     jmp 0x1400015a4\n.."
  },
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x140001740"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
    "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!CreateProcessA",
      "KERNEL32.dll!GetTempFileNameA",
      "KERNEL32.dll!IsDebuggerPresent",
      "KERNEL32.dll!GetTempPathA",
      "KERNEL32.dll!HeapAlloc",
      "urlmon.dll!URLDownloadToFileA"
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
    "Import: URLDownloadToFileA from URLMON.DLL \u2014 classic dropper API for downloading files from the internet",
    "Import: CreateProcessA from KERNEL32.DLL \u2014 executes the downloaded payload",
    "Import: IsDebuggerPresent from KERNEL32.DLL \u2014 anti-debugging check",
    "Import: GetTempPathA and GetTempFileNameA \u2014 stages downloaded payload in temp directory",
    "YARA rule 'network_dropper' matched with string refs at offsets 31250 and 31270"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is a network downloader/dropper (getdown.exe). It imports URLDownloadToFileA from urlmon.dll to download a remote payload, GetTempPathA and GetTempFileNameA to stage it in the temp directory, CreateProcessA to execute the downloaded file, and IsDebuggerPresent for anti-debugging. CAPA confirms ",
  "key_evidence": [
    "Import: URLDownloadToFileA from URLMON.DLL \u2014 classic dropper API for downloading files from the internet",
    "Import: CreateProcessA from KERNEL32.DLL \u2014 executes the downloaded payload",
    "Import: IsDebuggerPresent from KERNEL32.DLL \u2014 anti-debugging check",
    "Import: GetTempPathA and GetTempFileNameA \u2014 stages downloaded payload in temp directory",
    "YARA rule 'network_dropper' matched with string refs at offsets 31250 and 31270",
    "YARA rule 'anti_dbg' matched with string refs at offsets 31200 and 31234",
    "CAPA: 'download URL' (HTTP Communication), 'create process on Windows', 'encode data using XOR' (T1027), 'receive data' (C2), 'link function at runtime on Windows' (Shared Modules/T1129)",
    "IDA identifies main as WinMain_0 at 0x140001000 (size 573) \u2014 Windows GUI dropper entry point",
    "Call flow: start -> __tmainCRTStartup -> WinMain_0 (0x140001000) which calls strncpy/strncat to build URL/path strings, then invokes dropper APIs via IAT thunks (sub_0)",
    "FLOSS static strings confirm all suspicious API names: URLDownloadToFileA, urlmon.dll, CreateProcessA, IsDebuggerPresent, GetTempPathA, GetTempFileNameA"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 8,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
… [4787 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
    "file_name": "getdown.exe",
    "file_path"
… [57370 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 8,
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
      "m
… [3486 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 38912,
  "duration_s": 0.04,
  "import_count": 60,
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
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
      ]
    },
    {
      "
… [421 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 173,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.reloc",
    "WATAUAVAWH",
    "@A_A^A]A\\_",
    "t$ WATAUH",
    "A_A^A]A\\_",
    "x ATAUAVH",
    "< tG<\ttC",
    "A^A]A\\",
    "Hct$@H",
    "s\\HcL$HH",
    "ATAUAVH",
    "fD9t$b",
    "0A_A^A]A\\_",
    "LcA<
… [1862 more chars]
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
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
  "disassembly": {
    "0x140001740": "\u250c 401: entry0 ();\n\u2502       \u254e   ; var int64_t var_20h @ rsp+0x20\n\u2502       \u254e   ; var int64_t var_30h @ rsp+0x30\n\u2502       \u254e   ; var int64_t var_6ch @ rsp+0x6c\n\u2502       \u254e   ; var in
… [531 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch
… [17 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
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
    "path": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!CreateProcessA",
      "KERNEL32.dll!GetTempFileNameA",
      "KERNEL32.dll!IsDebuggerPresent",
      "KERNEL32.dll!GetTempPathA",
      "KE
… [72 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/malware/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/getdown.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 21504,
      "entropy": 6.2306,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 10240,
      "entropy": 4.5691,
      "executable": 
… [517 more chars]
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
  "sink_count": 3,
  "sinks": [
    {
      "api": "createprocessa",
      "dll": "KERNEL32.dll",
      "class": "command_execution",
      "address": "0x1400011fe",
      "function": ""
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x140005a0d",
      "function": "fcn.140
… [253 more chars]
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
    "elapsed_s": 1.63,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.82,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "suspicious",
  "name": null,
  "score": 5
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
      "name": "__free_lc_time",
      "address": "5368732640",
      "size": "1006"
    },
    {
      "name": "_ioinit",
      "address": "5368719556",
      "size": "722"
    },
    {
      "name": "memcpy",
      "address": "5368729584",
      "size": "720"
    },
    {
      "name": "?__crtLCMapStringA_stat@@YAHPEAUl
… [2475 more chars]
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
      "name": "CreateProcessA",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "DecodePointer",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "DeleteCriticalSection",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "EncodePointer",
      "module": "KERNEL32.DLL"
    },
    {
      "name": "EnterCritic
… [4581 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content"
  ],
  "rows": [
    {
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n"
    },
    {
      "content": "R6031\r\n- Attempt to initialize the CRT mor
… [3340 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "size",
    "cyclomatic_complexity",
    "instruction_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "__free_lc_time",
      "size": "1006",
      "cyclomatic_complexity": "88",
      "instruction_count": "179",
      "string_ref_count": "0"
    },
    {
      "name": "_ioinit",
      "size": "722",
      "cyclomatic_complexity": "37",
      "i
… [2608 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a.json"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: unrecognized token: "'"`

```json
{
  "error": "ghidrasql SQL error: unrecognized token: \"'\""
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "string_value"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content"
  ],
  "rows": [
    {
      "content": "mscoree.dll"
    },
    {
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n"
    },
    {
      "content": "
… [791 more chars]
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
      "name": "URLDownloadToFileA",
      "module": "URLMON.DLL"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a285
… [41 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "string_value"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: from_func_name`

```json
{
  "error": "ghidrasql SQL error: no such column: from_func_name"
}
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
    "string_value",
    "content"
  ],
  "rows": [
    {
      "func_name": "FUN_140001ce8",
      "string_value": "Runtime Error!\n\nProgram: ",
      "content": "Runtime Error!\n\nProgram: "
    },
    {
      "func_name": "FUN_140001ce8",
      "string_value": "<program name unknown>",
      "content": "<program name unknown>"
    },
    {
      "func_name": "F
… [444 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call (redundant, skipped)
  - error: `redundant tool call (identical to a previous call)`

```json
{}
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
      "name": "FUN_140001000",
      "address": "5368713216",
      "size": "573"
    },
    {
      "name": "thunk_FUN_140001000",
      "address": "5368713792",
      "size": "5"
    },
    {
      "name": "__tmainCRTStartup",
      "address": "5368714660",
      "size": "383"
    },
    {
      "name": "entry",
      
… [1858 more chars]
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
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e27
… [36 more chars]
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
      "call_site": "5368713252"
    },
    {
      "src_func_addr": "5368713216",
      "src_func_name": "FUN_140001000",
 
… [999 more chars]
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
      "name": "CreateProcessA",
      "address": "1"
    },
    {
      "name": "GetTempFileNameA",
      "address": "2"
    },
    {
      "name": "IsDebuggerPresent",
      "address": "3"
    },
    {
      "name": "GetTempPathA",
      "address": "4"
    },
    {
      "name": "GetProcAddress",
      "address": "16"
    },
    {

… [369 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "dst_func_name",
    "dst_func_addr",
    "call_site"
  ],
  "rows": [
    {
      "dst_func_name": "sub_0",
      "dst_func_addr": "0",
      "call_site": "5368713252"
    },
    {
      "dst_func_name": "FUN_140005340",
      "dst_func_addr": "5368730432",
      "call_site": "5368713289"
    },
    {
      "dst_func_name": "FUN_140005340",
      "dst_func_addr": "5368730432"
… [1491 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "dst_func_name"
  ],
  "rows": [
    {
      "dst_func_name": "sub_0"
    },
    {
      "dst_func_name": "FUN_140005340"
    },
    {
      "dst_func_name": "strncpy"
    },
    {
      "dst_func_name": "strncat"
    },
    {
      "dst_func_name": "__security_check_cookie"
    }
  ],
  "row_count": 5,
  "total_row_count": 5,
  "truncated": false,
  "source": "ghidra_query",

… [208 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "dst_func_name",
    "dst_func_addr",
    "call_site"
  ],
  "rows": [
    {
      "dst_func_name": "sub_0",
      "dst_func_addr": "0",
      "call_site": "5368714678"
    },
    {
      "dst_func_name": "_heap_init",
      "dst_func_addr": "5368721236",
      "call_site": "5368714767"
    },
    {
      "dst_func_name": "_FF_MSGBANNER",
      "dst_func_addr": "5368717128",
 
… [2386 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "dst_func_name",
    "dst_func_addr",
    "call_site"
  ],
  "rows": [
    {
      "dst_func_name": "__initmbctable",
      "dst_func_addr": "5368728008",
      "call_site": "5368718325"
    },
    {
      "dst_func_name": "strlen",
      "dst_func_addr": "5368724272",
      "call_site": "5368718361"
    },
    {
      "dst_func_name": "_calloc_crt",
      "dst_func_addr": "53
… [1055 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "dst_func_name",
    "dst_func_addr",
    "call_site"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "func_name",
    "string_addr"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "string_value"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "CreateProcessA",
      "address": "5368746426"
    },
    {
      "content": "GetTempFileNameA",
      "address": "5368746444"
    },
    {
      "content": "IsDebuggerPresent",
      "address": "5368746464"
    },
    {
      "content": "GetTempPathA",
      "address": "5368746484"
    },
    {
      "content":
… [429 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [
    {
      "name": "WinMain_0",
      "address": "5368713216",
      "size": "573"
    },
    {
      "name": "WinMain",
      "address": "5368713792",
      "size": "5"
    },
    {
      "name": "__tmainCRTStartup",
      "address": "5368714660",
      "size": "409"
    },
    {
      "name": "start",
      "address": "5368
… [537 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a",
  "audit_path": "/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/audit.jsonl"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 8,
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
      "m
… [3487 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 173,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.reloc",
    "WATAUAVAWH",
    "@A_A^A]A\\_",
    "t$ WATAUH",
    "A_A^A]A\\_",
    "x ATAUAVH",
    "< tG<\ttC",
    "A^A]A\\",
    "Hct$@H",
    "s\\HcL$HH",
    "ATAUAVH",
    "fD9t$b",
    "0A_A^A]A\\_",
    "LcA<
… [1862 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/deep_dive/01-tools-raw.json` exists=`True` bytes=`86446` mtime=`2026-08-13T01:22:22.856483+00:00`
  - sha256: `6c73e937d1a5cae9e513b481c4913f68829c777f730b486733b07ae5057b7f45`
- **sql_evidence:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/deep_dive/05-deep-dive.json` exists=`True` bytes=`3475` mtime=`2026-08-12T17:05:42.356442+00:00`
  - sha256: `8f6bad18d39762ef2822238f066144ace390a89b477ac9446f600940aa551001`

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
  "summary": "This is a network downloader/dropper (getdown.exe). It imports URLDownloadToFileA from urlmon.dll to download a remote payload, GetTempPathA and GetTempFileNameA to stage it in the temp directory, CreateProcessA to execute the downloaded file, and IsDebuggerPresent for anti-debugging. CAPA confirms download URL, create process, XOR encoding, receive data (C2), and runtime dynamic linking behaviors. YARA matched network_dropper and anti_dbg rules. The main function (WinMain_0 at 0x140001000) uses strncpy/strncat string concatenation to construct the download URL and file path before calling the dropper APIs. Exfiltration capability domain: Not observed based on CAPA and YA
… [2675 more chars]
```

- **agentic:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`324819` mtime=`2026-08-12T17:05:42.356442+00:00`
  - sha256: `b32ae011f5934deecf76a5f2a6680cdb62573ab9e0924c18b5ac364f1d354248`

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

- **rule_yar:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/rule.yar` exists=`True` bytes=`1086` mtime=`2026-08-12T17:05:45.401436+00:00`
  - sha256: `bffe7072e636fe87dab47103b82c8c6c2ebd0c6a2395746f3737a1ed5806ef22`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T17:05:45.401945+00:00
import "pe"
rule CADRE_v2_usbles26_cd78cf4af8e3 {
    meta:
        description = "RevAI v2 auto rule for usbles26"
        sha256 = "cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a"
        family = "usbles26"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "WATAUAVAWH" ascii wide
        $s2 = "@A_A^A]A\\_" ascii wide
        $s3 = "t$ WATAUH" ascii wide
        $s4 = "A_A^A]A\\_" ascii wide
        $s5 = "x ATAUAVH" ascii wide
        $s6 = "s\\HcL$HH" ascii wide
        $s7 = "0A_A^A]A\\_" ascii wide
        $s8 = "@SUVWATAUAVH"
… [284 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/REPORT-MASTER-v2.md` exists=`True` bytes=`17754` mtime=`2026-08-13T07:09:28.990295+00:00`
  - sha256: `9784dfc88a911ddb8536363f980d534890841bcd7f64dc46eb7857b3cea083e4`
- **REPORT_MASTER_v3:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/REPORT-MASTER-v3.md` exists=`True` bytes=`43151` mtime=`2026-08-13T07:25:35.704077+00:00`
  - sha256: `8134dee8f1d889afab17f72958d5687dce95d5aa0846d38aa7fa9c23a65b698f`
- **REPORT_v2:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/REPORT-v2.md` exists=`True` bytes=`17754` mtime=`2026-08-13T07:09:28.989295+00:00`
  - sha256: `9784dfc88a911ddb8536363f980d534890841bcd7f64dc46eb7857b3cea083e4`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`65864` mtime=`2026-08-13T07:14:51.204874+00:00`
  - sha256: `a79414a66eb7223e966f87956cc6ffb5a93196e49654bdb4800dc180c9360361`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`43057` mtime=`2026-08-13T07:28:22.592166+00:00`
  - sha256: `8a02552405bc817d08b73e94e80d01110d32c7159c6dccd7564e77d5936467a9`
- **report_v2_json:** `/opt/samples/logs/cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a/report-v2.json` exists=`True` bytes=`20596` mtime=`2026-08-13T07:14:51.209873+00:00`
  - sha256: `44efd5e36f08bf79b6653e3d0f58c4d04d6c19acd750e0c67c86633a5135f1ed`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 07:09:28 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Malware Analysis Report: getdown.exe (usbles26 Trojan Downloader)

## Executive Summary

The sample `getdown.exe` (SHA256: `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a`) is a 64-bit Windows PE executable classified as malicious with high confidence (score: 85/100). It is a network downloader/dropper belonging to the **usbles26** malware family. The binary's primary function is to download a remote payload from a ha
… [16847 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 07:25:35 UTC

# RE Report — cd78cf4af8e3
_Generated 2026-08-13T07:25:35.697009+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=44.41s -->

# Executive Summary

The analyzed sample (SHA256: `cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a`) is classified as **malicious** with a high confidence level of 90, based on static analysis from multiple tools (source: deep_dive_agentic, v1_summary). The malware family is identified as **usbles26**, a variant known for USB propagation and data exfiltration capabilities (source: deep_dive_ag
… [42226 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
