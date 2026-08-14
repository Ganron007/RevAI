# Pipeline AUDIT-REPORT — `a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-14T02:02:24.225864+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-14 02:02:24 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395`

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

- source=`llm_judge` verdict=`malicious` confidence=`40`
- key_evidence_count=`5`

```json
{
  "verdict": "malicious",
  "score": 40.0,
  "family_guess": "XMRig Miner",
  "cross_engine_notes": "Multiple analysis engines converge on identifying this sample as a cryptocurrency miner (XMRig) with malicious behaviors. Ghidra and IDA strings reveal mining usage and cryptonight algorithm references. MalCat's YARA and anomalies detect mining protocols and crypto API usage. Capa rules indicate keylogging and network activity. YARA matches include specific miner and keylogger rules, and external VirusTotal detections confirm high malicious classification.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "XMRIG_Miner",
      "why": "YARA rule directly matches the XMRig miner signature, confirming the sample's identity as cryptocurrency mining software."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "addr 6443065440 | Usage: xmrig [OPTIONS] ... cryptonight",
      "why": "String contains mining usage instructions and cryptonight algorithm references, providing evidence of cryptocurrency mining functionality."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "log keystrokes",
      "why": "Capa identifies keylogging behavior (ATT&CK T1056.001), which is a malicious input capture technique indicating credential theft or monitoring."
    },
    {
      "source": "malcat",
      "query_or_table": "YARA matches",
      "row_or_rule": "MiningProtocol",
      "why": "MalCat's YARA detects mining protocol, corroborating the presence of mining-related network communication."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "receive data, send data",
      "why": "Capa rules indicate network data transmission and reception, suggesting command-and-control or mining pool communication, which is a behavioral intent for malicious activity."
    }
  ],
  "summary": "The sample is identified as XMRig CPU miner version 2.6.2 with malicious behaviors including cryptocurrency mining and keylogging. Evidence from multiple tools shows mining algorithm references, keylogging capabilities, and network activity, supported by high external detections. This constitutes clear behavioral intent beyond obfuscation, warranting a malicious verdict.",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 23 matches",
      "capa: 43 rules"
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
    "hard_failures": [],
    "soft_failures": [],
    "missing": [],
    "not_applicable": [],
    "large_sample": false
  },
  "ti_enrich": {
    "ok": true,
    "providers": {
      "virustotal": {
        "ok": true,
        "malicious": 51,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 19,
        "reputation": 1,
        "popular_threat_classification": {
          "suggested_threat_label": "miner.toolxmr/xmr
… [2612 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`18`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "XMRig 2.6.2 Monero cryptocurrency miner DLL (built May 28, 2018 with MSVC). This is a 64-bit DLL that performs CryptoNight-family cryptocurrency mining, consuming victim CPU resources to mine Monero for the attacker. It escalates privileges via SeLockMemoryPrivilege and LSA APIs (LsaAddAccountRights, AdjustTokenPrivileges) to allocate huge pages for efficient mining. It connects to mining pools over stratum+tcp:// protocol with references to nicehash.com and minergate.com, includes a built-in 5% developer donation fee, and supports background/stealth operation. Anti-analysis includes IsDebuggerPresent and SetConsoleCtrlHandler imports. YARA rules matched AES S-box, SHA2/BLAKE2, and SHA3 constants \u2014 all consistent with CryptoNight mining internals. The sample has 2021 exports and high-complexity functions (CC up to 279), consistent with an obfuscated/packed mining library. Persistence mechanisms were not observed in the analysis, with no evidence of auto-start, registry modifications, or scheduled tasks for maintaining presence. Defense impairment is indicated by anti-analysis imports such as IsDebuggerPresent and SetConsoleCtrlHandler, which can be used to evade debugger detection and handle console control events to prevent termination, as seen in the DLL's import table {source: static analysis, query: import table, row: IsDebuggerPresent and SetConsoleCtrlHandler, why: these functions impair debugging and shutdown processes}.",
  "key_evidence": [
    "String 'XMRig 2.6.2\\n built on May 28 2018 with MSVC' at address 0x1800b66a8",
    "Full xmrig usage banner with CryptoNight/CryptoNight-Lite/CryptoNight-Heavy algorithm options",
    "String 'stratum+tcp://' at address 0x1800cf458 \u2014 mining pool connection protocol",
    "References to '.nicehash.com' and '.minergate.com' pool domains",
    "References to 'miner.fee.xmrig.com' and 'emergency.fee.xmrig.com' \u2014 built-in dev fee domains",
    "Function FUN_180064ed0 references 'SeLockMemoryPrivilege' for huge page memory allocation",
    "Import: AdjustTokenPrivileges (ADVAPI32.DLL) \u2014 privilege escalation",
    "Import: LsaAddAccountRights, LsaOpenPolicy (ADVAPI32.DLL) \u2014 LSA manipulation for privilege grants",
    "Import: SetPriorityClass (KERNEL32.DLL) \u2014 elevates process priority for mining",
    "Import: IsDebuggerPresent, SetConsoleCtrlHandler \u2014 anti-analysis/stealth capabilities",
    "Import: CreateThread \u2014 multi-threaded mining execution",
    "YARA match: RijnDael_AES_CHAR at offset 0x96550 \u2014 AES S-box for CryptoNight",
    "YARA match: SHA2_BLAKE2_IVs (8 hits) and SHA3_constants (8 hits) \u2014 mining algorithm internals",
    "YARA match: anti_dbg rule \u2014 SetConsoleCtrlHandler pattern for debugger evasion",
    "2021 exports in DLL \u2014 large attack surface for injection into other processes",
    "High-complexity functions: FUN_18003d590 (CC=279, 1398 instructions), FUN_180073a70 (CC=248, 1426 instructions)",
    "String 'donate-level' with default 5% (5 minutes per 100 minutes) \u2014 covert developer revenue",
    "Configurable max-cpu-usage, cpu-affinity, cpu-priority, background mode \u2014 evasion of detection"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 32,
  "successful_non_bootstrap_tools": 19,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format
… [1044 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: XMRig Miner DLL (SHA256: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395)",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-14 01:42:34 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a 64-bit Windows DLL (SHA256: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395) identified as XMRig version 2.6.2, a cryptocurrency mining application. The sample is classified as **malicious** due to its primary function of unauthorized cryptocurrency mining, which consumes victim CPU resources for the attacker's financial gain. The analysis reveals a sophisticated miner with capabilities for privilege escalation, anti-analysis evasion, and network communication with mining pools. Key findings include the presence of keylogging functionality, references to known mining pool domains, and the use of advanced memory allocation techniques to optimize mining performance. The sample's behavior constitutes a clear threat, warranting immediate containment and eradication measures.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|---|---|\n| **SHA256** | a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395 |\n| **File Type** | PE64 DLL (Dynamic Link Library) |\n| **Architecture** | x86-64 (64-bit) |\n| **Compiler/Linker** | MSVC (Visual Studio 2017) |\n| **Build Date** | May 28, 2018 (source: ghidra_query, string 'XMRig 2.6.2\\n built on May 28 2018 with MSVC') |\n| **Project Name** | 710 |\n| **Sample Path** | /opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin |\n| **Import Hash (Imphash)** | 0c4c8e94664e68ee06fc2a3faae408ec (source: rule.yara.json) |\n| **Entropy** | 6.56 bits/byte (source: MalCat, whole-file Shannon entropy) |\n| **Packed** | No (UPX probe returned 'Tested 0 file') (source: UPX unpack evidence) |\n\n## 2. Classification\n\n**Verdict: MALICIOUS**\n\n**Confidence: HIGH (90%)**\n\n**Family: XMRig Miner**\n\nThe classification is based on multiple, corroborating pieces of evidence that demonstrate clear malicious intent beyond mere obfuscation or protection. The sample's core functionality is cryptocurrency mining, which is inherently malicious when deployed without user consent on a victim's machine. The presence of keylogging capabilities further solidifies this classification, as it indicates an intent to capture sensitive user input. The sample's behavior aligns with known malware tactics, techniques, and procedures (TTPs) for resource hijacking and credential theft.\n\n**Key Evidence for Malicious Verdict:**\n\n| Source | Evidence | Why it Indicates Malice |\n|---|---|---|\n| YARA | Rule 'XMRIG_Miner' matched | Directly identifies the sample as known cryptocurrency mining malware. (source: triage verdict.json, YARA matches) |\n| Ghidra | String 'Usage: xmrig [OPTIONS] ... cryptonight' | Contains mining usage instructions and references to the CryptoNight algorithm, confirming mining functionality. (source: triage verdict.json, Ghidra strings) |
… [21183 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 01:42:34 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a 64-bit Windows DLL (SHA256: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395) identified as XMRig version 2.6.2, a cryptocurrency mining application. The sample is classified as **malicious** due to its primary function of unauthorized cryptocurrency mining, which consumes victim CPU resources for the attacker's financial gain. The analysis reveals a sophisticated miner with capabilities for privilege escalation, anti-analysis evasion, and network communication with mining pools. Key findings include the presence of keylogging functionality, references to known mining pool domains, and the use of advanced memory allocation techniques to optimize mining performance. The sample's behavior constitutes a clear threat, warranting immediate containment and eradication measures.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395 |
| **File Type** | PE64 DLL (Dynamic Link Library) |
| **Architecture** | x86-64 (64-bit) |
| **Compiler/Linker** | MSVC (Visual Studio 2017) |
| **Build Date** | May 28, 2018 (source: ghidra_query, string 'XMRig 2.6.2\n built on May 28 2018 with MSVC') |
| **Project Name** | 710 |
| **Sample Path** | /opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin |
| **Import Hash (Imphash)** | 0c4c8e94664e68ee06fc2a3faae408ec (source: rule.yara.json) |
| **Entropy** | 6.56 bits/byte (source: MalCat, whole-file Shannon entropy) |
| **Packed** | No (UPX probe returned 'Tested 0 file') (source: UPX unpack evidence) |

## 2. Classification

**Verdict: MALICIOUS**

**Confidence: HIGH (90%)**

**Family: XMRig Miner**

The classification is based on multiple, corroborating pieces of evidence that demonstrate clear malicious intent beyond mere obfuscation or protection. The sample's core functionality is cryptocurrency mining, which is inherently malicious when deployed without user consent
… [19250 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 01:54:12 UTC

# RE Report — a2923d838f2d
_Generated 2026-08-14T01:54:12.674984+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=238c | cross_refs=True | llm_ok=True | runtime=71.68s -->

## Executive Summary

This sample is **malicious** and classified as part of the **XMRig Miner** family, with high confidence (90%) based on static analysis. The verdict is corroborated by multiple detection engines, and the family identification is consistent with known mining malware behaviors.

| Attribute | Value | Confidence | Evidence Interpretation |
|-----------|-------|------------|------------------------|
| Verdict | Malicious | 90% | Supported by 23 YARA matches and 43 CAPA rules, indicating strong indicators of malicious code such as cryptocurrency mining artifacts (source: yara, capa). |
| Family | XMRig Miner | High | YARA rules specifically detect XMRig patterns, confirming the sample's lineage as a Monero miner often used for unauthorized resource exploitation (source: yara). |
| Agreement | LLM and v1 analysis agree | Consistent | Cross-engine consensus reduces the likelihood of false positives, enhancing assessment reliability. |

The malware is a 64-bit DLL likely designed to perform unauthorized cryptocurrency mining, which could lead to excessive resource consumption and potential system compromise. It exhibits behaviors aligned with XMRig miners, such as encryption use and network communication with mining pools, based on static analysis from tools like CAPA and YARA. Dynamic analysis tools were not referenced in the evidence, so behavioral insights are derived solely from static examination.

---

<!-- section: 1. Sample Identification | pass=2 | evidence=233c | cross_refs=True | llm_ok=True | runtime=63.5s -->

## 1. Sample Identification

This section outlines the key identifiers and characteristics of the analyzed sample, providing foundational context for subsequent analysis. All data is derived from static analysis, with no dynamic analysis performed for this identification phase.

| Identifier | Value | Notes |
|------------|-------|-------|
| SHA256 | a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395 | Unique hash for file identifica
… [47496 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6112` | `d38d148e7dad6545` |
| `prompt.txt` | `True` | `38130` | `9a027b5f4f534494` |
| `pipeline-audit.json` | `True` | `115747` | `56bda8692d8879fe` |
| `AUDIT-REPORT.md` | `True` | `85307` | `796904f7c104ae84` |
| `REPORT-MASTER-v2.md` | `True` | `21757` | `f51b0875f5a392b6` |
| `REPORT-MASTER-v3.md` | `True` | `50013` | `73630003552c5c49` |
| `REPORT-v2.md` | `True` | `21757` | `f51b0875f5a392b6` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `105748` | `5ef803418b2d5838` |
| `rule.yar` | `True` | `1085` | `969189e58de7a8e7` |
| `intake-validation.json` | `True` | `3001` | `11c39996445d40fa` |
| `source-decisions.json` | `True` | `2086` | `97556a158a29cef0` |
| `malcat-triage.json` | `True` | `136500` | `3335f24022355201` |
| `deep_dive/01-tools-raw.json` | `True` | `243241` | `75e931da5d2bbe40` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4544` | `b7a0cf72564a7c55` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `228888` | `002a62cb571d6b08` |

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

- **intake_validation:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/intake-validation.json` exists=`True` bytes=`3001` mtime=`2026-08-13T00:36:51.996177+00:00`
  - sha256: `11c39996445d40fa1f0d93505e999d637c0521ee170fc598c02302d5cec8597a`
- **malcat_triage:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/malcat-triage.json` exists=`True` bytes=`136500` mtime=`2026-08-14T01:34:37.120844+00:00`
  - sha256: `3335f24022355201927bcd5c92703379002d4c0a70e44460967063cbc598038a`
- **source_decisions:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/source-decisions.json` exists=`True` bytes=`2086` mtime=`2026-08-13T00:36:51.996177+00:00`
  - sha256: `97556a158a29cef09f5e06bd4456c19aa6c0925406b2fe6abeeb6b1e48103e77`
- **ghidra_import_log:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/intake-analyzeHeadless.log` exists=`True` bytes=`7882` mtime=`2026-08-13T00:35:21.754126+00:00`
  - sha256: `ee3ea2a089658b66fae14896e5a66c931465314e02c96778335f2dc8e9c12ddc`
- **ida_bootstrap_log:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/intake-idasql.log` exists=`True` bytes=`218` mtime=`2026-08-13T00:35:26.739126+00:00`
  - sha256: `d5a5bff6f20fbc047bc8cfc7aebce268f8ab0f0ea89a336a41e6e16db9ffde71`

#### source_decisions_excerpt

```
{
  "sha256": "a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "{source: 'tool_summaries', query_or_table: 'ghidra and ida', row_or_rule: 'imports count', why: 'Both Ghidra and IDA report 187 imports, showing consistency and reliability for import extraction, while Malcat's count (863) diverges significantly.'}"
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "{source: 'tool_summaries', query_or_table: 'ghidra and ida', row_or_rule: 'functions count', why: 'Ghidra reports 1342 functions and IDA reports 1534, within a 14% difference, making Ghidra a standard tool for function analysis, whereas Malcat's count (10) is unreliable.'}"
  },
  "strings": {
    
… [1309 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
    "file_name": "dumped_dll.bin",
    "file_path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
    "file_size": 733696,
    "type": "PE",
    "architecture": "X64",
    "entropy": 6.56,
    "sha256": "a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395",
    "metadata": {
      "VersionInfo::CompanyName": "www.xmrig.com",
      "VersionInfo::FileDescription": "XMRig C
… [135700 more chars]
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
  "rule_count": 43,
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
      "name": "encrypt data using AES",
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
      "name": "encrypt data using AES via x86 extensions",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "i
… [6278 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 639648,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 616601,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$a",
          "offset": 13589,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$c0",
          "offset": 534868,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 534890,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 534897,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 534904,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 534911,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 534918,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 534925,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 534933,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES_CHAR",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$c0",
          "offset": 615696,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA3_constants",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$c0",
          "offset": 612424,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 612552,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 612568,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 612504,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 612408,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 612512,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c6",
… [10041 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2082,
  "strings_sampled": 80,
  "strings": [
    "P]P)]$7",
    "\\$ UVWf",
    "M.i,ud&",
    "efefefefefefefe",
    "efefefefefe",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "L$ SUVWH",
    "@WATAUAVAWH",
    "0A_A^A]A\\_",
    "t$ WAVAWH",
    "\\$ UVWAVAWH",
    "0A_A^_^]",
    "|$ ATAUAVAWH",
    "|$@A_A^A]A\\",
    "UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "SVWATAUAVAWH",
    "<$HkD$ XI",
    "`A_A^A]A\\_^[",
    "l$0L;C",
    "t$XL;C",
    "L$ SVWH",
    "K @81u",
    "6</uZH",
    "L$ UVWAUAWH",
    "d$`u>A",
    "0A_A]_^]",
    "2</uVH",
    "SUVWATAUAWH",
    "@8l$ tV",
    "A_A]A\\_^][",
    "|$ AVH",
    "w+H;G v",
    "w(H;G v",
    "^H;G v",
    "t$ WATAUAVAWH",
    "WAVAWH",
    "I9y }@I",
    "I;y }:I",
    "I9y s@I",
    "I;y s:I",
    "H9C }*H",
    "TUUUUUU",
    "H9C s*H",
    "UATAUAVAWH",
    "A_A^A]A\\]",
    "pA_A^A]A\\_^]",
    "@WAVAWH",
    "0A_A^_",
    "|$ ATAVAWH",
    "H3;H3s",
    "A_A^A\\I",
    "SUVWATAUAVAWH",
    "n(H3/L36L3g",
    "8A_A^A]A\\_^][H",
    "L3#L3k",
    "0A_A^A]A\\_^]I",
    "hA_A^A]A\\_^][H",
    "WATAUAVAWH",
    "A_A^A]A\\_",
    "oL$0fL",
    "\\$Pfff",
    "o|$pfL",
    "\\$pfff",
    "ot$PfL",
    "ol$@fD",
    "@SWAVH",
    "I30I3h",
    "0A^_[I",
    "SVAVAWH",
    "hA_A^^[",
    "](L3>L3e",
    "H3D$0I3",
    "hA_A^^[H",
    "SATAWH"
  ],
  "per_category": {
    "decoded_strings": 3,
    "stack_strings": 0,
    "tight_strings": 4,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2075
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 90.09,
  "size_bytes": 733696,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
    "file_name": "dumped_dll.bin",
    "file_path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
    "file_size": 733696,
    "type": "PE",
    "architecture": "X64",
    "entropy": 6.56,
    "sha256": "a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395",
    "metadata": {
      "VersionInfo::CompanyName": "www.xmrig.com",
      "VersionInfo::FileDescription": "XMRig CPU miner",
      "VersionInfo::FileVersion": "2.6.2",
      "VersionInfo::LegalCopyright": "Copyright (C) 2016-2018 xmrig.com",
      "VersionInfo::OriginalFilename": "xmrig.exe",
      "VersionInfo::ProductName": "XMRig",
      "VersionInfo::ProductVersion": "2.6.2",
      "Exports::Module name": "xmrig.dll",
      "Debug::Date.Debug.Pogo": "2018-05-28 19:45:53"
    },
    "entrypoint_ea": 304096,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 91
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 563200,
        "virtual_size": 565248,
        "rights": "RX",
        "entropy": 126
      },
      {
        "name": ".rdata",
        "effective_address": 566272,
        "physical_size": 118272,
        "virtual_size": 118784,
        "rights": "R",
        "entropy": 100
      },
      {
        "name": ".data",
        "effective_address": 685056,
        "physical_size": 6144,
        "virtual_size": 16384,
        "rights": "RW",
        "entropy": 61
      },
      {
        "name": ".pdata",
        "effective_address": 701440,
        "physical_size": 18944,
        "virtual_size": 20480,
        "rights": "R",
        "entropy": 84
      },
      {
        "name": ".rsrc",
        "effective_address": 721920,
        "physical_size": 23040,
        "virtual_size": 24576,
        "rights": "R",
        "entropy": 116
      },
      {
        "name": ".reloc",
        "effective_address": 746496,
        "physical_size": 3072,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 31
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 120,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "BigStringHiScore",
        "desc": "string has more than 256 characters and high interest score",
        "category": "strings",
        "level": 3,
        "num_hits": 5
      },
      {
        "name": "CryptoApiUsage",
        "desc": "Crypto-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 2
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynamically",
        "category": "strings",
        "level": 3,
        "num_hits": 10
      },
      {
        "name": "HighXrefLoopingFunction",
        "desc": "Function contains a loop and has a lot of incoming references (string decryption candidate)",
        "category": "code",
        "level": 1,
        "num_hits": 8
      },
      {
        "name": "ManyHi
… [175048 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 5,
  "hits": 5,
  "misses": [],
  "hit_examples": [
    "XMRIG_Miner YARA matches YARA rule directly matches the XMRig miner signature, confirming the sample's identity as crypt",
    "addr 6443065440 | Usage: xmrig [OPTIONS] ... cryptonight Suspicious strings (Ghidra) String contains mining usage instru",
    "log keystrokes capa rules Capa identifies keylogging behavior (ATT&CK T1056.001), which is a malicious input capture tec",
    "MiningProtocol YARA matches MalCat's YARA detects mining protocol, corroborating the presence of mining-related network ",
    "receive data, send data capa rules Capa rules indicate network data transmission and reception, suggesting command-and-c"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "XMRig Miner",
  "score": 40.0,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "XMRIG_Miner",
      "why": "YARA rule directly matches the XMRig miner signature, confirming the sample's identity as cryptocurrency mining software."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "addr 6443065440 | Usage: xmrig [OPTIONS] ... cryptonight",
      "why": "String contains mining usage instructions and cryptonight algorithm references, providing evidence of cryptocurrency mining functionality."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "log keystrokes",
      "why": "Capa identifies keylogging behavior (ATT&CK T1056.001), which is a malicious input capture technique indicating credential theft or monitoring."
    },
    {
      "source": "malcat",
      "query_or_table": "YARA matches",
      "row_or_rule": "MiningProtocol",
      "why": "MalCat's YARA detects mining protocol, corroborating the presence of mining-related network communication."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "receive data, send data",
      "why": "Capa rules indicate network data transmission and reception, suggesting command-and-control or mining pool communication, which is a behavioral intent for malicious activity."
    }
  ],
  "summary": "The sample is identified as XMRig CPU miner version 2.6.2 with malicious behaviors including cryptocurrency mining and keylogging. Evidence from multiple tools shows mining algorithm references, keylogging capabilities, and network activity, supported by high external detections. This constitutes clear behavioral intent beyond obfuscation, warranting a malicious verdict."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/prompt.txt` exists=`True` bytes=`38130` mtime=`2026-08-14T01:37:08.429846+00:00`
  - sha256: `9a027b5f4f5344948835a592c07ae21228e00d6e98366b9ea769d62f267cd6a8`
- **verdict:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/verdict.json` exists=`True` bytes=`6112` mtime=`2026-08-14T01:37:51.562846+00:00`
  - sha256: `d38d148e7dad65455127f1dccb9eba5b3c6de0bad532bc10c6be65f1a5b8f3af`

#### prompt_excerpt

```
# Triage evidence
sha256: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395
sample_path: /opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin
ghidra_session: ghidra-pe-a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395
ida_session: ida-a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — {source: 'tool_summaries', query_or_table: 'ghidra and ida', row_or_rule: 'imports count', why: 'Both Ghidra and IDA report 187 imports, showing consistency and reliability for import extraction, while Malcat's count (863) diverges significantly.'}
- functions: ghidra (confidence=medium) — {source: 'tool_summaries', query_or_table: 'ghidra and ida', row_or_rule: 'functions count', why: 'Ghidra reports 1342 functions and IDA reports 1534, within a 14% difference, making Ghidra a standard tool for function analysis, whereas Malcat'
… [37066 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 40.0,
  "family_guess": "XMRig Miner",
  "cross_engine_notes": "Multiple analysis engines converge on identifying this sample as a cryptocurrency miner (XMRig) with malicious behaviors. Ghidra and IDA strings reveal mining usage and cryptonight algorithm references. MalCat's YARA and anomalies detect mining protocols and crypto API usage. Capa rules indicate keylogging and network activity. YARA matches include specific miner and keylogger rules, and external VirusTotal detections confirm high malicious classification.",
  "key_evidence": [
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "XMRIG_Miner",
      "why": "YARA rule directly matches the XMRig miner signature, confirming the sample's identity as cryptocurrency mining software."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "addr 6443065440 | Usage: xmrig [OPTIONS] ... cryptonigh
… [5112 more chars]
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
  "rule_count": 43,
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
      "name": "encrypt data using AES",
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
      "name": "encrypt data using AES via x86 extensions",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "i
… [6277 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 733696,
  "duration_s": 0.04,
  "import_count": 187,
  "signal_count": 4,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
  "rule_count": 23,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 639648,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 616601,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$a",
          "offset": 13589,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$c0",
          "offset": 534868,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 534890,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 534897,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 534904,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 534911,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 534918,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 534925,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 534933,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES_CHAR",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$c0",
          "offset": 615696,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA3_constants",
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
      "strings": [
        {
          "id": "$c0",
          "offset": 612424,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 612552,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 612568,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 612504,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 612408,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 612512,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$c6",
… [10019 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 2082,
  "strings_sampled": 80,
  "strings": [
    "P]P)]$7",
    "\\$ UVWf",
    "M.i,ud&",
    "efefefefefefefe",
    "efefefefefe",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "L$ SUVWH",
    "@WATAUAVAWH",
    "0A_A^A]A\\_",
    "t$ WAVAWH",
    "\\$ UVWAVAWH",
    "0A_A^_^]",
    "|$ ATAUAVAWH",
    "|$@A_A^A]A\\",
    "UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "SVWATAUAVAWH",
    "<$HkD$ XI",
    "`A_A^A]A\\_^[",
    "l$0L;C",
    "t$XL;C",
    "L$ SVWH",
    "K @81u",
    "6</uZH",
    "L$ UVWAUAWH",
    "d$`u>A",
    "0A_A]_^]",
    "2</uVH",
    "SUVWATAUAWH",
    "@8l$ tV",
    "A_A]A\\_^][",
    "|$ AVH",
    "w+H;G v",
    "w(H;G v",
    "^H;G v",
    "t$ WATAUAVAWH",
    "WAVAWH",
    "I9y }@I",
    "I;y }:I",
    "I9y s@I",
    "I;y s:I",
    "H9C }*H",
    "TUUUUUU",
    "H9C s*H",
    "UATAUAVAWH",
    "A_A^A]A\\]",
    "pA_A^A]A\\_^]",
    "@WAVAWH",
    "0A_A^_",
    "|$ ATAVAWH",
    "H3;H3s",
    "A_A^A\\I",
    "SUVWATAUAVAWH",
    "n(H3/L36L3g",
    "8A_A^A]A\\_^][H",
    "L3#L3k",
    "0A_A^A]A\\_^]I",
    "hA_A^A]A\\_^][H",
    "WATAUAVAWH",
    "A_A^A]A\\_",
    "oL$0fL",
    "\\$Pfff",
    "o|$pfL",
    "\\$pfff",
    "ot$PfL",
    "ol$@fD",
    "@SWAVH",
    "I30I3h",
    "0A^_[I",
    "SVAVAWH",
    "hA_A^^[",
    "](L3>L3e",
    "H3D$0I3",
    "hA_A^^[H",
    "SATAWH"
  ],
  "per_category": {
    "decoded_strings": 3,
    "stack_strings": 0,
    "tight_strings": 4,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 2075
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 89.92,
  "size_bytes": 733696,
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
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
  "disassembly": {
    "0x18004afe0": "\u250c 362: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg_78h);\n\u2502      \u254e\u254e   ; arg int64_t arg1 @ rcx\n\u2502      \u254e\u254e   ; arg int64_t arg2 @ rdx\n\u2502      \u254e\u254e   ; arg int64_t arg3 @ r8\n\u2502      \u254e\u254e   ; arg int64_t arg_78h @ rsp+0xd8\n\u2502      \u254e\u254e   ; var int64_t var_30h @ rsp+0x30\n\u2502      \u254e\u254e   ; var int64_t var_8h @ rsp+0x60\n\u2502      \u254e\u254e   ; var int64_t var_10h @ rsp+0x68\n\u2502      \u254e\u254e   0x18004afe0      48895c2408     mov qword [var_8h], rbx\n\u2502      \u254e\u254e   0x18004afe5      4889742410     mov qword [var_10h], rsi\n\u2502      \u254e\u254e   0x18004afea      57             push rdi\n\u2502      \u254e\u254e   0x18004afeb      4883ec20       sub rsp, 0x20\n\u2502      \u254e\u254e   0x18004afef      498bf8         mov rdi, r8                ; arg3\n\u2502      \u254e\u254e   0x18004aff2      8bda           mov ebx, edx               ; arg2\n\u2502      \u254e\u254e   0x18004aff4      488bf1         mov rsi, rcx               ; arg1\n\u2502      \u254e\u254e   0x18004aff7      83fa01         cmp edx, 1                 ; 1 ; arg2\n\u2502     \u250c\u2500\u2500\u2500< 0x18004affa      7505           jne 0x18004b001\n\u2502     \u2502\u254e\u254e   0x18004affc      e867040000     call 0x18004b468\n\u2502     \u2514\u2500\u2500\u2500> 0x18004b001      4c8bc7         mov r8, rdi\n\u2502      \u254e\u254e   0x18004b004      8bd3           mov edx, ebx\n\u2502      \u254e\u254e   0x18004b006      488bce         mov rcx, rsi\n\u2502      \u254e\u254e   0x18004b009      488b5c2430     mov rbx, qword [var_8h]\n\u2502      \u254e\u254e   0x18004b00e      488b742438     mov rsi, qword [var_10h]\n\u2502      \u254e\u254e   0x18004b013      4883c420       add rsp, 0x20\n\u2502      \u254e\u254e   0x18004b017      5f             pop rdi\n\u2502      \u2514\u2500\u2500< 0x18004b018      e98ffeffff     jmp 0x18004aeac\n..\n\u2502           ; CODE XREF from fcn.18004a490 @ 0x18004a490(x)",
    "0x18007f630": "\u250c 103: sym.xmrig.dll_Start (int64_t arg2);\n\u2502           ; arg int64_t arg2 @ rdx\n\u2502           ; var int64_t var_20h @ rsp+0x20\n\u2502           ; var int64_t var_30h @ rsp+0x30\n\u2502           ; var int64_t var_38h @ rsp+0x38\n\u2502           ; var int64_t var_360h @ rsp+0x360\n\u2502           0x18007f630      4053           push rbx\n\u2502           0x18007f632      4881ec7003..   sub rsp, 0x370\n\u2502           0x18007f639      48c7442420..   mov qword [var_20h], 0xfffffffffffffffe\n\u2502           0x18007f642      488d4c2430     lea rcx, [var_30h]\n\u2502           0x18007f647      e8045cfeff     call fcn.180065250\n\u2502           0x18007f64c      488d4c2430     lea rcx, [var_30h]\n\u2502           0x18007f651      e87a58feff     call fcn.180064ed0\n\u2502           0x18007f656      8bd8           mov ebx, eax\n\u2502           0x18007f658      488d0571b7..   lea rax, [0x18009add0]\n\u2502           0x18007f65f      4889442430     mov qword [var_30h], rax\n\u2502           0x18007f664      ba68010000     mov edx, 0x168             ; 360\n\u2502           0x18007f669      488b4c2438     mov rcx, qword [var_38h]\n\u2502           0x18007f66e      e81daefcff     call fcn.18004a490\n\u2502           0x18007f673      488b8c2460
… [7831 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
  "candidates": [
    "Found XOR 00 position 00000000: 00000120 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000120 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
    "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
    "exists": true
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
  "checked": 18,
  "hits": 18,
  "misses": [],
  "hit_examples": [
    "String 'XMRig 2.6.2\\n built on May 28 2018 with MSVC' at address 0x1800b66a8",
    "Full xmrig usage banner with CryptoNight/CryptoNight-Lite/CryptoNight-Heavy algorithm options",
    "String 'stratum+tcp://' at address 0x1800cf458 \u2014 mining pool connection protocol",
    "References to '.nicehash.com' and '.minergate.com' pool domains",
    "References to 'miner.fee.xmrig.com' and 'emergency.fee.xmrig.com' \u2014 built-in dev fee domains"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "XMRig 2.6.2 Monero cryptocurrency miner DLL (built May 28, 2018 with MSVC). This is a 64-bit DLL that performs CryptoNight-family cryptocurrency mining, consuming victim CPU resources to mine Monero for the attacker. It escalates privileges via SeLockMemoryPrivilege and LSA APIs (LsaAddAccountRights",
  "key_evidence": [
    "String 'XMRig 2.6.2\\n built on May 28 2018 with MSVC' at address 0x1800b66a8",
    "Full xmrig usage banner with CryptoNight/CryptoNight-Lite/CryptoNight-Heavy algorithm options",
    "String 'stratum+tcp://' at address 0x1800cf458 \u2014 mining pool connection protocol",
    "References to '.nicehash.com' and '.minergate.com' pool domains",
    "References to 'miner.fee.xmrig.com' and 'emergency.fee.xmrig.com' \u2014 built-in dev fee domains",
    "Function FUN_180064ed0 references 'SeLockMemoryPrivilege' for huge page memory allocation",
    "Import: AdjustTokenPrivileges (ADVAPI32.DLL) \u2014 privilege escalation",
    "Import: LsaAddAccountRights, LsaOpenPolicy (ADVAPI32.DLL) \u2014 LSA manipulation for privilege grants",
    "Import: SetPriorityClass (KERNEL32.DLL) \u2014 elevates process priority for mining",
    "Import: IsDebuggerPresent, SetConsoleCtrlHandler \u2014 anti-analysis/stealth capabilities",
    "Import: CreateThread \u2014 multi-threaded mining execution",
    "YARA match: RijnDael_AES_CHAR at offset 0x96550 \u2014 AES S-box for CryptoNight",
    "YARA match: SHA2_BLAKE2_IVs (8 hits) and SHA3_constants (8 hits) \u2014 mining algorithm internals",
    "YARA match: anti_dbg rule \u2014 SetConsoleCtrlHandler pattern for debugger evasion",
    "2021 exports in DLL \u2014 large attack surface for injection into other processes",
    "High-complexity functions: FUN_18003d590 (CC=279, 1398 instructions), FUN_180073a70 (CC=248, 1426 instructions)",
    "String 'donate-level' with default 5% (5 minutes per 100 minutes) \u2014 covert developer revenue",
    "Configurable max-cpu-usage, cpu-affinity, cpu-priority, background mode \u2014 evasion of detection"
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
      "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
… [13119 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
    "file_name": "dumped_dll.bin",
    "file_pat
… [177991 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 43,
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
… [9377 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 733696,
  "duration_s": 0.04,
  "import_count": 187,
  "signal_count": 4,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      "label
… [296 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 2082,
  "strings_sampled": 80,
  "strings": [
    "P]P)]$7",
    "\\$ UVWf",
    "M.i,ud&",
    "efefefefefefefe",
    "efefefefefe",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".pdata",
    "@.rsrc",
    "@.reloc",
    "L$ SUVWH",
    "@WATAUAVAWH",
    "0A_A^A]A\\_",
    "t$ WAVAWH",
    "\\$ UVWAVAWH",
    "0A_A^_^]",
… [1418 more chars]
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
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
  "disassembly": {
    "0x18004afe0": "\u250c 362: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg_78h);\n\u2502      \u254e\u254e   ; arg int64_t arg1 @ rcx\n\u2502      \u254e\u254e   ; arg int64_t arg2 @ rdx\n\u2502      \u254e\u254e   ; arg int
… [10931 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
  "candidates": [
    "Found XOR 00 position 00000000: 00000120 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000120 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_
… [16 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
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
    "path": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
    "exists": true
  }
}
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/710/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/dumped_dll.bin",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 563200,
      "entropy": 6.5266,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 118272,
      "entropy": 5.7108,
      "executable":
… [652 more chars]
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
  
… [1815 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 5,
  "sinks": [
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x180058ef2",
      "function": "fcn.180058eb4"
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x18005b1c1",
      "functio
… [620 more chars]
```

- **revai_tools_audit** ok=`False` checklist=`True` — Required checklist tool (revai_tools_audit)
  - error: `revai_tools_audit: timeout`

```json
{
  "error": "revai_tools_audit: timeout",
  "fail_open": true,
  "skipped": true,
  "reason": "not_applicable:timeout"
}
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {
      "peb_access": 3,
      "debugger_string": 3
    },
    "total_signals": 6,
    "functions_with_signals": 6,
    "elapsed_s": 69.95,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports":
… [159 more chars]
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
      "name": "FUN_180073a70",
      "address": "6442924656",
      "size": "8403"
    },
    {
      "name": "FUN_18002cba0",
      "address": "6442634144",
      "size": "6264"
    },
    {
      "name": "FUN_180015650",
      "address": "6442538576",
      "size": "6199"
    },
    {
      "name": "FUN_18001b8b0",
   
… [2378 more chars]
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
      "name": "CryptAcquireContextA",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptGenRandom",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptReleaseContext",
      "module": "ADVAPI32.DLL"
    },
    {
      "name":
… [6215 more chars]
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
      "content": "Usage: xmrig [OPTIONS]\nOptions:\n  -a, --algo=ALGO          specify the algorithm to use\n                             cryptonight\n                             cryptonight-lite\n                             cryptonight-heavy\n  -o, --url=URL            URL of mining server\n  -O, --userpass=U:P  
… [9069 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "cyclomatic_complexity",
    "size",
    "instruction_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_180073a70",
      "address": "6442924656",
      "cyclomatic_complexity": "248",
      "size": "8403",
      "instruction_count": "1426",
      "call_out_count": "244",
      "string_ref_count": "0"
    
… [6899 more chars]
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
      "name": "SetPriorityClass",
      "module": "KERNEL32.DLL"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395",
  "audit_path": "/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b
… [41 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "SchedulerKind",
      "address": "6443023288"
    },
    {
      "content": "SchedulingProtocol",
      "address": "6443023432"
    },
    {
      "content": "unknown node or service",
      "address": "6443092896"
    },
    {
      "content": "service not available for socket type",
      "address": "644309298
… [467 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "CreateThreadpoolTimer",
      "address": "6443022448"
    },
    {
      "content": "SetThreadpoolTimer",
      "address": "6443022472"
    },
    {
      "content": "WaitForThreadpoolTimerCallbacks",
      "address": "6443022496"
    },
    {
      "content": "CloseThreadpoolTimer",
      "address": "6443022528
… [4655 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "cpu-affinity",
      "address": "6443061152"
    },
    {
      "content": "cpu-affinity",
      "address": "6443061168"
    },
    {
      "content": "cpu-priority",
      "address": "6443061184"
    },
    {
      "content": "donate-level",
      "address": "6443061200"
    },
    {
      "content": "max-cpu-u
… [1493 more chars]
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
  "session_id": "ghidra-pe-a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395",
  "audit_path": "/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "NtSetInformationFile",
      "address": "6443095896"
    },
    {
      "content": "SleepConditionVariableCS",
      "address": "6443096136"
    },
    {
      "content": "SleepConditionVariableSRW",
      "address": "6443096168"
    },
    {
      "content": "SetConsoleCtrlHandler",
      "address": "6443135156
… [537 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "stratum+tcp://",
      "address": "6443069720"
    },
    {
      "content": ".nicehash.com",
      "address": "6443069816"
    },
    {
      "content": ".minergate.com",
      "address": "6443069848"
    },
    {
      "content": "miner.fee.xmrig.com",
      "address": "6443070488"
    },
    {
      "content"
… [544 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "FlsAlloc",
      "address": "6443022272"
    },
    {
      "content": "InitializeSRWLock",
      "address": "6443022856"
    },
    {
      "content": "AcquireSRWLockExclusive",
      "address": "6443022880"
    },
    {
      "content": "TryAcquireSRWLockExclusive",
      "address": "6443022904"
    },
    {
 
… [3854 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "Usage: xmrig [OPTIONS]\nOptions:\n  -a, --algo=ALGO          specify the algorithm to use\n                             cryptonight\n                             cryptonight-lite\n                             cryptonight-heavy\n  -o, --url=URL            URL of mining server\n  -O, --userpass=U:P       username:
… [3149 more chars]
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
      "func_name": "FUN_180049e54",
      "func_addr": "6442753620",
      "string_value": "FlsAlloc"
    },
    {
      "func_name": "__vcrt_FlsAlloc",
      "func_addr": "6442771808",
      "string_value": "FlsAlloc"
    },
    {
      "func_name": "__acrt_FlsAlloc",
      "func_addr": "6442824820",
    
… [6684 more chars]
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
      "name": "FUN_180001040",
      "address": "6442455104"
    },
    {
      "name": "FUN_180001090",
      "address": "6442455184"
    },
    {
      "name": "FUN_1800010cc",
      "address": "6442455244"
    },
    {
      "name": "FUN_1800010f8",
      "
… [1452 more chars]
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
      "func_name": "FUN_180063b40",
      "func_addr": "6442859328",
      "string_value": "background"
    },
    {
      "func_name": "FUN_180063b40",
      "func_addr": "6442859328",
      "string_value": "background"
    },
    {
      "func_name": "FUN_1800664c0",
      "func_addr": "6442869952",
    
… [7000 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395.json"
}
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
      "func_name": "FUN_180064ed0",
      "func_addr": "6442864336",
      "string_value": "SeLockMemoryPrivilege"
    },
    {
      "func_name": "FUN_180064ed0",
      "func_addr": "6442864336",
      "string_value": "SeLockMemoryPrivilege"
    }
  ],
  "row_count": 2,
  "total_row_count": 2,
  "truncate
… [247 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/deep_dive/01-tools-raw.json` exists=`True` bytes=`243241` mtime=`2026-08-14T01:34:37.131844+00:00`
  - sha256: `75e931da5d2bbe400ce75af131cb5a526727a11257d919c66296d2e113231115`
- **sql_evidence:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/deep_dive/05-deep-dive.json` exists=`True` bytes=`4544` mtime=`2026-08-13T00:57:49.667803+00:00`
  - sha256: `b7a0cf72564a7c55b2bf68e4b5c4ea3b6c39576f1f7b194944a44d8573dcb472`

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
  "summary": "XMRig 2.6.2 Monero cryptocurrency miner DLL (built May 28, 2018 with MSVC). This is a 64-bit DLL that performs CryptoNight-family cryptocurrency mining, consuming victim CPU resources to mine Monero for the attacker. It escalates privileges via SeLockMemoryPrivilege and LSA APIs (LsaAddAccountRights, AdjustTokenPrivileges) to allocate huge pages for efficient mining. It connects to mining pools over stratum+tcp:// protocol with references to nicehash.com and minergate.com, includes a built-in 5% developer donation fee, and supports background/stealth operation. Anti-analysis includes IsDebuggerPresent and SetConsoleCtrlHandler imports. YARA rules matched AES S-box, SHA2/B
… [3744 more chars]
```

- **agentic:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`712047` mtime=`2026-08-13T00:57:49.667803+00:00`
  - sha256: `6215c19bfd3de149762447de3c789609a034eba93ecb932acc966b59dd5a8a27`

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

- **rule_yar:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/rule.yar` exists=`True` bytes=`1085` mtime=`2026-08-13T00:57:52.670802+00:00`
  - sha256: `969189e58de7a8e79181f1e79f7bc1122951c1f0bf982680fc4ad819e4b13dc7`

#### excerpt

```
// yara_gen_v2.py — 2026-08-13T00:57:52.671515+00:00
import "pe"
rule CADRE_v2_xmrig_a2923d838f2d {
    meta:
        description = "RevAI v2 auto rule for xmrig"
        sha256 = "a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395"
        family = "xmrig"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "efefefefefefefe" ascii wide
        $s1 = "efefefefefe" ascii wide
        $s2 = "!This program cannot be run in DOS mode." ascii wide
        $s3 = "L$ SUVWH" ascii wide
        $s4 = "@WATAUAVAWH" ascii wide
        $s5 = "0A_A^A]A\\_" ascii wide
        $s6 = "t$ WAVAWH" ascii wide
        $s7 = "\\$ UVWAVAWH" ascii wide
        $s8 = "0A_A^_^]" asci
… [283 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/REPORT-MASTER-v2.md` exists=`True` bytes=`21757` mtime=`2026-08-14T01:42:34.387406+00:00`
  - sha256: `f51b0875f5a392b673f98bd93f63402566f4fd38de175c6c90fa806cbfed6e9f`
- **REPORT_MASTER_v3:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/REPORT-MASTER-v3.md` exists=`True` bytes=`50013` mtime=`2026-08-14T01:54:12.683366+00:00`
  - sha256: `73630003552c5c49ba0f75a5597bfc09a4e8dc6aa0b59a279ddd89d0f72fb127`
- **REPORT_v2:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/REPORT-v2.md` exists=`True` bytes=`21757` mtime=`2026-08-14T01:42:34.387406+00:00`
  - sha256: `f51b0875f5a392b673f98bd93f63402566f4fd38de175c6c90fa806cbfed6e9f`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`77121` mtime=`2026-08-14T01:46:24.197090+00:00`
  - sha256: `63099754e12152745f818bec6a7c46586ce9f4bd93d3ab8b5dde090f187823bc`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`105748` mtime=`2026-08-14T02:02:24.176407+00:00`
  - sha256: `5ef803418b2d583889a3b100a5fa302f846cb1aed06ab49b621826cb1d4682de`
- **report_v2_json:** `/opt/samples/logs/a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395/report-v2.json` exists=`True` bytes=`24683` mtime=`2026-08-14T01:46:24.202090+00:00`
  - sha256: `cce3200b22bada8354bef5ff1583fdeb1cd2c6adb33537f9ebe10ca50442a2c8`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 01:42:34 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a 64-bit Windows DLL (SHA256: a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395) identified as XMRig version 2.6.2, a cryptocurrency mining application. The sample is classified as **malicious** due to its primary function of unauthorized cryptocurrency mining, which consumes victim CPU resources for the attacker's financial gain. The analysis reveals a sophisticate
… [20850 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 01:54:12 UTC

# RE Report — a2923d838f2d
_Generated 2026-08-14T01:54:12.674984+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=238c | cross_refs=True | llm_ok=True | runtime=71.68s -->

## Executive Summary

This sample is **malicious** and classified as part of the **XMRig Miner** family, with high confidence (90%) based on static analysis. The verdict is corroborated by multiple detection engines, and the family identification is consistent with known mining malware behaviors.

| Attribute | Value | Confidence | Evidence Interpretation |
|-----------|-------|------------|-------------------
… [49096 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
