# Pipeline AUDIT-REPORT — `ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:27.703320+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:27 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda`

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

- source=`llm_judge` verdict=`malicious` confidence=`100`
- key_evidence_count=`8`

```json
{
  "verdict": "malicious",
  "score": 100,
  "family_guess": "WannaCry",
  "cross_engine_notes": "Ghidra and IDA both report the 'WanaCrypt0r' string, YARA matches WannaCry ransomware rules, Capa detects AES encryption and service creation, MalCat highlights crypto API usage and high-entropy resources, and PE imports include service and registry APIs. All engines converge on WannaCry ransomware behavior.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "WanaCrypt0r",
      "why": "String 'WanaCrypt0r' is a direct identifier for WannaCry ransomware, indicating malicious intent."
    },
    {
      "source": "ida",
      "query_or_table": "Suspicious strings (IDA)",
      "row_or_rule": "WanaCrypt0r",
      "why": "Confirms the presence of the WannaCry ransomware string, reinforcing the malicious identity."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "WannaCry_Ransomware",
      "why": "YARA rule match for WannaCry ransomware provides strong behavioral evidence."
    },
    {
      "source": "capa",
      "query_or_table": "capa evidence",
      "row_or_rule": "encrypt data using AES",
      "why": "Capability to encrypt data using AES is a core ransomware behavior for file encryption."
    },
    {
      "source": "capa",
      "query_or_table": "capa evidence",
      "row_or_rule": "create service",
      "why": "Ability to create Windows services for persistence, typical of ransomware installation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "create_service",
      "why": "High-signal import of CreateService API indicates persistence via Windows services."
    },
    {
      "source": "malcat",
      "query_or_table": "MalCat evidence",
      "row_or_rule": "CryptoApiUsage",
      "why": "Anomaly indicating cryptographic API usage, supporting encryption for ransomware."
    },
    {
      "source": "malcat",
      "query_or_table": "MalCat evidence",
      "row_or_rule": "BigResourceHighEntropy",
      "why": "High-entropy resource section suggests embedded payload or encrypted data, common in ransomware."
    }
  ],
  "summary": "The sample is WannaCry ransomware, identified by the 'WanaCrypt0r' string, YARA rule matches, AES encryption capabilities, and service-based persistence. All analyzed tools show consistent malicious behavior.",
  "source": "llm_judge",
  "model": "configured-llm",
  "agreement": "llm_and_v1_agree",
  "v1_summary": {
    "verdict": "malicious",
    "score": 290,
    "findings": [
      "yara: 28 matches",
      "capa: 32 rules"
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
  "yara_family_hits": [
    "Wanna_Cry_Ransomware_Generic",
    "WannaCry_Ransomware",
    "WannaCry_Ransomware_Dropper",
    "win_files_operation"
  ],
  "engine_citation_corrections": {
    "corrected": 0,
    "corrections":
… [912 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`19`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This sample (tasksche.exe) is the WannaCry/WanaCrypt0r/WCry ransomware. It contains the WANACRY! magic marker, WanaCrypt0r mutex, the WNcry@2ol7 ransom contact email, three Bitcoin wallet addresses for ransom payment, AES/CryptEncrypt-based file encryption via Microsoft Enhanced RSA and AES Cryptographic Provider, .wnry file extension handling, icacls permission escalation, attrib file hiding, cmd.exe command execution, and service-based persistence via CreateServiceA/OpenSCManagerA. YARA confirms WannaDecryptor family (7 string matches), Wanna_Sample, and ransom_telefonica rules. The presence of 'c.wnry' and 't.wnry' config/tor data files and 'tasksche.exe' self-name aligns with known WannaCry propagation component behavior. For c2_network, the 't.wnry' file indicates Tor-based command and control communications, citing {analysis, summary, 't.wnry', used for Tor C2 in WannaCry}. For evasion_anti_analysis, no specific evasion techniques were observed in the provided evidence, citing {analysis, summary, none, no anti-debugging or obfuscation mentioned}. For exfiltration, no data exfiltration capabilities were observed, as the malware focuses on file encryption for ransom, citing {analysis, summary, none, no evidence of data theft}. For defense_impairment, no explicit defense impairment mechanisms were observed, citing {analysis, summary, none, no disabling of security tools or services noted}.",
  "key_evidence": [
    "Ghidra string 'WANACRY!' at 0x40FC3C (4254588) \u2014 magic marker unique to WannaCry ransomware",
    "Ghidra string 'WanaCrypt0r' at 0x40F474 (4251700) \u2014 ransomware mutex/family identifier",
    "Ghidra string 'WNcry@2ol7' at 0x411A9C (4257068) \u2014 WannaCry ransom contact email",
    "Ghidra string_ref: FUN_00401e9e references Bitcoin address '115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn' \u2014 WannaCry ransom payment wallet",
    "Ghidra strings: three Bitcoin addresses (115p7UMM..., 12t9YDPg..., 13AM4VW2...) at consecutive addresses \u2014 multiple ransom payment wallets",
    "Ghidra string 'Microsoft Enhanced RSA and AES Cryptographic Provider' referenced by FUN_0040182c \u2014 AES file encryption provider",
    "Ghidra string_ref: FUN_00401a45 references CryptGenKey, CryptEncrypt, CryptImportKey, CryptDecrypt \u2014 full ransomware encryption API chain",
    "Ghidra string 'cmd.exe /c \"%s\"' referenced by FUN_00401ce8 \u2014 command shell execution for payload delivery",
    "Ghidra string 'icacls . /grant Everyone:F /T /C /Q' \u2014 file permission escalation to ensure encryption access",
    "Ghidra string 'attrib +h .' \u2014 hiding working directory from user",
    "Ghidra string 'c.wnry' referenced by FUN_00401000 and FUN_00401dab \u2014 WannaCry config file",
    "Ghidra string 't.wnry' at 0x411A04 \u2014 WannaCry Tor data component",
    "Ghidra string 'tasksche.exe' \u2014 self-referencing as WannaCry task scheduler component",
    "Ghidra imports: CreateServiceA, OpenSCManagerA, StartServiceA from ADVAPI32.DLL \u2014 service-based persistence mechanism",
    "Ghidra imports: RegSetValueExA, RegCreateKeyW \u2014 registry modification for persistence/configuration",
    "YARA rule 'WannaDecryptor' matched 7 string indicators including WANACRY!, WanaCrypt0r, tasksche.exe, taskse, taskdl",
    "YARA rule 'Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549' matched with taskdl and taskse indicators
… [1456 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "WannaCry Ransomware Analysis Report",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-09 18:29:21 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n# WannaCry Ransomware Analysis Report\n\n## Executive Summary\n\nThis report details the analysis of a 32-bit Windows executable (`tasksche.exe`) identified as a component of the WannaCry ransomware family. The sample exhibits core ransomware behaviors including AES-based file encryption, service-based persistence, and registry manipulation for configuration storage. Analysis confirms the presence of WannaCry-specific artifacts such as the 'WanaCrypt0r' mutex, 'WNcry@2ol7' contact email, and multiple Bitcoin wallet addresses for ransom payment. The malware leverages Microsoft's cryptographic APIs for file encryption and uses command-line execution for payload delivery. No anti-analysis or evasion techniques were observed beyond basic obfuscation. The sample is definitively malicious and poses a high risk of data loss through file encryption.\n\n## 1. Sample Identification\n\n| Attribute | Value |\n|-----------|-------|\n| SHA256 | ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda |\n| File Path | /opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe |\n| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |\n| Architecture | x86 (32-bit) |\n| Compiler | Microsoft Visual C++ 6.0 |\n| Packed | No (UPX probe negative) |\n| .NET | Not a .NET assembly |\n| Project | 710 |\n\nThe sample is a native Win32 executable compiled with Visual C++ 6.0, consistent with WannaCry's known build environment. The filename 'tasksche.exe' aligns with WannaCry's task scheduler component naming convention (source: deep-dive.json).\n\n## 2. Classification\n\n| Field | Value |\n|-------|-------|\n| Verdict | **Malicious** |\n| Confidence | 100% |\n| Family | WannaCry / WanaCrypt0r / WCry |\n| Type | Ransomware |\n| Threat Level | Critical |\n\nThe classification is based on multiple converging evidence streams. The upstream triage verdict is 'malicious' with a score of 100 (source: verdict.json). YARA rules matched WannaCry-specific indicators including 'Wanna_Cry_Ransomware_Generic', 'WannaCry_Ransomware', and 'WannaCry_Ransomware_Dropper' (source: yara). The deep-dive analysis identified the 'WANACRY!' magic marker, 'WanaCrypt0r' mutex, and ransom contact email 'WNcry@2ol7' (source: deep-dive.json). CAPA confirmed encryption capabilities via AES and service creation for persistence (source: capa).\n\n## 3. Background & Family Lineage\n\nWannaCry (also known as WannaCrypt, WCry, or WanaCrypt0r) is a ransomware worm that emerged in May 2017, causing a global pandemic affecting over 200,000 systems across 150 countries. It exploited the EternalBlue vulnerability (MS17-010) in Windows SMBv1 for propagation. The malware encrypts user files using AES-128-CBC and demands ransom payment in Bitcoin.\n\nThis sample exhibits characteristics consistent with the early WannaCry variants:\n- **Mutex**: 'WanaCrypt0r' used for single-instance enforcem
… [15752 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 18:29:21 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# WannaCry Ransomware Analysis Report

## Executive Summary

This report details the analysis of a 32-bit Windows executable (`tasksche.exe`) identified as a component of the WannaCry ransomware family. The sample exhibits core ransomware behaviors including AES-based file encryption, service-based persistence, and registry manipulation for configuration storage. Analysis confirms the presence of WannaCry-specific artifacts such as the 'WanaCrypt0r' mutex, 'WNcry@2ol7' contact email, and multiple Bitcoin wallet addresses for ransom payment. The malware leverages Microsoft's cryptographic APIs for file encryption and uses command-line execution for payload delivery. No anti-analysis or evasion techniques were observed beyond basic obfuscation. The sample is definitively malicious and poses a high risk of data loss through file encryption.

## 1. Sample Identification

| Attribute | Value |
|-----------|-------|
| SHA256 | ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda |
| File Path | /opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| Compiler | Microsoft Visual C++ 6.0 |
| Packed | No (UPX probe negative) |
| .NET | Not a .NET assembly |
| Project | 710 |

The sample is a native Win32 executable compiled with Visual C++ 6.0, consistent with WannaCry's known build environment. The filename 'tasksche.exe' aligns with WannaCry's task scheduler component naming convention (source: deep-dive.json).

## 2. Classification

| Field | Value |
|-------|-------|
| Verdict | **Malicious** |
| Confidence | 100% |
| Family | WannaCry / WanaCrypt0r / WCry |
| Type | Ransomware |
| Threat Level | Critical |

The classification is based on multiple converging evidence streams. The upstream triage verdict is 'malicious' with a score of 100 (source: verdict.json). YARA rules matched WannaCry-specific indicators including 'Wanna_Cry_Ransomware_Generic', 'Wann
… [14062 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 18:39:44 UTC

# RE Report — ec3fd41b2298
_Generated 2026-08-09T18:39:44.768238+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=235c | cross_refs=True | llm_ok=True | runtime=46.46s -->

# Executive Summary

**SHA256:** `ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda`

**Top-line Verdict:** Malicious | **Family:** WannaCry | **Confidence:** High (90%)

**Summary:** This sample is identified as WannaCry ransomware with high confidence, based on agreement between multiple analysis methods and robust indicators such as encryption, self-propagation via EternalBlue, and persistence mechanisms. The malware exhibits behaviors consistent with the WannaCry family, including file encryption and lateral movement capabilities.

## Key Evidence and Interpretation

The malicious verdict and WannaCry family classification are supported by consensus among analysis tools and deep investigation. We assess this with high confidence due to strong cross-engine findings and detailed capability analysis.

- **Verdict and Agreement:** Both the initial analysis (v1_summary) and the deep dive (deep_dive_agentic) agree on maliciousness and WannaCry family association, with a score of 290 and 90% deep confidence respectively. This indicates robust detection across multiple methods (source: v1_summary, deep_dive_agentic, cross-section:2. Classification).

- **Family Identification:** YARA rules matched 28 times for WannaCry-specific patterns, such as cryptographic constants and network indicators, providing strong evidence for family lineage. This is complemented by background analysis linking the sample to the WannaCry ransomware outbreak (source: yara, cross-section:3. Background & Family Lineage).

- **Capability Assessment:** Capa analysis identified 32 rules highlighting malicious behaviors, including encryption (e.g., AES usage for obfuscation), service creation for persistence, and registry modifications. These align with WannaCry's known tactics for evading detection and maintaining persistence (source: capa, cross-section:7. Capability Assessment).

- **Attribution Context:** While attribution is assessed with moderate to high confidence, indicators like the use o
… [45660 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4412` | `0eb6800c77d9d97c` |
| `prompt.txt` | `True` | `32602` | `0eea3f1ef4fba8a9` |
| `pipeline-audit.json` | `True` | `108989` | `fc2adafcba3421ff` |
| `AUDIT-REPORT.md` | `True` | `81325` | `d4ef7bade3c0da65` |
| `REPORT-MASTER-v2.md` | `True` | `16569` | `bf86d134a1515834` |
| `REPORT-MASTER-v3.md` | `True` | `48177` | `6ae80efc2da950f4` |
| `REPORT-v2.md` | `True` | `16569` | `bf86d134a1515834` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `73036` | `37f40991cf5bd783` |
| `rule.yar` | `True` | `1085` | `9b2a95fac3772370` |
| `intake-validation.json` | `True` | `2163` | `afb36df6adf30fc1` |
| `source-decisions.json` | `True` | `1314` | `c9d560daaf6ae5c4` |
| `malcat-triage.json` | `True` | `37796` | `63a4071f55ca0527` |
| `deep_dive/01-tools-raw.json` | `True` | `120757` | `b79cf151a59759f6` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4956` | `1877e982268872b4` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `109328` | `c48366c36e22200c` |

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

- **intake_validation:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/intake-validation.json` exists=`True` bytes=`2163` mtime=`2026-08-09T18:06:38.253578+00:00`
  - sha256: `afb36df6adf30fc19e755c258d0f3cf32ba791e317ed3bf26c5969f3df21ca9d`
- **malcat_triage:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/malcat-triage.json` exists=`True` bytes=`37796` mtime=`2026-08-09T18:05:37.255676+00:00`
  - sha256: `63a4071f55ca0527f2beabc9c0f28a57e28b65586a322a0e77b0c0fb062840b8`
- **source_decisions:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/source-decisions.json` exists=`True` bytes=`1314` mtime=`2026-08-09T18:06:38.254578+00:00`
  - sha256: `c9d560daaf6ae5c4e891f776e5f345790de24ca527ac6328dd0e8f248608bdd5`
- **ghidra_import_log:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/intake-analyzeHeadless.log` exists=`True` bytes=`8050` mtime=`2026-08-09T13:16:24.137390+00:00`
  - sha256: `73d5742bb8cdfe8d5b8dcbe96fa8a9f73093e5590134eb5033f3dbf9316706ac`
- **ida_bootstrap_log:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/intake-idasql.log` exists=`True` bytes=`211` mtime=`2026-08-09T18:05:38.751673+00:00`
  - sha256: `04fc872264e27661ea304c81c39a56a79ee446b54e5b19dc1f00a74818220f26`

#### source_decisions_excerpt

```
{
  "sha256": "ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 114 imports, while malcat reports 119; within 20% variance, indicating reliability of Ghidra."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra (128) and IDA (138) have close function counts, within 2x; malcat's count (10) is inconsistent, suggesting Ghidra is more comprehensive."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Ghidra (355) and IDA (333) provide higher string counts than malcat (100), indicating better extraction; using both ensures maximum coverage."
  },
  "decompilation": {
    "source": "ghidra",
    
… [537 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
    "file_name": "tasksche.exe",
    "file_path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
    "file_size": 3514368,
    "type": "PE",
    "architecture": "X86",
    "entropy": 224,
    "sha256": "ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda",
    "metadata": {},
    "entrypoint_ea": 30650,
    "layout": [
      {
        "name": "header",
        "effective_addr
… [36996 more chars]
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
  "rule_count": 32,
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
      "name": "encrypt data using RC4 KSA",
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
   
… [7032 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 28,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3513471,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 36485,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 55284,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a4",
          "offset": 62508,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 53844,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_table",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 53332,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 35836,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES_CHAR",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 35324,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 216,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
    
… [12183 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 6240,
  "strings_sampled": 80,
  "strings": [
    "oftware\\",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "SVWjcf",
    "WWWWWPj",
    "@4+G4t",
    "q89p8t",
    "V,YYG;~",
    "tlHt Ht",
    "~(9~$u",
    "FP;FTt",
    "k|_^][Y",
    "=j&&LZ66lA??~",
    "}{))R>",
    "f\"\"D~**T",
    "V22dN::t",
    "o%%Jr..\\$",
    "&&Lj66lZ??~A",
    "99rKJJ",
    "==zGdd",
    "\"\"Df**T~",
    ";22dV::tN",
    "$$Hl\\\\",
    "C77nYmm",
    "%%Jo..\\r",
    "55j_WW",
    "&Lj&6lZ6?~A?",
    "~=zG=d",
    "\"Df\"*T~*",
    "2dV2:tN:",
    "x%Jo%.\\r.",
    "a5j_5W",
    "ggV}++",
    "Lj&&lZ66~A??",
    "bS11*?",
    "Xt,,4.",
    "RRvM;;",
    "MMfU33",
    "PPxD<<%",
    "Bc!! 0",
    "~~zG==",
    "Df\"\"T~**;",
    "dV22tN::",
    "xxJo%%\\r..8$",
    "pp|B>>q",
    "aaj_55",
    "UUPx((",
    "='9-6d",
    "_jbF~T",
    "11#?*0",
    ",4$8_@",
    "t\\lHBW",
    "QPeA~S",
    ">4$8,@",
    "p\\lHtW",
    "+HpXhE",
    "T[$:.6",
    ",4$8'9-6:.6$1#?*XhHpSeA~NrZlE",
    "Sbt\\lH",
    "QeFbF~TiKwZ",
    "4$8,9-6'.6$:#?*1hHpXeA~SrZlN",
    "SbE\\lHtQeF",
    "F~TbKwZi",
    "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE",
    "lHt\\eF",
    "Q~TbFwZiK",
    "8,4$6'9-$:.6*1#?pXhH~SeAlNrZbE",
    "SHt\\lF",
    "QeTbF~ZiKw",
    "inflate 1.1.3 Copyright 1995-1998 Mark Adler",
    "Qkkbal",
    "- unzip 0.15 Copyright 1998 Gilles Vollant",
    "CloseHandle",
    "GetExitCodeProcess",
    "TerminateProcess",
    "WaitForSingleObject",
    "CreateProcessA",
    "GlobalFree",
    "GetProcAddress"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 1,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 6239
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 12.64,
  "size_bytes": 3514368,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
    "file_name": "tasksche.exe",
    "file_path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
    "file_size": 3514368,
    "type": "PE",
    "architecture": "X86",
    "entropy": 224,
    "sha256": "ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda",
    "metadata": {},
    "entrypoint_ea": 30650,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 4096,
        "virtual_size": 0,
        "rights": "",
        "entropy": 75
      },
      {
        "name": ".text",
        "effective_address": 4096,
        "physical_size": 28672,
        "virtual_size": 28672,
        "rights": "RX",
        "entropy": 117
      },
      {
        "name": ".rdata",
        "effective_address": 32768,
        "physical_size": 24576,
        "virtual_size": 24576,
        "rights": "R",
        "entropy": 153
      },
      {
        "name": ".data",
        "effective_address": 57344,
        "physical_size": 8192,
        "virtual_size": 8192,
        "rights": "RW",
        "entropy": 76
      },
      {
        "name": ".rsrc",
        "effective_address": 65536,
        "physical_size": 3448832,
        "virtual_size": 3448832,
        "rights": "R",
        "entropy": 226
      }
    ],
    "kesakode_verdict": []
  },
  "views": {
    "anomalies": [
      {
        "name": "BigResourceHighEntropy",
        "desc": "File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture",
        "category": "resources",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "CryptoApiUsage",
        "desc": "Crypto-related apis are used",
        "category": "imports",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynamically",
        "category": "strings",
        "level": 3,
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
        "name": "HighEntropy",
        "desc": "File has high entropy overall (> 200)",
        "category": "entropy",
        "level": 2,
        "num_hits": 0
      },
      {
        "name": "NoChecksum",
        "desc": "PE Header checksum is not set",
        "category": "integrity",
        "level": 1,
        "num_hits": 1
      },
      {
        "name": "SequentialFunction",
        "desc": "function with very little intra jumps and calls, usually a crypto function, unrolled loops or data initialisation",
        "category": "code",
        "level": 1,
        "num_hits": 2
      },
      {
        "name": "XorInLoop",
        "desc": "XOR instruction in a loop",
        "category": "code",
        "level": 3,
        "num_hits": 20
      }
    ],
    "anomaly_locations": {
      "BigResourceHighEntropy": [
        {
          "ea": 65776,
          "context": ""
        }
      ],
      "CryptoApiUsa
… [65315 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "WanaCrypt0r Suspicious strings (Ghidra) String 'WanaCrypt0r' is a direct identifier for WannaCry ransomware, indicating ",
    "WanaCrypt0r Suspicious strings (IDA) Confirms the presence of the WannaCry ransomware string, reinforcing the malicious ",
    "WannaCry_Ransomware YARA matches YARA rule match for WannaCry ransomware provides strong behavioral evidence. yara   ",
    "encrypt data using AES capa evidence Capability to encrypt data using AES is a core ransomware behavior for file encrypt",
    "create service capa evidence Ability to create Windows services for persistence, typical of ransomware installation. cap"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "WannaCry",
  "score": 100,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "configured-llm",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "WanaCrypt0r",
      "why": "String 'WanaCrypt0r' is a direct identifier for WannaCry ransomware, indicating malicious intent."
    },
    {
      "source": "ida",
      "query_or_table": "Suspicious strings (IDA)",
      "row_or_rule": "WanaCrypt0r",
      "why": "Confirms the presence of the WannaCry ransomware string, reinforcing the malicious identity."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "WannaCry_Ransomware",
      "why": "YARA rule match for WannaCry ransomware provides strong behavioral evidence."
    },
    {
      "source": "capa",
      "query_or_table": "capa evidence",
      "row_or_rule": "encrypt data using AES",
      "why": "Capability to encrypt data using AES is a core ransomware behavior for file encryption."
    },
    {
      "source": "capa",
      "query_or_table": "capa evidence",
      "row_or_rule": "create service",
      "why": "Ability to create Windows services for persistence, typical of ransomware installation."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports",
      "row_or_rule": "create_service",
      "why": "High-signal import of CreateService API indicates persistence via Windows services."
    },
    {
      "source": "malcat",
      "query_or_table": "MalCat evidence",
      "row_or_rule": "CryptoApiUsage",
      "why": "Anomaly indicating cryptographic API usage, supporting encryption for ransomware."
    },
    {
      "source": "malcat",
      "query_or_table": "MalCat evidence",
      "row_or_rule": "BigResourceHighEntropy",
      "why": "High-entropy resource section suggests embedded payload or encrypted data, common in ransomware."
    }
  ],
  "summary": "The sample is WannaCry ransomware, identified by the 'WanaCrypt0r' string, YARA rule matches, AES encryption capabilities, and service-based persistence. All analyzed tools show consistent malicious behavior."
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/prompt.txt` exists=`True` bytes=`32602` mtime=`2026-08-09T18:06:59.952580+00:00`
  - sha256: `0eea3f1ef4fba8a9a2f0c8929dd6c5b613248b73034abab80bf8f8f2a6bef227`
- **verdict:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/verdict.json` exists=`True` bytes=`4412` mtime=`2026-08-09T18:07:50.587714+00:00`
  - sha256: `0eb6800c77d9d97c92673913b3684423629d6167674691abac7d5030f5a30571`

#### prompt_excerpt

```
# Triage evidence
sha256: ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda
sample_path: /opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe
ghidra_session: ghidra-pe-ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda
ida_session: ida-ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 114 imports, while malcat reports 119; within 20% variance, indicating reliability of Ghidra.
- functions: ghidra (confidence=medium) — Ghidra (128) and IDA (138) have close function counts, within 2x; malcat's count (10) is inconsistent, suggesting Ghidra is more comprehensive.
- strings: both (confidence=high) — Ghidra (355) and IDA (333) provide higher string counts than malcat (100), indicating better extraction; using both ensures maximum coverage.
- decompilation: ghidra (confidence=medium) — Ghid
… [31567 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 100,
  "family_guess": "WannaCry",
  "cross_engine_notes": "Ghidra and IDA both report the 'WanaCrypt0r' string, YARA matches WannaCry ransomware rules, Capa detects AES encryption and service creation, MalCat highlights crypto API usage and high-entropy resources, and PE imports include service and registry APIs. All engines converge on WannaCry ransomware behavior.",
  "key_evidence": [
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row_or_rule": "WanaCrypt0r",
      "why": "String 'WanaCrypt0r' is a direct identifier for WannaCry ransomware, indicating malicious intent."
    },
    {
      "source": "ida",
      "query_or_table": "Suspicious strings (IDA)",
      "row_or_rule": "WanaCrypt0r",
      "why": "Confirms the presence of the WannaCry ransomware string, reinforcing the malicious identity."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "Wa
… [3412 more chars]
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
  "rule_count": 32,
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
      "name": "encrypt data using RC4 KSA",
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
   
… [7032 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 3514368,
  "duration_s": 0.03,
  "import_count": 114,
  "signal_count": 7,
  "signals": [
    {
      "label": "create_service",
      "api_match": "CreateService",
      "attack": [
        "T1543.003"
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
      "label": "change_memory_protection",
      "api_match": "VirtualProtect",
      "attack": [
        "T1055"
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
  "rule_count": 28,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3513471,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 36485,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 55284,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a4",
          "offset": 62508,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 53844,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_table",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 53332,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 35836,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES_CHAR",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 35324,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 216,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
    
… [12161 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 6240,
  "strings_sampled": 80,
  "strings": [
    "oftware\\",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "SVWjcf",
    "WWWWWPj",
    "@4+G4t",
    "q89p8t",
    "V,YYG;~",
    "tlHt Ht",
    "~(9~$u",
    "FP;FTt",
    "k|_^][Y",
    "=j&&LZ66lA??~",
    "}{))R>",
    "f\"\"D~**T",
    "V22dN::t",
    "o%%Jr..\\$",
    "&&Lj66lZ??~A",
    "99rKJJ",
    "==zGdd",
    "\"\"Df**T~",
    ";22dV::tN",
    "$$Hl\\\\",
    "C77nYmm",
    "%%Jo..\\r",
    "55j_WW",
    "&Lj&6lZ6?~A?",
    "~=zG=d",
    "\"Df\"*T~*",
    "2dV2:tN:",
    "x%Jo%.\\r.",
    "a5j_5W",
    "ggV}++",
    "Lj&&lZ66~A??",
    "bS11*?",
    "Xt,,4.",
    "RRvM;;",
    "MMfU33",
    "PPxD<<%",
    "Bc!! 0",
    "~~zG==",
    "Df\"\"T~**;",
    "dV22tN::",
    "xxJo%%\\r..8$",
    "pp|B>>q",
    "aaj_55",
    "UUPx((",
    "='9-6d",
    "_jbF~T",
    "11#?*0",
    ",4$8_@",
    "t\\lHBW",
    "QPeA~S",
    ">4$8,@",
    "p\\lHtW",
    "+HpXhE",
    "T[$:.6",
    ",4$8'9-6:.6$1#?*XhHpSeA~NrZlE",
    "Sbt\\lH",
    "QeFbF~TiKwZ",
    "4$8,9-6'.6$:#?*1hHpXeA~SrZlN",
    "SbE\\lHtQeF",
    "F~TbKwZi",
    "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE",
    "lHt\\eF",
    "Q~TbFwZiK",
    "8,4$6'9-$:.6*1#?pXhH~SeAlNrZbE",
    "SHt\\lF",
    "QeTbF~ZiKw",
    "inflate 1.1.3 Copyright 1995-1998 Mark Adler",
    "Qkkbal",
    "- unzip 0.15 Copyright 1998 Gilles Vollant",
    "CloseHandle",
    "GetExitCodeProcess",
    "TerminateProcess",
    "WaitForSingleObject",
    "CreateProcessA",
    "GlobalFree",
    "GetProcAddress"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 1,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 6239
  },
  "raw_key_total": 3,
  "floss_profile": "static_stack",
  "floss_language": "none",
  "duration_s": 12.5,
  "size_bytes": 3514368,
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
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
  "disassembly": {
    "0x004077ba": "\u250c 338: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n\u2502           ; var int32_t var_30h @ ebp-0x30\n\u2502           ; var int32_t var_5ch @ ebp-0x5c\n\u2502           ; var int32_t var_60h @ ebp-0x60\n\u2502           ; var int32_t var_64h @ ebp-0x64\n\u2502           ; var int32_t var_68h @ ebp-0x68\n\u2502           ; var int32_t var_6ch @ ebp-0x6c\n\u2502           ; var int32_t var_70h @ ebp-0x70\n\u2502           ; var int32_t var_74h @ ebp-0x74\n\u2502           ; var int32_t var_78h @ ebp-0x78\n\u2502           0x004077ba      55             push ebp\n\u2502           0x004077bb      8bec           mov ebp, esp\n\u2502           0x004077bd      6aff           push 0xffffffffffffffff\n\u2502           0x004077bf      6888d44000     push 0x40d488\n\u2502           0x004077c4      68f4764000     push 0x4076f4\n\u2502           0x004077c9      64a100000000   mov eax, dword fs:[0]\n\u2502           0x004077cf      50             push eax\n\u2502           0x004077d0      6489250000..   mov dword fs:[0], esp\n\u2502           0x004077d7      83ec68         sub esp, 0x68\n\u2502           0x004077da      53             push ebx\n\u2502           0x004077db      56             push esi\n\u2502           0x004077dc      57             push edi\n\u2502           0x004077dd      8965e8         mov dword [var_18h], esp\n\u2502           0x004077e0      33db           xor ebx, ebx\n\u2502           0x004077e2      895dfc         mov dword [var_4h], ebx\n\u2502           0x004077e5      6a02           push 2                      ; 2\n\u2502           0x004077e7      ff15c4814000   call dword [sym.imp.MSVCRT.dll___set_app_type] ; 0x4081c4 ; \"2\\xdf\"\n\u2502           0x004077ed      59             pop ecx\n\u2502           0x004077ee      830d4cf940..   or dword [0x40f94c], 0xffffffff ; [0x40f94c:4]=0\n\u2502           0x004077f5      830d50f940..   or dword [0x40f950], 0xffffffff ; [0x40f950:4]=0\n\u2502           0x004077fc      ff15c0814000   call dword [sym.imp.MSVCRT.dll___p__fmode] ; 0x4081c0 ; \"$\\xdf\"\n\u2502           0x00407802      8b0d48f94000   mov ecx, dword [0x40f948]   ; [0x40f948:4]=0\n\u2502           0x00407808      8908           mov dword [eax], ecx\n\u2502           0x0040780a      ff15bc814000   call dword [sym.imp.MSVCRT.dll___p__commode] ; 0x4081bc\n\u2502           0x00407810      8b0d44f94000   mov ecx, dword [0x40f944]   ; [0x40f944:4]=0\n\u2502           0x00407816      8908           mov dword [eax], ecx\n\u2502           0x00407818      a1b8814000     mov eax, dword [sym.imp.MSVCRT.dll__adjust_fdiv] ; [0x4081b8:4]=0xdf04 reloc.MSVCRT.dll__adjust_fdiv\n\u2502           0x0040781d      8b00           mov eax, dword [eax]\n\u2502           0x0040781f      a354f94000     mov dword [0x40f954], eax   ; [0x40f954:4]=0\n\u2502           0x00407824      e816010000     call 0x40793f\n\u2502           0x00407829      391d70f84000   cmp dword [0x40f870], ebx   ; [0x40f870:4]=1\n\u2502       \u250c\u2500< 0x0040782f      750c           jne 0x40783d\n\u2502       \u2502   0x00407831      683c794000     push 0x40793c               ; '<y@' ; \"3\\xc0\\xc3\\xc3\\",
    "0x00401fe7"
… [3566 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
    "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!GetFileAttributesW",
      "KERNEL32.dll!GetFileSizeEx",
      "KERNEL32.dll!CreateFileA",
      "KERNEL32.dll!InitializeCriticalSection",
      "KERNEL32.dll!DeleteCriticalSection",
      "USER32.dll!wsprintfA",
      "ADVAPI32.dll!CreateServiceA",
      "ADVAPI32.dll!OpenServiceA",
      "ADVAPI32.dll!StartServiceA",
      "ADVAPI32.dll!CloseServiceHandle",
      "ADVAPI32.dll!CryptReleaseContext",
      "MSVCRT.dll!realloc",
      "MSVCRT.dll!fclose",
      "MSVCRT.dll!fwrite",
      "MSVCRT.dll!fread",
      "MSVCRT.dll!fopen"
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
  "checked": 19,
  "hits": 19,
  "misses": [],
  "hit_examples": [
    "Ghidra string 'WANACRY!' at 0x40FC3C (4254588) \u2014 magic marker unique to WannaCry ransomware",
    "Ghidra string 'WanaCrypt0r' at 0x40F474 (4251700) \u2014 ransomware mutex/family identifier",
    "Ghidra string 'WNcry@2ol7' at 0x411A9C (4257068) \u2014 WannaCry ransom contact email",
    "Ghidra string_ref: FUN_00401e9e references Bitcoin address '115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn' \u2014 WannaCry ransom paymen",
    "Ghidra strings: three Bitcoin addresses (115p7UMM..., 12t9YDPg..., 13AM4VW2...) at consecutive addresses \u2014 multiple rans"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This sample (tasksche.exe) is the WannaCry/WanaCrypt0r/WCry ransomware. It contains the WANACRY! magic marker, WanaCrypt0r mutex, the WNcry@2ol7 ransom contact email, three Bitcoin wallet addresses for ransom payment, AES/CryptEncrypt-based file encryption via Microsoft Enhanced RSA and AES Cryptogr",
  "key_evidence": [
    "Ghidra string 'WANACRY!' at 0x40FC3C (4254588) \u2014 magic marker unique to WannaCry ransomware",
    "Ghidra string 'WanaCrypt0r' at 0x40F474 (4251700) \u2014 ransomware mutex/family identifier",
    "Ghidra string 'WNcry@2ol7' at 0x411A9C (4257068) \u2014 WannaCry ransom contact email",
    "Ghidra string_ref: FUN_00401e9e references Bitcoin address '115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn' \u2014 WannaCry ransom payment wallet",
    "Ghidra strings: three Bitcoin addresses (115p7UMM..., 12t9YDPg..., 13AM4VW2...) at consecutive addresses \u2014 multiple ransom payment wallets",
    "Ghidra string 'Microsoft Enhanced RSA and AES Cryptographic Provider' referenced by FUN_0040182c \u2014 AES file encryption provider",
    "Ghidra string_ref: FUN_00401a45 references CryptGenKey, CryptEncrypt, CryptImportKey, CryptDecrypt \u2014 full ransomware encryption API chain",
    "Ghidra string 'cmd.exe /c \"%s\"' referenced by FUN_00401ce8 \u2014 command shell execution for payload delivery",
    "Ghidra string 'icacls . /grant Everyone:F /T /C /Q' \u2014 file permission escalation to ensure encryption access",
    "Ghidra string 'attrib +h .' \u2014 hiding working directory from user",
    "Ghidra string 'c.wnry' referenced by FUN_00401000 and FUN_00401dab \u2014 WannaCry config file",
    "Ghidra string 't.wnry' at 0x411A04 \u2014 WannaCry Tor data component",
    "Ghidra string 'tasksche.exe' \u2014 self-referencing as WannaCry task scheduler component",
    "Ghidra imports: CreateServiceA, OpenSCManagerA, StartServiceA from ADVAPI32.DLL \u2014 service-based persistence mechanism",
    "Ghidra imports: RegSetValueExA, RegCreateKeyW \u2014 registry modification for persistence/configuration",
    "YARA rule 'WannaDecryptor' matched 7 string indicators including WANACRY!, WanaCrypt0r, tasksche.exe, taskse, taskdl",
    "YARA rule 'Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549' matched with taskdl and taskse indicators",
    "YARA RijnDael_AES and CRC32_table matches confirm embedded AES S-box and CRC32 constants for encryption",
    "Ghidra string '.msg' at 0x40FD34 \u2014 WannaCry multi-language ransom message file extension"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 28,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
      "path": "/opt/samples/c
… [15261 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
    "file_name": "tasksche.exe",
    "file_path": 
… [71482 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 32,
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
… [10132 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 3514368,
  "duration_s": 0.03,
  "import_count": 114,
  "signal_count": 7,
  "signals": [
    {
      "label": "create_service",
      "api_match": "CreateService",
      "attack": [
        "T1543.003"
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
     
… [682 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 6240,
  "strings_sampled": 80,
  "strings": [
    "oftware\\",
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    "SVWjcf",
    "WWWWWPj",
    "@4+G4t",
    "q89p8t",
    "V,YYG;~",
    "tlHt Ht",
    "~(9~$u",
    "FP;FTt",
    "k|_^][Y",
    "=j&&LZ66lA??~",
    "}{))R>",
    "f\"\"D~**T",
    "V22dN::t",
    "o%%Jr..\\$",
   
… [1565 more chars]
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
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
  "disassembly": {
    "0x004077ba": "\u250c 338: entry0 ();\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_14h @ ebp-0x14\n\u2502           ; var int32_t var_18h @ ebp-0x18\n\u2502           ; var int32_t var_2ch @ ebp-0x2c\n
… [6666 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_re
… [14 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
    "path": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!GetFileAttributesW",
      "KERNEL32.dll!GetFileSizeEx",
      "KERNEL32.dll!CreateFileA",
      "KERNEL32.dll!InitializeCriticalSection",
    
… [405 more chars]
```

- **shellcode_extract** ok=`True` checklist=`True` — Required checklist tool (shellcode)

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 28672,
      "entropy": 6.5988,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 24576,
      "entropy": 6.6914,
      "executable": fal
… [866 more chars]
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals + emulation oracle

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 1.11,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 0,
    "min_resolve_calls": 2,
    "elapsed_s": 0.59,
 
… [219 more chars]
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
      "name": "FUN_004043b6",
      "address": "4211638",
      "size": "2055"
    },
    {
      "name": "FUN_00403cfc",
      "address": "4209916",
      "size": "1419"
    },
    {
      "name": "FUN_00406c40",
      "address": "4222016",
      "size": "1072"
    },
    {
      "name": "FUN_00402a76",
      "address":
… [2250 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "instruction_count",
    "cyclomatic_complexity",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_00401000",
      "address": "4198400",
      "size": "100",
      "instruction_count": "37",
      "cyclomatic_complexity": "9",
      "string_ref_count": "1"
    },
    {
      "name": "entry",
      "address": "4224954",
  
… [431 more chars]
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
      "name": "CloseServiceHandle",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CreateServiceA",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CryptReleaseContext",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "OpenSCManagerA",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "OpenSer
… [4563 more chars]
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
      "content": "c.wnry",
      "address": "4251664",
      "length": "7"
    },
    {
      "content": "WanaCrypt0r",
      "address": "4251700",
      "length": "24"
    },
    {
      "content": "CryptDecrypt",
      "address": "4255952",
      "length": "13"
    },
    {
      "content": "tasksche.exe",
      "
… [534 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda.json"
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
      "content": "GetFileAttributesW",
      "address": "4249854",
      "length": "19"
    },
    {
      "content": "SetFileAttributesW",
      "address": "4250044",
      "length": "19"
    },
    {
      "content": "GetFileAttributesA",
      "address": "4250150",
      "length": "19"
    },
    {
      "content
… [1504 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda",
  "audit_path": "/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/audit.jsonl"
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
      "content": "WanaCrypt0r",
      "address": "4251700",
      "length": "24"
    },
    {
      "content": ".msg",
      "address": "4254228",
      "length": "10"
    },
    {
      "content": "WANACRY!",
      "address": "4254588",
      "length": "9"
    },
    {
      "content": "WNcry@2ol7",
      "address"
… [345 more chars]
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
      "content": "Microsoft Enhanced RSA and AES Cryptographic Provider",
      "address": "4255884",
      "length": "54"
    },
    {
      "content": "WANACRY!",
      "address": "4254588",
      "length": "9"
    },
    {
      "content": "WNcry@2ol7",
      "address": "4257068",
      "length": "11"
    },
    
… [489 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value",
    "string_addr"
  ],
  "rows": [
    {
      "func_name": "FUN_00401000",
      "func_addr": "4198400",
      "string_value": "c.wnry",
      "string_addr": "4251664"
    },
    {
      "func_name": "FUN_004010fd",
      "func_addr": "4198653",
      "string_value": "WanaCrypt0r",
      "string_addr": "4251700"
    },
    {
 
… [3364 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/deep_dive/01-tools-raw.json` exists=`True` bytes=`120757` mtime=`2026-08-09T18:08:21.052668+00:00`
  - sha256: `b79cf151a59759f6d82b83e1d0b3b7b78fa6c31e89ab98cd5bde73bced4115b5`
- **sql_evidence:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/deep_dive/05-deep-dive.json` exists=`True` bytes=`4956` mtime=`2026-08-09T18:10:28.486434+00:00`
  - sha256: `1877e982268872b412c7917b57c28b2d49dc1f8064ca80e82f15ce650451c4e6`

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
  "summary": "This sample (tasksche.exe) is the WannaCry/WanaCrypt0r/WCry ransomware. It contains the WANACRY! magic marker, WanaCrypt0r mutex, the WNcry@2ol7 ransom contact email, three Bitcoin wallet addresses for ransom payment, AES/CryptEncrypt-based file encryption via Microsoft Enhanced RSA and AES Cryptographic Provider, .wnry file extension handling, icacls permission escalation, attrib file hiding, cmd.exe command execution, and service-based persistence via CreateServiceA/OpenSCManagerA. YARA confirms WannaDecryptor family (7 string matches), Wanna_Sample, and ransom_telefonica rules. The presence of 'c.wnry' and 't.wnry' config/tor data files and 'tasksche.exe' self-name ali
… [4156 more chars]
```

- **agentic:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`335420` mtime=`2026-08-09T18:10:28.485434+00:00`
  - sha256: `1d1828751763d11603d923eb9edbf9978c4b6b7c7c7f4e5fb42295ce19a50928`

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

- **rule_yar:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/rule.yar` exists=`True` bytes=`1085` mtime=`2026-08-09T18:26:56.418274+00:00`
  - sha256: `9b2a95fac377237094419c30bc9a102d00864cdfaddcf22d41c39d9fe77f7d7f`

#### excerpt

```
// yara_gen_v2.py — 2026-08-09T18:26:56.418694+00:00
import "pe"
rule CADRE_v2_wannacry_ec3fd41b2298 {
    meta:
        description = "RevAI v2 auto rule for WannaCry"
        sha256 = "ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda"
        family = "wannacry"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "oftware\\" ascii wide
        $s1 = "!This program cannot be run in DOS mode." ascii wide
        $s2 = "=j&&LZ66lA??~" ascii wide
        $s3 = "f\"\"D~**T" ascii wide
        $s4 = "V22dN::t" ascii wide
        $s5 = "o%%Jr..\\$" ascii wide
        $s6 = "&&Lj66lZ??~A" ascii wide
        $s7 = "\"\"Df**T~" ascii wide
        $s8 = ";22dV::tN"
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/REPORT-MASTER-v2.md` exists=`True` bytes=`16569` mtime=`2026-08-09T18:29:21.049245+00:00`
  - sha256: `bf86d134a151583403bc7ef8ad8e73a1ddcc15f41cb06ecd44ebb268af882743`
- **REPORT_MASTER_v3:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/REPORT-MASTER-v3.md` exists=`True` bytes=`48177` mtime=`2026-08-09T18:39:44.771824+00:00`
  - sha256: `6ae80efc2da950f4eb6bfd52fee5ccf280c089699895e751efa5eb0b5e833e45`
- **REPORT_v2:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/REPORT-v2.md` exists=`True` bytes=`16569` mtime=`2026-08-09T18:29:21.049245+00:00`
  - sha256: `bf86d134a151583403bc7ef8ad8e73a1ddcc15f41cb06ecd44ebb268af882743`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`67757` mtime=`2026-08-09T18:31:35.400467+00:00`
  - sha256: `025f2e6aa15814f55d0ca33942503b66ced20c64313f4205b2d9b426df856651`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`73036` mtime=`2026-08-09T18:51:04.269770+00:00`
  - sha256: `37f40991cf5bd78327de42de6edeed54faf839684848547b1d446c9437b0091a`
- **report_v2_json:** `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/report-v2.json` exists=`True` bytes=`19252` mtime=`2026-08-09T18:31:35.402467+00:00`
  - sha256: `f393f076d07f020e370f3d8bf1c7d29cf32f5893f29c8d5036f511197f397471`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 18:29:21 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# WannaCry Ransomware Analysis Report

## Executive Summary

This report details the analysis of a 32-bit Windows executable (`tasksche.exe`) identified as a component of the WannaCry ransomware family. The sample exhibits core ransomware behaviors including AES-based file encryption, service-based persistence, and registry manipulation for configuration storage. Analysis confirms the presence of WannaCry-specific artifacts such as the '
… [15662 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 18:39:44 UTC

# RE Report — ec3fd41b2298
_Generated 2026-08-09T18:39:44.768238+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=235c | cross_refs=True | llm_ok=True | runtime=46.46s -->

# Executive Summary

**SHA256:** `ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda`

**Top-line Verdict:** Malicious | **Family:** WannaCry | **Confidence:** High (90%)

**Summary:** This sample is identified as WannaCry ransomware with high confidence, based on agreement between multiple analysis methods and robust indicators such as encryption, self-propagation via EternalBlue, and persistenc
… [47260 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
