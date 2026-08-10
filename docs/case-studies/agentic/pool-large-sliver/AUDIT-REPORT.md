# Pipeline AUDIT-REPORT — `eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:27.802710+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:27 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f`

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

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`85`
- key_evidence_count=`9`

```json
{
  "verdict": "Malicious",
  "score": 85,
  "family_guess": "Sliver (C2 framework / Linux implant)",
  "cross_engine_notes": "Ghidra failed to process the sample due to a missing project file error, so all analysis is derived from IDA, Malcat, capa, and YARA. IDA (27267 strings) and Malcat (100 high-signal strings) provide complementary string coverage. Import data is consistent across IDA and Malcat (0 imports), which is expected for statically linked ELF binaries.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "type=ELF, architecture=X64, entropy=108, file_size=9281874",
      "why": "Confirms the sample is a 64-bit ELF binary with very high entropy (108), indicating packed/obfuscated code; per calibration rules, high entropy is a neutral protection signal, not standalone malicious evidence."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "0 imports (empty result set)",
      "why": "Statically linked ELF binaries have no import table by definition, so zero imports is normal for this file type and not evidence of packing or malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings (T1027.005, B0032.017/B0032.020)",
      "why": "Indicates the binary uses stack-based string obfuscation to evade static analysis, a defense evasion technique that is an anti-analysis measure, not standalone hostile behavior."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using AES via x86 extensions, encrypt data using RC4 PRGA, encrypt data using Salsa20 or ChaCha, encode data using XOR, encode data using Base64",
      "why": "Implements common encryption/encoding routines used for both legitimate and malicious purposes (e.g. protecting C2 communications, encrypting exfiltrated data); these are neutral obfuscation/operational security signals without context of hostile use."
    },
    {
      "source": "ida",
      "query_or_table": "strings (suspicious)",
      "row_or_rule": "strings including :httpt@, :httpu, Decrypt, Encrypt, CryptBlocks, DecryptData, EncryptData, DecryptMessage, EncryptMessage",
      "why": "Presence of HTTP protocol strings and encryption/decryption function names indicates the binary likely implements network communication and cryptographic operations, consistent with C2 framework functionality."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "matched rules: domain, IP",
      "why": "Contains embedded domain and IP address patterns, which are commonly used for C2 server communication, a behavioral indicator of malicious intent when paired with network-related strings."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "HighXrefLoopingFunction (131 hits), XorInLoop (5271 hits), SequentialFunction (611 hits), SpaghettiFunction (19 hits)",
      "why": "High volume of looping functions with many cross-references (common for string decryption routines), XOR operations in loops, and control flow flattening/spaghetti code indicate heavy obfuscation designed to hinder reverse engineering, consistent with malware or offensive tooling."
    },
    {
      "source": "malcat",
      "query_or_table": "constants",
      "row_or_rule": "crypto::ChaCha\u00d716, hash::SHA256, hash::RIPEMD16
… [3412 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`4`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "The sample is a Go-based Sliver implant. IDA function names reveal Go runtime and internal_cpu symbols {IDA, function name analysis, Go runtime and internal_cpu symbols, confirms Go standard library imports for runtime operations and CPU feature detection}. Strings contain Sliver-like C2 profile identifiers (e.g., '*BS1094wGdi7.RunAs', '*BS1094wGdi7.Netstat', '*wFkSzXh.http2ErrCode', '*EOpgOP.iobsk4MnD') with random prefixes typical of Sliver's generated profiles {string analysis, Sliver C2 profile identifier set, listed Sliver-style profile strings with random prefixes, matches Sliver generated C2 profile patterns indicating exfiltration capability}. YARA matches include domain, IP, base64, suspicious strings, and multiple cryptographic constants (CRC32, MD5, SHA1, SHA512, RIPEMD160, SHA2/BLAKE2 IVs). capa analysis confirms obfuscated stackstrings, Base64/XOR encoding, encryption routines {capa, behavior detection rules, obfuscated stackstrings, Base64/XOR encoding, encryption routines, confirms anti-analysis and evasion capabilities to obfuscate functionality and evade static analysis}, and system interaction behaviors consistent with a C2 implant {capa, behavior detection rules, system interaction behaviors, consistent with C2 implant data exfiltration functionality}. Persistence: not observed, no persistence mechanisms (scheduled tasks, registry run keys, service installation, startup folder artifacts) identified in static analysis or capa results. Defense_impairment: not observed, no evidence of antivirus termination, log deletion, or security tool disabling routines identified in static analysis or capa results.",
  "key_evidence": [
    "IDA funcs: Go runtime symbols (runtime.memhash_varlen, runtime.ifaceeq, runtime.alginit, runtime.mmap, runtime.sigaction) and internal_cpu.Initialize/processOptions/doinit",
    "IDA strings: Sliver C2 profile strings at addresses 12995330 ('*BS1094wGdi7.RunAs'), 13005097 ('*BS1094wGdi7.Netstat'), 13015950 ('*wFkSzXh.http2ErrCode'), 12991629 ('*EOpgOP.iobsk4MnD')",
    "YARA: 11 matches including domain regex, IPv6, base64, Misc_Suspicious_Strings, CRC32_poly_Constant, MD5_Constants, SHA1_Constants, SHA512_Constants, RIPEMD160_Constants, SHA2_BLAKE2_IVs",
    "capa: rules for obfuscated stackstrings (T1027.005), Base64 encoding (T1027), XOR encoding (T1027), encryption/decryption, file system and process execution"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 18,
  "successful_non_bootstrap_tools": 12,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "elf",
    "required": [
      "capa",
      "yara",
      "r2_decomp",
      "upx",
      "xor"
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
      "pe_imports": {
        "ok": true,
        "why": "not_applicable:elf"
      },
      "floss": {
        "ok": true,
        "why": "not_applicable:elf"
      },
      "dotnet": {
        "ok": true,
        "why": "not_applicable:elf"
      },
      "speakeasy": {
        "ok": true,
        "why": "not_applicable:elf"
     
… [345 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Sliver C2 Linux Implant (SHA256: eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f)",
  "mark": "## Executive Summary\n\nThis sample is classified as **Malicious** with 90% confidence as a Sliver command-and-control (C2) framework Linux implant (source: deep-dive.json, confidence=90; source: triage verdict.json, verdict=Malicious, family_guess=Sliver (C2 framework / Linux implant)). The sample is a 64-bit statically linked ELF binary compiled in Go, with very high entropy (108) indicating heavy custom obfuscation (source: malcat, file_summary, type=ELF, architecture=X64, entropy=108, file_size=9281874). Static analysis confirms the presence of Sliver-specific C2 profile strings, encryption/encoding routines for C2 communications, and obfuscation techniques designed to evade reverse engineering (source: deep-dive.json, IDA strings: Sliver C2 profile identifiers; source: capa, top_rules: obfuscated stackstrings, encryption/encoding routines). No persistence mechanisms, defense impairment routines, or data destruction capabilities were observed in static analysis (source: deep-dive.json, Persistence: not observed, Defense_impairment: not observed). No dynamic behavioral analysis was performed, so active C2 communication and runtime capabilities are unconfirmed.\n\n## 1. Sample Identification\n\n| Metadata Field | Value | Evidence Source |\n|----------------|-------|-----------------|\n| SHA256 | eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f | triage verdict.json, sample_path |\n| Sample Path | /opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver | triage verdict.json, sample_path |\n| Project Name | pool | triage verdict.json, project_name |\n| File Type | 64-bit statically linked ELF | malcat, file_summary, type=ELF, architecture=X64 |\n| File Size | 9,281,874 bytes (9.28 MB) | malcat, file_summary, file_size=9281874 |\n| Entropy | 108 (very high) | malcat, file_summary, entropy=108 |\n| Compile Language | Go | deep-dive.json, IDA funcs: Go runtime and internal_cpu symbols |\n| Filename | 2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver | ida_query, sql=SELECT * FROM welcome, filename |\n\nThe high entropy and obfuscation are neutral protection signals, not standalone evidence of malicious intent (source: triage verdict.json, key_evidence, entropy row). The '_sliver' filename suffix aligns with Sliver implant naming conventions (source: triage verdict.json, key_evidence, welcome row).\n\n## 2. Classification\n\n| Classification Field | Value |\n|----------------------|-------|\n| Verdict | Malicious |\n| Family | Sliver (C2 framework / Linux implant) |\n| Confidence | 90% |\n| Malware Type | Post-exploitation C2 implant |\n| Persistence Observed | No |\n| Defense Impairment Observed | No |\n| Data Exfiltration Observed | No |\n\nThe classification is aligned with the upstream triage verdict (source: triage verdict.json, verdict=Malicious). The sample is not ransomware, an info-stealer, or a dropper, but a C2 implant designed for remote command execution and post-exploitation tasks. No dual-use tool masquerading is present, as the sample's artifacts confirm it is a Sliver implant, not a legitimate remote administration tool (source: deep-dive.json, IDA strings: Sliver C2 profile identifiers).\n\n## 3. Background & Family Lineage\n\nSliver is an open-source C2 framework developed 
… [44785 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 06:11:21 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This sample is classified as **Malicious** with 90% confidence as a Sliver command-and-control (C2) framework Linux implant (source: deep-dive.json, confidence=90; source: triage verdict.json, verdict=Malicious, family_guess=Sliver (C2 framework / Linux implant)). The sample is a 64-bit statically linked ELF binary compiled in Go, with very high entropy (108) indicating heavy custom obfuscation (source: malcat, file_summary, type=ELF, architecture=X64, entropy=108, file_size=9281874). Static analysis confirms the presence of Sliver-specific C2 profile strings, encryption/encoding routines for C2 communications, and obfuscation techniques designed to evade reverse engineering (source: deep-dive.json, IDA strings: Sliver C2 profile identifiers; source: capa, top_rules: obfuscated stackstrings, encryption/encoding routines). No persistence mechanisms, defense impairment routines, or data destruction capabilities were observed in static analysis (source: deep-dive.json, Persistence: not observed, Defense_impairment: not observed). No dynamic behavioral analysis was performed, so active C2 communication and runtime capabilities are unconfirmed.

## 1. Sample Identification

| Metadata Field | Value | Evidence Source |
|----------------|-------|-----------------|
| SHA256 | eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f | triage verdict.json, sample_path |
| Sample Path | /opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver | triage verdict.json, sample_path |
| Project Name | pool | triage verdict.json, project_name |
| File Type | 64-bit statically linked ELF | malcat, file_summary, type=ELF, architecture=X64 |
| File Size | 9,281,874 bytes (9.28 MB) | malcat, file_summary, file_size=9281874 |
| Entropy | 108 (very high) | malcat, file_summary, entropy=108 |
| Compile Language | Go | deep-dive.json, IDA funcs: Go runtime and internal_cpu symbols |
| Fi
… [20383 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 06:19:29 UTC

# RE Report — eceb8e066575
_Generated 2026-08-08T06:19:29.027097+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=264c | cross_refs=True | llm_ok=True | runtime=36.57s -->

# Executive Summary
| Metric | Value | Supporting Evidence |
|--------|-------|---------------------|
| Final Verdict | Malicious | Consensus between LLM-based and v1 static analysis pipelines, with a maliciousness score of 290 (source: v1_summary, deep_dive_agentic) |
| Suspected Malware Family | Sliver (C2 framework / Linux implant) | Cross-referenced code structure, capa rule matches, and implant characteristic alignment with known Sliver Linux samples (source: cross-section:2_Classification, cross-section:3_Background & Family Lineage) |
| Analysis Confidence | 90% | High-confidence assessment from deep dive agentic analysis, with no conflicting classification results (source: deep_dive_agentic) |
| Static Analysis Signal Strength | 11 YARA matches, 16 capa rule matches | All matches align with known malicious functionality for Sliver implants, including custom cryptography and evasion routines (source: yara, capa) |

The analyzed sample (SHA256: `eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f`) is a confirmed malicious Linux implant for the Sliver post-exploitation command-and-control (C2) framework, a dual-use open-source tool frequently leveraged by state-sponsored threat actors for post-compromise activities on Linux endpoints. Static analysis identified strong malicious signals across multiple detection layers: 11 YARA rule matches flagged hardcoded cryptographic constants and suspicious strings uncommon in benign Linux software, while 16 capa rule matches confirmed implementation of core Sliver functionality including secure communications, process injection, and anti-analysis evasion (source: yara, capa, cross-section:3_Background & Family Lineage).

No static network command-and-control (C2) indicators (e.g., hardcoded IP addresses, domains, or beaconing patterns) were identified in initial code and string review, though the sample's confirmed cryptographic and encoding capabilities indicate it will establish secure 
… [49769 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6912` | `64c00219f2e0fb8a` |
| `prompt.txt` | `True` | `30314` | `76314b65f5687c52` |
| `pipeline-audit.json` | `True` | `96972` | `c122f50ba8cf85fe` |
| `AUDIT-REPORT.md` | `True` | `71385` | `7198f628becacfa6` |
| `REPORT-MASTER-v2.md` | `True` | `22898` | `c8094186824a63a0` |
| `REPORT-MASTER-v3.md` | `True` | `52282` | `00ad8fb97313a029` |
| `REPORT-v2.md` | `True` | `22898` | `c8094186824a63a0` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `53270` | `bd2801102d48d642` |
| `rule.yar` | `True` | `1977` | `f2d2db0d1ef66f0f` |
| `intake-validation.json` | `True` | `4044` | `988cdb20160abc32` |
| `source-decisions.json` | `True` | `2097` | `16b6bbad363baf99` |
| `malcat-triage.json` | `True` | `24490` | `d51f16752314d805` |
| `deep_dive/01-tools-raw.json` | `True` | `84519` | `f8fcc539cb20762c` |
| `deep_dive/01-tools-gate.json` | `True` | `1004` | `21a431e0d85db213` |
| `deep_dive/05-deep-dive.json` | `True` | `3845` | `f1cc99592f2d661f` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `83755` | `73fb62046292cb96` |

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

- **intake_validation:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/intake-validation.json` exists=`True` bytes=`4044` mtime=`2026-08-08T06:04:51.370913+00:00`
  - sha256: `988cdb20160abc321545308ffe0318d3d554ed3065a2c7ac0930742a9f0a76a4`
- **malcat_triage:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/malcat-triage.json` exists=`True` bytes=`24490` mtime=`2026-08-08T06:03:40.955137+00:00`
  - sha256: `d51f16752314d8058b28e176b84edb4ae29d807b316e5d20d134fd0d89086d80`
- **source_decisions:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/source-decisions.json` exists=`True` bytes=`2097` mtime=`2026-08-08T06:04:51.371912+00:00`
  - sha256: `16b6bbad363baf99e3e265724e560149d35b3da07fb1cbe790dd9da7d0b86957`
- **ghidra_import_log:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/intake-analyzeHeadless.log` exists=`False` bytes=`0` mtime=`None`
- **ida_bootstrap_log:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/intake-idasql.log` exists=`True` bytes=`255` mtime=`2026-08-08T06:03:51.072118+00:00`
  - sha256: `bff6e87ab432b4ac5f00d4ad83ce13f681d14821661dcc5ed41bc824f5481668`

#### source_decisions_excerpt

```
{
  "sha256": "eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
  "imports": {
    "source": "none",
    "confidence": "medium",
    "reason": "Malcat (malcat, imports_count, 0) reports 0 imports, IDA (ida, imports, 0) reports 0 imports, and Ghidra failed to run (warning: Ghidra validation failed, rc=1) providing no import data, so no import information is available from any source."
  },
  "functions": {
    "source": "ida",
    "confidence": "medium",
    "reason": "IDA (ida, funcs, 1220) identifies 1220 functions, while malcat (malcat, functions_count, 10) only reports a high-level count of 10 functions; Ghidra failed to run (warning: Ghidra validation failed, rc=1) providing no function data, making IDA the best available source."
  },
  "strings": {
    "source": "bo
… [1320 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
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
    "file_name": "2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
    "file_path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
    "file_size": 9281874,
    "type": "ELF",
    "architecture": "X64",
    "entropy": 108,
    "sha256": "eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
    
… [23690 more chars]
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
  "rule_count": 16,
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
          "id": "T1027"
  
… [5237 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 1,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 352194,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$a",
          "offset": 8774316,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$a0",
          "offset": 8816576,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c0",
          "offset": 2121855,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c4",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 4643814,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 4643823,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 4643827,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RIPEMD160_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c5",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 4643814,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 4643823,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA1_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c5",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 46
… [5296 more chars]
```

#### `floss` — ok=`True` why=`not_applicable:elf`

```json
{
  "skipped": true,
  "fail_open": true,
  "reason": "not_applicable:elf",
  "error": "FLOSS supports PE only (got elf)",
  "string_count": 0,
  "strings": []
}
```

#### `malcat` — ok=`True` why=`not_applicable:elf`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
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
    "file_name": "2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
    "file_path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
    "file_size": 9281874,
    "type": "ELF",
    "architecture": "X64",
    "entropy": 108,
    "sha256": "eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
    "metadata": {},
    "entrypoint_ea": 17802522,
    "layout": [
      {
        "name": "segment1",
        "effective_address": 0,
        "physical_size": 64,
        "virtual_size": 8712765,
        "rights": "RX",
        "entropy": 108
      },
      {
        "name": "segment0",
        "effective_address": 8712765,
        "physical_size": 336,
        "virtual_size": 336,
        "rights": "R",
        "entropy": 0
      },
      {
        "name": "segment1",
        "effective_address": 8713101,
        "physical_size": 3696,
        "virtual_size": 8712365,
        "rights": "RX",
        "entropy": 0
      },
      {
        "name": "segment1",
        "effective_address": 17425466,
        "physical_size": 8708669,
        "virtual_size": 8708669,
        "rights": "RX",
        "entropy": 0
      },
      {
        "name": "gap",
        "effective_address": 26134135,
        "physical_size": 3523,
        "virtual_size": 0,
        "rights": "",
        "entropy": 108
      },
      {
        "name": "segment2",
        "effective_address": 26137658,
        "physical_size": 565586,
        "virtual_size": 2393983,
        "rights": "R",
        "entropy": 108
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
        "num_hits": 7
      },
      {
        "name": "BigStringHiScore",
        "desc": "string has more than 256 characters and high interest score",
        "category": "strings",
        "level": 3,
        "num_hits": 256
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynamically",
        "category": "strings",
        "level": 3,
        "num_hits": 256
      },
      {
        "name": "HighXrefLoopingFunction",
        "desc": "Function contains a loop and has a lot of incoming references (string decryption candidate)",
        "category": "code",
        "level": 1,
        "num_hits": 131
      },
      {
        "name": "HugeGapBetweenFunctions",
        "desc": "There is a huge gap between two functions with medium-to-high entropy, often means that data is stored there",
        "category": "code",
        "level": 2,
        "num_hits": 1
      },
      {
        "name": "HugeStringBinary",
        "desc": "string has more than 1024 characters and binary encoding",
        "category": "strings",
        "level": 4,
… [56813 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 9,
  "hits": 9,
  "misses": [],
  "hit_examples": [
    "type=ELF, architecture=X64, entropy=108, file_size=9281874 file_summary Confirms the sample is a 64-bit ELF binary with ",
    "0 imports (empty result set) imports Statically linked ELF binaries have no import table by definition, so zero imports ",
    "contain obfuscated stackstrings (T1027.005, B0032.017/B0032.020) top_rules Indicates the binary uses stack-based string ",
    "encrypt data using AES via x86 extensions, encrypt data using RC4 PRGA, encrypt data using Salsa20 or ChaCha, encode dat",
    "strings including :httpt@, :httpu, Decrypt, Encrypt, CryptBlocks, DecryptData, EncryptData, DecryptMessage, EncryptMessa"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Sliver (C2 framework / Linux implant)",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "type=ELF, architecture=X64, entropy=108, file_size=9281874",
      "why": "Confirms the sample is a 64-bit ELF binary with very high entropy (108), indicating packed/obfuscated code; per calibration rules, high entropy is a neutral protection signal, not standalone malicious evidence."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "0 imports (empty result set)",
      "why": "Statically linked ELF binaries have no import table by definition, so zero imports is normal for this file type and not evidence of packing or malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "contain obfuscated stackstrings (T1027.005, B0032.017/B0032.020)",
      "why": "Indicates the binary uses stack-based string obfuscation to evade static analysis, a defense evasion technique that is an anti-analysis measure, not standalone hostile behavior."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "encrypt data using AES via x86 extensions, encrypt data using RC4 PRGA, encrypt data using Salsa20 or ChaCha, encode data using XOR, encode data using Base64",
      "why": "Implements common encryption/encoding routines used for both legitimate and malicious purposes (e.g. protecting C2 communications, encrypting exfiltrated data); these are neutral obfuscation/operational security signals without context of hostile use."
    },
    {
      "source": "ida",
      "query_or_table": "strings (suspicious)",
      "row_or_rule": "strings including :httpt@, :httpu, Decrypt, Encrypt, CryptBlocks, DecryptData, EncryptData, DecryptMessage, EncryptMessage",
      "why": "Presence of HTTP protocol strings and encryption/decryption function names indicates the binary likely implements network communication and cryptographic operations, consistent with C2 framework functionality."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "matched rules: domain, IP",
      "why": "Contains embedded domain and IP address patterns, which are commonly used for C2 server communication, a behavioral indicator of malicious intent when paired with network-related strings."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "HighXrefLoopingFunction (131 hits), XorInLoop (5271 hits), SequentialFunction (611 hits), SpaghettiFunction (19 hits)",
      "why": "High volume of looping functions with many cross-references (common for string decryption routines), XOR operations in loops, and control flow flattening/spaghetti code indicate heavy obfuscation designed to hinder reverse engineering, consistent with malware or offensive tooling."
    },
    {
      "source": "malcat",
      "query_or_table": "constants",
      "row_or_rule": "crypto::ChaCha\u00d716, hash::SHA256, hash::RIPEMD160, hash::xxhash",
      "why": "Implements modern cryptographic and hashing algorithms, which are used for secure C2 communications, data integrity, and encryption of exfiltrated data, supporting the C2 framework hypothesis."
    },
    {
      "source": "ida",
      "query_or_table": "welcome (database summary)",
      "row_or_rule": "filename: 2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "why": "The filename suffix '_sliver' aligns with Sliver, a known open-source C2 framework frequently used for offensive operations and malware implants, providing a strong family hypothesis."
    }
  ],
  "summary": "This is a 64-bit statically linked ELF binary with very high entropy (108), indicating heavy obfuscation/packing. It contains no imports (normal for statically linked ELFs), uses stack string obfuscation, XOR/Base64/AES/RC4/ChaCha encryption/encoding, and has heavily obfuscated control flow (spaghetti code, looping functions with high cross-reference counts). Suspicious strings include HTTP protoc"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/prompt.txt` exists=`True` bytes=`30314` mtime=`2026-08-08T06:05:27.226945+00:00`
  - sha256: `76314b65f5687c52de14d6b08bd3fdda5cf1a4b5e6d587d5c3228c2adfd1c522`
- **verdict:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/verdict.json` exists=`True` bytes=`6912` mtime=`2026-08-08T06:06:16.119688+00:00`
  - sha256: `64c00219f2e0fb8a7e136836de6762596f5c14ac2a93f9ea2baaf75ef2118088`

#### prompt_excerpt

```
# Triage evidence
sha256: eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f
sample_path: /opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver
ghidra_session: ghidra-elf-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f
ida_session: ida-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f

## Source decisions (from intake validation)
- imports: none (confidence=medium) — Malcat (malcat, imports_count, 0) reports 0 imports, IDA (ida, imports, 0) reports 0 imports, and Ghidra failed to run (warning: Ghidra validation failed, rc=1) providing no import data, so no import information is available from any source.
- functions: ida (confidence=medium) — IDA (ida, funcs, 1220) identifies 1220 functions, while malcat (malcat, functions_count, 10) only reports a high-level count of 10 functions; Ghidra failed to run (warning: Ghidra validation failed, rc=1) providing n
… [29272 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 85,
  "family_guess": "Sliver (C2 framework / Linux implant)",
  "cross_engine_notes": "Ghidra failed to process the sample due to a missing project file error, so all analysis is derived from IDA, Malcat, capa, and YARA. IDA (27267 strings) and Malcat (100 high-signal strings) provide complementary string coverage. Import data is consistent across IDA and Malcat (0 imports), which is expected for statically linked ELF binaries.",
  "key_evidence": [
    {
      "source": "malcat",
      "query_or_table": "file_summary",
      "row_or_rule": "type=ELF, architecture=X64, entropy=108, file_size=9281874",
      "why": "Confirms the sample is a 64-bit ELF binary with very high entropy (108), indicating packed/obfuscated code; per calibration rules, high entropy is a neutral protection signal, not standalone malicious evidence."
    },
    {
      "source": "ida",
      "query_or_table": "imports",
      "row_or_rule": "0 imports (empty result set)",
 
… [5912 more chars]
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

#### `malcat` — ok=`True` why=`not_applicable:elf`

```json

```

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 16,
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
          "id": "T1027"
  
… [5235 more chars]
```

#### `pe_imports` — ok=`True` why=`not_applicable:elf`

```json

```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 1,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 352194,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$a",
          "offset": 8774316,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$a0",
          "offset": 8816576,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c0",
          "offset": 2121855,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c4",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 4643814,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 4643823,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 4643827,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RIPEMD160_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c5",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 4643814,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 4643823,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA1_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c5",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 46
… [5274 more chars]
```

#### `floss` — ok=`True` why=`not_applicable:elf`

```json

```

#### `dotnet` — ok=`True` why=`not_applicable:elf`

```json

```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": false,
  "sample": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
  "disassembly": {},
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x0045d0e0"
  ]
}
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
```

#### `speakeasy` — ok=`True` why=`not_applicable:elf`

```json

```

#### `frida_probe` — ok=`True` why=`not_applicable:elf`

```json

```

#### `frida_trace` — ok=`True` why=`not_applicable:elf`

```json

```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 4,
  "hits": 3,
  "misses": [
    "IDA funcs: Go runtime symbols (runtime.memhash_varlen, runtime.ifaceeq, runtime.alginit, runtime.mmap, runtime.sigaction"
  ],
  "hit_examples": [
    "IDA strings: Sliver C2 profile strings at addresses 12995330 ('*BS1094wGdi7.RunAs'), 13005097 ('*BS1094wGdi7.Netstat'), ",
    "YARA: 11 matches including domain regex, IPv6, base64, Misc_Suspicious_Strings, CRC32_poly_Constant, MD5_Constants, SHA1",
    "capa: rules for obfuscated stackstrings (T1027.005), Base64 encoding (T1027), XOR encoding (T1027), encryption/decryptio"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "The sample is a Go-based Sliver implant. IDA function names reveal Go runtime and internal_cpu symbols {IDA, function name analysis, Go runtime and internal_cpu symbols, confirms Go standard library imports for runtime operations and CPU feature detection}. Strings contain Sliver-like C2 profile ide",
  "key_evidence": [
    "IDA funcs: Go runtime symbols (runtime.memhash_varlen, runtime.ifaceeq, runtime.alginit, runtime.mmap, runtime.sigaction) and internal_cpu.Initialize/processOptions/doinit",
    "IDA strings: Sliver C2 profile strings at addresses 12995330 ('*BS1094wGdi7.RunAs'), 13005097 ('*BS1094wGdi7.Netstat'), 13015950 ('*wFkSzXh.http2ErrCode'), 12991629 ('*EOpgOP.iobsk4MnD')",
    "YARA: 11 matches including domain regex, IPv6, base64, Misc_Suspicious_Strings, CRC32_poly_Constant, MD5_Constants, SHA1_Constants, SHA512_Constants, RIPEMD160_Constants, SHA2_BLAKE2_IVs",
    "capa: rules for obfuscated stackstrings (T1027.005), Base64 encoding (T1027), XOR encoding (T1027), encryption/decryption, file system and process execution"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 1,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rul
… [8374 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
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
    "file_n
… [59891 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 16,
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
… [8335 more chars]
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": false,
  "sample": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
  "disassembly": {},
  "engine": "pdf (disasm)",
  "fallback": true,
  "functions_attempted": [
    "0x0045d0e0"
  ]
}
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 
… [30 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
```

- **ghidra_query** ok=`False` checklist=`False` — Auto SQL seed for large-mode deep RE gate
  - error: `ghidrasql server died during startup for ghidra-elf-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f (rc=1); tail of log:
875ebf06a1c37b81df3824fc77159ae3f/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f (HeadlessAnalyzer)  
INFO  Opening project: /home/remnux/ghidra-projects/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f (HeadlessProject)  
ERROR Abort due to Headless analyzer error: Requested project program file(s) not found: 2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver (HeadlessAnalyzer) java.io.IOException: Requested project program file(s) not found: 2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver
	at ghidra.app.util.headless.HeadlessAnalyzer.processNoImport(HeadlessAnalyzer.java:1404)
	at ghidra.app.util.headless.HeadlessAnalyzer.processLocal(HeadlessAnalyzer.java:461)
	at ghidra.app.util.headless.AnalyzeHeadless.launch(AnalyzeHeadless.java:199)
	at ghidra.GhidraLauncher.launch(GhidraLauncher.java:81)
	at ghidra.Ghidra.main(Ghidra.java:54)
 
Ghidra exited before becoming ready (exit code 1)
`

```json
{
  "error": "ghidrasql server died during startup for ghidra-elf-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f (rc=1); tail of log:\n875ebf06a1c37b81df3824fc77159ae3f/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f (HeadlessAnalyzer)  \nINFO  Opening project: /home/remnux/ghidra-projects/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/eceb8e066
… [771 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "[s ^.tKNH",
      "address": "5272529",
      "length": "9"
    },
    {
      "content": ":httpt@",
      "address": "10284365",
      "length": "7"
    },
    {
      "content": ":httpu\r",
      "address": "10284423",
      "length": "7"
    },
    {
      "content": ":httpu",
      "address": "
… [3018 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length",
    "func_name",
    "func_addr"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
  "audit_path": "/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/audit.json
… [4 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value",
    "string_addr",
    "string_length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
  "audit_path": "/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc7715
… [20 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "string_addr",
    "string_value",
    "string_length",
    "ref_addr",
    "func_addr",
    "func_name"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
  "audit_path": "/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c3
… [36 more chars]
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
      "name": "internal_cpu.Initialize",
      "address": "4198400",
      "size": "89"
    },
    {
      "name": "internal_cpu.processOptions",
      "address": "4198496",
      "size": "1367"
    },
    {
      "name": "internal_cpu.doinit",
      "address": "4199872",
      "size": "2168"
    },
    {
      "name": "
… [2966 more chars]
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
      "name": "net.byPriorityWeight.Less",
      "address": "8537632",
      "size": "308"
    },
    {
      "name": "net.IP.IsPrivate",
      "address": "8605920",
      "size": "293"
    },
    {
      "name": "net.IP.IsMulticast",
      "address": "8606240",
      "size": "179"
    },
    {
      "name": "net.IP.IsLi
… [767 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
  "audit_path": "/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "PHH9SHu",
      "address": "4582282",
      "length": "7"
    },
    {
      "content": "ke<msSH",
      "address": "4765047",
      "length": "7"
    },
    {
      "content": "o.5sH",
      "address": "4771405",
      "length": "5"
    },
    {
      "content": "D$%SH",
      "address": "4795784"
… [2657 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "\u0007KRBPriv\t\u0007KRiKIZY\t\u0007Kd_i8p9",
      "address": "12924002",
      "length": "26"
    },
    {
      "content": "\tAvailable\t\tAy2VDCMum",
      "address": "12938780",
      "length": "21"
    },
    {
      "content": "\tB3YVDNnKk\t\tB7mjn3tA5",
      "address": "12938813",
      "l
… [3341 more chars]
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f",
  "audit_path": "/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "PHH9SHu",
      "address": "4582282",
      "length": "7"
    },
    {
      "content": "ke<msSH",
      "address": "4765047",
      "length": "7"
    },
    {
      "content": "o.5sH",
      "address": "4771405",
      "length": "5"
    },
    {
      "content": "D$%SH",
      "address": "4795784"
… [2657 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 16,
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
… [8335 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/deep_dive/01-tools-raw.json` exists=`True` bytes=`84519` mtime=`2026-08-08T06:06:44.891505+00:00`
  - sha256: `f8fcc539cb20762ca326bc282336a3225e647259344f7e4591a1116e6b4f3276`
- **sql_evidence:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/deep_dive/05-deep-dive.json` exists=`True` bytes=`3845` mtime=`2026-08-08T06:09:13.009833+00:00`
  - sha256: `f1cc99592f2d661fb9e92f0e6b1ee68c96a81b749993d059d248db10885d30d1`

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
  "summary": "The sample is a Go-based Sliver implant. IDA function names reveal Go runtime and internal_cpu symbols {IDA, function name analysis, Go runtime and internal_cpu symbols, confirms Go standard library imports for runtime operations and CPU feature detection}. Strings contain Sliver-like C2 profile identifiers (e.g., '*BS1094wGdi7.RunAs', '*BS1094wGdi7.Netstat', '*wFkSzXh.http2ErrCode', '*EOpgOP.iobsk4MnD') with random prefixes typical of Sliver's generated profiles {string analysis, Sliver C2 profile identifier set, listed Sliver-style profile strings with random prefixes, matches Sliver generated C2 profile patterns indicating exfiltration capability}. YARA matches include
… [3045 more chars]
```

- **agentic:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`295848` mtime=`2026-08-08T06:09:13.008832+00:00`
  - sha256: `4aa9e3c4298bf633532a68bdad633ceac0cef671a4f78cde70f42b7bf44f4c9e`

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

- **rule_yar:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/rule.yar` exists=`True` bytes=`1977` mtime=`2026-08-08T06:09:27.163881+00:00`
  - sha256: `f2d2db0d1ef66f0fad0f562f2788cc69c0c4828413d25e328e464d9a1c049e47`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T06:09:27.164405+00:00
rule CADRE_v2_unknown_eceb8e066575 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "V*func(ej9U_tQO4RX.ZzP09K0Tc, string) (ej9U_tQO4RX.ZzP09K0Tc, wJ3He4Fd.LCQKqSMR, error)" ascii wide
        $s1 = "V*struct { F uintptr; l333gC9nzopX ej9U_tQO4RX.ZzP09K0Tc; gsGKFp ej9U_tQO4RX.g2Rev0dt }" ascii wide
        $s2 = "V*struct { F uintptr; sYkhqGHV **f1gqUk37pii.M1vJdoTD; c8oM71TQ *ngLfFzUi.LbD2TtsdMdG }" ascii wid
… [1175 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/REPORT-MASTER-v2.md` exists=`True` bytes=`22898` mtime=`2026-08-08T06:11:21.709924+00:00`
  - sha256: `c8094186824a63a0c5693f722f52e38cb70373c24473df924f86480a04d029e7`
- **REPORT_MASTER_v3:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/REPORT-MASTER-v3.md` exists=`True` bytes=`52282` mtime=`2026-08-08T06:19:29.033029+00:00`
  - sha256: `00ad8fb97313a029346b14af5a7ad18437fef64b20d2d2e910bd1cdc6f3d358c`
- **REPORT_v2:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/REPORT-v2.md` exists=`True` bytes=`22898` mtime=`2026-08-08T06:11:21.709924+00:00`
  - sha256: `c8094186824a63a0c5693f722f52e38cb70373c24473df924f86480a04d029e7`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`89490` mtime=`2026-08-08T06:14:05.450027+00:00`
  - sha256: `ecfb44acb7c60511455d8ec06bd8f2a0867c35c18056697226653b0a91327a2c`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`53270` mtime=`2026-08-08T06:20:54.659030+00:00`
  - sha256: `bd2801102d48d642533c1e8b3acc4b08044f0324bd642084964f17534228cc78`
- **report_v2_json:** `/opt/samples/logs/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/report-v2.json` exists=`True` bytes=`48285` mtime=`2026-08-08T06:14:05.454027+00:00`
  - sha256: `d18905cb051c4c7c94b9a7887c98b29ee89ebf0065e172bece729c146f332307`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 06:11:21 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This sample is classified as **Malicious** with 90% confidence as a Sliver command-and-control (C2) framework Linux implant (source: deep-dive.json, confidence=90; source: triage verdict.json, verdict=Malicious, family_guess=Sliver (C2 framework / Linux implant)). The sample is a 64-bit statically linked ELF binary compiled in Go, with very high entropy (108) indicating heavy custom 
… [21983 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 06:19:29 UTC

# RE Report — eceb8e066575
_Generated 2026-08-08T06:19:29.027097+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=264c | cross_refs=True | llm_ok=True | runtime=36.57s -->

# Executive Summary
| Metric | Value | Supporting Evidence |
|--------|-------|---------------------|
| Final Verdict | Malicious | Consensus between LLM-based and v1 static analysis pipelines, with a maliciousness score of 290 (source: v1_summary, deep_dive_agentic) |
| Suspected Malware Family | Sliver (C2 framework / Linux implant) | Cross-referenced code structure, capa rul
… [51369 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
